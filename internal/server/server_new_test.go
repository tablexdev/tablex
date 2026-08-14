package server_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/server"
)

// TestNewRefusesEachFallibleStep drives every class of fallible step in
// server.New to fail and asserts the refusal: the pure-validation parses
// (which must refuse before anything is acquired) and the session store
// (which fails after the audit sink is already open — the one path with
// something to release). No injection is needed: New never calls
// cfg.Validate(), so it can be handed configs the loader would reject, and a
// storage engine that is not registered fails instantly with no network.
// newTestServerWith cannot be used here — it t.Fatals on any New error, which
// is the outcome under test.
func TestNewRefusesEachFallibleStep(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"bad metrics CIDR", func(c *config.Config) {
			c.Metrics.AllowCIDRs = []string{"not-a-cidr"}
		}},
		{"bad trusted proxy CIDR", func(c *config.Config) {
			c.Security.TrustedProxyCIDRs = []string{"also-not-a-cidr"}
		}},
		{"session store failure after the audit sink opened", func(c *config.Config) {
			c.Audit.File = filepath.Join(t.TempDir(), "audit.jsonl")
			c.Storage.Engine = "nosuchengine"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			tc.mutate(&cfg)
			s, err := server.New(cfg, log, "test")
			if err == nil {
				_ = s.Shutdown(context.Background())
				t.Fatal("server.New accepted a config it must refuse")
			}
		})
	}
}

// TestNewResourceDiscipline pins the structure the fix above relies on, over
// server.go's AST. When openSessionStore fails, New returns nil and the audit
// logger becomes unreachable, so no test can observe its fd closing from the
// outside — the release is asserted structurally instead, alongside the two
// ordering rules that keep the class closed:
//
//  1. Pure validation (NewProxyTrust, NewCIDRSet) runs before the SSO
//     discovery round trip and before either acquisition.
//  2. The openSessionStore error arm releases the audit sink.
//  3. After session.NewManager there is no return but the final
//     `return s, nil`.
//
// Rule 3 is deliberately about returns, not call fallibility: the leak class
// is an EARLY ERROR RETURN after an acquisition. A later call whose error is
// checked must add exactly the return this rule forbids, and one whose error
// is ignored cannot exit New early at all — so the AST rule holds the
// invariant without needing type information to decide which calls can fail.
func TestNewResourceDiscipline(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing server.go: %v", err)
	}
	var newFn *ast.FuncDecl
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "New" && fn.Recv == nil {
			newFn = fn
			break
		}
	}
	if newFn == nil {
		t.Fatal("func New not found in server.go — this test is not looking where it thinks")
	}

	// Positions of the anchor calls. Each must exist, or the scan is stale.
	pos := map[string]token.Pos{}
	ast.Inspect(newFn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		default:
			return true
		}
		switch name {
		case "NewProxyTrust", "NewCIDRSet", "NewOIDCProvider", "openAuditLog", "openSessionStore", "NewManager":
			if _, dup := pos[name]; !dup { // first occurrence anchors the step
				pos[name] = call.Pos()
			}
		}
		return true
	})
	for _, want := range []string{"NewProxyTrust", "NewCIDRSet", "NewOIDCProvider", "openAuditLog", "openSessionStore", "NewManager"} {
		if pos[want] == token.NoPos {
			t.Fatalf("call %s not found in New — this test is not looking where it thinks", want)
		}
	}

	// Rule 1: validation before discovery, discovery before either acquisition.
	for _, v := range []string{"NewProxyTrust", "NewCIDRSet"} {
		if pos[v] >= pos["NewOIDCProvider"] {
			t.Errorf("%s runs after the SSO discovery round trip; pure validation must refuse startup before New talks to anything", v)
		}
	}
	if pos["openAuditLog"] >= pos["openSessionStore"] {
		t.Error("openAuditLog must run before openSessionStore (its error path is the one with nothing yet to release)")
	}

	// Rule 2: between openSessionStore and NewManager — i.e. in the store's
	// error arm — the audit sink is closed.
	closedInArm := false
	ast.Inspect(newFn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Close" {
			return true
		}
		if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == "auditLog" &&
			call.Pos() > pos["openSessionStore"] && call.Pos() < pos["NewManager"] {
			closedInArm = true
		}
		return true
	})
	if !closedInArm {
		t.Error("openSessionStore's error arm no longer closes auditLog; its file descriptor leaks on that path")
	}

	// Rule 3: after session.NewManager, the only way out is `return s, nil`.
	// Function literals are skipped: a return inside one (e.g. the BaseContext
	// closure) exits the closure, not New.
	var lateReturns []*ast.ReturnStmt
	ast.Inspect(newFn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok && ret.Pos() > pos["NewManager"] {
			lateReturns = append(lateReturns, ret)
		}
		return true
	})
	if len(lateReturns) != 1 {
		t.Fatalf("New has %d return statements after session.NewManager, want exactly the final `return s, nil`; an added error return there would leak the store, the reaper and the audit sink", len(lateReturns))
	}
	ret := lateReturns[0]
	okShape := len(ret.Results) == 2
	if okShape {
		s, sOK := ret.Results[0].(*ast.Ident)
		n, nOK := ret.Results[1].(*ast.Ident)
		okShape = sOK && nOK && s.Name == "s" && n.Name == "nil"
	}
	if !okShape {
		t.Errorf("the final return after session.NewManager is not `return s, nil` at %s", fset.Position(ret.Pos()))
	}
}
