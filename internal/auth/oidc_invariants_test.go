package auth_test

// The entire argument for reading ID-token claims WITHOUT verifying the
// signature (oidc.go's file comment; OIDC Core §3.1.3.7) rests on one
// structural fact: parseIDToken is only ever called on a token this process
// fetched itself over TLS from the token endpoint. That is a call-graph
// invariant no type can hold — a later front-channel addition (an implicit
// flow, a token from a redirect fragment) would invalidate it silently. This
// test pins the graph: parseIDToken is called only from verifyIDToken, and
// verifyIDToken only from Exchange.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseIDTokenIsOnlyReachableFromExchange(t *testing.T) {
	callers := map[string][]string{} // callee -> enclosing functions that call it
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("globbing the package sources: %v (%d files)", err, len(files))
	}
	parsed := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		parsed++
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				default:
					return true
				}
				if callee == "parseIDToken" || callee == "verifyIDToken" {
					callers[callee] = append(callers[callee], fn.Name.Name)
				}
				return true
			})
		}
	}
	if parsed < 3 { // this package has more than three non-test files
		t.Fatalf("parsed only %d non-test files — this test is not looking where it thinks", parsed)
	}

	for callee, want := range map[string]string{
		"parseIDToken":  "verifyIDToken",
		"verifyIDToken": "Exchange",
	} {
		got := callers[callee]
		if len(got) == 0 {
			t.Fatalf("no call to %s found — this test is not looking where it thinks", callee)
		}
		for _, from := range got {
			if from != want {
				t.Errorf("%s is called from %s; the signature-skip argument only holds when it is reachable solely via %s (see oidc.go's file comment)",
					callee, from, want)
			}
		}
	}
}

// Guard the guard: the file this invariant protects must still exist under the
// name the comment above points at.
func TestOIDCSourceFileExists(t *testing.T) {
	if _, err := os.Stat("oidc.go"); err != nil {
		t.Fatalf("oidc.go: %v", err)
	}
}
