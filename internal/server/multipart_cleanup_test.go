package server_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/auth"
)

// TestMultipartTempFilesAreRemoved: a SUCCESSFUL authenticated upload whose
// file part exceeds the 1 MiB in-memory threshold spills to a temp file, and
// net/http's own cleanup never fires (it is keyed on the request pointer the
// middleware chain's WithContext copies disconnected) — limitBody's deferred
// RemoveAll is what deletes it. The test design matters: a parse FAILURE
// cleans its own spilled files (stdlib ReadForm behaviour) and an oversized
// body is rejected before any spill, so only a successful in-cap upload can
// distinguish fixed from unfixed code. TMP/TEMP/TMPDIR are pointed at a fresh
// directory so the assertion sees only this process's multipart spills.
func TestMultipartTempFilesAreRemoved(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMPDIR", tmp)

	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// A 2 MiB SQL-comment payload: above the spill threshold, far below the
	// import cap, and a successful (200) import.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", csrf)
	_ = mw.WriteField("format", "sql")
	fw, err := mw.CreateFormFile("file", "big.sql")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	const line = "-- padding padding padding padding padding padding padding\n"
	for written := 0; written < 2<<20; written += len(line) {
		if _, err := io.WriteString(fw, line); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}
	mw.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/db/main/import", &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set(auth.CSRFHeader, csrf)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /import: %v", err)
	}
	// Drain to EOF: the chunked terminator is written after every middleware
	// (including limitBody's deferred cleanup) has finished, so reading the
	// whole body is the barrier that orders the assertion below.
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import = %d, want 200 — an unsuccessful upload cleans its own spill and proves nothing", resp.StatusCode)
	}

	// stdlib ReadForm spills with the "multipart-" prefix.
	leftover, err := filepath.Glob(filepath.Join(tmp, "multipart-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leftover) > 0 {
		t.Errorf("spilled multipart temp files survived the request: %v", leftover)
	}
}

// TestNoRequestCopiesBelowLimitBody pins the invariant limitBody's cleanup
// rests on: its deferred RemoveAll fires on the request POINTER the downstream
// parsers populate. The only WithContext copies in the production chain are
// made ABOVE limitBody — recover, logging and sessionMW — and nothing below it
// (importAdmission, csrf, the gates, restrict, the handlers) may derive a new
// request, or every spilled upload would silently leak to disk again. The scan
// covers this package and the handlers package, non-test files only.
func TestNoRequestCopiesBelowLimitBody(t *testing.T) {
	allowed := map[string]map[string]bool{
		// middleware.go functions that copy the request ABOVE limitBody.
		"middleware.go": {"recover": true, "logging": true, "sessionMW": true},
	}
	scanned := 0
	for _, dir := range []string{".", "handlers"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			scanned++
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
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || (sel.Sel.Name != "WithContext" && sel.Sel.Name != "Clone") {
						return true
					}
					// Only request derivation matters; both methods live on
					// *http.Request receivers named r/req in this codebase.
					if id, ok := sel.X.(*ast.Ident); !ok || (id.Name != "r" && id.Name != "req") {
						return true
					}
					if allowed[name][fn.Name.Name] {
						return true
					}
					t.Errorf("%s: %s derives a new *http.Request (%s.%s) — if this runs below limitBody it re-opens the multipart temp-file leak; move it above limitBody in the chain or re-point limitBody's cleanup, then update this guard",
						path, fn.Name.Name, exprString(sel.X), sel.Sel.Name)
					return true
				})
			}
		}
	}
	if scanned < 30 {
		t.Fatalf("scanned only %d non-test files — this guard is not looking where it thinks", scanned)
	}
}

func exprString(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}
