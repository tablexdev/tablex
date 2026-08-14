package handlers

// exportSink's finish/abort split, tested directly: it is unexported, and
// calling the abort path explicitly is deterministic where panicking a real
// dump end-to-end would need a fake dialect or a panicking ResponseWriter,
// neither of which reproduces the real write path. The end-to-end SUCCESS
// guard already lives in internal/server/gzip_export_test.go, which downloads
// a real .gz export and decompresses it — what it cannot see is the panic
// direction, which is what these add. Note this is the form-selected .gz FILE
// (Content-Type application/gzip, no Content-Encoding): the transport gzip
// middleware never wraps it, so its abort fix cannot reach this path.

import (
	"bytes"
	"compress/gzip"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http/httptest"
	"testing"
)

// stageCompressedPrefix writes a payload through the sink and flushes the
// encoder, so compressed bytes are on the wire the way a mid-dump chunk
// would be.
func stageCompressedPrefix(t *testing.T, out io.Writer) string {
	t.Helper()
	const payload = "INSERT INTO widgets VALUES (1, 'bolt');\n"
	if _, err := io.WriteString(out, payload); err != nil {
		t.Fatalf("write through the sink: %v", err)
	}
	fl, ok := out.(interface{ Flush() error })
	if !ok {
		t.Fatal("the compressed sink does not expose Flush; partial output cannot be staged")
	}
	if err := fl.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return payload
}

// TestExportSinkAbortLeavesTruncationDetectable: abort must NOT write the
// trailer — an aborted dump has to decode with io.ErrUnexpectedEOF, because a
// sealed stream would present a truncated backup as a complete one.
func TestExportSinkAbortLeavesTruncationDetectable(t *testing.T) {
	rec := httptest.NewRecorder()
	out, _, abort := exportSink(rec, true)
	stageCompressedPrefix(t, out)
	abort()

	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("the flushed prefix is not a gzip stream at all: %v", err)
	}
	if _, derr := io.ReadAll(zr); derr == nil {
		t.Fatal("an aborted export decoded cleanly: abort wrote the trailer over a truncated dump")
	} else if !errors.Is(derr, io.ErrUnexpectedEOF) {
		t.Errorf("decode error = %v, want io.ErrUnexpectedEOF (an unterminated stream)", derr)
	}
}

// TestExportSinkFinishWritesTheTrailer is the inversion guard: the
// finish/abort split is exactly the change that could swap them, and a finish
// that stopped sealing the stream would fail every SUCCESSFUL compressed
// export in the way most tools refuse outright.
func TestExportSinkFinishWritesTheTrailer(t *testing.T) {
	rec := httptest.NewRecorder()
	out, finish, _ := exportSink(rec, true)
	payload := stageCompressedPrefix(t, out)
	finish()

	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	got, derr := io.ReadAll(zr)
	if derr != nil {
		t.Fatalf("a finished export must decode cleanly; got %v", derr)
	}
	if string(got) != payload {
		t.Errorf("decoded %q, want %q", got, payload)
	}
}

// TestExportSinkUncompressedPassesThrough: without compression both arms are
// just the deadline clear, and the bytes pass through verbatim.
func TestExportSinkUncompressedPassesThrough(t *testing.T) {
	rec := httptest.NewRecorder()
	out, finish, abort := exportSink(rec, false)
	const payload = "-- plain dump\n"
	if _, err := io.WriteString(out, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	finish()
	abort() // both must be safe to call; neither may disturb the body
	if got := rec.Body.String(); got != payload {
		t.Errorf("body = %q, want %q", got, payload)
	}
}

// TestExportSinkCallersRunAbortOnNonCompletion: a direct exportSink test
// proves the sink, not its callers — and the caller is where a captured
// `defer finish(ok)` argument would hide (evaluated at the defer statement,
// it aborts every successful export). Both call sites must defer a CLOSURE
// that chooses between finish and abort, and must never defer either
// directly.
func TestExportSinkCallersRunAbortOnNonCompletion(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "export.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing export.go: %v", err)
	}

	var callers []*ast.FuncDecl
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "exportSink" {
					found = true
				}
			}
			return true
		})
		if found {
			callers = append(callers, fn)
		}
	}
	if len(callers) != 2 {
		t.Fatalf("found %d functions calling exportSink, want exactly 2 — this test is not looking where it thinks", len(callers))
	}

	for _, fn := range callers {
		completionClosure := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			d, ok := n.(*ast.DeferStmt)
			if !ok {
				return true
			}
			switch fun := d.Call.Fun.(type) {
			case *ast.FuncLit:
				var callsFinish, callsAbort bool
				ast.Inspect(fun.Body, func(m ast.Node) bool {
					if c, ok := m.(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok {
							switch id.Name {
							case "finish":
								callsFinish = true
							case "abort":
								callsAbort = true
							}
						}
					}
					return true
				})
				if callsFinish && callsAbort {
					completionClosure = true
				}
			case *ast.Ident:
				if fun.Name == "finish" || fun.Name == "abort" {
					t.Errorf("%s defers %s directly at %s; a deferred call's arguments are evaluated at the defer statement, so this shape cannot express finish-on-completion",
						fn.Name.Name, fun.Name, fset.Position(d.Pos()))
				}
			}
			return true
		})
		if !completionClosure {
			t.Errorf("%s calls exportSink but has no deferred closure choosing finish on completion and abort otherwise", fn.Name.Name)
		}
	}
}
