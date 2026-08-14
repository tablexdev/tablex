package handlers

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// TestRenderTableOpsFailsClosedOnLookupError: renderTableOps used to discard
// lookupTable's error, so a failed introspection read as "not a view" through
// the zero-value model.Table and the page offered Truncate and Drop-as-table —
// destructive controls on the strength of a failed lookup, for what may well
// be a view. A closed connection makes every later query fail, which is
// exactly the introspection failure under test.
func TestRenderTableOpsFailsClosedOnLookupError(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	var logBuf bytes.Buffer
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&logBuf, nil))}
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	conn := openTestConn(t)
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{}, conn, nil)
	conn.Close() // every introspection query on it now fails

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/db/main/table/v/operations", nil)
	h.renderTableOps(w, r, uc, conn, reqScope{DB: "main", Table: "v"}, nil, "")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("operations page on a failed lookup = %d, want 500", w.Code)
	}
	body := w.Body.String()
	for _, control := range []string{`"truncate"`, `"drop"`} {
		if strings.Contains(body, control) {
			t.Errorf("the page offers the %s control although the lookup failed; a view would be offered Truncate/Drop-as-table", control)
		}
	}
	if !strings.Contains(logBuf.String(), "table operations lookup failed") {
		t.Error("the failed lookup was not logged")
	}
}

// TestTableExistsSeparatesErrorFromAbsence pins tableExists' contract at the
// source: an introspection failure comes back as an error, absence as
// (false, nil). Conflating them is how the create-table guard failed OPEN
// (error read as "no duplicate" → CREATE proceeded) while three other callers
// failed CLOSED into a misleading 404.
func TestTableExistsSeparatesErrorFromAbsence(t *testing.T) {
	h := &Handlers{}
	conn := openTestConn(t)
	ctx := t.Context()
	if _, err := conn.Exec(ctx, `CREATE TABLE widgets (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if found, err := h.tableExists(ctx, conn, reqScope{DB: "main", Table: "widgets"}); err != nil || !found {
		t.Errorf("existing table = (%v, %v), want (true, nil)", found, err)
	}
	if found, err := h.tableExists(ctx, conn, reqScope{DB: "main", Table: "nope"}); err != nil || found {
		t.Errorf("missing table = (%v, %v), want (false, nil)", found, err)
	}
	conn.Close()
	if _, err := h.tableExists(ctx, conn, reqScope{DB: "main", Table: "widgets"}); err == nil {
		t.Error("a failed lookup returned no error; the callers cannot tell it from absence")
	}
}

// TestCreateTableGuardFailsClosed drives database.go's duplicate guard — the
// most consequential caller — through the real handler: with the lookup
// failing, the POST must stop with "could not verify", never proceed to
// CREATE TABLE against catalog state it never saw. The database-existence
// check ahead of it is satisfied through the request memo (the same seeding
// idiom as the sequence-guard tests), so the failure under test is the
// table lookup alone.
func TestCreateTableGuardFailsClosed(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	var logBuf bytes.Buffer
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&logBuf, nil))}
	d, _ := driver.Get("sqlite")
	conn := openTestConn(t)
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{}, conn, nil)
	conn.Close() // the table lookup will fail; the memo carries the db list

	ctx := WithListingMemo(t.Context())
	m := memoFrom(ctx)
	m.dbNames, m.hasDBNames = []model.Database{{Name: "main"}}, true

	form := url.Values{"table_name": {"newtbl"}, "col_name_0": {"id"}, "col_type_0": {"INTEGER"}}
	r := httptest.NewRequest(http.MethodPost, "/db/main/create-table", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("db", "main")
	r = authedRequest(t, r.WithContext(ctx), uc)
	w := httptest.NewRecorder()
	h.DBCreateTable(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("create with a failed duplicate guard = %d, want 500 (fail closed)", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "Could not verify whether that table already exists") {
		t.Errorf("expected the could-not-verify refusal, got:\n%.400s", body)
	}
	if !strings.Contains(logBuf.String(), "create-table duplicate guard failed") {
		t.Error("the failed guard was not logged")
	}
}

// TestStructureEditGuardDistinguishesErrorFrom404 drives structure.go's edit
// guard: a failed lookup is a 500 "could not verify", not the misleading
// "Table not found." 404.
func TestStructureEditGuardDistinguishesErrorFrom404(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	var logBuf bytes.Buffer
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&logBuf, nil))}
	d, _ := driver.Get("sqlite")
	conn := openTestConn(t)
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{}, conn, nil)
	conn.Close()

	form := url.Values{"action": {"drop_column"}, "column": {"id"}}
	r := httptest.NewRequest(http.MethodPost, "/db/main/table/widgets/structure", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("db", "main")
	r.SetPathValue("table", "widgets")
	r = authedRequest(t, r, uc)
	w := httptest.NewRecorder()
	h.TableStructure(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("structure edit with a failed lookup = %d, want 500, not a misleading 404", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "Table not found") {
		t.Error("a failed lookup rendered as 'Table not found.'")
	}
}

// TestTableExistsErrorIsNeverDiscarded holds every introspection-backed
// existence helper's call site to consuming ALL its returns, the error last
// among them: the multi-value signature makes the compiler enforce assignment,
// but `exists, _ :=` would silently re-open the class (a failed listing
// rendering the same 404/"Unknown X." as a genuinely absent object, cause
// neither logged nor shown). The map carries each helper's arity, because the
// class is the CONTRACT, not any one pair of helpers — isView/findIndex/
// fkExists re-opened it once by not being listed. The engine-gated callers are
// unreachable with the SQLite fixture, so this is what holds them.
func TestTableExistsErrorIsNeverDiscarded(t *testing.T) {
	guarded := map[string]int{ // helper name → return-value count (error last)
		"tableExists":    2,
		"databaseExists": 2,
		"isView":         2,
		"fkExists":       2,
		"findIndex":      3,
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("globbing the package: %v (%d files)", err, len(files))
	}
	sites := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || guarded[sel.Sel.Name] == 0 {
				return true
			}
			sites++
			if len(assign.Lhs) != guarded[sel.Sel.Name] {
				t.Errorf("%s: %s call at %s does not bind all %d returns", name, sel.Sel.Name, fset.Position(call.Pos()), guarded[sel.Sel.Name])
				return true
			}
			if id, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident); ok && id.Name == "_" {
				t.Errorf("%s: %s' error is discarded at %s; an introspection failure would be indistinguishable from absence again", name, sel.Sel.Name, fset.Position(call.Pos()))
			}
			return true
		})
	}
	const floor = 10 // tableExists (4) + databaseExists (3) + isView/findIndex/fkExists (1 each)
	if sites < floor {
		t.Fatalf("found %d guarded call sites, expected at least %d — this scan is not looking where it thinks", sites, floor)
	}
}

// TestRenderTableOpsMissingTableIs404 pins the companion arm: a table that
// introspection successfully reports absent gets a 404, not an operations page
// over nothing. (rename/drop redirect away after success, so the re-render
// path never comes back through here under a stale name.)
func TestRenderTableOpsMissingTableIs404(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))}
	d, _ := driver.Get("sqlite")
	conn := openTestConn(t)
	uc := NewUserContext("srv", "srv", d, driver.ConnParams{}, conn, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/db/main/table/nope/operations", nil)
	h.renderTableOps(w, r, uc, conn, reqScope{DB: "main", Table: "nope"}, nil, "")
	if w.Code != http.StatusNotFound {
		t.Errorf("operations page for a missing table = %d, want 404", w.Code)
	}
}
