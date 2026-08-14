package handlers

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// TestImportCSVDuplicateColumn covers #37: a CSV whose header repeats a column
// name is rejected with a clear error instead of building INSERT (id, id, …) and
// surfacing a low-signal engine error.
func TestImportCSVDuplicateColumn(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t (a INTEGER, b INTEGER)")
	h := &Handlers{}
	req := httptest.NewRequest("POST", "/", nil)
	_, err := h.importCSV(req, conn, reqScope{Table: "t"}, "a,a\n1,2\n")
	if err == nil || !strings.Contains(err.Error(), "duplicate CSV column") {
		t.Fatalf("expected duplicate-column error, got %v", err)
	}
}

// TestImportCSVSkipsComments covers the Theme A CSV re-import fix: TableX's own
// CSV export prefixes "# schema:" / "# table:" / "# <table>" comment lines, which
// must be skipped so the header is reached — while a data row whose first cell
// begins with '#' is preserved (csv.Reader.Comment would wrongly drop it).
func TestImportCSVSkipsComments(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t (a TEXT, b INTEGER)")
	h := &Handlers{}
	req := httptest.NewRequest("POST", "/", nil)
	csv := "# schema: sales\n# table: t\na,b\n#hash,1\nplain,2\n"
	n, err := h.importCSV(req, conn, reqScope{Table: "t"}, csv)
	if err != nil {
		t.Fatalf("import with leading comments: %v", err)
	}
	if n != 2 {
		t.Fatalf("imported %d rows, want 2", n)
	}
	var a string
	if e := conn.DB().QueryRowContext(context.Background(), "SELECT a FROM t WHERE b=1").Scan(&a); e != nil {
		t.Fatalf("query: %v", e)
	}
	if a != "#hash" {
		t.Errorf("a data cell beginning with # was dropped: got %q, want #hash", a)
	}
}

func TestSkipLeadingCSVComments(t *testing.T) {
	cases := []struct{ in, want string }{
		{"# a\n# b\nheader\nrow\n", "header\nrow\n"},
		{"header\nrow\n", "header\nrow\n"},
		{"#only\n", ""},
		{"#only", ""},
		{"  # indented\ndata\n", "data\n"},
	}
	for _, c := range cases {
		if got := skipLeadingCSVComments(c.in); got != c.want {
			t.Errorf("skipLeadingCSVComments(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// probeConn is a scriptConn stub for the db-collation marker verification:
// Dialect resolves through the registry (so a "mysql" probeConn is a real
// CollationProber) and Query returns the canned probe row or error.
type probeConn struct {
	engine string
	rows   [][]driver.Value
	err    error
}

func (p probeConn) Dialect() driver.Dialect {
	d, ok := driver.Get(p.engine)
	if !ok {
		panic("dialect not registered: " + p.engine)
	}
	return d
}
func (p probeConn) Query(context.Context, string, int) (*driver.ResultSet, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &driver.ResultSet{Rows: p.rows}, nil
}
func (p probeConn) Exec(context.Context, string) (driver.ExecResult, error) {
	return driver.ExecResult{}, nil
}
func (p probeConn) Explain(context.Context, string, bool) (*driver.ResultSet, error) {
	return &driver.ResultSet{}, nil
}
func (p probeConn) ExplainSQL(query string, _ bool) (string, bool) { return query, true }

func probeRow(db, collation string) [][]driver.Value {
	return [][]driver.Value{{{Str: db}, {Str: collation}}}
}

// TestVerifyCollationMarker table-tests the warning branches: mismatch warns
// with BOTH values, match stays silent, a failed lookup degrades to a "could
// not verify" note (the import keeps running — warnings are best-effort), and
// a non-prober dialect ignores markers entirely.
func TestVerifyCollationMarker(t *testing.T) {
	m := driver.DumpMarker{Kind: "routine", Name: "r1", Collation: "utf8mb4_general_ci"}
	cases := []struct {
		name     string
		conn     probeConn
		wantN    int
		wantText []string
	}{
		{"mismatch", probeConn{engine: "mysql", rows: probeRow("target_db", "latin1_swedish_ci")}, 1,
			[]string{"utf8mb4_general_ci", "latin1_swedish_ci", "target_db", `routine "r1"`}},
		{"match", probeConn{engine: "mysql", rows: probeRow("target_db", "utf8mb4_general_ci")}, 0, nil},
		{"lookup error", probeConn{engine: "mysql", err: errors.New("boom")}, 1,
			[]string{"could not verify", "boom"}},
		{"empty result", probeConn{engine: "mysql", rows: nil}, 1, []string{"could not verify"}},
		{"non-prober dialect", probeConn{engine: "sqlite", rows: probeRow("x", "y")}, 0, nil},
	}
	for _, c := range cases {
		var res importResult
		verifyCollationMarker(context.Background(), c.conn, m, &res)
		if res.WarningCount != c.wantN {
			t.Errorf("%s: WarningCount = %d, want %d (%v)", c.name, res.WarningCount, c.wantN, res.WarningSamples)
			continue
		}
		for _, want := range c.wantText {
			if len(res.WarningSamples) == 0 || !strings.Contains(res.WarningSamples[0], want) {
				t.Errorf("%s: warning %q missing %q", c.name, res.WarningSamples, want)
			}
		}
	}
}

// TestImportWarningSampleCap pins the O(1)-result invariant: the exact total
// keeps counting while retained samples stop at the cap, and summarizeImport
// carries both through (on success AND on failure).
func TestImportWarningSampleCap(t *testing.T) {
	var res importResult
	const n = maxImportWarningSamples + 7
	for i := 0; i < n; i++ {
		res.addWarning("w")
	}
	if res.WarningCount != n || len(res.WarningSamples) != maxImportWarningSamples {
		t.Fatalf("count=%d samples=%d, want %d/%d", res.WarningCount, len(res.WarningSamples), n, maxImportWarningSamples)
	}
	s := summarizeImport(res)
	if s.WarningCount != n || len(s.Warnings) != maxImportWarningSamples {
		t.Errorf("summary count=%d samples=%d, want %d/%d", s.WarningCount, len(s.Warnings), n, maxImportWarningSamples)
	}
	res.Failed = true
	res.Error = "boom"
	if s := summarizeImport(res); !s.Failed || s.WarningCount != n {
		t.Errorf("failure summary lost warnings: %+v", s)
	}
}

// TestImportCSVAllOrNothingRollback covers #23: a CSV import runs as one
// transaction, so a mid-file failure rolls back every prior row.
func TestImportCSVAllOrNothingRollback(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
	h := &Handlers{}
	req := httptest.NewRequest("POST", "/", nil)
	// Row 2 reuses primary key 1 -> the whole import must roll back.
	_, err := h.importCSV(req, conn, reqScope{Table: "t"}, "id,v\n1,a\n1,b\n")
	if err == nil {
		t.Fatal("expected an import error on the duplicate key")
	}
	var n int
	if e := conn.DB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM t").Scan(&n); e != nil {
		t.Fatalf("count: %v", e)
	}
	if n != 0 {
		t.Errorf("after a failed all-or-nothing import, row count = %d, want 0 (rolled back)", n)
	}
}

// TestBlankToNullType pins the L1 predicate: numeric/temporal/boolean columns
// take a NULL for an empty CSV cell (when nullable), while text and binary
// columns keep the empty string.
func TestBlankToNullType(t *testing.T) {
	null := []string{"int", "integer", "bigint", "int4", "decimal", "numeric",
		"double precision", "bool", "boolean", "date", "time", "datetime",
		"timestamp", "timestamptz", "timestamp with time zone", "interval", "year"}
	for _, bt := range null {
		if !blankToNullType(model.Column{BaseType: bt}) {
			t.Errorf("blankToNullType(%q) = false, want true", bt)
		}
	}
	notNull := []string{"text", "varchar", "char", "blob", "bytea", "json", "uuid", "enum"}
	for _, bt := range notNull {
		if blankToNullType(model.Column{BaseType: bt}) {
			t.Errorf("blankToNullType(%q) = true, want false", bt)
		}
	}
}

// TestImportUploadSpillsToDisk covers: the importer used to hand
// ParseMultipartForm the 32 MiB SIZE cap as its in-memory THRESHOLD, so every
// upload was buffered whole in RAM. On the htmx path the CSRF token rides a
// header, so this is the first parse of the body and nothing upstream had
// already spilled it.
//
// The observable property is the one the fix buys: past the 1 MiB threshold Go
// backs the part with a temp file (*os.File) instead of an in-memory reader —
// while readImportSource still returns the bytes intact.
func TestImportUploadSpillsToDisk(t *testing.T) {
	const size = 3 << 20 // comfortably over multipartMemoryThreshold, under MaxImportBytes
	payload := strings.Repeat("-- x\n", size/5)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "big.sql")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := io.WriteString(fw, payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/db/x/import", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	// Exactly what the importer does, with the same constants.
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, MaxImportBytes)
	if err := r.ParseMultipartForm(multipartMemoryThreshold); err != nil {
		t.Fatalf("ParseMultipartForm: %v", err)
	}
	t.Cleanup(func() { _ = r.MultipartForm.RemoveAll() })

	f, _, err := r.FormFile("file")
	if err != nil {
		t.Fatalf("FormFile: %v", err)
	}
	defer f.Close()
	if _, onDisk := f.(*os.File); !onDisk {
		t.Errorf("a %d-byte upload stayed in memory (%T); the multipart threshold is the 32 MiB size cap again", size, f)
	}

	content, filename, err := readImportSource(r)
	if err != nil {
		t.Fatalf("readImportSource: %v", err)
	}
	if filename != "big.sql" {
		t.Errorf("filename = %q, want big.sql", filename)
	}
	if content != payload {
		t.Errorf("spilled upload read back as %d bytes, want %d", len(content), len(payload))
	}
}
