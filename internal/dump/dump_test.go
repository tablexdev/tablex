package dump

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"    // register for ValueLiteral tests
	_ "github.com/tablexdev/tablex/internal/driver/postgres" // register for ValueLiteral tests
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
	"github.com/tablexdev/tablex/internal/sqlscript"
)

// openTestConn opens a throwaway SQLite connection for the writer tests: the
// dump writers take a *driver.Connection for value literals and the data phase,
// so even the pure-ordering tests need a real dialect behind one.
func openTestConn(t *testing.T) *driver.Connection {
	t.Helper()
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	path := filepath.Join(t.TempDir(), "t.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func mustExec(t *testing.T, conn *driver.Connection, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("exec %s: %v", sql, err)
	}
}

// TestJSONExportCoercion pins the WriteJSON per-cell coercion decisions (L4):
// a numeric column's value is emitted UNQUOTED (json.Number) only when it is a
// valid JSON number — a big integer round-trips without float64 precision loss,
// while PostgreSQL's NaN/Infinity (a numeric column can still hold them) stay
// quoted strings; and a genuine boolean column ("true"/"false") becomes a real
// JSON boolean while a MySQL TINYINT boolean stays numeric. The predicate is
// the shared driver.IsNumericLiteral (also behind the SQL dump's bare-numeric
// gate); its full case table lives with it in internal/driver.
func TestJSONExportCoercion(t *testing.T) {
	numeric := []struct {
		s    string
		want bool
	}{
		{"1", true},
		{"-42", true},
		{"9223372036854775807", true},            // int64 max — must stay unquoted
		{"123456789012345678901234567890", true}, // bigint far past float64 exact range
		{"3.14159", true},
		{"1e10", true},
		{"NaN", false},       // PG numeric can hold NaN — not a JSON number
		{"Infinity", false},  // ditto
		{"-Infinity", false}, // leading '-' passes the byte guard, json.Valid rejects
		{"", false},
		{"0x1f", false}, // leading '0' then garbage
		{"12abc", false},
		{"  1", false}, // leading space is not a JSON number
	}
	for _, c := range numeric {
		if got := driver.IsNumericLiteral(c.s); got != c.want {
			t.Errorf("IsNumericLiteral(%q) = %v, want %v", c.s, got, c.want)
		}
	}

	boolean := []struct {
		dbType string
		want   bool
	}{
		{"BOOL", true},
		{"boolean", true},
		{" Boolean ", true}, // trimmed + case-folded
		{"TINYINT", false},  // MySQL boolean — stays numeric
		{"INT", false},
		{"", false},
	}
	for _, c := range boolean {
		if got := isBooleanResultColumn(driver.ResultColumn{DBType: c.dbType}); got != c.want {
			t.Errorf("isBooleanResultColumn(%q) = %v, want %v", c.dbType, got, c.want)
		}
	}
}

// TestSQLDumpDynamicTypingLiterals pins the SQLite bare-vs-quoted literal
// decision at the WRITER level, both halves of the defect it guards:
//
//   - (a) type fidelity: a no-affinity column's INTEGER/REAL must dump BARE or
//     typeof() flips to TEXT on restore, while its numeric-LOOKING text must
//     stay quoted — the declared type gets both wrong, so the runtime kind
//     (Value.Numeric via ValueLiteralHooks.PreferValueKind) decides;
//   - (b) literal breakout: text planted in a DECLARED-numeric column (SQLite
//     stores any storage class anywhere) must dump quoted, or the crafted cell
//     terminates its INSERT and the remainder executes on restore.
//
// The dump is then executed against a fresh database to prove the malicious
// cell never runs and every typeof() survives the round trip.
func TestSQLDumpDynamicTypingLiterals(t *testing.T) {
	ctx := context.Background()
	conn := openTestConn(t)
	mustExec(t, conn, `CREATE TABLE kv (k, v)`)     // no affinity: the value's storage class is the truth
	mustExec(t, conn, `CREATE TABLE evil (id INT)`) // declared numeric
	mustExec(t, conn, `CREATE TABLE notes (x INT)`) // the breakout's DROP target
	mustExec(t, conn, `INSERT INTO kv VALUES ('int', 1), ('real', 1.5), ('text', '1'), ('word', 'x')`)
	// Non-numeric text in an INT column keeps TEXT storage (affinity cannot
	// convert it) — exactly what a hostile co-writer of the file can plant.
	mustExec(t, conn, `INSERT INTO evil VALUES ('0, NULL);DROP TABLE notes;--')`)

	tables := []driver.TableRef{
		{Database: "main", Table: "evil"},
		{Database: "main", Table: "kv"},
		{Database: "main", Table: "notes"},
	}
	o := Options{Structure: true, Data: true}
	plan, err := BuildPlan(ctx, conn, driver.TableRef{Database: "main"}, tables, "db", o, nil)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	var buf strings.Builder
	writeSQLDump(ctx, &buf, conn, plan, o)
	out := buf.String()

	// (a) runtime kind decides: INTEGER/REAL bare, numeric-looking TEXT quoted.
	for _, want := range []string{"('int', 1)", "('real', 1.5)", "('text', '1')", "('word', 'x')"} {
		if !strings.Contains(out, want) {
			t.Errorf("dump missing %s:\n%s", want, out)
		}
	}
	// (b) the malicious cell is a single quoted literal, never a bare breakout.
	if !strings.Contains(out, `('0, NULL);DROP TABLE notes;--')`) {
		t.Errorf("declared-numeric text must dump as ONE quoted literal:\n%s", out)
	}
	if strings.Contains(out, "VALUES (0, NULL)") {
		t.Errorf("declared-numeric text emitted bare — the cell breaks out of its INSERT:\n%s", out)
	}

	// Execute the dump against a fresh database: the breakout must not run and
	// every storage class must survive.
	d, _ := driver.Get("sqlite")
	restored := openTestConn(t)
	for _, stmt := range sqlscript.Split(out, driver.ProfileOf(d)) {
		if _, err := restored.Exec(ctx, stmt); err != nil {
			t.Fatalf("restore %q: %v", stmt, err)
		}
	}
	assertCol := func(query, want string) {
		t.Helper()
		rs, err := restored.Query(ctx, query, 10)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		var got []string
		for _, row := range rs.Rows {
			got = append(got, row[0].Str)
		}
		if joined := strings.Join(got, "|"); joined != want {
			t.Errorf("%s = %q, want %q", query, joined, want)
		}
	}
	assertCol(`SELECT typeof(v) FROM kv ORDER BY rowid`, "integer|real|text|text")
	assertCol(`SELECT count(*) FROM notes`, "0")                     // exists AND empty — the DROP never ran
	assertCol(`SELECT typeof(id) FROM evil`, "text")                 // the planted cell survives as data
	assertCol(`SELECT id FROM evil`, "0, NULL);DROP TABLE notes;--") // byte-exact
}

// TestJSONDynamicTypingWriter pins the same pair of decisions at the JSON
// WRITER level (decoding the emitted document, not just the predicate): a
// SQLite no-affinity column's INTEGER emits as a JSON number, its
// numeric-looking TEXT as a string, and malformed text in a declared-numeric
// column as a string.
func TestJSONDynamicTypingWriter(t *testing.T) {
	ctx := context.Background()
	conn := openTestConn(t)
	mustExec(t, conn, `CREATE TABLE kv (k, v)`)
	mustExec(t, conn, `INSERT INTO kv VALUES ('int', 1), ('text', '1'), ('word', 'x')`)
	mustExec(t, conn, `CREATE TABLE evil (id INT)`)
	mustExec(t, conn, `INSERT INTO evil VALUES ('12abc')`)

	var buf bytes.Buffer
	WriteJSON(ctx, &buf, conn, []SchemaGroup{{Tables: []driver.TableRef{
		{Database: "main", Table: "kv"}, {Database: "main", Table: "evil"},
	}}}, false, nil, nil)

	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	var doc map[string][]map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode emitted JSON: %v\n%s", err, buf.String())
	}
	if got, ok := doc["kv"][0]["v"].(json.Number); !ok || got.String() != "1" {
		t.Errorf("no-affinity INTEGER must emit as a JSON number, got %T %v", doc["kv"][0]["v"], doc["kv"][0]["v"])
	}
	if got, ok := doc["kv"][1]["v"].(string); !ok || got != "1" {
		t.Errorf("numeric-looking TEXT must stay a JSON string, got %T %v", doc["kv"][1]["v"], doc["kv"][1]["v"])
	}
	if got, ok := doc["kv"][2]["v"].(string); !ok || got != "x" {
		t.Errorf("TEXT must emit as a JSON string, got %T %v", doc["kv"][2]["v"], doc["kv"][2]["v"])
	}
	if got, ok := doc["evil"][0]["id"].(string); !ok || got != "12abc" {
		t.Errorf("malformed text in a declared-numeric column must stay a string, got %T %v", doc["evil"][0]["id"], doc["evil"][0]["id"])
	}
}

// TestExportCSVZeroExportableColumns covers the #13 degenerate case in a
// MULTI-table export: a table whose every column is generated yields an empty
// selectSQL, so WriteCSV skips it with an explicit "no exportable columns"
// comment — never a malformed "SELECT  FROM t" — and never queries the table.
// (BuildCSVPlan makes the single-table case a rendered preflight error.)
func TestExportCSVZeroExportableColumns(t *testing.T) {
	conn := openTestConn(t) // never queried (selectSQL == "")
	plan := []CSVTable{{scope: driver.TableRef{Table: "allgen"}, selectSQL: ""}}
	var buf bytes.Buffer
	if err := WriteCSV(context.Background(), &buf, conn, plan); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "# allgen") {
		t.Errorf("missing table comment, got %q", out)
	}
	if !strings.Contains(out, "# no exportable columns") {
		t.Errorf("missing the explicit no-exportable-columns comment, got %q", out)
	}
	if strings.Contains(out, "SELECT") {
		t.Errorf("zero-exportable table should not emit a SELECT, got %q", out)
	}
}

// TestExportCSVEmptyTableHeader covers #8: a zero-row table must still emit
// its header line (from the preflighted plan, not lazily from the first row),
// or the exported CSV cannot be re-imported — the reader would hit EOF looking
// for a header.
func TestExportCSVEmptyTableHeader(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE empty_t (id INTEGER PRIMARY KEY, name TEXT)")
	plan, err := BuildCSVPlan(context.Background(), conn, []driver.TableRef{{Database: "main", Table: "empty_t"}}, nil, nil)
	if err != nil {
		t.Fatalf("BuildCSVPlan: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteCSV(context.Background(), &buf, conn, plan); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "id,name") {
		t.Errorf("empty table export missing its header row:\n%q", out)
	}
}

// CommentSafe's tests moved to internal/driver with its implementation (the dump
// writers reach it through the dump.CommentSafe re-export); see
// TestCommentSafe there.

// TestExportCSVSchemaLabels covers H1's unambiguous CSV labeling: a "# schema:"
// line is emitted once per schema change and a "# table:" line per table (an
// identifier may contain '.', so a single "schema.table" line would be
// ambiguous). All are '#'-comments the CSV importer skips.
func TestExportCSVSchemaLabels(t *testing.T) {
	conn := openTestConn(t) // never queried (selectSQL == "")
	plan := []CSVTable{
		{scope: driver.TableRef{Schema: "sales", Table: "orders"}, selectSQL: ""},
		{scope: driver.TableRef{Schema: "sales", Table: "items"}, selectSQL: ""},
		{scope: driver.TableRef{Schema: "hr", Table: "orders"}, selectSQL: ""},
	}
	var buf bytes.Buffer
	if err := WriteCSV(context.Background(), &buf, conn, plan); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "# schema: sales") != 1 {
		t.Errorf("expected one '# schema: sales' line, got:\n%s", out)
	}
	if !strings.Contains(out, "# schema: hr") {
		t.Errorf("missing '# schema: hr':\n%s", out)
	}
	if strings.Count(out, "# table: orders") != 2 || !strings.Contains(out, "# table: items") {
		t.Errorf("missing/incorrect table labels:\n%s", out)
	}
}

// TestExportJSONFlatValid confirms the schema-less JSON export is well-formed
// and keyed by table name (unchanged behavior for MySQL/SQLite).
func TestExportJSONFlatValid(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t (id INTEGER, name TEXT)")
	mustExec(t, conn, "INSERT INTO t VALUES (1, 'a'), (2, 'b')")
	groups := []SchemaGroup{{Schema: "", Tables: []driver.TableRef{{Database: "main", Table: "t"}}}}
	var buf bytes.Buffer
	WriteJSON(context.Background(), &buf, conn, groups, false, nil, nil)
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("flat JSON export is not valid JSON: %v\n%s", err, buf.String())
	}
	if rows, ok := out["t"].([]any); !ok || len(rows) != 2 {
		t.Errorf("expected 2 rows under key t, got %#v", out["t"])
	}
}

// TestExportJSONColumnOrder pins: each row object emits its keys in table
// column order, not alphabetically (json.Marshal of a map sorts keys; the CSV
// and SQL exports preserve column order).
func TestExportJSONColumnOrder(t *testing.T) {
	conn := openTestConn(t)
	// Column order deliberately differs from alphabetical.
	mustExec(t, conn, "CREATE TABLE t (zeta INTEGER, alpha TEXT, mid INTEGER)")
	mustExec(t, conn, "INSERT INTO t VALUES (1, 'a', 2)")
	groups := []SchemaGroup{{Schema: "", Tables: []driver.TableRef{{Database: "main", Table: "t"}}}}
	var buf bytes.Buffer
	WriteJSON(context.Background(), &buf, conn, groups, false, nil, nil)
	out := buf.String()
	if err := json.Unmarshal(buf.Bytes(), &map[string]any{}); err != nil {
		t.Fatalf("JSON export is not valid JSON: %v\n%s", err, out)
	}
	zeta, alpha, mid := strings.Index(out, `"zeta"`), strings.Index(out, `"alpha"`), strings.Index(out, `"mid"`)
	if zeta < 0 || alpha < 0 || mid < 0 {
		t.Fatalf("row keys missing from export:\n%s", out)
	}
	if !(zeta < alpha && alpha < mid) {
		t.Errorf("row keys not in table column order (zeta@%d alpha@%d mid@%d):\n%s", zeta, alpha, mid, out)
	}
}

// TestExportJSONNestedValid confirms the schema-having JSON export nests tables
// under their schema and stays valid JSON (H1 — disambiguates same-named tables
// across schemas).
func TestExportJSONNestedValid(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t (id INTEGER)")
	mustExec(t, conn, "INSERT INTO t VALUES (1)")
	// SQLite ignores the schema in QualifyTable, so both groups read the same
	// physical table; only the JSON nesting shape is under test here.
	groups := []SchemaGroup{
		{Schema: "sales", Tables: []driver.TableRef{{Database: "main", Table: "t"}}},
		{Schema: "hr", Tables: []driver.TableRef{{Database: "main", Table: "t"}}},
	}
	var buf bytes.Buffer
	WriteJSON(context.Background(), &buf, conn, groups, true, nil, nil)
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("nested JSON export is not valid JSON: %v\n%s", err, buf.String())
	}
	for _, schema := range []string{"sales", "hr"} {
		sm, ok := out[schema].(map[string]any)
		if !ok {
			t.Fatalf("expected object under schema %q, got %#v", schema, out[schema])
		}
		if _, ok := sm["t"]; !ok {
			t.Errorf("expected table t under schema %q, got %#v", schema, sm)
		}
	}
}

// TestExportJSONNestedRepeatedSchemaStaysValid: two CONSECUTIVE groups naming
// one schema share a single schema object, so the comma between their tables
// has to come from state that lives with the object, not with the group. It did
// not, and the result was invalid JSON.
func TestExportJSONNestedRepeatedSchemaStaysValid(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER)")
	mustExec(t, conn, "CREATE TABLE t2 (id INTEGER)")
	groups := []SchemaGroup{
		{Schema: "sales", Tables: []driver.TableRef{{Database: "main", Table: "t1"}}},
		{Schema: "sales", Tables: []driver.TableRef{{Database: "main", Table: "t2"}}},
	}
	var buf bytes.Buffer
	WriteJSON(context.Background(), &buf, conn, groups, true, nil, nil)
	var out map[string]map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("nested JSON export is not valid JSON: %v\n%s", err, buf.String())
	}
	for _, table := range []string{"t1", "t2"} {
		if _, ok := out["sales"][table]; !ok {
			t.Errorf("table %q missing from schema sales: %#v", table, out["sales"])
		}
	}
}

// TestExportJSONNestedNonContiguousSchemaKeepsEveryTable: a schema that appears,
// is interrupted, and appears again used to be emitted as a DUPLICATE top-level
// key. That is well-formed JSON, so nothing failed — every decoder just keeps
// the last one, and the first appearance's tables silently vanished.
func TestExportJSONNestedNonContiguousSchemaKeepsEveryTable(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t1 (id INTEGER)")
	mustExec(t, conn, "CREATE TABLE t2 (id INTEGER)")
	mustExec(t, conn, "CREATE TABLE t3 (id INTEGER)")
	groups := []SchemaGroup{
		{Schema: "sales", Tables: []driver.TableRef{{Database: "main", Table: "t1"}}},
		{Schema: "hr", Tables: []driver.TableRef{{Database: "main", Table: "t3"}}},
		{Schema: "sales", Tables: []driver.TableRef{{Database: "main", Table: "t2"}}},
	}
	var buf bytes.Buffer
	WriteJSON(context.Background(), &buf, conn, groups, true, nil, nil)
	var out map[string]map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("nested JSON export is not valid JSON: %v\n%s", err, buf.String())
	}
	for _, table := range []string{"t1", "t2"} {
		if _, ok := out["sales"][table]; !ok {
			t.Errorf("table %q missing from schema sales — a duplicate key dropped it: %#v", table, out["sales"])
		}
	}
	if _, ok := out["hr"]["t3"]; !ok {
		t.Errorf("table t3 missing from schema hr: %#v", out["hr"])
	}
	// The literal text must name each schema once; a decoded map cannot show a
	// duplicate key, so the shape is checked on the wire format too.
	if n := strings.Count(buf.String(), `"sales": {`); n != 1 {
		t.Errorf("the dump opens \"sales\" %d times, want 1:\n%s", n, buf.String())
	}
}

// TestJSONCoalesceBySchemaKeepsFirstAppearanceOrder pins the ordering contract
// the writer depends on: schemas in first-appearance order, tables in input
// order within each.
func TestJSONCoalesceBySchemaKeepsFirstAppearanceOrder(t *testing.T) {
	ref := func(name string) driver.TableRef { return driver.TableRef{Table: name} }
	got := coalesceBySchema([]SchemaGroup{
		{Schema: "b", Tables: []driver.TableRef{ref("b1")}},
		{Schema: "a", Tables: []driver.TableRef{ref("a1")}},
		{Schema: "b", Tables: []driver.TableRef{ref("b2")}},
		{Schema: "a", Tables: []driver.TableRef{ref("a2")}},
	})
	want := []SchemaGroup{
		{Schema: "b", Tables: []driver.TableRef{ref("b1"), ref("b2")}},
		{Schema: "a", Tables: []driver.TableRef{ref("a1"), ref("a2")}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("coalesceBySchema = %#v, want %#v", got, want)
	}
}

// TestBuildCSVPlanExcludesGenerated proves the CSV plan resolves an explicit
// non-generated SELECT before the download commits (so a Columns failure or the
// degenerate case can't corrupt an already-committed stream).
func TestBuildCSVPlanExcludesGenerated(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, "CREATE TABLE t (a INTEGER, b INTEGER GENERATED ALWAYS AS (a+1) STORED)")
	plan, err := BuildCSVPlan(context.Background(), conn, []driver.TableRef{{Table: "t"}}, nil, nil)
	if err != nil {
		t.Fatalf("BuildCSVPlan: %v", err)
	}
	if len(plan) != 1 {
		t.Fatalf("plan length = %d, want 1", len(plan))
	}
	sel := plan[0].selectSQL
	if sel == "" || !strings.Contains(sel, `"a"`) {
		t.Errorf("selectSQL should include the non-generated column a: %q", sel)
	}
	if strings.Contains(sel, `"b"`) {
		t.Errorf("selectSQL must exclude the generated column b: %q", sel)
	}
}

// TestCSVCell pins the R1 symmetric decision matrix: hexing is decided by the
// COLUMN's binary type (importCSV's predicate), never the value's Binary flag
// alone. The string-in-binary-column case (SQLite dynamic typing) hexes the
// string's bytes — hexing the nil Bytes would silently write "". A text column
// whose value was classified binary (NUL/control chars, >1 MiB — MySQL returns
// text as []byte) writes the bytes as text when valid UTF-8, and errors (never
// silently corrupts) when not.
func TestCSVCell(t *testing.T) {
	cases := []struct {
		name      string
		binaryCol bool
		v         driver.Value
		want      string
		wantErr   bool
	}{
		{"null binary col", true, driver.Value{Null: true}, `\N`, false},
		{"null text col", false, driver.Value{Null: true}, `\N`, false},
		{"bytes in binary col", true, driver.Value{Binary: true, Bytes: []byte{0x00, 0xff}, Str: "[BLOB 2 B]"}, "00ff", false},
		{"string in binary col (sqlite)", true, driver.Value{Str: "hello"}, "68656c6c6f", false},
		{"empty string in binary col", true, driver.Value{Str: ""}, "", false},
		{"nul text in text col", false, driver.Value{Binary: true, Bytes: []byte("a\x00b"), Str: "[BLOB 3 B]"}, "a\x00b", false},
		{"non-utf8 in text col", false, driver.Value{Binary: true, Bytes: []byte{0x80, 0xff}, Str: "[BLOB 2 B]"}, "", true},
		{"plain text", false, driver.Value{Str: "plain"}, "plain", false},
		{"sentinel-shaped text", false, driver.Value{Str: `\N`}, `\\N`, false},
	}
	for _, c := range cases {
		got, err := csvCell("col", 7, c.binaryCol, c.v)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected an error, got %q", c.name, got)
			} else if !strings.Contains(err.Error(), `"col"`) || !strings.Contains(err.Error(), "row 7") {
				t.Errorf("%s: error should name the column and row: %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: csvCell = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestExportCSVBinaryColumnAlignment guards the binaryCols↔SELECT alignment: a
// generated column ORDERED BEFORE the binary column is excluded from the
// streamed SELECT, so an index built over all columns would look up the wrong
// entry (TestCSVRoundTripSQLite's generated column is last and would not catch
// it). Also covers the SQLite string-in-blob cell end-to-end: a TEXT value
// stored in a BLOB-declared column must hex its string bytes.
func TestExportCSVBinaryColumnAlignment(t *testing.T) {
	conn := openTestConn(t)
	mustExec(t, conn, `CREATE TABLE t (
		id INTEGER PRIMARY KEY,
		name_up TEXT GENERATED ALWAYS AS (upper(name)) STORED,
		name TEXT,
		data BLOB)`)
	mustExec(t, conn, "INSERT INTO t (id, name, data) VALUES (1, 'ann', X'00FF10')")
	mustExec(t, conn, "INSERT INTO t (id, name, data) VALUES (2, 'bob', 'hello')") // TEXT stored in the BLOB column
	plan, err := BuildCSVPlan(context.Background(), conn, []driver.TableRef{{Table: "t"}}, nil, nil)
	if err != nil {
		t.Fatalf("BuildCSVPlan: %v", err)
	}
	if len(plan) != 1 {
		t.Fatalf("plan length = %d, want 1", len(plan))
	}
	// Non-generated columns are (id, name, data): only the last is binary.
	if want := []bool{false, false, true}; !reflect.DeepEqual(plan[0].binaryCols, want) {
		t.Fatalf("binaryCols = %v, want %v (aligned to the non-generated SELECT)", plan[0].binaryCols, want)
	}
	var buf bytes.Buffer
	if err := WriteCSV(context.Background(), &buf, conn, plan); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "00ff10") {
		t.Errorf("BLOB bytes should hex-encode:\n%s", out)
	}
	if !strings.Contains(out, "68656c6c6f") {
		t.Errorf("TEXT value in the BLOB column should hex-encode its string bytes:\n%s", out)
	}
	if strings.Contains(out, ",hello") || strings.Contains(out, "hello\n") {
		t.Errorf("string-in-blob cell leaked as plain text:\n%s", out)
	}
}

// TestCSVSentinelEscapeRoundTrip pins the escape/unescape pair: any literal
// value survives escapeCSVCell → UnescapeCSVCell unchanged, and the escaped form
// never collides with the bare \N NULL sentinel.
func TestCSVSentinelEscapeRoundTrip(t *testing.T) {
	for _, in := range []string{"", "hello", `\N`, `\`, `\\N`, `\x00`, "a\\b", "#x", "plain"} {
		esc := escapeCSVCell(in)
		if esc == CSVNullSentinel {
			t.Errorf("escapeCSVCell(%q) = %q collides with the NULL sentinel", in, esc)
		}
		if got := UnescapeCSVCell(esc); got != in {
			t.Errorf("round-trip %q: escaped %q, unescaped %q", in, esc, got)
		}
	}
}

// (TestIsJSONNumber moved to internal/driver's TestIsNumericLiteral when the
// predicate was hoisted there — the SQL and JSON writers now share it.)

// dumperFor returns the registered dialect's Dumper (all built-ins implement it).
func dumperFor(t *testing.T, engine string) driver.Dumper {
	t.Helper()
	d, ok := driver.Get(engine)
	if !ok {
		t.Fatalf("dialect %s not registered", engine)
	}
	du, ok := d.(driver.Dumper)
	if !ok {
		t.Fatalf("dialect %s does not implement Dumper", engine)
	}
	return du
}

// TestValueLiteralZeroDates pins the MySQL zero-date sentinel: the driver's
// parseTime maps 0000-00-00 to Go's zero time (rendered 0001-01-01), and the
// dump must restore the sentinel instead of storing year 1.
func TestValueLiteralZeroDates(t *testing.T) {
	cases := []struct {
		engine, dbType, in, want string
	}{
		{"mysql", "DATE", "0001-01-01", "'0000-00-00'"},
		{"mysql", "DATETIME", "0001-01-01 00:00:00", "'0000-00-00 00:00:00'"},
		{"mysql", "TIMESTAMP", "0001-01-01 00:00:00", "'0000-00-00 00:00:00'"},
		// Non-temporal columns and other engines pass through untouched.
		{"mysql", "VARCHAR", "0001-01-01", "'0001-01-01'"},
		{"postgres", "DATE", "0001-01-01", "'0001-01-01'"},
		{"sqlite", "DATE", "0001-01-01", "'0001-01-01'"},
	}
	for _, c := range cases {
		got := dumperFor(t, c.engine).ValueLiteral(driver.ResultColumn{DBType: c.dbType}, driver.Value{Str: c.in})
		if got != c.want {
			t.Errorf("ValueLiteral(%s, %s, %q) = %q, want %q", c.engine, c.dbType, c.in, got, c.want)
		}
	}
}

func TestValueLiteralBinaryAndNumeric(t *testing.T) {
	bin := driver.Value{Binary: true, Bytes: []byte{0x00, 0xff}}
	if got := dumperFor(t, "postgres").ValueLiteral(driver.ResultColumn{}, bin); got != `'\x00ff'` {
		t.Errorf("postgres binary = %q", got)
	}
	if got := dumperFor(t, "mysql").ValueLiteral(driver.ResultColumn{}, bin); got != "X'00ff'" {
		t.Errorf("mysql binary = %q", got)
	}
	// Numeric: true models a real scan — SQLite returns numeric storage as
	// int64/float64 and formatValue records the runtime kind, which is what
	// the DynamicTyper dialect's literal decision reads.
	if got := dumperFor(t, "sqlite").ValueLiteral(driver.ResultColumn{Numeric: true}, driver.Value{Numeric: true, Str: "42"}); got != "42" {
		t.Errorf("numeric = %q", got)
	}
	if got := dumperFor(t, "sqlite").ValueLiteral(driver.ResultColumn{}, driver.Value{Null: true}); got != "NULL" {
		t.Errorf("null = %q", got)
	}
}

// TestValueLiteralNonFiniteFloat covers: a non-finite float (NaN/±Inf, which
// a PostgreSQL float8 can hold) must not dump as a bare token. PostgreSQL gets
// the quoted special literal; MySQL/SQLite, which cannot store it, get NULL
// (except SQLite ±Inf, which round-trips via an overflowing exponent).
func TestValueLiteralNonFiniteFloat(t *testing.T) {
	num := driver.ResultColumn{Numeric: true}
	cases := []struct {
		engine, in, want string
	}{
		{"postgres", "NaN", "'NaN'"},
		{"postgres", "+Inf", "'Infinity'"},
		{"postgres", "-Inf", "'-Infinity'"},
		{"mysql", "NaN", "NULL"},
		{"mysql", "+Inf", "NULL"}, // MySQL cannot store Inf
		{"sqlite", "+Inf", "9.0e+999"},
		{"sqlite", "-Inf", "-9.0e+999"},
		{"sqlite", "NaN", "NULL"},    // SQLite cannot store NaN
		{"postgres", "3.14", "3.14"}, // ordinary finite value still unquoted
	}
	for _, c := range cases {
		// Numeric: true models a real scan — a non-finite float arrives as a
		// float64, so formatValue records the runtime kind (which SQLite's
		// DynamicTyper literal decision reads; the others read the column).
		if got := dumperFor(t, c.engine).ValueLiteral(num, driver.Value{Numeric: true, Str: c.in}); got != c.want {
			t.Errorf("ValueLiteral(%s, %q) = %q, want %q", c.engine, c.in, got, c.want)
		}
	}
}

// TestWriteDumpScriptDelimiter confirms procedural bodies are wrapped in
// mysql-client DELIMITER directives, and plain DDL is ';'-terminated.
func TestWriteDumpScriptDelimiter(t *testing.T) {
	var b strings.Builder
	writeDumpScript(&b, driver.DumpScript{
		Comment:        "Trigger trg",
		Drop:           "DROP TRIGGER IF EXISTS `trg`",
		SQL:            "CREATE TRIGGER `trg` BEFORE INSERT ON t FOR EACH ROW BEGIN SET @x = 1; END",
		NeedsDelimiter: true,
	}, true)
	out := b.String()
	for _, want := range []string{
		"-- Trigger trg\n",
		"DROP TRIGGER IF EXISTS `trg`;\n",
		"DELIMITER $$\n",
		"END$$\nDELIMITER ;\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("DELIMITER wrap missing %q in:\n%s", want, out)
		}
	}

	b.Reset()
	writeDumpScript(&b, driver.DumpScript{SQL: "CREATE VIEW v AS SELECT 1"}, false)
	if got := b.String(); got != "CREATE VIEW v AS SELECT 1;\n" {
		t.Errorf("plain script = %q", got)
	}
}

// TestWriteDumpScriptGuardNamespace pins the guard/frame emission contract:
// per-object creation-context guards use @saved_* names OUTSIDE the DELIMITER
// wrap and never the preamble's @OLD_* variables (which the postamble restores
// LAST), opaque frames carry their body byte-exact, and the whole emission
// re-splits cleanly through the statement splitter.
func TestWriteDumpScriptGuardNamespace(t *testing.T) {
	d, ok := driver.Get("mysql")
	if !ok {
		t.Fatal("mysql dialect not registered")
	}
	body1 := "CREATE PROCEDURE p1() BEGIN SET @x = 'a\\'; SELECT 1; END" // NBE-authored body
	body2 := "CREATE DEFINER=`root`@`localhost` EVENT e1 ON SCHEDULE EVERY 1 DAY DO BEGIN SELECT '\x83\x5c'; END"
	guards := func(mode, tz string) (pre, post []string) {
		pre = []string{
			"SET @saved_cs_client = @@character_set_client",
			"SET character_set_client = 'cp932'",
			"SET @saved_sql_mode = @@sql_mode",
			"SET sql_mode = '" + mode + "'",
		}
		post = []string{
			"SET sql_mode = @saved_sql_mode",
			"SET character_set_client = @saved_cs_client",
		}
		if tz != "" {
			pre = append(pre, "SET @saved_time_zone = @@time_zone", "SET time_zone = '"+tz+"'")
			post = append([]string{"SET time_zone = @saved_time_zone"}, post...)
		}
		return pre, post
	}

	var b strings.Builder
	WritePreamble(&b, d)
	pre1, post1 := guards("NO_BACKSLASH_ESCAPES", "")
	writeDumpScript(&b, driver.DumpScript{
		Comment: "Procedure p1", SQL: body1,
		NeedsDelimiter: true, OpaqueFrame: true,
		Pre: pre1, Post: post1,
		Markers: []string{driver.FormatCollationMarker("routine", "p1", "utf8mb4_general_ci")},
	}, true)
	pre2, post2 := guards("ANSI_QUOTES", "+03:00")
	writeDumpScript(&b, driver.DumpScript{
		Comment: "Event e1", SQL: body2,
		NeedsDelimiter: true, OpaqueFrame: true,
		Pre: pre2, Post: post2,
		Markers: []string{driver.FormatCollationMarker("event", "e1", "utf8mb4_general_ci")},
	}, true)
	WritePostamble(&b, d)
	out := b.String()

	// The preamble's session variables are saved once and restored once — no
	// guard may reuse the @OLD_* namespace.
	if got := strings.Count(out, "@OLD_SQL_MODE"); got != 2 {
		t.Errorf("@OLD_SQL_MODE appears %d times, want 2 (preamble save + postamble restore):\n%s", got, out)
	}
	last := strings.LastIndex(out, "SET SQL_MODE=@OLD_SQL_MODE")
	if last < 0 || strings.Contains(out[last+1:], "sql_mode") {
		t.Errorf("the postamble sql_mode restore must be the final sql_mode statement:\n%s", out)
	}

	// The full emission must re-split through the splitter with both bodies
	// byte-exact and every guard outside the frames.
	stmts := sqlscript.Split(out, driver.ProfileOf(d))
	var foundBodies int
	for _, s := range stmts {
		switch s {
		case body1, body2:
			foundBodies++
		}
		if strings.Contains(strings.ToUpper(s), "DELIMITER") {
			t.Errorf("DELIMITER leaked into a statement: %q", s)
		}
	}
	if foundBodies != 2 {
		t.Errorf("re-split recovered %d/2 bodies byte-exact; statements:\n%q", foundBodies, stmts)
	}
	// Guards travel as their own statements, after/before the body.
	i1 := strings.Index(out, "SET @saved_sql_mode = @@sql_mode")
	iBody := strings.Index(out, body1)
	iRestore := strings.Index(out, "SET sql_mode = @saved_sql_mode")
	if !(i1 >= 0 && i1 < iBody && iBody < iRestore) {
		t.Errorf("guard ordering wrong: save=%d body=%d restore=%d\n%s", i1, iBody, iRestore, out)
	}
}

// TestWriteSQLDumpSequenceOrdering pins the PostgreSQL sequence-DDL phase
// ordering: CREATE SEQUENCE before CREATE TABLE (a serial DEFAULT nextval(...)
// must resolve at table-create time), DROP SEQUENCE after DROP TABLE in
// teardown (an owned sequence's dependency blocks an earlier drop), and the
// pg_dump --data-only parity — a data-only DB dump omits CREATE SEQUENCE yet
// still emits the standalone setval (Kind "sequence") and matview REFRESH
// (Kind "refresh") while dropping the "sequence-own" OWNED BY ALTER.
func TestWriteSQLDumpSequenceOrdering(t *testing.T) {
	conn := openTestConn(t) // a real dialect for the (no-op) data phase

	plan := &Plan{
		objects: driver.DumpPlan{
			Sequences: []driver.DumpScript{
				{Kind: "sequence-def", Comment: "Sequence s_emp", Drop: `DROP SEQUENCE IF EXISTS "public"."s_emp"`,
					SQL: `CREATE SEQUENCE "public"."s_emp" START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 100 CACHE 1`},
				{Kind: "sequence-def", Comment: "Sequence s_counter", Drop: `DROP SEQUENCE IF EXISTS "public"."s_counter"`,
					SQL: `CREATE SEQUENCE "public"."s_counter" AS integer START WITH 1000 INCREMENT BY 10 MINVALUE 100 MAXVALUE 100000 CACHE 5 CYCLE`},
			},
			PostData: []driver.DumpScript{
				{Kind: "sequence-own", Comment: "owned", SQL: `ALTER SEQUENCE "public"."s_emp" OWNED BY "public"."emp"."id"`},
				{Kind: "sequence", Comment: "Sequence s_emp", SQL: `SELECT pg_catalog.setval('"public"."s_emp"', 5, true)`},
				{Kind: "sequence", Comment: "Sequence s_counter", SQL: `SELECT pg_catalog.setval('"public"."s_counter"', 1000, true)`},
				{Kind: "refresh", Comment: "Refresh materialized view mv1", SQL: `REFRESH MATERIALIZED VIEW "public"."mv1"`},
			},
		},
		tables: []tableDump{
			{scope: driver.TableRef{Database: "rt", Table: "emp"}, qualified: `"public"."emp"`, create: `CREATE TABLE "public"."emp" (id int)`},
		},
	}

	// Full dump with drop-first: assert the four ordering anchors.
	var full strings.Builder
	writeSQLDump(context.Background(), &full, conn, plan,
		Options{Structure: true, Data: true, DropFirst: true})
	out := full.String()
	idxDropTable := strings.Index(out, `DROP TABLE IF EXISTS "public"."emp"`)
	idxDropSeq := strings.Index(out, `DROP SEQUENCE IF EXISTS "public"."s_emp"`)
	idxCreateSeq := strings.Index(out, `CREATE SEQUENCE "public"."s_emp"`)
	idxCreateTable := strings.Index(out, `CREATE TABLE "public"."emp"`)
	for name, idx := range map[string]int{"DROP TABLE": idxDropTable, "DROP SEQUENCE": idxDropSeq,
		"CREATE SEQUENCE": idxCreateSeq, "CREATE TABLE": idxCreateTable} {
		if idx < 0 {
			t.Fatalf("full dump missing %s:\n%s", name, out)
		}
	}
	if idxDropTable > idxDropSeq {
		t.Errorf("DROP SEQUENCE must follow DROP TABLE in teardown:\n%s", out)
	}
	if idxCreateSeq > idxCreateTable {
		t.Errorf("CREATE SEQUENCE must precede CREATE TABLE:\n%s", out)
	}

	// Data-only DB dump: pg_dump parity.
	var data strings.Builder
	writeSQLDump(context.Background(), &data, conn, plan,
		Options{Structure: false, Data: true, DropFirst: false})
	d := data.String()
	if strings.Contains(d, "CREATE SEQUENCE") {
		t.Errorf("data-only dump must omit CREATE SEQUENCE:\n%s", d)
	}
	if !strings.Contains(d, `setval('"public"."s_counter"'`) {
		t.Errorf("data-only dump must keep standalone-sequence setval:\n%s", d)
	}
	if !strings.Contains(d, "REFRESH MATERIALIZED VIEW") {
		t.Errorf("data-only dump must keep matview refresh:\n%s", d)
	}
	if strings.Contains(d, "OWNED BY") {
		t.Errorf("data-only dump must drop the sequence-own OWNED BY ALTER:\n%s", d)
	}
}

// TestResolveDBDumpPlanOrdering pins the unified planner's graph mechanics
// on synthetic plans: edges override the class-priority insertion order
// (type-shell → support function → type-final bootstrap), the define-first
// backfill shape for mutually-referencing pairs, deferrable-clause cutting
// with external dependers retargeted to the "-final" stage, routine stub
// staging, and the preflight failure for a genuinely unrestorable cycle.
func TestResolveDBDumpPlanOrdering(t *testing.T) {
	conn := openTestConn(t)
	o := Options{Structure: true, Data: false}
	render := func(t *testing.T, plan *Plan) string {
		t.Helper()
		dbp, err := ResolveDB(context.Background(), conn, []Section{{"", plan}}, o)
		if err != nil {
			t.Fatalf("ResolveDB: %v", err)
		}
		var b strings.Builder
		WriteDB(context.Background(), &b, conn, dbp, o)
		return b.String()
	}
	order := func(t *testing.T, out string, anchors ...string) {
		t.Helper()
		last := -1
		for _, a := range anchors {
			i := strings.Index(out, a)
			if i < 0 {
				t.Fatalf("missing %q in:\n%s", a, out)
			}
			if i < last {
				t.Fatalf("%q out of order in:\n%s", a, out)
			}
			last = i
		}
	}

	// (a) type-shell → support function → type-final: pure edge ordering, even
	// though the class priority puts all types before all routines.
	out := render(t, &Plan{objects: driver.DumpPlan{
		Types: []driver.DumpScript{
			{Kind: "type", Name: "type-shell:s\x00rng", SQL: "CREATE TYPE shell_rng"},
			{Kind: "type", Name: "type-final:s\x00rng", DependsOn: []string{"type-shell:s\x00rng", "routine:s\x00canon"}, SQL: "CREATE TYPE final_rng"},
		},
		Routines: []driver.DumpScript{
			{Kind: "routine", Name: "routine:s\x00canon", DependsOn: []string{"type-shell:s\x00rng"}, SQL: "CREATE FUNCTION canon_fn"},
		},
	}})
	order(t, out, "CREATE TYPE shell_rng", "CREATE FUNCTION canon_fn", "CREATE TYPE final_rng")

	// (b) the commutator define-first backfill shape: op1 carries its reference
	// to op2 as a deferrable clause, op2 references op1 hard — the clause is
	// cut, op1 emits bare, op2 follows, the "-final" stage re-adds the link.
	out = render(t, &Plan{objects: driver.DumpPlan{
		Routines: []driver.DumpScript{
			{Kind: "routine", Name: "op:s\x00op1", SQL: "CREATE OPERATOR op1", Clauses: []driver.DumpClause{{
				Text: " (COMMUTATOR op2)", Deps: []string{"op:s\x00op2"}, PreData: true,
				Finalize: []driver.DumpScript{{Kind: "routine", SQL: "LINK op1 TO op2"}},
			}}},
			{Kind: "routine", Name: "op:s\x00op2", DependsOn: []string{"op:s\x00op1"}, SQL: "CREATE OPERATOR op2"},
		},
	}})
	order(t, out, "CREATE OPERATOR op1", "CREATE OPERATOR op2", "LINK op1 TO op2")
	if strings.Contains(out, "(COMMUTATOR op2)") {
		t.Errorf("cut clause text leaked into the emission:\n%s", out)
	}

	// (c) a deferred PRE-DATA clause retargets EXTERNAL dependers to the
	// "-final" stage: the table-analog view here must wait for the deferred
	// ALTER, not just the base create.
	out = render(t, &Plan{objects: driver.DumpPlan{
		Types: []driver.DumpScript{
			{Kind: "type", Name: "type:s\x00dom", SQL: "CREATE DOMAIN dom", Clauses: []driver.DumpClause{{
				Text: " DEFAULT f()", Deps: []string{"routine:s\x00f"}, PreData: true,
				Finalize: []driver.DumpScript{{Kind: "type", SQL: "ALTER DOMAIN dom SET DEFAULT f()"}},
			}}},
		},
		Routines: []driver.DumpScript{
			{Kind: "routine", Name: "routine:s\x00f", DependsOn: []string{"type:s\x00dom"}, SQL: "CREATE FUNCTION f_returns_dom"},
		},
		Views: []driver.DumpScript{
			{Kind: "view", Name: "relation:s\x00consumer", DependsOn: []string{"type:s\x00dom"}, SQL: "CREATE VIEW consumer_of_dom"},
		},
	}})
	order(t, out, "CREATE DOMAIN dom", "CREATE FUNCTION f_returns_dom",
		"ALTER DOMAIN dom SET DEFAULT f()", "CREATE VIEW consumer_of_dom")
	if strings.Contains(out, "CREATE DOMAIN dom DEFAULT f()") {
		t.Errorf("deferred DEFAULT clause still inline:\n%s", out)
	}

	// (d) mutually-recursive routines: stubs first (dependency-reduced), then
	// the CREATE OR REPLACE finals.
	out = render(t, &Plan{objects: driver.DumpPlan{
		Routines: []driver.DumpScript{
			{Kind: "routine", Name: "routine:s\x00f2", DependsOn: []string{"routine:s\x00g2"},
				SQL: "CREATE OR REPLACE FUNCTION f2_real", Stub: "CREATE FUNCTION f2_stub"},
			{Kind: "routine", Name: "routine:s\x00g2", DependsOn: []string{"routine:s\x00f2"},
				SQL: "CREATE OR REPLACE FUNCTION g2_real", Stub: "CREATE FUNCTION g2_stub"},
		},
	}})
	order(t, out, "CREATE FUNCTION f2_stub", "CREATE FUNCTION g2_stub",
		"CREATE OR REPLACE FUNCTION f2_real", "CREATE OR REPLACE FUNCTION g2_real")

	// (e) an unbootstrappable cycle (no clause, no stub) preflight-fails with a
	// precise member list rather than emitting a broken dump.
	_, err := ResolveDB(context.Background(), conn, []Section{{"", &Plan{objects: driver.DumpPlan{
		Types: []driver.DumpScript{
			{Kind: "type", Name: "type:s\x00t1", DependsOn: []string{"type:s\x00t2"}, SQL: "T1"},
			{Kind: "type", Name: "type:s\x00t2", DependsOn: []string{"type:s\x00t1"}, SQL: "T2"},
		},
	}}}}, o)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("unresolvable cycle: err = %v, want a preflight cycle error", err)
	}
}

// teardownDump renders one synthetic plan as a drop-first structure dump.
func teardownDump(t *testing.T, plan *Plan) string {
	t.Helper()
	var b strings.Builder
	writeSQLDump(context.Background(), &b, openTestConn(t), plan,
		Options{Structure: true, Data: false, DropFirst: true})
	return b.String()
}

// teardownSection returns everything the dump emits before its first CREATE —
// the teardown block, where every DROP under test lives.
func teardownSection(out string) string {
	if i := strings.Index(out, "CREATE"); i >= 0 {
		return out[:i]
	}
	return out
}

// TestTeardownGroupsSameClassCycle: the planner deliberately RESTORES a
// mutually-recursive routine pair (stub, then CREATE OR REPLACE), so the
// restored catalog holds a genuine cycle. Individual reverse-ordered DROPs each
// fail under RESTRICT — verified live: "cannot drop function ra(integer)
// because other objects depend on it" — and the importer aborts at that first
// error. One DROP listing both members drops them as a group instead.
func TestTeardownGroupsSameClassCycle(t *testing.T) {
	a := routineScript("s", "ra", "integer", "FUNCTION")
	b := routineScript("s", "rb", "integer", "FUNCTION")
	a.DependsOn = []string{b.Name}
	b.DependsOn = []string{a.Name}
	out := teardownDump(t, &Plan{objects: driver.DumpPlan{Routines: []driver.DumpScript{a, b}}})
	td := teardownSection(out)

	want := `DROP FUNCTION IF EXISTS "s"."ra"(integer), "s"."rb"(integer);`
	alt := `DROP FUNCTION IF EXISTS "s"."rb"(integer), "s"."ra"(integer);`
	if !strings.Contains(td, want) && !strings.Contains(td, alt) {
		t.Errorf("cycle must drop as ONE grouped statement; teardown:\n%s", td)
	}
	// ...and never additionally as individual drops.
	if strings.Contains(td, `DROP FUNCTION IF EXISTS "s"."ra"(integer);`) ||
		strings.Contains(td, `DROP FUNCTION IF EXISTS "s"."rb"(integer);`) {
		t.Errorf("grouped members must not also drop individually:\n%s", td)
	}
	if strings.Contains(out, "CASCADE") {
		t.Errorf("teardown must never escalate to CASCADE:\n%s", out)
	}
}

// TestTeardownGroupsMixedRoutineCycle: a function and an aggregate share no
// DROP class, but DROP ROUTINE covers both — with the FLAT input signature,
// the one spelling valid for every routine kind (an ordered-set aggregate's
// identity arguments render an ORDER BY split that only DROP AGGREGATE takes).
func TestTeardownGroupsMixedRoutineCycle(t *testing.T) {
	fn := routineScript("s", "sf", "bigint, double precision", "FUNCTION")
	agg := driver.DumpScript{
		Kind: "routine", Name: routineNode("s", "osa", "double precision ORDER BY double precision"),
		Comment: "Aggregate osa",
		Drop:    `DROP AGGREGATE IF EXISTS "s"."osa"(double precision ORDER BY double precision)`,
		DropForm: driver.DropForm{Class: "AGGREGATE",
			Ref:        `"s"."osa"(double precision ORDER BY double precision)`,
			RoutineRef: `"s"."osa"(double precision, double precision)`},
		SQL: `CREATE OR REPLACE AGGREGATE "s"."osa"(double precision ORDER BY double precision) (SFUNC = sf, STYPE = internal)`,
	}
	fn.DependsOn = []string{agg.Name}
	agg.DependsOn = []string{fn.Name}
	td := teardownSection(teardownDump(t, &Plan{objects: driver.DumpPlan{Routines: []driver.DumpScript{fn, agg}}}))

	if !strings.Contains(td, "DROP ROUTINE IF EXISTS ") {
		t.Fatalf("mixed routine-kind cycle must drop via DROP ROUTINE:\n%s", td)
	}
	if !strings.Contains(td, `"s"."osa"(double precision, double precision)`) {
		t.Errorf("DROP ROUTINE must use the FLAT input signature, not the ORDER BY identity:\n%s", td)
	}
	if strings.Contains(td, "ORDER BY") {
		t.Errorf("DROP ROUTINE must not carry an ORDER BY split:\n%s", td)
	}
	if !strings.Contains(td, `"s"."sf"(bigint, double precision)`) {
		t.Errorf("DROP ROUTINE must list the function too:\n%s", td)
	}
}

// TestTeardownRetainsMixedClassCycle: a base type and its I/O functions form a
// cycle no single DROP command spans (a DROP TYPE and a DROP FUNCTION cannot be
// merged), and CASCADE is forbidden. Verified live: dropping either member
// first fails. So BOTH drops are omitted and warned about — omitting only the
// DROP TYPE would leave a DROP FUNCTION that fails and aborts the restore.
//
// The type is emitted in two stages (shell, then the completing CREATE) exactly
// as a base type is emitted: collapsing them onto one logical object is what
// makes the cycle visible here at all.
func TestTeardownRetainsMixedClassCycle(t *testing.T) {
	shell := driver.DumpScript{
		Kind: "type", Name: "type-shell:s\x00bt", StageOf: "type:s\x00bt",
		Comment: "Shell for type bt", SQL: `CREATE TYPE "s"."bt"`,
	}
	in := routineScript("s", "bt_in", "cstring", "FUNCTION")
	in.DependsOn = []string{shell.Name} // its signature returns the shell type
	final := driver.DumpScript{
		Kind: "type", Name: "type-final:s\x00bt", StageOf: "type:s\x00bt",
		DependsOn: []string{shell.Name, in.Name},
		Comment:   "Type bt", Drop: `DROP TYPE IF EXISTS "s"."bt"`,
		DropForm: driver.DropForm{Class: "TYPE", Ref: `"s"."bt"`},
		SQL:      `CREATE TYPE "s"."bt" (INPUT = bt_in, OUTPUT = bt_out)`,
	}
	out := teardownDump(t, &Plan{objects: driver.DumpPlan{
		Types: []driver.DumpScript{shell, final}, Routines: []driver.DumpScript{in},
	}})
	td := teardownSection(out)

	if strings.Contains(td, `DROP TYPE IF EXISTS "s"."bt"`) {
		t.Errorf("a type in a type-versus-function cycle must NOT be dropped:\n%s", td)
	}
	if strings.Contains(td, `DROP FUNCTION IF EXISTS "s"."bt_in"`) {
		t.Errorf("the support function in the cycle must NOT be dropped either "+
			"(it fails under RESTRICT and aborts the restore):\n%s", td)
	}
	if !strings.Contains(out, "-- WARNING: drop-first teardown omits the DROP of ") {
		t.Errorf("a retained cycle must be warned about:\n%s", out)
	}
	if !strings.Contains(out, "Type bt") || !strings.Contains(out, "Function bt_in") {
		t.Errorf("the warning must NAME the retained objects:\n%s", out)
	}
}

// TestTeardownRetentionClosure: an object the dialect refuses to drop at all —
// PostgreSQL's operator FAMILY, whose DROP would take contained (possibly
// target-only) operator classes with it — SURVIVES the teardown, so every
// prerequisite it still holds becomes undroppable and must be omitted too.
func TestTeardownRetentionClosure(t *testing.T) {
	op := driver.DumpScript{
		Kind: "operator", Name: "operator:s\x00#\x0023\x0023",
		Comment: "Operator #", Drop: `DROP OPERATOR IF EXISTS "s".# (integer, integer)`,
		DropForm: driver.DropForm{Class: "OPERATOR", Ref: `"s".# (integer, integer)`},
		SQL:      `CREATE OPERATOR "s".# (FUNCTION = "s"."opfn", LEFTARG = integer, RIGHTARG = integer)`,
	}
	// The family carries no Drop by policy; its loose-member ALTER is a second
	// STAGE of the same object, so the members it holds ride its edges.
	fam := driver.DumpScript{
		Kind: "opfamily", Name: "opfamily:btree\x00s\x00f",
		Comment: "Operator family f USING btree",
		SQL:     `CREATE OPERATOR FAMILY "s"."f" USING "btree"`,
	}
	add := driver.DumpScript{
		Kind: "opfamily", Name: "opfamily-add:btree\x00s\x00f",
		StageOf: fam.Name, DependsOn: []string{fam.Name, op.Name},
		Comment: "Loose members of operator family f",
		SQL:     `ALTER OPERATOR FAMILY "s"."f" USING "btree" ADD OPERATOR 1 "s".# (integer, integer)`,
	}
	out := teardownDump(t, &Plan{objects: driver.DumpPlan{Routines: []driver.DumpScript{op, fam, add}}})
	td := teardownSection(out)

	if strings.Contains(td, "DROP OPERATOR FAMILY") {
		t.Errorf("an operator family's drop is never emitted:\n%s", td)
	}
	if strings.Contains(td, "DROP OPERATOR IF EXISTS") {
		t.Errorf("a retained family still holds its loose member: that DROP must be omitted:\n%s", td)
	}
	if !strings.Contains(out, "-- WARNING: drop-first teardown also omits the DROP of ") ||
		!strings.Contains(out, "Operator #") {
		t.Errorf("the retention closure must be warned about, naming the object:\n%s", out)
	}
	// Retention is warn-only: it never DE-LINKS a member (ALTER … DROP OPERATOR
	// addresses a slot, not the occupying member, so on an unknown populated
	// target it could remove a target-only member).
	if strings.Contains(td, "ALTER OPERATOR FAMILY") {
		t.Errorf("teardown must never de-link family members:\n%s", td)
	}
}

// TestTeardownRoutineDropOrdering: PostgreSQL routine drops belong in the
// REVERSE teardown, ahead of the types their signatures name — not inline above
// their own CREATE (the mysqldump shape, which a dialect opts into explicitly).
func TestTeardownRoutineDropOrdering(t *testing.T) {
	typ := driver.DumpScript{
		Kind: "type", Name: "type:s\x00mood", Comment: "Type mood",
		Drop: `DROP TYPE IF EXISTS "s"."mood"`, DropForm: driver.DropForm{Class: "TYPE", Ref: `"s"."mood"`},
		SQL: `CREATE TYPE "s"."mood" AS ENUM ('ok')`,
	}
	fn := routineScript("s", "usesmood", `"s"."mood"`, "FUNCTION")
	fn.DependsOn = []string{typ.Name}
	out := teardownDump(t, &Plan{objects: driver.DumpPlan{
		Types: []driver.DumpScript{typ}, Routines: []driver.DumpScript{fn},
	}})

	dropFn := strings.Index(out, `DROP FUNCTION IF EXISTS "s"."usesmood"`)
	dropType := strings.Index(out, `DROP TYPE IF EXISTS "s"."mood"`)
	createFn := strings.Index(out, `CREATE OR REPLACE FUNCTION "s"."usesmood"`)
	if dropFn < 0 || dropType < 0 || createFn < 0 {
		t.Fatalf("missing anchors (fn drop %d, type drop %d, fn create %d):\n%s", dropFn, dropType, createFn, out)
	}
	if dropFn > dropType {
		t.Errorf("a routine's drop must precede the DROP TYPE its signature names:\n%s", out)
	}
	if dropFn > createFn {
		t.Errorf("a PostgreSQL routine drop belongs in teardown, not inline above its CREATE:\n%s", out)
	}
	// Nothing is retained here, so both drops are emitted exactly once.
	if strings.Count(out, `DROP FUNCTION IF EXISTS "s"."usesmood"`) != 1 {
		t.Errorf("routine drop emitted more than once:\n%s", out)
	}
}

// routineScript builds a PostgreSQL-shaped routine script (identity arguments
// as the drop signature, the same list flat for a grouped DROP ROUTINE) with a
// stub, so a cycle among such scripts resolves on the CREATE side the way the resolver
// resolves it in production.
func routineScript(schema, name, args, class string) driver.DumpScript {
	q := `"` + schema + `"."` + name + `"`
	return driver.DumpScript{
		Kind: "routine", Name: routineNode(schema, name, args),
		Comment:  "Function " + name,
		Drop:     "DROP " + class + " IF EXISTS " + q + "(" + args + ")",
		DropForm: driver.DropForm{Class: class, Ref: q + "(" + args + ")", RoutineRef: q + "(" + args + ")"},
		Stub:     "CREATE FUNCTION " + q + "(" + args + ") RETURNS integer LANGUAGE sql AS 'SELECT NULL'",
		SQL:      "CREATE OR REPLACE FUNCTION " + q + "(" + args + ") RETURNS integer LANGUAGE sql AS $$SELECT 1$$",
	}
}

// routineNode mirrors the PostgreSQL dialect's routine node id (overloads must
// never collapse onto one node).
func routineNode(schema, name, args string) string {
	return "routine:" + schema + "\x00" + name + "\x00" + args
}
