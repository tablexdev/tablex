package server_test

// Column rename. The interesting property is not that the statement runs — it
// is that renaming is available on an engine that cannot MODIFY a column at
// all (SQLite), and that a rename changes ONLY the name: the alternative
// spelling on MySQL, CHANGE, restates the whole column, so an implementation
// that reached for it would silently drop every attribute the caller did not
// pass. These tests read the definition back from introspection rather than
// from the page, so that class of loss cannot hide behind rendering.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

const structureURL = "/db/main/table/widgets/structure"

// TestRenameColumnOfferedWithoutModify: SQLite implements ColumnRenamer and NOT
// ColumnModifier. If rename had been folded into the modify editor, the one
// engine whose only column edit IS a rename would offer nothing at all.
func TestRenameColumnOfferedWithoutModify(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+structureURL)
	if code != http.StatusOK {
		t.Fatalf("structure page = %d, want 200", code)
	}
	if !strings.Contains(body, `value="rename_column"`) {
		t.Error("rename is not offered on an engine that supports it")
	}
	if strings.Contains(body, `value="modify_column"`) {
		t.Error("SQLite cannot modify a column; the editor must stay hidden")
	}
}

// TestRenameColumn renames a column and verifies the schema followed — through
// introspection, not the rendered page.
func TestRenameColumn(t *testing.T) {
	ts, client, path := newTestServer(t)
	login(t, client, ts.URL)

	if code, body := postStructureOp(t, client, ts.URL, url.Values{
		"action": {"rename_column"}, "column": {"qty"}, "new_name": {"quantity"},
	}); code != http.StatusSeeOther {
		t.Fatalf("rename = %d, want 303:\n%.600s", code, body)
	}

	cols := sqliteColumns(t, path, "widgets")
	if _, ok := findCol(cols, "quantity"); !ok {
		t.Errorf("the renamed column is missing: %v", colNames(cols))
	}
	if _, ok := findCol(cols, "qty"); ok {
		t.Errorf("the old name survives: %v", colNames(cols))
	}
	// The rows are still there: a rename is not a rebuild.
	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if code != http.StatusOK || !strings.Contains(body, "bolt") {
		t.Errorf("browse after rename = %d; the data must survive", code)
	}
}

// TestRenameColumnKeepsTheDefinition is the CHANGE-vs-RENAME COLUMN guard: the
// renamed column must keep its type, its NOT NULL, and its index membership.
func TestRenameColumnKeepsTheDefinition(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `CREATE INDEX idx_name ON widgets (name)`)
	login(t, client, ts.URL)

	if code, body := postStructureOp(t, client, ts.URL, url.Values{
		"action": {"rename_column"}, "column": {"name"}, "new_name": {"label"},
	}); code != http.StatusSeeOther {
		t.Fatalf("rename = %d, want 303:\n%.600s", code, body)
	}

	c, ok := findCol(sqliteColumns(t, path, "widgets"), "label")
	if !ok {
		t.Fatal("the renamed column is missing")
	}
	if c.Nullable {
		t.Error("NOT NULL was lost — the rename restated the column instead of renaming it")
	}
	if !strings.EqualFold(c.BaseType, "text") {
		t.Errorf("the type changed to %q; a rename must not touch it", c.DataType)
	}

	// SQLite rewrites the index to follow the column. Whatever the engine does,
	// the index must not still name a column that no longer exists.
	conn := openSQLite(t, path)
	defer conn.Close()
	idxs, err := conn.Indexes(context.Background(), driver.TableRef{Table: "widgets"})
	if err != nil {
		t.Fatalf("indexes: %v", err)
	}
	for _, idx := range idxs {
		for _, ic := range idx.Columns {
			if ic.Name == "name" {
				t.Errorf("index %q still references the old column name", idx.Name)
			}
		}
	}
}

// TestRenameColumnRejects covers every refusal. Each case pins the MESSAGE, not
// only the status: a database error is also rendered as 400, so asserting the
// code alone would pass even with the validation deleted — the engine would
// simply refuse the same request one layer later, with its own wording and
// after the statement had already been built and sent.
func TestRenameColumnRejects(t *testing.T) {
	ts, client, path := newTestServer(t)
	login(t, client, ts.URL)

	for _, tc := range []struct{ name, col, newName, want string }{
		{"unknown column", "nope", "x", "Unknown column."},
		{"empty new name", "qty", "", "Invalid column name."},
		{"same name", "qty", "qty", "The new name is the same"},
		{"collides with another column", "qty", "name", "already exists"},
		// Case-insensitive collision: SQLite and MySQL cannot tell "NAME" from
		// "name", so accepting this would hand the user the engine's error.
		{"collides case-insensitively", "qty", "NAME", "already exists"},
		{"quote in the name", "qty", `a"b`, "Invalid column name."},
		{"statement in the name", "qty", "x; DROP TABLE widgets", "Invalid column name."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postStructureOp(t, client, ts.URL, url.Values{
				"action": {"rename_column"}, "column": {tc.col}, "new_name": {tc.newName},
			})
			if code != http.StatusBadRequest {
				t.Errorf("rename %q → %q = %d, want 400", tc.col, tc.newName, code)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("rename %q → %q: want the refusal to say %q, got:\n%.600s", tc.col, tc.newName, tc.want, body)
			}
		})
	}

	// Nothing above touched the table.
	if got := colNames(sqliteColumns(t, path, "widgets")); strings.Join(got, ",") != "id,name,qty" {
		t.Errorf("columns after the refused renames = %v, want [id name qty]", got)
	}
}

// --- helpers --------------------------------------------------------------------

// postStructureOp posts one structure-edit form and returns the status and body.
func postStructureOp(t *testing.T, client *http.Client, base string, form url.Values) (int, string) {
	t.Helper()
	form.Set("csrf_token", csrfFrom(t, client, base+"/"))
	resp, err := client.PostForm(base+structureURL, form)
	if err != nil {
		t.Fatalf("POST %s: %v", structureURL, err)
	}
	return resp.StatusCode, readBody(t, resp)
}

func openSQLite(t *testing.T, path string) *driver.Connection {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func execSQLite(t *testing.T, path, stmt string) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer conn.Close()
	if _, err := conn.Exec(context.Background(), stmt); err != nil {
		t.Fatalf("exec %q: %v", stmt, err)
	}
}

func sqliteColumns(t *testing.T, path, table string) []model.Column {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer conn.Close()
	cols, err := conn.Columns(context.Background(), driver.TableRef{Table: table})
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	return cols
}

func findCol(cols []model.Column, name string) (model.Column, bool) {
	for _, c := range cols {
		if c.Name == name {
			return c, true
		}
	}
	return model.Column{}, false
}

func colNames(cols []model.Column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Name
	}
	return out
}

func TestLiveMySQLRenameColumn(t *testing.T) {
	liveRenameColumn(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBRenameColumn(t *testing.T) {
	liveRenameColumn(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLivePostgresRenameColumn(t *testing.T) {
	liveRenameColumn(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveRenameColumn renames a column carrying every attribute the rename form
// does not collect — NOT NULL, a default, a comment, an index — and asserts all
// of them survive. On MySQL this is the difference between RENAME COLUMN and
// CHANGE: the latter would drop the comment and the default outright.
func liveRenameColumn(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, _ := driver.Get(env.engine)
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s: %v", env.label, err)
	}
	defer admin.Close()
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer conn.Close()

	ref := driver.TableRef{Database: liveDB, Table: "t"}
	if env.engine == "postgres" {
		ref.Schema = "public"
	}
	q := conn.QualifiedName(ref)
	for _, s := range []string{
		`CREATE TABLE ` + q + ` (id int PRIMARY KEY, tag varchar(32) NOT NULL DEFAULT 'x')`,
		`COMMENT ON COLUMN ` + q + `.tag IS 'the tag'`,
		`CREATE INDEX idx_tag ON ` + q + ` (tag)`,
		`INSERT INTO ` + q + ` (id, tag) VALUES (1, 'a')`,
	} {
		if env.engine != "postgres" && strings.HasPrefix(s, "COMMENT ON") {
			s = `ALTER TABLE ` + q + ` MODIFY tag varchar(32) NOT NULL DEFAULT 'x' COMMENT 'the tag'`
		}
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}

	if !conn.Capabilities().SupportsColumnRename {
		t.Fatalf("%s reports no column rename; the live container is below the supported floor", env.label)
	}
	renamer, ok := conn.Dialect().(driver.ColumnRenamer)
	if !ok {
		t.Fatalf("%s claims SupportsColumnRename but implements no ColumnRenamer", env.label)
	}
	stmts, err := renamer.RenameColumnSQL(ref, "tag", "label")
	if err != nil {
		t.Fatalf("build rename: %v", err)
	}
	if err := conn.ExecScript(ctx, stmts, conn.Capabilities().SupportsTransactionalDDL); err != nil {
		t.Fatalf("%s rename (%s): %v", env.label, strings.Join(stmts, "; "), err)
	}

	cols, err := conn.Columns(ctx, ref)
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	c, ok := findCol(cols, "label")
	if !ok {
		t.Fatalf("%s: the renamed column is missing: %v", env.label, colNames(cols))
	}
	if c.Nullable {
		t.Errorf("%s: NOT NULL was lost", env.label)
	}
	if c.Default == nil || !strings.Contains(*c.Default, "x") {
		t.Errorf("%s: the default was lost (%v)", env.label, c.Default)
	}
	if c.Comment != "the tag" {
		t.Errorf("%s: the comment was lost (%q)", env.label, c.Comment)
	}
	// The index followed the rename rather than being dropped.
	idxs, err := conn.Indexes(ctx, ref)
	if err != nil {
		t.Fatalf("indexes: %v", err)
	}
	found := false
	for _, idx := range idxs {
		for _, ic := range idx.Columns {
			if ic.Name == "label" {
				found = true
			}
			if ic.Name == "tag" {
				t.Errorf("%s: index %q still names the old column", env.label, idx.Name)
			}
		}
	}
	if !found {
		t.Errorf("%s: no index covers the renamed column; the rename dropped it", env.label)
	}
	// And the row is untouched.
	set, err := conn.Query(ctx, fmt.Sprintf("SELECT label FROM %s WHERE id = 1", q), 10)
	if err != nil {
		t.Fatalf("verify select: %v", err)
	}
	if len(set.Rows) != 1 {
		t.Errorf("%s: %d rows after rename, want 1", env.label, len(set.Rows))
	}
}
