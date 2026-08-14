package server_test

// Column reordering. MySQL/MariaDB are the only engines of the three with a
// statement for it, so the interesting cases are the two ends: the control must
// be absent where it cannot work, and the move must actually happen where it
// can. The live half reads the resulting column ORDER back from introspection —
// the only evidence that distinguishes "the clause was emitted" from "the
// column moved".

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestColumnPositionNotOfferedWithoutSupport: SQLite cannot reorder columns.
// The control must not be rendered, and — because a form is never the authority
// — a hand-posted position must be refused with a sentence rather than
// silently ignored by the dialect.
func TestColumnPositionNotOfferedWithoutSupport(t *testing.T) {
	ts, client, path := newTestServer(t)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+structureURL)
	if code != http.StatusOK {
		t.Fatalf("structure page = %d, want 200", code)
	}
	if strings.Contains(body, `name="col_after"`) {
		t.Error("the position control is offered on an engine that cannot reorder columns")
	}

	code, body = postStructureOp(t, client, ts.URL, url.Values{
		"action": {"add_column"}, "col_name": {"extra"}, "col_type": {"TEXT"},
		"col_nullable": {"1"}, "col_after": {"__first__"},
	})
	if code != http.StatusBadRequest {
		t.Errorf("positioned add = %d, want 400", code)
	}
	if !strings.Contains(body, "cannot reorder columns") {
		t.Errorf("the refusal does not explain itself:\n%.600s", body)
	}
	// Refused means refused: the column must not have been added unpositioned.
	if _, ok := findCol(sqliteColumns(t, path, "widgets"), "extra"); ok {
		t.Error("the column was added even though the placement was refused")
	}
}

func TestLiveMySQLColumnPosition(t *testing.T) {
	liveColumnPosition(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBColumnPosition(t *testing.T) {
	liveColumnPosition(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveColumnPosition adds a column at the FRONT of a table and then moves an
// existing one, asserting the resulting order each time. Asserting the emitted
// SQL would not distinguish a clause the server accepted and ignored.
func liveColumnPosition(t *testing.T, env liveEnv) {
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
	if _, err := conn.Exec(ctx, `CREATE TABLE `+conn.QualifiedName(ref)+
		` (id int PRIMARY KEY, a varchar(8), b varchar(8))`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if !conn.Capabilities().SupportsColumnPosition {
		t.Fatalf("%s reports no column positioning", env.label)
	}
	editor := conn.Dialect().(driver.SchemaEditor)
	modifier := conn.Dialect().(driver.ColumnModifier)
	run := func(what string, stmts []string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s build %s: %v", env.label, what, err)
		}
		if err := conn.ExecScript(ctx, stmts, false); err != nil {
			t.Fatalf("%s %s (%s): %v", env.label, what, strings.Join(stmts, "; "), err)
		}
	}
	order := func() []string {
		t.Helper()
		cols, err := conn.Columns(ctx, ref)
		if err != nil {
			t.Fatalf("columns: %v", err)
		}
		return colNames(cols)
	}

	stmts, err := editor.AddColumnSQL(ref, driver.ColumnSpec{
		Name: "head", Type: "varchar(8)", Nullable: true, Placement: driver.PlaceFirst,
	})
	run("add first", stmts, err)
	if got := order(); strings.Join(got, ",") != "head,id,a,b" {
		t.Errorf("%s after ADD ... FIRST the order is %v, want [head id a b]", env.label, got)
	}

	stmts, err = modifier.ModifyColumnSQL(ref, "a", driver.ColumnSpec{
		Name: "a", Type: "varchar(8)", Nullable: true,
		Placement: driver.PlaceAfter, PlacementAfter: "b",
	})
	run("modify after", stmts, err)
	if got := order(); strings.Join(got, ",") != "head,id,b,a" {
		t.Errorf("%s after MODIFY ... AFTER b the order is %v, want [head id b a]", env.label, got)
	}

	// A modify with no placement leaves the column where it is — otherwise every
	// ordinary column edit would silently reshuffle the table.
	stmts, err = modifier.ModifyColumnSQL(ref, "b", driver.ColumnSpec{
		Name: "b", Type: "varchar(16)", Nullable: true,
	})
	run("modify in place", stmts, err)
	if got := order(); strings.Join(got, ",") != "head,id,b,a" {
		t.Errorf("%s an unpositioned modify moved the column: %v", env.label, got)
	}
}
