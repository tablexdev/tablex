package server_test

// ENUM/SET against a real server. The unit tests in internal/server/handlers
// prove the assembled type is quoted correctly; only a live engine proves the
// result is a type MySQL will actually accept, that a hostile member is stored
// as data rather than executed, and that widening an ENUM keeps the rows that
// already used the old members.

import (
	"context"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

func TestLiveMySQLValueListColumns(t *testing.T) {
	liveValueListColumns(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBValueListColumns(t *testing.T) {
	liveValueListColumns(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func liveValueListColumns(t *testing.T, env liveEnv) {
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
	if _, err := conn.Exec(ctx, `CREATE TABLE `+conn.QualifiedName(ref)+` (id int PRIMARY KEY)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	typer, ok := conn.Dialect().(driver.ValueListTyper)
	if !ok {
		t.Fatalf("%s implements no ValueListTyper", env.label)
	}
	editor := conn.Dialect().(driver.SchemaEditor)

	// A member that tries to break out of its literal, alongside ordinary ones.
	// If the quoting were wrong this would not be a wrong value — it would be a
	// syntax error or an extra statement.
	hostile := `x'),('pwned`
	enumType, err := typer.ValueListType("ENUM", []string{"small", "large", hostile})
	if err != nil {
		t.Fatalf("build ENUM: %v", err)
	}
	setType, err := typer.ValueListType("SET", []string{"read", "write"})
	if err != nil {
		t.Fatalf("build SET: %v", err)
	}
	for _, spec := range []driver.ColumnSpec{
		{Name: "size", Type: enumType, Nullable: true},
		{Name: "perms", Type: setType, Nullable: true},
	} {
		stmts, err := editor.AddColumnSQL(ref, spec)
		if err != nil {
			t.Fatalf("AddColumnSQL %s: %v", spec.Name, err)
		}
		if err := conn.ExecScript(ctx, stmts, false); err != nil {
			t.Fatalf("%s add %s (%s): %v", env.label, spec.Name, strings.Join(stmts, "; "), err)
		}
	}

	cols, err := conn.Columns(ctx, ref)
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	size, ok := findCol(cols, "size")
	if !ok {
		t.Fatal("the ENUM column is missing")
	}
	if !strings.EqualFold(size.BaseType, "enum") {
		t.Errorf("size.BaseType = %q, want enum", size.BaseType)
	}
	// The hostile member came back as ONE member, holding exactly what was
	// asked for — the round trip through the catalog is the proof.
	if !strings.Contains(size.DataType, "pwned") {
		t.Errorf("the adversarial member is missing from %q", size.DataType)
	}

	// It is a value, so a row can hold it, and a member that was never declared
	// is rejected by the server.
	q := conn.Dialect().QuoteString
	if _, err := conn.Exec(ctx, `INSERT INTO `+conn.QualifiedName(ref)+
		` (id, size, perms) VALUES (1, `+q(hostile)+`, `+q("read,write")+`)`); err != nil {
		t.Fatalf("%s insert the adversarial member: %v", env.label, err)
	}
	set, err := conn.Query(ctx, `SELECT size FROM `+conn.QualifiedName(ref)+` WHERE id = 1`, 10)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(set.Rows) != 1 || set.Rows[0][0].Str != hostile {
		t.Errorf("%s stored %+v, want the member verbatim", env.label, set.Rows)
	}

	// Widening the ENUM keeps the existing rows: the members already in use are
	// still in the new list.
	widened, err := typer.ValueListType("ENUM", []string{"small", "medium", "large", hostile})
	if err != nil {
		t.Fatalf("widen: %v", err)
	}
	stmts, err := conn.Dialect().(driver.ColumnModifier).ModifyColumnSQL(ref, "size",
		driver.ColumnSpec{Name: "size", Type: widened, Nullable: true})
	if err != nil {
		t.Fatalf("ModifyColumnSQL: %v", err)
	}
	if err := conn.ExecScript(ctx, stmts, false); err != nil {
		t.Fatalf("%s widen (%s): %v", env.label, strings.Join(stmts, "; "), err)
	}
	set, err = conn.Query(ctx, `SELECT size FROM `+conn.QualifiedName(ref)+` WHERE id = 1`, 10)
	if err != nil {
		t.Fatalf("select after widen: %v", err)
	}
	if len(set.Rows) != 1 || set.Rows[0][0].Str != hostile {
		t.Errorf("%s: widening the ENUM lost the row's value: %+v", env.label, set.Rows)
	}
	// And the table is still there — nothing in the member list ran as SQL.
	if _, err := conn.Query(ctx, `SELECT id FROM `+conn.QualifiedName(ref), 10); err != nil {
		t.Errorf("%s: the table is gone; a member escaped its literal: %v", env.label, err)
	}
}
