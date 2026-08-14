package server_test

// Column metadata that only a real catalog can prove: PostgreSQL's attnum is a
// slot number, not an ordinal, and identity mode is now a typed model field
// rather than a magic string smuggled through Column.Extra.

import (
	"context"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/driver/drivertest"
	"github.com/tablexdev/tablex/internal/model"
)

// TestLive*TableCountMatchesListing is the B8 acceptance check for
// model.Database.TableCount: the databases page's number must equal the number
// of rows the database structure page shows for that database. MySQL counted
// every information_schema.TABLES row, including the MariaDB SEQUENCE objects
// that page deliberately skips.
//
// The MariaDB variant is the discriminating one — it seeds a SEQUENCE, which is
// the only relation kind the two numbers disagree about, and fails on the
// pre-fix query. MySQL 8.4 has no sequences, so its variant only guards the
// invariant against future drift.
func TestLiveMySQLTableCountMatchesListing(t *testing.T) {
	liveTableCountMatchesListing(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"), false)
}

func TestLiveMariaDBTableCountMatchesListing(t *testing.T) {
	liveTableCountMatchesListing(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"), true)
}

func liveTableCountMatchesListing(t *testing.T, env liveEnv, withSequence bool) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
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

	seed := []string{
		`CREATE TABLE t1 (id int)`,
		`CREATE TABLE t2 (id int)`,
		`CREATE VIEW v1 AS SELECT * FROM t1`,
	}
	if withSequence {
		seed = append(seed, `CREATE SEQUENCE s1`)
	}
	for _, s := range seed {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	if withSequence {
		// Guard the guard: if the sequence stopped being reported as one, the
		// test would silently lose the only case the two numbers disagree about.
		sequences := 0
		tbls, err := conn.ListTables(ctx, driver.Scope{Database: liveDB})
		if err != nil {
			t.Fatalf("ListTables: %v", err)
		}
		for _, tb := range tbls {
			if tb.IsSequence() {
				sequences++
			}
		}
		if sequences != 1 {
			t.Fatalf("seeded 1 sequence but ListTables reports %d; this test no longer discriminates", sequences)
		}
	}

	// Count the relations the structure page would list: everything ListTables
	// returns except the sequences that page skips.
	tables, err := conn.ListTables(ctx, driver.Scope{Database: liveDB})
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	listed := 0
	for _, tb := range tables {
		if !tb.IsSequence() {
			listed++
		}
	}

	dbs, err := admin.ListDatabases(ctx)
	if err != nil {
		t.Fatalf("ListDatabases: %v", err)
	}
	found := false
	for _, dbm := range dbs {
		if dbm.Name != liveDB {
			continue
		}
		found = true
		if dbm.TableCount != listed {
			t.Errorf("%s: TableCount = %d but the structure page lists %d relations", env.label, dbm.TableCount, listed)
		}
	}
	if !found {
		t.Fatalf("%s is not in ListDatabases", liveDB)
	}
}

// TestLivePostgresColumnMetadata is the B6/B8 acceptance check.
//
// Position: pg_attribute.attnum keeps its gaps after a DROP COLUMN, so a table
// that has lost its second column reports attnums 1, 3, 4 — which the structure
// page rendered raw. Every engine must report a contiguous 1..N ordinal.
//
// Identity: 'a'/'d' must land in Column.Identity as IdentityAlways /
// IdentityByDefault. Nothing may read those from Extra any more, which is what
// the dump path and the column editor used to do.
func TestLivePostgresColumnMetadata(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
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

	seed := []string{
		`CREATE TABLE gapped (
			a integer GENERATED ALWAYS AS IDENTITY,
			doomed text,
			b text,
			c integer GENERATED BY DEFAULT AS IDENTITY
		)`,
		`ALTER TABLE gapped DROP COLUMN doomed`,
	}
	for _, s := range seed {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}

	cols, err := conn.Columns(ctx, driver.TableRef{Schema: "public", Table: "gapped"})
	if err != nil {
		t.Fatalf("Columns: %v", err)
	}
	if len(cols) != 3 {
		t.Fatalf("got %d columns, want 3 (a, b, c)", len(cols))
	}
	for i, c := range cols {
		if c.Position != i+1 {
			var got []int
			for _, x := range cols {
				got = append(got, x.Position)
			}
			t.Fatalf("positions %v are not contiguous; the dropped column left an attnum gap", got)
		}
	}

	want := map[string]string{"a": model.IdentityAlways, "b": "", "c": model.IdentityByDefault}
	for _, c := range cols {
		if c.Identity != want[c.Name] {
			t.Errorf("column %q Identity = %q, want %q", c.Name, c.Identity, want[c.Name])
		}
		// The mode is typed now; the free-text cell must not carry a control value.
		if c.Extra != "" {
			t.Errorf("column %q leaked %q into Extra; Identity is the typed field", c.Name, c.Extra)
		}
		if got := c.ExtraDisplay(); c.Identity != "" && got == "" {
			t.Errorf("column %q shows nothing in the structure page's Extra cell", c.Name)
		}
	}
}

// TestLive*ConnectionConformance runs the shared driver conformance suite's
// connection half (drivertest.RunConnectionSuite) against a real server. It
// creates a table through the dialect's OWN DDL builders and asserts the
// engine-neutral model introspection returns is populated — contiguous column
// positions, a lower-cased BaseType, nullability and the primary key. SQLite
// runs the same function without Docker in internal/driver.
func TestLiveMySQLConnectionConformance(t *testing.T) {
	liveConnectionConformance(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBConnectionConformance(t *testing.T) {
	liveConnectionConformance(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLivePostgresConnectionConformance(t *testing.T) {
	liveConnectionConformance(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func liveConnectionConformance(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
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

	scope := driver.Scope{Database: liveDB}
	if conn.Capabilities().HasSchemas {
		scope.Schema = "public"
	}
	drivertest.RunConnectionSuite(t, conn, scope)
}
