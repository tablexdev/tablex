package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

func TestFKAction(t *testing.T) {
	cases := map[string]string{"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT", "?": ""}
	for in, want := range cases {
		if got := fkAction(in); got != want {
			t.Errorf("fkAction(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCanonicalBaseType pins the pg_type.typname → canonical-name mapping (H3):
// the alias spellings must map to entries that exist in ColumnTypes(), else the
// modify-column form silently selects option #0 (a possible narrowing rewrite).
func TestCanonicalBaseType(t *testing.T) {
	cases := map[string]string{
		"int2":   "smallint",
		"int4":   "integer",
		"int8":   "bigint",
		"float4": "real",
		"float8": "double precision",
		"bool":   "boolean",
		"bpchar": "char",
		// Un-normalized (already canonical in ColumnTypes()).
		"timetz": "timetz",
		"bit":    "bit",
		"varbit": "varbit",
		"text":   "text",
		"jsonb":  "jsonb",
	}
	allow := make(map[string]bool)
	for _, ct := range (dialect{}).ColumnTypes() {
		allow[ct] = true
	}
	for in, want := range cases {
		got := canonicalBaseType(in)
		if got != want {
			t.Errorf("canonicalBaseType(%q) = %q, want %q", in, got, want)
		}
		// Every normalizer output for a real introspected type must be in the
		// allowlist so the form's <option> sync finds a match.
		if !allow[got] {
			t.Errorf("canonicalBaseType(%q) = %q not in ColumnTypes()", in, got)
		}
	}
}

// TestDecodeTriggerType pins the pg_trigger.tgtype bitmask decoding (#32): the
// timing and event list now come from the catalog bits, not a scan of the
// rendered DDL text (which could embed " ON " or keywords in a quoted name).
func TestDecodeTriggerType(t *testing.T) {
	const (
		row      = 1 << 0
		before   = 1 << 1
		insert   = 1 << 2
		del      = 1 << 3
		update   = 1 << 4
		truncate = 1 << 5
		instead  = 1 << 6
	)
	cases := []struct {
		tgtype     int
		wantTiming string
		wantEvent  string
	}{
		{row | before | insert, "BEFORE", "INSERT"},
		{row | insert, "AFTER", "INSERT"},          // no BEFORE bit => AFTER
		{instead | update, "INSTEAD OF", "UPDATE"}, // INSTEAD wins over BEFORE
		{row | before | insert | update | del, "BEFORE", "INSERT, UPDATE, DELETE"},
		{truncate, "AFTER", "TRUNCATE"},
	}
	for _, c := range cases {
		timing, event := decodeTriggerType(c.tgtype)
		if timing != c.wantTiming || event != c.wantEvent {
			t.Errorf("decodeTriggerType(%#x) = (%q, %q), want (%q, %q)",
				c.tgtype, timing, event, c.wantTiming, c.wantEvent)
		}
	}
}

func TestSchemaOf(t *testing.T) {
	if schemaOf(driver.TableRef{}) != "public" {
		t.Error("empty schema should default to public")
	}
	if schemaOf(driver.TableRef{Schema: "sales"}) != "sales" {
		t.Error("explicit schema should be kept")
	}
}

// TestSearchExpr pins the LIKE text-cast: PostgreSQL's LIKE takes text only,
// so uuid/json/bool/enum/inet/array columns need the cast or the whole query
// errors (dropping tables from database search, failing table search).
func TestSearchExpr(t *testing.T) {
	var d any = dialect{}
	sc, ok := d.(driver.SearchCaster)
	if !ok {
		t.Fatal("postgres dialect must implement driver.SearchCaster")
	}
	if got := sc.SearchExpr(`"user_id"`); got != `"user_id"::text` {
		t.Errorf("SearchExpr = %q, want \"user_id\"::text", got)
	}
}

// TestBuildDSNIPv6Host covers 1.2: an IPv6 literal host must be bracketed in
// the DSN authority ([::1]:5432) — the bare "::1:5432" concatenation
// mis-parses (silently wrong host for ::1, hard failure for most literals).
// Hostnames and IPv4 stay unbracketed.
func TestBuildDSNIPv6Host(t *testing.T) {
	cases := []struct{ host, wantAuthority string }{
		{"::1", "[::1]:5433"},
		{"2001:db8::7", "[2001:db8::7]:5433"},
		{"127.0.0.1", "127.0.0.1:5433"},
		{"db.example.com", "db.example.com:5433"},
		// An already-bracketed literal must come out single-bracketed —
		// JoinHostPort alone would produce the unresolvable "[[::1]]:5433".
		{"[::1]", "[::1]:5433"},
		{"[2001:db8::7]", "[2001:db8::7]:5433"},
	}
	for _, c := range cases {
		dsn, err := dialect{}.BuildDSN(driver.ConnParams{Host: c.host, Port: 5433, User: "u", Database: "db"})
		if err != nil {
			t.Fatalf("BuildDSN(%q): %v", c.host, err)
		}
		if !strings.Contains(dsn, "@"+c.wantAuthority+"/") {
			t.Errorf("BuildDSN(%q) authority = %q, want %q", c.host, dsn, c.wantAuthority)
		}
	}
}

func TestDSNEscapesCredentials(t *testing.T) {
	// A password with URL-special characters must be percent-encoded, not raw.
	dsn, err := dialect{}.BuildDSN(driver.ConnParams{Host: "h", Port: 5432, User: "u", Password: "p@ss:w/rd?", Database: "db"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dsn, "p@ss:w/rd?") {
		t.Errorf("password not escaped in DSN: %q", dsn)
	}
	if !strings.HasPrefix(dsn, "postgres://") {
		t.Errorf("unexpected DSN scheme: %q", dsn)
	}
}

// TestBuildDSNRejectsReservedParams pins: sslmode and connect_timeout are
// computed by the dialect, so a same-named Params entry that would silently
// override them is rejected (parity with the MySQL dialect's tls rejection).
// Other keys — including libpq "options" (the export session's search_path pin)
// — still pass through.
func TestBuildDSNRejectsReservedParams(t *testing.T) {
	for _, k := range []string{"sslmode", "connect_timeout", "SSLMode", "Connect_Timeout"} {
		_, err := dialect{}.BuildDSN(driver.ConnParams{
			Host: "h", Port: 5432, User: "u", Database: "db",
			Params: map[string]string{k: "x"},
		})
		if err == nil {
			t.Errorf("BuildDSN with Params[%q] should be rejected", k)
		}
	}
	// "options" (and other arbitrary keys) must still compose.
	dsn, err := dialect{}.BuildDSN(driver.ConnParams{
		Host: "h", Port: 5432, User: "u", Database: "db",
		Params: map[string]string{"options": "-c search_path="},
	})
	if err != nil {
		t.Fatalf("BuildDSN with options param: %v", err)
	}
	if !strings.Contains(dsn, "options=") {
		t.Errorf("options param not passed through: %q", dsn)
	}
}

// TestReturningMergeGate pins: MERGE … RETURNING is PostgreSQL 17+, gated
// via the major version WithServerInfo parses; INSERT/UPDATE/DELETE RETURNING is
// always on. An unparseable/absent version fails the MERGE gate closed.
func TestReturningMergeGate(t *testing.T) {
	prof := func(ver string) driver.ReturningCaps {
		d := dialect{}.WithServerInfo(driver.ServerInfo{Version: ver})
		return d.(driver.StatementLexer).LexerProfile().Returning
	}
	for _, ver := range []string{"16.2", "13.9", ""} {
		rc := prof(ver)
		if rc.Merge {
			t.Errorf("PG %q: Merge RETURNING should be gated off", ver)
		}
		if !rc.Insert || !rc.Update || !rc.Delete {
			t.Errorf("PG %q: INSERT/UPDATE/DELETE RETURNING should always be on: %+v", ver, rc)
		}
		if rc.Replace {
			t.Errorf("PG %q: no REPLACE statement, should be off", ver)
		}
	}
	for _, ver := range []string{"17.0", "18.1"} {
		if !prof(ver).Merge {
			t.Errorf("PG %q: Merge RETURNING should be on", ver)
		}
	}
	if got := pgMajorVersion("17.2"); got != 17 {
		t.Errorf("pgMajorVersion(17.2) = %d, want 17", got)
	}
	if got := pgMajorVersion("garbage"); got != 0 {
		t.Errorf("pgMajorVersion(garbage) = %d, want 0 (fail closed)", got)
	}
}

func TestPlaceholderNumbering(t *testing.T) {
	d := dialect{}
	if d.Placeholder(1) != "$1" || d.Placeholder(10) != "$10" {
		t.Errorf("placeholders: %q %q", d.Placeholder(1), d.Placeholder(10))
	}
}

func ptr(s string) *string { return &s }

func TestPostgresSchemaEditorSQL(t *testing.T) {
	d := dialect{}
	tr := driver.TableRef{Schema: "public", Table: "items"}

	eq := func(name string, got []string, err error, want ...string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: builder error: %v", name, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got %d statements %v, want %d", name, len(got), got, len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s[%d]:\n got %q\nwant %q", name, i, got[i], want[i])
			}
		}
	}

	g, err := d.AddColumnSQL(tr, driver.ColumnSpec{Name: "n", Type: "integer", Default: ptr("0")})
	eq("add", g, err, `ALTER TABLE "public"."items" ADD COLUMN "n" integer NOT NULL DEFAULT 0`)

	g, err = d.AddColumnSQL(tr, driver.ColumnSpec{Name: "note", Type: "text", Nullable: true, Comment: "c"})
	eq("add+comment", g, err,
		`ALTER TABLE "public"."items" ADD COLUMN "note" text`,
		`COMMENT ON COLUMN "public"."items"."note" IS 'c'`)

	// Modify expands to ordered ALTER COLUMN steps: drop default, type (USING
	// cast), set NOT NULL, set the new default, then clear the comment (an emptied
	// comment field must CLEAR any existing comment, not silently keep it).
	g, err = d.ModifyColumnSQL(tr, "n", driver.ColumnSpec{Name: "n", Type: "bigint", Default: ptr("0")})
	eq("modify", g, err,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" DROP DEFAULT`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" TYPE bigint USING "n"::bigint`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" SET NOT NULL`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" SET DEFAULT 0`,
		`COMMENT ON COLUMN "public"."items"."n" IS NULL`)

	// Nullable modify without a default omits SET NOT NULL and SET DEFAULT.
	g, err = d.ModifyColumnSQL(tr, "n", driver.ColumnSpec{Name: "n", Type: "text", Nullable: true})
	eq("modify nullable", g, err,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" DROP DEFAULT`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" TYPE text USING "n"::text`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" DROP NOT NULL`,
		`COMMENT ON COLUMN "public"."items"."n" IS NULL`)

	// Identity columns have no separate default: DROP DEFAULT and SET DEFAULT
	// are hard errors, so both steps are skipped (the identity is untouched).
	g, err = d.ModifyColumnSQL(tr, "id", driver.ColumnSpec{Name: "id", Type: "bigint", Identity: "always", Default: ptr("0")})
	eq("modify identity", g, err,
		`ALTER TABLE "public"."items" ALTER COLUMN "id" TYPE bigint USING "id"::bigint`,
		`ALTER TABLE "public"."items" ALTER COLUMN "id" SET NOT NULL`,
		`COMMENT ON COLUMN "public"."items"."id" IS NULL`)

	// A comment set on modify emits the COMMENT statement instead of IS NULL.
	g, err = d.ModifyColumnSQL(tr, "n", driver.ColumnSpec{Name: "n", Type: "text", Nullable: true, Comment: "hi"})
	eq("modify with comment", g, err,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" DROP DEFAULT`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" TYPE text USING "n"::text`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" DROP NOT NULL`,
		`COMMENT ON COLUMN "public"."items"."n" IS 'hi'`)

	// A same-base change (length/precision only) omits the USING cast so a shrink
	// errors on overflow instead of silently truncating.
	g, err = d.ModifyColumnSQL(tr, "n", driver.ColumnSpec{Name: "n", Type: "varchar(100)", Nullable: true, SameBaseType: true})
	eq("modify same base", g, err,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" DROP DEFAULT`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" TYPE varchar(100)`,
		`ALTER TABLE "public"."items" ALTER COLUMN "n" DROP NOT NULL`,
		`COMMENT ON COLUMN "public"."items"."n" IS NULL`)

	g, err = d.DropColumnSQL(tr, "n")
	eq("drop", g, err, `ALTER TABLE "public"."items" DROP COLUMN "n"`)

	plain := []driver.IndexColumn{{Name: "a"}, {Name: "b"}}
	g, err = d.AddIndexSQL(tr, driver.IndexSpec{Name: "idx_ab", Columns: plain})
	eq("add index", g, err, `CREATE INDEX "idx_ab" ON "public"."items" ("a", "b")`)

	g, err = d.AddIndexSQL(tr, driver.IndexSpec{Name: "u", Columns: plain[:1], Unique: true})
	eq("add unique index", g, err, `CREATE UNIQUE INDEX "u" ON "public"."items" ("a")`)

	// USING precedes the key list; the predicate follows it. Both are validated
	// by the handler — the method against IndexOptions().Methods, the predicate
	// as a single expression — so the builder only places them.
	g, err = d.AddIndexSQL(tr, driver.IndexSpec{
		Name: "idx_g", Columns: []driver.IndexColumn{{Name: "doc"}}, Method: "gin",
	})
	eq("add index using", g, err, `CREATE INDEX "idx_g" ON "public"."items" USING gin ("doc")`)

	g, err = d.AddIndexSQL(tr, driver.IndexSpec{
		Name: "idx_w", Columns: []driver.IndexColumn{{Name: "a", Desc: true}}, Where: "qty > 0",
	})
	eq("add partial index", g, err, `CREATE INDEX "idx_w" ON "public"."items" ("a" DESC) WHERE qty > 0`)

	// DROP INDEX is schema-scoped in PostgreSQL, so the index name is qualified.
	g, err = d.DropIndexSQL(tr, "idx_ab")
	eq("drop index", g, err, `DROP INDEX "public"."idx_ab"`)

	g, err = d.AddForeignKeySQL(tr, "fk1", []string{"author_id"}, "authors", []string{"id"}, "CASCADE", "")
	eq("add fk", g, err,
		`ALTER TABLE "public"."items" ADD CONSTRAINT "fk1" FOREIGN KEY ("author_id") REFERENCES "public"."authors" ("id") ON UPDATE CASCADE`)

	g, err = d.DropForeignKeySQL(tr, "fk1")
	eq("drop fk", g, err, `ALTER TABLE "public"."items" DROP CONSTRAINT "fk1"`)

	// Adversarial identifiers are quoted (double-quote doubled), not rejected.
	g, err = d.DropColumnSQL(driver.TableRef{Schema: "public", Table: "t"}, `a"b`)
	eq("adversarial", g, err, `ALTER TABLE "public"."t" DROP COLUMN "a""b"`)

	// M6: object DROP/RENAME route to the right statement per object kind.
	g, err = d.DropObjectSQL(tr, driver.ObjectTable)
	eq("drop table", g, err, `DROP TABLE "public"."items"`)
	g, err = d.DropObjectSQL(tr, driver.ObjectView)
	eq("drop view", g, err, `DROP VIEW "public"."items"`)
	g, err = d.DropObjectSQL(tr, driver.ObjectMatView)
	eq("drop matview", g, err, `DROP MATERIALIZED VIEW "public"."items"`)
	g, err = d.RenameObjectSQL(tr, "renamed", driver.ObjectTable)
	eq("rename table", g, err, `ALTER TABLE "public"."items" RENAME TO "renamed"`)
	g, err = d.RenameObjectSQL(tr, "renamed", driver.ObjectView)
	eq("rename view", g, err, `ALTER TABLE "public"."items" RENAME TO "renamed"`)
	g, err = d.RenameObjectSQL(tr, "renamed", driver.ObjectMatView)
	eq("rename matview", g, err, `ALTER MATERIALIZED VIEW "public"."items" RENAME TO "renamed"`)
}

// TestPGCreateTableSQL pins the exact statements the SchemaEditor emits: one
// CREATE TABLE with the PK as a table constraint, then COMMENT ON COLUMN
// statements (comments are not part of the PostgreSQL column grammar) — the
// same split AddColumnSQL uses via the shared columnDef.
func TestPGCreateTableSQL(t *testing.T) {
	d := dialect{}
	tr := driver.TableRef{Schema: "public", Table: "orders"}
	got, err := d.CreateTableSQL(tr, []driver.ColumnSpec{
		{Name: "id", Type: "integer"},
		{Name: "note", Type: "text", Nullable: true, Comment: "hi"},
	}, []string{"id"})
	if err != nil {
		t.Fatalf("CreateTableSQL: %v", err)
	}
	want := []string{
		"CREATE TABLE \"public\".\"orders\" (\n  \"id\" integer NOT NULL,\n  \"note\" text,\n  PRIMARY KEY (\"id\")\n)",
		`COMMENT ON COLUMN "public"."orders"."note" IS 'hi'`,
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("CreateTableSQL:\n got %q\nwant %q", got, want)
	}

	if _, err := d.CreateTableSQL(tr, nil, nil); err == nil {
		t.Error("empty column list should error")
	}
	if _, err := d.CreateTableSQL(tr, []driver.ColumnSpec{{Name: "id", Type: "integer"}}, []string{"ghost"}); err == nil {
		t.Error("pk entry not among the columns should error")
	}
}

// TestPGUserAndPrivilegeSQL pins the exact DCL the UserManager /
// PrivilegeManager builders emit: roles are identifiers (QuoteIdent), PUBLIC is
// the bare pseudo-role keyword (never a quoted identifier), passwords are
// string literals, grant privileges are validated against the scope allowlist
// while revoke accepts any keyword shape (introspection-driven — PG 17
// MAINTAIN stays revokable), and injection shapes are rejected.
func TestPGUserAndPrivilegeSQL(t *testing.T) {
	d := dialect{}
	one := func(got []string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("builder error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 statement, got %d: %v", len(got), got)
		}
		return got[0]
	}
	fails := func(got []string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("expected error, got statements %v", got)
		}
	}

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"create role with attributes and password",
			one(d.CreateUserSQL(driver.UserSpec{Name: "carol", CanLogin: true, Password: "it''s", SetPassword: true})),
			`CREATE ROLE "carol" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD 'it''''s'`},
		{"create role blank password becomes PASSWORD NULL",
			one(d.CreateUserSQL(driver.UserSpec{Name: "carol", CanLogin: true, SetPassword: true})),
			`CREATE ROLE "carol" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD NULL`},
		{"set password is password-only (attributes untouched)",
			one(d.AlterUserSQL(driver.UserSpec{Name: "carol", Password: "x", SetPassword: true})),
			`ALTER ROLE "carol" WITH PASSWORD 'x'`},
		{"alter attributes emits both polarities",
			one(d.AlterUserSQL(driver.UserSpec{Name: "carol", CanLogin: true, CreateDB: true})),
			`ALTER ROLE "carol" WITH LOGIN NOSUPERUSER CREATEDB NOCREATEROLE`},
		{"drop role",
			one(d.DropUserSQL("carol", "")),
			`DROP ROLE "carol"`},
		{"role name quoted as identifier",
			one(d.DropUserSQL(`ro"le`, "")),
			`DROP ROLE "ro""le"`},
		{"grant database scope",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"connect"}, Database: "shop", Grantee: "carol"})),
			`GRANT CONNECT ON DATABASE "shop" TO "carol"`},
		{"grant table scope defaults schema to public",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT", "UPDATE"}, Database: "shop", Table: "items", Grantee: "carol", WithGrant: true})),
			`GRANT SELECT, UPDATE ON TABLE "public"."items" TO "carol" WITH GRANT OPTION`},
		{"grant to PUBLIC emits the bare keyword",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Schema: "app", Table: "items", Grantee: "PUBLIC"})),
			`GRANT SELECT ON TABLE "app"."items" TO PUBLIC`},
		{"grant db default to PUBLIC without grant option succeeds",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"CONNECT"}, Database: "shop", Grantee: "PUBLIC"})),
			`GRANT CONNECT ON DATABASE "shop" TO PUBLIC`},
		{"revoke database default from PUBLIC",
			one(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"CONNECT"}, Database: "shop", Grantee: "PUBLIC"})),
			`REVOKE CONNECT ON DATABASE "shop" FROM PUBLIC`},
		// Revoke is keyword-gated, not allowlist-gated: MAINTAIN (PG 17) is
		// absent from the grant allowlist but must stay revokable.
		{"revoke accepts MAINTAIN outside the grant allowlist",
			one(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"MAINTAIN"}, Database: "shop", Table: "items", Grantee: "carol"})),
			`REVOKE MAINTAIN ON TABLE "public"."items" FROM "carol"`},
		// Column scope. The list is repeated per privilege because that is the
		// grammar: "SELECT, UPDATE (a)" grants SELECT on the whole table.
		{"grant one column",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Schema: "app", Table: "items",
				Grantee: "carol", Columns: []string{"price"}})),
			`GRANT SELECT ("price") ON TABLE "app"."items" TO "carol"`},
		{"grant repeats the column list per privilege",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT", "UPDATE"}, Database: "shop", Table: "items",
				Grantee: "carol", Columns: []string{"price", "sku"}})),
			`GRANT SELECT ("price", "sku"), UPDATE ("price", "sku") ON TABLE "public"."items" TO "carol"`},
		{"column names are quoted, not interpolated",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Table: "items",
				Grantee: "carol", Columns: []string{`a"b`}})),
			`GRANT SELECT ("a""b") ON TABLE "public"."items" TO "carol"`},
		{"column grant to PUBLIC",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Table: "items",
				Grantee: "PUBLIC", Columns: []string{"price"}})),
			`GRANT SELECT ("price") ON TABLE "public"."items" TO PUBLIC`},
		{"revoke one column",
			one(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Table: "items",
				Grantee: "carol", Columns: []string{"price"}})),
			`REVOKE SELECT ("price") ON TABLE "public"."items" FROM "carol"`},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}

	// CONNECT is a valid db-scope privilege, so this reaches (and exercises) the
	// PUBLIC+WithGrant guard rather than being rejected earlier by the allowlist;
	// the positive "grant to PUBLIC without grant option" case above shares
	// everything but WithGrant, isolating the guard as the cause.
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"CONNECT"}, Database: "shop", Grantee: "PUBLIC", WithGrant: true})) // grant options cannot go to PUBLIC
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"CONNECT"}, Database: "shop", Table: "items", Grantee: "carol"}))   // db-only priv at table scope
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"MAINTAIN"}, Database: "shop", Table: "items", Grantee: "carol"}))  // outside the offerable set
	fails(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT; DROP TABLE x"}, Database: "shop", Grantee: "carol"}))     // injection shape
	fails(d.RevokeSQL(driver.GrantSpec{Privileges: nil, Database: "shop", Grantee: "carol"}))                                  // empty set
	// Column scope: both unexpressible shapes must error rather than fall back
	// to the wider object-wide statement.
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"CONNECT"}, Database: "shop", Grantee: "carol",
		Columns: []string{"price"}})) // DATABASE takes no column list
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"DELETE"}, Database: "shop", Table: "items", Grantee: "carol",
		Columns: []string{"price"}})) // DELETE has no column form
	fails(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"CONNECT"}, Database: "shop", Grantee: "carol",
		Columns: []string{"price"}})) // revoke keeps the target rule too
}

// TestPGRoutineGrantSQL pins the routine-grant builders. The identity-argument
// list is the load-bearing part: PostgreSQL allows overloading, so a GRANT that
// named only the function would either fail as ambiguous or, worse, land on the
// wrong overload. It rides through verbatim — it is server-generated catalog
// text with its own quoting, not an identifier this dialect could quote — which
// is the same contract DropRoutineSQL documents.
func TestPGRoutineGrantSQL(t *testing.T) {
	d := dialect{}
	one := func(stmts []string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("builder error: %v", err)
		}
		if len(stmts) != 1 {
			t.Fatalf("expected 1 statement, got %d: %q", len(stmts), stmts)
		}
		return stmts[0]
	}
	fn := model.Routine{Name: "calc", Type: "FUNCTION", ArgSignature: "integer, text"}
	proc := model.Routine{Name: "do_it", Type: "PROCEDURE"}
	scope := driver.Scope{Database: "shop", Schema: "app"}
	for _, c := range []struct{ name, got, want string }{
		{"grant execute on a function, with its identity args",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"execute"}, Grantee: "carol"})),
			`GRANT EXECUTE ON FUNCTION "app"."calc"(integer, text) TO "carol"`},
		{"a zero-argument routine keeps the empty parens",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: proc, Privileges: []string{"EXECUTE"}, Grantee: "carol"})),
			`GRANT EXECUTE ON PROCEDURE "app"."do_it"() TO "carol"`},
		{"schema defaults to public",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: driver.Scope{Database: "shop"}, Routine: proc, Privileges: []string{"EXECUTE"}, Grantee: "carol"})),
			`GRANT EXECUTE ON PROCEDURE "public"."do_it"() TO "carol"`},
		{"PUBLIC is the bare keyword here too",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"EXECUTE"}, Grantee: "PUBLIC"})),
			`GRANT EXECUTE ON FUNCTION "app"."calc"(integer, text) TO PUBLIC`},
		{"grant option",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"EXECUTE"}, Grantee: "carol", WithGrant: true})),
			`GRANT EXECUTE ON FUNCTION "app"."calc"(integer, text) TO "carol" WITH GRANT OPTION`},
		{"revoke", one(d.RevokeRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"EXECUTE"}, Grantee: "carol"})),
			`REVOKE EXECUTE ON FUNCTION "app"."calc"(integer, text) FROM "carol"`},
		{"name is quoted as an identifier",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: model.Routine{Name: `ca"lc`, Type: "FUNCTION"}, Privileges: []string{"EXECUTE"}, Grantee: "carol"})),
			`GRANT EXECUTE ON FUNCTION "app"."ca""lc"() TO "carol"`},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
	// SELECT is a table privilege; a routine has only EXECUTE.
	if stmts, err := d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"SELECT"}, Grantee: "carol"}); err == nil {
		t.Errorf("GrantRoutineSQL(SELECT) = %q, want an error", stmts)
	}
	if stmts, err := d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Grantee: "PUBLIC", Privileges: []string{"EXECUTE"}, WithGrant: true}); err == nil {
		t.Errorf("GrantRoutineSQL(PUBLIC WITH GRANT OPTION) = %q, want an error", stmts)
	}
}

// TestPGRoleMembershipSQL pins the role-membership builders. PostgreSQL has no
// host component, so both ends are plain quoted identifiers; PUBLIC is refused
// because it is a grantee for object privileges but not a role — quoting it
// would target a role that cannot exist.
func TestPGRoleMembershipSQL(t *testing.T) {
	d := dialect{}
	one := func(stmts []string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("builder error: %v", err)
		}
		if len(stmts) != 1 {
			t.Fatalf("expected 1 statement, got %d: %q", len(stmts), stmts)
		}
		return stmts[0]
	}
	for _, c := range []struct{ name, got, want string }{
		{"grant role", one(d.GrantRoleSQL(driver.RoleGrant{Role: "readers", Member: "carol"})),
			`GRANT "readers" TO "carol"`},
		{"grant role with admin option", one(d.GrantRoleSQL(driver.RoleGrant{Role: "readers", Member: "carol", AdminOption: true})),
			`GRANT "readers" TO "carol" WITH ADMIN OPTION`},
		{"names are quoted as identifiers", one(d.GrantRoleSQL(driver.RoleGrant{Role: `re"ad`, Member: "carol"})),
			`GRANT "re""ad" TO "carol"`},
		{"revoke role ignores the admin option", one(d.RevokeRoleSQL(driver.RoleGrant{Role: "readers", Member: "carol", AdminOption: true})),
			`REVOKE "readers" FROM "carol"`},
		// The host fields exist for MySQL 8 and must be inert here, not
		// smuggled into the identifier.
		{"host fields are ignored", one(d.GrantRoleSQL(driver.RoleGrant{Role: "readers", RoleHost: "%", Member: "carol", MemberHost: "%"})),
			`GRANT "readers" TO "carol"`},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
	for _, g := range []driver.RoleGrant{
		{Role: "", Member: "carol"},
		{Role: "readers", Member: ""},
		{Role: "PUBLIC", Member: "carol"},
		{Role: "readers", Member: "PUBLIC"},
	} {
		if stmts, err := d.GrantRoleSQL(g); err == nil {
			t.Errorf("GrantRoleSQL(%+v) = %q, want an error", g, stmts)
		}
		if stmts, err := d.RevokeRoleSQL(g); err == nil {
			t.Errorf("RevokeRoleSQL(%+v) = %q, want an error", g, stmts)
		}
	}
}

// TestPGSchemaManagerSQL pins the schema DDL builders: names go through
// QuoteIdent (an embedded quote is doubled) and drop is CASCADE (the handler
// confirms first).
func TestPGSchemaManagerSQL(t *testing.T) {
	d := dialect{}
	if got := d.CreateSchemaSQL("sales"); got != `CREATE SCHEMA "sales"` {
		t.Errorf("CreateSchemaSQL = %q", got)
	}
	if got := d.CreateSchemaSQL(`a"b`); got != `CREATE SCHEMA "a""b"` {
		t.Errorf("CreateSchemaSQL adversarial = %q", got)
	}
	if got := d.DropSchemaSQL("sales"); got != `DROP SCHEMA "sales" CASCADE` {
		t.Errorf("DropSchemaSQL = %q", got)
	}
}

// TestPGCreateDatabaseIgnoresCollation pins that the (MySQL-style) collation
// parameter never reaches PostgreSQL DDL.
func TestPGCreateDatabaseIgnoresCollation(t *testing.T) {
	if got := (dialect{}).CreateDatabaseSQL("shop", "utf8mb4_bin"); got != `CREATE DATABASE "shop"` {
		t.Errorf("CreateDatabaseSQL = %q, collation must be ignored", got)
	}
}

// TestSeqOptions pins the CREATE-sequence option rendering used by both the
// standalone-sequence and identity-column dumps: the fixed clause order and the
// CYCLE suffix, with negative bounds/increment (a descending sequence) preserved
// verbatim.
func TestSeqOptions(t *testing.T) {
	cases := []struct {
		start, inc, minv, maxv, cache int64
		cycle                         bool
		want                          string
	}{
		{1, 1, 1, 9223372036854775807, 1, false,
			"START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 9223372036854775807 CACHE 1"},
		{5, 2, 5, 100, 10, true,
			"START WITH 5 INCREMENT BY 2 MINVALUE 5 MAXVALUE 100 CACHE 10 CYCLE"},
		{-1, -1, -100, -1, 1, false,
			"START WITH -1 INCREMENT BY -1 MINVALUE -100 MAXVALUE -1 CACHE 1"},
	}
	for _, c := range cases {
		if got := seqOptions(c.start, c.inc, c.minv, c.maxv, c.cache, c.cycle); got != c.want {
			t.Errorf("seqOptions(%d,%d,%d,%d,%d,%v) = %q, want %q",
				c.start, c.inc, c.minv, c.maxv, c.cache, c.cycle, got, c.want)
		}
	}
}

// TestTriggerStateSQL pins the trigger enable-state rendering: 'O' (default) and
// unknown codes emit nothing, D/R/A map to the ALTER verbs, and only a foreign
// table (relkind 'f') switches the head to ALTER FOREIGN TABLE — tables,
// partitioned parents and views all use plain ALTER TABLE (pg_dump parity).
func TestTriggerStateSQL(t *testing.T) {
	d := dialect{}
	cases := []struct {
		relkind, tgenabled, want string
	}{
		{"r", "O", ""},
		{"r", "?", ""},
		{"r", "D", `ALTER TABLE "public"."t" DISABLE TRIGGER "trg"`},
		{"p", "R", `ALTER TABLE "public"."t" ENABLE REPLICA TRIGGER "trg"`},
		{"v", "A", `ALTER TABLE "public"."t" ENABLE ALWAYS TRIGGER "trg"`},
		{"f", "D", `ALTER FOREIGN TABLE "public"."t" DISABLE TRIGGER "trg"`},
	}
	for _, c := range cases {
		if got := d.triggerStateSQL(`"public"."t"`, "trg", c.relkind, c.tgenabled); got != c.want {
			t.Errorf("triggerStateSQL(%s,%s) = %q, want %q", c.relkind, c.tgenabled, got, c.want)
		}
	}
}

// TestPhysicalSettingLines drives production dialect.major directly (the plan's
// PG13-floor rule: version-specific SQL generation is unit-tested, no test-only
// version override): SET COMPRESSION is emitted only at major >= 14 — the
// grammar and attcompression both start there — while STORAGE/STATISTICS are
// unconditional, and the parameterized head covers the matview form.
func TestPhysicalSettingLines(t *testing.T) {
	target := func(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
	cases := []struct {
		name  string
		major int
		head  string
		want  []string
	}{
		{"pg13-suppresses-compression", 13, `ALTER TABLE ONLY "public"."t"`, []string{
			`ALTER TABLE ONLY "public"."t" ALTER COLUMN "c" SET STORAGE EXTERNAL`,
			`ALTER TABLE ONLY "public"."t" ALTER COLUMN "c" SET STATISTICS 250`,
		}},
		{"pg14-emits-compression", 14, `ALTER TABLE ONLY "public"."t"`, []string{
			`ALTER TABLE ONLY "public"."t" ALTER COLUMN "c" SET STORAGE EXTERNAL`,
			`ALTER TABLE ONLY "public"."t" ALTER COLUMN "c" SET COMPRESSION lz4`,
			`ALTER TABLE ONLY "public"."t" ALTER COLUMN "c" SET STATISTICS 250`,
		}},
		{"matview-head", 18, `ALTER MATERIALIZED VIEW "public"."mv"`, []string{
			`ALTER MATERIALIZED VIEW "public"."mv" ALTER COLUMN "c" SET STORAGE EXTERNAL`,
			`ALTER MATERIALIZED VIEW "public"."mv" ALTER COLUMN "c" SET COMPRESSION lz4`,
			`ALTER MATERIALIZED VIEW "public"."mv" ALTER COLUMN "c" SET STATISTICS 250`,
		}},
	}
	for _, c := range cases {
		d := dialect{major: c.major}
		got := d.physicalSettingLines(c.head, "c", "e", "x", "l", target("250"))
		if len(got) != len(c.want) {
			t.Errorf("%s: %d lines, want %d: %q", c.name, len(got), len(c.want), got)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: line %d = %q, want %q", c.name, i, got[i], c.want[i])
			}
		}
	}
	// Default states emit nothing: storage matches the type default, no
	// compression, and both the pre-17 (-1) and PG17+ (NULL) statistics defaults.
	d := dialect{major: 18}
	if got := d.physicalSettingLines("ALTER TABLE ONLY t", "c", "x", "x", "", target("-1")); got != nil {
		t.Errorf("default settings emitted %q, want none", got)
	}
	if got := d.physicalSettingLines("ALTER TABLE ONLY t", "c", "x", "x", "", sql.NullString{}); got != nil {
		t.Errorf("NULL statistics emitted %q, want none", got)
	}
}

// TestTypeVersionGates drives production dialect.major for the version-gated
// SQL fragments (the plan's PG13-floor rule): MULTIRANGE_TYPE_NAME and
// SUBSCRIPT exist only from PG14 — a 13-floor dump must never carry either —
// and a multirange NAME COLLISION shape (an explicitly-renamed multirange)
// still renders through the same clause.
func TestTypeVersionGates(t *testing.T) {
	if got := (dialect{major: 13}).multirangeNameClause(9999, "public", "seatmulti"); got != "" {
		t.Errorf("PG13 multirange clause = %q, want none", got)
	}
	if got := (dialect{major: 14}).multirangeNameClause(9999, "public", "seatmulti"); got != `MULTIRANGE_TYPE_NAME = "public"."seatmulti"` {
		t.Errorf("PG14 multirange clause = %q", got)
	}
	// Collision shape: a multirange deliberately named like something else
	// entirely still emits the ACTUAL name — never the auto-derivation.
	if got := (dialect{major: 18}).multirangeNameClause(9999, "s", "weird_name"); got != `MULTIRANGE_TYPE_NAME = "s"."weird_name"` {
		t.Errorf("explicit multirange name = %q", got)
	}
	if got := (dialect{major: 14}).multirangeNameClause(0, "public", ""); got != "" {
		t.Errorf("no-multirange clause = %q, want none", got)
	}
	if got := (dialect{major: 13}).subscriptClause("raw_array_subscript_handler"); got != "" {
		t.Errorf("PG13 subscript clause = %q, want none", got)
	}
	if got := (dialect{major: 14}).subscriptClause("raw_array_subscript_handler"); got != "SUBSCRIPT = raw_array_subscript_handler" {
		t.Errorf("PG14 subscript clause = %q", got)
	}
}

// TestForeignOptionPolicy pins the foreign-option provenance allowlist: only known
// non-secret options of a RECOGNIZED wrapper survive; a DSN-shaped dbname is
// value-level redacted (defense in depth per security.md); everything on an
// unrecognized wrapper — and every user-mapping option — is redacted.
func TestForeignOptionPolicy(t *testing.T) {
	d := dialect{}
	clause, redacted := d.foreignOptionsClause("postgres_fdw", "server",
		"host=db.example\x1fport=5432\x1fdbname=appdb\x1fpassword=secret")
	if clause != ` OPTIONS (host 'db.example', port '5432', dbname 'appdb')` {
		t.Errorf("postgres_fdw server clause = %q", clause)
	}
	if len(redacted) != 1 || redacted[0] != "password" {
		t.Errorf("redacted = %v, want [password]", redacted)
	}
	// A DSN-shaped dbname could smuggle a credential — redacted.
	clause, redacted = d.foreignOptionsClause("postgres_fdw", "server",
		"dbname=host=evil password=x dbname=app")
	if clause != "" || len(redacted) != 1 {
		t.Errorf("DSN-shaped dbname must be redacted: clause=%q redacted=%v", clause, redacted)
	}
	// Unrecognized wrapper (even one NAMED postgres_fdw upstream): everything
	// redacted, nothing leaks.
	clause, redacted = d.foreignOptionsClause("", "server", "host=h\x1fsecret=s3cr3t")
	if clause != "" || len(redacted) != 2 {
		t.Errorf("unknown wrapper must redact all: clause=%q redacted=%v", clause, redacted)
	}
	if strings.Contains(clause, "s3cr3t") {
		t.Errorf("secret leaked: %q", clause)
	}
	// file_fdw tables keep format/header, never filename/program.
	clause, redacted = d.foreignOptionsClause("file_fdw", "table",
		"filename=/etc/passwd\x1fformat=csv\x1fheader=true")
	if clause != ` OPTIONS (format 'csv', header 'true')` || len(redacted) != 1 || redacted[0] != "filename" {
		t.Errorf("file_fdw table policy: clause=%q redacted=%v", clause, redacted)
	}
}

func TestCollationOptions(t *testing.T) {
	cases := []struct {
		name          string
		provider      string
		deterministic bool
		collate       string
		ctype         string
		locale        string
		iculocale     string
		icurules      string
		want          string
		wantOK        bool
	}{
		{"libc-locale", "c", true, "C", "C", "", "", "", "LOCALE = 'C', PROVIDER = libc", true},
		{"libc-split", "c", true, "en_US.utf8", "de_DE.utf8", "", "", "",
			"LC_COLLATE = 'en_US.utf8', LC_CTYPE = 'de_DE.utf8', PROVIDER = libc", true},
		{"icu-17locale", "i", true, "", "", "en-US", "", "", "LOCALE = 'en-US', PROVIDER = icu", true},
		{"icu-15iculocale", "i", true, "", "", "", "und", "", "LOCALE = 'und', PROVIDER = icu", true},
		{"icu-nondeterministic", "i", false, "", "", "und-u-ks-level2", "", "",
			"LOCALE = 'und-u-ks-level2', PROVIDER = icu, DETERMINISTIC = false", true},
		// ICU tailoring rules (PG16+) — including one carrying a quote, which
		// must be doubled rather than terminating the literal.
		{"icu-rules", "i", true, "", "", "und", "", "&V << w <<< W",
			"LOCALE = 'und', PROVIDER = icu, RULES = '&V << w <<< W'", true},
		{"icu-rules-quote", "i", false, "", "", "und", "", "&'a' < b",
			"LOCALE = 'und', PROVIDER = icu, RULES = '&''a'' < b', DETERMINISTIC = false", true},
		// A libc/builtin collation never carries ICU rules, even if the column
		// somehow held one.
		{"libc-ignores-rules", "c", true, "C", "C", "", "", "&V << w", "LOCALE = 'C', PROVIDER = libc", true},
		{"builtin", "b", true, "", "", "C.UTF-8", "", "", "LOCALE = 'C.UTF-8', PROVIDER = builtin", true},
		{"database-default-skipped", "d", true, "", "", "", "", "", "", false},
	}
	for _, c := range cases {
		got, ok := collationOptions(c.provider, c.deterministic, c.collate, c.ctype, c.locale, c.iculocale, c.icurules)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("collationOptions(%s) = %q,%v; want %q,%v", c.name, got, ok, c.want, c.wantOK)
		}
	}
}

// TestSyntheticSeqCandidates pins the replacement-sequence naming: six
// deterministic candidates per seed, hex prefix lengthened 12..52 (11+52 = 63
// keeps NAMEDATALEN-1), each extending the previous, distinct across seeds and
// across the serial/identity seed kinds.
func TestSyntheticSeqCandidates(t *testing.T) {
	c1 := syntheticSeqCandidates(serialSeqSeed("public", "xsrc", "s1"))
	if len(c1) != 6 {
		t.Fatalf("candidates = %d, want 6", len(c1))
	}
	wantLens := []int{23, 31, 39, 47, 55, 63}
	for i, c := range c1 {
		if len(c) != wantLens[i] {
			t.Errorf("candidate %d length = %d, want %d (%s)", i, len(c), wantLens[i], c)
		}
		if !strings.HasPrefix(c, "tablex_seq_") {
			t.Errorf("candidate %d lacks the tablex_seq_ prefix: %s", i, c)
		}
		if !strings.HasPrefix(c, c1[0]) && i > 0 {
			t.Errorf("candidate %d does not extend the shortest: %s vs %s", i, c, c1[0])
		}
	}
	if c2 := syntheticSeqCandidates(serialSeqSeed("public", "xsrc", "s2")); c2[0] == c1[0] {
		t.Errorf("distinct seeds must give distinct names")
	}
	if c3 := syntheticSeqCandidates(serialSeqSeed("public", "xsrc", "s1")); c3[0] != c1[0] {
		t.Errorf("the same seed must be deterministic")
	}
	if id := syntheticSeqCandidates(identitySeqSeed("public", "xsrc", "public", "s1")); id[0] == c1[0] {
		t.Errorf("identity and serial seeds must not collide")
	}
	// A different placement schema is a different identity (the collision
	// check runs per placement).
	if p2 := syntheticSeqCandidates(serialSeqSeed("other", "xsrc", "s1")); p2[0] == c1[0] {
		t.Errorf("placement schema must be bound into the name")
	}
}

// TestOpclassDropStatement pins the fresh-target guard. Every other class
// TableX drops no-ops harmlessly under IF EXISTS when its identity names an
// absent user type (PostgreSQL propagates missing_ok into that lookup), but an
// operator class resolves its access method with missing_ok=false, so a drop
// naming an extension-provided AM raises undefined_object even under IF EXISTS
// and would abort the whole restore at the first statement.
func TestOpclassDropStatement(t *testing.T) {
	d := dialect{}
	// A built-in access method always exists: the plain drop stays plain.
	plain := d.opclassDropStatement(`"s"."opc"`, "btree")
	if plain != `DROP OPERATOR CLASS IF EXISTS "s"."opc" USING "btree"` {
		t.Errorf("built-in AM drop = %q, want the unguarded form", plain)
	}
	for _, am := range []string{"btree", "hash", "gist", "gin", "spgist", "brin"} {
		if got := d.opclassDropStatement(`"s"."opc"`, am); strings.HasPrefix(got, "DO ") {
			t.Errorf("built-in AM %q must not be guarded: %q", am, got)
		}
	}

	// A custom AM: the drop rides an error-tolerant DO block, with BOTH escaping
	// layers exercised by an identifier carrying a quote AND a dollar-quote.
	got := d.opclassDropStatement(`"s"."o'p$$c"`, "custom_am")
	if !strings.HasPrefix(got, "DO $tablex") || !strings.Contains(got, "EXCEPTION WHEN undefined_object THEN NULL") {
		t.Fatalf("custom AM drop is not a guarded DO block: %q", got)
	}
	// The embedded statement is a string literal: its quotes must be doubled, so
	// the identifier's ' cannot terminate the EXECUTE argument.
	if !strings.Contains(got, `EXECUTE 'DROP OPERATOR CLASS IF EXISTS "s"."o''p$$c" USING "custom_am"'`) {
		t.Errorf("quote escaping wrong: %q", got)
	}
	// The dollar tag must not occur inside the body it delimits.
	tag, _, _ := strings.Cut(strings.TrimPrefix(got, "DO "), " ")
	body := strings.TrimSuffix(strings.TrimPrefix(got, "DO "+tag+" "), " "+tag)
	if strings.Contains(body, tag) {
		t.Errorf("dollar tag %q occurs inside its own body: %q", tag, got)
	}
	if !strings.HasSuffix(got, " "+tag) {
		t.Errorf("DO block is not closed by its opening tag: %q", got)
	}

	// A body already containing the default tag forces a fresh one.
	if tag := collisionFreeDollarTag("x $tablex$ y"); tag == "$tablex$" {
		t.Error("collisionFreeDollarTag returned a tag present in the body")
	}
	if tag := collisionFreeDollarTag("x $tablex$ $tablex1$ y"); tag != "$tablex2$" {
		t.Errorf("collisionFreeDollarTag = %q, want $tablex2$", tag)
	}
}

// TestTeardownNodeCollapse pins the staged-creation collapse: the drop graph
// must see a shell type and the CREATE completing it as ONE object, or the
// type-versus-support-function cycle that staging exists to break stays
// invisible to the teardown that must not emit it.
func TestTeardownNodeCollapse(t *testing.T) {
	shell := nodeID("type-shell", "s", "bt")
	final := nodeID("type-final", "s", "bt")
	want := nodeID("type", "s", "bt")
	if got := teardownNode(shell); got != want {
		t.Errorf("teardownNode(shell) = %q, want %q", got, want)
	}
	if got := teardownNode(final); got != want {
		t.Errorf("teardownNode(final) = %q, want %q", got, want)
	}
	// Unstaged ids pass through untouched.
	for _, id := range []string{want, nodeID("relation", "s", "t"), routineNodeID("s", "f", "integer"), ""} {
		if got := teardownNode(id); got != id {
			t.Errorf("teardownNode(%q) = %q, want it unchanged", id, got)
		}
	}
}

// TestMaintenanceDatabases pins the order and the freshness contract. The order
// is the preference order the caller walks: postgres first, template1 as the
// fallback for a managed host that blocks postgres. The slice is handed to a
// session, so a mutation by one caller must not be visible to the next.
func TestMaintenanceDatabases(t *testing.T) {
	var d dialect
	got := d.MaintenanceDatabases()
	want := []string{"postgres", "template1"}
	if len(got) != len(want) {
		t.Fatalf("MaintenanceDatabases() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("MaintenanceDatabases() = %v, want %v", got, want)
		}
	}

	got[0] = "clobbered"
	if again := d.MaintenanceDatabases(); again[0] != "postgres" {
		t.Errorf("a caller mutated shared state: second call = %v", again)
	}
}
