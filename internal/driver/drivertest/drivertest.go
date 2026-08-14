// Package drivertest is the reusable conformance suite for a TableX Dialect.
//
// Every rule the rest of the application relies on but cannot enforce with a
// type — quoting that round-trips, placeholders that are consistently
// positional or consistently numbered, a LIMIT clause that survives a 64-bit
// offset, and capability flags that agree with the optional interfaces the
// dialect actually implements — is asserted here once instead of being
// rediscovered per engine.
//
// A new engine wires itself in with a single call:
//
//	func TestConformance(t *testing.T) { drivertest.RunDialectSuite(t, dialect{}) }
//
// or, for the built-in engines, simply by being registered — the suite in
// internal/driver runs over driver.All(). RunDialectSuite needs no database.
// RunConnectionSuite is the second half: it needs a live connection and checks
// that introspection populates the engine-neutral model the handlers read.
//
// See docs/adding-an-engine.md for the full contract.
package drivertest

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// RunDialectSuite runs every conformance check that needs no database. It is
// safe to call on the registered (unspecialized) dialect value.
func RunDialectSuite(t *testing.T, d driver.Dialect) {
	t.Helper()
	t.Run("identity", func(t *testing.T) { checkIdentity(t, d) })
	t.Run("quote_ident", func(t *testing.T) { checkQuoteIdent(t, d) })
	t.Run("quote_string", func(t *testing.T) { checkQuoteString(t, d) })
	t.Run("placeholders", func(t *testing.T) { checkPlaceholders(t, d) })
	t.Run("limit_clause", func(t *testing.T) { checkLimitClause(t, d) })
	t.Run("qualify_table", func(t *testing.T) { checkQualifyTable(t, d) })
	t.Run("explain", func(t *testing.T) { checkExplain(t, d) })
	t.Run("capability_coherence", func(t *testing.T) { checkCapabilityCoherence(t, d) })
	t.Run("object_kinds", func(t *testing.T) { checkObjectKinds(t, d) })
	t.Run("column_placement", func(t *testing.T) { checkColumnPlacement(t, d) })
	t.Run("index_options", func(t *testing.T) { checkIndexOptions(t, d) })
	t.Run("column_privileges", func(t *testing.T) { checkColumnPrivileges(t, d) })
	t.Run("routine_privileges", func(t *testing.T) { checkRoutinePrivileges(t, d) })
}

// checkRoutinePrivileges pins the one thing a routine grant can get wrong
// without failing: addressing the wrong object. Both engines require the
// FUNCTION/PROCEDURE keyword — neither has a bare "ON <name>" for routines —
// so a builder that ignored model.Routine.Type would grant on an object of the
// other kind, or on nothing, rather than refusing to parse.
func checkRoutinePrivileges(t *testing.T, d driver.Dialect) {
	rp, ok := d.(driver.RoutinePrivileger)
	if !ok {
		return
	}
	privs := rp.RoutineGrantablePrivileges()
	if len(privs) == 0 {
		t.Error("RoutineGrantablePrivileges() is empty; the grant form would render no checkbox at all")
	}
	if !slices.Contains(privs, "EXECUTE") {
		t.Errorf("RoutineGrantablePrivileges() = %v; EXECUTE is the privilege a routine grant exists for", privs)
	}
	scope := driver.Scope{Database: "appdb"}
	if d.Capabilities().HasSchemas {
		scope.Schema = "public"
	}
	for _, kind := range []string{"FUNCTION", "PROCEDURE"} {
		g := driver.RoutineGrant{
			Scope:      scope,
			Routine:    model.Routine{Name: "calc_total", Type: kind},
			Privileges: []string{"EXECUTE"},
			Grantee:    "app_reader",
			Host:       "%",
		}
		for _, c := range []struct {
			what  string
			build func(driver.RoutineGrant) ([]string, error)
		}{{"GrantRoutineSQL", rp.GrantRoutineSQL}, {"RevokeRoutineSQL", rp.RevokeRoutineSQL}} {
			stmts, err := c.build(g)
			if err != nil {
				t.Errorf("%s(%s): %v", c.what, kind, err)
				continue
			}
			if len(stmts) == 0 || !strings.Contains(stmts[0], d.QuoteIdent("calc_total")) {
				t.Errorf("%s(%s) = %q; it must name the quoted routine", c.what, kind, stmts)
				continue
			}
			if !strings.Contains(stmts[0], " "+kind+" ") {
				t.Errorf("%s(%s) = %q; the routine kind must reach the statement, or the grant addresses the wrong object", c.what, kind, stmts)
			}
		}
	}
	// An empty privilege set is an error, never an empty (and therefore
	// syntactically broken, or worse silently different) statement.
	if stmts, err := rp.GrantRoutineSQL(driver.RoutineGrant{
		Scope: scope, Routine: model.Routine{Name: "calc_total", Type: "FUNCTION"}, Grantee: "app_reader",
	}); err == nil {
		t.Errorf("GrantRoutineSQL with no privileges = %q, want an error", stmts)
	}
}

// checkColumnPrivileges holds a ColumnPrivileger to the containment its callers
// assume: a column-grantable privilege is a table privilege GRANTED NARROWLY,
// so every keyword it offers must also be in the table allowlist. The grant
// handler validates against GrantablePrivileges(true) FIRST and the column set
// second; a keyword in only the column set would render a checkbox that the
// first gate then rejects as invalid — a control that cannot work.
//
// It also pins the two shapes the builders depend on: a column list needs a
// table, and it must survive into the statement. A dialect that accepted
// GrantSpec.Columns and dropped it would emit a WIDER grant than asked for and
// report success.
func checkColumnPrivileges(t *testing.T, d driver.Dialect) {
	cp, ok := d.(driver.ColumnPrivileger)
	if !ok {
		return
	}
	table := cp.GrantablePrivileges(true)
	cols := cp.ColumnGrantablePrivileges()
	if len(cols) == 0 {
		t.Error("ColumnGrantablePrivileges() is empty; implementing ColumnPrivileger then offering nothing hides the feature behind a working interface")
	}
	for _, p := range cols {
		if !slices.Contains(table, p) {
			t.Errorf("ColumnGrantablePrivileges() offers %q, which is not in GrantablePrivileges(true) %v; the grant form's first gate would reject it", p, table)
		}
	}

	ref := driver.TableRef{Database: "appdb", Table: "users"}
	if d.Capabilities().HasSchemas {
		ref.Schema = "public"
	}
	g := driver.GrantSpec{
		Privileges: cols[:1],
		Database:   ref.Database,
		Schema:     ref.Schema,
		Table:      ref.Table,
		Grantee:    "app_reader",
		Columns:    []string{"email"},
	}
	stmts, err := cp.GrantSQL(g)
	if err != nil {
		t.Fatalf("GrantSQL with a column list: %v", err)
	}
	if len(stmts) == 0 || !strings.Contains(stmts[0], d.QuoteIdent("email")) {
		t.Errorf("GrantSQL(%v) = %q; the column list must reach the statement, or the grant silently covers every column", g.Columns, stmts)
	}
	if rev, err := cp.RevokeSQL(g); err != nil {
		t.Errorf("RevokeSQL with a column list: %v", err)
	} else if len(rev) == 0 || !strings.Contains(rev[0], d.QuoteIdent("email")) {
		t.Errorf("RevokeSQL(%v) = %q; a column grant that cannot be revoked column-wise is unrevokable", g.Columns, rev)
	}

	dbScope := g
	dbScope.Table = ""
	if _, err := cp.GrantSQL(dbScope); err == nil {
		t.Error("GrantSQL accepted a column list at database scope; the object takes no column list, so this can only produce a broken or over-broad statement")
	}
}

// checkIndexOptions holds IndexOptions to its word in both directions: every
// option the dialect CLAIMS must change the statement AddIndexSQL builds, and
// every option it does not claim must be ignored if handed one anyway. A
// silently-dropped option is the worst outcome of the pair — the UI keeps
// offering it, the user keeps setting it, and the index is quietly not what
// they asked for. (MariaDB does exactly that with DESC, which is why it
// reports SupportsDesc false rather than passing the keyword along.)
func checkIndexOptions(t *testing.T, d driver.Dialect) {
	editor, ok := d.(driver.SchemaEditor)
	if !ok {
		return
	}
	ref := driver.TableRef{Database: "appdb", Table: "users"}
	if d.Capabilities().HasSchemas {
		ref.Schema = "public"
	}
	opts := driver.IndexOptions{}
	if o, ok := d.(driver.IndexOptioner); ok {
		opts = o.IndexOptions()
	}
	base := driver.IndexSpec{Name: "idx", Columns: []driver.IndexColumn{{Name: "a"}}}
	render := func(s driver.IndexSpec) string {
		t.Helper()
		got, err := editor.AddIndexSQL(ref, s)
		if err != nil {
			t.Fatalf("AddIndexSQL: %v", err)
		}
		return strings.Join(got, ";")
	}
	plain := render(base)
	if !strings.Contains(plain, d.QuoteIdent("idx")) || !strings.Contains(plain, d.QuoteIdent("a")) {
		t.Errorf("AddIndexSQL = %q; it must name the index and its column", plain)
	}
	if u := render(driver.IndexSpec{Name: "idx", Columns: base.Columns, Unique: true}); u == plain {
		t.Error("IndexSpec.Unique changes nothing")
	}

	for _, tc := range []struct {
		name      string
		supported bool
		spec      driver.IndexSpec
	}{
		{"SupportsDesc", opts.SupportsDesc, driver.IndexSpec{Name: "idx", Columns: []driver.IndexColumn{{Name: "a", Desc: true}}}},
		{"SupportsPrefix", opts.SupportsPrefix, driver.IndexSpec{Name: "idx", Columns: []driver.IndexColumn{{Name: "a", Prefix: 10}}}},
		{"SupportsPartial", opts.SupportsPartial, driver.IndexSpec{Name: "idx", Columns: base.Columns, Where: "a IS NOT NULL"}},
		{"Methods", len(opts.Methods) > 0, driver.IndexSpec{Name: "idx", Columns: base.Columns, Method: firstMethod(opts)}},
	} {
		changed := render(tc.spec) != plain
		switch {
		case tc.supported && !changed:
			t.Errorf("IndexOptions() claims %s but the option does not reach the statement: %q", tc.name, render(tc.spec))
		case !tc.supported && changed:
			t.Errorf("IndexOptions() does not claim %s, yet the option altered the statement: %q", tc.name, render(tc.spec))
		}
	}
}

func firstMethod(o driver.IndexOptions) string {
	if len(o.Methods) == 0 {
		return ""
	}
	return o.Methods[0]
}

// checkColumnPlacement pins ColumnSpec.Placement to its capability in both
// directions. The half that matters is the negative one: an engine with no
// reordering statement must IGNORE a placement it was handed, never approximate
// it. A dialect that quietly rebuilt the table to honour "AFTER x" would be
// doing something a column edit has no business doing, and the caller — which
// only checks the flag — would never know.
func checkColumnPlacement(t *testing.T, d driver.Dialect) {
	editor, ok := d.(driver.SchemaEditor)
	if !ok {
		return
	}
	ref := driver.TableRef{Database: "appdb", Table: "users"}
	if d.Capabilities().HasSchemas {
		ref.Schema = "public"
	}
	base := driver.ColumnSpec{Name: "note", Type: firstTextType(editor), Nullable: true}
	plain, err := editor.AddColumnSQL(ref, base)
	if err != nil {
		t.Fatalf("AddColumnSQL: %v", err)
	}
	placed := base
	placed.Placement = driver.PlaceAfter
	placed.PlacementAfter = "id"
	moved, err := editor.AddColumnSQL(ref, placed)
	if err != nil {
		t.Fatalf("AddColumnSQL with placement: %v", err)
	}
	same := strings.Join(plain, ";") == strings.Join(moved, ";")
	if d.Capabilities().SupportsColumnPosition {
		if same {
			t.Error("Capabilities().SupportsColumnPosition is true but ColumnSpec.Placement changes nothing; the control would silently do nothing")
		}
		return
	}
	if !same {
		t.Errorf("Capabilities().SupportsColumnPosition is false but ColumnSpec.Placement altered the statement:\n%s", strings.Join(moved, ";\n"))
	}
}

// checkIdentity: the name is a stable lower-case id used in URLs, config and
// the registry; the display name is what the login form shows.
func checkIdentity(t *testing.T, d driver.Dialect) {
	name := d.Name()
	switch {
	case name == "":
		t.Error("Name() is empty")
	case name != strings.ToLower(name):
		t.Errorf("Name() = %q; it is a config/URL token and must be lower-case", name)
	case strings.ContainsAny(name, " \t/\\?&="):
		t.Errorf("Name() = %q; it must be a bare token (config value and URL segment)", name)
	}
	if d.DisplayName() == "" {
		t.Error("DisplayName() is empty; the login form has nothing to show")
	}
	if d.SQLDriverName() == "" {
		t.Error("SQLDriverName() is empty; database/sql has nothing to open")
	}

	port, network := d.DefaultPort(), d.Capabilities().IsNetworkEngine
	switch {
	case network && (port <= 0 || port > 65535):
		t.Errorf("DefaultPort() = %d for a network engine; want 1..65535", port)
	case !network && port != 0:
		t.Errorf("DefaultPort() = %d for a file-backed engine; want 0", port)
	}
}

// checkQuoteIdent: an identifier must come back delimited, and unquoting must
// return exactly what went in — including a name that contains the delimiter
// itself, which is where a naive implementation produces injectable DDL.
func checkQuoteIdent(t *testing.T, d driver.Dialect) {
	plain := d.QuoteIdent("users")
	if len(plain) < 3 {
		t.Fatalf("QuoteIdent(%q) = %q; identifiers must be delimited", "users", plain)
	}
	open, closeQ := plain[0], plain[len(plain)-1]
	if open != closeQ {
		t.Fatalf("QuoteIdent(%q) = %q; expected the same delimiter at both ends", "users", plain)
	}
	delim := string(open)

	for _, name := range []string{
		"users",
		"Mixed_Case",
		"with space",
		"with" + delim + "delimiter",
		delim + delim,
		"unicode_ä_名",
	} {
		q := d.QuoteIdent(name)
		if len(q) < 2 || q[0] != open || q[len(q)-1] != closeQ {
			t.Errorf("QuoteIdent(%q) = %q; not delimited", name, q)
			continue
		}
		// Standard unquoting: strip the delimiters, halve every doubled one.
		got := strings.ReplaceAll(q[1:len(q)-1], delim+delim, delim)
		if got != name {
			t.Errorf("QuoteIdent(%q) = %q, which unquotes to %q; the round-trip must be exact or the delimiter is injectable",
				name, q, got)
		}
	}
}

// checkQuoteString: generated DDL and dumps embed literals through this, so an
// embedded quote must not be able to end the literal early.
func checkQuoteString(t *testing.T, d driver.Dialect) {
	if got, want := d.QuoteString("abc"), "'abc'"; got != want {
		t.Errorf("QuoteString(%q) = %q, want %q", "abc", got, want)
	}
	for _, s := range []string{"it's", "''", `back\slash`, "line\nbreak", ""} {
		q := d.QuoteString(s)
		// An E'…' escape-string prefix is part of the literal's SYNTAX, not of
		// its content: PostgreSQL emits one for a value carrying a backslash so
		// the literal means the same thing whether or not
		// standard_conforming_strings is on. Strip it before the interior scan,
		// which would otherwise never run for that value — the quote check below
		// would fail on the 'E' and `continue`.
		lit := q
		if strings.HasPrefix(lit, "E'") {
			lit = lit[1:]
		}
		if len(lit) < 2 || lit[0] != '\'' || lit[len(lit)-1] != '\'' {
			t.Errorf("QuoteString(%q) = %q; string literals must be single-quoted", s, q)
			continue
		}
		// Nothing inside may terminate the literal: after removing the two
		// escape forms an engine may use, no bare quote can remain.
		inner := lit[1 : len(lit)-1]
		inner = strings.ReplaceAll(inner, `\\`, "")
		inner = strings.ReplaceAll(inner, `\'`, "")
		inner = strings.ReplaceAll(inner, "''", "")
		if strings.Contains(inner, "'") {
			t.Errorf("QuoteString(%q) = %q; it leaves an unescaped quote that ends the literal early", s, q)
		}
	}
}

// checkPlaceholders: a dialect is either positional-agnostic (one form reused,
// like MySQL's "?") or numbered (a distinct form per index, like PostgreSQL's
// "$n"). A partial mix silently binds the wrong argument.
func checkPlaceholders(t *testing.T, d driver.Dialect) {
	const n = 5
	seen := make([]string, n)
	for i := range seen {
		seen[i] = d.Placeholder(i + 1)
		if seen[i] == "" {
			t.Fatalf("Placeholder(%d) is empty", i+1)
		}
	}
	if got := d.Placeholder(1); got != seen[0] {
		t.Errorf("Placeholder(1) is not stable: %q then %q", seen[0], got)
	}

	distinct := map[string]bool{}
	for _, p := range seen {
		distinct[p] = true
	}
	if len(distinct) != 1 && len(distinct) != n {
		t.Errorf("Placeholder must be either one reused form or one per index; got %q", seen)
	}
}

// checkLimitClause: the offset is int64 end-to-end so browsing past row 2^31 on
// a 32-bit build does not silently wrap. A clause that renders the offset
// through an int would lose it here.
func checkLimitClause(t *testing.T, d driver.Dialect) {
	const bigOffset int64 = 1 << 40
	cases := []struct {
		limit  int
		offset int64
		want   []string
	}{
		{25, 0, []string{"25"}},
		{1, 1, []string{"1"}},
		{10, bigOffset, []string{"10", "1099511627776"}},
	}
	for _, c := range cases {
		got := d.LimitClause(c.limit, c.offset)
		if strings.TrimSpace(got) == "" {
			t.Errorf("LimitClause(%d, %d) is empty", c.limit, c.offset)
			continue
		}
		for _, want := range c.want {
			if !strings.Contains(got, want) {
				t.Errorf("LimitClause(%d, %d) = %q; missing %q (a truncated offset silently reshuffles the page)",
					c.limit, c.offset, got, want)
			}
		}
	}
}

// checkQualifyTable: handlers build every generated statement around this, so
// the table name must actually appear, quoted, and the schema must appear only
// where the engine has one.
func checkQualifyTable(t *testing.T, d driver.Dialect) {
	caps := d.Capabilities()
	ref := driver.TableRef{Database: "appdb", Schema: "public", Table: "users"}
	if !caps.HasSchemas {
		ref.Schema = ""
	}
	q := d.QualifyTable(ref)
	if !strings.Contains(q, d.QuoteIdent("users")) {
		t.Errorf("QualifyTable(%+v) = %q; it must contain the quoted table name %q", ref, q, d.QuoteIdent("users"))
	}
	if caps.HasSchemas && !strings.Contains(q, d.QuoteIdent("public")) {
		t.Errorf("QualifyTable(%+v) = %q; an engine with schemas must qualify with one", ref, q)
	}
	// A table name containing the delimiter must still be quoted, not spliced.
	tricky := driver.TableRef{Database: ref.Database, Schema: ref.Schema, Table: `we"ird`}
	if got := d.QualifyTable(tricky); !strings.Contains(got, d.QuoteIdent(tricky.Table)) {
		t.Errorf("QualifyTable(%+v) = %q; it must use QuoteIdent, not string concatenation", tricky, got)
	}
}

// checkExplain: the capability flag and the ok return must agree, or the UI
// offers a button that the dialect refuses.
func checkExplain(t *testing.T, d driver.Dialect) {
	const query = "SELECT 1"
	sql, ok := d.ExplainSQL(query, false)
	if want := d.Capabilities().SupportsExplain; ok != want {
		t.Errorf("ExplainSQL ok = %v but Capabilities().SupportsExplain = %v", ok, want)
	}
	if ok && !strings.Contains(sql, query) {
		t.Errorf("ExplainSQL(%q) = %q; the query must survive", query, sql)
	}
}

// checkCapabilityCoherence is the check the whole suite exists for: a
// capability flag is a promise the UI acts on, and the optional interface is
// how the promise is kept. A dialect that sets the flag and omits the interface
// renders a control that fails at the type assertion.
func checkCapabilityCoherence(t *testing.T, d driver.Dialect) {
	caps := d.Capabilities()
	type rule struct {
		flag  bool
		name  string // the Capabilities field
		iface string // the interface it promises
		has   bool
	}
	_, colMod := d.(driver.ColumnModifier)
	_, colRen := d.(driver.ColumnRenamer)
	_, fkEd := d.(driver.ForeignKeyEditor)
	_, schemaEd := d.(driver.SchemaEditor)
	_, dbMgr := d.(driver.DatabaseManager)
	_, schemaMgr := d.(driver.SchemaManager)
	_, userMgr := d.(driver.UserManager)
	_, privMgr := d.(driver.PrivilegeManager)
	_, priv := d.(driver.Privileger)
	_, roleMgr := d.(driver.RoleManager)
	_, collations := d.(driver.CollationLister)
	_, pool := d.(driver.PoolOpener)

	for _, r := range []rule{
		{caps.SupportsColumnModify, "SupportsColumnModify", "ColumnModifier", colMod},
		{caps.SupportsColumnModify, "SupportsColumnModify", "SchemaEditor", schemaEd},
		{caps.SupportsColumnRename, "SupportsColumnRename", "ColumnRenamer", colRen},
		{caps.SupportsForeignKeyDDL, "SupportsForeignKeyDDL", "ForeignKeyEditor", fkEd},
		{caps.CanManageDatabases, "CanManageDatabases", "DatabaseManager", dbMgr},
		{caps.HasSchemas, "HasSchemas", "SchemaManager", schemaMgr},
		{caps.HasUsers, "HasUsers", "UserManager", userMgr},
		{caps.HasUsers, "HasUsers", "PrivilegeManager", privMgr},
		{caps.HasUsers, "HasUsers", "Privileger", priv},
		{caps.SupportsRoles, "SupportsRoles", "RoleManager", roleMgr},
		{caps.SupportsCharset, "SupportsCharset", "CollationLister", collations},
		// A network engine must build its pool through a Connector, or
		// ConnParams.DialControl — the dial-time SSRF guard — never runs.
		{caps.IsNetworkEngine, "IsNetworkEngine", "PoolOpener", pool},
	} {
		if r.flag && !r.has {
			t.Errorf("Capabilities().%s is true but the dialect does not implement driver.%s; the UI would offer a control the type assertion refuses",
				r.name, r.iface)
		}
	}

	// The reverse direction for the two that were split out of SchemaEditor:
	// implementing the builder while denying the capability hides a working
	// feature behind a flag nobody will think to flip.
	if colMod && !caps.SupportsColumnModify {
		t.Error("the dialect implements driver.ColumnModifier but Capabilities().SupportsColumnModify is false")
	}
	if fkEd && !caps.SupportsForeignKeyDDL {
		t.Error("the dialect implements driver.ForeignKeyEditor but Capabilities().SupportsForeignKeyDDL is false")
	}
	// ColumnRenamer deliberately has no reverse rule. MySQL's dialect implements
	// it unconditionally but reports the capability from the DETECTED server
	// version — MariaDB below 10.5.2 has no RENAME COLUMN — so "implements it,
	// denies the flag" is the correct answer there, not a mistake. RoleManager
	// is the same shape for the same reason (MySQL 8.0 / MariaDB 10.0.5), and
	// note this suite runs on the UNSPECIALIZED dialect, where that version is
	// unknown — so mysql reporting SupportsRoles false here is the fail-closed
	// default working, not a missing capability.

	if caps.IdentifierMaxBytes < 0 {
		t.Errorf("Capabilities().IdentifierMaxBytes = %d; use 0 for no limit", caps.IdentifierMaxBytes)
	}
	if caps.IdentifierMaxChars < 0 {
		t.Errorf("Capabilities().IdentifierMaxChars = %d; use 0 for no limit", caps.IdentifierMaxChars)
	}
	// The identifier cap has ONE unit per engine. Declaring both would leave
	// ValidNewIdentifier applying whichever bites first — two answers to one
	// question, and the stricter one silently wins.
	if caps.IdentifierMaxBytes > 0 && caps.IdentifierMaxChars > 0 {
		t.Errorf("Capabilities() declares an identifier cap in both units (%d bytes, %d chars); an engine measures its limit one way",
			caps.IdentifierMaxBytes, caps.IdentifierMaxChars)
	}
}

// checkObjectKinds: DROP and RENAME are routed through the dialect precisely so
// a DROP TABLE is never emitted for a view. Each kind must produce a statement
// naming the object.
func checkObjectKinds(t *testing.T, d driver.Dialect) {
	editor, ok := d.(driver.SchemaEditor)
	if !ok {
		return
	}
	ref := driver.TableRef{Database: "appdb", Table: "users"}
	if d.Capabilities().HasSchemas {
		ref.Schema = "public"
	}
	for _, kind := range []string{driver.ObjectTable, driver.ObjectView, driver.ObjectMatView} {
		drop, err := editor.DropObjectSQL(ref, kind)
		if err != nil {
			t.Errorf("DropObjectSQL(%s): %v", kind, err)
		} else if len(drop) == 0 || !strings.Contains(drop[0], d.QuoteIdent("users")) {
			t.Errorf("DropObjectSQL(%s) = %q; it must name the quoted object", kind, drop)
		}
		ren, err := editor.RenameObjectSQL(ref, "people", kind)
		if err != nil {
			t.Errorf("RenameObjectSQL(%s): %v", kind, err)
		} else if len(ren) == 0 || !strings.Contains(ren[0], d.QuoteIdent("people")) {
			t.Errorf("RenameObjectSQL(%s) = %q; it must name the quoted new name", kind, ren)
		}
	}
	if types := editor.ColumnTypes(); len(types) == 0 {
		t.Error("ColumnTypes() is empty; the create/modify forms would offer no type at all")
	}
}

// RunConnectionSuite is the half that needs a database. It creates a small
// table through the dialect's own DDL, introspects it, and asserts the
// engine-neutral model the handlers read is actually populated — which is the
// part no amount of pure-function testing can prove.
//
// scope is where the table is created (Database, plus Schema on an engine with
// schemas). The table is dropped on the way out.
func RunConnectionSuite(t *testing.T, conn *driver.Connection, scope driver.Scope) {
	t.Helper()
	ctx := context.Background()
	d := conn.Dialect()
	ref := driver.TableRef{Database: scope.Database, Schema: scope.Schema, Table: "tablex_conformance"}

	editor, ok := d.(driver.SchemaEditor)
	if !ok {
		t.Skip("dialect has no SchemaEditor; nothing to create")
	}
	cols := []driver.ColumnSpec{
		{Name: "id", Type: firstIntType(editor), Nullable: false},
		{Name: "label", Type: firstTextType(editor), Nullable: true},
	}
	create, err := editor.CreateTableSQL(ref, cols, []string{"id"})
	if err != nil {
		t.Fatalf("CreateTableSQL: %v", err)
	}
	if err := conn.ExecScript(ctx, create, d.Capabilities().SupportsTransactionalDDL); err != nil {
		t.Fatalf("create conformance table: %v\n%s", err, strings.Join(create, ";\n"))
	}
	t.Cleanup(func() {
		if drop, err := editor.DropObjectSQL(ref, driver.ObjectTable); err == nil {
			_ = conn.ExecScript(context.Background(), drop, false)
		}
	})

	got, err := conn.Columns(ctx, ref)
	if err != nil {
		t.Fatalf("Columns: %v", err)
	}
	if len(got) != len(cols) {
		t.Fatalf("Columns returned %d columns, want %d", len(got), len(cols))
	}
	for i, c := range got {
		if c.Name == "" {
			t.Errorf("column %d has no Name", i)
		}
		if c.Position != i+1 {
			t.Errorf("column %q Position = %d, want %d; positions must be contiguous 1..N on every engine", c.Name, c.Position, i+1)
		}
		if c.DataType == "" {
			t.Errorf("column %q has no DataType", c.Name)
		}
		if c.BaseType == "" {
			t.Errorf("column %q has no BaseType", c.Name)
		}
		if c.BaseType != strings.ToLower(c.BaseType) {
			t.Errorf("column %q BaseType = %q; it must be lower-cased", c.Name, c.BaseType)
		}
	}
	if !got[0].IsPrimaryKey {
		t.Errorf("column %q was created as the PRIMARY KEY but IsPrimaryKey is false", got[0].Name)
	}
	if got[0].Nullable {
		t.Errorf("column %q was created NOT NULL but Nullable is true", got[0].Name)
	}
	if !got[1].Nullable {
		t.Errorf("column %q was created nullable but Nullable is false", got[1].Name)
	}

	tables, err := conn.ListTables(ctx, scope)
	if err != nil {
		t.Fatalf("ListTables: %v", err)
	}
	found := false
	for _, tb := range tables {
		if tb.Name != ref.Table {
			continue
		}
		found = true
		if tb.Type != "table" {
			t.Errorf("ListTables reports %q as %q, want a base table", tb.Name, tb.Type)
		}
	}
	if !found {
		t.Errorf("ListTables did not return the table just created (%q)", ref.Table)
	}
}

// firstIntType / firstTextType pick a type from the dialect's OWN allowlist, so
// the suite never has to name an engine's spelling.
func firstIntType(e driver.SchemaEditor) string { return firstTypeMatching(e, "int", "integer") }
func firstTextType(e driver.SchemaEditor) string {
	return firstTypeMatching(e, "text", "varchar", "character varying")
}

func firstTypeMatching(e driver.SchemaEditor, wants ...string) string {
	types := e.ColumnTypes()
	for _, want := range wants {
		for _, ty := range types {
			if strings.EqualFold(ty, want) {
				return ty
			}
		}
	}
	if len(types) > 0 {
		return types[0]
	}
	return "TEXT"
}
