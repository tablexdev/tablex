package driver_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

func mustGet(t *testing.T, name string) driver.Dialect {
	t.Helper()
	d, ok := driver.Get(name)
	if !ok {
		t.Fatalf("dialect %q not registered", name)
	}
	return d
}

func TestRegistryAll(t *testing.T) {
	all := driver.All()
	if len(all) < 3 {
		t.Fatalf("expected at least 3 dialects, got %d", len(all))
	}
	names := map[string]bool{}
	for _, d := range all {
		names[d.Name()] = true
	}
	for _, want := range []string{"mysql", "postgres", "sqlite"} {
		if !names[want] {
			t.Errorf("missing dialect %q", want)
		}
	}
}

func TestQuoteIdent(t *testing.T) {
	cases := []struct{ engine, in, want string }{
		{"mysql", "users", "`users`"},
		{"mysql", "a`b", "`a``b`"}, // injection: backtick doubled
		{"postgres", "users", `"users"`},
		{"postgres", `a"b`, `"a""b"`}, // quote doubled
		{"sqlite", "users", `"users"`},
		{"sqlite", `a"b`, `"a""b"`},
	}
	for _, c := range cases {
		if got := mustGet(t, c.engine).QuoteIdent(c.in); got != c.want {
			t.Errorf("%s.QuoteIdent(%q) = %q, want %q", c.engine, c.in, got, c.want)
		}
	}
}

func TestQuoteString(t *testing.T) {
	// A single quote must be neutralized so it can't break out of the literal.
	for _, engine := range []string{"mysql", "postgres", "sqlite"} {
		got := mustGet(t, engine).QuoteString("O'Brien")
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("%s.QuoteString not wrapped in quotes: %q", engine, got)
		}
		// Must not contain a lone, unescaped quote in the interior.
		inner := got[1 : len(got)-1]
		if strings.Contains(inner, "'") && !strings.Contains(inner, "''") && !strings.Contains(inner, `\'`) {
			t.Errorf("%s.QuoteString did not escape the quote: %q", engine, got)
		}
	}
}

func TestPlaceholder(t *testing.T) {
	if got := mustGet(t, "mysql").Placeholder(1); got != "?" {
		t.Errorf("mysql placeholder = %q, want ?", got)
	}
	if got := mustGet(t, "sqlite").Placeholder(3); got != "?" {
		t.Errorf("sqlite placeholder = %q, want ?", got)
	}
	pg := mustGet(t, "postgres")
	if pg.Placeholder(1) != "$1" || pg.Placeholder(2) != "$2" {
		t.Errorf("postgres placeholders wrong: %q %q", pg.Placeholder(1), pg.Placeholder(2))
	}
}

func TestLimitClause(t *testing.T) {
	for _, engine := range []string{"mysql", "postgres", "sqlite"} {
		got := mustGet(t, engine).LimitClause(25, 50)
		if !strings.Contains(got, "25") || !strings.Contains(got, "50") {
			t.Errorf("%s.LimitClause(25,50) = %q", engine, got)
		}
	}
}

func TestQualifyTable(t *testing.T) {
	mysql := mustGet(t, "mysql").QualifyTable(driver.TableRef{Database: "shop", Table: "orders"})
	if mysql != "`shop`.`orders`" {
		t.Errorf("mysql qualify = %q", mysql)
	}
	pg := mustGet(t, "postgres").QualifyTable(driver.TableRef{Database: "shop", Schema: "public", Table: "orders"})
	if pg != `"public"."orders"` { // PG ignores the bound database, qualifies by schema
		t.Errorf("postgres qualify = %q", pg)
	}
	sq := mustGet(t, "sqlite").QualifyTable(driver.TableRef{Database: "main", Table: "orders"})
	if sq != `"orders"` {
		t.Errorf("sqlite qualify = %q", sq)
	}
}

// TestValidNewIdentifier pins the create/rename name policy: legal real-world
// names (spaces, hyphens, dots, leading digits, non-Latin scripts) are
// accepted — they were already browsable, so refusing to create them was an
// asymmetry — while injection-shaped or unusable names stay rejected. The
// length rule is dialect-aware in size AND unit: PostgreSQL's 63-BYTE cap is
// load-bearing because the server silently truncates beyond it, while
// MySQL/MariaDB's 64 counts CHARACTERS.
func TestValidNewIdentifier(t *testing.T) {
	mysqlCaps := mustGet(t, "mysql").Capabilities()   // 64 characters
	pgCaps := mustGet(t, "postgres").Capabilities()   // 63 bytes
	sqliteCaps := mustGet(t, "sqlite").Capabilities() // 0 (no cap)
	all := []driver.Capabilities{mysqlCaps, pgCaps, sqliteCaps}

	// Character-set policy is engine-independent.
	accept := []string{
		"users", "Users", "_private", "user accounts", "order-items",
		"v1.snapshot", "2024_sales", "naïve", "顧客", "a$b",
	}
	for _, caps := range all {
		for _, s := range accept {
			if !driver.ValidNewIdentifier(caps, s) {
				t.Errorf("ValidNewIdentifier(%q) = false, want true", s)
			}
		}
	}
	reject := []string{
		"", " ", " padded", "padded ", "a\tb", "a\nb", "a\x00b",
		`quo"te`, "quo'te", "back`tick", "semi;colon", `back\slash`,
	}
	for _, caps := range all {
		for _, s := range reject {
			if driver.ValidNewIdentifier(caps, s) {
				t.Errorf("ValidNewIdentifier(%q) = true, want false", s)
			}
		}
	}

	// Dialect-aware length boundary.
	x63, x64, x65 := strings.Repeat("x", 63), strings.Repeat("x", 64), strings.Repeat("x", 65)
	if !driver.ValidNewIdentifier(mysqlCaps, x64) || driver.ValidNewIdentifier(mysqlCaps, x65) {
		t.Error("MySQL identifier cap should accept 64 characters and reject 65")
	}
	if !driver.ValidNewIdentifier(pgCaps, x63) || driver.ValidNewIdentifier(pgCaps, x64) {
		t.Error("PostgreSQL identifier cap should accept 63 bytes and reject 64")
	}
	// PostgreSQL's cap is bytes, not runes: 32 two-byte runes = 64 bytes, over 63.
	if driver.ValidNewIdentifier(pgCaps, strings.Repeat("é", 32)) {
		t.Error("PostgreSQL cap must measure bytes: 64-byte name should be rejected")
	}
	// MySQL's is the other way round: 64 is a CHARACTER count, so a multi-byte
	// name well past 64 bytes is legal — and already browsable in TableX, which
	// is the asymmetry this validator exists to avoid. 40 three-byte CJK runes
	// are 120 bytes and 40 characters.
	if !driver.ValidNewIdentifier(mysqlCaps, strings.Repeat("顧", 40)) {
		t.Error("MySQL cap must measure characters: a 40-character (120-byte) name should be accepted")
	}
	if !driver.ValidNewIdentifier(mysqlCaps, strings.Repeat("顧", 64)) {
		t.Error("MySQL cap must measure characters: exactly 64 characters should be accepted")
	}
	if driver.ValidNewIdentifier(mysqlCaps, strings.Repeat("顧", 65)) {
		t.Error("MySQL cap must still bite at 65 characters")
	}
	// SQLite imposes no fixed cap.
	if !driver.ValidNewIdentifier(sqliteCaps, strings.Repeat("x", 200)) {
		t.Error("SQLite should not impose an identifier length cap")
	}
}

func TestBuildDSN(t *testing.T) {
	mysql, err := mustGet(t, "mysql").BuildDSN(driver.ConnParams{Host: "db", Port: 3306, User: "u", Password: "p", Database: "shop"})
	if err != nil || !strings.Contains(mysql, "tcp(db:3306)") || !strings.Contains(mysql, "parseTime=true") {
		t.Errorf("mysql DSN = %q err=%v", mysql, err)
	}
	pg, err := mustGet(t, "postgres").BuildDSN(driver.ConnParams{Host: "db", Port: 5432, User: "u", Password: "p", Database: "shop"})
	if err != nil || !strings.HasPrefix(pg, "postgres://") || !strings.Contains(pg, "sslmode=prefer") {
		t.Errorf("postgres DSN = %q err=%v", pg, err)
	}
	dbPath := filepath.Join(t.TempDir(), "app.db")
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	sq, err := mustGet(t, "sqlite").BuildDSN(driver.ConnParams{FilePath: dbPath})
	if err != nil || !strings.Contains(sq, dbPath) || !strings.Contains(sq, "_pragma") {
		t.Errorf("sqlite DSN = %q err=%v", sq, err)
	}
	if _, err := mustGet(t, "sqlite").BuildDSN(driver.ConnParams{}); err == nil {
		t.Error("sqlite DSN without a file path should error")
	}
	// A missing file must be reported, not silently created.
	if _, err := mustGet(t, "sqlite").BuildDSN(driver.ConnParams{FilePath: filepath.Join(t.TempDir(), "missing.db")}); err == nil {
		t.Error("sqlite DSN for a missing file should error")
	}
	// A plain memory path keeps the single-'?' shape.
	mem, err := mustGet(t, "sqlite").BuildDSN(driver.ConnParams{FilePath: ":memory:"})
	if err != nil || strings.Count(mem, "?") != 1 || !strings.Contains(mem, "_pragma") {
		t.Errorf("sqlite :memory: DSN = %q err=%v, want one '?' and pragmas", mem, err)
	}
	// A query-bearing memory path must join the pragmas with '&' — a second
	// '?' would fold them into the cache parameter's value.
	shared, err := mustGet(t, "sqlite").BuildDSN(driver.ConnParams{FilePath: "file::memory:?cache=shared"})
	if err != nil || strings.Count(shared, "?") != 1 {
		t.Errorf("sqlite shared-memory DSN = %q err=%v, want exactly one '?'", shared, err)
	}
	if !strings.Contains(shared, "cache=shared&") && !strings.Contains(shared, "&_pragma") {
		t.Errorf("sqlite shared-memory DSN = %q, want pragmas joined with '&'", shared)
	}
	// A '#' in a memory path would start a URI fragment and silently drop the
	// appended pragmas; it must be rejected like the file-path form.
	if _, err := mustGet(t, "sqlite").BuildDSN(driver.ConnParams{FilePath: "file::memory:?cache=shared#frag"}); err == nil {
		t.Error("sqlite memory DSN with '#' should error")
	}
}

func TestCapabilities(t *testing.T) {
	if !mustGet(t, "postgres").Capabilities().HasSchemas {
		t.Error("postgres should report HasSchemas")
	}
	if mustGet(t, "mysql").Capabilities().HasSchemas {
		t.Error("mysql should not report HasSchemas")
	}
	if mustGet(t, "sqlite").Capabilities().HasUsers {
		t.Error("sqlite should not report HasUsers")
	}
	if !mustGet(t, "mysql").Capabilities().HasEvents {
		t.Error("mysql should report HasEvents")
	}
	if mustGet(t, "postgres").Capabilities().DatabasesShareConnection {
		t.Error("postgres binds one database per connection")
	}
	if !mustGet(t, "mysql").Capabilities().AccountHasHost {
		t.Error("mysql accounts are host-qualified ('user'@'host')")
	}
	if mustGet(t, "postgres").Capabilities().AccountHasHost {
		t.Error("postgres roles have no host part")
	}
	if !mustGet(t, "postgres").Capabilities().SupportsRoleAttributes {
		t.Error("postgres should report SupportsRoleAttributes")
	}
	for _, engine := range []string{"mysql", "sqlite"} {
		if mustGet(t, engine).Capabilities().SupportsRoleAttributes {
			t.Errorf("%s should not report SupportsRoleAttributes", engine)
		}
	}
	if c := mustGet(t, "sqlite").Capabilities(); c.AccountHasHost {
		t.Error("sqlite has no accounts at all")
	}
}

// TestValidPrivilegeKeyword pins the shape gate on the introspection-driven
// revoke path: uppercase words with single spaces only, bounded length.
func TestValidPrivilegeKeyword(t *testing.T) {
	valid := []string{"SELECT", "ALL PRIVILEGES", "CREATE TEMPORARY TABLES", "MAINTAIN"}
	for _, s := range valid {
		if !driver.ValidPrivilegeKeyword(s) {
			t.Errorf("ValidPrivilegeKeyword(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "select", "Select", "SELECT; DROP", "SELECT  UPDATE",
		" SELECT", "SELECT ", "SELECT,UPDATE", "SELECT'X",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} // 33 bytes: over the cap
	for _, s := range invalid {
		if driver.ValidPrivilegeKeyword(s) {
			t.Errorf("ValidPrivilegeKeyword(%q) = true, want false", s)
		}
	}
}

// TestNormalizePrivileges pins the shared trim/upper-case + re-check pipeline
// the Grant/Revoke builders run before emitting keywords verbatim.
func TestNormalizePrivileges(t *testing.T) {
	got, err := driver.NormalizePrivileges([]string{" select ", "all privileges"}, driver.ValidPrivilegeKeyword)
	if err != nil || len(got) != 2 || got[0] != "SELECT" || got[1] != "ALL PRIVILEGES" {
		t.Errorf("NormalizePrivileges = %v, %v", got, err)
	}
	if _, err := driver.NormalizePrivileges(nil, driver.ValidPrivilegeKeyword); err == nil {
		t.Error("empty privilege set should error")
	}
	if _, err := driver.NormalizePrivileges([]string{"SELECT; DROP"}, driver.ValidPrivilegeKeyword); err == nil {
		t.Error("injection shape should error")
	}
}

func TestExplainSQL(t *testing.T) {
	if got, ok := mustGet(t, "postgres").ExplainSQL("SELECT 1", true); !ok || !strings.Contains(got, "ANALYZE") {
		t.Errorf("postgres explain analyze = %q ok=%v", got, ok)
	}
	if got, ok := mustGet(t, "sqlite").ExplainSQL("SELECT 1", false); !ok || !strings.Contains(got, "QUERY PLAN") {
		t.Errorf("sqlite explain = %q ok=%v", got, ok)
	}
}

// TestQuoteStringIsBackslashModeIndependent — PostgreSQL's
// standard_conforming_strings decides whether a backslash inside an ordinary
// '…' literal escapes the next character. It is settable per database, per role
// and per session, so a literal that only survives under `on` is a literal that
// can be broken out of. Named without the engine so it does not inflate the
// engine-named live-test floors in ci.yml.
func TestQuoteStringIsBackslashModeIndependent(t *testing.T) {
	pg := mustGet(t, "postgres")

	// The payload: under `off`, \' is two characters and the literal ends at
	// the third quote, leaving the rest to parse as SQL.
	got := pg.QuoteString(`\' ; DROP TABLE t; --`)
	if !strings.HasPrefix(got, "E'") {
		t.Fatalf("QuoteString of a backslash-bearing value = %q; want an E'…' escape string, which means the same thing in both modes", got)
	}
	if !strings.Contains(got, `\`) {
		t.Errorf("QuoteString(%q) = %q; the backslash must be doubled", `\'`, got)
	}
	// No bare quote may remain once both escape forms are removed — the same
	// property drivertest asserts, restated here against the payload itself.
	inner := got[2 : len(got)-1]
	inner = strings.ReplaceAll(inner, `\`, "")
	inner = strings.ReplaceAll(inner, `\'`, "")
	inner = strings.ReplaceAll(inner, "''", "")
	if strings.Contains(inner, "'") {
		t.Errorf("QuoteString(%q) = %q; it leaves a quote that ends the literal early", `\' ; DROP TABLE t; --`, got)
	}

	// The prefix is CONDITIONAL by design: a value with no backslash means the
	// same thing under either setting, and both conformance tests pin the plain
	// form exactly. Relaxing this into an unconditional E'…' reddens them.
	for _, s := range []string{"abc", "O'Brien", "", "line\nbreak"} {
		if q := pg.QuoteString(s); strings.HasPrefix(q, "E'") {
			t.Errorf("QuoteString(%q) = %q; a value with no backslash must keep the plain form", s, q)
		}
	}
	// SQLite shares driver.QuoteAnsiString and must be untouched: a backslash is
	// never an escape there, so an E'…' would be wrong rather than merely noisy.
	if q := mustGet(t, "sqlite").QuoteString(`back\slash`); q != `'back\slash'` {
		t.Errorf("sqlite QuoteString(%q) = %q; want the plain ANSI form", `back\slash`, q)
	}
}

// TestBuildDSNPinsStandardConformingStrings — the E'…' form above carries the
// safety; this is defence in depth, and it has to survive an operator supplying
// their own libpq options.
func TestBuildDSNPinsStandardConformingStrings(t *testing.T) {
	pg := mustGet(t, "postgres")
	base := driver.ConnParams{Host: "db", Port: 5432, User: "u", Password: "p", Database: "shop"}

	dsn, err := pg.BuildDSN(base)
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}
	if !strings.Contains(dsn, "standard_conforming_strings%3Don") {
		t.Errorf("DSN = %q; want the GUC pinned on", dsn)
	}

	// APPENDED, never Set: the export session pins search_path/row_security
	// through the same key, so a Set here would break every export. Within one
	// options string the last -c wins, which is what makes an options-carried
	// override of the same GUC harmless.
	withOpts := base
	withOpts.Params = map[string]string{"options": "-c row_security=off -c standard_conforming_strings=off"}
	dsn, err = pg.BuildDSN(withOpts)
	if err != nil {
		t.Fatalf("BuildDSN with options: %v", err)
	}
	if !strings.Contains(dsn, "row_security%3Doff") {
		t.Errorf("DSN = %q; the caller's own options were dropped", dsn)
	}
	if i, j := strings.LastIndex(dsn, "standard_conforming_strings%3Don"), strings.Index(dsn, "standard_conforming_strings%3Doff"); i < j {
		t.Errorf("DSN = %q; the pin must come after a conflicting options-carried value, so it wins", dsn)
	}

	// A DIRECT param is a different mechanism — it arrives as its own startup
	// parameter beside the computed one, and which wins is not something to
	// reason about. Rejected, like sslmode and connect_timeout.
	for _, k := range []string{"standard_conforming_strings", "STANDARD_CONFORMING_STRINGS"} {
		bad := base
		bad.Params = map[string]string{k: "off"}
		if _, err := pg.BuildDSN(bad); err == nil {
			t.Errorf("BuildDSN accepted a direct %q param", k)
		}
	}
}
