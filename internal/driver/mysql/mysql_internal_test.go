package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// TestExportConnParams pins the ExportConnAdjuster contract (3.3): the pins
// land on a CLONE of the shared Params map (the original — shared with the
// server config and session base params — stays byte-identical), and they
// overwrite any same-name config key (a configured sql_quote_show_create=0
// must not survive into an export session).
func TestExportConnParams(t *testing.T) {
	base := map[string]string{
		"sql_quote_show_create": "0",          // hostile config value: must be overwritten
		"sql_mode":              "'ANSI'",     // ditto
		"custom":                "kept-as-is", // unrelated config param: must be carried
	}
	p := dialect{}.ExportConnParams(driver.ConnParams{Host: "h", Database: "db", Params: base})

	if base["sql_quote_show_create"] != "0" || base["sql_mode"] != "'ANSI'" || len(base) != 3 {
		t.Errorf("shared config Params map was mutated: %v", base)
	}
	want := map[string]string{
		"time_zone":             "'+00:00'",
		"sql_mode":              "'NO_AUTO_VALUE_ON_ZERO'",
		"sql_quote_show_create": "1",
		"custom":                "kept-as-is",
	}
	for k, v := range want {
		if p.Params[k] != v {
			t.Errorf("Params[%s] = %q, want %q", k, p.Params[k], v)
		}
	}
	if p.Database != "db" {
		t.Errorf("scalar fields must pass through: Database = %q", p.Database)
	}
}

// TestWriteDatabaseSectionHeader covers the server-dump framing hook: the
// section header preserves a valid introspected collation and drops one that
// fails the bare-identifier check (defense-in-depth — quoting is a syntax
// error in that position).
func TestWriteDatabaseSectionHeader(t *testing.T) {
	var b strings.Builder
	dialect{}.WriteDatabaseSectionHeader(&b, "app", "utf8mb4_bin")
	if got := b.String(); got != "CREATE DATABASE IF NOT EXISTS `app` COLLATE utf8mb4_bin;\nUSE `app`;\n\n" {
		t.Errorf("section header = %q", got)
	}
	b.Reset()
	dialect{}.WriteDatabaseSectionHeader(&b, "app", "bad collation; DROP")
	if got := b.String(); strings.Contains(got, "COLLATE") {
		t.Errorf("invalid collation not dropped: %q", got)
	}
}

// TestSplitGrantee covers the Theme G unescape: a doubled quote in the stored
// grantee (O'Brien, whose quote is stored doubled) collapses back to one,
// while an unquoted grantee is
// returned trimmed.
func TestSplitGrantee(t *testing.T) {
	cases := []struct{ in, wantUser, wantHost string }{
		{"'alice'@'%'", "alice", "%"},
		{"'O''Brien'@'localhost'", "O'Brien", "localhost"},
		{"`bob`@`10.0.0.1`", "bob", "10.0.0.1"},
		{"root@localhost", "root", "localhost"},
	}
	for _, c := range cases {
		u, h := splitGrantee(c.in)
		if u != c.wantUser || h != c.wantHost {
			t.Errorf("splitGrantee(%q) = (%q,%q), want (%q,%q)", c.in, u, h, c.wantUser, c.wantHost)
		}
	}
}

func TestMapTableType(t *testing.T) {
	if mapTableType("VIEW") != model.TableView {
		t.Error("VIEW should map to TableView")
	}
	if mapTableType("BASE TABLE") != model.TableBase {
		t.Error("BASE TABLE should map to TableBase")
	}
	if mapTableType("SYSTEM VIEW") != model.TableSystem {
		t.Error("SYSTEM VIEW should map to TableSystem")
	}
	if mapTableType("SEQUENCE") != model.TableSequence {
		t.Error("SEQUENCE should map to TableSequence (MariaDB sequence object)")
	}
}

func TestSumSize(t *testing.T) {
	if got := sumSize(sql.NullInt64{}, sql.NullInt64{}); got != -1 {
		t.Errorf("sumSize of unknowns = %d, want -1", got)
	}
	if got := sumSize(sql.NullInt64{Int64: 100, Valid: true}, sql.NullInt64{Int64: 50, Valid: true}); got != 150 {
		t.Errorf("sumSize = %d, want 150", got)
	}
}

func TestDSNContainsParseTime(t *testing.T) {
	dsn, err := dialect{}.BuildDSN(driver.ConnParams{Host: "localhost", Port: 3306, User: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "parseTime=true") || !strings.Contains(dsn, "tcp(localhost:3306)") {
		t.Errorf("unexpected DSN: %q", dsn)
	}
}

// TestBuildDSNIPv6Host mirrors the postgres dialect's test: an IPv6 literal is
// bracketed exactly once in the DSN address — a bare "::1" gains brackets, an
// already-bracketed "[::1]" must not be double-bracketed into "[[::1]]:3306".
func TestBuildDSNIPv6Host(t *testing.T) {
	cases := []struct{ host, wantAddr string }{
		{"::1", "tcp([::1]:3306)"},
		{"[::1]", "tcp([::1]:3306)"},
		{"2001:db8::7", "tcp([2001:db8::7]:3306)"},
		{"[2001:db8::7]", "tcp([2001:db8::7]:3306)"},
		{"127.0.0.1", "tcp(127.0.0.1:3306)"},
	}
	for _, c := range cases {
		dsn, err := dialect{}.BuildDSN(driver.ConnParams{Host: c.host, Port: 3306, User: "u"})
		if err != nil {
			t.Fatalf("BuildDSN(%q): %v", c.host, err)
		}
		if !strings.Contains(dsn, c.wantAddr) {
			t.Errorf("BuildDSN(%q) = %q, want address %q", c.host, dsn, c.wantAddr)
		}
	}
}

// TestOpenPoolSSLModes proves every SSL-mode value the login form can emit —
// including the PostgreSQL-only ones (prefer/allow/verify-ca/verify-full) that
// the selector posts for a MySQL login — builds a pool without error. OpenPool
// calls gomysql.NewConnector, which runs Config.normalize: the exact path that
// rejected "prefer" with "invalid value / unknown config name: prefer". No live
// MySQL is contacted (the pool is lazy), so this needs no Docker.
func TestOpenPoolSSLModes(t *testing.T) {
	for _, m := range []string{"", "disable", "prefer", "allow", "require", "verify-ca", "verify-full", "skip-verify"} {
		db, err := dialect{}.OpenPool(driver.ConnParams{Host: "127.0.0.1", Port: 3306, SSLMode: m})
		if err != nil {
			t.Fatalf("OpenPool sslmode=%q: %v", m, err)
		}
		db.Close()
	}
}

// TestBuildDSNSSLModeTLS asserts the neutral SSL vocabulary is translated to the
// driver's accepted tls= token rather than passed through raw. require maps to
// skip-verify (encrypt, unverified — PG `require` semantics without a root CA);
// only verify-ca/verify-full/true authenticate (tls=true).
func TestBuildDSNSSLModeTLS(t *testing.T) {
	cases := map[string]string{
		"prefer":      "tls=preferred",
		"allow":       "tls=preferred",
		"require":     "tls=skip-verify",
		"verify-ca":   "tls=true",
		"verify-full": "tls=true",
		"skip-verify": "tls=skip-verify",
	}
	for mode, want := range cases {
		dsn, err := dialect{}.BuildDSN(driver.ConnParams{Host: "127.0.0.1", Port: 3306, SSLMode: mode})
		if err != nil {
			t.Fatalf("BuildDSN sslmode=%q: %v", mode, err)
		}
		if !strings.Contains(dsn, want) {
			t.Errorf("BuildDSN sslmode=%q: %q missing %q", mode, dsn, want)
		}
	}
	// "disable" / "" carry no TLS, so no tls= token appears.
	dsn, err := dialect{}.BuildDSN(driver.ConnParams{Host: "127.0.0.1", Port: 3306, SSLMode: "disable"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dsn, "tls=") {
		t.Errorf("BuildDSN sslmode=disable: unexpected tls= token in %q", dsn)
	}
}

// TestBuildDSNUnknownSSLModeRejected proves an unknown sslmode (reachable via a
// predefined server's TOML, which bypasses the login form's engine gate) is
// rejected with a clear error instead of being forwarded raw as a registered
// TLS-config name.
func TestBuildDSNUnknownSSLModeRejected(t *testing.T) {
	if _, err := (dialect{}).BuildDSN(driver.ConnParams{Host: "127.0.0.1", Port: 3306, SSLMode: "bogus"}); err == nil {
		t.Fatal("BuildDSN with unknown sslmode: expected error, got nil")
	}
	if _, err := (dialect{}).OpenPool(driver.ConnParams{Host: "127.0.0.1", Port: 3306, SSLMode: "bogus"}); err == nil {
		t.Fatal("OpenPool with unknown sslmode: expected error, got nil")
	}
}

// TestBuildDSNParamsTLSRejected proves a tls connection param is rejected (it is
// not a session system variable, so go-sql-driver would SET tls=… and fail);
// TLS is configured only via sslmode. A non-tls param is still forwarded.
func TestBuildDSNParamsTLSRejected(t *testing.T) {
	for _, sslmode := range []string{"", "require"} {
		if _, err := (dialect{}).BuildDSN(driver.ConnParams{
			Host: "127.0.0.1", Port: 3306, SSLMode: sslmode,
			Params: map[string]string{"tls": "skip-verify"},
		}); err == nil {
			t.Errorf("tls param with sslmode=%q should be rejected", sslmode)
		}
	}
	// A non-tls param is still forwarded into the DSN.
	dsn, err := dialect{}.BuildDSN(driver.ConnParams{
		Host: "127.0.0.1", Port: 3306,
		Params: map[string]string{"charset": "utf8mb4"},
	})
	if err != nil {
		t.Fatalf("non-tls param should be honored: %v", err)
	}
	if !strings.Contains(dsn, "charset=utf8mb4") {
		t.Errorf("non-tls param missing from DSN: %q", dsn)
	}
}

func ptr(s string) *string { return &s }

// keyParts builds plain (no prefix, ascending) index key parts.
func keyParts(names ...string) []driver.IndexColumn {
	out := make([]driver.IndexColumn, len(names))
	for i, n := range names {
		out[i] = driver.IndexColumn{Name: n}
	}
	return out
}

// TestQuoteStringModes pins: a quote is always doubled (mode-independent),
// while backslash/control escapes are emitted only in the default mode. Under
// NO_BACKSLASH_ESCAPES a backslash stays literal (escaping it would corrupt the
// value), and a NUL byte — which has no literal spelling there — is spliced via
// CHAR(0).
func TestQuoteStringModes(t *testing.T) {
	def := dialect{}
	nbe := dialect{}.WithServerInfo(driver.ServerInfo{SQLMode: "STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES"})

	cases := []struct {
		name, in, wantDefault, wantNBE string
	}{
		{"quote", "O'Brien", `'O''Brien'`, `'O''Brien'`},
		{"backslash", `a\b`, `'a\\b'`, `'a\b'`},
		{"newline", "a\nb", `'a\nb'`, "'a\nb'"},
		{"quote+backslash", `it's\`, `'it''s\\'`, `'it''s\'`},
	}
	for _, c := range cases {
		if got := def.QuoteString(c.in); got != c.wantDefault {
			t.Errorf("%s default: QuoteString(%q) = %q, want %q", c.name, c.in, got, c.wantDefault)
		}
		if got := nbe.QuoteString(c.in); got != c.wantNBE {
			t.Errorf("%s no-backslash: QuoteString(%q) = %q, want %q", c.name, c.in, got, c.wantNBE)
		}
	}
	// A NUL byte: \0 escape in default mode, CHAR(0) splice under NO_BACKSLASH_ESCAPES.
	if got := def.QuoteString("a\x00b"); got != `'a\0b'` {
		t.Errorf("NUL default = %q, want 'a\\0b'", got)
	}
	if got := nbe.QuoteString("a\x00b"); got != "CONCAT('a', CHAR(0), 'b')" {
		t.Errorf("NUL no-backslash = %q, want CONCAT('a', CHAR(0), 'b')", got)
	}
}

// TestMySQLDefaultKind pins the flavor-aware default classifier: MySQL 8 marks
// expression defaults with DEFAULT_GENERATED, while MariaDB quotes literal
// strings (expressions stay unquoted) and renders DEFAULT NULL as the bare
// keyword — kept distinct (isNull) from the quoted literal string 'NULL', so
// a modify round-trip cannot rewrite one into the other. Every case here is a
// def.Valid value: MySQL's explicit DEFAULT NULL arrives as SQL NULL and is
// filtered by the caller's def.Valid guard before this classifier runs.
func TestMySQLDefaultKind(t *testing.T) {
	valid := func(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
	cases := []struct {
		name     string
		mariadb  bool
		nbe      bool // session sql_mode carries NO_BACKSLASH_ESCAPES
		def      sql.NullString
		extra    string
		wantVal  string
		wantExpr bool
		wantNull bool
	}{
		{"mysql8 marked expression", false, false, valid("uuid()"), "DEFAULT_GENERATED", "uuid()", true, false},
		{"mysql8 current_timestamp", false, false, valid("CURRENT_TIMESTAMP"), "DEFAULT_GENERATED", "CURRENT_TIMESTAMP", true, false},
		{"mysql literal string (unquoted)", false, false, valid("hello"), "", "hello", false, false},
		{"mysql numeric literal", false, false, valid("0"), "", "0", false, false},
		// MySQL stores the literal string default 'NULL' as the unquoted 4-char
		// value: it is a custom literal, never the keyword null.
		{"mysql literal string NULL", false, false, valid("NULL"), "", "NULL", false, false},
		{"mysql literal string CURRENT_TIMESTAMP", false, false, valid("CURRENT_TIMESTAMP"), "", "CURRENT_TIMESTAMP", false, false},
		{"mariadb quoted literal", true, false, valid("'hello'"), "", "hello", false, false},
		{"mariadb doubled-quote literal", true, false, valid("'it''s'"), "", "it's", false, false},
		{"mariadb unquoted expression", true, false, valid("current_timestamp()"), "", "current_timestamp()", true, false},
		{"mariadb NOW() expression", true, false, valid("NOW()"), "", "NOW()", true, false},
		{"mariadb explicit NULL keyword", true, false, valid("NULL"), "", "NULL", false, true},
		// The three MariaDB spellings of "NULL"/"CURRENT_TIMESTAMP" stay a
		// three-way split: keyword (above), quoted literal, expression.
		{"mariadb quoted literal NULL string", true, false, valid("'NULL'"), "", "NULL", false, false},
		{"mariadb quoted literal CURRENT_TIMESTAMP string", true, false, valid("'CURRENT_TIMESTAMP'"), "", "CURRENT_TIMESTAMP", false, false},
		// MariaDB stores numeric literals unquoted, so the classifier treats them
		// as expressions; re-applied they become DEFAULT (0) — cosmetically
		// parenthesized but functionally identical, and the dump path (SHOW CREATE)
		// is unaffected.
		{"mariadb numeric literal", true, false, valid("42"), "", "42", true, false},
		// MariaDB literal defaults come back through the server's string-literal
		// grammar, backslash escapes included — the reader must invert every one
		// the writer can emit, or the display is off by one escape and every
		// modify Save adds another.
		{"mariadb backslash literal", true, false, valid(`'a\\b'`), "", `a\b`, false, false},
		{"mariadb every escape", true, false, valid(`'\0\'\"\b\n\r\t\Z\\'`), "", "\x00'\"\b\n\r\t\x1a\\", false, false},
		// \% and \_ keep their backslash (LIKE-pattern escapes, preserved
		// verbatim by the server's literal grammar).
		{"mariadb like-pattern escapes", true, false, valid(`'100\%\_x'`), "", `100\%\_x`, false, false},
		// An unknown escape yields the escaped character itself.
		{"mariadb unknown escape", true, false, valid(`'a\xb'`), "", "axb", false, false},
		{"mariadb quote+backslash", true, false, valid(`'it''s\\'`), "", `it's\`, false, false},
		// Under NO_BACKSLASH_ESCAPES a backslash is an ordinary character —
		// the same mode split QuoteString (the writer) makes.
		{"mariadb NBE backslash literal", true, true, valid(`'a\b'`), "", `a\b`, false, false},
		{"mariadb NBE doubled quote", true, true, valid(`'it''s\'`), "", `it's\`, false, false},
	}
	for _, c := range cases {
		gotVal, gotExpr, gotNull := mysqlDefaultKind(c.mariadb, c.nbe, c.def, c.extra)
		if gotVal != c.wantVal || gotExpr != c.wantExpr || gotNull != c.wantNull {
			t.Errorf("%s: got (%q,%v,%v), want (%q,%v,%v)", c.name, gotVal, gotExpr, gotNull, c.wantVal, c.wantExpr, c.wantNull)
		}
	}
}

// TestMariaDBLiteralRoundTrip pins the no-compounding property directly: for
// any value, quoting through the writer (QuoteString) and decoding the body
// back through the reader (unescapeMariaDBLiteral) must return the original
// bytes — in BOTH escape modes. This is the invariant that makes a second
// consecutive column-modify Save a no-op instead of adding one more backslash
// per round trip.
func TestMariaDBLiteralRoundTrip(t *testing.T) {
	corpus := []string{
		"", "plain", `a\b`, `a\\b`, "it's", `it's\`, "line1\nline2",
		"tab\there", "cr\rhere", "bell\bhere", "ctrlz\x1ahere", "nul\x00here",
		`100\%`, `under\_score`, `mixed 'quote' and \slash\`, "ünïcode✓",
	}
	def := dialect{}
	nbe := dialect{}.WithServerInfo(driver.ServerInfo{SQLMode: "NO_BACKSLASH_ESCAPES"})
	for _, v := range corpus {
		if q := def.QuoteString(v); strings.HasPrefix(q, "'") && strings.HasSuffix(q, "'") {
			if got := unescapeMariaDBLiteral(q[1:len(q)-1], false); got != v {
				t.Errorf("default mode: unescape(quote(%q)) = %q — a modify Save would compound", v, got)
			}
		}
		q := nbe.QuoteString(v)
		if !strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'") {
			continue // the CHAR(0) CONCAT splice is not a plain literal; the server re-renders it
		}
		if got := unescapeMariaDBLiteral(q[1:len(q)-1], true); got != v {
			t.Errorf("NO_BACKSLASH_ESCAPES: unescape(quote(%q)) = %q — a modify Save would compound", v, got)
		}
	}
}

func TestMySQLSchemaEditorSQL(t *testing.T) {
	d := dialect{}
	tr := driver.TableRef{Database: "shop", Table: "items"}

	// one asserts the builder produced exactly one statement and returns it.
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

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"add not null default", one(d.AddColumnSQL(tr, driver.ColumnSpec{Name: "price", Type: "DECIMAL(10,2)", Default: ptr("0")})),
			"ALTER TABLE `shop`.`items` ADD COLUMN `price` DECIMAL(10,2) NOT NULL DEFAULT 0"},
		{"add nullable with comment", one(d.AddColumnSQL(tr, driver.ColumnSpec{Name: "note", Type: "VARCHAR(50)", Nullable: true, Comment: "hi"})),
			"ALTER TABLE `shop`.`items` ADD COLUMN `note` VARCHAR(50) NULL COMMENT 'hi'"},
		{"modify", one(d.ModifyColumnSQL(tr, "price", driver.ColumnSpec{Name: "price", Type: "INT"})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `price` INT NOT NULL"},
		// Preserved attributes are emitted only on type categories where they are
		// valid: INT carries AUTO_INCREMENT but never CHARACTER SET/COLLATE or
		// ON UPDATE (each is a hard syntax error on a numeric column).
		{"modify preserves valid attrs only", one(d.ModifyColumnSQL(tr, "id", driver.ColumnSpec{Name: "id", Type: "INT", AutoIncrement: true, Charset: "utf8mb4", Collation: "utf8mb4_bin", OnUpdate: "CURRENT_TIMESTAMP", Comment: "x"})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `id` INT NOT NULL AUTO_INCREMENT COMMENT 'x'"},
		{"modify keeps unsigned zerofill", one(d.ModifyColumnSQL(tr, "qty", driver.ColumnSpec{Name: "qty", Type: "INT", Unsigned: true, Zerofill: true, Comment: "c"})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `qty` INT UNSIGNED ZEROFILL NOT NULL COMMENT 'c'"},
		{"unsigned dropped on string type", one(d.ModifyColumnSQL(tr, "qty", driver.ColumnSpec{Name: "qty", Type: "VARCHAR(20)", Unsigned: true, Nullable: true})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `qty` VARCHAR(20) NULL"},
		{"charset kept on string type", one(d.ModifyColumnSQL(tr, "note", driver.ColumnSpec{Name: "note", Type: "VARCHAR(50)", Nullable: true, Charset: "utf8mb4", Collation: "utf8mb4_bin"})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `note` VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL"},
		{"on update kept on timestamp", one(d.ModifyColumnSQL(tr, "ts", driver.ColumnSpec{Name: "ts", Type: "TIMESTAMP", OnUpdate: "CURRENT_TIMESTAMP", Default: ptr("CURRENT_TIMESTAMP"), DefaultExpr: true})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `ts` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"},
		// Expression defaults are wrapped in the parentheses MySQL requires;
		// literal defaults stay verbatim.
		{"expression default parenthesized", one(d.ModifyColumnSQL(tr, "u", driver.ColumnSpec{Name: "u", Type: "VARCHAR(36)", Nullable: true, Default: ptr("uuid()"), DefaultExpr: true})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `u` VARCHAR(36) NULL DEFAULT (uuid())"},
		{"literal default not parenthesized", one(d.ModifyColumnSQL(tr, "s", driver.ColumnSpec{Name: "s", Type: "VARCHAR(10)", Nullable: true, Default: ptr("'abc'")})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `s` VARCHAR(10) NULL DEFAULT 'abc'"},
		// FIRST / AFTER ride ADD and MODIFY only — CREATE TABLE takes its order
		// from the column list — and the referenced column is quoted like any
		// other identifier.
		{"add first", one(d.AddColumnSQL(tr, driver.ColumnSpec{Name: "a", Type: "INT", Placement: driver.PlaceFirst})),
			"ALTER TABLE `shop`.`items` ADD COLUMN `a` INT NOT NULL FIRST"},
		{"add after", one(d.AddColumnSQL(tr, driver.ColumnSpec{Name: "a", Type: "INT", Placement: driver.PlaceAfter, PlacementAfter: "we`ird"})),
			"ALTER TABLE `shop`.`items` ADD COLUMN `a` INT NOT NULL AFTER `we``ird`"},
		{"modify moves the column", one(d.ModifyColumnSQL(tr, "qty", driver.ColumnSpec{Name: "qty", Type: "INT", Placement: driver.PlaceAfter, PlacementAfter: "id"})),
			"ALTER TABLE `shop`.`items` MODIFY COLUMN `qty` INT NOT NULL AFTER `id`"},
		// PlacementAfter without PlaceAfter is inert: the placement KIND decides,
		// so a stale name cannot leak into the statement.
		{"placement default ignores the after name", one(d.AddColumnSQL(tr, driver.ColumnSpec{Name: "a", Type: "INT", PlacementAfter: "id"})),
			"ALTER TABLE `shop`.`items` ADD COLUMN `a` INT NOT NULL"},
		{"drop column", one(d.DropColumnSQL(tr, "price")),
			"ALTER TABLE `shop`.`items` DROP COLUMN `price`"},
		{"add index", one(d.AddIndexSQL(tr, driver.IndexSpec{Name: "idx_ab", Columns: keyParts("a", "b")})),
			"ALTER TABLE `shop`.`items` ADD INDEX `idx_ab` (`a`, `b`)"},
		{"add unique index", one(d.AddIndexSQL(tr, driver.IndexSpec{Name: "u", Columns: keyParts("a"), Unique: true})),
			"ALTER TABLE `shop`.`items` ADD UNIQUE INDEX `u` (`a`)"},
		// Prefix length rides the key part, in key order.
		{"add index with prefix", one(d.AddIndexSQL(tr, driver.IndexSpec{
			Name: "idx_p", Columns: []driver.IndexColumn{{Name: "a", Prefix: 10}, {Name: "b"}},
		})), "ALTER TABLE `shop`.`items` ADD INDEX `idx_p` (`a`(10), `b`)"},
		// DESC is emitted only where it is HONOURED. An unspecialized dialect
		// (unknown version) and MariaDB — which parses the keyword and then
		// ignores it — both drop it rather than build an index that silently is
		// not what was asked for.
		{"desc on MySQL 8.0", one(dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MySQL", Version: "8.0.35"}).(dialect).
			AddIndexSQL(tr, driver.IndexSpec{Name: "i", Columns: []driver.IndexColumn{{Name: "a", Desc: true}}})),
			"ALTER TABLE `shop`.`items` ADD INDEX `i` (`a` DESC)"},
		{"desc dropped on MySQL 8.0.0", one(dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MySQL", Version: "8.0.0"}).(dialect).
			AddIndexSQL(tr, driver.IndexSpec{Name: "i", Columns: []driver.IndexColumn{{Name: "a", Desc: true}}})),
			"ALTER TABLE `shop`.`items` ADD INDEX `i` (`a`)"},
		{"desc dropped on MariaDB", one(dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MariaDB", Version: "11.4.2-MariaDB"}).(dialect).
			AddIndexSQL(tr, driver.IndexSpec{Name: "i", Columns: []driver.IndexColumn{{Name: "a", Desc: true}}})),
			"ALTER TABLE `shop`.`items` ADD INDEX `i` (`a`)"},
		{"drop index", one(d.DropIndexSQL(tr, "idx_ab")),
			"ALTER TABLE `shop`.`items` DROP INDEX `idx_ab`"},
		{"add fk", one(d.AddForeignKeySQL(tr, "fk1", []string{"author_id"}, "authors", []string{"id"}, "CASCADE", "SET NULL")),
			"ALTER TABLE `shop`.`items` ADD CONSTRAINT `fk1` FOREIGN KEY (`author_id`) REFERENCES `shop`.`authors` (`id`) ON UPDATE CASCADE ON DELETE SET NULL"},
		{"add fk no actions", one(d.AddForeignKeySQL(tr, "fk2", []string{"a"}, "other", []string{"id"}, "", "")),
			"ALTER TABLE `shop`.`items` ADD CONSTRAINT `fk2` FOREIGN KEY (`a`) REFERENCES `shop`.`other` (`id`)"},
		{"drop fk", one(d.DropForeignKeySQL(tr, "fk1")),
			"ALTER TABLE `shop`.`items` DROP FOREIGN KEY `fk1`"},
		// M6: DROP routes to DROP TABLE / DROP VIEW; RENAME uses RENAME TABLE for
		// both (ALTER TABLE ... RENAME fails on a view with error 1347).
		{"drop table", one(d.DropObjectSQL(tr, driver.ObjectTable)),
			"DROP TABLE `shop`.`items`"},
		{"drop view", one(d.DropObjectSQL(tr, driver.ObjectView)),
			"DROP VIEW `shop`.`items`"},
		{"rename table", one(d.RenameObjectSQL(tr, "renamed", driver.ObjectTable)),
			"RENAME TABLE `shop`.`items` TO `shop`.`renamed`"},
		{"rename view", one(d.RenameObjectSQL(tr, "renamed", driver.ObjectView)),
			"RENAME TABLE `shop`.`items` TO `shop`.`renamed`"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
}

// TestMySQLCreateTableSQL pins the exact CREATE TABLE the SchemaEditor emits:
// one statement, PK as a table constraint, column comments inline (MySQL
// grammar), and the shared contract checks rejecting bad input.
func TestMySQLCreateTableSQL(t *testing.T) {
	d := dialect{}
	tr := driver.TableRef{Database: "shop", Table: "orders"}
	got, err := d.CreateTableSQL(tr, []driver.ColumnSpec{
		{Name: "id", Type: "INT"},
		{Name: "note", Type: "VARCHAR(50)", Nullable: true, Comment: "hi"},
	}, []string{"id"})
	if err != nil {
		t.Fatalf("CreateTableSQL: %v", err)
	}
	want := "CREATE TABLE `shop`.`orders` (\n  `id` INT NOT NULL,\n  `note` VARCHAR(50) NULL COMMENT 'hi',\n  PRIMARY KEY (`id`)\n)"
	if len(got) != 1 || got[0] != want {
		t.Errorf("CreateTableSQL:\n got %q\nwant %q", got, want)
	}

	if _, err := d.CreateTableSQL(tr, nil, nil); err == nil {
		t.Error("empty column list should error")
	}
	if _, err := d.CreateTableSQL(tr, []driver.ColumnSpec{{Name: "id", Type: "INT"}}, []string{"ghost"}); err == nil {
		t.Error("pk entry not among the columns should error")
	}
	if _, err := d.CreateTableSQL(tr, []driver.ColumnSpec{{Name: "id", Type: "INT"}, {Name: "id", Type: "INT"}}, nil); err == nil {
		t.Error("duplicate column names should error")
	}
}

// TestMySQLUserAndPrivilegeSQL pins the exact DCL the UserManager /
// PrivilegeManager builders emit: account parts are string literals
// (QuoteString), objects are identifiers (QuoteIdent), grant privileges are
// validated against the scope's allowlist while revoke accepts any keyword
// shape (introspection-driven), and injection shapes are rejected.
func TestMySQLUserAndPrivilegeSQL(t *testing.T) {
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
	fails := func(got []string, err error) error {
		t.Helper()
		if err == nil {
			t.Fatalf("expected error, got statements %v", got)
		}
		return err
	}

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"create user with password (escaped)",
			one(d.CreateUserSQL(driver.UserSpec{Name: "alice", Host: "%", Password: `it's\`, SetPassword: true})),
			// Default mode: quote doubled ('' — mode-independent), backslash escaped.
			`CREATE USER 'alice'@'%' IDENTIFIED BY 'it''s\\'`},
		{"account host emitted verbatim (default is the handler's job)",
			one(d.CreateUserSQL(driver.UserSpec{Name: "bob", Host: "%"})),
			`CREATE USER 'bob'@'%'`},
		{"empty host is targeted exactly, not aliased to %",
			one(d.DropUserSQL("bob", "")),
			`DROP USER 'bob'@''`},
		{"account name quoted as literal, not identifier",
			one(d.CreateUserSQL(driver.UserSpec{Name: "a'b", Host: "localhost"})),
			`CREATE USER 'a''b'@'localhost'`},
		{"set password",
			one(d.AlterUserSQL(driver.UserSpec{Name: "alice", Host: "localhost", Password: "new", SetPassword: true})),
			`ALTER USER 'alice'@'localhost' IDENTIFIED BY 'new'`},
		{"drop user",
			one(d.DropUserSQL("alice", "localhost")),
			`DROP USER 'alice'@'localhost'`},
		{"grant db scope normalizes case",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"select", " Insert "}, Database: "shop", Grantee: "alice", Host: "%"})),
			"GRANT SELECT, INSERT ON `shop`.* TO 'alice'@'%'"},
		// The db-scope target is a LIKE pattern, so _ and % are escaped —
		// otherwise `my_app`.* would over-grant on `myXapp` too.
		{"grant db scope escapes pattern metacharacters",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "my_app", Grantee: "alice", Host: "%"})),
			"GRANT SELECT ON `my\\_app`.* TO 'alice'@'%'"},
		// Table scope is literal (the db part there is not a pattern), so no escaping.
		{"grant table scope does not escape the db name",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "my_app", Table: "t", Grantee: "alice", Host: "%"})),
			"GRANT SELECT ON `my_app`.`t` TO 'alice'@'%'"},
		{"grant table scope with grant option",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Table: "items", Grantee: "alice", Host: "%", WithGrant: true})),
			"GRANT SELECT ON `shop`.`items` TO 'alice'@'%' WITH GRANT OPTION"},
		{"grant db-only privilege at db scope",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"EVENT"}, Database: "shop", Grantee: "alice", Host: "%"})),
			"GRANT EVENT ON `shop`.* TO 'alice'@'%'"},
		{"revoke",
			one(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Grantee: "alice", Host: "%"})),
			"REVOKE SELECT ON `shop`.* FROM 'alice'@'%'"},
		// Revoke is keyword-gated, not allowlist-gated: EVENT is not table-
		// grantable but an existing grant of it must stay revokable.
		{"revoke accepts keyword outside the table allowlist",
			one(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"EVENT"}, Database: "shop", Table: "items", Grantee: "alice", Host: "%"})),
			"REVOKE EVENT ON `shop`.`items` FROM 'alice'@'%'"},
		// Column scope. Each privilege carries its own copy of the list — that
		// is the grammar, not a formatting choice: "SELECT, UPDATE (a)" would
		// grant SELECT on the WHOLE table and UPDATE on one column.
		{"grant one column",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Table: "items",
				Grantee: "alice", Host: "%", Columns: []string{"price"}})),
			"GRANT SELECT (`price`) ON `shop`.`items` TO 'alice'@'%'"},
		{"grant repeats the column list per privilege",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT", "UPDATE"}, Database: "shop", Table: "items",
				Grantee: "alice", Host: "%", Columns: []string{"price", "sku"}})),
			"GRANT SELECT (`price`, `sku`), UPDATE (`price`, `sku`) ON `shop`.`items` TO 'alice'@'%'"},
		{"column names are quoted, not interpolated",
			one(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Table: "items",
				Grantee: "alice", Host: "%", Columns: []string{"a`b"}})),
			"GRANT SELECT (`a``b`) ON `shop`.`items` TO 'alice'@'%'"},
		{"revoke one column",
			one(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Table: "items",
				Grantee: "alice", Host: "%", Columns: []string{"price"}})),
			"REVOKE SELECT (`price`) ON `shop`.`items` FROM 'alice'@'%'"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}

	// Db-scope revoke by stored pattern: MySQL matches grant rows by the exact
	// stored pattern string, so when the introspection supplies the stored
	// forms (raw for an externally-created grant, escaped for TableX's own),
	// one REVOKE per pattern is emitted verbatim — no re-escaping.
	stmts, err := d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "my_app",
		Grantee: "alice", Host: "%", DatabasePatterns: []string{"my_app", `my\_app`}})
	if err != nil {
		t.Fatalf("stored-pattern revoke: %v", err)
	}
	wantStmts := []string{
		"REVOKE SELECT ON `my_app`.* FROM 'alice'@'%'",
		"REVOKE SELECT ON `my\\_app`.* FROM 'alice'@'%'",
	}
	if len(stmts) != 2 || stmts[0] != wantStmts[0] || stmts[1] != wantStmts[1] {
		t.Errorf("stored-pattern revoke:\n got %q\nwant %q", stmts, wantStmts)
	}
	// Table scope ignores the field — the table-scope db part is literal.
	if got := one(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "my_app", Table: "t",
		Grantee: "alice", Host: "%", DatabasePatterns: []string{"my_app"}})); got != "REVOKE SELECT ON `my_app`.`t` FROM 'alice'@'%'" {
		t.Errorf("table-scope revoke with DatabasePatterns = %q, want the literal table target", got)
	}

	fails(d.AlterUserSQL(driver.UserSpec{Name: "alice", Host: "%"}))                                                                          // nothing to change
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"EVENT"}, Database: "shop", Table: "items", Grantee: "a", Host: "%"}))             // db-only priv at table scope
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"BOGUS"}, Database: "shop", Grantee: "a", Host: "%"}))                             // unknown privilege
	fails(d.GrantSQL(driver.GrantSpec{Privileges: nil, Database: "shop", Grantee: "a", Host: "%"}))                                           // empty set
	fails(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT; DROP TABLE x"}, Database: "shop", Grantee: "a", Host: "%"}))             // injection shape
	fails(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT ON `x`.* FROM 'y'@'%'; --"}, Database: "shop", Grantee: "a", Host: "%"})) // injection shape
	// Column scope: the two ways a caller can ask for something the grammar
	// cannot express. Both must ERROR rather than silently emit the wider
	// object-wide grant.
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Grantee: "a", Host: "%",
		Columns: []string{"price"}})) // db scope takes no column list
	fails(d.GrantSQL(driver.GrantSpec{Privileges: []string{"DELETE"}, Database: "shop", Table: "items", Grantee: "a", Host: "%",
		Columns: []string{"price"}})) // DELETE has no column form
	// Revoke keeps the looser keyword rule (an introspected grant authorizes
	// it) but not the looser TARGET rule: a column list still needs a table.
	fails(d.RevokeSQL(driver.GrantSpec{Privileges: []string{"SELECT"}, Database: "shop", Grantee: "a", Host: "%",
		Columns: []string{"price"}}))
}

// TestMySQLRoutineGrantSQL pins the routine-grant builders. MySQL has no
// "ON ROUTINE", so the FUNCTION/PROCEDURE keyword is mandatory and a wrong one
// addresses an object that does not exist rather than failing to parse.
func TestMySQLRoutineGrantSQL(t *testing.T) {
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
	scope := driver.Scope{Database: "shop"}
	fn := model.Routine{Name: "calc", Type: "FUNCTION"}
	proc := model.Routine{Name: "do_it", Type: "PROCEDURE"}
	for _, c := range []struct{ name, got, want string }{
		{"grant execute on a function",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"execute"}, Grantee: "alice", Host: "%"})),
			"GRANT EXECUTE ON FUNCTION `shop`.`calc` TO 'alice'@'%'"},
		{"grant on a procedure",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: proc, Privileges: []string{"ALTER ROUTINE"}, Grantee: "alice", Host: "%"})),
			"GRANT ALTER ROUTINE ON PROCEDURE `shop`.`do_it` TO 'alice'@'%'"},
		// The routine target's database part is LITERAL, unlike the db-scope
		// `db`.* target, which is a LIKE pattern — so _ is NOT escaped here.
		{"the database part is not pattern-escaped",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: driver.Scope{Database: "my_app"}, Routine: fn, Privileges: []string{"EXECUTE"}, Grantee: "alice", Host: "%"})),
			"GRANT EXECUTE ON FUNCTION `my_app`.`calc` TO 'alice'@'%'"},
		{"grant option",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"EXECUTE"}, Grantee: "alice", Host: "%", WithGrant: true})),
			"GRANT EXECUTE ON FUNCTION `shop`.`calc` TO 'alice'@'%' WITH GRANT OPTION"},
		{"revoke",
			one(d.RevokeRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn, Privileges: []string{"EXECUTE"}, Grantee: "alice", Host: "%"})),
			"REVOKE EXECUTE ON FUNCTION `shop`.`calc` FROM 'alice'@'%'"},
		{"name is quoted as an identifier",
			one(d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: model.Routine{Name: "ca`lc", Type: "FUNCTION"}, Privileges: []string{"EXECUTE"}, Grantee: "alice", Host: "%"})),
			"GRANT EXECUTE ON FUNCTION `shop`.`ca``lc` TO 'alice'@'%'"},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}
	// SELECT has no routine form; GRANT OPTION is the WithGrant flag, not a
	// grantable privilege of its own.
	for _, p := range []string{"SELECT", "GRANT OPTION", "BOGUS"} {
		if stmts, err := d.GrantRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn,
			Privileges: []string{p}, Grantee: "alice", Host: "%"}); err == nil {
			t.Errorf("GrantRoutineSQL(%q) = %q, want an error", p, stmts)
		}
	}
	if stmts, err := d.RevokeRoutineSQL(driver.RoutineGrant{Scope: scope, Routine: fn,
		Privileges: []string{"EXECUTE ON FUNCTION x; --"}, Grantee: "alice", Host: "%"}); err == nil {
		t.Errorf("RevokeRoutineSQL(injection shape) = %q, want an error", stmts)
	}
}

// TestMySQLRoleMembershipSQL pins the two role-grant shapes this one dialect
// has to speak. They differ in what a role IS: a MySQL 8 role is an account, so
// it is addressed 'r'@'host' and 'r'@'%' is a different role from 'r'@'localhost';
// a MariaDB role has no host at all and is named as a bare string literal.
// Emitting either shape at the other server is a syntax error, so the flavor
// gate is load-bearing, not cosmetic.
func TestMySQLRoleMembershipSQL(t *testing.T) {
	mysql8 := dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MySQL", Version: "8.4.0"}).(dialect)
	maria := dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MariaDB", Version: "11.4.2-MariaDB"}).(dialect)
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
		{"MySQL 8 addresses the role as an account",
			one(mysql8.GrantRoleSQL(driver.RoleGrant{Role: "readers", RoleHost: "%", Member: "alice", MemberHost: "localhost"})),
			`GRANT 'readers'@'%' TO 'alice'@'localhost'`},
		{"MySQL 8 with admin option",
			one(mysql8.GrantRoleSQL(driver.RoleGrant{Role: "readers", RoleHost: "%", Member: "alice", MemberHost: "%", AdminOption: true})),
			`GRANT 'readers'@'%' TO 'alice'@'%' WITH ADMIN OPTION`},
		{"MySQL 8 revoke ignores the admin option",
			one(mysql8.RevokeRoleSQL(driver.RoleGrant{Role: "readers", RoleHost: "%", Member: "alice", MemberHost: "%", AdminOption: true})),
			`REVOKE 'readers'@'%' FROM 'alice'@'%'`},
		{"MariaDB names the role bare, with no host",
			one(maria.GrantRoleSQL(driver.RoleGrant{Role: "readers", RoleHost: "", Member: "alice", MemberHost: "%"})),
			`GRANT 'readers' TO 'alice'@'%'`},
		// A stray host on MariaDB is inert — the role side has no host there, so
		// carrying one through would build 'readers'@'%', which MariaDB parses
		// as a USER and refuses.
		{"MariaDB ignores a role host it was handed",
			one(maria.GrantRoleSQL(driver.RoleGrant{Role: "readers", RoleHost: "%", Member: "alice", MemberHost: "%"})),
			`GRANT 'readers' TO 'alice'@'%'`},
		{"MariaDB revoke",
			one(maria.RevokeRoleSQL(driver.RoleGrant{Role: "readers", Member: "alice", MemberHost: "%"})),
			`REVOKE 'readers' FROM 'alice'@'%'`},
		// Both sides are string literals in this grammar, so a quote is doubled,
		// never escaped into the statement.
		{"role name is quoted as a literal",
			one(maria.GrantRoleSQL(driver.RoleGrant{Role: "re'ad", Member: "alice", MemberHost: "%"})),
			`GRANT 're''ad' TO 'alice'@'%'`},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, c.got, c.want)
		}
	}

	// The version gate fails CLOSED: an unspecialized dialect (no version) and
	// any pre-role server must refuse to build, because the statement does not
	// exist there and the catalog table the UI would read is absent.
	for _, d := range []dialect{
		{}, // registered, unspecialized: version unknown
		dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MySQL", Version: "5.7.44"}).(dialect),
		dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MariaDB", Version: "10.0.4-MariaDB"}).(dialect),
	} {
		if d.Capabilities().SupportsRoles {
			t.Errorf("dialect %+v reports SupportsRoles; the gate must fail closed on an unknown or pre-role version", d)
		}
		if stmts, err := d.GrantRoleSQL(driver.RoleGrant{Role: "readers", Member: "alice", MemberHost: "%"}); err == nil {
			t.Errorf("GrantRoleSQL on a server without roles = %q, want an error", stmts)
		}
	}
	// ...and opens exactly at the documented floors.
	for _, d := range []dialect{
		dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MySQL", Version: "8.0.0"}).(dialect),
		dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MariaDB", Version: "10.0.5-MariaDB"}).(dialect),
	} {
		if !d.Capabilities().SupportsRoles {
			t.Errorf("dialect %+v should report SupportsRoles", d)
		}
	}
	// Both ends are required whatever the version.
	for _, g := range []driver.RoleGrant{{Role: "", Member: "alice"}, {Role: "readers", Member: ""}} {
		if stmts, err := mysql8.GrantRoleSQL(g); err == nil {
			t.Errorf("GrantRoleSQL(%+v) = %q, want an error", g, stmts)
		}
		if stmts, err := mysql8.RevokeRoleSQL(g); err == nil {
			t.Errorf("RevokeRoleSQL(%+v) = %q, want an error", g, stmts)
		}
	}
}

// TestMySQLSchemaEditorQuotesAdversarialIdentifiers proves the stateless builders
// quote (rather than reject) hostile identifiers: a backtick is doubled.
func TestMySQLSchemaEditorQuotesAdversarialIdentifiers(t *testing.T) {
	d := dialect{}
	got, err := d.DropColumnSQL(driver.TableRef{Table: "t"}, "a`b")
	if err != nil {
		t.Fatalf("builder error: %v", err)
	}
	want := "ALTER TABLE `t` DROP COLUMN `a``b`"
	if len(got) != 1 || got[0] != want {
		t.Errorf("got %v, want %q", got, want)
	}
}

func TestParseServerVersion(t *testing.T) {
	cases := []struct {
		flavor, version string
		maj, min, pat   int
	}{
		{"MySQL", "8.0.35", 8, 0, 35},
		{"MySQL", "5.7.44-log", 5, 7, 44},
		{"MySQL", "8.4.0", 8, 4, 0},
		// MariaDB prefixes VERSION() with 5.5.5- for old-client compatibility.
		{"MariaDB", "5.5.5-10.4.2-MariaDB-1:10.4.2+maria~bionic", 10, 4, 2},
		{"MariaDB", "10.11.6-MariaDB", 10, 11, 6},
		{"", "garbage", 0, 0, 0},
		{"MySQL", "", 0, 0, 0},
	}
	for _, c := range cases {
		maj, min, pat := parseServerVersion(c.flavor, c.version)
		if maj != c.maj || min != c.min || pat != c.pat {
			t.Errorf("parseServerVersion(%q,%q)=%d.%d.%d, want %d.%d.%d",
				c.flavor, c.version, maj, min, pat, c.maj, c.min, c.pat)
		}
	}
}

func TestVersionGates(t *testing.T) {
	mysql := func(v string) dialect {
		return dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MySQL", Version: v}).(dialect)
	}
	maria := func(v string) dialect {
		return dialect{}.WithServerInfo(driver.ServerInfo{Flavor: "MariaDB", Version: v}).(dialect)
	}
	// account_locked: MySQL >= 5.7.6, MariaDB >= 10.4.2.
	if mysql("5.7.5").hasAccountLocked() {
		t.Error("MySQL 5.7.5 should not expose account_locked")
	}
	if !mysql("5.7.6").hasAccountLocked() {
		t.Error("MySQL 5.7.6 should expose account_locked")
	}
	if !mysql("8.0.35").hasAccountLocked() {
		t.Error("MySQL 8.0 should expose account_locked")
	}
	if maria("10.4.1").hasAccountLocked() {
		t.Error("MariaDB 10.4.1 should not expose account_locked")
	}
	if !maria("5.5.5-10.4.2-MariaDB").hasAccountLocked() {
		t.Error("MariaDB 10.4.2 should expose account_locked")
	}
	// functional-index EXPRESSION: MySQL >= 8.0.13 only, never MariaDB.
	if mysql("8.0.12").hasFunctionalIndexExpr() {
		t.Error("MySQL 8.0.12 has no functional-index EXPRESSION")
	}
	if !mysql("8.0.13").hasFunctionalIndexExpr() {
		t.Error("MySQL 8.0.13 exposes functional-index EXPRESSION")
	}
	if maria("10.11.6-MariaDB").hasFunctionalIndexExpr() {
		t.Error("MariaDB never exposes functional-index EXPRESSION")
	}
	// Unknown flavor/version falls back conservatively.
	zero := dialect{}
	if zero.hasAccountLocked() || zero.hasFunctionalIndexExpr() {
		t.Error("unknown version must fail closed to the conservative query")
	}
	// RENAME COLUMN: MySQL >= 8.0.3 (below the 8.0.13 floor, so effectively
	// always), MariaDB >= 10.5.2. This gate is the OPPOSITE of the two above —
	// unknown fails OPEN, because the only servers that must say no are old
	// MariaDB, and a MariaDB flavor is always detected when it is one.
	if !mysql("8.0.13").Capabilities().SupportsColumnRename {
		t.Error("MySQL 8.0.13 can RENAME COLUMN")
	}
	if maria("10.4.34-MariaDB").Capabilities().SupportsColumnRename {
		t.Error("MariaDB 10.4 has no RENAME COLUMN")
	}
	if maria("5.5.5-10.5.1-MariaDB").Capabilities().SupportsColumnRename {
		t.Error("MariaDB 10.5.1 has no RENAME COLUMN")
	}
	if !maria("5.5.5-10.5.2-MariaDB").Capabilities().SupportsColumnRename {
		t.Error("MariaDB 10.5.2 can RENAME COLUMN")
	}
	if !maria("11.4.2-MariaDB").Capabilities().SupportsColumnRename {
		t.Error("MariaDB 11.4 can RENAME COLUMN")
	}
	if !zero.Capabilities().SupportsColumnRename {
		t.Error("an unspecialized dialect must still offer rename; only detected old MariaDB refuses")
	}
}

// TestMySQLCreateDatabaseSQL pins the create-DB builder: the name is
// backtick-quoted; the collation — pre-validated by the handler against
// information_schema.COLLATIONS — is emitted bare (quoting is invalid there).
func TestMySQLCreateDatabaseSQL(t *testing.T) {
	d := dialect{}
	if got := d.CreateDatabaseSQL("shop", ""); got != "CREATE DATABASE `shop`" {
		t.Errorf("no collation: %q", got)
	}
	if got := d.CreateDatabaseSQL("shop", "utf8mb4_general_ci"); got != "CREATE DATABASE `shop` COLLATE utf8mb4_general_ci" {
		t.Errorf("with collation: %q", got)
	}
	if got := d.CreateDatabaseSQL("a`b", "utf8mb4_bin"); got != "CREATE DATABASE `a``b` COLLATE utf8mb4_bin" {
		t.Errorf("adversarial name: %q", got)
	}
}

// TestShouldRetryListUsersWithoutJoin pins the G4 fallback decision: retry only
// when the mysql.global_priv join was used (hasRole && hasLocked), the query
// failed, and the context is not cancelled.
func TestShouldRetryListUsersWithoutJoin(t *testing.T) {
	errQ := errors.New("query failed")
	errCtx := context.Canceled
	cases := []struct {
		name               string
		hasRole, hasLocked bool
		queryErr, ctxErr   error
		want               bool
	}{
		{"join used, plain failure", true, true, errQ, nil, true},
		{"join used, ctx cancelled", true, true, errQ, errCtx, false},
		{"no query error", true, true, nil, nil, false},
		{"role only (no join)", true, false, errQ, nil, false},
		{"locked only (MySQL, no join)", false, true, errQ, nil, false},
		{"neither", false, false, errQ, nil, false},
	}
	for _, c := range cases {
		if got := shouldRetryListUsersWithoutJoin(c.hasRole, c.hasLocked, c.queryErr, c.ctxErr); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// TestReturningCapsByFlavor pins: RETURNING is a MariaDB extension — DELETE
// always (below the 10.2.7 floor), INSERT/REPLACE from 10.5, UPDATE never; MySQL
// proper has none. The registered zero value (unknown flavor) reports none.
func TestReturningCapsByFlavor(t *testing.T) {
	prof := func(flavor, ver string) driver.ReturningCaps {
		return dialect{}.WithServerInfo(driver.ServerInfo{Flavor: flavor, Version: ver}).(dialect).LexerProfile().Returning
	}
	// MariaDB below 10.5: DELETE only.
	rc := prof("MariaDB", "10.4.30")
	if !rc.Delete || rc.Insert || rc.Replace || rc.Update {
		t.Errorf("MariaDB 10.4: want DELETE only, got %+v", rc)
	}
	// MariaDB 10.5+: DELETE + INSERT + REPLACE, never UPDATE.
	rc = prof("MariaDB", "10.5.0")
	if !rc.Delete || !rc.Insert || !rc.Replace || rc.Update {
		t.Errorf("MariaDB 10.5: want DELETE+INSERT+REPLACE, got %+v", rc)
	}
	// MySQL proper: none.
	if rc := prof("MySQL", "8.4.0"); rc.Delete || rc.Insert || rc.Replace || rc.Update || rc.Merge {
		t.Errorf("MySQL: want none, got %+v", rc)
	}
	// Registered zero value (unknown flavor/version): none (fail closed).
	if rc := (dialect{}).LexerProfile().Returning; rc.Delete || rc.Insert || rc.Replace || rc.Update {
		t.Errorf("unknown flavor: want none, got %+v", rc)
	}
}

// TestLexerProfileBackslashMode pins that the splitter's string grammar follows
// the session's backslash mode, exactly as QuoteString already does: under
// NO_BACKSLASH_ESCAPES a backslash is a literal character, so treating \' as an
// escaped quote would merge NBE-authored statements across their real
// boundaries. The registered zero value keeps backslash escapes — MySQL's
// default mode — until the connection specializes the dialect.
func TestLexerProfileBackslashMode(t *testing.T) {
	if !(dialect{}).LexerProfile().BackslashStrings {
		t.Error("registered zero value: BackslashStrings = false, want true (backslash escapes are MySQL's default)")
	}
	nbe := dialect{}.WithServerInfo(driver.ServerInfo{SQLMode: "STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES"})
	if nbe.(dialect).LexerProfile().BackslashStrings {
		t.Error("NO_BACKSLASH_ESCAPES session: BackslashStrings = true, want false")
	}
	def := dialect{}.WithServerInfo(driver.ServerInfo{SQLMode: "STRICT_TRANS_TABLES,ONLY_FULL_GROUP_BY"})
	if !def.(dialect).LexerProfile().BackslashStrings {
		t.Error("default-escaping session: BackslashStrings = false, want true")
	}
}

// TestDefaultClause pins the DEFAULT rendering split: a literal default is
// emitted verbatim, while an EXPRESSION default is wrapped in parentheses
// (MySQL 8 grammar) EXCEPT the forms that are already valid bare — NULL, the
// CURRENT_TIMESTAMP / NOW( temporal functions, and an already-parenthesized
// expression.
func TestDefaultClause(t *testing.T) {
	cases := []struct {
		def    string
		isExpr bool
		want   string
	}{
		{"5", false, "5"},                                // literal passthrough
		{"'x'", false, "'x'"},                            // literal string passthrough
		{"NULL", true, "NULL"},                           // NULL expr not wrapped
		{"null", true, "null"},                           // case-insensitive
		{"CURRENT_TIMESTAMP", true, "CURRENT_TIMESTAMP"}, // temporal fn not wrapped
		{"CURRENT_TIMESTAMP(6)", true, "CURRENT_TIMESTAMP(6)"},
		{"NOW()", true, "NOW()"}, // NOW( not wrapped
		{"now(3)", true, "now(3)"},
		{"(a + b)", true, "(a + b)"},             // already parenthesized
		{"a + b", true, "(a + b)"},               // bare expr gets wrapped
		{"json_array()", true, "(json_array())"}, // an fn other than NOW/CURRENT_TIMESTAMP wraps
	}
	for _, c := range cases {
		if got := defaultClause(c.def, c.isExpr); got != c.want {
			t.Errorf("defaultClause(%q, %v) = %q, want %q", c.def, c.isExpr, got, c.want)
		}
	}
}

// TestEscapeGrantDatabasePattern pins the GRANT-pattern escaping: the LIKE
// wildcards _ and % are escaped so a database named `foo_bar` grants only on
// that database, not every `fooXbar`. The backslash is escaped FIRST so the
// escapes it introduces are not re-escaped.
func TestEscapeGrantDatabasePattern(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mydb", "mydb"},
		{"my_db", `my\_db`},
		{"my%db", `my\%db`},
		{`a\b`, `a\\b`},
		{`a\_%`, `a\\\_\%`}, // backslash first, then _ and %
	}
	for _, c := range cases {
		if got := escapeGrantDatabasePattern(c.in); got != c.want {
			t.Errorf("escapeGrantDatabasePattern(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestParseOnUpdate pins the EXTRA parsing that used to live in the column
// editor as a MySQL-shaped regex run over every engine's Extra (B6). The
// vocabulary is MySQL's, so the parsing belongs here.
func TestParseOnUpdate(t *testing.T) {
	cases := map[string]string{
		"on update CURRENT_TIMESTAMP":                      "CURRENT_TIMESTAMP",
		"DEFAULT_GENERATED on update CURRENT_TIMESTAMP":    "CURRENT_TIMESTAMP",
		"DEFAULT_GENERATED on update current_timestamp(3)": "CURRENT_TIMESTAMP(3)",
		"auto_increment":  "",
		"":                "",
		"identity always": "", // not a MySQL EXTRA at all
	}
	for extra, want := range cases {
		if got := parseOnUpdate(extra); got != want {
			t.Errorf("parseOnUpdate(%q) = %q, want %q", extra, got, want)
		}
	}
}
