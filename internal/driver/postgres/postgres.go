// Package postgres implements the TableX Dialect for PostgreSQL using the
// pure-Go jackc/pgx/v5 driver (via its database/sql adapter). PostgreSQL has a
// schema level (HasSchemas = true) and binds one database per connection, so
// switching databases opens a fresh pool (handled by the connection manager).
// DDL is reconstructed from pg_catalog because there is no SHOW CREATE TABLE.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/tablexdev/tablex/internal/driver"
)

// dialect carries the parsed server major version (from WithServerInfo) used to
// gate version-specific script behavior (MERGE … RETURNING is PostgreSQL 17+).
// The registered/zero value has major 0, so every version gate fails closed to
// the conservative behavior; driver.Open swaps in the specialized copy after
// loading ServerInfo.
type dialect struct{ major int }

func init() { driver.Register(dialect{}) }

// WithServerInfo returns a dialect copy carrying the parsed server major
// version. All PostgreSQL script/quoting rules are version-independent except
// the MERGE RETURNING gate, so this only records the major.
func (d dialect) WithServerInfo(info driver.ServerInfo) driver.Dialect {
	d.major = pgMajorVersion(info.Version)
	return d
}

// pgMajorVersion parses the leading integer of a PostgreSQL version string
// (ServerInfo.Version is the "17.2"-style short form). Unparseable input yields
// 0, failing every version gate closed.
func pgMajorVersion(version string) int {
	i := 0
	for i < len(version) && (version[i] < '0' || version[i] > '9') {
		i++
	}
	j := i
	for j < len(version) && version[j] >= '0' && version[j] <= '9' {
		j++
	}
	n, _ := strconv.Atoi(version[i:j])
	return n
}

func (dialect) Name() string          { return "postgres" }
func (dialect) DisplayName() string   { return "PostgreSQL" }
func (dialect) DefaultPort() int      { return 5432 }
func (dialect) SQLDriverName() string { return "pgx" }

func (dialect) Capabilities() driver.Capabilities {
	return driver.Capabilities{
		HasSchemas:               true,
		HasUsers:                 true,
		HasForeignKeys:           true,
		HasStoredRoutines:        true,
		HasTriggers:              true,
		HasEvents:                false,
		HasViews:                 true,
		SupportsExplain:          true,
		SupportsTransactionalDDL: true,
		SupportsCharset:          false,
		SupportsColumnModify:     true,
		SupportsColumnRename:     true,
		SupportsForeignKeyDDL:    true,
		CanManageDatabases:       true,
		CanDropConnectedDatabase: false, // WITH (FORCE) only terminates OTHER sessions; own database needs a maintenance connection
		ExecReportsChangedRows:   false, // RowsAffected counts matched rows
		SupportsTruncate:         true,
		AccountHasHost:           false,
		SupportsRoleAttributes:   true,
		SupportsRoles:            true, // pg_auth_members on every supported version
		IsNetworkEngine:          true,
		ShowsSSLModeUI:           true, // the ad-hoc login form exposes the sslmode selector
		SSLModeNote:              "prefer tries TLS and silently falls back to plaintext. require encrypts but does NOT check the server's certificate. Only verify-ca and verify-full authenticate the server.",
		IdentifierMaxBytes:       63, // NAMEDATALEN-1; PG silently truncates beyond this
	}
}

// NormalizeParams defaults an empty connect database to "postgres" — one
// database per connection, so login needs SOME maintenance DB. A params
// rewrite (never a BuildDSN default): params.Database must stay observably
// set, since it flows into the session base params and the server-connection
// reuse test.
func (dialect) NormalizeParams(p driver.ConnParams) driver.ConnParams {
	if p.Database == "" {
		p.Database = "postgres"
	}
	return p
}

// LoginDatabaseHint labels the ad-hoc form's database field as the
// maintenance DB and pre-fills the same default NormalizeParams applies.
func (dialect) LoginDatabaseHint() driver.LoginDatabaseHint {
	return driver.LoginDatabaseHint{
		Label:       "Maintenance database",
		Placeholder: `defaults to "postgres"`,
		Default:     "postgres",
		Note:        `Connects through this DB (default "postgres"). Use a specific database on managed hosts that block it.`,
	}
}

// ServerDumpProfile: PostgreSQL binds one database per connection, so server
// dump sections switch via \connect meta-commands and the session preamble is
// re-emitted per section (SETs do not survive \connect).
func (dialect) ServerDumpProfile() driver.ServerDumpProfile {
	return driver.ServerDumpProfile{
		PerSectionPreamble: true,
		UsesConnectMarkers: true,
		FormNote:           `Sections switch databases with \connect; the target databases must already exist when restoring.`,
	}
}

func (dialect) WriteServerDumpHeader(w io.Writer) {
	fmt.Fprint(w, "-- Sections switch databases via \\connect; restore with psql or the\n-- TableX server-scope import. The target databases must already exist.\n")
}

func (d dialect) WriteDatabaseSectionHeader(w io.Writer, name, _ string) {
	fmt.Fprintf(w, "\\connect %s\n\n", d.QuoteIdent(name))
}

// UnaddressableDatabase: a database whose name contains \r or \n cannot be
// addressed by a psql \connect meta-command (its argument cannot continue
// past end-of-line), and the residual line fragment would leak into the next
// section as executable SQL — the pg_dumpall CVE-2016-5424 remediation.
func (dialect) UnaddressableDatabase(name string) string {
	if strings.ContainsAny(name, "\r\n") {
		return "database name contains a newline; a psql \\connect meta-command cannot address it"
	}
	return ""
}

// pgRoutineRe matches the routine-creating statements whose PG14+ SQL-standard
// BEGIN ATOMIC bodies hold internal semicolons OUTSIDE any quoting (see
// LexerProfile.RoutineBodyRe). Matched after leading comments are stripped.
var pgRoutineRe = regexp.MustCompile(`(?is)^CREATE\s+(OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE)\b`)

// LexerProfile supplies the PostgreSQL script grammar to the statement
// splitter: dollar-quoted literals, E'…' escape strings and nested block
// comments. Procedural (plpgsql etc.) bodies are dollar-quoted strings, but a
// PG14+ SQL-standard BEGIN ATOMIC body is bare grammar with internal
// semicolons — RoutineBodyRe makes the splitter track BEGIN/CASE…END depth
// inside a CREATE FUNCTION/PROCEDURE instead of splitting mid-body (the
// dump emits such bodies via pg_get_functiondef). BEGIN/END/CASE are reserved
// words, so an unquoted identifier collision is impossible, and a top-level
// transaction BEGIN is never counted (the statement must match the pattern).
func (d dialect) LexerProfile() driver.LexerProfile {
	return driver.LexerProfile{
		EscapeStringE:       true,
		DollarQuotes:        true,
		NestedBlockComments: true,
		RoutineBodyRe:       pgRoutineRe,
		// PostgreSQL supports RETURNING on all DML; MERGE … RETURNING lands in 17.
		// `returning` is a reserved word, so an unquoted identifier collision is
		// grammatically impossible.
		Returning: driver.ReturningCaps{
			Insert: true, Update: true, Delete: true, Merge: d.major >= 17,
		},
	}
}

func (dialect) BuildDSN(p driver.ConnParams) (string, error) {
	port := p.Port
	if port == 0 {
		port = 5432
	}
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(p.User, p.Password),
		// JoinHostPort brackets IPv6 literals ([::1]:5432) — a bare "::1:5432"
		// authority mis-parses. UnbracketHost first, or an already-bracketed
		// "[::1]" would come out double-bracketed and unresolvable. No-op for
		// hostnames and IPv4 (mirrors the MySQL dialect's addr handling).
		Host: net.JoinHostPort(driver.UnbracketHost(p.Host), strconv.Itoa(port)),
		Path: "/" + p.Database,
	}
	q := url.Values{}
	ssl := p.SSLMode
	if ssl == "" {
		ssl = "prefer"
	}
	q.Set("sslmode", ssl)
	q.Set("connect_timeout", "15")
	for k, v := range p.Params {
		// sslmode is configured via ConnParams.SSLMode, connect_timeout is fixed
		// above and standard_conforming_strings is pinned below; a same-named
		// extra param would arrive as its own startup parameter beside the
		// computed one, and which wins is not something to reason about. Reject
		// all three, for parity with the MySQL dialect's tls rejection. Other
		// keys (including libpq "options", which the export session uses to pin
		// search_path/row_security) pass through.
		if strings.EqualFold(k, "sslmode") || strings.EqualFold(k, "connect_timeout") ||
			strings.EqualFold(k, "standard_conforming_strings") {
			return "", fmt.Errorf("unsupported connection param %q; sslmode comes from the login, the connect timeout is fixed, and standard_conforming_strings is pinned on", k)
		}
		q.Set(k, v)
	}
	// Defence in depth behind QuoteString's E'…' literals: pin the GUC on for
	// every session this DSN opens, both here and on the pgx.Config branch below
	// (BuildDSN runs before it). APPENDED rather than Set, because the export
	// session pins search_path/row_security through the same key and a Set would
	// break every export. Within one options string the last -c wins, which is
	// what makes an options-CARRIED override harmless; the direct param is the
	// one that had to be rejected above.
	const scsPin = "-c standard_conforming_strings=on"
	if existing := strings.TrimSpace(q.Get("options")); existing != "" {
		q.Set("options", existing+" "+scsPin)
	} else {
		q.Set("options", scsPin)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// OpenPool builds the pool so an ad-hoc login's dial-time SSRF guard
// (p.DialControl) is applied to every TCP connection — pgx's DialFunc runs
// before TLS, so the resolved peer IP is checked per connection. Predefined
// logins (DialControl == nil) use the default pgx stdlib registration.
func (d dialect) OpenPool(p driver.ConnParams) (*sql.DB, error) {
	dsn, err := d.BuildDSN(p)
	if err != nil {
		return nil, err
	}
	if p.DialControl == nil {
		return sql.Open(d.SQLDriverName(), dsn)
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, Control: p.DialControl}
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
	return stdlib.OpenDB(*cfg), nil
}

func (dialect) QuoteIdent(name string) string { return driver.QuoteAnsiIdent(name) }

// QuoteString quotes a string literal so it means the same thing regardless of
// `standard_conforming_strings`. That GUC decides whether a backslash inside an
// ordinary '…' literal is an escape character, and it is settable per database,
// per role and per session — so under `off` a value containing `\'` would close
// the literal at the third quote and everything after it would parse as SQL.
// A value carrying a backslash is therefore emitted as an E'…' escape string,
// where `\` always escapes, with both `\` and `'` doubled. MySQL already adapts
// (it reads NO_BACKSLASH_ESCAPES); this is the same fix for the same class.
//
// The prefix is CONDITIONAL, and that is load-bearing rather than cosmetic: a
// value with no backslash means the same thing under either setting, and two
// conformance tests pin the plain form exactly — drivertest's
// QuoteString("abc") == "'abc'" and dialect_test's O'Brien prefix check.
// Do not relax it into an unconditional prefix.
//
// The shared driver.QuoteAnsiString is deliberately left alone: SQLite uses it
// too, and a backslash is never an escape there.
func (dialect) QuoteString(s string) string {
	if !strings.Contains(s, `\`) {
		return driver.QuoteAnsiString(s)
	}
	return "E'" + strings.NewReplacer(`\`, `\\`, `'`, `''`).Replace(s) + "'"
}

func (dialect) Placeholder(n int) string { return "$" + strconv.Itoa(n) }

// StorageDDL types TableX's own metadata tables (driver.StorageHost).
// PostgreSQL's text is unbounded and fully indexable, so one type covers both
// roles, and a table needs no options at all.
func (dialect) StorageDDL() driver.StorageDDL {
	return driver.StorageDDL{ID: "text", Text: "text", Int64: "bigint"}
}

func (dialect) LimitClause(limit int, offset int64) string {
	return driver.DefaultLimitClause(limit, offset)
}

func (dialect) InsertDefaultRowSQL(qualified string) string {
	return "INSERT INTO " + qualified + " DEFAULT VALUES"
}

func (d dialect) QualifyTable(t driver.TableRef) string {
	if t.Schema != "" {
		return d.QuoteIdent(t.Schema) + "." + d.QuoteIdent(t.Table)
	}
	return d.QuoteIdent(t.Table)
}

func (dialect) ExplainSQL(query string, analyze bool) (string, bool) {
	if analyze {
		return "EXPLAIN ANALYZE " + query, true
	}
	return "EXPLAIN " + query, true
}

// schemaOrPublic is the single spelling of PostgreSQL's empty-schema default;
// schemaOf/schemaOfScope wrap it for the two ref types, and string-typed
// callers (GrantSpec) use it directly. Re-grep for `= "public"` before adding
// a new inlined default.
func schemaOrPublic(schema string) string {
	if schema == "" {
		return "public"
	}
	return schema
}

func schemaOf(t driver.TableRef) string { return schemaOrPublic(t.Schema) }

func schemaOfScope(s driver.Scope) string { return schemaOrPublic(s.Schema) }

// ServerBelowFloor implements driver.VersionFloor. 13 is the floor
// docs/database-drivers.md documents: attgenerated generated columns arrived in
// 12, but the Operations "Drop database" action emits DROP DATABASE … WITH
// (FORCE), which is 13+. A version that did not parse leaves major == 0, and
// warning from that would cry wolf on every build string this parser cannot read.
func (d dialect) ServerBelowFloor() (string, bool) {
	if d.major == 0 {
		return "", false
	}
	return "13", d.major < 13
}
