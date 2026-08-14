// Package mysql implements the TableX Dialect for MySQL and MariaDB.
//
// Both share the same wire protocol and the go-sql-driver/mysql driver; MariaDB
// is detected from the server version string and surfaced for display only.
// Introspection uses information_schema plus SHOW CREATE TABLE.
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"maps"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/tablexdev/tablex/internal/driver"
)

// dialect carries per-connection server facts derived from ServerInfo (see
// WithServerInfo): a noBackslashEscapes flag from sql_mode, plus the flavor and
// parsed version used to gate flavor/version-specific introspection columns
// (account_locked, is_role, functional-index EXPRESSION). The registered/zero
// value is the default MySQL mode with an unknown version, so every gate falls
// back to the conservative query; driver.Open swaps in the specialized copy
// after loading ServerInfo.
type dialect struct {
	noBackslashEscapes  bool
	flavor              string // "MySQL" or "MariaDB"; "" when unknown
	major, minor, patch int    // parsed server version; all 0 when unknown
}

func init() { driver.Register(dialect{}) }

// WithServerInfo returns a dialect copy specialized for the connection's
// sql_mode and server version. Under NO_BACKSLASH_ESCAPES a backslash is a
// literal character and only a doubled quote escapes a quote, so QuoteString
// must not emit backslash escapes. The flavor/version drive introspection
// column gating. All are fixed at connect time; a mid-session SET is out of
// scope.
func (d dialect) WithServerInfo(info driver.ServerInfo) driver.Dialect {
	d.noBackslashEscapes = strings.Contains(strings.ToUpper(info.SQLMode), "NO_BACKSLASH_ESCAPES")
	d.flavor = info.Flavor
	d.major, d.minor, d.patch = parseServerVersion(info.Flavor, info.Version)
	return d
}

// parseServerVersion extracts major.minor.patch from a MySQL/MariaDB VERSION()
// string. MariaDB prefixes its version with "5.5.5-" for old-client
// compatibility (e.g. "5.5.5-10.4.2-MariaDB-1:10.4.2+maria~bionic"), so that
// prefix is stripped for the MariaDB flavor before the leading dotted-numeric
// run is parsed. Unparseable input yields zeros, which makes every atLeast gate
// fail closed to the conservative query.
func parseServerVersion(flavor, version string) (maj, min, pat int) {
	v := version
	if strings.EqualFold(flavor, "MariaDB") {
		v = strings.TrimPrefix(v, "5.5.5-")
	}
	end := 0
	for end < len(v) && (v[end] == '.' || (v[end] >= '0' && v[end] <= '9')) {
		end++
	}
	// A non-numeric head leaves end == 0, so parts is [""] and every field
	// parses to 0 — the fail-closed zeros the doc comment describes.
	parts := strings.Split(v[:end], ".")
	atoi := func(i int) int {
		if i < len(parts) {
			n, _ := strconv.Atoi(parts[i])
			return n
		}
		return 0
	}
	return atoi(0), atoi(1), atoi(2)
}

// atLeast reports whether the parsed server version is >= maj.min.pat.
func (d dialect) atLeast(maj, min, pat int) bool {
	switch {
	case d.major != maj:
		return d.major > maj
	case d.minor != min:
		return d.minor > min
	default:
		return d.patch >= pat
	}
}

// isMariaDBFlavor reports the specialized flavor (empty/unknown → false).
func (d dialect) isMariaDBFlavor() bool { return strings.EqualFold(d.flavor, "MariaDB") }

// hasAccountLocked reports whether the server's account lock state is readable
// (MySQL >= 5.7.6: the mysql.user.account_locked column; MariaDB >= 10.4.2: the
// account_locked attribute in mysql.global_priv's Priv JSON — MariaDB's
// mysql.user compatibility view has no such column). ListUsers picks the
// mechanism by flavor.
func (d dialect) hasAccountLocked() bool {
	switch {
	case d.isMariaDBFlavor():
		return d.atLeast(10, 4, 2)
	case strings.EqualFold(d.flavor, "MySQL"):
		return d.atLeast(5, 7, 6)
	}
	return false
}

// hasFunctionalIndexExpr reports whether information_schema.STATISTICS exposes
// the EXPRESSION column for functional key parts (MySQL >= 8.0.13 only; MariaDB
// has no such column at any version).
func (d dialect) hasFunctionalIndexExpr() bool {
	return strings.EqualFold(d.flavor, "MySQL") && d.atLeast(8, 0, 13)
}

func (dialect) Name() string          { return "mysql" }
func (dialect) DisplayName() string   { return "MySQL / MariaDB" }
func (dialect) DefaultPort() int      { return 3306 }
func (dialect) SQLDriverName() string { return "mysql" }

// Capabilities. ShowsSSLModeUI is set even though the vocabulary is
// PostgreSQL's: applyTLSMode already accepts and maps every token, and the
// alternative was worse — the selector stayed in the DOM for every engine (it is
// hidden with x-show, not removed), so a MySQL ad-hoc login POSTED a value that
// sslModeFor then discarded, producing plaintext with a control on screen
// claiming otherwise. SSLModeNote carries the difference in MEANING, because the
// twelve accepted tokens collapse to four behaviours here and `require` does not
// authenticate the server.
func (d dialect) Capabilities() driver.Capabilities {
	return driver.Capabilities{
		HasSchemas:               false,
		HasUsers:                 true,
		HasForeignKeys:           true,
		HasStoredRoutines:        true,
		HasTriggers:              true,
		HasEvents:                true,
		HasViews:                 true,
		SupportsExplain:          true,
		SupportsTransactionalDDL: false,
		SupportsCharset:          true,
		SupportsColumnModify:     true,
		// RENAME COLUMN arrived in MySQL 8.0.3 — below the documented 8.0.13
		// floor, so always present there — but not until MariaDB 10.5.2, which
		// IS above the 10.2.7 MariaDB floor. Unknown flavor (the registered
		// zero value, before WithServerInfo specializes the dialect) is treated
		// as capable: it is only ever MariaDB 10.2-10.4 that must say no, and
		// on those the builder is simply never offered.
		SupportsColumnRename:     !d.isMariaDBFlavor() || d.atLeast(10, 5, 2),
		SupportsColumnPosition:   true, // the only one of the three with FIRST / AFTER
		SupportsForeignKeyDDL:    true,
		CanManageDatabases:       true,
		CanDropConnectedDatabase: true, // any connection can drop any database, including its current one
		ExecReportsChangedRows:   true, // default protocol reports changed rows, not matched (no CLIENT_FOUND_ROWS)
		SupportsTruncate:         true,
		AccountHasHost:           true,
		SupportsRoleAttributes:   false,
		// Roles arrived in MySQL 8.0 and MariaDB 10.0.5, both ABOVE the
		// documented version floors, so this one must fail CLOSED on an
		// unknown flavor/version: the catalog table is simply absent below
		// them, and claiming support would turn the Users page into an error.
		SupportsRoles:      d.supportsRoles(),
		IsNetworkEngine:    true,
		ShowsSSLModeUI:     true,
		SSLModeNote:        "MySQL/MariaDB accepts PostgreSQL's words but not its behaviour: prefer/allow tries TLS and falls back to plaintext, UNVERIFIED. require encrypts but checks nothing — it is skip-verify here. Only verify-ca and verify-full authenticate the server.",
		IdentifierMaxChars: 64, // MySQL/MariaDB identifier maximum, counted in CHARACTERS
	}
}

// mysqlRoutineRe matches the routine-creating statements whose BEGIN...END
// bodies hold internal semicolons (see LexerProfile.RoutineBodyRe). Matched
// after leading comments are stripped.
var mysqlRoutineRe = regexp.MustCompile(`(?is)^CREATE\s+(OR\s+REPLACE\s+)?(DEFINER\s*=\s*\S+\s+)?(AGGREGATE\s+)?(PROCEDURE|FUNCTION|TRIGGER|EVENT)\b`)

// LexerProfile supplies the MySQL/MariaDB script grammar to the statement
// splitter: string escapes following the session's backslash mode (under
// NO_BACKSLASH_ESCAPES a backslash is a literal character, so the splitter
// must not treat \' as an escaped quote), '#' comments, the "-- needs
// whitespace" rule, mysql-client DELIMITER directives (and TableX opaque
// frames), '$' as an identifier character, and BEGIN…END body tracking for
// routine DDL. ANSI_QUOTES (double-quoted identifiers) remains deliberately
// unmodeled: double-quoted runs are skipped as opaque either way.
func (d dialect) LexerProfile() driver.LexerProfile {
	// RETURNING is a MariaDB extension: DELETE since 10.0.5 (below the 10.2.7
	// floor, so always available), INSERT/REPLACE since 10.5, and UPDATE never.
	// MySQL proper has no RETURNING on any statement. The registered zero value
	// (unknown flavor/version) reports none, so a RETURNING clause runs as Exec
	// until the connection specializes the dialect.
	var ret driver.ReturningCaps
	if d.isMariaDBFlavor() {
		ret.Delete = true
		if d.atLeast(10, 5, 0) {
			ret.Insert = true
			ret.Replace = true
		}
	}
	return driver.LexerProfile{
		BackslashStrings:      !d.noBackslashEscapes,
		HashComments:          true,
		DashCommentNeedsSpace: true,
		DelimiterDirectives:   true,
		DollarInWords:         true,
		RoutineBodyRe:         mysqlRoutineRe,
		Returning:             ret,
	}
}

// ExportConnParams pins a dedicated export connection's session (the params
// become session SETs) to the exact state the dump preamble forces on restore:
//
//   - time_zone UTC, so TIMESTAMP values dump as the UTC wall-clock the
//     preamble's `SET time_zone='+00:00'` declares;
//   - sql_mode 'NO_AUTO_VALUE_ON_ZERO' — the preamble's exact mode — so data
//     literals AND SHOW CREATE DDL render under default backslash escaping and
//     backtick quoting even when the server default is NO_BACKSLASH_ESCAPES or
//     ANSI_QUOTES (driver.Open re-specializes the dialect from the pinned mode
//     via ServerInfo/WithServerInfo);
//   - sql_quote_show_create=1, because a configured =0 would strip identifier
//     quoting from every SHOW CREATE and make dumps unrestorable for
//     quote-requiring identifiers.
//
// The Params map is cloned (it is shared with the server config and session
// base params) and the pins are set AFTER the copy, overwriting any same-name
// config key.
func (dialect) ExportConnParams(p driver.ConnParams) driver.ConnParams {
	params := make(map[string]string, len(p.Params)+3)
	maps.Copy(params, p.Params)
	params["time_zone"] = "'+00:00'"
	params["sql_mode"] = "'NO_AUTO_VALUE_ON_ZERO'"
	params["sql_quote_show_create"] = "1"
	p.Params = params
	return p
}

// bareCollationRE validates an introspected collation for the bare-identifier
// position in CREATE DATABASE … COLLATE … (quoting is a syntax error there).
// The value is the server's own catalog entry; this is defense-in-depth.
var bareCollationRE = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// ServerDumpProfile: one MySQL script addresses every database via executable
// CREATE DATABASE/USE, with a single global preamble.
func (dialect) ServerDumpProfile() driver.ServerDumpProfile {
	return driver.ServerDumpProfile{}
}

func (dialect) WriteServerDumpHeader(io.Writer) {}

// WriteDatabaseSectionHeader introduces one database section: CREATE DATABASE
// IF NOT EXISTS preserving the introspected default collation (which implies
// its charset) so a restore doesn't silently fall back to the target server's
// default, then USE.
func (d dialect) WriteDatabaseSectionHeader(w io.Writer, name, collation string) {
	create := "CREATE DATABASE IF NOT EXISTS " + d.QuoteIdent(name)
	if collation != "" && bareCollationRE.MatchString(collation) {
		create += " COLLATE " + collation
	}
	fmt.Fprintf(w, "%s;\nUSE %s;\n\n", create, d.QuoteIdent(name))
}

// UnaddressableDatabase: a USE statement is ordinary quoted SQL, so every
// introspected database name is addressable.
func (dialect) UnaddressableDatabase(string) string { return "" }

// CollationProbeSQL backs the importer's db-collation marker verification
// (driver.CollationProber): the current database and its default collation,
// read on the import's pinned connection at the marker's position — so a
// server-scope dump's executable USE statements are already in effect.
func (dialect) CollationProbeSQL() string {
	return "SELECT DATABASE(), @@collation_database"
}

// --- DSN & syntax --------------------------------------------------------------

func (dialect) buildConfig(p driver.ConnParams) (*gomysql.Config, error) {
	cfg := gomysql.NewConfig()
	cfg.User = p.User
	cfg.Passwd = p.Password
	cfg.DBName = p.Database
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Collation = "utf8mb4_general_ci"
	cfg.Timeout = 15 * time.Second
	cfg.AllowNativePasswords = true
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	if p.Socket != "" {
		cfg.Net = "unix"
		cfg.Addr = p.Socket
	} else {
		port := p.Port
		if port == 0 {
			port = 3306
		}
		cfg.Net = "tcp"
		// UnbracketHost first: JoinHostPort brackets any host containing ':',
		// so an already-bracketed "[::1]" would come out double-bracketed.
		cfg.Addr = net.JoinHostPort(driver.UnbracketHost(p.Host), strconv.Itoa(port))
	}
	if err := applyTLSMode(cfg, p); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyTLSMode maps the neutral/PostgreSQL SSL vocabulary onto the
// go-sql-driver/mysql TLS config names ("", false, true, skip-verify, preferred,
// or a name registered via RegisterTLSConfig). This mapping is what lets the
// login form offer the selector here at all (Capabilities().ShowsSSLModeUI): the
// posted value is a PostgreSQL word like "prefer", and passing it raw to the
// driver is rejected ("unknown config name: prefer"), so it is translated rather
// than forwarded. Capabilities().SSLModeNote carries the difference in MEANING
// to the user, because the tokens below collapse to four behaviours.
//
// Verification semantics differ across these tokens, so the mapping is
// deliberate:
//
//   - disable/"" → no TLS (plaintext).
//   - prefer/allow/preferred → "preferred": opportunistic TLS with plaintext
//     fallback, and crucially *unauthenticated* (the driver's built-in preferred
//     config uses InsecureSkipVerify — neither the certificate chain nor the
//     hostname is checked).
//   - require → "skip-verify": always TLS but still *unverified* (no CA or
//     hostname check). This matches PostgreSQL's `require` semantics when no root
//     CA is configured (PG's documented default): encrypt, but do not
//     authenticate the server. MySQL has no CA pool wired here, so the legacy PG
//     behavior where `require` validates the CA if sslrootcert is present
//     (`require` ≈ verify-ca) is intentionally not replicated. Because the name
//     reads stricter than the behaviour, config.Warnings() emits a startup
//     advisory for any predefined server configured this way; only verify-ca /
//     verify-full / true authenticate the server.
//   - verify-ca → "true": MySQL has no CA-only mode, so verify-ca has no exact
//     equivalent and is collapsed up to full cert+hostname verification.
//   - verify-full / true → "true": full certificate chain and hostname
//     verification. Only these tokens actually authenticate the server.
//   - skip-verify → "skip-verify": explicit unverified TLS.
//
// Any other value is rejected rather than forwarded raw as a registered-config
// name: a predefined server's TOML `sslmode` reaches here via paramsFromConfig
// without passing the login form's engine gate, so an arbitrary string must not
// silently become a (missing) TLS config name.
func applyTLSMode(cfg *gomysql.Config, p driver.ConnParams) error {
	switch strings.ToLower(p.SSLMode) {
	case "", "disable", "false":
		// no TLS
	case "prefer", "allow", "preferred":
		cfg.TLSConfig = "preferred"
	case "require", "skip-verify", "skip_verify":
		cfg.TLSConfig = "skip-verify"
	case "verify-ca", "verify-full", "true":
		cfg.TLSConfig = "true"
	default:
		return fmt.Errorf("unsupported sslmode %q for MySQL/MariaDB", p.SSLMode)
	}
	for k, v := range p.Params {
		// go-sql-driver applies cfg.Params as session system variables
		// (SET <name> = <value>) after connect — but "tls" is not a system
		// variable, so it would fail with "Unknown system variable 'tls'" and
		// break the connection. TLS is configured only via sslmode (applyTLSMode
		// above), so reject a tls param outright rather than silently forwarding it.
		if strings.EqualFold(k, "tls") {
			return fmt.Errorf("unsupported connection param %q; configure TLS via sslmode instead", k)
		}
		cfg.Params[k] = v
	}
	return nil
}

func (d dialect) BuildDSN(p driver.ConnParams) (string, error) {
	cfg, err := d.buildConfig(p)
	if err != nil {
		return "", err
	}
	return cfg.FormatDSN(), nil
}

// OpenPool builds the pool through a connector so an ad-hoc login's dial-time
// SSRF guard (p.DialControl) is applied to every TCP connection. Predefined
// logins (DialControl == nil) get the driver's default dialer.
func (d dialect) OpenPool(p driver.ConnParams) (*sql.DB, error) {
	cfg, err := d.buildConfig(p)
	if err != nil {
		return nil, err
	}
	if p.DialControl != nil {
		dialer := &net.Dialer{Timeout: cfg.Timeout, Control: p.DialControl}
		cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}
	}
	connector, err := gomysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(connector), nil
}

func (dialect) QuoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// QuoteString renders a MySQL/MariaDB string literal. A quote is ALWAYS escaped
// by doubling it (valid in every sql_mode). Backslash escapes (\\ \' \0 \n \r
// \Z) are emitted only in the default mode; under NO_BACKSLASH_ESCAPES a
// backslash is literal and those sequences would corrupt the value or, with
// crafted content, be escapable — so in that mode the raw bytes are emitted,
// except NUL which cannot appear in a bare literal there and is written via a
// CONCAT(CHAR(0)) splice. Values are still parameterized everywhere they can be;
// this covers the DDL/DCL positions that accept no placeholder and must
// interpolate a literal: CREATE/ALTER USER, GRANT/REVOKE, a column's COMMENT and
// custom string DEFAULT, ENUM/SET member lists, and dumped data literals. See
// docs/security.md §4 for the authoritative list.
func (d dialect) QuoteString(s string) string {
	if d.noBackslashEscapes {
		// Double the quote; keep everything else literal. A NUL byte has no literal
		// spelling under NO_BACKSLASH_ESCAPES, so splice it in with CHAR(0).
		esc := strings.ReplaceAll(s, `'`, `''`)
		if !strings.Contains(esc, "\x00") {
			return "'" + esc + "'"
		}
		var b strings.Builder
		b.WriteString("CONCAT(")
		for i, part := range strings.Split(esc, "\x00") {
			if i > 0 {
				b.WriteString(", CHAR(0), ")
			}
			b.WriteByte('\'')
			b.WriteString(part)
			b.WriteByte('\'')
		}
		b.WriteByte(')')
		return b.String()
	}
	r := strings.NewReplacer(`\`, `\\`, `'`, `''`, "\x00", `\0`, "\n", `\n`, "\r", `\r`, "\x1a", `\Z`)
	return "'" + r.Replace(s) + "'"
}

func (dialect) Placeholder(int) string { return "?" }

// StorageDDL types TableX's own metadata tables (driver.StorageHost).
//
// VARCHAR(64) rather than TEXT because MySQL cannot index a TEXT column without
// a prefix length, and every ID column here is a primary key. LONGTEXT rather
// than TEXT because MySQL's TEXT tops out at 64 KiB, which a stored SQL
// statement can exceed. The options pin utf8mb4 (a server defaulting to latin1
// would mangle non-ASCII text on the way in) and InnoDB (MyISAM would silently
// drop the transaction the storage layer's atomic updates rely on).
func (dialect) StorageDDL() driver.StorageDDL {
	return driver.StorageDDL{
		ID:           "VARCHAR(64)",
		Text:         "LONGTEXT",
		Int64:        "BIGINT",
		TableOptions: " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
	}
}

func (dialect) LimitClause(limit int, offset int64) string {
	return driver.DefaultLimitClause(limit, offset)
}

func (dialect) InsertDefaultRowSQL(qualified string) string {
	return "INSERT INTO " + qualified + " () VALUES ()"
}

func (d dialect) QualifyTable(t driver.TableRef) string {
	if t.Database != "" {
		return d.QuoteIdent(t.Database) + "." + d.QuoteIdent(t.Table)
	}
	return d.QuoteIdent(t.Table)
}

func (d dialect) ExplainSQL(query string, analyze bool) (string, bool) {
	if analyze {
		// MySQL spells this "EXPLAIN ANALYZE <stmt>" but MariaDB spells it
		// "ANALYZE <stmt>" — emitting the MySQL form would be a syntax error on
		// MariaDB. This shared dialect cannot tell the flavor here (ExplainSQL
		// takes no context, unlike Columns which reads ServerFlavorFromContext),
		// and no caller currently requests analyze, so report it unsupported
		// rather than emit a form that breaks on one flavor. Wire the flavor
		// through (interface change) if an analyze caller is ever added.
		return "", false
	}
	return "EXPLAIN " + query, true
}

// --- Server info ---------------------------------------------------------------

func (dialect) ServerInfo(ctx context.Context, db *sql.DB) (driver.ServerInfo, error) {
	var version, user, charset, collation, sqlMode sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT VERSION(), CURRENT_USER(), @@character_set_server, @@collation_server, @@SESSION.sql_mode`).
		Scan(&version, &user, &charset, &collation, &sqlMode)
	if err != nil {
		return driver.ServerInfo{}, err
	}
	flavor := "MySQL"
	if strings.Contains(strings.ToLower(version.String), "mariadb") {
		flavor = "MariaDB"
	}
	return driver.ServerInfo{
		Engine:    "mysql",
		Flavor:    flavor,
		Version:   version.String,
		User:      user.String,
		Charset:   charset.String,
		Collation: collation.String,
		SQLMode:   sqlMode.String,
	}, nil
}

// --- helpers -------------------------------------------------------------------

func nullInt(v sql.NullInt64, fallback int64) int64 {
	if v.Valid {
		return v.Int64
	}
	return fallback
}

func sumSize(a, b sql.NullInt64) int64 {
	if !a.Valid && !b.Valid {
		return -1
	}
	return a.Int64 + b.Int64
}

// ServerBelowFloor implements driver.VersionFloor. The floors are the ones
// docs/database-drivers.md documents: MySQL 8.0.13 for the DEFAULT_GENERATED
// marker that distinguishes an expression default from a literal one, and
// MariaDB 10.2.7 for the quoted-literal COLUMN_DEFAULT convention the same code
// depends on. A version that did not parse leaves major == 0, and answering
// "below" from that would warn on every build string this parser does not know.
func (d dialect) ServerBelowFloor() (string, bool) {
	if d.major == 0 {
		return "", false
	}
	if d.isMariaDBFlavor() {
		return "10.2.7", !d.atLeast(10, 2, 7)
	}
	return "8.0.13", !d.atLeast(8, 0, 13)
}
