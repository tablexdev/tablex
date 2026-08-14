package server_test

// Live NO_BACKSLASH_ESCAPES / creation-context round-trip tests (finding 1.1):
// the export session is pinned to the dump preamble's sql_mode, object bodies
// travel byte-exact in opaque frames under per-object creation-context guards,
// and db-collation disclosure markers surface import warnings — the target
// database's collation is NEVER altered. Gated on TABLEX_TEST_<ENGINE>_HOST
// like the other live tests.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
)

func TestLiveNBEDumpMySQL(t *testing.T) {
	liveNBEDump(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveNBEDumpMariaDB(t *testing.T) {
	liveNBEDump(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveNBEConsoleMySQL(t *testing.T) {
	liveNBEConsole(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveNBEConsoleMariaDB(t *testing.T) {
	liveNBEConsole(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveNBEConsole pins the console splitter's grammar to the session's real
// backslash mode, end to end: the predefined server pins NO_BACKSLASH_ESCAPES
// on every session connection, so the session dialect specializes with
// noBackslashEscapes=true and its LexerProfile must drop backslash escapes. The
// posted script is legal NBE MySQL — 'a\' is a complete string, two statements.
// A splitter still lexing with backslash escapes reads \' as an escaped quote,
// merges the two statements across the real boundary, and the server rejects
// the merged text (MultiStatements is off), so neither row would land.
func liveNBEConsole(t *testing.T, env liveEnv) {
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
	if _, err := admin.Exec(ctx, "CREATE TABLE `"+liveDB+"`.`nbe_console` (id INT NOT NULL PRIMARY KEY, val VARCHAR(64) NOT NULL)"); err != nil {
		t.Fatalf("seed table: %v", err)
	}

	base, client, csrf := liveNBELogin(t, env, map[string]string{"sql_mode": "'NO_BACKSLASH_ESCAPES'"})
	script := `INSERT INTO nbe_console (id, val) VALUES (1, 'a\');` + "\n" +
		`INSERT INTO nbe_console (id, val) VALUES (2, 'b');`
	status, page := livePost(t, client, base, "/db/"+liveDB+"/sql", url.Values{
		"csrf_token": {csrf}, "sql_query": {script},
	})
	if status != http.StatusOK || strings.Contains(page, "tx-alert-error") {
		t.Fatalf("NBE console POST = %d: %s", status, pageErrorSnippet(page))
	}

	// Both statements executed: the two rows are the proof, with the backslash
	// stored as the literal character the NBE author wrote.
	rows := queryRows(t, admin, "SELECT id, val FROM `"+liveDB+"`.`nbe_console` ORDER BY id")
	want := []string{`1|a\`, `2|b`}
	if len(rows) != len(want) {
		t.Fatalf("rows after NBE console script = %q, want %q", rows, want)
	}
	for i := range want {
		if strings.TrimSpace(rows[i]) != want[i] {
			t.Errorf("row %d = %q, want %q", i, rows[i], want[i])
		}
	}
}

// nbeSeedParams pins the SEEDING session to a hostile creation context: the
// NO_BACKSLASH_ESCAPES sql_mode, a non-UTF8 client charset (cp932, whose ソ
// character carries a 0x5C backslash TRAIL byte), and a non-default time zone
// for the event. Pinned via ConnParams.Params (DSN-level session SETs applied
// to every pooled connection) — the live suite documents that plain session
// SETs are unreliable on a pool.
func nbeSeedParams() map[string]string {
	return map[string]string{
		"sql_mode":             "'NO_BACKSLASH_ESCAPES'",
		"character_set_client": "cp932",
		"collation_connection": "cp932_japanese_ci",
		"time_zone":            "'+03:00'",
	}
}

// jpSo is the cp932 encoding of ソ (0x83 0x5C) — its trail byte is a literal
// backslash, the classic mojibake/mis-lex hazard.
const jpSo = "\x83\x5c"

// liveNBELogin builds the HTTP app with a predefined server for env (params
// optionally carried into the server config) and logs in, returning the base
// URL, client and a post-login CSRF token.
func liveNBELogin(t *testing.T, env liveEnv, params map[string]string) (string, *http.Client, string) {
	t.Helper()
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port, Params: params,
		})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"csrf_token": {csrf}, "server": {"live"},
		"username": {env.user}, "password": {env.pass},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	return ts.URL, client, csrfFrom(t, client, ts.URL+"/")
}

// livePost posts form to base+path and returns status + page body.
func livePost(t *testing.T, client *http.Client, base, path string, form url.Values) (int, string) {
	t.Helper()
	resp, err := client.PostForm(base+path, form)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

// snapshotNBE fingerprints the creation-context metadata and definitions of
// every object the NBE test seeds, plus table DDL and data. Reads go through
// a fresh default-mode utf8mb4 session on both sides of the round-trip, so
// the (deterministic) charset conversion cancels out in the comparison.
func snapshotNBE(t *testing.T, d driver.Dialect, params driver.ConnParams) map[string]string {
	t.Helper()
	conn, err := driver.Open(context.Background(), d, params)
	if err != nil {
		t.Fatalf("snapshot connect: %v", err)
	}
	defer conn.Close()
	out := map[string]string{}
	out["routines"] = strings.Join(queryRows(t, conn, `
		SELECT ROUTINE_NAME, SQL_MODE, CHARACTER_SET_CLIENT, COLLATION_CONNECTION, ROUTINE_DEFINITION
		FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = '`+liveDB+`' ORDER BY ROUTINE_NAME`), "\n")
	out["triggers"] = strings.Join(queryRows(t, conn, `
		SELECT TRIGGER_NAME, SQL_MODE, CHARACTER_SET_CLIENT, COLLATION_CONNECTION, ACTION_STATEMENT
		FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = '`+liveDB+`' ORDER BY TRIGGER_NAME`), "\n")
	out["events"] = strings.Join(queryRows(t, conn, `
		SELECT EVENT_NAME, SQL_MODE, TIME_ZONE, CHARACTER_SET_CLIENT, COLLATION_CONNECTION, EVENT_DEFINITION
		FROM information_schema.EVENTS WHERE EVENT_SCHEMA = '`+liveDB+`' ORDER BY EVENT_NAME`), "\n")
	out["views"] = strings.Join(queryRows(t, conn, `
		SELECT TABLE_NAME, CHARACTER_SET_CLIENT, COLLATION_CONNECTION, VIEW_DEFINITION
		FROM information_schema.VIEWS WHERE TABLE_SCHEMA = '`+liveDB+`' ORDER BY TABLE_NAME`), "\n")
	rows := queryRows(t, conn, "SHOW CREATE TABLE `"+liveDB+"`.`bs`")
	if len(rows) != 1 {
		t.Fatalf("SHOW CREATE TABLE bs: %d rows", len(rows))
	}
	_, create, _ := strings.Cut(rows[0], "|")
	out["create:bs"] = normalizeSQL(create)
	out["data:bs"] = strings.Join(queryRows(t, conn, "SELECT id, val, HEX(CONVERT(val USING binary)), bin FROM `"+liveDB+"`.`bs` ORDER BY id"), "\n")
	return out
}

func liveNBEDump(t *testing.T, env liveEnv) {
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

	// Seed under NO_BACKSLASH_ESCAPES + cp932 + a non-default time zone. The
	// literals below are written NBE-style: every backslash is LITERAL.
	seedParams := adminParams
	seedParams.Database = liveDB
	seedParams.Params = nbeSeedParams()
	seed, err := driver.Open(ctx, d, seedParams)
	if err != nil {
		t.Fatalf("connect (NBE seed) to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		// Trailing-backslash DEFAULT and a backslash COMMENT — both rendered by
		// SHOW CREATE under the source session's mode at export time.
		`CREATE TABLE bs (
			id INT NOT NULL PRIMARY KEY,
			val VARCHAR(64) NULL DEFAULT 'def\' COMMENT 'comment with \ backslash',
			bin VARBINARY(64) NULL)`,
		`CREATE PROCEDURE p_nbe() BEGIN SELECT 'tail\' AS s; SELECT '` + jpSo + `' AS jp; END`,
		`CREATE TRIGGER trg_nbe BEFORE INSERT ON bs FOR EACH ROW BEGIN SET NEW.val = CONCAT(IFNULL(NEW.val,''), 'x\'); END`,
		`CREATE EVENT ev_nbe ON SCHEDULE EVERY 1 DAY DISABLE DO SELECT 'e\'`,
		`CREATE VIEW v_nbe AS SELECT 'v\' AS c`,
		// The cp932 character sits mid-literal: MySQL itself cannot re-open a
		// view whose literal ENDS in a 0x5C trail byte (SHOW CREATE VIEW errors
		// from every session — a server-side canonicalization limitation that
		// breaks mysqldump identically), so that exact shape is exercised at
		// the routine level (p_nbe) and in the splitter unit tests instead.
		`CREATE VIEW v_jp AS SELECT '` + jpSo + `AA' AS jp`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	// Row data binds as parameters (mode-independent): a backslash, a trailing
	// backslash, and backslash+NUL.
	for _, row := range []struct {
		id  int
		val string
	}{{1, `back\slash`}, {2, `trailing\`}, {3, "bs-nul:\\\x00end"}} {
		if _, err := seed.DB().ExecContext(ctx, "INSERT INTO bs (id, val, bin) VALUES (?, ?, ?)",
			row.id, row.val, []byte{0x00, 0x5c, 0xff}); err != nil {
			seed.Close()
			t.Fatalf("seed row %d: %v", row.id, err)
		}
	}
	seed.Close()

	// Snapshots read through a default-mode connection.
	checkParams := adminParams
	checkParams.Database = liveDB
	before := snapshotNBE(t, d, checkParams)
	if !strings.Contains(before["routines"], "NO_BACKSLASH_ESCAPES") ||
		!strings.Contains(before["routines"], "cp932") ||
		!strings.Contains(before["events"], "+03:00") {
		t.Fatalf("seed did not capture the NBE creation context:\n%v", before)
	}

	base, client, csrf := liveNBELogin(t, env, nil)
	status, dump := livePost(t, client, base, "/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if status != http.StatusOK || !strings.Contains(dump, "CREATE TABLE") {
		t.Fatalf("export = %d, dump len %d, error: %s", status, len(dump), pageErrorSnippet(dump))
	}
	// Structural dump assertions: opaque frames, per-object guards in the
	// @saved_* namespace, disclosure markers, and byte-exact NBE/cp932 bodies.
	for _, want := range []string{
		"-- tablex:v1 frame delimiter=",
		"SET @saved_sql_mode = @@sql_mode",
		"SET sql_mode = 'NO_BACKSLASH_ESCAPES'",
		"SET character_set_client = 'cp932'",
		"SET time_zone = '+03:00'",
		"-- tablex:v1 db-collation kind=routine",
		"-- tablex:v1 db-collation kind=trigger",
		"-- tablex:v1 db-collation kind=event",
		"'tail\\' AS s", // the raw NBE body, NOT re-escaped
		jpSo,            // raw cp932 bytes survived binary retrieval
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing %q:\n%.4000s", want, dump)
		}
	}

	// Round 1: restore into a same-collation database and compare snapshots.
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	status, page := livePost(t, client, base, "/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if status != http.StatusOK || strings.Contains(page, "tx-alert-error") {
		t.Fatalf("import failed (%d):\n%.4000s\n--- dump ---\n%.6000s", status, page, dump)
	}
	after := snapshotNBE(t, d, checkParams)
	compareSnapshots(t, before, after, dump)

	// Round 2: restore into a database with a DIFFERENT collation. The import
	// must succeed, surface bounded db-collation warnings naming BOTH values,
	// and never alter the target database's collation.
	liveDropDB(t, admin, env.engine)
	const otherCollation = "latin1_swedish_ci"
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+liveDB+" CHARACTER SET latin1 COLLATE "+otherCollation); err != nil {
		t.Fatalf("create mismatched-collation db: %v", err)
	}
	status, page = livePost(t, client, base, "/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if status != http.StatusOK || strings.Contains(page, "tx-alert-error") {
		t.Fatalf("mismatched-collation import failed (%d):\n%.4000s", status, page)
	}
	if !strings.Contains(page, "tx-alert-warning") || !strings.Contains(page, otherCollation) {
		t.Errorf("import summary lacks the collation-mismatch warning naming %q:\n%.4000s", otherCollation, page)
	}
	if got := dbCollation(t, admin); got != otherCollation {
		t.Errorf("target database collation was altered by the import: %q, want %q", got, otherCollation)
	}
	// Views never produce a collation warning (SHOW CREATE VIEW has no
	// Database Collation column, so no marker is ever emitted for them).
	if strings.Contains(page, `view "`) {
		t.Errorf("a view produced a collation warning:\n%.4000s", page)
	}

	// Round 3: a failing import still never touches the target's collation,
	// and warnings recorded before the failure survive into the summary.
	marker := driver.FormatCollationMarker("routine", "ghost", "utf8mb4_general_ci")
	status, page = livePost(t, client, base, "/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"sql_script": {marker + "\nSELECT 1;\nCREATE TABLE broken (;"},
	})
	if status != http.StatusOK || !strings.Contains(page, "tx-alert-error") {
		t.Fatalf("failing import did not fail (%d):\n%.4000s", status, page)
	}
	if !strings.Contains(page, "tx-alert-warning") || !strings.Contains(page, "ghost") {
		t.Errorf("warning recorded before the failure was lost:\n%.4000s", page)
	}
	if got := dbCollation(t, admin); got != otherCollation {
		t.Errorf("failed import altered the target database collation: %q, want %q", got, otherCollation)
	}
}

// pageErrorSnippet extracts the text around the first "failed" occurrence of
// an error page, so a Fatalf shows the real message instead of the page head.
func pageErrorSnippet(page string) string {
	i := strings.Index(page, "failed")
	if i < 0 {
		if len(page) > 2000 {
			return page[:2000]
		}
		return page
	}
	lo, hi := max(0, i-200), min(len(page), i+600)
	return page[lo:hi]
}

// dbCollation reads liveDB's current default collation.
func dbCollation(t *testing.T, admin *driver.Connection) string {
	t.Helper()
	rows := queryRows(t, admin,
		"SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '"+liveDB+"'")
	if len(rows) != 1 {
		t.Fatalf("collation of %s: %d rows", liveDB, len(rows))
	}
	return strings.TrimSpace(rows[0])
}

// TestLiveQuoteShowCreatePinMySQL: a configured sql_quote_show_create=0 must
// not strip identifier quoting from dumps — the export session pin overwrites
// the config param, so a quote-requiring identifier stays restorable.
func TestLiveQuoteShowCreatePinMySQL(t *testing.T) {
	liveQuoteShowCreatePin(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func liveQuoteShowCreatePin(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, _ := driver.Get(env.engine)
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)
	if _, err := admin.Exec(ctx, "CREATE TABLE `"+liveDB+"`.`order` (`select` INT NOT NULL PRIMARY KEY)"); err != nil {
		t.Fatalf("seed reserved-word table: %v", err)
	}

	// The predefined server carries the hostile config param; the export pin
	// must overwrite it.
	base, client, csrf := liveNBELogin(t, env, map[string]string{"sql_quote_show_create": "0"})
	status, dump := livePost(t, client, base, "/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"},
	})
	if status != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", status, dump)
	}
	if !strings.Contains(dump, "CREATE TABLE `order`") || !strings.Contains(dump, "`select`") {
		t.Errorf("dump lost identifier quoting under sql_quote_show_create=0:\n%.4000s", dump)
	}
}

// TestLiveServerDumpPostgres covers the PG half of the 3.1 framing refactor
// live (nothing else exercises PG server-scope framing against a real
// server): sections switch via \connect, the session preamble is re-emitted
// PER SECTION (PG SETs do not survive \connect) rather than globally, and the
// dump restores through the server-scope import into existing databases.
func TestLiveServerDumpPostgres(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
	ctx := context.Background()
	d, _ := driver.Get(env.engine)
	admin, err := driver.Open(ctx, d, driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()
	requireIsolatedServerScope(t, admin, env.engine)
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: liveDB}
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	for _, stmt := range []string{
		"CREATE TABLE keepme (id int PRIMARY KEY, v text)",
		"INSERT INTO keepme VALUES (1, 'survives')",
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	base, client, csrf := liveNBELogin(t, env, nil)
	status, dump := livePost(t, client, base, "/server/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if status != http.StatusOK || !strings.Contains(dump, "CREATE TABLE") {
		t.Fatalf("server export = %d:\n%.2000s", status, dump)
	}
	connectMarker := `\connect "` + liveDB + `"`
	if !strings.Contains(dump, connectMarker) {
		t.Fatalf("server dump missing the \\connect marker %q:\n%.2000s", connectMarker, dump)
	}
	// Per-section preamble: the standard_conforming_strings SET must appear
	// AFTER the first \connect (never as a global preamble the \connect would
	// discard), and once per addressable section.
	firstConnect := strings.Index(dump, `\connect`)
	firstPreamble := strings.Index(dump, "SET standard_conforming_strings")
	if firstPreamble < 0 || firstPreamble < firstConnect {
		t.Errorf("PG preamble must be per-section (after \\connect): connect@%d preamble@%d\n%.2000s",
			firstConnect, firstPreamble, dump)
	}

	// Restore through the server-scope import (targets must already exist).
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	status, page := livePost(t, client, base, "/server/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if status != http.StatusOK || strings.Contains(page, "tx-alert-error") {
		t.Fatalf("server import failed (%d): %s", status, pageErrorSnippet(page))
	}
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	rows := queryRows(t, check, "SELECT v FROM keepme WHERE id = 1")
	if len(rows) != 1 || strings.TrimSpace(rows[0]) != "survives" {
		t.Errorf("restored row = %v, want [survives]", rows)
	}
}

// TestLiveServerImportCollationWarningsMySQL exercises the USE-based marker
// lookup across a multi-database MySQL server-scope import: the probe runs on
// the pinned connection at the marker's stream position, so a marker after
// `USE w1` compares against w1's collation and one after `USE w2` against
// w2's — one existing target created with a different collation (warns), one
// with the recorded collation (silent).
func TestLiveServerImportCollationWarningsMySQL(t *testing.T) {
	env := liveEnvFor(t, "MYSQL", "mysql", 3306, "root")
	ctx := context.Background()
	d, _ := driver.Get(env.engine)
	admin, err := driver.Open(ctx, d, driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()
	const w1, w2 = "tablex_rt_w1", "tablex_rt_w2"
	drop := func() {
		for _, db := range []string{w1, w2} {
			if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+db); err != nil {
				t.Fatalf("drop %s: %v", db, err)
			}
		}
	}
	drop()
	defer drop()

	const recorded = "latin1_swedish_ci"
	script := strings.Join([]string{
		"CREATE DATABASE " + w1 + " CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;",
		"USE " + w1 + ";",
		driver.FormatCollationMarker("routine", "r_mismatch", recorded),
		"CREATE TABLE t1 (id INT PRIMARY KEY);",
		"CREATE DATABASE " + w2 + " CHARACTER SET latin1 COLLATE " + recorded + ";",
		"USE " + w2 + ";",
		driver.FormatCollationMarker("routine", "r_match", recorded),
		"CREATE TABLE t2 (id INT PRIMARY KEY);",
	}, "\n")

	base, client, csrf := liveNBELogin(t, env, nil)
	status, page := livePost(t, client, base, "/server/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {script},
	})
	if status != http.StatusOK || strings.Contains(page, "tx-alert-error") {
		t.Fatalf("server import failed (%d):\n%.4000s", status, page)
	}
	if !strings.Contains(page, "1 warning(s):") {
		t.Errorf("expected exactly one collation warning:\n%.4000s", page)
	}
	for _, want := range []string{"r_mismatch", recorded, "utf8mb4_general_ci", w1} {
		if !strings.Contains(page, want) {
			t.Errorf("warning text missing %q:\n%.4000s", want, page)
		}
	}
	if strings.Contains(page, "r_match") {
		t.Errorf("matching-collation marker produced a spurious warning:\n%.4000s", page)
	}
}
