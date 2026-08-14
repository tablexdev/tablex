package server_test

// Live-engine round-trip tests: export → drop → re-import → snapshot equality
// against real MySQL / MariaDB / PostgreSQL servers. They are the first place
// the MySQL/PostgreSQL dialect SQL executes outside unit tests, which is
// exactly how earlier dump/structure bugs survived — unit tests asserted the
// buggy strings.
//
// Each test is gated on TABLEX_TEST_<ENGINE>_HOST (set by the CI Docker
// services; set locally to run against your own server) and skips otherwise:
//
//	TABLEX_TEST_MYSQL_HOST / _PORT / _USER / _PASSWORD
//	TABLEX_TEST_MARIADB_HOST / _PORT / _USER / _PASSWORD
//	TABLEX_TEST_POSTGRES_HOST / _PORT / _USER / _PASSWORD
//
// The tests own the scratch database "tablex_rt" on the target server and drop
// it on completion.

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	"github.com/tablexdev/tablex/internal/model"
)

const liveDB = "tablex_rt"

type liveEnv struct {
	label  string // env prefix: MYSQL / MARIADB / POSTGRES
	engine string // dialect name: mysql / postgres
	host   string
	port   int
	user   string
	pass   string
}

func liveEnvFor(t *testing.T, label, engine string, defPort int, defUser string) liveEnv {
	t.Helper()
	host := os.Getenv("TABLEX_TEST_" + label + "_HOST")
	if host == "" {
		t.Skipf("TABLEX_TEST_%s_HOST not set; live %s round-trip skipped", label, strings.ToLower(label))
	}
	port := defPort
	if p := os.Getenv("TABLEX_TEST_" + label + "_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			// Fail loudly rather than silently connecting to the default port,
			// which would run the test against an unexpected server.
			t.Fatalf("TABLEX_TEST_%s_PORT=%q is not a valid port: %v", label, p, err)
		}
		port = n
	}
	user := os.Getenv("TABLEX_TEST_" + label + "_USER")
	if user == "" {
		user = defUser
	}
	return liveEnv{
		label: label, engine: engine, host: host, port: port,
		user: user, pass: os.Getenv("TABLEX_TEST_" + label + "_PASSWORD"),
	}
}

func TestLiveRoundTripMySQL(t *testing.T) {
	liveRoundTrip(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveRoundTripMariaDB(t *testing.T) {
	liveRoundTrip(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveRoundTripPostgres(t *testing.T) {
	liveRoundTrip(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLiveMariaDBExpressionDefault(t *testing.T) {
	liveExpressionDefault(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveMariaDBLiteralDefaultFidelity(t *testing.T) {
	liveMariaDBLiteralDefaultFidelity(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveMySQLDatabaseSearch(t *testing.T) {
	liveDBSearch(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBDatabaseSearch(t *testing.T) {
	liveDBSearch(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLivePostgresDatabaseSearch(t *testing.T) {
	liveDBSearch(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveDBSearch covers #46: DBSearch's bulk fast path. On an engine with
// driver.BulkIntrospector (MySQL/MariaDB/PostgreSQL) the whole-database search
// reads every table's columns in ONE schema-wide query instead of one per table
// — and must return the same hits the per-table path did. The SQLite unit test
// exercises the fallback branch (SQLite has no BulkIntrospector); this exercises
// the bulk branch the fallback test cannot reach.
func liveDBSearch(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		// PostgreSQL binds one database per connection; the maintenance one is
		// where CREATE/DROP DATABASE runs.
		adminParams.Database = "postgres"
	}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	// Two tables; the search term lives only in parts.name.
	for _, stmt := range []string{
		"CREATE TABLE parts (id INT PRIMARY KEY, name VARCHAR(64))",
		"CREATE TABLE widgets (id INT PRIMARY KEY, label VARCHAR(64))",
		"INSERT INTO parts VALUES (1, 'searchbolt'), (2, 'nut')",
		"INSERT INTO widgets VALUES (1, 'gizmo')",
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	csrf = csrfFrom(t, client, ts.URL+"/")

	// A term present only in parts.name: the bulk path must find the hit there.
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/search", url.Values{"csrf_token": {csrf}, "term": {"searchbolt"}})
	if err != nil {
		t.Fatalf("db search: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("db search = %d:\n%.1000s", resp.StatusCode, page)
	}
	if !strings.Contains(string(page), "parts") || !strings.Contains(string(page), "match(es)") {
		t.Errorf("bulk-path db search missed the parts hit:\n%.2000s", page)
	}

	// A term present nowhere returns no matches — proof the search actually ran
	// over the data rather than just rendering the table list.
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/search", url.Values{"csrf_token": {csrf}, "term": {"zzz_no_such_value_zzz"}})
	if err != nil {
		t.Fatalf("db search (miss): %v", err)
	}
	miss, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(miss), "match(es)") {
		t.Errorf("bulk-path db search reported a match for a term present nowhere:\n%.2000s", miss)
	}

	// Case sensitivity belongs to the ENGINE — the search folds nothing itself
	// (see likeContains), so LIKE behaves exactly as it does for any other
	// comparison against that column's collation. MySQL/MariaDB match
	// case-insensitively under their usual collations; PostgreSQL does not,
	// unless the column is citext or carries a case-insensitive ICU collation.
	// Pinned per engine because a shared "it matches" assertion would be wrong
	// on one of them, and the comment makes a specific claim about both.
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/search", url.Values{"csrf_token": {csrf}, "term": {"SEARCHBOLT"}})
	if err != nil {
		t.Fatalf("db search (upper case): %v", err)
	}
	upper, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	switch matched := strings.Contains(string(upper), "match(es)"); env.engine {
	case "postgres":
		if matched {
			t.Errorf("PostgreSQL matched an upper-cased term against a case-sensitive collation; the search must not fold case itself:\n%.2000s", upper)
		}
	default:
		if !matched {
			t.Errorf("%s did not match an upper-cased term, though its collation is case-insensitive:\n%.2000s", env.label, upper)
		}
	}
}

// liveMariaDBLiteralDefaultFidelity pins the MariaDB literal-DEFAULT read
// grammar end to end. MariaDB renders literal defaults back through its own
// string-literal grammar (backslash escapes included), and the reader used to
// collapse only doubled quotes — so a DEFAULT 'a\b' displayed as a\\b, and
// every UNTOUCHED column-modify Save re-quoted the displayed text, adding one
// more backslash per round trip. The test does exactly what a user does:
// scrape the modify form's prefill, save it back unchanged, twice — then
// proves the stored default still inserts the original bytes.
func liveMariaDBLiteralDefaultFidelity(t *testing.T, env liveEnv) {
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	// SQL-escaped: the stored default VALUE is a\b (one backslash).
	if _, err := seed.Exec(ctx, `CREATE TABLE ld (id INT NOT NULL PRIMARY KEY, v VARCHAR(64) NULL DEFAULT 'a\\b')`); err != nil {
		seed.Close()
		t.Fatalf("seed: %v", err)
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	inputRE := regexp.MustCompile(`<input[^>]*name="default_value"[^>]*>`)
	valueRE := regexp.MustCompile(`value="([^"]*)"`)
	scrape := func() string {
		t.Helper()
		resp, err := client.Get(ts.URL + "/db/" + liveDB + "/table/ld/structure?modify=v")
		if err != nil {
			t.Fatalf("GET ?modify=v: %v", err)
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET ?modify=v = %d", resp.StatusCode)
		}
		// The page carries SEVERAL default_value inputs (per-row drop forms and
		// the Add-column form come first); anchor to the modify form via its
		// hidden action input.
		anchor := strings.Index(string(page), `name="action" value="modify_column"`)
		if anchor < 0 {
			t.Fatalf("no modify form on the page:\n%.3000s", page)
		}
		tag := inputRE.Find(page[anchor:])
		if tag == nil {
			t.Fatalf("no default_value input on the modify form:\n%.3000s", page)
		}
		m := valueRE.FindSubmatch(tag)
		if m == nil {
			t.Fatalf("default_value input carries no value attribute: %s", tag)
		}
		return html.UnescapeString(string(m[1]))
	}
	save := func(prefill string) {
		t.Helper()
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/table/ld/structure", url.Values{
			"csrf_token":    {csrf},
			"action":        {"modify_column"},
			"column":        {"v"},
			"col_type":      {"VARCHAR"},
			"col_length":    {"64"},
			"col_nullable":  {"1"},
			"default_mode":  {"custom"},
			"default_value": {prefill},
		})
		if err != nil {
			t.Fatalf("modify: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("modify_column = %d, want 303:\n%.2000s", resp.StatusCode, body)
		}
	}

	// The form must prefill the RAW value; an untouched Save must be a no-op —
	// twice, because the defect compounded one escape per round trip.
	if got := scrape(); got != `a\b` {
		t.Fatalf(`modify prefill = %q, want a\b (the reader is off by one escape)`, got)
	}
	save(scrape())
	if got := scrape(); got != `a\b` {
		t.Fatalf(`prefill after one save = %q, want a\b (the save compounded an escape)`, got)
	}
	save(scrape())
	if got := scrape(); got != `a\b` {
		t.Fatalf(`prefill after two saves = %q, want a\b`, got)
	}

	// Ground truth: a row relying on the default stores the original bytes.
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	if _, err := check.Exec(ctx, "INSERT INTO ld (id) VALUES (1)"); err != nil {
		t.Fatalf("insert default row: %v", err)
	}
	if got := queryRows(t, check, "SELECT v FROM ld WHERE id = 1"); strings.Join(got, "") != `a\b` {
		t.Errorf(`defaulted value after two saves = %q, want a\b`, strings.Join(got, ""))
	}
}

func TestLiveMySQLExpressionDefault(t *testing.T) {
	liveExpressionDefault(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLivePostgresVirtualGenerated(t *testing.T) {
	liveVirtualGenerated(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresCrossSchema(t *testing.T) {
	liveCrossSchema(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresInheritance(t *testing.T) {
	liveInheritance(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresPartitionChildObjects(t *testing.T) {
	livePartitionChildObjects(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresMixedPartitionTree(t *testing.T) {
	liveMixedPartitionTree(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresRestoreCriticalObjects(t *testing.T) {
	liveRestoreCriticalObjects(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresZeroInsertable(t *testing.T) {
	liveZeroInsertable(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresViewExport(t *testing.T) {
	liveViewExport(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresColumnSettings(t *testing.T) {
	liveColumnSettings(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresRelationOptions(t *testing.T) {
	liveRelationOptions(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresCollations(t *testing.T) {
	liveCollations(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresNoOwnerACL(t *testing.T) {
	liveNoOwnerACL(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLivePostgresInheritanceMulti(t *testing.T) {
	liveInheritanceMulti(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveInheritanceMulti pins the G10 INHERITS-link edge cases: MULTIPLE parents
// (both must create before the child — topo ordering) and a child with NO local
// columns (empty `()` body). The child links to both parents after round-trip.
func liveInheritanceMulti(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		// zz_p1/zz_p2 sort AFTER the child alphabetically, so the topo ordering (not
		// alphabetical) is what makes the parents create first.
		`CREATE TABLE zz_p1 (a int)`,
		`CREATE TABLE zz_p2 (b int)`,
		// aa_child has NO local columns — an empty-body CREATE TABLE () INHERITS.
		`CREATE TABLE aa_child () INHERITS (zz_p1, zz_p2)`,
		`INSERT INTO aa_child (a, b) VALUES (1, 2)`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("multi-parent inheritance import failed (%d):\n%.3000s\n--- dump ---\n%.4000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// aa_child links to BOTH parents after restore.
	if got := queryRows(t, check, `SELECT count(*) FROM pg_inherits WHERE inhrelid = 'public.aa_child'::regclass`); strings.TrimSpace(strings.Join(got, "")) != "2" {
		t.Errorf("aa_child parent count = %v after round-trip, want 2", got)
	}
	// Both inherited columns exist, both inherited (no local columns).
	if got := queryRows(t, check, `SELECT attname || ':' || attislocal::text FROM pg_attribute WHERE attrelid = 'public.aa_child'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum`); strings.Join(got, ",") != "a:false,b:false" {
		t.Errorf("aa_child columns = %q after round-trip, want a:false,b:false", strings.Join(got, ","))
	}
	if got := queryRows(t, check, `SELECT a || ',' || b FROM ONLY aa_child`); strings.TrimSpace(strings.Join(got, "")) != "1,2" {
		t.Errorf("aa_child row = %v, want 1,2", got)
	}
}

// assertNoOwnerACL pins the PostgreSQL ownership/ACL posture (pg_dump --no-owner
// --no-acl parity): no dumped statement begins with GRANT, REVOKE, ALTER …
// OWNER TO or ALTER DEFAULT PRIVILEGES. The check is statement-HEAD-anchored, not
// substring — a routine body is opaque SQL that may legally contain those words,
// so only a LINE whose trimmed prefix starts the keyword counts (OWNER TO is
// always mid-statement, so its whole-dump absence is asserted directly).
func assertNoOwnerACL(t *testing.T, dump string) {
	t.Helper()
	if strings.Contains(dump, " OWNER TO ") {
		t.Errorf("dump emitted an OWNER TO statement (ownership must not be dumped):\n%s", dump)
	}
	for line := range strings.SplitSeq(dump, "\n") {
		head := strings.ToUpper(strings.TrimSpace(line))
		for _, kw := range []string{"GRANT ", "REVOKE ", "ALTER DEFAULT PRIVILEGES"} {
			if strings.HasPrefix(head, kw) {
				t.Errorf("dump emitted a %q statement (privileges must not be dumped):\n\t%s", strings.TrimSpace(kw), line)
			}
		}
	}
}

// liveNoOwnerACL pins WS-6: a PostgreSQL SQL dump carries no ownership or
// privilege statements. Every table/routine has an owner and default privileges,
// so if the dump code ever emitted them they would appear here.
func liveNoOwnerACL(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE TABLE t (id int PRIMARY KEY)`,
		`INSERT INTO t VALUES (1)`,
		// A routine whose body legally contains the words GRANT/REVOKE proves the
		// head-anchored check does not false-positive on opaque SQL bodies.
		`CREATE FUNCTION note() RETURNS text LANGUAGE sql AS $$ SELECT 'grant revoke owner to nobody' $$`,
		`CREATE VIEW v AS SELECT id FROM t`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dumpBytes)
	}
	assertNoOwnerACL(t, string(dumpBytes))
}

// liveCollations pins WS-2 G9: a column's non-default collation and any
// user-defined collation it needs were silently lost — the column COLLATE was
// never emitted and no CREATE COLLATION pass existed, so a restore either lost
// the collation semantics or failed on the missing collation. Now a portable
// libc collation and a built-in ("C") collation both round-trip.
func liveCollations(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		// A portable libc collation (present on every build) + a comment.
		`CREATE COLLATION mycoll (LOCALE = 'C', PROVIDER = libc)`,
		`COMMENT ON COLLATION mycoll IS 'portable C collation'`,
		// a: built-in non-default collation; b: user-defined; c: default (no COLLATE).
		`CREATE TABLE ct (a text COLLATE "C", b text COLLATE mycoll, c text)`,
		`INSERT INTO ct VALUES ('x','y','z')`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	// An ICU collation carrying TAILORING RULES (PG16+, and only on a build
	// compiled with ICU). Run-or-skip: the rules are part of the collation's
	// identity, so restoring without them silently changes comparison results —
	// but a non-ICU build cannot host the fixture at all.
	icuRules := `&V << w <<< W`
	icu := true
	if _, err := seed.Exec(ctx, `CREATE COLLATION icucoll (PROVIDER = icu, LOCALE = 'und', RULES = '`+icuRules+`')`); err != nil {
		t.Logf("skipping the ICU RULES fixture on this build: %v", err)
		icu = false
	} else if _, err := seed.Exec(ctx, `ALTER TABLE ct ADD COLUMN d text COLLATE icucoll`); err != nil {
		seed.Close()
		t.Fatalf("seed ICU column: %v", err)
	}
	seed.Close()

	fingerprint := func() string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		icuFP := ""
		if icu {
			icuFP = "\n--\n" + strings.Join(queryRows(t, c, `
				SELECT collname || '|' || collprovider::text || '|' ||
				       COALESCE(to_jsonb(co)->>'collicurules','')
				FROM pg_collation co JOIN pg_namespace n ON n.oid = co.collnamespace
				WHERE n.nspname = 'public' AND collname = 'icucoll'`), "\n")
		}
		// Per-column collation name, plus the user collation's own definition.
		cols := queryRows(t, c, `
			SELECT a.attname || '|' || COALESCE(co.collname, '(default)')
			FROM pg_attribute a
			JOIN pg_class rc ON rc.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = rc.relnamespace
			LEFT JOIN pg_collation co ON co.oid = a.attcollation AND a.attcollation <> 0
			WHERE n.nspname='public' AND rc.relname='ct' AND a.attnum>0 AND NOT a.attisdropped
			ORDER BY a.attnum`)
		coll := queryRows(t, c, `
			SELECT collname || '|' || collprovider::text || '|' ||
			       COALESCE(to_jsonb(co)->>'collcollate','') || '|' ||
			       COALESCE(obj_description(co.oid,'pg_collation'),'')
			FROM pg_collation co JOIN pg_namespace n ON n.oid=co.collnamespace
			WHERE n.nspname='public' AND collname='mycoll'`)
		return strings.Join(cols, "\n") + "\n--\n" + strings.Join(coll, "\n") + icuFP
	}
	before := fingerprint()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	if !strings.Contains(dump, "CREATE COLLATION") || !strings.Contains(dump, "PROVIDER = libc") {
		t.Errorf("dump missing CREATE COLLATION:\n%s", dump)
	}
	if !strings.Contains(dump, "COLLATE") {
		t.Errorf("dump missing column COLLATE:\n%s", dump)
	}
	if icu {
		if want := `PROVIDER = icu, RULES = '` + icuRules + `'`; !strings.Contains(dump, want) {
			t.Errorf("dump must carry the ICU tailoring rules (%q):\n%s", want, dump)
		}
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("collation import failed (%d):\n%.3000s\n--- dump ---\n%.3000s", resp.StatusCode, importBody, dump)
	}

	if after := fingerprint(); after != before {
		t.Errorf("collations drifted after round-trip:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// liveRelationOptions pins WS-2 G9: a relation's storage parameters (reloptions)
// were silently lost from dumps — including a VIEW's security_barrier /
// security_invoker / check_option, whose loss silently changes restored
// authorization. They must now round-trip. security_invoker is gated on PG15+.
func liveRelationOptions(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	pg15 := pgServerVersionNum(t, admin) >= 150000

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	viewOpts := "security_barrier = true, check_option = 'local'"
	if pg15 {
		viewOpts = "security_invoker = true, " + viewOpts
	}
	for _, stmt := range []string{
		`CREATE TABLE topt (id int) WITH (fillfactor = 70, autovacuum_enabled = false)`,
		`INSERT INTO topt VALUES (1), (2)`,
		`CREATE VIEW vopt WITH (` + viewOpts + `) AS SELECT id FROM topt WHERE id > 0`,
		`CREATE MATERIALIZED VIEW mopt WITH (autovacuum_enabled = false) AS SELECT id FROM topt WITH DATA`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	fingerprint := func() string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		got := queryRows(t, c, `
			SELECT relname || '|' || COALESCE(array_to_string(reloptions, ','), '')
			FROM pg_class WHERE relname IN ('topt','vopt','mopt') ORDER BY relname`)
		return strings.Join(got, "\n")
	}
	before := fingerprint()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	if !strings.Contains(dump, "fillfactor = '70'") {
		t.Errorf("dump missing table reloptions:\n%s", dump)
	}
	if pg15 && !strings.Contains(dump, "security_invoker = 'true'") {
		t.Errorf("dump missing view security_invoker:\n%s", dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("reloptions import failed (%d):\n%.3000s\n--- dump ---\n%.3000s", resp.StatusCode, importBody, dump)
	}

	if after := fingerprint(); after != before {
		t.Errorf("reloptions drifted after round-trip:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// liveColumnSettings pins WS-2 G15(b): a column's non-default physical settings —
// SET STORAGE, SET COMPRESSION (pglz), SET STATISTICS — that the CREATE TABLE
// column line does not carry were silently lost from dumps. They must now
// round-trip (attstorage/attcompression/attstattarget identical before/after).
func liveColumnSettings(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	// Column compression (SET COMPRESSION) is PG14+; skip that column on the 13
	// floor while keeping STORAGE/STATISTICS coverage.
	pg14 := pgServerVersionNum(t, admin) >= 140000
	seedStmts := []string{
		`CREATE TABLE settings (a text, b text, c text, d int, e int)`,
		`ALTER TABLE settings ALTER COLUMN b SET STORAGE EXTERNAL`,
		`ALTER TABLE settings ALTER COLUMN d SET STATISTICS 250`,
		`ALTER TABLE settings ALTER COLUMN e SET STATISTICS 0`,
		`INSERT INTO settings VALUES ('x','y','z',1,2)`,
	}
	if pg14 {
		seedStmts = append(seedStmts, `ALTER TABLE settings ALTER COLUMN c SET COMPRESSION pglz`)
	}
	for _, stmt := range seedStmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	fingerprint := func() string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		got := queryRows(t, c, `
			SELECT a.attname || '|' || a.attstorage::text || '|' ||
			       COALESCE(to_jsonb(a)->>'attcompression','') || '|' ||
			       COALESCE(to_jsonb(a)->>'attstattarget','')
			FROM pg_attribute a
			JOIN pg_class rc ON rc.oid=a.attrelid
			JOIN pg_namespace n ON n.oid=rc.relnamespace
			WHERE n.nspname='public' AND rc.relname='settings' AND a.attnum>0 AND NOT a.attisdropped
			ORDER BY a.attnum`)
		return strings.Join(got, "\n")
	}
	before := fingerprint()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	// The dump must actually carry the settings ALTERs (a live fingerprint alone
	// would also pass if the target defaulted to the same value).
	wantSettings := []string{"SET STORAGE EXTERNAL", "SET STATISTICS 250", "SET STATISTICS 0"}
	if pg14 {
		wantSettings = append(wantSettings, "SET COMPRESSION pglz")
	}
	for _, want := range wantSettings {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing %q:\n%s", want, dump)
		}
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("column-settings import failed (%d):\n%.3000s\n--- dump ---\n%.3000s", resp.StatusCode, importBody, dump)
	}

	if after := fingerprint(); after != before {
		t.Errorf("column settings drifted after round-trip:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// liveViewExport pins V1 on PostgreSQL: a table-scope SQL export of a VIEW emits
// CREATE VIEW (not a physical CREATE TABLE snapshot with row INSERTs), and of a
// MATERIALIZED VIEW emits CREATE MATERIALIZED VIEW … WITH NO DATA plus a data-
// gated REFRESH. Both round-trip into a target that already holds the base table
// (a single-view export is not self-contained). Before the fix the view dumped
// as a table snapshot and the matview lost its refresh.
func liveViewExport(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	// baseSeed recreates the base table + rows the views read; run once for the
	// initial seed and again in each fresh restore target (a single-view export is
	// not self-contained).
	baseSeed := []string{
		`CREATE TABLE vbase (id int PRIMARY KEY, name text)`,
		`INSERT INTO vbase VALUES (1, 'a'), (2, 'b'), (3, 'c')`,
	}
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	stmts := append([]string(nil), baseSeed...)
	stmts = append(stmts,
		`CREATE VIEW vw AS SELECT id, name FROM vbase WHERE id > 1`,
		`COMMENT ON VIEW vw IS 'names past one'`,
		`COMMENT ON COLUMN vw.name IS 'the name'`,
		`CREATE MATERIALIZED VIEW mv AS SELECT id FROM vbase WITH DATA`,
	)
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	exportView := func(name string) string {
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/table/"+name+"/export", url.Values{
			"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
		})
		if err != nil {
			t.Fatalf("export %s: %v", name, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %s = %d:\n%.2000s", name, resp.StatusCode, b)
		}
		return string(b)
	}

	// --- plain view ---
	vwDump := exportView("vw")
	if !strings.Contains(vwDump, "CREATE OR REPLACE VIEW") || !strings.Contains(vwDump, "vw") {
		t.Errorf("view dump missing CREATE VIEW:\n%s", vwDump)
	}
	if strings.Contains(vwDump, "CREATE TABLE") {
		t.Errorf("view dump wrongly emitted a physical CREATE TABLE:\n%s", vwDump)
	}
	if strings.Contains(vwDump, "INSERT INTO") {
		t.Errorf("view dump wrongly emitted row INSERTs:\n%s", vwDump)
	}
	if !strings.Contains(vwDump, "COMMENT ON VIEW") || !strings.Contains(vwDump, "COMMENT ON COLUMN") {
		t.Errorf("view dump lost its comments:\n%s", vwDump)
	}

	// --- materialized view ---
	mvDump := exportView("mv")
	if !strings.Contains(mvDump, "CREATE MATERIALIZED VIEW") || !strings.Contains(mvDump, "WITH NO DATA") {
		t.Errorf("matview dump missing CREATE MATERIALIZED VIEW … WITH NO DATA:\n%s", mvDump)
	}
	if !strings.Contains(mvDump, "REFRESH MATERIALIZED VIEW") {
		t.Errorf("matview dump missing REFRESH (data-gated):\n%s", mvDump)
	}

	// Round-trip both into a fresh DB that already holds the base table.
	restore := func(name, dump string) {
		liveDropDB(t, admin, env.engine)
		liveCreateDB(t, admin)
		target, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("restore-seed connect: %v", err)
		}
		for _, stmt := range baseSeed {
			if _, err := target.Exec(ctx, stmt); err != nil {
				target.Close()
				t.Fatalf("restore-seed %q: %v", stmt, err)
			}
		}
		target.Close()
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
		if err != nil {
			t.Fatalf("import %s: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "tx-alert-error") {
			t.Fatalf("import %s failed (%d):\n%.3000s\n--- dump ---\n%.3000s", name, resp.StatusCode, body, dump)
		}
	}
	check := func() *driver.Connection {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("verify connect: %v", err)
		}
		return c
	}

	restore("vw", vwDump)
	c := check()
	if got := queryRows(t, c, `SELECT count(*) FROM vw`); strings.TrimSpace(strings.Join(got, "")) != "2" {
		t.Errorf("vw returned %q rows after round-trip, want 2 (id > 1)", got)
	}
	if got := queryRows(t, c, `SELECT obj_description('public.vw'::regclass, 'pg_class')`); strings.TrimSpace(strings.Join(got, "")) != "names past one" {
		t.Errorf("vw comment = %q after round-trip", got)
	}
	c.Close()

	restore("mv", mvDump)
	c = check()
	// The matview restored populated (its data-gated REFRESH ran).
	if got := queryRows(t, c, `SELECT count(*) FROM mv`); strings.TrimSpace(strings.Join(got, "")) != "3" {
		t.Errorf("mv returned %q rows after round-trip, want 3 (REFRESH must have run)", got)
	}
	c.Close()
}

// liveZeroInsertable pins WS-1 L10: a table with NO insertable columns — a
// zero-column table, and one whose only column is generated — has rows that carry
// no writable value, so the SQL dump silently lost every row (empty INSERT list →
// empty SELECT → table skipped). Now it emits N all-defaults INSERTs.
func liveZeroInsertable(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE TABLE zerocol ()`,
		`INSERT INTO zerocol DEFAULT VALUES`,
		`INSERT INTO zerocol DEFAULT VALUES`,
		`INSERT INTO zerocol DEFAULT VALUES`,
		// A table whose only column is generated (constant expression) — no
		// insertable column either.
		`CREATE TABLE allgen (g int GENERATED ALWAYS AS (7) STORED)`,
		`INSERT INTO allgen DEFAULT VALUES`,
		`INSERT INTO allgen DEFAULT VALUES`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("zero-insertable import failed (%d):\n%.3000s\n--- dump ---\n%.3000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	if got := queryRows(t, check, `SELECT count(*) FROM zerocol`); strings.TrimSpace(strings.Join(got, "")) != "3" {
		t.Errorf("zerocol count = %q after round-trip, want 3 (rows must not be silently lost)", got)
	}
	if got := queryRows(t, check, `SELECT count(*) FROM allgen`); strings.TrimSpace(strings.Join(got, "")) != "2" {
		t.Errorf("allgen count = %q after round-trip, want 2", got)
	}
}

// livePartitionChildObjects pins WS-1 G11: a partition CHILD's LOCAL objects — a
// child-only FK, a NOT VALID CHECK, and a table comment — were silently dropped
// from the dump because partition children were excluded from the object passes'
// gate set. They must now round-trip, while the parent-cloned objects must NOT be
// double-emitted (conparentid/conislocal/tgparentid filters).
func livePartitionChildObjects(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE TABLE ref (id int PRIMARY KEY)`,
		`INSERT INTO ref VALUES (1), (2)`,
		`CREATE TABLE part (id int, region int, ref_id int, amt int) PARTITION BY LIST (region)`,
		`CREATE TABLE part_a PARTITION OF part FOR VALUES IN (1)`,
		`CREATE TABLE part_b PARTITION OF part FOR VALUES IN (2)`,
		// Child-LOCAL objects on part_a only.
		`ALTER TABLE part_a ADD CONSTRAINT fk_pa FOREIGN KEY (ref_id) REFERENCES ref(id)`,
		`ALTER TABLE part_a ADD CONSTRAINT chk_pa CHECK (amt >= 0) NOT VALID`,
		`COMMENT ON TABLE part_a IS 'partition A local'`,
		// A trigger on the PARTITIONED parent is cloned onto every child, and
		// the clone really fires there — so the child's Triggers tab must list
		// it. PostgreSQL flags that clone tgisinternal on 13 but not on 14+.
		`CREATE FUNCTION part_trg_f() RETURNS trigger LANGUAGE plpgsql AS 'begin return new; end'`,
		`CREATE TRIGGER part_trg BEFORE INSERT ON part FOR EACH ROW EXECUTE FUNCTION part_trg_f()`,
		`INSERT INTO part VALUES (10, 1, 1, 5), (20, 2, 2, 7)`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}

	// The child's Triggers tab must report the CLONED trigger — it fires on this
	// table — on every supported server, and must never surface the
	// referential-integrity machinery, which is internal AND cloned onto
	// partitions too. (PostgreSQL flags the clone tgisinternal on 13, but not on
	// 14+, so the naive internal test reports "no triggers" on the floor.)
	tabCode, tabPage := getBody(t, client, ts.URL+"/db/"+liveDB+"/table/part_a/triggers?schema=public")
	if tabCode != http.StatusOK {
		t.Fatalf("part_a triggers tab = %d", tabCode)
	}
	if !strings.Contains(tabPage, "part_trg") {
		t.Errorf("a partition child's Triggers tab must list its cloned trigger:\n%.3000s", tabPage)
	}
	if strings.Contains(tabPage, "RI_ConstraintTrigger") {
		t.Errorf("the Triggers tab must not surface referential-integrity triggers:\n%.3000s", tabPage)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("partition-child import failed (%d):\n%.3000s\n--- dump ---\n%.5000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// The child-local FK and CHECK survived on part_a exactly once each.
	if got := queryRows(t, check, `SELECT conname, contype::text FROM pg_constraint WHERE conrelid = 'public.part_a'::regclass AND conname IN ('fk_pa','chk_pa') ORDER BY conname`); strings.Join(got, "\n") != "chk_pa|c\nfk_pa|f" {
		t.Errorf("part_a local constraints = %q after round-trip, want chk_pa (check) + fk_pa (fk)", strings.Join(got, "\n"))
	}
	// The child-local comment survived.
	if got := queryRows(t, check, `SELECT obj_description('public.part_a'::regclass, 'pg_class')`); strings.TrimSpace(strings.Join(got, "")) != "partition A local" {
		t.Errorf("part_a comment = %q after round-trip, want 'partition A local'", got)
	}
	// Data round-trips (2 rows, no duplication).
	if got := queryRows(t, check, `SELECT count(*) FROM part`); strings.TrimSpace(strings.Join(got, "")) != "2" {
		t.Errorf("part count = %q after round-trip, want 2", got)
	}
}

// liveMixedPartitionTree pins the mixed local/foreign partition-tree split in
// every scope/kind combination. The split (StructureOnlyTables: the root must
// not be scanned recursively — that scan would also open a connection to the
// REMOTE server; DataOnlyTables: each local leaf read exactly once via FROM
// ONLY, and created only via the root's PARTITION OF emission) used to run
// only inside the structure+data database pass, so a DATA-ONLY database
// export dumped every local row twice (root recursion + leaf FROM ONLY), a
// TABLE-scope export of the root ran the recursive scan against the remote
// server, and a STRUCTURE-ONLY export created each kept local leaf twice
// (standalone CREATE + the root's PARTITION OF), aborting the restore on
// "relation already exists". The foreign server points at an unreachable host
// on purpose: any recursive root scan fails and lands as an in-dump `-- data
// export error` marker, so "no marker" is also the no-FDW-connection
// assertion. The structure-only export must still carry NO mixed-tree
// warning — the split runs, but its warnings are data-facing.
func liveMixedPartitionTree(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	// postgres_fdw ships with contrib (present in the postgres images); skip
	// politely on a build without it.
	if _, err := seed.Exec(ctx, `CREATE EXTENSION postgres_fdw`); err != nil {
		seed.Close()
		t.Skipf("postgres_fdw extension unavailable: %v", err)
	}
	for _, stmt := range []string{
		// Allowlisted options only, so the foreign leaf's CREATE survives
		// redaction and the restore below is executable.
		`CREATE SERVER mixremote FOREIGN DATA WRAPPER postgres_fdw
			OPTIONS (host 'remote.example', port '5433', dbname 'appdb')`,
		`CREATE TABLE mixt (id int, region text, note text) PARTITION BY LIST (region)`,
		`CREATE TABLE mixt_local PARTITION OF mixt FOR VALUES IN ('local')`,
		`CREATE FOREIGN TABLE mixt_far PARTITION OF mixt FOR VALUES IN ('far')
			SERVER mixremote OPTIONS (schema_name 'public', table_name 'mixt_far')`,
		`INSERT INTO mixt VALUES (1, 'local', 'mix-alpha'), (2, 'local', 'mix-beta')`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	export := func(path string, form url.Values) string {
		t.Helper()
		form.Set("csrf_token", csrf)
		form.Set("format", "sql")
		resp, err := client.PostForm(ts.URL+path, form)
		if err != nil {
			t.Fatalf("export %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %s = %d:\n%.2000s", path, resp.StatusCode, b)
		}
		return string(b)
	}
	const rootInsert = `INSERT INTO "public"."mixt" (`
	const farWarning = "is a FOREIGN table; its rows live on the remote server and are not dumped"
	assertLocalRowsOnce := func(label, dump string) {
		t.Helper()
		for _, val := range []string{"mix-alpha", "mix-beta"} {
			if n := strings.Count(dump, val); n != 1 {
				t.Errorf("%s: %q appears %d times, want exactly 1 (a recursive root scan duplicates every local row):\n%s", label, val, n, dump)
			}
		}
		if strings.Contains(dump, rootInsert) {
			t.Errorf("%s must not scan the partition ROOT for data:\n%s", label, dump)
		}
		if strings.Contains(dump, "-- data export error") {
			t.Errorf("%s reached a data scan that failed — the recursive root scan would open a connection to the remote FDW server:\n%s", label, dump)
		}
		if !strings.Contains(dump, farWarning) {
			t.Errorf("%s must warn that the foreign leaf's rows are not dumped:\n%s", label, dump)
		}
	}

	// (1) DATA-ONLY database export: the split must run without structure.
	assertLocalRowsOnce("data-only DB export", export("/db/"+liveDB+"/export", url.Values{"data": {"1"}}))

	// (2) TABLE-scope export of the root, structure+data and data-only: the
	// local leaf is absent from the request list, so its rows arrive through
	// the appended data-only leaf entries.
	dump := export("/db/"+liveDB+"/table/mixt/export", url.Values{"structure": {"1"}, "data": {"1"}})
	if !strings.Contains(dump, `CREATE TABLE "public"."mixt"`) {
		t.Errorf("table-scope export must emit the root's DDL:\n%s", dump)
	}
	assertLocalRowsOnce("table-scope structure+data export", dump)
	assertLocalRowsOnce("table-scope data-only export", export("/db/"+liveDB+"/table/mixt/export", url.Values{"data": {"1"}}))

	// (3) STRUCTURE-ONLY database export: no data is read, so the data-facing
	// mixed-tree warning must not surface — but the split itself must still
	// run: DumpDataTables keeps the local leaf in the effective table list,
	// and only the split's DataOnlyTables verdict stops that leaf from getting
	// a standalone CREATE on top of the root's PARTITION OF emission.
	dump = export("/db/"+liveDB+"/export", url.Values{"structure": {"1"}})
	if !strings.Contains(dump, `CREATE TABLE "public"."mixt"`) {
		t.Errorf("structure-only export must emit the root's DDL:\n%s", dump)
	}
	if strings.Contains(dump, farWarning) {
		t.Errorf("structure-only export must not carry the data-facing mixed-tree warning:\n%s", dump)
	}
	if strings.Contains(dump, "INSERT INTO") {
		t.Errorf("structure-only export must carry no data:\n%s", dump)
	}
	if n := strings.Count(dump, `CREATE TABLE "public"."mixt_local"`); n != 1 {
		t.Errorf(`structure-only export must create the local leaf exactly once, got %d (a second CREATE aborts the restore on "relation already exists"):`+"\n%s", n, dump)
	}
	if !strings.Contains(dump, `CREATE TABLE "public"."mixt_local" PARTITION OF`) {
		t.Errorf("the local leaf must be created via the root's PARTITION OF emission, not standalone:\n%s", dump)
	}

	// restoreInto drops and re-creates the live database (with postgres_fdw
	// pre-installed — extensions are not part of a dump) and imports the given
	// dump; the import succeeding IS the decisive duplicate-CREATE assertion.
	restoreInto := func(label, script string) {
		t.Helper()
		liveDropDB(t, admin, env.engine)
		liveCreateDB(t, admin)
		pre, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("%s: preseed connect: %v", label, err)
		}
		if _, err := pre.Exec(ctx, `CREATE EXTENSION postgres_fdw`); err != nil {
			pre.Close()
			t.Fatalf("%s: preseed postgres_fdw: %v", label, err)
		}
		pre.Close()
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {script}})
		if err != nil {
			t.Fatalf("%s: import: %v", label, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "tx-alert-error") {
			t.Fatalf("%s: import failed (%d):\n%.3000s\n--- dump ---\n%.5000s", label, resp.StatusCode, body, script)
		}
	}

	// (4) Full round trip: capture the structure+data dump BEFORE any restore
	// replaces the seeded database, then restore the STRUCTURE-ONLY dump into
	// a fresh database — the assertion the duplicate leaf CREATE used to fail —
	// and finally the full dump: every local row restores exactly once.
	full := export("/db/"+liveDB+"/export", url.Values{"structure": {"1"}, "data": {"1"}})
	restoreInto("structure-only import", dump)
	restoreInto("mixed-tree import", full)
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// Count the local leaf directly — a recursive count on the root would
	// itself query the remote server.
	if got := queryRows(t, check, `SELECT count(*) FROM mixt_local`); strings.TrimSpace(strings.Join(got, "")) != "2" {
		t.Errorf("mixt_local count = %q after round-trip, want 2 (duplicated rows mean the root was scanned too)", got)
	}
}

// liveRestoreCriticalObjects pins three restore-breaking dump defects with one
// seed, all on the structure side:
//
//  1. a foreign PARTITION leaf whose validator-REQUIRED file_fdw option
//     (filename/program) was redacted must ride only as an inert template —
//     not a live CREATE the server would refuse — and EVERY dependent object
//     (its COMMENT) must be suppressed with it, while an emitted foreign leaf's
//     comment uses COMMENT ON FOREIGN TABLE (COMMENT ON TABLE errors with
//     "is not a table");
//  2. a ZERO-argument aggregate's comment must use the aggregate-shaped (*)
//     signature — COMMENT ON AGGREGATE f() is not a production in the
//     aggr_args grammar and dies with a syntax error;
//  3. a domain whose CHECK uses a USER-DEFINED operator must be emitted after
//     the operator — the dependency scans omitted pg_operator, so the domain
//     landed in the Types slot before the operator in Routines.
//
// The import of the whole dump is the decisive assertion: any of the three
// regressions makes the restore fail outright.
func liveRestoreCriticalObjects(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	if _, err := seed.Exec(ctx, `CREATE EXTENSION file_fdw`); err != nil {
		seed.Close()
		t.Skipf("file_fdw extension unavailable: %v", err)
	}
	if _, err := seed.Exec(ctx, `CREATE EXTENSION postgres_fdw`); err != nil {
		seed.Close()
		t.Skipf("postgres_fdw extension unavailable: %v", err)
	}
	for _, stmt := range []string{
		// (1) The partition tree: one local leaf with rows, one foreign leaf
		// whose REQUIRED filename option is redacted (template + suppressed
		// comment), one foreign leaf on a reproducible server whose comment
		// must take the FOREIGN TABLE verb.
		`CREATE SERVER trio_files FOREIGN DATA WRAPPER file_fdw`,
		`CREATE SERVER trio_pg FOREIGN DATA WRAPPER postgres_fdw
			OPTIONS (host 'remote.example', port '5433', dbname 'appdb')`,
		`CREATE TABLE pt (id int, region text) PARTITION BY LIST (region)`,
		`CREATE TABLE pt_local PARTITION OF pt FOR VALUES IN ('l')`,
		`CREATE FOREIGN TABLE pt_far PARTITION OF pt FOR VALUES IN ('f')
			SERVER trio_files OPTIONS (filename '/tmp/secret_trio.csv', format 'csv')`,
		`COMMENT ON FOREIGN TABLE pt_far IS 'far comment'`,
		`CREATE FOREIGN TABLE pt_ok PARTITION OF pt FOR VALUES IN ('k')
			SERVER trio_pg OPTIONS (schema_name 'public', table_name 'pt_ok')`,
		`COMMENT ON FOREIGN TABLE pt_ok IS 'ok comment'`,
		`INSERT INTO pt VALUES (1, 'l'), (2, 'l')`,
		// (2) A zero-argument aggregate with a comment.
		`CREATE FUNCTION zacc(int) RETURNS int LANGUAGE sql AS 'SELECT COALESCE($1, 0) + 1'`,
		`CREATE AGGREGATE countall(*) (SFUNC = zacc, STYPE = int, INITCOND = '0')`,
		`COMMENT ON AGGREGATE countall(*) IS 'counts everything'`,
		// (3) A domain CHECK over a user-defined operator.
		`CREATE FUNCTION oddcheck(int, int) RETURNS boolean LANGUAGE sql AS 'SELECT ($1 % $2) = 1'`,
		`CREATE OPERATOR %% (FUNCTION = oddcheck, LEFTARG = int, RIGHTARG = int)`,
		`CREATE DOMAIN oddint AS int CHECK (VALUE %% 2)`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}

	for _, want := range []string{
		// (1) The suppressed leaf rides only inside the WARNING comment line…
		`-- WARNING: foreign partition public.pt_far is not dumped`,
		// …the emitted foreign leaf's comment takes the FOREIGN TABLE verb…
		`COMMENT ON FOREIGN TABLE "public"."pt_ok" IS 'ok comment'`,
		// (2) …the zero-arg aggregate comment is aggregate-shaped…
		`COMMENT ON AGGREGATE "public"."countall"(*) IS 'counts everything'`,
		// (3) …and both halves of the domain/operator pair are present.
		`CREATE OPERATOR "public".%%`,
		`CREATE DOMAIN "public"."oddint"`,
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing %q:\n%s", want, dump)
		}
	}
	for _, notWant := range []string{
		"secret_trio", // the redacted REQUIRED option's value
		// An executable CREATE for the suppressed leaf (the template lives on
		// a comment line, never at the start of one).
		"\nCREATE FOREIGN TABLE \"public\".\"pt_far\"",
		// Any comment on the suppressed leaf, under either verb.
		`ON TABLE "public"."pt_far"`,
		`ON FOREIGN TABLE "public"."pt_far"`,
		// The emitted foreign leaf must not get the plain-table verb.
		`COMMENT ON TABLE "public"."pt_ok"`,
	} {
		if strings.Contains(dump, notWant) {
			t.Errorf("dump must not contain %q:\n%s", notWant, dump)
		}
	}
	if opIdx, domIdx := strings.Index(dump, `CREATE OPERATOR "public".%%`), strings.Index(dump, `CREATE DOMAIN "public"."oddint"`); opIdx >= 0 && domIdx >= 0 && domIdx < opIdx {
		t.Errorf("the domain must be created AFTER the operator its CHECK uses:\n%s", dump)
	}

	// The restore is the decisive assertion: any of the three regressions
	// fails the import outright.
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	pre, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("preseed connect: %v", err)
	}
	for _, stmt := range []string{`CREATE EXTENSION file_fdw`, `CREATE EXTENSION postgres_fdw`} {
		if _, err := pre.Exec(ctx, stmt); err != nil {
			pre.Close()
			t.Fatalf("preseed %q: %v", stmt, err)
		}
	}
	pre.Close()
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("restore-critical import failed (%d):\n%.3000s\n--- dump ---\n%.9000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// The suppressed leaf stayed a template; the emitted one restored with its
	// comment; the aggregate comment and the domain both survived.
	if got := queryRows(t, check, `SELECT count(*) FROM pg_class WHERE relname = 'pt_far'`); strings.Join(got, "") != "0" {
		t.Errorf("suppressed foreign partition must NOT restore (template only): %v", got)
	}
	if got := queryRows(t, check, `SELECT obj_description('public.pt_ok'::regclass, 'pg_class')`); strings.Join(got, "") != "ok comment" {
		t.Errorf("emitted foreign partition's comment = %v, want 'ok comment'", got)
	}
	if got := queryRows(t, check, `
		SELECT obj_description(oid, 'pg_proc') FROM pg_proc WHERE proname = 'countall'`); strings.Join(got, "") != "counts everything" {
		t.Errorf("zero-arg aggregate comment = %v, want 'counts everything'", got)
	}
	if got := queryRows(t, check, `SELECT (3::oddint)::text`); strings.Join(got, "") != "3" {
		t.Errorf("restored domain rejects a valid value: %v", got)
	}
	if got := queryRows(t, check, `SELECT count(*) FROM pt_local`); strings.Join(got, "") != "2" {
		t.Errorf("pt_local count = %v after round-trip, want 2", got)
	}
}

// liveInheritance pins WS-1 G10: ORDINARY (INHERITS) inheritance must not
// duplicate child rows into the parent. The parent's data SELECT lacked ONLY, so
// it returned every descendant row via inheritance, AND the child was dumped
// separately — so every child row restored twice inside the parent (silent data
// corruption). With FROM ONLY the parent scans only its own rows. The check is on
// `FROM ONLY parent` counts: the parent's PHYSICAL row set must be unchanged by
// the round-trip, not doubled.
func liveInheritance(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE TABLE base (id int PRIMARY KEY, val text)`,
		`CREATE TABLE derived (extra text) INHERITS (base)`,
		// base has 2 OWN rows; derived has 3 (which also appear in base via
		// inheritance, so an un-ONLY parent scan sees 5).
		`INSERT INTO base (id, val) VALUES (1, 'a'), (2, 'b')`,
		`INSERT INTO derived (id, val, extra) VALUES (3, 'c', 'x'), (4, 'd', 'y'), (5, 'e', 'z')`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	// G10 link preservation: derived must dump as CREATE TABLE … INHERITS (base),
	// re-declaring ONLY its local column (extra) — not as a standalone table with
	// the inherited columns copied local.
	if !strings.Contains(dump, "INHERITS (") {
		t.Errorf("dump lost the INHERITS clause (child dumped standalone):\n%s", dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("inheritance import failed (%d):\n%.3000s\n--- dump ---\n%.4000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// base's PHYSICAL rows (FROM ONLY) must be exactly its 2 own rows — NOT 5
	// (2 own + 3 derived duplicated), which is the bug this fixes.
	if got := queryRows(t, check, `SELECT count(*) FROM ONLY base`); strings.TrimSpace(strings.Join(got, "")) != "2" {
		t.Errorf("FROM ONLY base count = %v after round-trip, want 2 (child rows must not duplicate into the parent)", got)
	}
	if got := queryRows(t, check, `SELECT count(*) FROM ONLY derived`); strings.TrimSpace(strings.Join(got, "")) != "3" {
		t.Errorf("derived count = %v after round-trip, want 3", got)
	}
	// The inheritance LINK survived: derived is still a child of base.
	if got := queryRows(t, check, `SELECT count(*) FROM pg_inherits WHERE inhrelid = 'public.derived'::regclass AND inhparent = 'public.base'::regclass`); strings.TrimSpace(strings.Join(got, "")) != "1" {
		t.Errorf("pg_inherits link derived→base = %v after round-trip, want 1 (INHERITS link lost)", got)
	}
	// Column provenance survived: id/val are inherited (attislocal=false), extra is
	// local (attislocal=true) — not every column flipped to local.
	if got := queryRows(t, check, `SELECT attname || ':' || attislocal::text FROM pg_attribute WHERE attrelid = 'public.derived'::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum`); strings.Join(got, ",") != "id:false,val:false,extra:true" {
		t.Errorf("derived column provenance = %q after round-trip, want id:false,val:false,extra:true", strings.Join(got, ","))
	}
}

// liveCrossSchema pins WS-1 G0: a whole-database dump must restore cross-schema
// references in dependency order. The old writer emitted complete per-schema
// sections in ALPHABETICAL order, so an object in an earlier-sorted schema that
// depends on a later-sorted one restored before its dependency existed and the
// import failed. Here `public` (earlier) holds an FK and a view that both
// reference `s2` (later); with the phase-interleaved writeDatabaseDump the import
// succeeds. The test passing IS the proof — the old writer's import 500s here.
func liveCrossSchema(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE SCHEMA s2`,
		// s2 (sorts AFTER public) holds the dependency targets.
		`CREATE TABLE s2.parent (id int PRIMARY KEY, label text)`,
		`INSERT INTO s2.parent VALUES (1, 'root'), (2, 'other')`,
		// public (sorts BEFORE s2) references s2 via a cross-schema FK and a
		// cross-schema view — both unrestorable under the old alphabetical writer.
		`CREATE TABLE public.child (id int PRIMARY KEY, parent_id int REFERENCES s2.parent(id))`,
		`INSERT INTO public.child VALUES (10, 1), (20, 2)`,
		`CREATE VIEW public.parent_names AS SELECT id, label FROM s2.parent`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(dump, "CREATE SCHEMA IF NOT EXISTS \"s2\"") {
		t.Fatalf("export = %d, missing s2 schema:\n%.3000s", resp.StatusCode, dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("cross-schema import failed (%d) — the old alphabetical writer's failure mode:\n%.4000s\n--- dump ---\n%.6000s",
			resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// The cross-schema FK survived.
	if fk := queryRows(t, check, `SELECT conname FROM pg_constraint WHERE conrelid = 'public.child'::regclass AND contype = 'f'`); len(fk) != 1 {
		t.Errorf("cross-schema FK not restored on public.child: %v", fk)
	}
	// The cross-schema view resolves and returns s2's rows.
	if v := queryRows(t, check, `SELECT id, label FROM public.parent_names ORDER BY id`); strings.Join(v, "\n") != "1|root\n2|other" {
		t.Errorf("cross-schema view data = %q, want the two s2.parent rows", strings.Join(v, "\n"))
	}
	if c := queryRows(t, check, `SELECT id, parent_id FROM public.child ORDER BY id`); strings.Join(c, "\n") != "10|1\n20|2" {
		t.Errorf("public.child data = %q after round-trip", strings.Join(c, "\n"))
	}
}

// liveVirtualGenerated pins fix: a PostgreSQL 18+ VIRTUAL generated
// column must round-trip as VIRTUAL, not be silently re-dumped as STORED — which
// would change the column's storage semantics. Gated on server_version_num >=
// 180000 because VIRTUAL generated columns do not exist before PG18 (CI runs
// PG17, so this skips there and only fires against a real PG18 instance).
func liveVirtualGenerated(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	if v := pgServerVersionNum(t, admin); v > 0 && v < 180000 {
		t.Skipf("PostgreSQL server_version_num %d < 180000; VIRTUAL generated columns unsupported", v)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE TABLE vg (id int PRIMARY KEY, base int NOT NULL, doubled int GENERATED ALWAYS AS (base * 2) VIRTUAL)`,
		`INSERT INTO vg (id, base) VALUES (1, 10), (2, 21)`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(dump, "CREATE TABLE") {
		t.Fatalf("export = %d, dump len %d:\n%.2000s", resp.StatusCode, len(dump), dump)
	}
	// The dump must reconstruct the column as VIRTUAL, never STORED.
	if !strings.Contains(dump, "VIRTUAL") {
		t.Errorf("dump dropped the VIRTUAL kind:\n%s", dump)
	}
	if strings.Contains(dump, "STORED") {
		t.Errorf("VIRTUAL column was dumped as STORED:\n%s", dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("import failed (%d):\n%.4000s\n--- dump ---\n%.4000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// attgenerated cast to text: 'v' = VIRTUAL, 's' = STORED.
	kind := queryRows(t, check, `SELECT attgenerated::text FROM pg_attribute WHERE attrelid = 'public.vg'::regclass AND attname = 'doubled'`)
	if len(kind) != 1 || strings.TrimSpace(kind[0]) != "v" {
		t.Errorf("doubled column attgenerated = %v after round-trip, want \"v\" (VIRTUAL)", kind)
	}
	data := queryRows(t, check, `SELECT id, base, doubled FROM public.vg ORDER BY id`)
	if want := "1|10|20\n2|21|42"; strings.Join(data, "\n") != want {
		t.Errorf("data mismatch after round-trip:\ngot  %q\nwant %q", strings.Join(data, "\n"), want)
	}
}

// liveExpressionDefault pins the F-4 fix: a column with an expression DEFAULT
// (uuid()) modified through the structure form (here a comment change) must keep
// its default as an expression, not have it re-quoted into the string literal
// 'uuid()'. MariaDB is the regression case — it has no DEFAULT_GENERATED marker,
// so before the fix DefaultIsExpr was never set and preserveDefaultExpr bailed.
// The MySQL twin guards that the mysqlDefaultKind refactor kept the marker path.
func liveExpressionDefault(t *testing.T, env liveEnv) {
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	if _, err := seed.Exec(ctx, "CREATE TABLE ed (id INT NOT NULL PRIMARY KEY, u VARCHAR(36) NULL DEFAULT (uuid()))"); err != nil {
		seed.Close()
		t.Fatalf("seed: %v", err)
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	// #11: the ?modify=<column> GET round-trip renders the column's CURRENT
	// definition server-side (no JavaScript involved) — the expression default
	// prefilled in custom mode, the column carried as an immutable hidden input.
	resp, err = client.Get(ts.URL + "/db/" + liveDB + "/table/ed/structure?modify=u")
	if err != nil {
		t.Fatalf("GET ?modify=u: %v", err)
	}
	modifyPage, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET ?modify=u = %d", resp.StatusCode)
	}
	for _, want := range []string{`name="column" value="u"`, `name="default_value"`, "uuid()", `value="custom" selected`} {
		if !strings.Contains(string(modifyPage), want) {
			t.Errorf("?modify=u editor missing %q (server-side prefill broken):\n%.3000s", want, modifyPage)
		}
	}

	// Modify the column (only the comment), submitting the default controls the
	// form would prefill from columnDefaultForForm — custom mode, value "uuid()".
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/table/ed/structure", url.Values{
		"csrf_token":    {csrf},
		"action":        {"modify_column"},
		"column":        {"u"},
		"col_type":      {"VARCHAR"},
		"col_length":    {"36"},
		"col_nullable":  {"1"},
		"default_mode":  {"custom"},
		"default_value": {"uuid()"},
		"col_comment":   {"changed"},
	})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("modify_column = %d, want 303:\n%.2000s", resp.StatusCode, body)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	rows := queryRows(t, check, "SHOW CREATE TABLE `"+liveDB+"`.`ed`")
	if len(rows) != 1 {
		t.Fatalf("SHOW CREATE TABLE ed: %d rows", len(rows))
	}
	_, create, _ := strings.Cut(rows[0], "|")
	low := strings.ToLower(create)
	if !strings.Contains(low, "uuid()") {
		t.Errorf("modified column lost its expression default:\n%s", create)
	}
	if strings.Contains(low, "'uuid()'") {
		t.Errorf("expression default was re-quoted into a string literal:\n%s", create)
	}
	if !strings.Contains(create, "changed") {
		t.Errorf("comment change did not apply:\n%s", create)
	}
}

func TestLiveMariaDBSequence(t *testing.T) {
	liveMariaDBSequence(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveMariaDBSequence pins the #4 sequence policy end-to-end: a SEQUENCE
// object stays out of the browsable UI (DB structure, nav children), every
// table-scoped route except export rejects it, and the db-scope dump keeps it
// — CREATE TABLE … SEQUENCE=1 plus the single state row — so a round-trip
// restores nextval() state exactly like mariadb-dump.
func liveMariaDBSequence(t *testing.T, env liveEnv) {
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		"CREATE SEQUENCE seq1 START WITH 5 INCREMENT BY 2",
		"SELECT NEXTVAL(seq1)", // advance the state so the dump carries non-initial values
		"CREATE TABLE t1 (id INT NOT NULL PRIMARY KEY, v VARCHAR(10))",
		"INSERT INTO t1 VALUES (1, 'x')",
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	stateBefore := queryRows(t, seed, "SELECT next_not_cached_value FROM "+liveDB+".seq1")
	seed.Close()
	if len(stateBefore) != 1 {
		t.Fatalf("sequence state query returned %v", stateBefore)
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	// The browsable UI must not list the sequence: neither the DB structure
	// page nor the nav children fragment.
	for _, path := range []string{"/db/" + liveDB, "/nav/children?db=" + liveDB} {
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		if strings.Contains(string(page), "seq1") {
			t.Errorf("%s lists the sequence seq1 as a table:\n%.2000s", path, page)
		}
		if path == "/db/"+liveDB && !strings.Contains(string(page), "t1") {
			t.Errorf("%s is missing the ordinary table t1", path)
		}
	}

	// Every table-scoped route except export rejects the sequence.
	for _, tab := range []string{"", "/structure", "/sql", "/search", "/insert", "/import", "/operations", "/triggers", "/privileges"} {
		resp, err := client.Get(ts.URL + "/db/" + liveDB + "/table/seq1" + tab)
		if err != nil {
			t.Fatalf("GET seq1%s: %v", tab, err)
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(page), "sequence") {
			t.Errorf("GET seq1%s = %d, want 400 with a sequence rejection:\n%.500s", tab, resp.StatusCode, page)
		}
	}

	// Table-scope export of the sequence stays allowed and is restore-valid.
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/table/seq1/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("table export: %v", err)
	}
	tblDumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	tblDump := string(tblDumpBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(tblDump, "SEQUENCE=1") {
		t.Errorf("table-scope sequence export = %d, want 200 with SEQUENCE=1:\n%.2000s", resp.StatusCode, tblDump)
	}

	// DB-scope dump keeps the sequence and restores its state.
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(dump, "SEQUENCE=1") {
		t.Fatalf("db export = %d, want 200 with the sequence kept (SEQUENCE=1):\n%.4000s", resp.StatusCode, dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("import failed (%d):\n%.4000s\n--- dump ---\n%.4000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	stateAfter := queryRows(t, check, "SELECT next_not_cached_value FROM "+liveDB+".seq1")
	if len(stateAfter) != 1 || stateAfter[0] != stateBefore[0] {
		t.Errorf("sequence state after round-trip = %v, want %v", stateAfter, stateBefore)
	}
	if next := queryRows(t, check, "SELECT NEXTVAL("+liveDB+".seq1)"); len(next) != 1 {
		t.Errorf("NEXTVAL after restore returned %v", next)
	}
}

func TestLivePostgresRangeRoundTrip(t *testing.T) {
	livePostgresRangeRoundTrip(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// livePostgresRangeRoundTrip pins the #2 fix: range-typed values ([1,11)) must
// export as quoted literals — the old digit-suffix numeric classification
// emitted them bare, producing an unrestorable INSERT.
func livePostgresRangeRoundTrip(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	// int4multirange is PG14+; on the 13 floor drop the multirange column and its
	// assertions, keeping int4range/int8range coverage.
	pg14 := pgServerVersionNum(t, admin) >= 140000
	createRanges := `CREATE TABLE ranges (id int PRIMARY KEY, r int4range, r8 int8range, m int4multirange)`
	insertRanges := `INSERT INTO ranges VALUES (1, '[1,11)', '[100,200)', '{[1,3),[5,9)}'), (2, NULL, NULL, NULL)`
	selectRanges := `SELECT id, r::text, r8::text, m::text FROM public.ranges ORDER BY id`
	wantRanges := "1|[1,11)|[100,200)|{[1,3),[5,9)}\n2|<null>|<null>|<null>"
	if !pg14 {
		createRanges = `CREATE TABLE ranges (id int PRIMARY KEY, r int4range, r8 int8range)`
		insertRanges = `INSERT INTO ranges VALUES (1, '[1,11)', '[100,200)'), (2, NULL, NULL)`
		selectRanges = `SELECT id, r::text, r8::text FROM public.ranges ORDER BY id`
		wantRanges = "1|[1,11)|[100,200)\n2|<null>|<null>"
	}
	for _, stmt := range []string{createRanges, insertRanges} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(dump, "CREATE TABLE") {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	// The range values must be quoted string literals, never bare numerals.
	if !strings.Contains(dump, "'[1,11)'") {
		t.Errorf("range value not exported as a quoted literal:\n%s", dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("import failed (%d):\n%.4000s\n--- dump ---\n%.4000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	rows := queryRows(t, check, selectRanges)
	if got := strings.Join(rows, "\n"); got != wantRanges {
		t.Errorf("range data mismatch after round-trip:\ngot  %q\nwant %q", got, wantRanges)
	}
}

func TestLivePostgresQBELikeNonText(t *testing.T) {
	liveQBELikeNonText(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveQBELikeNonText pins fix: a QBE LIKE against a non-text PostgreSQL
// column (here uuid) must route through the dialect SearchExpr (which appends
// ::text) so it matches rows, exactly as Search/DBSearch do — not error with
// "operator does not exist: uuid ~~ unknown".
func liveQBELikeNonText(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE TABLE u (id uuid PRIMARY KEY, label text)`,
		`INSERT INTO u VALUES ('11111111-1111-1111-1111-111111111111', 'alpha')`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	// QBE: LIKE '%1111%' on the uuid column — must match via the ::text cast.
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/qbe", url.Values{
		"csrf_token": {csrf},
		"table":      {"u"},
		"show_id":    {"1"},
		"show_label": {"1"},
		"op_id":      {"LIKE"},
		"val_id":     {"1111"},
	})
	if err != nil {
		t.Fatalf("qbe post: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(page)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("qbe = %d:\n%.2000s", resp.StatusCode, body)
	}
	if strings.Contains(body, "operator does not exist") || strings.Contains(body, "tx-alert-error") {
		t.Errorf("QBE LIKE on uuid column errored (regression):\n%.2000s", body)
	}
	if !strings.Contains(body, "alpha") {
		t.Errorf("QBE LIKE on uuid column did not return the matching row:\n%.2000s", body)
	}
}

// liveRoundTrip drives the full cycle through the real HTTP handlers: seed an
// engine-specific schema exercising the dump features (FK cycle + self-ref,
// counter-ahead auto-increment/identity, generated column, dependent views,
// trigger with statement bodies, routine, secondary/unique indexes, binary
// data; PG adds matview, partitioned table with named CHECK, timestamptz and
// the constraint shapes DEFERRABLE/NOT VALID/MATCH FULL/column-subset SET
// NULL) → export → drop the database → re-import the dump → compare schema
// and data fingerprints.
func liveRoundTrip(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
	}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	pgVer := 0
	if env.engine == "postgres" {
		pgVer = pgServerVersionNum(t, admin)
	}
	for _, stmt := range liveSeedStatements(env.engine, pgVer) {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	before := liveSnapshot(t, d, env.engine, dbParams)
	// Guard against a vacuous pass: an empty before-snapshot would "equal" a
	// failed restore. The seeded emp table must show its rows and structure.
	if !strings.Contains(before["data:emp"], "ann") || before["tables"] == "" {
		t.Fatalf("seed snapshot looks empty: tables=%q data:emp=%q", before["tables"], before["data:emp"])
	}

	// The HTTP application, logging in through a predefined server for the
	// live engine with the env-supplied credentials.
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"},
		"structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK || !strings.Contains(dump, "CREATE TABLE") {
		t.Fatalf("export = %d, dump len %d:\n%.2000s", resp.StatusCode, len(dump), dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("import failed (%d). Page:\n%.4000s\n--- dump was ---\n%.6000s",
			resp.StatusCode, importBody, dump)
	}

	after := liveSnapshot(t, d, env.engine, dbParams)
	compareSnapshots(t, before, after, dump)
}

// requireIsolatedServerScope fails fast when the target server holds ambient
// (non-system) databases beyond the engine's stock baseline and this suite's
// tablex_rt* scratch names. Server-scope dump/import tests sweep EVERY
// non-system database — running them against a shared instance would export,
// and on re-import write into, unrelated user databases. PostgreSQL's stock
// "postgres" database is a normal non-system entry on every standard cluster,
// so a bare "no non-system databases" rule would trip everywhere; it is
// baseline-allowed instead.
func requireIsolatedServerScope(t *testing.T, admin *driver.Connection, engine string) {
	t.Helper()
	baseline := map[string]bool{}
	if engine == "postgres" {
		baseline["postgres"] = true
	}
	dbs, err := admin.ListDatabaseNames(context.Background())
	if err != nil {
		t.Fatalf("isolation precondition: list databases: %v", err)
	}
	var ambient []string
	for _, db := range dbs {
		if db.IsSystem || baseline[db.Name] || strings.HasPrefix(db.Name, liveDB) {
			continue
		}
		ambient = append(ambient, db.Name)
	}
	if len(ambient) > 0 {
		t.Fatalf("server-scope test requires an isolated instance: ambient non-system databases %v would be swept into the server dump/import — drop them or point TABLEX_TEST_%s_* at a dedicated server", ambient, strings.ToUpper(engine))
	}
}

func liveDropDB(t *testing.T, admin *driver.Connection, engine string) {
	t.Helper()
	stmt := "DROP DATABASE IF EXISTS " + liveDB
	if engine == "postgres" {
		// FORCE (PG 13+) terminates lingering session-pool connections.
		stmt = "DROP DATABASE IF EXISTS " + liveDB + " WITH (FORCE)"
	}
	if _, err := admin.Exec(context.Background(), stmt); err != nil {
		t.Fatalf("drop %s: %v", liveDB, err)
	}
}

func liveCreateDB(t *testing.T, admin *driver.Connection) {
	t.Helper()
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+liveDB); err != nil {
		t.Fatalf("create %s: %v", liveDB, err)
	}
}

// pgServerVersionNum returns PostgreSQL's server_version_num (e.g. 180003 for
// 18.3, 130000 for 13.0), so version-dependent fixtures can gate themselves; 0
// if it cannot be read (non-PostgreSQL, or query failure). CI runs the live
// suite against both the 13 floor and 18, so newer-only syntax must gate.
func pgServerVersionNum(t *testing.T, conn *driver.Connection) int {
	t.Helper()
	rows := queryRows(t, conn, "SELECT current_setting('server_version_num')")
	if len(rows) != 1 {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(rows[0]))
	if err != nil {
		return 0
	}
	return n
}

// liveSeedStatements returns the engine-specific schema + data, one statement
// per entry (Exec sends single statements; trigger/procedure bodies with
// semicolons are fine at the protocol level without DELIMITER games). pgVersion
// is PostgreSQL's server_version_num (0 for other engines) so the seed can gate
// features newer than the PG 13 CI floor.
func liveSeedStatements(engine string, pgVersion int) []string {
	if engine == "postgres" {
		// Column-subset SET NULL on an FK and UNLOGGED sequences are both PG 15+.
		// Below 15, degrade to plain SET NULL / a logged sequence (the dynamic
		// snapshot fingerprints follow, so the round-trip still matches).
		fkESetNull := "ON DELETE SET NULL (y)"
		ulseqPersistence := "UNLOGGED "
		if pgVersion < 150000 {
			fkESetNull = "ON DELETE SET NULL"
			ulseqPersistence = ""
		}
		return []string{
			// FK cycle (deferrable) + self-reference + NOT VALID + column-subset
			// SET NULL (PG 15+).
			`CREATE TABLE a (id int PRIMARY KEY, b_id int)`,
			`CREATE TABLE b (id int PRIMARY KEY, a_id int, parent_id int)`,
			`ALTER TABLE a ADD CONSTRAINT fk_a_b FOREIGN KEY (b_id) REFERENCES b(id) DEFERRABLE INITIALLY DEFERRED`,
			`ALTER TABLE b ADD CONSTRAINT fk_b_a FOREIGN KEY (a_id) REFERENCES a(id) NOT VALID`,
			`ALTER TABLE b ADD CONSTRAINT fk_b_self FOREIGN KEY (parent_id) REFERENCES b(id)`,
			`INSERT INTO b (id, a_id, parent_id) VALUES (1, NULL, NULL), (2, NULL, 1)`,
			`INSERT INTO a (id, b_id) VALUES (1, 1), (2, 2)`,
			`UPDATE b SET a_id = 1 WHERE id = 1`,
			// MATCH FULL and column-subset SET NULL (PG 15+) on composite keys.
			`CREATE TABLE c (x int, y int, PRIMARY KEY (x, y))`,
			`CREATE TABLE d (x int, y int, CONSTRAINT fk_d FOREIGN KEY (x, y) REFERENCES c (x, y) MATCH FULL)`,
			`CREATE TABLE e (x int, y int, CONSTRAINT fk_e FOREIGN KEY (x, y) REFERENCES c (x, y) ` + fkESetNull + `)`,
			`INSERT INTO c VALUES (1, 2)`,
			`INSERT INTO d VALUES (1, 2)`,
			`INSERT INTO e VALUES (1, 2)`,
			// F-2: table-level UNIQUE (DEFERRABLE) + EXCLUDE constraints. They must
			// restore as constraints, not as plain/unique indexes (today they lose
			// their shape — UNIQUE shows as CREATE UNIQUE INDEX, EXCLUDE as a bogus
			// non-unique index). EXCLUDE USING btree (… WITH =) needs no extension.
			`CREATE TABLE cons (
				id int PRIMARY KEY,
				code int,
				x int,
				CONSTRAINT uq_cons_code UNIQUE (code) DEFERRABLE INITIALLY DEFERRED,
				CONSTRAINT ex_x EXCLUDE USING btree (x WITH =))`,
			`INSERT INTO cons (id, code, x) VALUES (1, 100, 10), (2, 200, 20)`,
			// Identity (counter ahead of data), generated column, bytea,
			// timestamptz, unique + secondary indexes.
			`CREATE TABLE emp (
				id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
				name text NOT NULL,
				salary numeric(10,2),
				tag text GENERATED ALWAYS AS (name || '-x') STORED,
				bin bytea,
				created timestamptz)`,
			`INSERT INTO emp (name, salary, bin, created) VALUES
				('ann', 10.50, '\x00ff10', '2024-03-01 12:30:45+05:30'),
				('bob', NULL, NULL, NULL)`,
			`SELECT setval(pg_get_serial_sequence('emp','id'), 50, true)`,
			// WS-1 G12: a RENAMED identity sequence must restore under its custom
			// name (the post-data setval/comment target it), not the default
			// emp_id_seq — the SEQUENCE NAME identity option preserves it.
			`ALTER SEQUENCE emp_id_seq RENAME TO emp_id_custom`,
			`CREATE UNIQUE INDEX uq_emp_name ON emp (name)`,
			`CREATE INDEX idx_emp_salary ON emp (salary)`,
			// F-1 regression: a serial column dumps DEFAULT nextval(...) but needs
			// an explicit CREATE SEQUENCE to restore into an empty database. Rows
			// advance the owned sequence past its start.
			`CREATE TABLE seqtest (id serial PRIMARY KEY, label text)`,
			`INSERT INTO seqtest (label) VALUES ('one'), ('two'), ('three')`,
			// Standalone sequence (no owning column) with non-default options,
			// advanced past START — only a db-scope dump recreates it.
			`CREATE SEQUENCE counter AS integer INCREMENT BY 10 MINVALUE 100 MAXVALUE 100000 START WITH 1000 CACHE 5 CYCLE`,
			`SELECT nextval('counter')`,
			`SELECT nextval('counter')`,
			// WS-1 G3: a sequence comment (lost today). WS-1 G13: an UNLOGGED
			// standalone sequence must restore UNLOGGED (relpersistence 'u') on PG15+;
			// below 15 (no UNLOGGED sequences) it degrades to a logged sequence.
			`COMMENT ON SEQUENCE counter IS 'global counter'`,
			`CREATE ` + ulseqPersistence + `SEQUENCE ulseq START WITH 5 INCREMENT BY 2`,
			`SELECT nextval('ulseq')`,
			// Identity with explicit sequence options, BY DEFAULT branch (the
			// options must ride inside the GENERATED … AS IDENTITY clause).
			`CREATE TABLE idtest (id int GENERATED BY DEFAULT AS IDENTITY (START WITH 50 INCREMENT BY 5) PRIMARY KEY, note text)`,
			`INSERT INTO idtest (note) VALUES ('x'), ('y')`,
			// Dependent views + matview.
			`CREATE VIEW v1 AS SELECT id, name FROM emp`,
			`CREATE VIEW v2 AS SELECT name FROM v1`,
			`CREATE MATERIALIZED VIEW mv1 AS SELECT count(*) AS n FROM emp`,
			// Regression: a matview over another matview must REFRESH in
			// dependency order on restore (source before dependent). Named so the
			// dependent (agg) sorts alphabetically *before* its source (ztotals):
			// an alphabetical REFRESH would run agg first and fail on the still-empty
			// ztotals.
			`CREATE MATERIALIZED VIEW ztotals AS SELECT count(*) AS total FROM emp`,
			`CREATE MATERIALIZED VIEW agg AS SELECT total FROM ztotals`,
			// Routine + trigger with a multi-statement body.
			`CREATE FUNCTION f1() RETURNS trigger AS $tx$
			BEGIN
				NEW.salary := COALESCE(NEW.salary, 0);
				NEW.name := trim(NEW.name);
				RETURN NEW;
			END
			$tx$ LANGUAGE plpgsql`,
			`CREATE TRIGGER trg BEFORE INSERT ON emp FOR EACH ROW EXECUTE FUNCTION f1()`,
			`COMMENT ON TRIGGER trg ON emp IS 'normalize row on insert'`, // WS-1 G3
			// Partitioned table with a named CHECK — multi-level (Theme A): the
			// high partition is itself partitioned, so its own PARTITION BY and
			// its grandchildren must survive the round-trip.
			`CREATE TABLE measurements (
				city int NOT NULL,
				reading numeric,
				CONSTRAINT chk_pos CHECK (reading >= 0)
			) PARTITION BY RANGE (city)`,
			`CREATE TABLE measurements_low PARTITION OF measurements FOR VALUES FROM (0) TO (100)`,
			`CREATE TABLE measurements_high PARTITION OF measurements FOR VALUES FROM (100) TO (1000) PARTITION BY LIST (city)`,
			`CREATE TABLE measurements_high_500 PARTITION OF measurements_high FOR VALUES IN (500)`,
			`CREATE TABLE measurements_high_rest PARTITION OF measurements_high DEFAULT`,
			`INSERT INTO measurements VALUES (5, 1.5), (500, 2.5), (900, 3.5)`,
			// WS-1 G1: user-defined types — an enum (commented), a NOT NULL + CHECK
			// domain and a composite, each used as a column so the CREATE TYPE/DOMAIN
			// must restore BEFORE the table. Without the type pass the restore fails
			// at CREATE TABLE person.
			`CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy')`,
			`COMMENT ON TYPE mood IS 'how someone feels'`,
			`CREATE DOMAIN posint AS integer NOT NULL CHECK (VALUE > 0)`,
			`CREATE TYPE fullname AS (first text, last text)`,
			`CREATE TABLE person (id int PRIMARY KEY, feeling mood, age posint, name fullname)`,
			`INSERT INTO person (id, feeling, age, name) VALUES
				(1, 'happy', 30, ROW('ann','smith')), (2, 'ok', 5, ROW('bob','lee'))`,
			// WS-1 G16: an unpopulated (WITH NO DATA) matview must restore
			// unpopulated — no REFRESH is emitted, or the restore would wrongly
			// populate it and a dependent's refresh could fail.
			`CREATE MATERIALIZED VIEW mv_empty AS SELECT id FROM emp WITH NO DATA`,
			// WS-1 G3: object + column comments on views/matviews (lost today).
			`COMMENT ON VIEW v1 IS 'employee names'`,
			`COMMENT ON COLUMN v1.name IS 'the display name'`,
			`COMMENT ON MATERIALIZED VIEW mv1 IS 'employee count'`,
			// WS-1 G14: row-level security. ENABLE + FORCE state, a permissive and a
			// restrictive policy (one commented, TO PUBLIC) — all lost from the dump
			// today. The whole RLS surface must round-trip.
			`CREATE TABLE secure (id int PRIMARY KEY, owner text, val int)`,
			`INSERT INTO secure VALUES (1, 'ann', 10), (2, 'bob', 20)`,
			`ALTER TABLE secure ENABLE ROW LEVEL SECURITY`,
			`ALTER TABLE secure FORCE ROW LEVEL SECURITY`,
			`CREATE POLICY p_sel ON secure FOR SELECT USING (true)`,
			`CREATE POLICY p_owner ON secure AS RESTRICTIVE FOR ALL TO PUBLIC USING (owner = current_user)`,
			`COMMENT ON POLICY p_sel ON secure IS 'allow all reads'`,
			// WS-1 G15(a): non-default REPLICA IDENTITY — FULL and USING INDEX (lost
			// today). uq_emp_name is UNIQUE on the NOT NULL name column, so it is a
			// valid identity index.
			`ALTER TABLE cons REPLICA IDENTITY FULL`,
			`ALTER TABLE emp REPLICA IDENTITY USING INDEX uq_emp_name`,
			// WS-1 G3: schema / index / constraint comments (all lost today).
			`COMMENT ON SCHEMA public IS 'the application schema'`,
			`COMMENT ON INDEX idx_emp_salary IS 'salary lookup'`,
			`COMMENT ON CONSTRAINT fk_a_b ON a IS 'a references b'`,
			// WS-2 G3: comments on INLINE constraints (UNIQUE + EXCLUDE) — lost today
			// because inlineConstraints (shared with the display path) carries no
			// comment. FK comments already round-tripped via the PostData pass.
			`COMMENT ON CONSTRAINT uq_cons_code ON cons IS 'unique product code'`,
			`COMMENT ON CONSTRAINT ex_x ON cons IS 'no overlapping x'`,
		}
	}
	// MySQL / MariaDB. Seeding runs on a pool, so session SETs (like
	// FOREIGN_KEY_CHECKS) cannot be relied on — the cyclic rows are inserted
	// in an order that satisfies the FKs and closed with an UPDATE instead.
	return []string{
		`CREATE TABLE a (id INT NOT NULL PRIMARY KEY, b_id INT NULL)`,
		`CREATE TABLE b (id INT NOT NULL PRIMARY KEY, a_id INT NULL, parent_id INT NULL)`,
		`ALTER TABLE a ADD CONSTRAINT fk_a_b FOREIGN KEY (b_id) REFERENCES b (id)`,
		`ALTER TABLE b ADD CONSTRAINT fk_b_a FOREIGN KEY (a_id) REFERENCES a (id)`,
		`ALTER TABLE b ADD CONSTRAINT fk_b_self FOREIGN KEY (parent_id) REFERENCES b (id)`,
		`INSERT INTO b (id, a_id, parent_id) VALUES (1, NULL, NULL), (2, NULL, 1)`,
		`INSERT INTO a (id, b_id) VALUES (1, 1), (2, 2)`,
		`UPDATE b SET a_id = 1 WHERE id = 1`,
		`CREATE TABLE emp (
			id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(50) NOT NULL,
			salary DECIMAL(10,2) NULL,
			tag VARCHAR(64) GENERATED ALWAYS AS (CONCAT(name, '-x')) STORED,
			bin BLOB,
			UNIQUE KEY uq_name (name),
			KEY idx_salary (salary))`,
		`INSERT INTO emp (name, salary, bin) VALUES ('ann', 10.50, X'00FF10'), ('bob', NULL, NULL)`,
		`ALTER TABLE emp AUTO_INCREMENT = 50`,
		`CREATE VIEW v1 AS SELECT id, name FROM emp`,
		`CREATE VIEW v2 AS SELECT name FROM v1`,
		`CREATE TRIGGER trg BEFORE INSERT ON emp FOR EACH ROW BEGIN SET NEW.salary = IFNULL(NEW.salary, 0); SET NEW.name = TRIM(NEW.name); END`,
		`CREATE PROCEDURE p1(IN x INT) BEGIN SELECT x; SELECT x + 1; END`,
	}
}

// liveSnapshot fingerprints the database's schema and data through a fresh
// direct connection (never the HTTP session's pools, which teardown kills).
func liveSnapshot(t *testing.T, d driver.Dialect, engine string, params driver.ConnParams) map[string]string {
	t.Helper()
	ctx := context.Background()
	conn, err := driver.Open(ctx, d, params)
	if err != nil {
		t.Fatalf("snapshot connect: %v", err)
	}
	defer conn.Close()
	if engine == "postgres" {
		return snapshotPostgres(t, conn)
	}
	return snapshotMySQL(t, conn)
}

func normalizeSQL(s string) string { return strings.Join(strings.Fields(s), " ") }

// queryRows runs a query and renders each row as a |-joined line (binary
// cells as hex), sorted for order-independence where the caller wants it.
func queryRows(t *testing.T, conn *driver.Connection, q string) []string {
	t.Helper()
	var rows []string
	err := conn.Stream(context.Background(), q, func(_ []driver.ResultColumn, row []driver.Value) error {
		parts := make([]string, len(row))
		for i, v := range row {
			switch {
			case v.Null:
				parts[i] = "<null>"
			case v.Binary:
				parts[i] = fmt.Sprintf("0x%x", v.Bytes)
			default:
				parts[i] = v.Str
			}
		}
		rows = append(rows, strings.Join(parts, "|"))
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot query %q: %v", q, err)
	}
	return rows
}

func snapshotMySQL(t *testing.T, conn *driver.Connection) map[string]string {
	t.Helper()
	out := map[string]string{}
	var tables, views []string
	for _, line := range queryRows(t, conn, `
		SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = '`+liveDB+`' ORDER BY TABLE_NAME`) {
		name, typ, _ := strings.Cut(line, "|")
		if strings.Contains(typ, "VIEW") {
			views = append(views, name)
		} else {
			tables = append(tables, name)
		}
	}
	out["tables"] = strings.Join(tables, ",")
	out["views"] = strings.Join(views, ",")
	for _, tb := range tables {
		rows := queryRows(t, conn, "SHOW CREATE TABLE `"+liveDB+"`.`"+tb+"`")
		if len(rows) != 1 {
			t.Fatalf("SHOW CREATE TABLE %s: %d rows", tb, len(rows))
		}
		_, create, _ := strings.Cut(rows[0], "|")
		out["create:"+tb] = normalizeSQL(create)
		out["data:"+tb] = strings.Join(queryRows(t, conn, "SELECT * FROM `"+liveDB+"`.`"+tb+"` ORDER BY 1"), "\n")
	}
	// Every stored-object fingerprint carries its DEFINER. The definer is
	// part of the object's SECURITY identity — a view or routine restored under
	// the importing account silently executes with different privileges — so a
	// round-trip that drops it must fail here rather than look clean.
	for _, line := range queryRows(t, conn, `
		SELECT TABLE_NAME, DEFINER, VIEW_DEFINITION FROM information_schema.VIEWS
		WHERE TABLE_SCHEMA = '`+liveDB+`' ORDER BY TABLE_NAME`) {
		name, rest, _ := strings.Cut(line, "|")
		out["view:"+name] = normalizeDefiner(normalizeSQL(rest))
	}
	for _, line := range queryRows(t, conn, `
		SELECT TRIGGER_NAME, DEFINER, ACTION_TIMING, EVENT_MANIPULATION, EVENT_OBJECT_TABLE, ACTION_STATEMENT
		FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = '`+liveDB+`' ORDER BY TRIGGER_NAME`) {
		name, rest, _ := strings.Cut(line, "|")
		out["trigger:"+name] = normalizeDefiner(normalizeSQL(rest))
	}
	for _, line := range queryRows(t, conn, `
		SELECT ROUTINE_NAME, DEFINER, ROUTINE_TYPE, ROUTINE_DEFINITION
		FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = '`+liveDB+`' ORDER BY ROUTINE_NAME`) {
		name, rest, _ := strings.Cut(line, "|")
		out["routine:"+name] = normalizeDefiner(normalizeSQL(rest))
	}
	for _, line := range queryRows(t, conn, `
		SELECT EVENT_NAME, DEFINER, EVENT_DEFINITION, ON_COMPLETION, STATUS
		FROM information_schema.EVENTS WHERE EVENT_SCHEMA = '`+liveDB+`' ORDER BY EVENT_NAME`) {
		name, rest, _ := strings.Cut(line, "|")
		out["event:"+name] = normalizeDefiner(normalizeSQL(rest))
	}
	return out
}

// normalizeDefiner folds the two spellings a DEFINER can take across MySQL and
// MariaDB — `user`@`host` in SHOW CREATE output versus the bare user@host of
// information_schema — so a fingerprint compares the IDENTITY, not the quoting.
func normalizeDefiner(s string) string { return strings.ReplaceAll(s, "`", "") }

func snapshotPostgres(t *testing.T, conn *driver.Connection) map[string]string {
	t.Helper()
	out := map[string]string{}
	out["columns"] = strings.Join(queryRows(t, conn, `
		SELECT table_name, column_name, data_type, is_nullable,
		       COALESCE(column_default, ''), is_identity, COALESCE(identity_generation, ''),
		       is_generated
		FROM information_schema.columns WHERE table_schema = 'public'
		ORDER BY table_name, ordinal_position`), "\n")
	// FK + CHECK + UNIQUE + EXCLUDE constraint shapes compare via
	// pg_get_constraintdef verbatim (DEFERRABLE, NOT VALID, MATCH FULL,
	// column-subset SET NULL, NULLS NOT DISTINCT and EXCLUDE … USING all show up
	// here). A plain unique INDEX that is not a constraint is covered by the
	// index definitions below instead.
	// contype 'n': PG18+ named table NOT NULL constraints — their names
	// and definitions (incl. NO INHERIT / NOT VALID) must round-trip too. On
	// PG13–17 no such rows exist, so the fingerprint is unchanged there.
	out["constraints"] = strings.Join(queryRows(t, conn, `
		SELECT rel.relname, con.conname, pg_get_constraintdef(con.oid, true)
		FROM pg_constraint con
		JOIN pg_class rel ON rel.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = rel.relnamespace
		WHERE n.nspname = 'public' AND con.contype IN ('f','c','u','x','n')
		ORDER BY rel.relname, con.conname`), "\n")
	out["indexes"] = strings.Join(queryRows(t, conn, `
		SELECT tablename, indexname, indexdef FROM pg_indexes
		WHERE schemaname = 'public' ORDER BY tablename, indexname`), "\n")
	// Partition tree shape: every parent→child edge with the child's bound and
	// (for a sub-partitioned child) its own partition key. A multi-level tree
	// must restore with its exact structure — a grandchild reattached to the
	// wrong parent, a lost bound, or a child flattened to a plain table all
	// change this fingerprint.
	out["partitions"] = strings.Join(queryRows(t, conn, `
		SELECT p.relname, c.relname, pg_get_expr(c.relpartbound, c.oid, true),
		       COALESCE(pg_get_partkeydef(c.oid), '')
		FROM pg_inherits i
		JOIN pg_class c ON c.oid = i.inhrelid
		JOIN pg_class p ON p.oid = i.inhparent
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relispartition
		ORDER BY p.relname, c.relname`), "\n")
	// User-defined types (WS-1 G1): enum labels in sort order, domain base/notnull/
	// default and constraints, composite attributes, and type comments. A lost
	// CREATE TYPE/DOMAIN, a dropped enum label or a missing domain CHECK all change
	// these fingerprints. The composite query filters relkind='c' so table row
	// types (relkind 'r'/'p') are excluded.
	out["enums"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname, e.enumlabel
		FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' ORDER BY t.typname, e.enumsortorder`), "\n")
	out["domains"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname, pg_catalog.format_type(t.typbasetype, t.typtypmod),
		       t.typnotnull, COALESCE(pg_get_expr(t.typdefaultbin, 0), '')
		FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' AND t.typtype = 'd' ORDER BY t.typname`), "\n")
	out["domain-constraints"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname, con.conname, pg_get_constraintdef(con.oid)
		FROM pg_constraint con JOIN pg_type t ON t.oid = con.contypid
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' ORDER BY t.typname, con.conname`), "\n")
	out["composites"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)
		FROM pg_type t
		JOIN pg_class c ON c.oid = t.typrelid AND c.relkind = 'c'
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' AND t.typtype = 'c' ORDER BY t.typname, a.attnum`), "\n")
	out["type-comments"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname, obj_description(t.oid, 'pg_type')
		FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' AND t.typtype IN ('e','d','c')
		  AND obj_description(t.oid, 'pg_type') IS NOT NULL ORDER BY t.typname`), "\n")
	out["views"] = strings.Join(queryRows(t, conn, `
		SELECT table_name, view_definition FROM information_schema.views
		WHERE table_schema = 'public' ORDER BY table_name`), "\n")
	out["matviews"] = strings.Join(queryRows(t, conn, `
		SELECT matviewname, definition FROM pg_matviews
		WHERE schemaname = 'public' ORDER BY matviewname`), "\n")
	// WS-1 G16: populated state per matview. An unpopulated (WITH NO DATA) matview
	// must restore unpopulated (ispopulated=false); a wrongly-emitted REFRESH would
	// flip this to true.
	out["matview-populated"] = strings.Join(queryRows(t, conn, `
		SELECT matviewname, ispopulated FROM pg_matviews
		WHERE schemaname = 'public' ORDER BY matviewname`), "\n")
	// WS-1 G3: object + column comments on views/matviews.
	out["view-comments"] = strings.Join(queryRows(t, conn, `
		SELECT c.relname, c.relkind::text, obj_description(c.oid, 'pg_class')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('v','m')
		  AND obj_description(c.oid, 'pg_class') IS NOT NULL ORDER BY c.relname`), "\n")
	out["view-column-comments"] = strings.Join(queryRows(t, conn, `
		SELECT c.relname, a.attname, col_description(c.oid, a.attnum)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		WHERE n.nspname = 'public' AND c.relkind IN ('v','m')
		  AND col_description(c.oid, a.attnum) IS NOT NULL
		ORDER BY c.relname, a.attnum`), "\n")
	// Confirm the nested matview restored *populated*. An out-of-order REFRESH
	// hard-errors a full restore, but in a data-only dump it would silently leave
	// agg empty — this fingerprint catches both.
	out["matview-data:agg"] = strings.Join(queryRows(t, conn, `SELECT total FROM agg ORDER BY 1`), "\n")
	out["triggers"] = strings.Join(queryRows(t, conn, `
		SELECT t.tgname, pg_get_triggerdef(t.oid, true)
		FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND NOT t.tgisinternal
		ORDER BY t.tgname`), "\n")
	// WS-1 G14: RLS state + policies + policy comments (whole surface lost today).
	out["rls-state"] = strings.Join(queryRows(t, conn, `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r','p')
		  AND (c.relrowsecurity OR c.relforcerowsecurity) ORDER BY c.relname`), "\n")
	out["policies"] = strings.Join(queryRows(t, conn, `
		SELECT c.relname, pol.polname, pol.polcmd, pol.polpermissive,
		       COALESCE(pg_get_expr(pol.polqual, pol.polrelid), ''),
		       COALESCE(pg_get_expr(pol.polwithcheck, pol.polrelid), '')
		FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' ORDER BY c.relname, pol.polname`), "\n")
	out["policy-comments"] = strings.Join(queryRows(t, conn, `
		SELECT pol.polname, obj_description(pol.oid, 'pg_policy')
		FROM pg_policy pol JOIN pg_class c ON c.oid = pol.polrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND obj_description(pol.oid, 'pg_policy') IS NOT NULL
		ORDER BY pol.polname`), "\n")
	// WS-1 G15(a): non-default replica identity (relreplident + the USING INDEX
	// name) must round-trip; the default 'd' identity is not fingerprinted (every
	// table has it).
	out["replica-identity"] = strings.Join(queryRows(t, conn, `
		SELECT c.relname, c.relreplident, COALESCE(i.relname, '')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_index ix ON ix.indrelid = c.oid AND ix.indisreplident
		LEFT JOIN pg_class i ON i.oid = ix.indexrelid
		WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND c.relreplident <> 'd'
		ORDER BY c.relname`), "\n")
	// Identity arguments in the key, projection AND ORDER BY — a
	// proname-only fingerprint makes overload pairs compare nondeterministically.
	// Filtered to prokind <> 'a' — pg_get_functiondef ERRORS on aggregates
	// (it handles window and LANGUAGE C functions fine); aggregates get their
	// own pg_aggregate catalog fingerprint below.
	out["functions"] = strings.Join(queryRows(t, conn, `
		SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
		       pg_get_functiondef(p.oid)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public' AND p.prokind <> 'a'
		ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)`), "\n")
	// The complete aggregate surface (incl. aggkind — a hypothetical-set
	// aggregate restoring as a plain ordered-set one changes this) plus the
	// operator flags (oprcanhash/oprcanmerge must survive the CREATE-only
	// bootstrap).
	out["aggregates"] = strings.Join(queryRows(t, conn, `
		SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
		       agg.aggkind::text, agg.aggnumdirectargs,
		       agg.aggtransfn::regproc::text, pg_catalog.format_type(agg.aggtranstype, NULL),
		       COALESCE(agg.agginitval, '<null>'),
		       agg.aggfinalfn::regproc::text, agg.aggfinalextra, agg.aggfinalmodify::text,
		       agg.aggmtransfn::regproc::text, agg.aggminvtransfn::regproc::text,
		       CASE WHEN agg.aggmtranstype = 0 THEN '' ELSE pg_catalog.format_type(agg.aggmtranstype, NULL) END,
		       COALESCE(agg.aggminitval, '<null>'), agg.aggsortop::regoper::text
		FROM pg_proc p JOIN pg_aggregate agg ON agg.aggfnoid = p.oid
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)`), "\n")
	// Range/base/shell types. The multirange name (PG14+) rides through
	// to_jsonb so the PG13 floor still parses.
	out["ranges"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname, pg_catalog.format_type(rng.rngsubtype, NULL),
		       opc.opcname,
		       CASE WHEN rng.rngcanonical = 0 THEN '' ELSE rng.rngcanonical::regproc::text END,
		       CASE WHEN rng.rngsubdiff = 0 THEN '' ELSE rng.rngsubdiff::regproc::text END,
		       COALESCE((SELECT mt.typname FROM pg_type mt
		                 WHERE mt.oid = COALESCE((to_jsonb(rng)->>'rngmultitypid')::bigint, 0)), '')
		FROM pg_range rng JOIN pg_type t ON t.oid = rng.rngtypid
		JOIN pg_opclass opc ON opc.oid = rng.rngsubopc
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' ORDER BY t.typname`), "\n")
	out["basetypes"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname, t.typlen, t.typbyval, t.typalign::text, t.typstorage::text,
		       t.typcategory::text, t.typispreferred, t.typdelim::text,
		       t.typinput::regproc::text, t.typoutput::regproc::text,
		       t.typcollation <> 0, COALESCE(t.typdefault, '<null>')
		FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' AND t.typtype = 'b' AND t.typisdefined
		  AND NOT EXISTS (SELECT 1 FROM pg_type el WHERE el.oid = t.typelem AND el.typarray = t.oid)
		ORDER BY t.typname`), "\n")
	out["shelltypes"] = strings.Join(queryRows(t, conn, `
		SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE n.nspname = 'public' AND NOT t.typisdefined ORDER BY t.typname`), "\n")
	// User casts and operators.
	out["casts"] = strings.Join(queryRows(t, conn, `
		SELECT pg_catalog.format_type(c.castsource, NULL), pg_catalog.format_type(c.casttarget, NULL),
		       c.castcontext::text, c.castmethod::text,
		       CASE WHEN c.castfunc = 0 THEN '' ELSE c.castfunc::regprocedure::text END
		FROM pg_cast c WHERE c.oid >= 16384
		ORDER BY 1, 2`), "\n")
	out["operators"] = strings.Join(queryRows(t, conn, `
		SELECT o.oprname,
		       CASE WHEN o.oprleft = 0 THEN '' ELSE pg_catalog.format_type(o.oprleft, NULL) END,
		       CASE WHEN o.oprright = 0 THEN '' ELSE pg_catalog.format_type(o.oprright, NULL) END,
		       o.oprcode::regproc::text,
		       CASE WHEN o.oprcom = 0 THEN '' ELSE o.oprcom::regoper::text END,
		       CASE WHEN o.oprnegate = 0 THEN '' ELSE o.oprnegate::regoper::text END,
		       o.oprcanhash, o.oprcanmerge
		FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace
		WHERE n.nspname = 'public' AND o.oprcode <> 0
		ORDER BY o.oprname, o.oprleft, o.oprright`), "\n")
	// WS-1 G3: trigger comments (lost today).
	out["trigger-comments"] = strings.Join(queryRows(t, conn, `
		SELECT t.tgname, obj_description(t.oid, 'pg_trigger')
		FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND NOT t.tgisinternal
		  AND obj_description(t.oid, 'pg_trigger') IS NOT NULL ORDER BY t.tgname`), "\n")
	// WS-1 G3: schema / index / constraint comments (lost today).
	out["schema-comment"] = strings.Join(queryRows(t, conn, `
		SELECT nspname, obj_description(oid, 'pg_namespace')
		FROM pg_namespace WHERE nspname = 'public'
		  AND obj_description(oid, 'pg_namespace') IS NOT NULL`), "\n")
	out["index-comments"] = strings.Join(queryRows(t, conn, `
		SELECT ic.relname, obj_description(ic.oid, 'pg_class')
		FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid
		JOIN pg_class c ON c.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND obj_description(ic.oid, 'pg_class') IS NOT NULL
		ORDER BY ic.relname`), "\n")
	out["constraint-comments"] = strings.Join(queryRows(t, conn, `
		SELECT con.conname, obj_description(con.oid, 'pg_constraint')
		FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND obj_description(con.oid, 'pg_constraint') IS NOT NULL
		ORDER BY con.conname`), "\n")

	seqs := queryRows(t, conn, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'S' ORDER BY c.relname`)
	out["sequences"] = strings.Join(seqs, ",")
	for _, s := range seqs {
		state := queryRows(t, conn, `SELECT last_value, is_called FROM public."`+s+`"`)
		out["seq:"+s] = strings.Join(state, "|")
	}
	// Sequence definition options (type/start/increment/min/max/cache/cycle):
	// without these, a restored CREATE SEQUENCE could silently reset to defaults
	// and the round-trip would still "pass" on last_value alone.
	out["seqopts"] = strings.Join(queryRows(t, conn, `
		SELECT c.relname, pg_catalog.format_type(s.seqtypid, NULL),
		       s.seqstart, s.seqincrement, s.seqmin, s.seqmax, s.seqcache, s.seqcycle,
		       c.relpersistence
		FROM pg_sequence s
		JOIN pg_class c ON c.oid = s.seqrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' ORDER BY c.relname`), "\n")
	// WS-1 G3: sequence comments (lost today).
	out["sequence-comments"] = strings.Join(queryRows(t, conn, `
		SELECT c.relname, obj_description(c.oid, 'pg_class')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'S'
		  AND obj_description(c.oid, 'pg_class') IS NOT NULL ORDER BY c.relname`), "\n")

	tables := queryRows(t, conn, `
		SELECT c.relname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r','p') AND NOT c.relispartition
		ORDER BY c.relname`)
	out["tables"] = strings.Join(tables, ",")
	for _, tb := range tables {
		rows := queryRows(t, conn, `SELECT * FROM public."`+tb+`" ORDER BY 1`)
		out["data:"+tb] = strings.Join(rows, "\n")
	}
	rows := queryRows(t, conn, `SELECT * FROM public.mv1`)
	out["data:mv1"] = strings.Join(rows, "\n")
	return out
}

func compareSnapshots(t *testing.T, before, after map[string]string, dump string) {
	t.Helper()
	var keys []string
	for k := range before {
		keys = append(keys, k)
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	failed := false
	for _, k := range keys {
		b, inB := before[k]
		a, inA := after[k]
		if !inB {
			t.Errorf("restore introduced %s:\n%s", k, a)
			failed = true
			continue
		}
		if !inA {
			t.Errorf("restore lost %s:\n%s", k, b)
			failed = true
			continue
		}
		if a != b {
			t.Errorf("%s differs after round-trip:\n--- before ---\n%s\n--- after ---\n%s", k, b, a)
			failed = true
		}
	}
	if failed {
		t.Logf("--- dump that was restored ---\n%s", dump)
	}
}

func TestLiveUserPrivilegesMySQL(t *testing.T) {
	liveUserPrivileges(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveUserPrivilegesMariaDB(t *testing.T) {
	liveUserPrivileges(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveUserPrivilegesPostgres(t *testing.T) {
	liveUserPrivileges(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveUserPrivileges drives the account/privilege management feature end to
// end against a real server: create user → grant (database and table scope) →
// verify via introspection → revoke → verify gone → drop user, plus the
// rejection paths (unknown grantee, privilege outside the allowlist, revoking
// an absent grant, dropping the logged-in account). On PostgreSQL it also
// revokes a database default from PUBLIC and proves via aclexplode that it is
// gone. The scratch account name is randomized and dropped via a deferred
// admin statement so a failing test never leaves it behind.
func liveUserPrivileges(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
	}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	// Two columns: column-scope grants need one column to grant on and one to
	// prove was NOT granted on.
	if _, err := seed.Exec(ctx, "CREATE TABLE pt (id int PRIMARY KEY, note varchar(40))"); err != nil {
		seed.Close()
		t.Fatalf("seed: %v", err)
	}
	seed.Close()

	// Randomized scratch account, cleaned up even when an assertion fails.
	var rnd [4]byte
	if _, err := cryptorand.Read(rnd[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	account := fmt.Sprintf("tablex_u%x", rnd)
	granteeVal := account // the grantee <select> value the form would submit
	dropStmt := `DROP ROLE IF EXISTS "` + account + `"`
	if env.engine == "mysql" {
		granteeVal = account + "@%"
		dropStmt = "DROP USER IF EXISTS '" + account + "'@'%'"
	}
	defer func() { _, _ = admin.Exec(context.Background(), dropStmt) }()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	post := func(path string, form url.Values) int {
		t.Helper()
		form.Set("csrf_token", csrf)
		// Destructive actions are gated on a server-side confirmation; the
		// browser gets it from the interstitial (or from app.js after the
		// hx-confirm dialog). Non-destructive actions ignore the field.
		form.Set("tx_confirm", "1")
		resp, err := client.PostForm(ts.URL+path, form)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 1. Create the account (LOGIN checked, as the PG form defaults it).
	if code := post("/server/users", url.Values{
		"action": {"create_user"}, "user_name": {account},
		"password": {"tx_l1ve_s3cret"}, "attr_login": {"1"},
	}); code != http.StatusSeeOther {
		t.Fatalf("create_user = %d, want 303", code)
	}
	users, err := admin.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	found := false
	for _, u := range users {
		if u.Name == account {
			found = true
		}
	}
	if !found {
		t.Fatalf("account %q not present after create_user", account)
	}

	// Introspection helper bound to the scratch database.
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	hasGrant := func(ref driver.TableRef, user, priv string) bool {
		t.Helper()
		privs, err := check.Privileges(ctx, ref)
		if err != nil {
			t.Fatalf("introspect privileges on %+v: %v", ref, err)
		}
		for _, p := range privs {
			if p.User == user && strings.EqualFold(p.Privilege, priv) {
				return true
			}
		}
		return false
	}
	// hasGrantOn is hasGrant narrowed to one scope: column "" is the
	// object-wide grant, which is a DIFFERENT grant from the same privilege on
	// a column. Keeping them apart is the point — a dropped column list would
	// show up here as an object-wide grant materializing.
	hasGrantOn := func(ref driver.TableRef, user, priv, column string) bool {
		t.Helper()
		privs, err := check.Privileges(ctx, ref)
		if err != nil {
			t.Fatalf("introspect privileges on %+v: %v", ref, err)
		}
		for _, p := range privs {
			if p.User == user && strings.EqualFold(p.Privilege, priv) && p.Column == column {
				return true
			}
		}
		return false
	}
	dbRef := driver.TableRef{Database: liveDB}
	tableRef := driver.TableRef{Database: liveDB, Table: "pt"}

	// 2. Database-scope grant → visible → revoke → gone.
	dbPriv := "SELECT"
	if env.engine == "postgres" {
		dbPriv = "CONNECT"
	}
	if code := post("/db/"+liveDB+"/privileges", url.Values{
		"action": {"grant"}, "grantee": {granteeVal}, "privs": {dbPriv},
	}); code != http.StatusSeeOther {
		t.Fatalf("db grant = %d, want 303", code)
	}
	if !hasGrant(dbRef, account, dbPriv) {
		t.Fatalf("db grant of %s to %q not visible after grant", dbPriv, account)
	}
	if code := post("/db/"+liveDB+"/privileges", url.Values{
		"action": {"revoke"}, "grantee": {granteeVal}, "priv": {dbPriv},
	}); code != http.StatusSeeOther {
		t.Fatalf("db revoke = %d, want 303", code)
	}
	if hasGrant(dbRef, account, dbPriv) {
		t.Errorf("db grant of %s to %q still present after revoke", dbPriv, account)
	}

	// 3. Table-scope grant with grant option → visible → revoke → gone.
	if code := post("/db/"+liveDB+"/table/pt/privileges", url.Values{
		"action": {"grant"}, "grantee": {granteeVal}, "privs": {"SELECT"}, "with_grant": {"1"},
	}); code != http.StatusSeeOther {
		t.Fatalf("table grant = %d, want 303", code)
	}
	if !hasGrant(tableRef, account, "SELECT") {
		t.Fatalf("table grant of SELECT to %q not visible after grant", account)
	}
	if code := post("/db/"+liveDB+"/table/pt/privileges", url.Values{
		"action": {"revoke"}, "grantee": {granteeVal}, "priv": {"SELECT"},
	}); code != http.StatusSeeOther {
		t.Fatalf("table revoke = %d, want 303", code)
	}
	if hasGrant(tableRef, account, "SELECT") {
		t.Errorf("table grant of SELECT to %q still present after revoke", account)
	}

	// 3b. Column-scope grant → visible AS A COLUMN GRANT → revoke → gone.
	//
	// The three assertions are deliberately distinct. "Is the column grant
	// there" catches a column list that never reached the server. "Is the
	// object-wide grant absent" catches the far worse failure — a column list
	// dropped somewhere in the chain, which grants SELECT on every column of
	// the table while the UI reports exactly what was asked for. And "is the
	// OTHER column ungranted" catches a list that widened to all columns.
	if code := post("/db/"+liveDB+"/table/pt/privileges", url.Values{
		"action": {"grant"}, "grantee": {granteeVal}, "privs": {"SELECT"}, "columns": {"id"},
	}); code != http.StatusSeeOther {
		t.Fatalf("column grant = %d, want 303", code)
	}
	if !hasGrantOn(tableRef, account, "SELECT", "id") {
		t.Errorf("column grant of SELECT(id) to %q not visible after grant", account)
	}
	if hasGrantOn(tableRef, account, "SELECT", "") {
		t.Errorf("column grant of SELECT(id) also produced a TABLE-WIDE SELECT for %q — the column list was dropped, widening the grant", account)
	}
	if hasGrantOn(tableRef, account, "SELECT", "note") {
		t.Errorf("column grant of SELECT(id) also covered column note for %q", account)
	}
	// A column the table does not have is refused before any SQL runs — the
	// alternative (skipping it) would leave an empty list, i.e. table-wide.
	if code := post("/db/"+liveDB+"/table/pt/privileges", url.Values{
		"action": {"grant"}, "grantee": {granteeVal}, "privs": {"SELECT"}, "columns": {"ghost"},
	}); code != http.StatusBadRequest {
		t.Errorf("column grant naming an unknown column = %d, want 400", code)
	}
	// DELETE has no column form on either engine.
	if code := post("/db/"+liveDB+"/table/pt/privileges", url.Values{
		"action": {"grant"}, "grantee": {granteeVal}, "privs": {"DELETE"}, "columns": {"id"},
	}); code != http.StatusBadRequest {
		t.Errorf("column grant of DELETE = %d, want 400", code)
	}
	// Revoking the object-wide grant must not remove the column grant: they are
	// separate rows, and the presence check refuses a grant that is not there.
	if code := post("/db/"+liveDB+"/table/pt/privileges", url.Values{
		"action": {"revoke"}, "grantee": {granteeVal}, "priv": {"SELECT"},
	}); code != http.StatusBadRequest {
		t.Errorf("revoke of the absent table-wide SELECT = %d, want 400", code)
	}
	if !hasGrantOn(tableRef, account, "SELECT", "id") {
		t.Errorf("column grant of SELECT(id) disappeared after a refused table-wide revoke")
	}
	if code := post("/db/"+liveDB+"/table/pt/privileges", url.Values{
		"action": {"revoke"}, "grantee": {granteeVal}, "priv": {"SELECT"}, "column": {"id"},
	}); code != http.StatusSeeOther {
		t.Fatalf("column revoke = %d, want 303", code)
	}
	if hasGrantOn(tableRef, account, "SELECT", "id") {
		t.Errorf("column grant of SELECT(id) still present after revoke")
	}

	// 4. Rejection paths: every one must be a clean 400, before any SQL runs.
	ghost := "tablex_ghost"
	if env.engine == "mysql" {
		ghost += "@%"
	}
	if code := post("/db/"+liveDB+"/privileges", url.Values{
		"action": {"grant"}, "grantee": {ghost}, "privs": {"SELECT"},
	}); code != http.StatusBadRequest {
		t.Errorf("grant to unknown grantee = %d, want 400", code)
	}
	if code := post("/db/"+liveDB+"/privileges", url.Values{
		"action": {"grant"}, "grantee": {granteeVal}, "privs": {"BOGUS"},
	}); code != http.StatusBadRequest {
		t.Errorf("grant of unknown privilege = %d, want 400", code)
	}
	if code := post("/db/"+liveDB+"/privileges", url.Values{
		"action": {"revoke"}, "grantee": {granteeVal}, "priv": {"INSERT"},
	}); code != http.StatusBadRequest {
		t.Errorf("revoke of absent grant = %d, want 400", code)
	}
	selfQuery := "SELECT current_user"
	if env.engine == "mysql" {
		selfQuery = "SELECT CURRENT_USER()"
	}
	self := queryRows(t, admin, selfQuery)
	if len(self) != 1 {
		t.Fatalf("current user query returned %v", self)
	}
	selfUser, selfHost := self[0], ""
	if env.engine == "mysql" {
		if i := strings.LastIndex(self[0], "@"); i >= 0 {
			selfUser, selfHost = self[0][:i], self[0][i+1:]
		}
	}
	if code := post("/server/users", url.Values{
		"action": {"drop_user"}, "user_name": {selfUser}, "user_host": {selfHost},
	}); code != http.StatusBadRequest {
		t.Errorf("self drop_user = %d, want 400 (self-lockout guard)", code)
	}

	// 5. PostgreSQL: revoke a database default from PUBLIC and prove via
	// aclexplode that the PUBLIC (grantee OID 0) CONNECT entry is gone.
	if env.engine == "postgres" {
		if code := post("/db/"+liveDB+"/privileges", url.Values{
			"action": {"revoke"}, "grantee": {"PUBLIC"}, "priv": {"CONNECT"},
		}); code != http.StatusSeeOther {
			t.Fatalf("revoke CONNECT from PUBLIC = %d, want 303", code)
		}
		left := queryRows(t, admin, `SELECT count(*) FROM pg_database d,
			aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
			WHERE d.datname = '`+liveDB+`' AND a.grantee = 0 AND a.privilege_type = 'CONNECT'`)
		if len(left) != 1 || strings.TrimSpace(left[0]) != "0" {
			t.Errorf("PUBLIC CONNECT still in datacl after revoke: %v", left)
		}
	}

	// 4b. Routine-scope grants: EXECUTE on one routine, through the per-routine
	// privileges page.
	//
	// BOTH engines seed two routines that share the name rp_calc, because both
	// have a way for a name alone to be ambiguous and the grant must land on
	// exactly the addressed one. PostgreSQL overloads on argument types;
	// MySQL cannot overload but keeps functions and procedures in separate
	// namespaces, so a function and a procedure of the same name coexist.
	if len(check.RoutineGrantablePrivileges()) > 0 {
		seed, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("connect to seed routines: %v", err)
		}
		stmts := []string{"CREATE FUNCTION rp_calc(a int) RETURNS int DETERMINISTIC RETURN a",
			"CREATE PROCEDURE rp_calc(a int) SELECT a"}
		if env.engine == "postgres" {
			stmts = []string{"CREATE FUNCTION rp_calc(a int) RETURNS int LANGUAGE sql AS $$ SELECT a $$",
				"CREATE FUNCTION rp_calc(a text) RETURNS text LANGUAGE sql AS $$ SELECT a $$"}
		}
		for _, s := range stmts {
			if _, err := seed.Exec(ctx, s); err != nil {
				seed.Close()
				t.Fatalf("seed routine %q: %v", s, err)
			}
		}
		seed.Close()

		routines, err := check.ListRoutines(ctx, driver.Scope{Database: liveDB})
		if err != nil {
			t.Fatalf("list routines: %v", err)
		}
		idx := -1
		for i, rt := range routines {
			if rt.Name == "rp_calc" && strings.EqualFold(rt.Type, "FUNCTION") {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatalf("seeded function rp_calc not listed: %+v", routines)
		}
		target := routines[idx]
		privURL := "/db/" + liveDB + "/routines/privileges?name=rp_calc&i=" + strconv.Itoa(idx)
		hasRoutineGrant := func(rt model.Routine, user, priv string) bool {
			t.Helper()
			privs, err := check.RoutinePrivileges(ctx, driver.Scope{Database: liveDB}, rt)
			if err != nil {
				t.Fatalf("introspect routine privileges: %v", err)
			}
			for _, p := range privs {
				if p.User == user && strings.EqualFold(p.Privilege, priv) {
					return true
				}
			}
			return false
		}
		if code := post(privURL, url.Values{
			"action": {"grant"}, "grantee": {granteeVal}, "privs": {"EXECUTE"},
		}); code != http.StatusSeeOther {
			t.Fatalf("routine grant = %d, want 303", code)
		}
		if !hasRoutineGrant(target, account, "EXECUTE") {
			t.Errorf("EXECUTE on rp_calc not visible for %q after grant", account)
		}
		// The same-named routine the request did NOT address must be untouched.
		// Without the identity arguments (PostgreSQL) or the routine kind
		// (MySQL) in both the WHERE clause and the ON target, each half of this
		// feature would address whichever one the catalog returned first.
		siblings := 0
		for _, rt := range routines {
			if rt.Name != "rp_calc" || (rt.Type == target.Type && rt.ArgSignature == target.ArgSignature) {
				continue
			}
			siblings++
			if hasRoutineGrant(rt, account, "EXECUTE") {
				t.Errorf("granting EXECUTE on %s rp_calc(%s) also granted it on %s rp_calc(%s)",
					target.Type, target.ArgSignature, rt.Type, rt.ArgSignature)
			}
		}
		if siblings == 0 {
			t.Error("no same-named sibling routine was listed; the ambiguity this check exists for is not being exercised")
		}
		// A table privilege has no routine form.
		if code := post(privURL, url.Values{
			"action": {"grant"}, "grantee": {granteeVal}, "privs": {"SELECT"},
		}); code != http.StatusBadRequest {
			t.Errorf("routine grant of SELECT = %d, want 400", code)
		}
		// A stale position that no longer carries the name is refused.
		if code := post("/db/"+liveDB+"/routines/privileges?name=rp_calc&i=999", url.Values{
			"action": {"grant"}, "grantee": {granteeVal}, "privs": {"EXECUTE"},
		}); code != http.StatusNotFound {
			t.Errorf("routine grant at a stale position = %d, want 404", code)
		}
		if code := post(privURL, url.Values{
			"action": {"revoke"}, "grantee": {granteeVal}, "priv": {"EXECUTE"},
		}); code != http.StatusSeeOther {
			t.Fatalf("routine revoke = %d, want 303", code)
		}
		if hasRoutineGrant(target, account, "EXECUTE") {
			t.Errorf("EXECUTE on rp_calc still present for %q after revoke", account)
		}
	}

	// 5b. Role membership: create a role, grant it to the scratch account
	// through the UI, see the edge in the catalog, revoke it, see it gone.
	//
	// A role is created as an account here rather than through a dedicated
	// form, because all three engines model it as one: PostgreSQL roles are
	// roles, MySQL 8 roles ARE accounts, and MariaDB is the only engine with a
	// separate CREATE ROLE — run directly below, since the account form has no
	// reason to grow an engine-specific switch for it.
	if admin.CanManageRoles() {
		roleName := account + "_r"
		var mkRole, dropRole string
		switch env.engine {
		case "mysql":
			// MariaDB needs a real role (is_role); MySQL 8's CREATE ROLE makes
			// an ordinary locked account, which is exactly what a role is there.
			mkRole = "CREATE ROLE '" + roleName + "'"
			dropRole = "DROP ROLE IF EXISTS '" + roleName + "'"
		default:
			mkRole = `CREATE ROLE "` + roleName + `"`
			dropRole = `DROP ROLE IF EXISTS "` + roleName + `"`
		}
		if _, err := admin.Exec(ctx, mkRole); err != nil {
			t.Fatalf("create role: %v", err)
		}
		// defer, not t.Cleanup: cleanups run AFTER the function's defers, so
		// the admin connection is already closed by then and the role would
		// survive on a shared server.
		defer func() { _, _ = admin.Exec(context.Background(), dropRole) }()
		// The role's account reference, as the <select> would submit it:
		// CREATE ROLE lands at '%' on MySQL 8 but at the EMPTY host on
		// MariaDB, and PostgreSQL has no host component at all.
		roleVal := roleName
		if env.engine == "mysql" {
			roleHost := "%"
			if strings.EqualFold(admin.Info().Flavor, "MariaDB") {
				roleHost = ""
			}
			roleVal = roleName + "@" + roleHost
		}
		hasMembership := func(role, member string) bool {
			t.Helper()
			ms, err := admin.RoleMemberships(ctx)
			if err != nil {
				t.Fatalf("read role memberships: %v", err)
			}
			for _, m := range ms {
				if m.Role == role && m.Member == member {
					return true
				}
			}
			return false
		}
		if code := post("/server/users", url.Values{
			"action": {"grant_role"}, "role": {roleVal}, "member": {granteeVal},
		}); code != http.StatusSeeOther {
			t.Fatalf("grant_role = %d, want 303", code)
		}
		if !hasMembership(roleName, account) {
			t.Errorf("role %q not granted to %q after grant_role", roleName, account)
		}
		// Rejection paths, both before any SQL runs.
		if code := post("/server/users", url.Values{
			"action": {"grant_role"}, "role": {"tablex_ghost_role"}, "member": {granteeVal},
		}); code != http.StatusBadRequest {
			t.Errorf("grant_role with an unknown role = %d, want 400", code)
		}
		if code := post("/server/users", url.Values{
			"action": {"grant_role"}, "role": {roleVal}, "member": {roleVal},
		}); code != http.StatusBadRequest {
			t.Errorf("grant_role of a role to itself = %d, want 400", code)
		}
		if code := post("/server/users", url.Values{
			"action": {"revoke_role"}, "role": {roleVal}, "member": {granteeVal},
		}); code != http.StatusSeeOther {
			t.Fatalf("revoke_role = %d, want 303", code)
		}
		if hasMembership(roleName, account) {
			t.Errorf("role %q still granted to %q after revoke_role", roleName, account)
		}
	}

	// 6. Set a new password, then drop the account through the UI.
	if code := post("/server/users", url.Values{
		"action": {"set_password"}, "user_name": {account}, "user_host": {"%"},
		"password": {"tx_l1ve_s3cret2"},
	}); code != http.StatusSeeOther {
		t.Fatalf("set_password = %d, want 303", code)
	}
	if code := post("/server/users", url.Values{
		"action": {"drop_user"}, "user_name": {account}, "user_host": {"%"},
	}); code != http.StatusSeeOther {
		t.Fatalf("drop_user = %d, want 303", code)
	}
	users, err = admin.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users after drop: %v", err)
	}
	for _, u := range users {
		if u.Name == account {
			t.Errorf("account %q still present after drop_user", account)
		}
	}
}

func TestLiveCreateTableMySQL(t *testing.T) {
	liveCreateTable(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveCreateTableMariaDB(t *testing.T) {
	liveCreateTable(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveCreateTablePostgres(t *testing.T) {
	liveCreateTable(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveCreateTable drives the create-table form against a real engine: a table
// with a PK, a NOT NULL column with a custom default and a nullable column
// (with a blank form row in the middle), verified via introspection.
func liveCreateTable(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
	}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	colType, textType := "INT", "VARCHAR"
	if env.engine == "postgres" {
		colType, textType = "integer", "varchar"
	}
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/create-table", url.Values{
		"csrf_token": {csrf}, "table_name": {"ct1"},
		"col_name_0": {"id"}, "col_type_0": {colType}, "col_pk_0": {"1"},
		// row 1 intentionally blank
		"col_name_2": {"label"}, "col_type_2": {textType}, "col_length_2": {"40"},
		"default_mode_2": {"custom"}, "default_value_2": {"n/a"},
		"col_name_3": {"qty"}, "col_type_3": {colType}, "col_nullable_3": {"1"},
	})
	if err != nil {
		t.Fatalf("create-table POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create-table POST = %d, want 303", resp.StatusCode)
	}

	dbParams := adminParams
	dbParams.Database = liveDB
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	ref := driver.TableRef{Database: liveDB, Table: "ct1"}
	if env.engine == "postgres" {
		ref.Schema = "public"
	}
	cols, err := check.Columns(ctx, ref)
	if err != nil {
		t.Fatalf("introspect ct1: %v", err)
	}
	if len(cols) != 3 || cols[0].Name != "id" || cols[1].Name != "label" || cols[2].Name != "qty" {
		names := make([]string, len(cols))
		for i, c := range cols {
			names[i] = c.Name
		}
		t.Fatalf("ct1 columns = %v, want [id label qty]", names)
	}
	if !cols[0].IsPrimaryKey {
		t.Error("id should be the primary key")
	}
	if cols[1].Nullable || cols[1].Default == nil || !strings.Contains(*cols[1].Default, "n/a") {
		t.Errorf("label should be NOT NULL with default n/a; got nullable=%v default=%v", cols[1].Nullable, cols[1].Default)
	}
	if !cols[2].Nullable {
		t.Error("qty should be nullable")
	}
}

func TestLiveGrantDBWildcardMySQL(t *testing.T) {
	liveGrantDBWildcard(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveGrantDBWildcardMariaDB(t *testing.T) {
	liveGrantDBWildcard(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveGrantDBWildcard proves the MySQL database-scope GRANT target escapes the
// LIKE-pattern metacharacters: a db-scope grant on "gw_a" (underscore) must NOT
// leak access to a sibling database "gwXa" that matches the unescaped pattern.
// It grants through the real handler, then logs in AS the granted account and
// confirms it can read the granted db but is denied the pattern-sibling — and
// that the introspection round-trips (the grant is visible and revocable
// despite the escaping).
func liveGrantDBWildcard(t *testing.T, env liveEnv) {
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

	// The granted database has an underscore; the sibling matches "gw_a" as a
	// LIKE pattern (_ = any single char) but must stay inaccessible.
	const grantedDB, siblingDB = "gw_a", "gwxa"
	for _, db := range []string{grantedDB, siblingDB} {
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+d.QuoteIdent(db)); err != nil {
			t.Fatalf("drop %s: %v", db, err)
		}
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+d.QuoteIdent(db)); err != nil {
			t.Fatalf("create %s: %v", db, err)
		}
	}
	defer func() {
		for _, db := range []string{grantedDB, siblingDB} {
			_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+d.QuoteIdent(db))
		}
	}()
	if _, err := admin.Exec(ctx, "CREATE TABLE "+d.QuoteIdent(siblingDB)+".t (id int)"); err != nil {
		t.Fatalf("seed sibling table: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE TABLE "+d.QuoteIdent(grantedDB)+".t (id int)"); err != nil {
		t.Fatalf("seed granted table: %v", err)
	}

	var rnd [4]byte
	if _, err := cryptorand.Read(rnd[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	account := fmt.Sprintf("tablex_gw%x", rnd)
	const pw = "tx_gw_s3cret"
	defer func() { _, _ = admin.Exec(context.Background(), "DROP USER IF EXISTS '"+account+"'@'%'") }()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	post := func(path string, form url.Values) int {
		t.Helper()
		form.Set("csrf_token", csrf)
		// Destructive actions are gated on a server-side confirmation; the
		// browser gets it from the interstitial (or from app.js after the
		// hx-confirm dialog). Non-destructive actions ignore the field.
		form.Set("tx_confirm", "1")
		resp, err := client.PostForm(ts.URL+path, form)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := post("/server/users", url.Values{
		"action": {"create_user"}, "user_name": {account}, "password": {pw},
	}); code != http.StatusSeeOther {
		t.Fatalf("create_user = %d, want 303", code)
	}
	if code := post("/db/"+grantedDB+"/privileges", url.Values{
		"action": {"grant"}, "grantee": {account + "@%"}, "privs": {"SELECT"},
	}); code != http.StatusSeeOther {
		t.Fatalf("db grant = %d, want 303", code)
	}

	// Introspection still finds the (escaped) grant — visible and revocable.
	privs, err := admin.Privileges(ctx, driver.TableRef{Database: grantedDB})
	if err != nil {
		t.Fatalf("introspect grant: %v", err)
	}
	seen := false
	for _, p := range privs {
		if p.User == account && p.Privilege == "SELECT" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("escaped db grant not visible via introspection: %+v", privs)
	}

	// Log in AS the granted account and check the actual access boundary.
	userConn, err := driver.Open(ctx, d, driver.ConnParams{
		Host: env.host, Port: env.port, User: account, Password: pw, Database: grantedDB,
	})
	if err != nil {
		t.Fatalf("connect as granted account: %v", err)
	}
	defer userConn.Close()
	if _, err := userConn.Query(ctx, "SELECT COUNT(*) FROM "+d.QuoteIdent(grantedDB)+".t", 1); err != nil {
		t.Errorf("granted account cannot read the granted db (should be allowed): %v", err)
	}
	if _, err := userConn.Query(ctx, "SELECT COUNT(*) FROM "+d.QuoteIdent(siblingDB)+".t", 1); err == nil {
		t.Errorf("OVER-GRANT: granted account could read pattern-sibling %s.t; the db-scope grant must be escaped to a literal", siblingDB)
	}
}

// --- Theme F: database collation + schema management ------------------------------

func TestLiveCreateDBCollationMySQL(t *testing.T) {
	liveCreateDBCollation(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveCreateDBCollationMariaDB(t *testing.T) {
	liveCreateDBCollation(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveCreateDBCollation drives the create-database control with an explicit
// collation through the real handler: the created database must carry the
// collation (introspected), and an unknown/injection-shaped collation must be
// rejected 400 without creating anything (the builder emits the collation as a
// bare identifier, so the introspection allowlist is the only guard).
func liveCreateDBCollation(t *testing.T, env liveEnv) {
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
	defer liveDropDB(t, admin, env.engine)

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	post := func(form url.Values) int {
		t.Helper()
		form.Set("csrf_token", csrf)
		// Destructive actions are gated on a server-side confirmation; the
		// browser gets it from the interstitial (or from app.js after the
		// hx-confirm dialog). Non-destructive actions ignore the field.
		form.Set("tx_confirm", "1")
		resp, err := client.PostForm(ts.URL+"/server", form)
		if err != nil {
			t.Fatalf("POST /server: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// The create form offers the server's real collations.
	code, page := getBody(t, client, ts.URL+"/server")
	if code != http.StatusOK || !strings.Contains(page, "utf8mb4_bin") {
		t.Fatalf("databases page should offer collations: code=%d has utf8mb4_bin=%v", code, strings.Contains(page, "utf8mb4_bin"))
	}

	// Injection-shaped and unknown collations are rejected without a side effect.
	for _, bad := range []string{"utf8mb4_bin; DROP DATABASE x", "no_such_collation"} {
		if code := post(url.Values{"action": {"create_db"}, "db_name": {liveDB}, "db_collation": {bad}}); code != http.StatusBadRequest {
			t.Fatalf("create_db with collation %q = %d, want 400", bad, code)
		}
	}
	dbs, err := admin.ListDatabases(ctx)
	if err != nil {
		t.Fatalf("list databases: %v", err)
	}
	for _, db := range dbs {
		if db.Name == liveDB {
			t.Fatalf("rejected create_db still created %s", liveDB)
		}
	}

	// A real collation is accepted and lands on the created database.
	if code := post(url.Values{"action": {"create_db"}, "db_name": {liveDB}, "db_collation": {"utf8mb4_bin"}}); code != http.StatusSeeOther {
		t.Fatalf("create_db with utf8mb4_bin = %d, want 303", code)
	}
	dbs, err = admin.ListDatabases(ctx)
	if err != nil {
		t.Fatalf("list databases after create: %v", err)
	}
	found := false
	for _, db := range dbs {
		if db.Name == liveDB {
			found = true
			if db.Collation != "utf8mb4_bin" {
				t.Errorf("created db collation = %q, want utf8mb4_bin", db.Collation)
			}
		}
	}
	if !found {
		t.Fatalf("created database %s not listed", liveDB)
	}
}

// TestLiveSchemaManagementPostgres drives create/drop schema through the real
// DB-operations handler: create lands in introspection, duplicates and system
// schemas are refused, and drop (CASCADE) removes the schema and its objects.
func TestLiveSchemaManagementPostgres(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	post := func(form url.Values) int {
		t.Helper()
		form.Set("csrf_token", csrf)
		// Destructive actions are gated on a server-side confirmation; the
		// browser gets it from the interstitial (or from app.js after the
		// hx-confirm dialog). Non-destructive actions ignore the field.
		form.Set("tx_confirm", "1")
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/operations", form)
		if err != nil {
			t.Fatalf("POST operations: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	hasSchema := func(name string) bool {
		t.Helper()
		dbParams := adminParams
		dbParams.Database = liveDB
		check, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("verify connect: %v", err)
		}
		defer check.Close()
		schemas, err := check.ListSchemas(ctx, liveDB)
		if err != nil {
			t.Fatalf("list schemas: %v", err)
		}
		for _, s := range schemas {
			if s.Name == name {
				return true
			}
		}
		return false
	}

	// Create; it must land in introspection.
	if code := post(url.Values{"action": {"create_schema"}, "schema_name": {"sales"}}); code != http.StatusSeeOther {
		t.Fatalf("create_schema = %d, want 303", code)
	}
	if !hasSchema("sales") {
		t.Fatal("created schema 'sales' not introspected")
	}
	// Duplicate name and injection-shaped name are refused.
	if code := post(url.Values{"action": {"create_schema"}, "schema_name": {"sales"}}); code != http.StatusBadRequest {
		t.Errorf("duplicate create_schema = %d, want 400", code)
	}
	if code := post(url.Values{"action": {"create_schema"}, "schema_name": {`x"; DROP SCHEMA public`}}); code != http.StatusBadRequest {
		t.Errorf("injection-shaped create_schema = %d, want 400", code)
	}
	// System schemas and unknown schemas cannot be dropped.
	if code := post(url.Values{"action": {"drop_schema"}, "schema_name": {"pg_catalog"}}); code != http.StatusBadRequest {
		t.Errorf("drop_schema pg_catalog = %d, want 400", code)
	}
	if code := post(url.Values{"action": {"drop_schema"}, "schema_name": {"nope"}}); code != http.StatusNotFound {
		t.Errorf("drop_schema unknown = %d, want 404", code)
	}
	// Drop cascades objects inside the schema.
	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	if _, err := seed.Exec(ctx, `CREATE TABLE "sales"."orders" (id int)`); err != nil {
		seed.Close()
		t.Fatalf("seed table: %v", err)
	}
	seed.Close()
	if code := post(url.Values{"action": {"drop_schema"}, "schema_name": {"sales"}}); code != http.StatusSeeOther {
		t.Fatalf("drop_schema sales = %d, want 303", code)
	}
	if hasSchema("sales") {
		t.Error("dropped schema 'sales' still introspected")
	}
}

func TestLiveServerDumpDBCollationMySQL(t *testing.T) {
	liveServerDumpDBCollation(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveServerDumpDBCollationMariaDB(t *testing.T) {
	liveServerDumpDBCollation(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveServerDumpDBCollation proves a server-scope dump preserves each
// database's default collation: a database created COLLATE utf8mb4_bin (not
// the server default on any supported version) is exported at server scope,
// dropped, restored through the server-scope import, and must come back
// utf8mb4_bin rather than silently falling back to the server default.
func liveServerDumpDBCollation(t *testing.T, env liveEnv) {
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
	requireIsolatedServerScope(t, admin, env.engine)

	liveDropDB(t, admin, env.engine)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+liveDB+" COLLATE utf8mb4_bin"); err != nil {
		t.Fatalf("create collated db: %v", err)
	}
	defer liveDropDB(t, admin, env.engine)
	if _, err := admin.Exec(ctx, "CREATE TABLE "+liveDB+".t (id INT PRIMARY KEY, v VARCHAR(20))"); err != nil {
		t.Fatalf("seed table: %v", err)
	}
	if _, err := admin.Exec(ctx, "INSERT INTO "+liveDB+".t VALUES (1, 'keep')"); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/server/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("server export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("server export = %d", resp.StatusCode)
	}
	if !strings.Contains(dump, "CREATE DATABASE IF NOT EXISTS `"+liveDB+"` COLLATE utf8mb4_bin;") {
		t.Fatalf("server dump missing the collated CREATE DATABASE:\n%.2000s", dump)
	}

	liveDropDB(t, admin, env.engine)
	resp, err = client.PostForm(ts.URL+"/server/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump},
	})
	if err != nil {
		t.Fatalf("server import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("server import failed (%d). Page:\n%.4000s\n--- dump was ---\n%.4000s",
			resp.StatusCode, importBody, dump)
	}

	dbs, err := admin.ListDatabases(ctx)
	if err != nil {
		t.Fatalf("list databases: %v", err)
	}
	found := false
	for _, db := range dbs {
		if db.Name == liveDB {
			found = true
			if db.Collation != "utf8mb4_bin" {
				t.Errorf("restored db collation = %q, want utf8mb4_bin (silently fell back to the server default)", db.Collation)
			}
		}
	}
	if !found {
		t.Fatalf("restored database %s not listed", liveDB)
	}
	// The data survived the same round-trip.
	dbParams := adminParams
	dbParams.Database = liveDB
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	rs, err := check.Query(ctx, "SELECT v FROM t WHERE id = 1", 1)
	if err != nil || len(rs.Rows) != 1 {
		t.Fatalf("restored row read: err=%v rows=%v", err, rs)
	}
}

func TestLiveBulkIntrospectionEquivalenceMySQL(t *testing.T) {
	liveBulkEquivalence(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveBulkIntrospectionEquivalenceMariaDB(t *testing.T) {
	liveBulkEquivalence(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveBulkIntrospectionEquivalencePostgres(t *testing.T) {
	liveBulkEquivalence(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveBulkEquivalence pins the BulkIntrospector contract on the rich round-trip
// seed schema (generated columns, identity, expression defaults, composite and
// self-referencing FKs, partitions): for EVERY table, the bulk maps must equal
// the per-table Columns/ForeignKeys results exactly. The designer's fast path
// showing anything different from the structure page would be a lie.
func liveBulkEquivalence(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
	}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("seed connect: %v", err)
	}
	pgVer := 0
	if env.engine == "postgres" {
		pgVer = pgServerVersionNum(t, admin)
	}
	for _, stmt := range liveSeedStatements(env.engine, pgVer) {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	scope := driver.Scope{Database: liveDB}
	bulkCols, haveCols, err := conn.BulkColumns(ctx, scope)
	if !haveCols || err != nil {
		t.Fatalf("BulkColumns: have=%v err=%v", haveCols, err)
	}
	bulkFKs, haveFKs, err := conn.BulkForeignKeys(ctx, scope)
	if !haveFKs || err != nil {
		t.Fatalf("BulkForeignKeys: have=%v err=%v", haveFKs, err)
	}
	tables, err := conn.ListTableNames(ctx, scope)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) == 0 {
		t.Fatal("seeded schema lists no tables (vacuous)")
	}
	checked := 0
	for _, tb := range tables {
		ref := driver.TableRef{Database: liveDB, Schema: tb.Schema, Table: tb.Name}
		single, err := conn.Columns(ctx, ref)
		if err != nil {
			t.Fatalf("Columns(%s): %v", tb.Name, err)
		}
		if !reflect.DeepEqual(single, bulkCols[tb.Name]) {
			t.Errorf("BulkColumns[%s] diverges from Columns:\n bulk: %#v\n single: %#v", tb.Name, bulkCols[tb.Name], single)
		}
		singleFKs, err := conn.ForeignKeys(ctx, ref)
		if err != nil {
			t.Fatalf("ForeignKeys(%s): %v", tb.Name, err)
		}
		if !reflect.DeepEqual(singleFKs, bulkFKs[tb.Name]) {
			t.Errorf("BulkForeignKeys[%s] diverges from ForeignKeys:\n bulk: %#v\n single: %#v", tb.Name, bulkFKs[tb.Name], singleFKs)
		}
		if len(single) > 0 {
			checked++
		}
	}
	if checked < 3 {
		t.Fatalf("only %d non-empty tables compared — seed schema unexpectedly thin", checked)
	}
}

// TestLivePostgresColumnsRelkinds pins the relkind set behind the PG Columns
// path (which delegates to bulkColumns with a table filter): every relation
// kind ListTables surfaces — plain table 'r', partitioned parent 'p', view
// 'v', materialized view 'm' — must introspect its columns. A regression that
// narrows the set would silently return an empty column list for one of these.
func TestLivePostgresColumnsRelkinds(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	for _, stmt := range []string{
		`CREATE TABLE plain (id int PRIMARY KEY, label text)`,
		`CREATE TABLE parted (id int, at date) PARTITION BY RANGE (at)`,
		`CREATE VIEW v_plain AS SELECT id, label FROM plain`,
		`CREATE MATERIALIZED VIEW mv_plain AS SELECT id FROM plain`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	for _, name := range []string{"plain", "parted", "v_plain", "mv_plain"} {
		cols, err := conn.Columns(ctx, driver.TableRef{Database: liveDB, Schema: "public", Table: name})
		if err != nil {
			t.Errorf("Columns(%s): %v", name, err)
			continue
		}
		if len(cols) == 0 {
			t.Errorf("Columns(%s) returned no columns — relkind excluded from the introspection set", name)
		}
	}
}

func TestLiveCSVBinaryRoundTripMySQL(t *testing.T) {
	liveCSVBinaryRoundTrip(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveCSVBinaryRoundTripMariaDB(t *testing.T) {
	liveCSVBinaryRoundTrip(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveCSVBinaryRoundTripPostgres(t *testing.T) {
	liveCSVBinaryRoundTrip(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveCSVBinaryRoundTrip pins the R1 symmetric-CSV fix on real engines: a
// binary column's bytes hex-encode on export and decode back on import, and a
// TEXT column whose value the export stream classified binary — MySQL returns
// text as []byte, so a NUL-holding or >1 MiB value trips isPrintableUTF8 —
// must still be written as CSV TEXT (import would otherwise insert literal hex
// into the text column: the pre-fix corruption). PostgreSQL only exercises the
// binary column (pgx never returns text as []byte).
func liveCSVBinaryRoundTrip(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
	}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	var stmts []string
	if env.engine == "postgres" {
		stmts = []string{
			`CREATE TABLE csvbin (id int PRIMARY KEY, data bytea, txt text)`,
			`INSERT INTO csvbin VALUES (1, '\x00ff10', 'plain')`,
			`INSERT INTO csvbin VALUES (2, NULL, NULL)`,
			`INSERT INTO csvbin VALUES (3, '\x', 'empty bytes above')`,
		}
	} else {
		stmts = []string{
			"CREATE TABLE csvbin (id int PRIMARY KEY, data BLOB, txt MEDIUMTEXT)",
			"INSERT INTO csvbin VALUES (1, X'00FF10', 'plain')",
			"INSERT INTO csvbin VALUES (2, NULL, NULL)",
			"INSERT INTO csvbin VALUES (3, X'', 'empty bytes above')",
			// NUL-holding text: valid UTF-8, classified binary by isPrintableUTF8.
			"INSERT INTO csvbin VALUES (4, NULL, 'a\\0b')",
			// >1 MiB text: classified binary by size alone; must export as text.
			"INSERT INTO csvbin VALUES (5, NULL, REPEAT('x', 2097153))",
		}
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// md5 keeps the >1 MiB text row's snapshot small; HEX/encode pins the bytes.
	snapSQL := "SELECT id, HEX(data), MD5(txt) FROM csvbin ORDER BY id"
	if env.engine == "postgres" {
		snapSQL = "SELECT id, encode(data, 'hex'), md5(txt) FROM csvbin ORDER BY id"
	}
	before := queryRows(t, check, snapSQL)
	if len(before) != len(stmts)-1 {
		t.Fatalf("seed snapshot = %d rows, want %d: %v", len(before), len(stmts)-1, before)
	}

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/table/csvbin/export",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csvBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	exported := string(csvBytes)
	if resp.StatusCode != http.StatusOK || strings.Contains(exported, "# export error") {
		t.Fatalf("csv export failed (%d):\n%.2000s", resp.StatusCode, exported)
	}
	if !strings.Contains(exported, "00ff10") {
		t.Errorf("binary column should hex-encode:\n%.2000s", exported)
	}
	if env.engine == "mysql" {
		if !strings.Contains(exported, "a\x00b") {
			t.Errorf("NUL-holding text should export as text, not hex:\n%.2000s", exported)
		}
		if !strings.Contains(exported, "xxxxxxxx") {
			t.Errorf(">1 MiB text should export as text, not hex (len %d)", len(exported))
		}
	}

	if _, err := check.Exec(ctx, "DELETE FROM csvbin"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/table/csvbin/import",
		url.Values{"csrf_token": {csrf}, "format": {"csv"}, "sql_script": {exported}})
	if err != nil {
		t.Fatalf("csv import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	wantRows := fmt.Sprintf("Imported %d row", len(before))
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(importBody), wantRows) {
		t.Fatalf("csv import did not report %q (%d):\n%.4000s", wantRows, resp.StatusCode, importBody)
	}

	after := queryRows(t, check, snapSQL)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Errorf("CSV round-trip mismatch:\n--- before ---\n%s\n--- after ---\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
}

// TestLivePostgresCoveringIndexColumns guards the indnkeyatts bound in the
// Indexes introspection: a covering index's INCLUDE payload columns must not
// be reported (or rendered) as key columns on the structure page.
func TestLivePostgresCoveringIndexColumns(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	for _, stmt := range []string{
		`CREATE TABLE covered (keycol int NOT NULL, payload text)`,
		`CREATE UNIQUE INDEX covered_key_idx ON covered (keycol) INCLUDE (payload)`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	// Driver-level: only the key column is reported.
	idxs, err := conn.Indexes(ctx, driver.TableRef{Database: liveDB, Schema: "public", Table: "covered"})
	if err != nil {
		t.Fatalf("Indexes: %v", err)
	}
	found := false
	for _, ix := range idxs {
		if ix.Name != "covered_key_idx" {
			continue
		}
		found = true
		names := ix.ColumnNames()
		if strings.Join(names, ",") != "keycol" {
			t.Errorf("covered_key_idx columns = %v, want [keycol] (INCLUDE payload must be excluded)", names)
		}
	}
	if !found {
		t.Fatal("covered_key_idx not introspected")
	}

	// Structure page: the index row lists the key column, not the payload.
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	code, page := getBody(t, client, ts.URL+"/db/"+liveDB+"/table/covered/structure?schema=public")
	if code != http.StatusOK {
		t.Fatalf("structure page = %d, want 200", code)
	}
	if !strings.Contains(page, "covered_key_idx") {
		t.Fatalf("structure page missing covered_key_idx:\n%.4000s", page)
	}
	if !strings.Contains(page, "<code>keycol</code>") {
		t.Error("structure page should list keycol as the index's only column")
	}
	if strings.Contains(page, "keycol, payload") {
		t.Error("structure page lists INCLUDE payload column as a key column")
	}
}

func TestLiveExternalGrantRevokeMySQL(t *testing.T) {
	liveExternalGrantRevoke(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveExternalGrantRevokeMariaDB(t *testing.T) {
	liveExternalGrantRevoke(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveExternalGrantRevoke proves the stored-pattern revoke path: MySQL
// matches REVOKE targets by the exact stored grant pattern, so a grant created
// externally on a _-named database (stored raw, e.g. "rv_app") and TableX's
// own grant (stored escaped, "rv\_app") must BOTH be revocable through the
// handler — re-escaping the name would miss the raw row with "There is no
// such grant defined".
func liveExternalGrantRevoke(t *testing.T, env liveEnv) {
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

	const grantDB = "rv_app"
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+d.QuoteIdent(grantDB)); err != nil {
		t.Fatalf("drop %s: %v", grantDB, err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+d.QuoteIdent(grantDB)); err != nil {
		t.Fatalf("create %s: %v", grantDB, err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+d.QuoteIdent(grantDB)) }()

	var rnd [4]byte
	if _, err := cryptorand.Read(rnd[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	account := fmt.Sprintf("tablex_rv%x", rnd)
	defer func() { _, _ = admin.Exec(context.Background(), "DROP USER IF EXISTS '"+account+"'@'%'") }()
	if _, err := admin.Exec(ctx, "CREATE USER '"+account+"'@'%' IDENTIFIED BY 'tx_rv_s3cret'"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	// The external grant: raw pattern, exactly as a CLI `GRANT ... ON rv_app.*`
	// stores it (unescaped underscore).
	if _, err := admin.Exec(ctx, "GRANT SELECT ON "+d.QuoteIdent(grantDB)+".* TO '"+account+"'@'%'"); err != nil {
		t.Fatalf("external raw grant: %v", err)
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")

	post := func(form url.Values) int {
		t.Helper()
		form.Set("csrf_token", csrf)
		// Destructive actions are gated on a server-side confirmation; the
		// browser gets it from the interstitial (or from app.js after the
		// hx-confirm dialog). Non-destructive actions ignore the field.
		form.Set("tx_confirm", "1")
		resp, err := client.PostForm(ts.URL+"/db/"+grantDB+"/privileges", form)
		if err != nil {
			t.Fatalf("POST privileges: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	selectRows := func() []string {
		t.Helper()
		privs, err := admin.Privileges(ctx, driver.TableRef{Database: grantDB})
		if err != nil {
			t.Fatalf("introspect grants: %v", err)
		}
		var got []string
		for _, p := range privs {
			if p.User == account && p.Privilege == "SELECT" {
				got = append(got, p.StoredObject)
			}
		}
		return got
	}

	// TableX's own grant stores the escaped pattern alongside the raw one.
	if code := post(url.Values{"action": {"grant"}, "grantee": {account + "@%"}, "privs": {"SELECT"}}); code != http.StatusSeeOther {
		t.Fatalf("handler grant = %d, want 303", code)
	}
	if rows := selectRows(); len(rows) != 2 {
		t.Fatalf("expected raw+escaped grant rows before revoke, got %q", rows)
	}

	// One revoke through the handler must clear BOTH stored patterns.
	if code := post(url.Values{"action": {"revoke"}, "grantee": {account + "@%"}, "priv": {"SELECT"}}); code != http.StatusSeeOther {
		t.Fatalf("revoke = %d, want 303", code)
	}
	// accessExecFailed also 303s (with an error flash), so assert the outcome:
	// the flash is the success wording and the grant rows are gone.
	_, page := getBody(t, client, ts.URL+"/db/"+grantDB+"/privileges")
	if !strings.Contains(page, "Revoked SELECT") {
		t.Error("revoke did not report success — the raw-stored grant row was likely missed")
	}
	if rows := selectRows(); len(rows) != 0 {
		t.Errorf("grant rows still present after revoke: %q", rows)
	}
}

func TestLiveMetadataTabsMySQL(t *testing.T) {
	liveMetadataTabs(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMetadataTabsMariaDB(t *testing.T) {
	liveMetadataTabs(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveMetadataTabs renders the routines/triggers/events tabs against a live
// server: /routines and /events previously had zero test coverage, and
// the SQLite /triggers smoke never asserted content. Each page must list the
// seeded object by name.
func liveMetadataTabs(t *testing.T, env liveEnv) {
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
	for _, stmt := range []string{
		`CREATE TABLE t (id INT NOT NULL PRIMARY KEY, v INT NULL)`,
		`CREATE TRIGGER meta_trg BEFORE INSERT ON t FOR EACH ROW SET NEW.v = IFNULL(NEW.v, 0)`,
		`CREATE PROCEDURE meta_proc(IN x INT) SELECT x`,
		// Creating an event does not require the scheduler to be running.
		`CREATE EVENT meta_ev ON SCHEDULE EVERY 1 DAY DO SELECT 1`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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

	for _, c := range []struct{ tab, want string }{
		{"routines", "meta_proc"},
		{"triggers", "meta_trg"},
		{"events", "meta_ev"},
	} {
		code, page := getBody(t, client, ts.URL+"/db/"+liveDB+"/"+c.tab)
		if code != http.StatusOK {
			t.Errorf("GET /%s = %d, want 200", c.tab, code)
			continue
		}
		if !strings.Contains(page, c.want) {
			t.Errorf("/%s page does not list seeded %q:\n%.2000s", c.tab, c.want, page)
		}
	}
}

func TestLiveKillProcessMySQL(t *testing.T) {
	liveKillProcess(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveKillProcessMariaDB(t *testing.T) {
	liveKillProcess(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveKillProcessPostgres(t *testing.T) {
	liveKillProcess(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveKillProcess drives the process page's kill button against a real server:
// open a second connection, find its session in the list, terminate it through
// the UI, and prove the session is GONE — not merely that the POST returned
// 303, which a no-op would too.
//
// The victim pool is pinned to ONE connection so the id it reports is the id
// that gets killed; with the default pool the query could answer from one
// physical connection and the kill land on another.
func liveKillProcess(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
	}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	victimParams := adminParams
	victimParams.Tuning = driver.Tuning{MaxOpenConns: 1, MaxIdleConns: 1}
	victim, err := driver.Open(ctx, d, victimParams)
	if err != nil {
		t.Fatalf("open victim connection: %v", err)
	}
	defer victim.Close()

	idQuery := "SELECT CONNECTION_ID()"
	if env.engine == "postgres" {
		idQuery = "SELECT pg_backend_pid()"
	}
	got := queryRows(t, victim, idQuery)
	if len(got) != 1 {
		t.Fatalf("%s returned %v", idQuery, got)
	}
	victimID := strings.TrimSpace(got[0])

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
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
	csrf = csrfFrom(t, client, ts.URL+"/")
	post := func(form url.Values) int {
		t.Helper()
		form.Set("csrf_token", csrf)
		// Destructive actions are gated on a server-side confirmation; the
		// browser gets it from the interstitial (or from app.js after the
		// hx-confirm dialog). Non-destructive actions ignore the field.
		form.Set("tx_confirm", "1")
		resp, err := client.PostForm(ts.URL+"/server/processes", form)
		if err != nil {
			t.Fatalf("POST /server/processes: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// The page must offer the button, and the victim must be on it.
	code, page := getBody(t, client, ts.URL+"/server/processes")
	if code != http.StatusOK {
		t.Fatalf("GET /server/processes = %d, want 200", code)
	}
	if !strings.Contains(page, `name="action" value="kill"`) {
		t.Errorf("processes page has no kill control:\n%.1500s", page)
	}
	if !strings.Contains(page, victimID) {
		t.Errorf("processes page does not list the victim session %s:\n%.3000s", victimID, page)
	}

	// Rejections, before any statement runs.
	if c := post(url.Values{"action": {"kill"}, "pid": {"not-a-number"}}); c != http.StatusBadRequest {
		t.Errorf("kill with a non-numeric pid = %d, want 400", c)
	}
	if c := post(url.Values{"action": {"kill"}, "pid": {"2147483646"}}); c != http.StatusNotFound {
		t.Errorf("kill of a pid absent from the listing = %d, want 404", c)
	}
	if c := post(url.Values{"action": {"bogus"}, "pid": {victimID}}); c != http.StatusBadRequest {
		t.Errorf("unknown action = %d, want 400", c)
	}

	if c := post(url.Values{"action": {"kill"}, "pid": {victimID}}); c != http.StatusSeeOther {
		t.Fatalf("kill = %d, want 303", c)
	}
	// Gone means gone: re-read the list from the ADMIN connection rather than
	// trusting the flash. MySQL's KILL is asynchronous, so allow the server a
	// moment to reap the thread before deciding.
	sessionGone := func() bool {
		for _, id := range queryRows(t, admin, sessionIDsQuery(env.engine)) {
			if strings.TrimSpace(id) == victimID {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(5 * time.Second)
	for !sessionGone() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !sessionGone() {
		t.Errorf("session %s is still connected after the kill", victimID)
	}
}

// sessionIDsQuery lists live session identifiers for the engine.
func sessionIDsQuery(engine string) string {
	if engine == "postgres" {
		return "SELECT pid FROM pg_stat_activity"
	}
	return "SELECT Id FROM information_schema.PROCESSLIST"
}

func TestLivePostgresViewObjects(t *testing.T) {
	liveViewObjects(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveViewObjects pins the matview/view fidelity set: a functional INSTEAD
// OF view trigger, a view-column DEFAULT, trigger enable-state (a disabled
// table trigger must survive DISABLED, an ALWAYS one ALWAYS), a matview's
// UNIQUE index (+ its comment) and per-column STORAGE/STATISTICS
// (+ COMPRESSION on PG14+) — all previously lost from the dump. Also asserts
// the matview index is emitted exactly ONCE on both the database- and
// table-scope paths (DumpView delegates to dumpViews; double collection would
// double-emit).
func liveViewObjects(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	pg14 := pgServerVersionNum(t, admin) >= 140000
	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	seedStmts := []string{
		`CREATE TABLE vbase2 (id int PRIMARY KEY, name text)`,
		`INSERT INTO vbase2 VALUES (1, 'a'), (2, 'b')`,
		`CREATE VIEW vins AS SELECT id, name FROM vbase2 WHERE id < 100`,
		// A view-column default (applied by INSERTs through the trigger).
		`ALTER VIEW vins ALTER COLUMN name SET DEFAULT 'anon'`,
		`CREATE FUNCTION vins_ins() RETURNS trigger AS $fn$
		BEGIN
			INSERT INTO vbase2 (id, name) VALUES (NEW.id, NEW.name);
			RETURN NEW;
		END
		$fn$ LANGUAGE plpgsql`,
		`CREATE TRIGGER trg_vins INSTEAD OF INSERT ON vins FOR EACH ROW EXECUTE FUNCTION vins_ins()`,
		`COMMENT ON TRIGGER trg_vins ON vins IS 'route inserts to vbase2'`,
		// Non-default trigger enable states on a TABLE.
		`CREATE FUNCTION tnoop() RETURNS trigger AS $fn$ BEGIN RETURN NEW; END $fn$ LANGUAGE plpgsql`,
		`CREATE TRIGGER trg_dis BEFORE UPDATE ON vbase2 FOR EACH ROW EXECUTE FUNCTION tnoop()`,
		`ALTER TABLE vbase2 DISABLE TRIGGER trg_dis`,
		`CREATE TRIGGER trg_alw BEFORE DELETE ON vbase2 FOR EACH ROW EXECUTE FUNCTION tnoop()`,
		`ALTER TABLE vbase2 ENABLE ALWAYS TRIGGER trg_alw`,
		// Matview with a UNIQUE index (+ comment) and column settings.
		`CREATE MATERIALIZED VIEW mvx AS SELECT id, name FROM vbase2`,
		`CREATE UNIQUE INDEX uq_mvx_id ON mvx (id)`,
		`COMMENT ON INDEX uq_mvx_id IS 'mv key'`,
		`ALTER MATERIALIZED VIEW mvx ALTER COLUMN name SET STATISTICS 123`,
		`ALTER MATERIALIZED VIEW mvx ALTER COLUMN name SET STORAGE EXTERNAL`,
	}
	if pg14 {
		seedStmts = append(seedStmts, `ALTER MATERIALIZED VIEW mvx ALTER COLUMN name SET COMPRESSION pglz`)
	}
	for _, stmt := range seedStmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	export := func(path string) string {
		resp, err := client.PostForm(ts.URL+path, url.Values{
			"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
		})
		if err != nil {
			t.Fatalf("export %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %s = %d:\n%.2000s", path, resp.StatusCode, b)
		}
		return string(b)
	}
	dump := export("/db/" + liveDB + "/export")
	for _, want := range []string{
		"INSTEAD OF INSERT",         // the view trigger's CREATE
		`DISABLE TRIGGER "trg_dis"`, // trigger enable state
		`ENABLE ALWAYS TRIGGER "trg_alw"`,
		`SET DEFAULT 'anon'`, // view-column default
		"SET STATISTICS 123", // matview column settings
		`ALTER MATERIALIZED VIEW "public"."mvx"`,
		"COMMENT ON INDEX", // matview index comment
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("db-scope dump missing %q:\n%s", want, dump)
		}
	}
	if pg14 && !strings.Contains(dump, `ALTER MATERIALIZED VIEW "public"."mvx" ALTER COLUMN "name" SET COMPRESSION pglz`) {
		t.Errorf("db-scope dump missing matview SET COMPRESSION:\n%s", dump)
	}
	// Exactly ONE index statement per scope (double collection in both
	// dumpViews and DumpView would emit two).
	if n := strings.Count(dump, "CREATE UNIQUE INDEX uq_mvx_id"); n != 1 {
		t.Errorf("db-scope dump has %d uq_mvx_id CREATE INDEX statements, want exactly 1:\n%s", n, dump)
	}
	mvDump := export("/db/" + liveDB + "/table/mvx/export")
	if n := strings.Count(mvDump, "CREATE UNIQUE INDEX uq_mvx_id"); n != 1 {
		t.Errorf("table-scope matview dump has %d uq_mvx_id CREATE INDEX statements, want exactly 1:\n%s", n, mvDump)
	}

	// Round-trip the db-scope dump into a fresh database.
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("view-objects import failed (%d):\n%.3000s\n--- dump ---\n%.4000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// Functional INSTEAD OF trigger: an INSERT through the view (using the
	// restored view-column default) lands in the base table.
	if _, err := check.Exec(ctx, `INSERT INTO vins (id) VALUES (7)`); err != nil {
		t.Fatalf("INSERT through restored view failed (INSTEAD OF trigger not functional): %v", err)
	}
	if got := queryRows(t, check, `SELECT name FROM vbase2 WHERE id = 7`); strings.Join(got, "") != "anon" {
		t.Errorf("view INSERT row = %q, want default 'anon' applied via the view-column default", got)
	}
	// Enable states survived.
	if got := queryRows(t, check, `
		SELECT t.tgname || '|' || t.tgenabled::text FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid WHERE c.relname = 'vbase2' AND NOT t.tgisinternal
		ORDER BY t.tgname`); strings.Join(got, ",") != "trg_alw|A,trg_dis|D" {
		t.Errorf("trigger enable states = %v, want [trg_alw|A trg_dis|D]", got)
	}
	// Matview index + column settings survived.
	if got := queryRows(t, check, `SELECT indexname FROM pg_indexes WHERE tablename = 'mvx'`); strings.Join(got, ",") != "uq_mvx_id" {
		t.Errorf("matview indexes = %v, want [uq_mvx_id]", got)
	}
	if got := queryRows(t, check, `SELECT obj_description(('public.uq_mvx_id')::regclass, 'pg_class')`); strings.Join(got, "") != "mv key" {
		t.Errorf("matview index comment = %q, want 'mv key'", got)
	}
	wantSettings := "name|e|123"
	settingsQ := `
		SELECT a.attname || '|' || a.attstorage::text || '|' || COALESCE(to_jsonb(a)->>'attstattarget','')
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
		WHERE c.relname = 'mvx' AND a.attname = 'name'`
	if got := queryRows(t, check, settingsQ); strings.Join(got, "") != wantSettings {
		t.Errorf("matview column settings = %v, want %q", got, wantSettings)
	}
	if pg14 {
		if got := queryRows(t, check, `
			SELECT COALESCE(to_jsonb(a)->>'attcompression','') FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid WHERE c.relname = 'mvx' AND a.attname = 'name'`); strings.Join(got, "") != "p" {
			t.Errorf("matview column compression = %q, want 'p' (pglz)", got)
		}
	}
}

func TestLivePostgresNamedNotNull(t *testing.T) {
	liveNamedNotNull(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveNamedNotNull pins named NOT NULL on PostgreSQL 18+ (skipped below — PG13–17 keep
// the bare attnotnull clause): named/commented/NO INHERIT table NOT NULL
// constraints round-trip; a NOT VALID one over an existing NULL row survives
// NOT VALID with the row intact; a parent-NOT-VALID/child-validated INHERITS
// pair restores the child VALIDATED (post-data VALIDATE CONSTRAINT); a child's
// local NOT NULL merged with an inherited one keeps its provenance and
// survives NO INHERIT detachment; and a STANDALONE table-scope child keeps a
// plain bare NOT NULL (an interim until the named form is materialized).
func liveNamedNotNull(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	if pgServerVersionNum(t, admin) < 180000 {
		t.Skip("named table NOT NULL constraints need PostgreSQL 18+")
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		// Named + commented + NO INHERIT, next to an auto-named bare NOT NULL.
		`CREATE TABLE nn1 (a int, b int NOT NULL, CONSTRAINT nn1_a NOT NULL a NO INHERIT)`,
		`COMMENT ON CONSTRAINT nn1_a ON nn1 IS 'named nn'`,
		// NOT VALID over an existing NULL row: the row must survive the restore
		// and the constraint must stay NOT VALID.
		`CREATE TABLE nnv (x int, y text)`,
		`INSERT INTO nnv VALUES (NULL, 'keepme')`,
		`ALTER TABLE nnv ADD CONSTRAINT nnv_x NOT NULL x NOT VALID`,
		`COMMENT ON CONSTRAINT nnv_x ON nnv IS 'to validate later'`,
		// Parent NOT VALID / child validated (the post-data VALIDATE fix-up),
		// with a child-local comment on the purely-inherited copy.
		`CREATE TABLE nnp (px int, py int)`,
		`CREATE TABLE nnc () INHERITS (nnp)`,
		`INSERT INTO nnp VALUES (NULL, 1)`,
		`ALTER TABLE nnp ADD CONSTRAINT nnp_px NOT NULL px NOT VALID`,
		`ALTER TABLE nnc VALIDATE CONSTRAINT nnp_px`,
		`COMMENT ON CONSTRAINT nnp_px ON nnc IS 'child copy comment'`,
		// A child-LOCAL named NOT NULL merged with an inherited one
		// (conislocal = true AND coninhcount > 0). ADD CONSTRAINT must reuse the
		// inherited name — PostgreSQL rejects a differently-named ADD over an
		// existing inherited copy (an inline CREATE-time declaration may rename;
		// both merge to conislocal = true).
		`CREATE TABLE nnp2 (m int, CONSTRAINT nnp2_m NOT NULL m)`,
		`CREATE TABLE nnc2 () INHERITS (nnp2)`,
		`ALTER TABLE nnc2 ADD CONSTRAINT nnp2_m NOT NULL m`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	fingerprint := func() map[string]string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		out := map[string]string{}
		out["notnull"] = strings.Join(queryRows(t, c, `
			SELECT rel.relname || '|' || con.conname || '|' || pg_get_constraintdef(con.oid, true) ||
			       '|' || con.convalidated || '|' || con.conislocal || '|' || con.coninhcount ||
			       '|' || con.connoinherit
			FROM pg_constraint con
			JOIN pg_class rel ON rel.oid = con.conrelid
			JOIN pg_namespace n ON n.oid = rel.relnamespace
			WHERE n.nspname = 'public' AND con.contype = 'n'
			ORDER BY rel.relname, con.conname`), "\n")
		out["comments"] = strings.Join(queryRows(t, c, `
			SELECT rel.relname || '|' || con.conname || '|' || obj_description(con.oid, 'pg_constraint')
			FROM pg_constraint con
			JOIN pg_class rel ON rel.oid = con.conrelid
			JOIN pg_namespace n ON n.oid = rel.relnamespace
			WHERE n.nspname = 'public' AND con.contype = 'n'
			  AND obj_description(con.oid, 'pg_constraint') IS NOT NULL
			ORDER BY rel.relname, con.conname`), "\n")
		return out
	}
	before := fingerprint()
	if !strings.Contains(before["notnull"], "nn1_a") || !strings.Contains(before["comments"], "child copy comment") {
		t.Fatalf("seed fingerprint looks wrong:\n%v", before)
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	export := func(path string) string {
		resp, err := client.PostForm(ts.URL+path, url.Values{
			"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
		})
		if err != nil {
			t.Fatalf("export %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %s = %d:\n%.2000s", path, resp.StatusCode, b)
		}
		return string(b)
	}
	dump := export("/db/" + liveDB + "/export")
	for _, want := range []string{
		`CONSTRAINT "nn1_a" NOT NULL a NO INHERIT`,    // named + NO INHERIT inline
		`ADD CONSTRAINT "nnv_x" NOT NULL x NOT VALID`, // NOT VALID is post-data
		`VALIDATE CONSTRAINT "nnp_px"`,                // the child fix-up
		"child copy comment",                          // the inherited copy's own comment
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing %q:\n%s", want, dump)
		}
	}
	// The STANDALONE path (this supersedes the interim bare-clause rule):
	// a table-scope export of the INHERITS child MATERIALIZES the inherited
	// named NOT NULL as the child's own constraint — name and comment survive
	// — while the orphan VALIDATE fix-up (which references the parent's state)
	// still never appears.
	childDump := export("/db/" + liveDB + "/table/nnc/export")
	for _, want := range []string{`CONSTRAINT "nnp_px" NOT NULL`, "child copy comment"} {
		if !strings.Contains(childDump, want) {
			t.Errorf("standalone child dump missing materialized %q:\n%s", want, childDump)
		}
	}
	if strings.Contains(childDump, "VALIDATE CONSTRAINT") {
		t.Errorf("standalone child dump must not carry an orphan VALIDATE:\n%s", childDump)
	}

	// Round-trip the db-scope dump.
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("named-NOT-NULL import failed (%d):\n%.3000s\n--- dump ---\n%.5000s", resp.StatusCode, importBody, dump)
	}
	after := fingerprint()
	for k, b := range before {
		if a := after[k]; a != b {
			t.Errorf("%s differs after round-trip:\n--- before ---\n%s\n--- after ---\n%s\n--- dump ---\n%s", k, b, a, dump)
		}
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// The NULL row survived under the NOT VALID constraint.
	if got := queryRows(t, check, `SELECT count(*) FROM nnv WHERE x IS NULL`); strings.Join(got, "") != "1" {
		t.Errorf("nnv NULL row count = %q after restore, want 1", got)
	}
	// Detach: the merged child-local constraint survives NO INHERIT.
	if _, err := check.Exec(ctx, `ALTER TABLE nnc2 NO INHERIT nnp2`); err != nil {
		t.Fatalf("NO INHERIT detach: %v", err)
	}
	if got := queryRows(t, check, `
		SELECT con.conislocal || '|' || con.coninhcount FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		WHERE c.relname = 'nnc2' AND con.contype = 'n'`); strings.Join(got, "") != "true|0" {
		t.Errorf("nnc2 constraint after detach = %v, want [true|0] (local constraint must survive)", got)
	}
}

func TestLivePostgresTypedTablesRules(t *testing.T) {
	liveTypedTablesRules(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveTypedTablesRules pins typed tables and rules: a TYPED table (CREATE TABLE … OF type,
// with per-column WITH OPTIONS deviations) round-trips as a typed table; user
// non-SELECT rewrite rules (on a table and on a view) round-trip with their
// enable state and comments, and are recreated POST-data (an enabled DO ALSO
// rule must not double-apply during the row restore); and an
// extension-ATTACHED table (with rows) and view are still dumped LOOSE —
// definition and rows preserved, never excluded — with the informational
// notice naming them, while CSV export behavior is unchanged.
func liveTypedTablesRules(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
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
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		// A typed table with per-column deviations + a PK.
		`CREATE TYPE pairt AS (k int, v text)`,
		`CREATE TABLE tt OF pairt (k WITH OPTIONS NOT NULL DEFAULT 7, PRIMARY KEY (k))`,
		`INSERT INTO tt VALUES (1, 'a'), (2, 'b')`,
		// Rules — an enabled DO ALSO (post-data placement check), a
		// DISABLED one, a comment, and a DO INSTEAD rule on a view.
		`CREATE TABLE rl (x int)`,
		`CREATE TABLE rlog (x int)`,
		`CREATE RULE r_log AS ON INSERT TO rl DO ALSO INSERT INTO rlog (x) VALUES (NEW.x)`,
		`COMMENT ON RULE r_log ON rl IS 'audit inserts'`,
		`CREATE RULE r_upd AS ON UPDATE TO rl DO INSTEAD NOTHING`,
		`ALTER TABLE rl DISABLE RULE r_upd`,
		`INSERT INTO rl VALUES (1), (2)`, // fires r_log → rlog gets 1,2
		`CREATE VIEW rlview AS SELECT x FROM rl`,
		`CREATE RULE r_vdel AS ON DELETE TO rlview DO INSTEAD DELETE FROM rl WHERE rl.x = OLD.x`,
		// Extension-attached relations stay loose (plpgsql is always
		// installed; ALTER EXTENSION … ADD only associates, never recreates).
		`CREATE TABLE exttab (id int PRIMARY KEY, s text)`,
		`INSERT INTO exttab VALUES (1, 'x'), (2, 'y')`,
		`CREATE VIEW extv AS SELECT id FROM exttab`,
		`ALTER EXTENSION plpgsql ADD TABLE exttab`,
		`ALTER EXTENSION plpgsql ADD VIEW extv`,
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	fingerprint := func() map[string]string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		out := map[string]string{}
		out["typed"] = strings.Join(queryRows(t, c, `
			SELECT c.relname || '|' || c.reloftype::regtype::text
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.reloftype <> 0 ORDER BY c.relname`), "\n")
		out["typed-defaults"] = strings.Join(queryRows(t, c, `
			SELECT a.attname || '|' || a.attnotnull || '|' || COALESCE(pg_get_expr(ad.adbin, ad.adrelid), '')
			FROM pg_attribute a
			LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
			WHERE a.attrelid = 'public.tt'::regclass AND a.attnum > 0 ORDER BY a.attnum`), "\n")
		out["rules"] = strings.Join(queryRows(t, c, `
			SELECT c.relname || '|' || r.rulename || '|' || r.ev_enabled::text || '|' || pg_get_ruledef(r.oid, true)
			FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND r.rulename <> '_RETURN'
			ORDER BY c.relname, r.rulename`), "\n")
		out["rule-comments"] = strings.Join(queryRows(t, c, `
			SELECT r.rulename || '|' || obj_description(r.oid, 'pg_rewrite')
			FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND r.rulename <> '_RETURN'
			  AND obj_description(r.oid, 'pg_rewrite') IS NOT NULL ORDER BY r.rulename`), "\n")
		out["data:tt"] = strings.Join(queryRows(t, c, `SELECT * FROM tt ORDER BY 1`), "\n")
		out["data:rlog"] = strings.Join(queryRows(t, c, `SELECT * FROM rlog ORDER BY 1`), "\n")
		out["data:exttab"] = strings.Join(queryRows(t, c, `SELECT * FROM exttab ORDER BY 1`), "\n")
		out["extv"] = strings.Join(queryRows(t, c, `
			SELECT table_name FROM information_schema.views
			WHERE table_schema = 'public' AND table_name = 'extv'`), "\n")
		return out
	}
	before := fingerprint()
	if before["typed"] != "tt|pairt" || before["data:rlog"] == "" {
		t.Fatalf("seed fingerprint looks wrong:\n%v", before)
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	for _, want := range []string{
		`OF "public"."pairt"`,                    // typed table head
		`WITH OPTIONS`,                           // per-column deviation
		`CREATE RULE r_log`,                      // rules via pg_get_ruledef
		`DISABLE RULE "r_upd"`,                   // rule enable state
		`COMMENT ON RULE "r_log"`,                // rule comment
		`r_vdel`,                                 // view rule
		`"exttab"`,                               // extension-attached table stays loose
		`CREATE OR REPLACE VIEW "public"."extv"`, // extension-attached view stays loose
		`is attached to extension plpgsql`,       // the informational notice
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing %q:\n%s", want, dump)
		}
	}
	if !strings.Contains(dump, "INSERT INTO \"public\".\"exttab\"") {
		t.Errorf("extension-attached table's ROWS missing from dump:\n%s", dump)
	}

	// CSV of the extension-attached table is unchanged (the keep-loose notice is
	// SQL-format-only; the CSV path never consults extension membership).
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/table/exttab/export", url.Values{
		"csrf_token": {csrf}, "format": {"csv"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("csv export: %v", err)
	}
	csvBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(csvBytes), "x") || strings.Contains(string(csvBytes), "WARNING") {
		t.Errorf("CSV export of extension-attached table changed (code %d):\n%s", resp.StatusCode, csvBytes)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("typed-tables/rules import failed (%d):\n%.3000s\n--- dump ---\n%.5000s", resp.StatusCode, importBody, dump)
	}

	after := fingerprint()
	for k, b := range before {
		if a := after[k]; a != b {
			t.Errorf("%s differs after round-trip:\n--- before ---\n%s\n--- after ---\n%s\n--- dump ---\n%s", k, b, a, dump)
		}
	}
	// data:rlog equality above is the post-data placement proof: if the restored
	// r_log rule had been created BEFORE the data phase, the rl INSERTs would
	// have fired it and doubled rlog's rows.

	// The restored rules are functional: an insert routes through r_log.
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	if _, err := check.Exec(ctx, `INSERT INTO rl VALUES (9)`); err != nil {
		t.Fatalf("post-restore insert: %v", err)
	}
	if got := queryRows(t, check, `SELECT count(*) FROM rlog WHERE x = 9`); strings.Join(got, "") != "1" {
		t.Errorf("restored r_log rule not functional: rlog x=9 count = %q, want 1", got)
	}
}

func TestLivePostgresObjectBreadth(t *testing.T) {
	liveObjectBreadth(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveObjectBreadth pins the object surface live: a RANGE type with a
// CANONICAL function restored via the type-shell → support-function →
// type-final bootstrap (with the explicit MULTIRANGE_TYPE_NAME on 14+), a
// BASE type over LANGUAGE internal I/O functions (full physical surface incl.
// ELEMENT/DEFAULT/DELIMITER), full-surface aggregates (moving, ordered-set and
// HYPOTHETICAL — aggkind must survive), a self-commutative operator carrying
// HASHES+MERGES plus a mutually-commutative pair restored via the CREATE-only
// define-first bootstrap (never ALTER OPERATOR), user casts (incl. a
// multirange→range cast PRESERVED while PostgreSQL's auto range→multirange
// cast is EXCLUDED), an operator family with cross-type loose members and a
// non-default opclass, and the foreign-data surface: a provenance-
// recognized postgres_fdw server (allowlisted options only), a user mapping
// (emitted, options redacted), a foreign table with a DISABLED trigger (ALTER
// FOREIGN TABLE), a file_fdw table whose validator-required filename is
// redacted (state-c template, dependents suppressed), an OPTIONLESS custom
// wrapper (executable round-trip) and a spoofed wrapper whose options never
// leak. Plus the table-scope foreign resolver: SQL export works (no data
// pass), CSV/JSON keep the 404.
func liveObjectBreadth(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	pg14 := pgServerVersionNum(t, admin) >= 140000

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	// The FDW extensions ship with contrib (present in the postgres images);
	// skip the whole test politely on a build without them.
	if _, err := seed.Exec(ctx, `CREATE EXTENSION postgres_fdw`); err != nil {
		seed.Close()
		t.Skipf("postgres_fdw extension unavailable: %v", err)
	}
	stmts := []string{
		`CREATE EXTENSION file_fdw`,
		// Aggregates.
		`CREATE FUNCTION agg_acc(int, int) RETURNS int LANGUAGE sql AS 'SELECT $1 + $2'`,
		`CREATE FUNCTION agg_inv(int, int) RETURNS int LANGUAGE sql AS 'SELECT $1 - $2'`,
		`CREATE FUNCTION agg_fin(int) RETURNS text LANGUAGE sql AS $$SELECT 'sum=' || $1$$`,
		`CREATE AGGREGATE mysum(int) (SFUNC = agg_acc, STYPE = int, INITCOND = '0',
			FINALFUNC = agg_fin, MSFUNC = agg_acc, MINVFUNC = agg_inv, MSTYPE = int,
			MINITCOND = '0', MFINALFUNC = agg_fin, PARALLEL = SAFE)`,
		`CREATE FUNCTION osa_trans(int[], int) RETURNS int[] LANGUAGE sql AS 'SELECT $1 || $2'`,
		`CREATE FUNCTION osa_final(int[], int) RETURNS int LANGUAGE sql AS 'SELECT COALESCE($1[$2], 0)'`,
		`CREATE AGGREGATE nth_val(int ORDER BY int) (SFUNC = osa_trans, STYPE = int[], FINALFUNC = osa_final)`,
		`CREATE FUNCTION hyp_final(int[], int) RETURNS int LANGUAGE sql AS 'SELECT 1'`,
		`CREATE AGGREGATE myrank(int ORDER BY int) (SFUNC = osa_trans, STYPE = int[], FINALFUNC = hyp_final, HYPOTHETICAL)`,
		// Operators: self-commutative with HASHES+MERGES, and a mutual pair.
		`CREATE FUNCTION opeq(int8, int8) RETURNS boolean LANGUAGE sql AS 'SELECT $1 = $2'`,
		`CREATE OPERATOR === (FUNCTION = opeq, LEFTARG = int8, RIGHTARG = int8, COMMUTATOR = ===, HASHES, MERGES)`,
		`CREATE FUNCTION oplt(int8, int8) RETURNS boolean LANGUAGE sql AS 'SELECT $1 < $2'`,
		`CREATE FUNCTION opgt(int8, int8) RETURNS boolean LANGUAGE sql AS 'SELECT $1 > $2'`,
		`CREATE OPERATOR <<< (FUNCTION = oplt, LEFTARG = int8, RIGHTARG = int8, COMMUTATOR = >>>)`,
		`CREATE OPERATOR >>> (FUNCTION = opgt, LEFTARG = int8, RIGHTARG = int8, COMMUTATOR = <<<)`,
		// Base type over LANGUAGE internal I/O (the documented bootstrap recipe;
		// superuser).
		`CREATE TYPE myfixed`,
		`CREATE FUNCTION myfixed_in(cstring) RETURNS myfixed AS 'int4in' LANGUAGE internal IMMUTABLE STRICT`,
		`CREATE FUNCTION myfixed_out(myfixed) RETURNS cstring AS 'int4out' LANGUAGE internal IMMUTABLE STRICT`,
		// Range with CANONICAL (shell → internal-language canonical → final).
		`CREATE TYPE seatrange`,
		`CREATE FUNCTION seat_canon(seatrange) RETURNS seatrange AS 'int4range_canonical' LANGUAGE internal IMMUTABLE STRICT`,
		`CREATE TYPE seatrange AS RANGE (SUBTYPE = int4, CANONICAL = seat_canon)`,
		`CREATE TABLE seats (id int PRIMARY KEY, taken seatrange)`,
		`INSERT INTO seats VALUES (1, '[3,7)')`,
		// Casts: a function cast used by a view + a column default (edge-less
		// consumers — class priority orders the cast first).
		`CREATE TYPE colors AS ENUM ('r','g','b')`,
		`CREATE FUNCTION text_to_colors(text) RETURNS colors LANGUAGE sql AS 'SELECT ($1)::colors'`,
		`CREATE CAST (text AS colors) WITH FUNCTION text_to_colors(text) AS ASSIGNMENT`,
		`CREATE VIEW vcast AS SELECT CAST('r'::text AS colors) AS c`,
		`CREATE TABLE tcast (id int PRIMARY KEY, c colors DEFAULT CAST('g'::text AS colors))`,
		// Operator family with cross-type loose members + a non-default opclass.
		`CREATE OPERATOR FAMILY myfam USING btree`,
		`ALTER OPERATOR FAMILY myfam USING btree ADD OPERATOR 1 <(int4, int8), FUNCTION 1 btint48cmp(int4, int8)`,
		`CREATE OPERATOR CLASS colors_ops FOR TYPE colors USING hash AS
			OPERATOR 1 =(anyenum, anyenum), FUNCTION 1 hashenum(anyenum)`,
		// Foreign data: recognized postgres_fdw (fetch_size is valid but not
		// allowlisted → redacted+warned), user mapping (credentials redacted),
		// foreign table with a DISABLED trigger.
		`CREATE SERVER remote_pg FOREIGN DATA WRAPPER postgres_fdw
			OPTIONS (host 'remote.example', port '5433', dbname 'appdb', fetch_size '111')`,
		`CREATE USER MAPPING FOR postgres SERVER remote_pg OPTIONS ("user" 'ruser', password 'rpass')`,
		`CREATE FOREIGN TABLE ftab (id int NOT NULL, note text)
			SERVER remote_pg OPTIONS (schema_name 'public', table_name 'src')`,
		`CREATE FUNCTION ftnoop() RETURNS trigger LANGUAGE plpgsql AS 'begin return new; end'`,
		`CREATE TRIGGER ftrg BEFORE INSERT ON ftab FOR EACH ROW EXECUTE FUNCTION ftnoop()`,
		`ALTER FOREIGN TABLE ftab DISABLE TRIGGER ftrg`,
		// file_fdw: filename is validator-REQUIRED and redacted → state (c)
		// template; its trigger must be suppressed with it.
		`CREATE SERVER files FOREIGN DATA WRAPPER file_fdw`,
		`CREATE FOREIGN TABLE fcsv (a text) SERVER files OPTIONS (filename '/tmp/secret_path.csv', format 'csv')`,
		`CREATE TRIGGER fcsv_trg BEFORE INSERT ON fcsv FOR EACH ROW EXECUTE FUNCTION ftnoop()`,
		// An OPTIONLESS custom wrapper is fully reproducible (executable DDL);
		// a spoofed wrapper WITH options is templated and never leaks them.
		`CREATE FOREIGN DATA WRAPPER plainw`,
		`CREATE SERVER plains FOREIGN DATA WRAPPER plainw`,
		`CREATE FOREIGN DATA WRAPPER fakefdw OPTIONS (secret 'donotleak')`,
	}
	// The fixed-length ELEMENT base type: PG14+ requires a SUBSCRIPT function
	// alongside ELEMENT (which also exercises the SUBSCRIPT dump gate); PG13
	// takes ELEMENT alone.
	baseCreate := `CREATE TYPE myfixed (INPUT = myfixed_in, OUTPUT = myfixed_out, INTERNALLENGTH = 4,
		PASSEDBYVALUE, ALIGNMENT = int4, STORAGE = plain, CATEGORY = 'N',
		DEFAULT = '42', ELEMENT = int4, DELIMITER = ';'`
	if pg14 {
		baseCreate += `, SUBSCRIPT = raw_array_subscript_handler`
	}
	stmts = append(stmts, baseCreate+`)`)
	if pg14 {
		stmts = append(stmts,
			`CREATE FUNCTION mr_merge(seatmultirange) RETURNS seatrange LANGUAGE sql AS 'SELECT range_merge($1)'`,
			`CREATE CAST (seatmultirange AS seatrange) WITH FUNCTION mr_merge(seatmultirange)`,
		)
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	// Round-trip fingerprints for the classes that restore FULLY (casts,
	// operators, aggregates, types, opfamily members). Foreign options are
	// asserted directly post-restore (redacted keys are EXPECTED to be gone).
	fingerprint := func() map[string]string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		out := map[string]string{}
		out["casts"] = strings.Join(queryRows(t, c, `
			SELECT pg_catalog.format_type(ca.castsource, NULL) || '>' || pg_catalog.format_type(ca.casttarget, NULL) ||
			       '|' || ca.castcontext::text || '|' || ca.castmethod::text
			FROM pg_cast ca WHERE ca.oid >= 16384 ORDER BY 1`), "\n")
		out["operators"] = strings.Join(queryRows(t, c, `
			SELECT o.oprname || '|' ||
			       CASE WHEN o.oprcom = 0 THEN '' ELSE o.oprcom::regoper::text END || '|' ||
			       CASE WHEN o.oprnegate = 0 THEN '' ELSE o.oprnegate::regoper::text END || '|' ||
			       o.oprcanhash || '|' || o.oprcanmerge
			FROM pg_operator o JOIN pg_namespace n ON n.oid = o.oprnamespace
			WHERE n.nspname = 'public' AND o.oprcode <> 0
			ORDER BY o.oprname, o.oprleft, o.oprright`), "\n")
		out["aggregates"] = strings.Join(queryRows(t, c, `
			SELECT p.proname || '|' || agg.aggkind::text || '|' || agg.aggnumdirectargs ||
			       '|' || COALESCE(agg.agginitval, '<null>') || '|' || agg.aggmtransfn::regproc::text
			FROM pg_proc p JOIN pg_aggregate agg ON agg.aggfnoid = p.oid
			JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = 'public' ORDER BY p.proname`), "\n")
		out["basetype"] = strings.Join(queryRows(t, c, `
			SELECT t.typname || '|' || t.typlen || '|' || t.typbyval || '|' || t.typalign::text ||
			       '|' || t.typstorage::text || '|' || t.typcategory::text || '|' || t.typdelim::text ||
			       '|' || COALESCE(t.typdefault, '<null>') || '|' || el.typname
			FROM pg_type t JOIN pg_type el ON el.oid = t.typelem
			JOIN pg_namespace n ON n.oid = t.typnamespace
			WHERE n.nspname = 'public' AND t.typname = 'myfixed'`), "\n")
		out["range"] = strings.Join(queryRows(t, c, `
			SELECT t.typname || '|' || pg_catalog.format_type(rng.rngsubtype, NULL) || '|' ||
			       rng.rngcanonical::regproc::text || '|' ||
			       COALESCE((SELECT mt.typname FROM pg_type mt
			                 WHERE mt.oid = COALESCE((to_jsonb(rng)->>'rngmultitypid')::bigint, 0)), '')
			FROM pg_range rng JOIN pg_type t ON t.oid = rng.rngtypid
			JOIN pg_namespace n ON n.oid = t.typnamespace
			WHERE n.nspname = 'public' ORDER BY t.typname`), "\n")
		out["famloose"] = strings.Join(queryRows(t, c, `
			SELECT ao.amopstrategy || '|' || ao.amopopr::regoperator::text
			FROM pg_amop ao JOIN pg_opfamily f ON f.oid = ao.amopfamily
			JOIN pg_namespace n ON n.oid = f.opfnamespace
			WHERE n.nspname = 'public' AND f.opfname = 'myfam' ORDER BY 1`), "\n")
		out["opclass"] = strings.Join(queryRows(t, c, `
			SELECT c.opcname || '|' || am.amname || '|' || c.opcdefault
			FROM pg_opclass c JOIN pg_am am ON am.oid = c.opcmethod
			JOIN pg_namespace n ON n.oid = c.opcnamespace
			WHERE n.nspname = 'public' ORDER BY c.opcname`), "\n")
		out["data:seats"] = strings.Join(queryRows(t, c, `SELECT * FROM seats ORDER BY 1`), "\n")
		return out
	}
	before := fingerprint()
	if !strings.Contains(before["aggregates"], "myrank|h") || before["basetype"] == "" {
		t.Fatalf("seed fingerprint looks wrong:\n%v", before)
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}

	for _, want := range []string{
		`CREATE TYPE "public"."seatrange"`, // the shell
		`CREATE TYPE "public"."seatrange" AS RANGE (SUBTYPE = integer, CANONICAL = public.seat_canon`,
		`CREATE TYPE "public"."myfixed" (INPUT = public.myfixed_in`,
		"PASSEDBYVALUE",
		"ELEMENT = integer",
		`CREATE OR REPLACE AGGREGATE "public"."myrank"`,
		"HYPOTHETICAL",
		"HASHES",
		"MERGES",
		`CREATE CAST (text AS public.colors) WITH FUNCTION public.text_to_colors(text) AS ASSIGNMENT`,
		`CREATE OPERATOR FAMILY "public"."myfam" USING "btree"`,
		`ALTER OPERATOR FAMILY "public"."myfam" USING "btree" ADD`,
		`CREATE OPERATOR CLASS "public"."colors_ops"`,
		`CREATE SERVER "remote_pg"`,
		`host 'remote.example'`,
		`CREATE USER MAPPING FOR "postgres" SERVER "remote_pg"`,
		`CREATE FOREIGN TABLE "public"."ftab"`,
		`schema_name 'public'`,
		`ALTER FOREIGN TABLE "public"."ftab" DISABLE TRIGGER "ftrg"`,
		`CREATE FOREIGN DATA WRAPPER "plainw"`,
		`CREATE SERVER "plains"`,
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing %q:\n%s", want, dump)
		}
	}
	if pg14 {
		if !strings.Contains(dump, `MULTIRANGE_TYPE_NAME = "public"."seatmultirange"`) {
			t.Errorf("dump missing the explicit multirange name:\n%s", dump)
		}
		if !strings.Contains(dump, `CREATE CAST (public.seatmultirange AS public.seatrange)`) {
			t.Errorf("user multirange→range cast must be PRESERVED:\n%s", dump)
		}
		if strings.Contains(dump, `CREATE CAST (public.seatrange AS public.seatmultirange)`) {
			t.Errorf("PostgreSQL's auto range→multirange cast must be EXCLUDED:\n%s", dump)
		}
	}
	for _, notWant := range []string{
		// CREATE-only commutator/negator/hashes/merges bootstrap on every
		// version — never the PG17+ ALTER OPERATOR SET forms. ("ALTER OPERATOR
		// FAMILY … ADD" is legitimate, so match the SET grammar.)
		"SET (COMMUTATOR", "SET (NEGATOR", "SET (HASHES", "SET (MERGES",
		"'rpass'", "'ruser'", // user-mapping credential VALUES
		"donotleak",   // spoofed-wrapper option value
		"secret_path", // file_fdw filename value
		"'111'",       // the redacted fetch_size VALUE
		// State (c): fcsv rides only an inert comment-line template — never an
		// executable statement — and its trigger is suppressed with it.
		"\nCREATE FOREIGN TABLE \"public\".\"fcsv\"",
		`ON "public"."fcsv"`,
	} {
		if strings.Contains(dump, notWant) {
			t.Errorf("dump must not contain %q:\n%s", notWant, dump)
		}
	}
	// The state-(c) template and the redaction notices are present as warnings.
	for _, want := range []string{
		"foreign table public.fcsv is not dumped",
		"options fetch_size are redacted",
		"ALL its options are redacted",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing warning %q:\n%s", want, dump)
		}
	}

	// Table-scope foreign export: SQL resolves (explicit and omitted format),
	// emits no data pass; CSV keeps the 404.
	for _, form := range []url.Values{
		{"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}},
		{"csrf_token": {csrf}, "structure": {"1"}, "data": {"1"}},
	} {
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/table/ftab/export", form)
		if err != nil {
			t.Fatalf("foreign table export: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), `CREATE FOREIGN TABLE "public"."ftab"`) {
			t.Errorf("table-scope foreign export = %d:\n%.2000s", resp.StatusCode, b)
		}
		if strings.Contains(string(b), "INSERT INTO") {
			t.Errorf("table-scope foreign export must have NO data pass:\n%s", b)
		}
	}
	// Every ROW-STREAMING format keeps the 404. The handler gate is "not a data
	// format" (isDataFormat) rather than a list of exclusions, because an
	// unrecognized format falls through to the SQL path — so a new format
	// missing from that list would resolve the foreign table as structure-only
	// and then stream its rows from the REMOTE server. Adding a format here is
	// how that stays caught.
	for _, format := range []string{"csv", "json", "xml"} {
		resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/table/ftab/export", url.Values{
			"csrf_token": {csrf}, "format": {format}, "structure": {"1"}, "data": {"1"},
		})
		if err != nil {
			t.Fatalf("foreign %s export: %v", format, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s export of a foreign table = %d, want 404", format, resp.StatusCode)
		}
	}

	// Round-trip: fresh DB with the extensions PRE-SEEDED (state (b): CREATE
	// EXTENSION recreates the wrappers the dump references but never emits).
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	pre, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("preseed connect: %v", err)
	}
	for _, stmt := range []string{`CREATE EXTENSION postgres_fdw`, `CREATE EXTENSION file_fdw`} {
		if _, err := pre.Exec(ctx, stmt); err != nil {
			pre.Close()
			t.Fatalf("preseed %q: %v", stmt, err)
		}
	}
	pre.Close()
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("object-breadth import failed (%d):\n%.3000s\n--- dump ---\n%.9000s", resp.StatusCode, importBody, dump)
	}

	after := fingerprint()
	for k, b := range before {
		if a := after[k]; a != b {
			t.Errorf("%s differs after round-trip:\n--- before ---\n%s\n--- after ---\n%s", k, b, a)
		}
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// The restored aggregate works end to end.
	if got := queryRows(t, check, `SELECT mysum(v) FROM (VALUES (1),(2)) t(v)`); strings.Join(got, "") != "sum=3" {
		t.Errorf("mysum = %q after restore, want sum=3", got)
	}
	// Foreign structure survived: allowlisted server options only, the user
	// mapping exists (options gone — redacted by policy), the disabled
	// foreign-table trigger stayed disabled, fcsv stayed un-restored (template).
	if got := queryRows(t, check, `
		SELECT array_to_string(srvoptions, ',') FROM pg_foreign_server WHERE srvname = 'remote_pg'`); strings.Join(got, "") != "host=remote.example,port=5433,dbname=appdb" {
		t.Errorf("restored remote_pg options = %v, want the allowlisted trio only", got)
	}
	if got := queryRows(t, check, `SELECT count(*) FROM pg_user_mapping um JOIN pg_foreign_server s ON s.oid = um.umserver WHERE s.srvname = 'remote_pg'`); strings.Join(got, "") != "1" {
		t.Errorf("user mapping not restored: %v", got)
	}
	if got := queryRows(t, check, `
		SELECT t.tgenabled::text FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
		WHERE c.relname = 'ftab' AND t.tgname = 'ftrg'`); strings.Join(got, "") != "D" {
		t.Errorf("foreign-table trigger state = %v, want D (disabled)", got)
	}
	if got := queryRows(t, check, `SELECT count(*) FROM pg_class WHERE relname = 'fcsv'`); strings.Join(got, "") != "0" {
		t.Errorf("state-(c) fcsv must NOT restore (template only): %v", got)
	}
	// The optionless custom wrapper + server round-tripped as executable DDL.
	if got := queryRows(t, check, `SELECT count(*) FROM pg_foreign_data_wrapper WHERE fdwname = 'plainw'`); strings.Join(got, "") != "1" {
		t.Errorf("optionless custom wrapper must round-trip: %v", got)
	}
	// The spoofed wrapper's secret never landed anywhere.
	if got := queryRows(t, check, `SELECT count(*) FROM pg_foreign_data_wrapper WHERE fdwname = 'fakefdw'`); strings.Join(got, "") != "0" {
		t.Errorf("spoofed wrapper must not restore executable: %v", got)
	}
}

func TestLivePostgresTopology(t *testing.T) {
	liveTopology(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveTopology pins the unified cross-schema/cross-phase topological
// ordering on both export paths: a domain in an EARLIER schema over a
// composite in a LATER one, a composite-typed table across schemas, a
// cross-schema view-over-view, a PG14+ BEGIN ATOMIC function reading a LATER
// schema's table (edges must hoist the table above the routine class), a
// 3-schema matview-refresh chain whose alphabetical order would refresh the
// dependent first, a cross-schema routine default-arg chain, an overloaded
// routine pair with distinct identities, shadowed same-named cross-schema
// tables under the pinned empty search_path, and finally the same
// catalog through the SERVER-scope export (previously per-schema sections that
// hid every cross-schema dependency).
func liveTopology(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	requireIsolatedServerScope(t, admin, env.engine)
	pg14 := pgServerVersionNum(t, admin) >= 140000

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	stmts := []string{
		`CREATE SCHEMA s_a`, `CREATE SCHEMA s_b`, `CREATE SCHEMA s_c`,
		// Cross-schema type-over-type + composite-typed table: the s_a objects
		// depend on the LATER (alphabetically) s_b composite.
		`CREATE TYPE s_b.zz_base AS (k int, v text)`,
		`CREATE DOMAIN s_a.aa_dom AS s_b.zz_base`,
		`CREATE TABLE s_a.aa_dep (id int PRIMARY KEY, payload s_b.zz_base)`,
		`INSERT INTO s_a.aa_dep VALUES (1, ROW(7, 'x'))`,
		// Cross-schema view-over-view.
		`CREATE VIEW s_b.v_src AS SELECT 1 AS x`,
		`CREATE VIEW s_a.v_dep AS SELECT x FROM s_b.v_src`,
		// 3-schema matview chain: alphabetical refresh (m3 first) would fail.
		`CREATE MATERIALIZED VIEW s_c.m1 AS SELECT 5 AS n`,
		`CREATE MATERIALIZED VIEW s_b.m2 AS SELECT n FROM s_c.m1`,
		`CREATE MATERIALIZED VIEW s_a.m3 AS SELECT n FROM s_b.m2`,
		// Cross-schema routine default-arg chain.
		`CREATE FUNCTION s_b.base_fn() RETURNS int LANGUAGE sql AS 'SELECT 7'`,
		`CREATE FUNCTION s_a.wrap_fn(x int DEFAULT s_b.base_fn()) RETURNS int LANGUAGE sql AS 'SELECT x'`,
		// Overloads: distinct graph identities, deterministic fingerprints.
		`CREATE FUNCTION s_a.over(i int) RETURNS int LANGUAGE sql AS 'SELECT 1'`,
		`CREATE FUNCTION s_a.over(t text) RETURNS int LANGUAGE sql AS 'SELECT 2'`,
		// Shadowed cross-schema names: the deparse must fully qualify under the
		// pinned empty search_path or the view resolves the WRONG shadow.
		`CREATE TABLE s_a.shadow (v text)`,
		`INSERT INTO s_a.shadow VALUES ('wrong')`,
		`CREATE TABLE s_b.shadow (v text)`,
		`INSERT INTO s_b.shadow VALUES ('right')`,
		`CREATE VIEW s_a.vshadow AS SELECT v FROM s_b.shadow`,
	}
	if pg14 {
		// A BEGIN ATOMIC body reading a LATER schema's table: parsed at CREATE,
		// so the table must be hoisted above the routine despite class priority.
		stmts = append(stmts,
			`CREATE TABLE s_b.tt2 (id int)`,
			`INSERT INTO s_b.tt2 VALUES (1), (2)`,
			`CREATE FUNCTION s_a.readtab() RETURNS bigint LANGUAGE sql BEGIN ATOMIC SELECT count(*) FROM s_b.tt2; END`,
		)
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	fingerprint := func() map[string]string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		out := map[string]string{}
		out["types"] = strings.Join(queryRows(t, c, `
			SELECT n.nspname || '.' || t.typname || '|' || t.typtype::text
			FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
			WHERE n.nspname IN ('s_a','s_b','s_c') AND t.typtype IN ('c','d')
			  AND (t.typtype <> 'c' OR EXISTS (SELECT 1 FROM pg_class pc WHERE pc.oid = t.typrelid AND pc.relkind = 'c'))
			ORDER BY 1`), "\n")
		out["functions"] = strings.Join(queryRows(t, c, `
			SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
			FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname IN ('s_a','s_b','s_c')
			ORDER BY 1`), "\n")
		out["views"] = strings.Join(queryRows(t, c, `
			SELECT schemaname || '.' || viewname || '|' || definition FROM pg_views
			WHERE schemaname IN ('s_a','s_b') ORDER BY 1`), "\n")
		out["matview-populated"] = strings.Join(queryRows(t, c, `
			SELECT schemaname || '.' || matviewname || '|' || ispopulated FROM pg_matviews
			WHERE schemaname IN ('s_a','s_b','s_c') ORDER BY 1`), "\n")
		out["data:aa_dep"] = strings.Join(queryRows(t, c, `SELECT * FROM s_a.aa_dep ORDER BY 1`), "\n")
		out["data:m3"] = strings.Join(queryRows(t, c, `SELECT * FROM s_a.m3`), "\n")
		out["vshadow"] = strings.Join(queryRows(t, c, `SELECT * FROM s_a.vshadow`), "\n")
		return out
	}
	before := fingerprint()
	if before["vshadow"] != "right" || !strings.Contains(before["types"], "s_a.aa_dom") {
		t.Fatalf("seed fingerprint looks wrong:\n%v", before)
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	export := func(path string) string {
		resp, err := client.PostForm(ts.URL+path, url.Values{
			"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
		})
		if err != nil {
			t.Fatalf("export %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %s = %d:\n%.2000s", path, resp.StatusCode, b)
		}
		return string(b)
	}
	restore := func(label, path, dump string) {
		liveDropDB(t, admin, env.engine)
		liveCreateDB(t, admin)
		resp, err := client.PostForm(ts.URL+path, url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
		if err != nil {
			t.Fatalf("import %s: %v", label, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "tx-alert-error") {
			t.Fatalf("%s import failed (%d):\n%.3000s\n--- dump ---\n%.6000s", label, resp.StatusCode, body, dump)
		}
	}

	// Database-scope round-trip: ordering anchors + full fingerprint equality.
	dump := export("/db/" + liveDB + "/export")
	for _, pair := range [][2]string{
		{`CREATE TYPE "s_b"."zz_base"`, `CREATE DOMAIN "s_a"."aa_dom"`},                  // type before cross-schema domain
		{`CREATE TYPE "s_b"."zz_base"`, `CREATE TABLE "s_a"."aa_dep"`},                   // type before cross-schema table
		{`CREATE OR REPLACE VIEW "s_b"."v_src"`, `CREATE OR REPLACE VIEW "s_a"."v_dep"`}, // view before dependent
		{`REFRESH MATERIALIZED VIEW "s_c"."m1"`, `REFRESH MATERIALIZED VIEW "s_b"."m2"`},
		{`REFRESH MATERIALIZED VIEW "s_b"."m2"`, `REFRESH MATERIALIZED VIEW "s_a"."m3"`},
	} {
		i, j := strings.Index(dump, pair[0]), strings.Index(dump, pair[1])
		if i < 0 || j < 0 || i > j {
			t.Errorf("ordering anchor %q must precede %q (at %d / %d):\n%s", pair[0], pair[1], i, j, dump)
		}
	}
	if pg14 {
		// Anchor on the CREATE, not the bare name: the teardown names the
		// function in a DROP long before any CREATE runs.
		i, j := strings.Index(dump, `CREATE TABLE "s_b"."tt2"`), strings.Index(dump, "FUNCTION s_a.readtab")
		if i < 0 || j < 0 || i > j {
			t.Errorf("atomic function's table must be hoisted before it (table@%d fn@%d):\n%s", i, j, dump)
		}
	}
	restore("db-scope", "/db/"+liveDB+"/import", dump)
	after := fingerprint()
	for k, b := range before {
		if a := after[k]; a != b {
			t.Errorf("%s differs after db-scope round-trip:\n--- before ---\n%s\n--- after ---\n%s", k, b, a)
		}
	}
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	if got := queryRows(t, check, `SELECT s_a.wrap_fn()`); strings.Join(got, "") != "7" {
		t.Errorf("wrap_fn() default-arg chain = %q after restore, want 7", got)
	}
	if pg14 {
		if got := queryRows(t, check, `SELECT s_a.readtab()`); strings.Join(got, "") != "2" {
			t.Errorf("readtab() = %q after restore, want 2", got)
		}
	}
	check.Close()

	// Server-scope round-trip over the SAME (restored) catalog — the path that
	// previously wrote complete per-schema sections.
	serverDump := export("/server/export")
	if !strings.Contains(serverDump, `\connect "`+liveDB+`"`) {
		t.Fatalf("server dump missing the \\connect marker:\n%.2000s", serverDump)
	}
	i, j := strings.Index(serverDump, `CREATE TYPE "s_b"."zz_base"`), strings.Index(serverDump, `CREATE TABLE "s_a"."aa_dep"`)
	if i < 0 || j < 0 || i > j {
		t.Errorf("server dump: cross-schema type must precede its consumer (type@%d table@%d):\n%s", i, j, serverDump)
	}
	restore("server-scope", "/server/import", serverDump)
	after = fingerprint()
	for k, b := range before {
		if a := after[k]; a != b {
			t.Errorf("%s differs after server-scope round-trip:\n--- before ---\n%s\n--- after ---\n%s", k, b, a)
		}
	}
}

func TestLivePostgresCycles(t *testing.T) {
	liveCycles(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveCycles pins the cycle-resolution engine live, the four staged shapes
// the commit gates on: a mutually-recursive BEGIN ATOMIC pair (routine stubs +
// CREATE OR REPLACE finals), a cyclic default-argument routine pair (defaults
// omitted from the stubs, restored by the finals), a domain DEFAULT calling a
// function returning that domain (deferred clause → ALTER DOMAIN in the
// pre-data finalizer lane, with the consuming table retargeted after it), a
// view-column default calling a routine that reads the view (the default's own
// node — no staging needed), and an atomic function reading a table whose
// inline column default calls it (deferrable table edge → staged post-data
// SET DEFAULT).
func liveCycles(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	pg14 := pgServerVersionNum(t, admin) >= 140000

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	stmts := []string{
		// Cyclic default-argument pair (plpgsql — works on the PG13 floor). The
		// defaults use EXPLICIT arguments for the other routine: a default
		// relying on the OTHER staged routine's defaults is the documented
		// unrestorable residual (pg_dump cannot restore ANY default-arg cycle).
		`CREATE FUNCTION cyc_a(x int) RETURNS int LANGUAGE plpgsql AS 'begin return x; end'`,
		`CREATE FUNCTION cyc_b(y int DEFAULT cyc_a(41)) RETURNS int LANGUAGE plpgsql AS 'begin return y + 1; end'`,
		`CREATE OR REPLACE FUNCTION cyc_a(x int DEFAULT cyc_b(0)) RETURNS int LANGUAGE plpgsql AS 'begin return x; end'`,
		// Domain default calling a function returning that domain.
		`CREATE DOMAIN money2 AS int`,
		`CREATE FUNCTION mkmoney() RETURNS money2 LANGUAGE sql AS 'SELECT 42'`,
		`ALTER DOMAIN money2 SET DEFAULT mkmoney()`,
		`CREATE TABLE uses_dom (id int PRIMARY KEY, amt money2)`,
		`INSERT INTO uses_dom (id) VALUES (1)`,
	}
	if pg14 {
		stmts = append(stmts,
			// Mutually-recursive BEGIN ATOMIC pair (real pg_depend edges both ways).
			`CREATE FUNCTION even_f(n int) RETURNS boolean LANGUAGE sql AS 'SELECT true'`,
			`CREATE FUNCTION odd_f(n int) RETURNS boolean LANGUAGE sql BEGIN ATOMIC SELECT CASE WHEN n = 0 THEN false ELSE even_f(n - 1) END; END`,
			`CREATE OR REPLACE FUNCTION even_f(n int) RETURNS boolean LANGUAGE sql BEGIN ATOMIC SELECT CASE WHEN n = 0 THEN true ELSE odd_f(n - 1) END; END`,
			// View-column default calling an atomic routine that reads the view.
			`CREATE TABLE vd_base (id int, val int)`,
			`INSERT INTO vd_base VALUES (1, 10)`,
			`CREATE VIEW vd_v AS SELECT id, val FROM vd_base`,
			`CREATE FUNCTION vd_next() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT COALESCE(max(val), 0) + 1 FROM vd_v; END`,
			`ALTER VIEW vd_v ALTER COLUMN val SET DEFAULT vd_next()`,
			// Atomic function reading a table whose inline default calls it.
			`CREATE TABLE selfd (id int PRIMARY KEY, ver int DEFAULT 1)`,
			`CREATE FUNCTION selfd_next() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT COALESCE(max(ver), 0) + 1 FROM selfd; END`,
			`ALTER TABLE selfd ALTER COLUMN ver SET DEFAULT selfd_next()`,
			`INSERT INTO selfd (id) VALUES (1)`,
			`INSERT INTO selfd (id) VALUES (2)`,
		)
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	// The staged shapes are visible in the dump text.
	if !strings.Contains(dump, `ALTER DOMAIN "public"."money2" SET DEFAULT`) {
		t.Errorf("dump missing the deferred ALTER DOMAIN … SET DEFAULT:\n%s", dump)
	}
	// The domain's deferred default must precede the consuming table.
	di, ti := strings.Index(dump, `ALTER DOMAIN "public"."money2" SET DEFAULT`), strings.Index(dump, `CREATE TABLE "public"."uses_dom"`)
	if di < 0 || ti < 0 || di > ti {
		t.Errorf("deferred domain default must precede its consuming table (alter@%d table@%d):\n%s", di, ti, dump)
	}
	if pg14 {
		if !strings.Contains(dump, "LANGUAGE sql AS 'SELECT NULL'") {
			t.Errorf("dump missing routine cycle stubs:\n%s", dump)
		}
		// The staged table default lands post-data (after the selfd INSERTs).
		si, ii := strings.Index(dump, `ALTER TABLE ONLY "public"."selfd" ALTER COLUMN "ver" SET DEFAULT`), strings.Index(dump, `INSERT INTO "public"."selfd"`)
		if si < 0 || ii < 0 || si < ii {
			t.Errorf("staged table default must follow the data phase (alter@%d insert@%d):\n%s", si, ii, dump)
		}
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("cycles import failed (%d):\n%.3000s\n--- dump ---\n%.8000s", resp.StatusCode, importBody, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	// Cyclic default-arg pair restored WITH its defaults.
	if got := queryRows(t, check, `SELECT cyc_a()`); strings.Join(got, "") != "1" {
		t.Errorf("cyc_a() = %q after restore, want 1 (default cyc_b(0) = 0+1)", got)
	}
	if got := queryRows(t, check, `SELECT cyc_b()`); strings.Join(got, "") != "42" {
		t.Errorf("cyc_b() = %q after restore, want 42 (default cyc_a(41)+1)", got)
	}
	// Domain default functional: an INSERT without amt gets 42.
	if _, err := check.Exec(ctx, `INSERT INTO uses_dom (id) VALUES (9)`); err != nil {
		t.Fatalf("post-restore domain-default insert: %v", err)
	}
	if got := queryRows(t, check, `SELECT amt FROM uses_dom WHERE id = 9`); strings.Join(got, "") != "42" {
		t.Errorf("uses_dom.amt = %q after restore, want the domain default 42", got)
	}
	if pg14 {
		// The mutually-recursive pair works (real bodies restored).
		if got := queryRows(t, check, `SELECT even_f(4) || '|' || odd_f(3)`); strings.Join(got, "") != "true|true" {
			t.Errorf("mutual recursion = %q after restore, want true|true", got)
		}
		// The view-column default survived as its own deferred node.
		if got := queryRows(t, check, `
			SELECT pg_get_expr(ad.adbin, ad.adrelid) FROM pg_attrdef ad
			JOIN pg_class c ON c.oid = ad.adrelid WHERE c.relname = 'vd_v'`); !strings.Contains(strings.Join(got, ""), "vd_next()") {
			t.Errorf("vd_v column default = %q after restore, want vd_next()", got)
		}
		// The staged table default is functional and the rows survived.
		if got := queryRows(t, check, `SELECT count(*) FROM selfd`); strings.Join(got, "") != "2" {
			t.Errorf("selfd rows = %q after restore, want 2", got)
		}
		if _, err := check.Exec(ctx, `INSERT INTO selfd (id) VALUES (3)`); err != nil {
			t.Fatalf("post-restore staged-default insert: %v", err)
		}
		if got := queryRows(t, check, `SELECT ver FROM selfd WHERE id = 3`); strings.Join(got, "") != "3" {
			t.Errorf("selfd.ver = %q after restore, want 3 (staged default restored)", got)
		}
	}
}

func TestLivePostgresStandaloneChildren(t *testing.T) {
	liveStandaloneChildren(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveStandaloneChildren pins the standalone-child and replacement-sequence behaviour live: a table-scope export of an
// INHERITS child materializes it standalone with its inherited constraints and
// a tablex_seq_* replacement for the parent's serial sequence (never naming the
// source); a partition child materializes with a synthesized bound CHECK,
// cloned trigger (with enable state) and attached index; a HASH child warns and
// emits no unstable CHECK; a PG17+ identity partition inlines its replacement
// via SEQUENCE NAME with the source's options and NO standalone CREATE
// SEQUENCE; late-bound '…'::text references are rewritten while dynamic ones
// warn; data-only dumps target the ORIGINAL sequences with no tablex_seq_*;
// structure-only dumps carry no setval/REFRESH and matviews restore
// WITH NO DATA; a normal db-scope dump preserves OWNED BY under multiple
// consumers and the PG15+ identity-sequence persistence delta.
func liveStandaloneChildren(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	vnum := pgServerVersionNum(t, admin)
	pg15, pg17 := vnum >= 150000, vnum >= 170000

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	stmts := []string{
		// Inherited serial: the child's default names the parent's sequence.
		`CREATE TABLE par (id serial PRIMARY KEY, note text, CONSTRAINT par_pos CHECK (id >= 0))`,
		`CREATE TABLE chi (extra int) INHERITS (par)`,
		`INSERT INTO par (note) VALUES ('p1'), ('p2')`,
		`INSERT INTO chi (note, extra) VALUES ('c1', 7)`,
		// Customized cross-schema standalone sequence + early/late/dynamic refs.
		`CREATE SCHEMA xsrc`,
		`CREATE SEQUENCE xsrc.custom_sm AS smallint START WITH 100 INCREMENT BY 5 MINVALUE 50 MAXVALUE 30000 CACHE 3 CYCLE`,
		`COMMENT ON SEQUENCE xsrc.custom_sm IS 'customized counter'`,
		`CREATE TABLE seqcons (a int, b int DEFAULT nextval('xsrc.custom_sm'), c int DEFAULT nextval('xsrc.custom_sm'::text), dyn int DEFAULT nextval(('xsrc' || '.custom_sm')::regclass))`,
		// One owner, two consumers: consumer count never forces OWNED BY NONE.
		`CREATE SEQUENCE owned_seq`,
		`CREATE TABLE ownert (k int DEFAULT nextval('owned_seq'))`,
		`CREATE TABLE sibling (k int DEFAULT nextval('owned_seq'))`,
		`ALTER SEQUENCE owned_seq OWNED BY ownert.k`,
		// Partition tree: cloned trigger (disabled on the child), attached index.
		`CREATE TABLE proot (id int NOT NULL, v text) PARTITION BY RANGE (id)`,
		`CREATE TABLE pc1 PARTITION OF proot FOR VALUES FROM (0) TO (100)`,
		`CREATE INDEX proot_v_idx ON proot (v)`,
		`CREATE FUNCTION trg_f() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'`,
		`CREATE TRIGGER ptrg BEFORE INSERT ON proot FOR EACH ROW EXECUTE FUNCTION trg_f()`,
		`ALTER TABLE pc1 DISABLE TRIGGER ptrg`,
		`INSERT INTO proot VALUES (1, 'a'), (2, 'b')`,
		// Hash partition: the bound embeds the parent OID — warn, no CHECK.
		`CREATE TABLE hroot (h int) PARTITION BY HASH (h)`,
		`CREATE TABLE hc0 PARTITION OF hroot FOR VALUES WITH (MODULUS 2, REMAINDER 0)`,
		// A serial-style sequence owned by a partition CHILD. Children are
		// folded out of the exported table list (their DDL rides the root's
		// PARTITION OF), so this sequence is reachable only through the widened
		// gate set — and a data-only dump that skipped the widening emitted no
		// setval for it, leaving the restored child to hand out ids its
		// restored rows already hold.
		`CREATE TABLE sroot (id int NOT NULL, region text NOT NULL) PARTITION BY LIST (region)`,
		`CREATE TABLE schild PARTITION OF sroot FOR VALUES IN ('x')`,
		`CREATE SEQUENCE schild_id_seq OWNED BY schild.id`,
		`ALTER TABLE schild ALTER COLUMN id SET DEFAULT nextval('schild_id_seq')`,
		`INSERT INTO schild (region) VALUES ('x'), ('x'), ('x')`,
		// A populated matview must NOT refresh in a structure-only dump.
		`CREATE TABLE mvbase (m int)`,
		`INSERT INTO mvbase VALUES (1)`,
		`CREATE MATERIALIZED VIEW mv1 AS SELECT m FROM mvbase`,
	}
	if pg15 {
		stmts = append(stmts,
			// Ordinary identity sequence with diverging persistence (PG15+).
			`CREATE TABLE idper (n int GENERATED BY DEFAULT AS IDENTITY)`,
			`ALTER SEQUENCE idper_n_seq SET UNLOGGED`,
		)
	}
	if pg17 {
		stmts = append(stmts,
			// Identity on a partitioned table (PG17+): partitions share the
			// root's sequence.
			`CREATE TABLE iroot (iid bigint GENERATED ALWAYS AS IDENTITY (START WITH 500 INCREMENT BY 3), lbl text NOT NULL) PARTITION BY LIST (lbl)`,
			`CREATE TABLE ipart PARTITION OF iroot FOR VALUES IN ('a')`,
			`INSERT INTO iroot (lbl) VALUES ('a'), ('a')`,
		)
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	export := func(path string, form url.Values) string {
		t.Helper()
		form.Set("csrf_token", csrf)
		// Destructive actions are gated on a server-side confirmation; the
		// browser gets it from the interstitial (or from app.js after the
		// hx-confirm dialog). Non-destructive actions ignore the field.
		form.Set("tx_confirm", "1")
		resp, err := client.PostForm(ts.URL+path, form)
		if err != nil {
			t.Fatalf("export %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %s = %d:\n%.2000s", path, resp.StatusCode, b)
		}
		return string(b)
	}
	importInto := func(dump, label string, preseed ...string) {
		t.Helper()
		liveDropDB(t, admin, env.engine)
		liveCreateDB(t, admin)
		if len(preseed) > 0 {
			// A scoped export is NOT self-contained: its external dependencies
			// (here a trigger function) must pre-exist in the restore target.
			pre, err := driver.Open(ctx, d, dbParams)
			if err != nil {
				t.Fatalf("%s preseed connect: %v", label, err)
			}
			for _, stmt := range preseed {
				if _, err := pre.Exec(ctx, stmt); err != nil {
					pre.Close()
					t.Fatalf("%s preseed %q: %v", label, stmt, err)
				}
			}
			pre.Close()
		}
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
		if err != nil {
			t.Fatalf("import %s: %v", label, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "tx-alert-error") {
			t.Fatalf("%s import failed (%d):\n%.3000s\n--- dump ---\n%.9000s", label, resp.StatusCode, body, dump)
		}
	}
	// executable strips the inert comment lines (warnings legitimately NAME an
	// out-of-scope source; the executable statements must not).
	executable := func(dump string) string {
		var b strings.Builder
		for line := range strings.SplitSeq(dump, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
		return b.String()
	}

	both := url.Values{"format": {"sql"}, "structure": {"1"}, "data": {"1"}}
	chiDump := export("/db/"+liveDB+"/table/chi/export", url.Values{"format": {"sql"}, "structure": {"1"}, "data": {"1"}})
	chiData := export("/db/"+liveDB+"/table/chi/export", url.Values{"format": {"sql"}, "data": {"1"}})
	chiStruct := export("/db/"+liveDB+"/table/chi/export", url.Values{"format": {"sql"}, "structure": {"1"}})
	pc1Dump := export("/db/"+liveDB+"/table/pc1/export", both)
	hc0Dump := export("/db/"+liveDB+"/table/hc0/export", both)
	seqconsDump := export("/db/"+liveDB+"/table/seqcons/export", both)
	siblingDump := export("/db/"+liveDB+"/table/sibling/export", both)
	dbStruct := export("/db/"+liveDB+"/export", url.Values{"format": {"sql"}, "structure": {"1"}})
	dbData := export("/db/"+liveDB+"/export", url.Values{"format": {"sql"}, "data": {"1"}})
	dbDump := export("/db/"+liveDB+"/export", both)
	var ipartDump string
	if pg17 {
		ipartDump = export("/db/"+liveDB+"/table/ipart/export", both)
	}

	// The INHERITS child never names the source sequence; the replacement
	// carries the inherited CHECK and warns.
	for _, want := range []string{
		"tablex_seq_",
		`CONSTRAINT "par_pos" CHECK`,
		"is not part of this export; a replacement sequence",
		"it is dumped standalone and the inheritance link is not restored",
	} {
		if !strings.Contains(chiDump, want) {
			t.Errorf("chi dump missing %q:\n%s", want, chiDump)
		}
	}
	if strings.Contains(executable(chiDump), "par_id_seq") {
		t.Errorf("chi dump's executable DDL must never name the source sequence par_id_seq:\n%s", chiDump)
	}
	// Data-only: original setval, no synthetic reference (the rule split).
	if strings.Contains(chiData, "tablex_seq_") {
		t.Errorf("data-only chi dump must not reference tablex_seq_*:\n%s", chiData)
	}
	if !strings.Contains(chiData, `par_id_seq`) || !strings.Contains(chiData, "setval") {
		t.Errorf("data-only chi dump must sync the ORIGINAL sequence:\n%s", chiData)
	}
	// Structure-only: no setval at all.
	if strings.Contains(chiStruct, "setval") {
		t.Errorf("structure-only chi dump must carry no setval:\n%s", chiStruct)
	}

	// The partition child materializes with bound CHECK, cloned trigger
	// (still disabled), attached index — and no PARTITION OF.
	for _, want := range []string{
		`CREATE TABLE "public"."pc1"`,
		`(id < 100)`, // the synthesized bound CHECK
		`CREATE TRIGGER ptrg`,
		`DISABLE TRIGGER "ptrg"`,
		`CREATE INDEX pc1_v_idx`,
		"is exported standalone: the partition link is not restored",
	} {
		if !strings.Contains(pc1Dump, want) {
			t.Errorf("pc1 dump missing %q:\n%s", want, pc1Dump)
		}
	}
	if strings.Contains(pc1Dump, "PARTITION OF") {
		t.Errorf("standalone pc1 dump must not contain PARTITION OF:\n%s", pc1Dump)
	}

	// Hash child: warning, no unstable CHECK.
	if !strings.Contains(hc0Dump, "HASH bound cannot be reproduced portably") {
		t.Errorf("hc0 dump missing the hash-bound warning:\n%s", hc0Dump)
	}
	if strings.Contains(executable(hc0Dump), "satisfies_hash_partition") {
		t.Errorf("hc0 dump's executable DDL must not embed satisfies_hash_partition:\n%s", hc0Dump)
	}

	// Early- and late-bound references rebound to one replacement
	// with the source's full definition; the dynamic default warns.
	for _, want := range []string{
		"AS smallint START WITH 100 INCREMENT BY 5 MINVALUE 50 MAXVALUE 30000 CACHE 3 CYCLE",
		"'customized counter'",
		"calls nextval with a non-literal argument",
	} {
		if !strings.Contains(seqconsDump, want) {
			t.Errorf("seqcons dump missing %q:\n%s", want, seqconsDump)
		}
	}
	reEarly := regexp.MustCompile(`nextval\('public\.tablex_seq_[0-9a-f]+'::regclass\)`)
	reLate := regexp.MustCompile(`nextval\(\('public\.tablex_seq_[0-9a-f]+'::text\)::regclass\)`)
	if !reEarly.MatchString(seqconsDump) {
		t.Errorf("seqcons dump: early-bound default not rewritten:\n%s", seqconsDump)
	}
	if !reLate.MatchString(seqconsDump) {
		t.Errorf("seqcons dump: late-bound default not rewritten:\n%s", seqconsDump)
	}

	// The sibling (non-owner consumer) gets a replacement with OWNED BY NONE
	// semantics (no OWNED BY linkage, warning says so).
	if !strings.Contains(siblingDump, "tablex_seq_") || !strings.Contains(siblingDump, "OWNED BY NONE") {
		t.Errorf("sibling dump missing replacement/OWNED BY NONE warning:\n%s", siblingDump)
	}
	if regexp.MustCompile(`ALTER SEQUENCE "public"\."tablex_seq_[0-9a-f]+" OWNED BY`).MatchString(siblingDump) {
		t.Errorf("sibling replacement must not carry an OWNED BY linkage:\n%s", siblingDump)
	}

	// db scope: no replacements anywhere; OWNED BY survives multiple consumers.
	if strings.Contains(dbDump, "tablex_seq_") {
		t.Errorf("db-scope dump must contain no replacement sequences:\n%s", dbDump)
	}
	if !strings.Contains(dbDump, `ALTER SEQUENCE "public"."owned_seq" OWNED BY "public"."ownert"."k"`) {
		t.Errorf("db-scope dump lost owned_seq's OWNED BY:\n%s", dbDump)
	}
	if pg15 && !strings.Contains(dbDump, `ALTER SEQUENCE "public"."idper_n_seq" SET UNLOGGED`) {
		t.Errorf("db-scope dump missing the identity-sequence persistence delta:\n%s", dbDump)
	}

	// A partition CHILD's own serial sequence must be value-synced by BOTH
	// db-scope kinds. The child is folded out of the exported table list, so
	// the sequence pass sees it only through the widened gate set; that
	// widening used to be structure-gated, and a data-only dump therefore
	// restored the child with its counter back at 1 — the next insert reissues
	// an id the restored rows already hold, and a primary key would reject it.
	for _, tc := range []struct{ label, dump string }{
		{"data-only db dump", dbData},
		{"structure+data db dump", dbDump},
	} {
		if !strings.Contains(tc.dump, `setval('"public"."schild_id_seq"'`) {
			t.Errorf("%s carries no setval for the partition child's own sequence:\n%s", tc.label, tc.dump)
		}
	}
	// Structure-only stays silent: the writer drops setval whatever the pass
	// collected, and the assertion below re-states that for the whole dump.

	// Structure-only db dump — no setval, no REFRESH, matview WITH NO DATA.
	if strings.Contains(dbStruct, "setval") || strings.Contains(dbStruct, "REFRESH MATERIALIZED VIEW") {
		t.Errorf("structure-only db dump must carry no setval/REFRESH:\n%s", dbStruct)
	}
	if !strings.Contains(dbStruct, "WITH NO DATA") {
		t.Errorf("structure-only db dump: matview must be created WITH NO DATA:\n%s", dbStruct)
	}
	if !strings.Contains(dbDump, "REFRESH MATERIALIZED VIEW") {
		t.Errorf("structure+data db dump must still refresh the populated matview:\n%s", dbDump)
	}

	if pg17 {
		// Identity replacement: inline SEQUENCE NAME with the source's options,
		// no standalone CREATE SEQUENCE / OWNED BY for it (dump-text proof).
		reInline := regexp.MustCompile(`GENERATED ALWAYS AS IDENTITY \(SEQUENCE NAME "public"\."tablex_seq_[0-9a-f]+" START WITH 500 INCREMENT BY 3`)
		if !reInline.MatchString(ipartDump) {
			t.Errorf("ipart dump missing the inline identity replacement:\n%s", ipartDump)
		}
		if strings.Contains(ipartDump, `CREATE SEQUENCE "public"."tablex_seq`) {
			t.Errorf("identity replacement must not emit a standalone CREATE SEQUENCE:\n%s", ipartDump)
		}
		if strings.Contains(ipartDump, "OWNED BY") {
			t.Errorf("identity replacement must not emit an OWNED BY linkage:\n%s", ipartDump)
		}
		if !strings.Contains(ipartDump, "shared identity stream is split") {
			t.Errorf("ipart dump missing the identity-split fidelity warning:\n%s", ipartDump)
		}
	}

	// Round-trip 1: the INHERITS child — inherited constraints enforced, the
	// replacement supplies values, the source sequence is never needed.
	importInto(chiDump, "chi")
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("chi verify connect: %v", err)
	}
	if _, err := check.Exec(ctx, `INSERT INTO chi (note, extra) VALUES ('new', 8)`); err != nil {
		t.Errorf("post-restore chi insert: %v", err)
	}
	if got := queryRows(t, check, `SELECT count(*) FROM chi WHERE id IS NOT NULL`); strings.Join(got, "") != "2" {
		t.Errorf("chi rows after insert = %q, want 2", got)
	}
	if _, err := check.Exec(ctx, `INSERT INTO chi (id, note) VALUES (NULL, 'x')`); err == nil {
		t.Errorf("chi.id NULL insert must fail (inherited NOT NULL lost)")
	}
	if _, err := check.Exec(ctx, `INSERT INTO chi (id, note) VALUES (-5, 'x')`); err == nil {
		t.Errorf("chi CHECK (id >= 0) must reject -5 (inherited CHECK lost)")
	}
	check.Close()

	// Round-trip 2: the partition child — bound CHECK enforced, trigger there
	// and disabled. The trigger FUNCTION is an external dependency of the
	// scoped export (routines are database-scope objects) and is pre-seeded.
	importInto(pc1Dump, "pc1",
		`CREATE FUNCTION trg_f() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'`)
	check, err = driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("pc1 verify connect: %v", err)
	}
	if _, err := check.Exec(ctx, `INSERT INTO pc1 VALUES (5, 'ok')`); err != nil {
		t.Errorf("in-bound pc1 insert: %v", err)
	}
	if _, err := check.Exec(ctx, `INSERT INTO pc1 VALUES (200, 'oob')`); err == nil {
		t.Errorf("out-of-bound pc1 insert must fail (synthesized bound CHECK lost)")
	}
	if got := queryRows(t, check, `SELECT tgenabled::text FROM pg_trigger WHERE tgname = 'ptrg' AND NOT tgisinternal`); strings.Join(got, "") != "D" {
		t.Errorf("pc1 cloned trigger enable state = %q, want D", got)
	}
	check.Close()

	// Round-trip 3: seqcons — the replacement continues the source's stream
	// (START 100, INCREMENT 5, smallint).
	importInto(seqconsDump, "seqcons")
	check, err = driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("seqcons verify connect: %v", err)
	}
	if _, err := check.Exec(ctx, `INSERT INTO seqcons (a, dyn) VALUES (1, 0)`); err != nil {
		t.Errorf("post-restore seqcons insert: %v", err)
	}
	if got := queryRows(t, check, `SELECT b::text || '|' || c::text FROM seqcons WHERE a = 1`); strings.Join(got, "") != "100|105" {
		t.Errorf("seqcons b|c = %q, want 100|105 (replacement continues the source definition)", got)
	}
	check.Close()

	if pg17 {
		// Round-trip 4: the identity partition — the replacement continues the
		// root's stream (500, 503 consumed at seed, so the next value is 506).
		importInto(ipartDump, "ipart")
		check, err = driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("ipart verify connect: %v", err)
		}
		if _, err := check.Exec(ctx, `INSERT INTO ipart (lbl) VALUES ('a')`); err != nil {
			t.Errorf("post-restore ipart insert: %v", err)
		}
		if got := queryRows(t, check, `SELECT max(iid)::text FROM ipart`); strings.Join(got, "") != "506" {
			t.Errorf("ipart identity value = %q, want 506 (seeded from the source stream)", got)
		}
		check.Close()
	}

	// Round-trip 5: the full db dump — idper's sequence persistence and
	// owned_seq's single owner survive.
	if pg15 {
		importInto(dbDump, "db")
		check, err = driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("db verify connect: %v", err)
		}
		if got := queryRows(t, check, `SELECT relpersistence::text FROM pg_class WHERE relname = 'idper_n_seq'`); strings.Join(got, "") != "u" {
			t.Errorf("idper_n_seq persistence = %q after round-trip, want u", got)
		}
		if got := queryRows(t, check, `
			SELECT ot.relname || '.' || oa.attname
			FROM pg_depend dep
			JOIN pg_class s ON s.oid = dep.objid AND s.relname = 'owned_seq'
			JOIN pg_class ot ON ot.oid = dep.refobjid
			JOIN pg_attribute oa ON oa.attrelid = dep.refobjid AND oa.attnum = dep.refobjsubid
			WHERE dep.classid = 'pg_class'::regclass AND dep.deptype = 'a'`); strings.Join(got, "") != "ownert.k" {
			t.Errorf("owned_seq owner after round-trip = %q, want ownert.k", got)
		}
		check.Close()
	}
}

func TestLivePostgresDefaultDeltas(t *testing.T) {
	liveDefaultDeltas(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveDefaultDeltas pins the inherited-DEFAULT deltas live at database scope: a linked INHERITS
// child's divergent inherited-column defaults re-establish post-data in BOTH
// directions (child DROP DEFAULT under a defaulted parent; child SET DEFAULT
// under a default-less parent); a multi-parent default CONFLICT (compatible at
// creation, diverged via ALTER TABLE ONLY) suppresses the column inline across
// the hierarchy and re-emits each member's own default — the restore would
// otherwise fail at CREATE … INHERITS; a partition child's divergent default
// survives PARTITION OF; and (PG17+) an inherited-only generated column's
// divergent expression re-establishes via SET EXPRESSION with
// attislocal/attinhcount untouched.
func liveDefaultDeltas(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	pg17 := pgServerVersionNum(t, admin) >= 170000

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	stmts := []string{
		// Divergence in both directions.
		`CREATE TABLE dp (a int DEFAULT 1, b int)`,
		`CREATE TABLE dc () INHERITS (dp)`,
		`ALTER TABLE ONLY dc ALTER COLUMN a DROP DEFAULT`,
		`ALTER TABLE ONLY dc ALTER COLUMN b SET DEFAULT 5`,
		`INSERT INTO dp DEFAULT VALUES`,
		// Multi-parent conflict: compatible at creation, diverged afterwards.
		`CREATE TABLE p1 (x1 int, v int DEFAULT 1)`,
		`CREATE TABLE p2 (x2 int, v int DEFAULT 1)`,
		`CREATE TABLE pc () INHERITS (p1, p2)`,
		`ALTER TABLE ONLY p1 ALTER COLUMN v SET DEFAULT 2`,
		// Partition child with its own default.
		`CREATE TABLE dproot (k int, dd int DEFAULT 10) PARTITION BY RANGE (k)`,
		`CREATE TABLE dpc PARTITION OF dproot FOR VALUES FROM (0) TO (10)`,
		`ALTER TABLE dpc ALTER COLUMN dd SET DEFAULT 20`,
		`INSERT INTO dproot VALUES (1)`,
	}
	if pg17 {
		stmts = append(stmts,
			`CREATE TABLE gp (g int, gg int GENERATED ALWAYS AS (g * 2) STORED)`,
			`CREATE TABLE gc () INHERITS (gp)`,
			`ALTER TABLE ONLY gc ALTER COLUMN gg SET EXPRESSION AS (g * 3)`,
			`INSERT INTO gc (g) VALUES (4)`,
		)
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	fingerprint := func() map[string]string {
		c, err := driver.Open(ctx, d, dbParams)
		if err != nil {
			t.Fatalf("fingerprint connect: %v", err)
		}
		defer c.Close()
		out := map[string]string{}
		out["defaults"] = strings.Join(queryRows(t, c, `
			SELECT cl.relname || '.' || a.attname || '|' || a.attislocal::text || '|' || a.attinhcount::text || '|' ||
			       COALESCE(pg_get_expr(ad.adbin, ad.adrelid), '<none>')
			FROM pg_attribute a
			JOIN pg_class cl ON cl.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = cl.relnamespace
			LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
			WHERE n.nspname = 'public' AND cl.relkind IN ('r','p') AND a.attnum > 0
			  AND NOT a.attisdropped AND a.attname IN ('a','b','v','dd','gg')
			ORDER BY cl.relname, a.attnum`), "\n")
		return out
	}
	before := fingerprint()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}

	for _, want := range []string{
		`ALTER TABLE ONLY "public"."dc" ALTER COLUMN "a" DROP DEFAULT`,
		`ALTER TABLE ONLY "public"."dc" ALTER COLUMN "b" SET DEFAULT 5`,
		`ALTER TABLE ONLY "public"."p1" ALTER COLUMN "v" SET DEFAULT 2`,
		`ALTER TABLE ONLY "public"."p2" ALTER COLUMN "v" SET DEFAULT 1`,
		`ALTER TABLE ONLY "public"."pc" ALTER COLUMN "v" SET DEFAULT 1`,
		`ALTER TABLE ONLY "public"."dpc" ALTER COLUMN "dd" SET DEFAULT 20`,
		`has conflicting parent defaults`,
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump missing %q:\n%s", want, dump)
		}
	}
	// The conflict members' creates carry NO inline default for v (the CREATE
	// … INHERITS conflict fires before any staged DDL could run).
	reP1 := regexp.MustCompile(`(?s)CREATE TABLE "public"\."p1" \((.*?)\);`)
	if m := reP1.FindStringSubmatch(dump); m == nil || strings.Contains(m[1], "DEFAULT") {
		t.Errorf("p1's create must carry no inline default for the conflict column:\n%s", dump)
	}
	if pg17 && !strings.Contains(dump, `SET EXPRESSION AS ((g * 3))`) {
		t.Errorf("dump missing the generated-expression delta:\n%s", dump)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import", url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	importBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(importBody), "tx-alert-error") {
		t.Fatalf("default-deltas import failed (%d):\n%.3000s\n--- dump ---\n%.9000s", resp.StatusCode, importBody, dump)
	}

	after := fingerprint()
	for k, b := range before {
		if a := after[k]; a != b {
			t.Errorf("%s differs after round-trip:\n--- before ---\n%s\n--- after ---\n%s\n--- dump ---\n%s", k, b, a, dump)
		}
	}

	// Functional: pc still takes p2's surviving value 1; dpc applies 20.
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	if _, err := check.Exec(ctx, `INSERT INTO pc (x1) VALUES (9)`); err != nil {
		t.Fatalf("post-restore pc insert: %v", err)
	}
	if got := queryRows(t, check, `SELECT v::text FROM pc WHERE x1 = 9`); strings.Join(got, "") != "1" {
		t.Errorf("pc.v default = %q after restore, want 1", got)
	}
	if _, err := check.Exec(ctx, `INSERT INTO dpc (k) VALUES (2)`); err != nil {
		t.Fatalf("post-restore dpc insert: %v", err)
	}
	if got := queryRows(t, check, `SELECT dd::text FROM dpc WHERE k = 2`); strings.Join(got, "") != "20" {
		t.Errorf("dpc.dd default = %q after restore, want 20", got)
	}
	if pg17 {
		if got := queryRows(t, check, `SELECT gg::text FROM gc WHERE g = 4`); strings.Join(got, "") != "12" {
			t.Errorf("gc.gg = %q after restore, want 12 (divergent generated expression)", got)
		}
	}
}

// TestLivePostgresTeardownAudit pins: the drop-first teardown drops the
// object classes a reverse walk alone would leave behind (routines, aggregates,
// the newer object classes), collapses the dependency cycles the planner deliberately RESTORES
// into grouped multi-object DROPs, RETAINS the cycles no single DROP command
// spans (warning instead of emitting statements that would abort a restore),
// propagates that retention to prerequisites a surviving object still holds,
// guards the one drop that is not fresh-target-safe, and warns about source-side
// blockers it cannot drop.
func TestLivePostgresTeardownAudit(t *testing.T) {
	liveTeardownAudit(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// teardownBlock returns the dump prefix through the teardown: the preamble,
// schema hoist, warnings and every DROP, stopping at the first CREATE that
// starts a line. Matching on line starts matters — a warning legitimately
// QUOTES DDL ("requires CREATE EXTENSION bloom"), and a substring cut there
// would hide most of the teardown from the assertions.
func teardownBlock(dump string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(dump, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "CREATE ") && !strings.HasPrefix(t, "CREATE SCHEMA") {
			break
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// executableLines strips inert comment lines: a warning legitimately QUOTES
// what the executable statements must never contain.
func executableLines(dump string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(dump, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func liveTeardownAudit(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()
	pg14 := pgServerVersionNum(t, admin) >= 140000

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	bloom := true
	if _, err := seed.Exec(ctx, `CREATE EXTENSION bloom`); err != nil {
		bloom = false // a build without contrib: the DO-guard case is skipped
	}
	stmts := []string{
		// A base type and its I/O functions: a genuine cycle on the restored
		// catalog (each member's DROP fails under RESTRICT while the other
		// lives), and no single DROP spans a type and a function.
		`CREATE TYPE bt`,
		`CREATE FUNCTION bt_in(cstring) RETURNS bt AS 'int4in' LANGUAGE internal IMMUTABLE STRICT`,
		`CREATE FUNCTION bt_out(bt) RETURNS cstring AS 'int4out' LANGUAGE internal IMMUTABLE STRICT`,
		`CREATE TYPE bt (INPUT = bt_in, OUTPUT = bt_out, INTERNALLENGTH = 4, PASSEDBYVALUE, ALIGNMENT = int4)`,
		// A range type WITH a canonical function is the same cycle; one WITHOUT
		// is acyclic and must still drop normally.
		`CREATE TYPE rc`,
		`CREATE FUNCTION rc_canon(rc) RETURNS rc AS 'int4range_canonical' LANGUAGE internal IMMUTABLE STRICT`,
		`CREATE TYPE rc AS RANGE (SUBTYPE = int4, CANONICAL = rc_canon)`,
		`CREATE TYPE rp AS RANGE (SUBTYPE = int4)`,
		// An operator family whose loose member is one of OUR operators: the
		// family is never dropped (its DROP would take contained, possibly
		// target-only, opclasses), so the member it holds cannot be dropped.
		`CREATE FUNCTION fneq(int8, int8) RETURNS boolean LANGUAGE sql AS 'SELECT $1 <> $2'`,
		`CREATE OPERATOR ### (FUNCTION = fneq, LEFTARG = int8, RIGHTARG = int8)`,
		`CREATE OPERATOR FAMILY tfam USING btree`,
		`ALTER OPERATOR FAMILY tfam USING btree ADD OPERATOR 1 ###(int8, int8)`,
		// Ordinary routines across every prokind: each must be dropped with the
		// signature form ITS command takes — plain identity arguments for a
		// function/procedure/window function, the direct/ORDER BY split for an
		// ordered-set aggregate, (*) for a zero-argument one.
		`CREATE FUNCTION acc(int, int) RETURNS int LANGUAGE sql AS 'SELECT $1 + $2'`,
		`CREATE AGGREGATE agsum(int) (SFUNC = acc, STYPE = int, INITCOND = '0')`,
		`CREATE AGGREGATE agcount(*) (SFUNC = int8inc, STYPE = int8, INITCOND = '0')`,
		`CREATE FUNCTION osa_trans(int[], int) RETURNS int[] LANGUAGE sql AS 'SELECT $1 || $2'`,
		`CREATE FUNCTION osa_final(int[], int) RETURNS int LANGUAGE sql AS 'SELECT COALESCE($1[$2], 0)'`,
		`CREATE AGGREGATE nth_val(int ORDER BY int) (SFUNC = osa_trans, STYPE = int[], FINALFUNC = osa_final)`,
		`CREATE PROCEDURE prc(a int) LANGUAGE sql AS 'SELECT 1'`,
		`CREATE FUNCTION wf(int) RETURNS int WINDOW LANGUAGE internal AS 'window_rank'`,
		// A cast and a free-standing operator: object classes the reverse teardown
		// must drop too (the family-held operator above is retained instead).
		`CREATE TYPE colors AS ENUM ('r', 'g', 'b')`,
		`CREATE FUNCTION t2c(text) RETURNS colors LANGUAGE sql AS 'SELECT ($1)::public.colors'`,
		`CREATE CAST (text AS colors) WITH FUNCTION t2c(text) AS ASSIGNMENT`,
		`CREATE FUNCTION opsim(int8, int8) RETURNS boolean LANGUAGE sql AS 'SELECT $1 = $2'`,
		`CREATE OPERATOR @@@ (FUNCTION = opsim, LEFTARG = int8, RIGHTARG = int8)`,
		// A domain whose DEFAULT calls a function RETURNING that domain: the resolver
		// restores it by deferring the default, but the restored catalog holds a
		// genuine domain-versus-function cycle no single DROP spans.
		`CREATE DOMAIN dd AS int`,
		`CREATE FUNCTION ddf() RETURNS dd LANGUAGE sql AS 'SELECT 1::public.dd'`,
		`ALTER DOMAIN dd SET DEFAULT public.ddf()`,
		// Table-scope blocker fixtures: the exported table keeps an external
		// view, an out-of-scope inheritance child, and an out-of-scope default
		// over its own (emitted) sequence.
		`CREATE TABLE tb (id serial PRIMARY KEY, n int)`,
		`INSERT INTO tb (n) VALUES (1)`,
		`CREATE VIEW vext AS SELECT id FROM tb`,
		`CREATE TABLE tchild () INHERITS (tb)`,
		`CREATE TABLE tother (z int DEFAULT nextval('tb_id_seq'))`,
	}
	if pg14 {
		// A mutually-recursive BEGIN ATOMIC pair: the resolver restores it via a stub plus
		// CREATE OR REPLACE, so the restored catalog holds the cycle.
		stmts = append(stmts,
			`CREATE FUNCTION ra(x int) RETURNS int LANGUAGE sql AS 'SELECT 0'`,
			`CREATE FUNCTION rb(x int) RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT CASE WHEN x < 1 THEN 0 ELSE public.ra(x - 1) END; END`,
			`CREATE OR REPLACE FUNCTION ra(x int) RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT CASE WHEN x < 1 THEN 0 ELSE public.rb(x - 1) END; END`,
			// An aggregate and its state function in a cycle: two DIFFERENT
			// routine kinds, so only DROP ROUTINE — with the flat signature —
			// covers them in one statement.
			`CREATE FUNCTION accx(a int, b int) RETURNS int LANGUAGE sql AS 'SELECT a + b'`,
			`CREATE AGGREGATE agx(int) (SFUNC = accx, STYPE = int, INITCOND = '0')`,
			`CREATE OR REPLACE FUNCTION accx(a int, b int) RETURNS int LANGUAGE sql
				BEGIN ATOMIC SELECT a + (SELECT public.agx(x) FROM (SELECT b AS x) s); END`,
		)
	}
	if bloom {
		// A non-built-in access method: its opclass drop is the ONE statement
		// that raises undefined_object on a target without the extension, even
		// under IF EXISTS.
		stmts = append(stmts,
			`CREATE OPERATOR CLASS bopc FOR TYPE int8 USING bloom AS OPERATOR 1 =(int8, int8), FUNCTION 1 hashint8(int8)`)
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	loginResp, err := client.PostForm(ts.URL+"/login",
		url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", loginResp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	export := func(path string) string {
		resp, err := client.PostForm(ts.URL+path, url.Values{
			"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
		})
		if err != nil {
			t.Fatalf("export %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %s: status %d\n%.2000s", path, resp.StatusCode, body)
		}
		return string(body)
	}

	dump := export("/db/" + liveDB + "/export")
	teardown := teardownBlock(dump)
	has := func(sub string) bool { return strings.Contains(teardown, sub) }

	// 1. Ordinary routines/aggregates/procedures ARE dropped now — each with the
	//    signature form ITS command takes — as are the newer object classes, and all of
	//    them before the types their signatures name.
	for _, want := range []string{
		`DROP FUNCTION IF EXISTS "public"."acc"(integer, integer)`,
		`DROP AGGREGATE IF EXISTS "public"."agsum"(integer)`,
		`DROP AGGREGATE IF EXISTS "public"."agcount"(*)`,                        // zero-argument form
		`DROP AGGREGATE IF EXISTS "public"."nth_val"(integer ORDER BY integer)`, // ordered-set split
		`DROP FUNCTION IF EXISTS "public"."wf"(integer)`,                        // a window function drops as a FUNCTION
		// A procedure drops as a PROCEDURE. The argument spelling is
		// version-dependent (PG14+ renders the IN mode, PG13 does not), so the
		// assertion stops at the identity the command keys on.
		`DROP PROCEDURE IF EXISTS "public"."prc"(`,
		`DROP CAST IF EXISTS (text AS public.colors)`,
		`DROP OPERATOR IF EXISTS "public".@@@ (bigint, bigint)`,
		`DROP TYPE IF EXISTS "public"."rp"`, // an acyclic range still drops
	} {
		if !has(want) {
			t.Errorf("teardown must contain %q:\n%s", want, teardown)
		}
	}

	// 2. The type-versus-support-function cycles are RETAINED WHOLE: omitting
	//    only the DROP TYPE would leave a DROP FUNCTION that fails under
	//    RESTRICT and aborts the entire restore.
	for _, unwanted := range []string{
		`DROP TYPE IF EXISTS "public"."bt"`,
		`DROP FUNCTION IF EXISTS "public"."bt_in"`,
		`DROP FUNCTION IF EXISTS "public"."bt_out"`,
		`DROP TYPE IF EXISTS "public"."rc"`,
		`DROP FUNCTION IF EXISTS "public"."rc_canon"`,
		`DROP OPERATOR FAMILY`,
		`DROP OPERATOR IF EXISTS "public".###`, // held by the retained family
		// A deferred-edge cycle: on the restored catalog the domain's DEFAULT is
		// present again, so domain and function depend on each other.
		`DROP DOMAIN IF EXISTS "public"."dd"`,
		`DROP FUNCTION IF EXISTS "public"."ddf"()`,
	} {
		if has(unwanted) {
			t.Errorf("teardown must NOT contain %q (retained object):\n%s", unwanted, teardown)
		}
	}
	// Only the STATEMENTS matter: the retention warning legitimately explains
	// why CASCADE is never used.
	if strings.Contains(executableLines(teardown), "CASCADE") {
		t.Errorf("teardown must never escalate a DROP to CASCADE:\n%s", teardown)
	}
	for _, want := range []string{
		"drop-first teardown omits the DROP of ",
		"drop-first teardown also omits the DROP of ",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("dump must carry the %q warning:\n%.6000s", want, dump)
		}
	}

	// 3. A mutually-recursive pair drops as ONE statement (individually, each
	//    DROP fails while the other member still references it).
	if pg14 {
		if !has(`DROP FUNCTION IF EXISTS "public"."ra"(x integer), "public"."rb"(x integer)`) &&
			!has(`DROP FUNCTION IF EXISTS "public"."rb"(x integer), "public"."ra"(x integer)`) {
			t.Errorf("the atomic cycle must drop as one grouped DROP FUNCTION:\n%s", teardown)
		}
		if has(`DROP FUNCTION IF EXISTS "public"."ra"(x integer);`) {
			t.Errorf("a grouped member must not ALSO drop individually:\n%s", teardown)
		}
		// An aggregate and its state function share no DROP class, so only
		// DROP ROUTINE — with the FLAT input signature — covers both at once.
		if !has(`DROP ROUTINE IF EXISTS `) ||
			!has(`"public"."agx"(integer)`) || !has(`"public"."accx"(integer, integer)`) {
			t.Errorf("the aggregate/function cycle must drop via one DROP ROUTINE:\n%s", teardown)
		}
	}

	// 4. The custom-access-method opclass drop is guarded; a built-in-AM one is
	//    not (it no-ops under IF EXISTS).
	if bloom {
		if !has(`DO $tablex$ BEGIN EXECUTE 'DROP OPERATOR CLASS IF EXISTS "public"."bopc" USING "bloom"'; EXCEPTION WHEN undefined_object THEN NULL; END $tablex$`) {
			t.Errorf("a custom-AM operator-class drop must ride an error-tolerant DO guard:\n%s", teardown)
		}
	}

	// 5. Executing the TEARDOWN ALONE against a fresh database must succeed:
	//    every drop no-ops (IF EXISTS), including those naming user-defined
	//    types that do not exist there and the guarded custom-AM opclass whose
	//    access method is absent (no bloom extension in the fresh target).
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/import",
		url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {teardown}})
	if err != nil {
		t.Fatalf("teardown-only import: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "tx-alert-error") {
		t.Fatalf("teardown alone must be a no-op on a fresh target (%d):\n%.3000s\n--- teardown ---\n%s",
			resp.StatusCode, body, teardown)
	}

	// 6. Source-side blocker advisories: a TABLE-scope export plans only that
	//    table's drops, so its external view, its out-of-scope inheritance
	//    child, and an out-of-scope default over its emitted sequence are all
	//    dependents this dump does not drop.
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	reseed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("reconnect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		`CREATE TABLE tb (id serial PRIMARY KEY, n int)`,
		`CREATE VIEW vext AS SELECT id FROM tb`,
		`CREATE TABLE tchild () INHERITS (tb)`,
		`CREATE TABLE tother (z int DEFAULT nextval('tb_id_seq'))`,
		// An operator class in one schema, used by an index in another: a
		// named-schema export plans the opclass drop while the index survives.
		`CREATE SCHEMA sopc`,
		`CREATE SCHEMA sidx`,
		`CREATE OPERATOR CLASS sopc.int8_alt FOR TYPE int8 USING btree AS
			OPERATOR 1 <(int8, int8), OPERATOR 2 <=(int8, int8), OPERATOR 3 =(int8, int8),
			OPERATOR 4 >=(int8, int8), OPERATOR 5 >(int8, int8), FUNCTION 1 btint8cmp(int8, int8)`,
		`CREATE TABLE sidx.t (v int8)`,
		`CREATE INDEX t_alt ON sidx.t USING btree (v sopc.int8_alt)`,
	} {
		if _, err := reseed.Exec(ctx, stmt); err != nil {
			reseed.Close()
			t.Fatalf("blocker seed %q: %v", stmt, err)
		}
	}
	reseed.Close()

	scoped := export("/db/" + liveDB + "/table/tb/export")
	// The advisory quotes PostgreSQL's own description of the blocking
	// dependency, which names the surviving object it belongs to.
	for _, want := range []string{
		`DROP TABLE IF EXISTS "public"."tb" may be blocked by rule _RETURN on view public.vext`,
		`DROP TABLE IF EXISTS "public"."tb" may be blocked by table public.tchild`,
		`DROP SEQUENCE IF EXISTS "public"."tb_id_seq" may be blocked by default value for column z of table public.tother`,
	} {
		if !strings.Contains(scoped, want) {
			t.Errorf("table-scope dump must warn %q:\n%.8000s", want, scoped)
		}
	}
	// The audit is advisory: it never suppresses the drop it warns about, and
	// never fails the export.
	if !strings.Contains(scoped, `DROP TABLE IF EXISTS "public"."tb";`) {
		t.Errorf("a blocked-drop advisory must NOT suppress the drop itself:\n%.8000s", scoped)
	}
	// Negatives: an object that dies WITH a planned drop is no blocker. The
	// serial sequence is owned by the very table being dropped, and its
	// index/constraint go with it — none may be reported.
	for _, unwanted := range []string{
		`may be blocked by table public.tb`,
		`may be blocked by sequence public.tb_id_seq`,
		`may be blocked by index public.tb_pkey`,
	} {
		if strings.Contains(scoped, unwanted) {
			t.Errorf("an auto-dependent of a planned drop must not be reported (%q):\n%.8000s", unwanted, scoped)
		}
	}

	// A NAMED-SCHEMA export plans the operator class but not the index in the
	// other schema that uses it — the one dependency that blocks a DROP
	// OPERATOR CLASS.
	oneSchema := export("/db/" + liveDB + "/export?schema=sopc")
	if want := `DROP OPERATOR CLASS IF EXISTS "sopc"."int8_alt" USING "btree" may be blocked by index sidx.t_alt`; !strings.Contains(oneSchema, want) {
		t.Errorf("named-schema dump must warn %q:\n%.8000s", want, oneSchema)
	}

	// A database-scope export covers every schema, so the same objects are all
	// in scope and nothing is reported as an external blocker.
	full := export("/db/" + liveDB + "/export")
	if strings.Contains(full, "may be blocked by rule _RETURN on view public.vext") {
		t.Errorf("a database-scope dump drops the view itself: no blocker advisory expected:\n%.8000s", full)
	}
}

// TestLiveMysqlDefinerMySQL / …MariaDB pin that a stored object's DEFINER is
// part of its security identity — a view, routine, trigger or event restored
// under the IMPORTING account executes with that account's privileges instead
// of the original's, a silent privilege change no schema comparison would
// reveal. The dump must carry `DEFINER=` and the restore must preserve it.
func TestLiveMysqlDefinerMySQL(t *testing.T) {
	liveMysqlDefiner(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMysqlDefinerMariaDB(t *testing.T) {
	liveMysqlDefiner(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func liveMysqlDefiner(t *testing.T, env liveEnv) {
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

	// A DISTINCT definer account, so a dump that silently re-attributed objects
	// to the importing account (root) would be caught. Dropped first as well as
	// last, so a previous interrupted run cannot collide.
	const definerUser = "tablex_definer"
	definer := "'" + definerUser + "'@'%'"
	dropUser := func() {
		if _, err := admin.Exec(ctx, "DROP USER IF EXISTS "+definer); err != nil {
			t.Logf("cleanup DROP USER: %v", err)
		}
	}
	dropUser()
	if _, err := admin.Exec(ctx, "CREATE USER "+definer+" IDENTIFIED BY 'tablex_definer_pw'"); err != nil {
		t.Skipf("cannot create a definer account on this server: %v", err)
	}
	defer dropUser()

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer seed.Close()
	if _, err := admin.Exec(ctx, "GRANT SELECT, INSERT, UPDATE ON `"+liveDB+"`.* TO "+definer); err != nil {
		t.Fatalf("grant to definer: %v", err)
	}
	stmts := []string{
		"CREATE TABLE t (id INT NOT NULL PRIMARY KEY, v INT NULL)",
		"INSERT INTO t VALUES (1, 10)",
		"CREATE DEFINER=" + definer + " VIEW vdef AS SELECT id, v FROM t",
		"CREATE DEFINER=" + definer + " PROCEDURE pdef(IN x INT) SELECT x + 1",
		"CREATE DEFINER=" + definer + " FUNCTION fdef(x INT) RETURNS INT DETERMINISTIC RETURN x * 2",
		"CREATE DEFINER=" + definer + " TRIGGER trgdef BEFORE INSERT ON t FOR EACH ROW SET NEW.v = IFNULL(NEW.v, 0)",
	}
	// Creating an event needs no running scheduler, but the capability is the
	// dialect's to declare.
	if seed.Capabilities().HasEvents {
		stmts = append(stmts,
			"CREATE DEFINER="+definer+" EVENT evdef ON SCHEDULE EVERY 1 DAY DO SELECT 1")
	}
	for _, stmt := range stmts {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}

	before := snapshotMySQL(t, seed)
	wantDefiner := definerUser + "@%"
	for _, key := range []string{"view:vdef", "routine:pdef", "routine:fdef", "trigger:trgdef"} {
		if !strings.Contains(before[key], wantDefiner) {
			t.Fatalf("seed did not attribute %s to %s: %q", key, wantDefiner, before[key])
		}
	}

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{Name: "live", Engine: env.engine, Host: env.host, Port: env.port})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login",
		url.Values{"csrf_token": {csrf}, "server": {"live"}, "username": {env.user}, "password": {env.pass}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}, "drop": {"1"},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dumpBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	dump := string(dumpBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, dump)
	}
	// The dump must carry the definer EXPLICITLY: without the clause every
	// object silently restores as the importing account.
	if want := "DEFINER=`" + definerUser + "`@`%`"; !strings.Contains(dump, want) {
		t.Errorf("dump missing %q:\n%.6000s", want, dump)
	}
	// Object names are matched backtick-insensitively: MariaDB's SHOW CREATE
	// TRIGGER leaves the trigger name unquoted where MySQL quotes it.
	bare := normalizeDefiner(dump)
	wantObjects := []string{"VIEW vdef", "PROCEDURE pdef", "FUNCTION fdef", "TRIGGER trgdef"}
	if seed.Capabilities().HasEvents {
		wantObjects = append(wantObjects, "EVENT evdef")
	}
	for _, want := range wantObjects {
		if !strings.Contains(bare, want) {
			t.Errorf("dump missing %q:\n%.6000s", want, dump)
		}
	}

	// Round-trip into a fresh database, imported as root — the definer must
	// survive rather than collapse onto the importing account.
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/import",
		url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {dump}})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(page), "tx-alert-error") {
		t.Fatalf("definer import failed (%d):\n%.3000s\n--- dump ---\n%.6000s", resp.StatusCode, page, dump)
	}

	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	after := snapshotMySQL(t, check)
	for k, b := range before {
		if a := after[k]; a != b {
			t.Errorf("%s differs after the DEFINER round-trip:\n--- before ---\n%s\n--- after ---\n%s", k, b, a)
		}
	}
	// Explicitly: every stored object still belongs to the ORIGINAL account, not
	// to root, which performed the import.
	for _, row := range [][2]string{
		{"VIEWS", "SELECT DEFINER FROM information_schema.VIEWS WHERE TABLE_SCHEMA = '" + liveDB + "'"},
		{"ROUTINES", "SELECT DEFINER FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = '" + liveDB + "' ORDER BY ROUTINE_NAME"},
		{"TRIGGERS", "SELECT DEFINER FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = '" + liveDB + "'"},
	} {
		got := queryRows(t, check, row[1])
		if len(got) == 0 {
			t.Errorf("%s: no rows after restore", row[0])
		}
		for _, g := range got {
			if normalizeDefiner(strings.TrimSpace(g)) != wantDefiner {
				t.Errorf("%s definer = %q after restore, want %q", row[0], g, wantDefiner)
			}
		}
	}
}
