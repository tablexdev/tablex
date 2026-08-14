package server_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
)

// Restricted mode's UI half cannot be checked on SQLite, and the unit suite runs
// on SQLite. Three of the affordances it withholds do not exist there at all —
// SQLite has no CREATE DATABASE, no process list, and exactly one database — so an
// assertion that they are hidden passes whether the policy works or not.
//
// That is not a theoretical gap. Written first against SQLite, all three of those
// assertions were VACUOUS: reverting the code each was meant to guard left them
// green. They live here instead, against an engine that really has the affordance,
// and each is paired with a POSITIVE control on the same engine and the same page
// unrestricted — without which the next change that stops rendering the control for
// an unrelated reason would quietly make them vacuous again.

func TestLiveRestrictedUIMySQL(t *testing.T) {
	liveRestrictedUI(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveRestrictedUIMariaDB(t *testing.T) {
	liveRestrictedUI(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveRestrictedUIPostgres(t *testing.T) {
	liveRestrictedUI(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLiveDatabaseNamedSQLMySQL(t *testing.T) {
	liveDatabaseNamedSQL(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveDatabaseNamedSQLMariaDB(t *testing.T) {
	liveDatabaseNamedSQL(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveDatabaseNamedSQLPostgres(t *testing.T) {
	liveDatabaseNamedSQL(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveDatabaseNamedSQL is the half of the false-403 that SQLite cannot express:
// its dialect hard-codes "main" as the one database, so a DATABASE named "sql"
// is unconstructible there — which is worse than a vacuous test, because it
// would silently assert nothing. The unit suite covers the TABLE half, which
// SQLite can express.
//
// The defect: the policy used to be inferred from the request's last path
// segment, so /db/sql ended in "sql" and browsing that database answered
// "Running SQL directly is disabled" under allow_console = false.
func liveDatabaseNamedSQL(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	params := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		params.Database = "postgres"
	}
	admin, err := driver.Open(ctx, d, params)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	// EXACTLY "sql", and that is the whole test. The old classifier switched on
	// the final path segment as a literal, so a name that merely ENDS in "sql"
	// (tablex_rt_sql) never matched it and would assert nothing at all.
	//
	// It therefore does not carry the liveDB prefix, so a run killed between the
	// CREATE and the cleanup leaves a database requireIsolatedServerScope will
	// refuse. That failure is loud and tells you to drop it, which is the right
	// trade for a test that would otherwise be decorative.
	const name = "sql"
	drop := func() {
		stmt := "DROP DATABASE IF EXISTS " + d.QuoteIdent(name)
		if env.engine == "postgres" {
			stmt += " WITH (FORCE)"
		}
		if _, err := admin.Exec(context.Background(), stmt); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
	}
	drop()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+d.QuoteIdent(name)); err != nil {
		admin.Close()
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() { drop(); admin.Close() })

	base, client := liveRestrictedServer(t, env, func(rc *config.RestrictConfig) {
		rc.AllowConsole = false
		rc.AllowDDL = true
	})
	code, body := getBody(t, client, base+"/db/"+name)
	if code != http.StatusOK {
		t.Errorf("%s: browsing a database named %q with allow_console = false = %d, want 200\n%.400s", env.label, name, code, body)
	}
	if strings.Contains(body, "Running SQL directly is disabled") {
		t.Errorf("%s: browsing %q rendered the console refusal:\n%.400s", env.label, name, body)
	}
	// The positive control for the restriction itself: the console on that same
	// database must still be refused, or the assertion above passes because
	// nothing is restricted.
	if code, _ := getBody(t, client, base+"/db/"+name+"/sql"); code != http.StatusForbidden {
		t.Errorf("%s: the console on %q = %d, want 403 — the restriction is not in force", env.label, name, code)
	}
}

// liveRestrictedServer starts TableX against a live engine under a [restrict]
// policy, and returns the base URL with a logged-in client.
func liveRestrictedServer(t *testing.T, env liveEnv, apply func(*config.RestrictConfig)) (string, *http.Client) {
	t.Helper()
	db := ""
	if env.engine == "postgres" {
		db = "postgres"
	}
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Servers = []config.ServerConfig{{
			Name: testServerName, Engine: env.engine,
			Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: db,
		}}
		if apply != nil {
			apply(&cfg.Restrict)
		}
	})
	login(t, client, ts.URL)
	return ts.URL, client
}

// serverDumpNamesADatabase reports whether a server-scope dump switches database
// at all: the MySQL family opens each section with an executable CREATE DATABASE,
// PostgreSQL with a \connect meta-command.
//
// Both markers include the token that follows them, and that is not fussiness.
// A first version matched a bare `\connect`, which the PostgreSQL dump's own
// HEADER contains ("Sections switch databases via \connect; restore with psql
// …") — so it reported a database in a dump that carried none, and the test
// failed against correct code. The quote and the trailing space are what separate
// a statement from prose about statements.
func serverDumpNamesADatabase(dump string) bool {
	return strings.Contains(dump, "CREATE DATABASE IF NOT EXISTS ") || strings.Contains(dump, `\connect "`)
}

// restrictDB is the scratch database this test dumps. It carries the liveDB
// prefix so the server-scope isolation check tolerates it.
const restrictDB = liveDB + "_restrict"

// seedRestrictDB creates the scratch database and drops it again afterwards. A
// server dump of an engine with no USER database names nothing at all — the
// system databases are filtered out — so without this the positive control below
// could never pass, and the negative one would prove nothing.
func seedRestrictDB(t *testing.T, env liveEnv) {
	t.Helper()
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	params := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		params.Database = "postgres"
	}
	admin, err := driver.Open(ctx, d, params)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	drop := func() {
		stmt := "DROP DATABASE IF EXISTS " + d.QuoteIdent(restrictDB)
		if env.engine == "postgres" {
			stmt += " WITH (FORCE)"
		}
		if _, err := admin.Exec(context.Background(), stmt); err != nil {
			t.Errorf("drop %s: %v", restrictDB, err)
		}
	}
	drop()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+d.QuoteIdent(restrictDB)); err != nil {
		admin.Close()
		t.Fatalf("create %s: %v", restrictDB, err)
	}
	t.Cleanup(func() { drop(); admin.Close() })
}

func liveRestrictedUI(t *testing.T, env liveEnv) {
	seedRestrictDB(t, env)

	// --- the positive controls, unrestricted, on this engine ---
	openBase, openClient := liveRestrictedServer(t, env, nil)
	_, openDBs := getBody(t, openClient, openBase+"/server")
	if !strings.Contains(openDBs, "create_db") {
		t.Fatalf("%s: the Databases page offers no create-database form even unrestricted; the check below would prove nothing", env.label)
	}
	_, openProcs := getBody(t, openClient, openBase+"/server/processes")
	if !strings.Contains(openProcs, `value="kill"`) {
		t.Fatalf("%s: the process list offers no kill button even unrestricted; the check below would prove nothing", env.label)
	}
	_, openHome := getBody(t, openClient, openBase+"/")
	if !strings.Contains(openHome, `href="/server/users"`) {
		t.Fatalf("%s: the home page offers no User accounts link even unrestricted; the check below would prove nothing", env.label)
	}
	openCSRF := csrfFrom(t, openClient, openBase+"/")
	code, openDump := postTo(t, openClient, openBase+"/server/export",
		url.Values{"csrf_token": {openCSRF}, "format": {"sql"}, "structure": {"1"}})
	if code != http.StatusOK {
		t.Fatalf("%s: server export = %d:\n%.400s", env.label, code, openDump)
	}
	if !serverDumpNamesADatabase(openDump) {
		t.Fatalf("%s: an unrestricted server dump names no database at all; the check below would prove nothing:\n%.600s", env.label, openDump)
	}

	// --- allow_ddl = false withholds the two administrative controls ---
	ddlBase, ddlClient := liveRestrictedServer(t, env, func(rc *config.RestrictConfig) { rc.AllowDDL = false })
	_, dbs := getBody(t, ddlClient, ddlBase+"/server")
	if strings.Contains(dbs, "create_db") {
		t.Errorf("%s: the Databases page still offers a create-database form under allow_ddl = false", env.label)
	}
	_, procs := getBody(t, ddlClient, ddlBase+"/server/processes")
	if strings.Contains(procs, `value="kill"`) {
		t.Errorf("%s: the process list still offers a kill button under allow_ddl = false", env.label)
	}
	// The users tab is DDL-classified (account management is administration),
	// so the home page's "User accounts" quick link goes with it. The positive
	// control above pinned the link's presence unrestricted on this engine —
	// the unit suite's SQLite server has no Users capability at all, which
	// would make this assertion pass vacuously there.
	_, ddlHome := getBody(t, ddlClient, ddlBase+"/")
	if strings.Contains(ddlHome, `href="/server/users"`) {
		t.Errorf("%s: the home page still offers User accounts under allow_ddl = false", env.label)
	}
	// The process list itself stays: seeing who is connected is a read, and
	// dropping the page would take the reading away with the killing. Asserted on
	// the TAB LINK rather than on the page's heading — the heading renders whether
	// or not the tab was withheld, so a heading check would pass either way.
	if !strings.Contains(procs, `href="/server/processes"`) {
		t.Errorf("%s: the Processes tab was withheld under allow_ddl = false; the listing is a read", env.label)
	}

	// --- an allowlist matching nothing empties every listing, the dump included ---
	//
	// The server dump is the case that matters most: its route names no database,
	// so without the listing filter it would hand over in one file exactly what the
	// rest of the UI declines to show. Checked against the BYTES, because the export
	// page lists tables rather than databases and no markup assertion there could
	// say anything.
	listBase, listClient := liveRestrictedServer(t, env, func(rc *config.RestrictConfig) {
		rc.Databases = []string{restrictDB + "_absent"} // a real-looking name this server does not have
	})
	listCSRF := csrfFrom(t, listClient, listBase+"/")
	code, dump := postTo(t, listClient, listBase+"/server/export",
		url.Values{"csrf_token": {listCSRF}, "format": {"sql"}, "structure": {"1"}})
	if code != http.StatusOK {
		t.Fatalf("%s: server export under an allowlist = %d:\n%.400s", env.label, code, dump)
	}
	if serverDumpNamesADatabase(dump) {
		t.Errorf("%s: the server dump still carries a database the allowlist excludes:\n%.800s", env.label, dump)
	}
}
