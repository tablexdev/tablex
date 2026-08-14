package server_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
)

// Restricted mode (E3) is defence in depth below what database grants already
// allow. What these tests pin is that it is enforced on the REQUEST — every case
// posts directly, the way a user who has found the URL would, rather than checking
// that a button is hidden. A hidden button is not a control.

// restrictedServer starts a TableX with a [restrict] policy applied.
func restrictedServer(t *testing.T, apply func(*config.RestrictConfig)) (base string, client *http.Client) {
	t.Helper()
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) { apply(&cfg.Restrict) })
	return ts.URL, client
}

// TestReadOnlyRefusesEveryChange: nothing may be changed, the console included —
// TableX will not try to decide whether somebody else's SQL writes.
func TestReadOnlyRefusesEveryChange(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) { rc.ReadOnly = true })
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	for _, c := range []struct{ name, path string }{
		{"truncate a table", "/db/main/table/widgets/operations"},
		{"edit a structure", "/db/main/table/widgets/structure"},
		{"insert a row", "/db/main/table/widgets/insert"},
		{"delete rows", "/db/main/table/widgets/delete"},
		{"run SQL", "/db/main/sql"},
		{"import SQL", "/db/main/import"},
		{"create a table", "/db/main/create-table"},
		{"manage accounts", "/server/users"},
		{"manage databases", "/server"},
	} {
		code, _ := postTo(t, client, base+c.path, url.Values{"csrf_token": {csrf}, "tx_confirm": {"1"}})
		if code != http.StatusForbidden {
			t.Errorf("%s under read_only = %d, want 403", c.name, code)
		}
	}

	// Reads keep working: that is the point of read-only rather than off.
	for _, u := range []string{"/", "/db/main", "/db/main/table/widgets", "/db/main/table/widgets/structure", "/server/status"} {
		if code, _ := getBody(t, client, base+u); code != http.StatusOK {
			t.Errorf("GET %s under read_only = %d, want 200", u, code)
		}
	}
}

// TestNoConsoleLeavesTheRestWorking: turning off arbitrary SQL must not turn off
// the generated operations, or the setting is read_only with extra steps.
func TestNoConsoleLeavesTheRestWorking(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.AllowConsole = false
		rc.AllowDDL = true
	})
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	// The console and import are gone — the PAGE too, not just the POST: a console
	// that refuses to run anything is a worse answer than no console.
	for _, u := range []string{"/db/main/sql", "/server/sql", "/db/main/table/widgets/sql", "/db/main/import", "/server/import"} {
		if code, _ := getBody(t, client, base+u); code != http.StatusForbidden {
			t.Errorf("GET %s with allow_console = false = %d, want 403", u, code)
		}
		if code, _ := postTo(t, client, base+u, url.Values{"csrf_token": {csrf}, "sql_query": {"SELECT 1"}}); code != http.StatusForbidden {
			t.Errorf("POST %s with allow_console = false = %d, want 403", u, code)
		}
	}
	// A generated structure change still works.
	code, body := postTo(t, client, base+"/db/main/table/widgets/structure", url.Values{
		"csrf_token": {csrf}, "action": {"add_column"},
		"col_name": {"note"}, "col_type": {"TEXT"}, "col_nullable": {"1"}, "default_mode": {"none"},
	})
	if code != http.StatusSeeOther {
		t.Errorf("add_column with allow_console = false = %d, want 303\n%.300s", code, body)
	}
}

// TestNoDDLStillEditsRows pins the distinction that makes allow_ddl worth having
// separately from read_only: fix the data, do not reshape it.
func TestNoDDLStillEditsRows(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.AllowConsole = true
		rc.AllowDDL = false
	})
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	for _, c := range []struct{ name, path string }{
		{"structure editor", "/db/main/table/widgets/structure"},
		{"table operations", "/db/main/table/widgets/operations"},
		{"create table", "/db/main/create-table"},
		{"database operations", "/db/main/operations"},
		{"accounts", "/server/users"},
		{"grants", "/db/main/privileges"},
		{"databases", "/server"},
	} {
		code, _ := postTo(t, client, base+c.path, url.Values{"csrf_token": {csrf}, "tx_confirm": {"1"}})
		if code != http.StatusForbidden {
			t.Errorf("%s with allow_ddl = false = %d, want 403", c.name, code)
		}
	}

	// A row insert is not DDL, so it is not refused by this setting.
	code, body := postTo(t, client, base+"/db/main/table/widgets/insert",
		url.Values{"csrf_token": {csrf}, "col_name": {"bolt2"}, "col_qty": {"7"}})
	if code == http.StatusForbidden {
		t.Errorf("inserting a row was refused by allow_ddl = false; row edits are not DDL\n%.300s", body)
	}
	// And the console is untouched by this setting.
	if code, _ := getBody(t, client, base+"/db/main/sql"); code != http.StatusOK {
		t.Errorf("GET the console with allow_ddl = false = %d, want 200", code)
	}
}

// TestDatabaseAllowlistRefusesOthers covers the allowlist, and what it leaves
// alone.
func TestDatabaseAllowlistRefusesOthers(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.AllowConsole = true
		rc.AllowDDL = true
		rc.Databases = []string{"main"}
	})
	login(t, client, base)

	if code, _ := getBody(t, client, base+"/db/main/table/widgets"); code != http.StatusOK {
		t.Errorf("GET an allowed database = %d, want 200", code)
	}
	for _, u := range []string{"/db/other", "/db/other/table/x", "/db/other/sql"} {
		if code, _ := getBody(t, client, base+u); code != http.StatusForbidden {
			t.Errorf("GET %s outside the allowlist = %d, want 403", u, code)
		}
	}
	// Server-level pages are not database-scoped, so the allowlist does not
	// silently take them away.
	if code, _ := getBody(t, client, base+"/server/status"); code != http.StatusOK {
		t.Errorf("GET /server/status with an allowlist = %d, want 200", code)
	}
}

// TestAllowlistCoversTheRoutesThatCarryADatabaseOffThePath: the middleware reads
// the database out of the PATH, so a route that carries it in a query parameter
// or a form field was never checked at all. Both of these answered as if no
// allowlist were configured.
func TestAllowlistCoversTheRoutesThatCarryADatabaseOffThePath(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.AllowConsole = true
		rc.AllowDDL = true
		rc.Databases = []string{"main"}
	})
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	// The nav tree's own data source. The positive control matters more than the
	// refusal here: a 403 for "other" proves nothing if the route answers 403 for
	// every database, or 404 for all of them.
	code, body := getBody(t, client, base+"/nav/children?db=main")
	if code != http.StatusOK {
		t.Fatalf("GET /nav/children for an ALLOWED database = %d, want 200 — the negative below would be vacuous", code)
	}
	if !strings.Contains(body, "widgets") {
		t.Fatalf("GET /nav/children?db=main returned 200 but no tables:\n%.300s", body)
	}
	if code, _ := getBody(t, client, base+"/nav/children?db=other"); code != http.StatusForbidden {
		t.Errorf("GET /nav/children?db=other outside the allowlist = %d, want 403", code)
	}

	// createDatabase takes the name from the BODY, and is reachable from
	// POST /server, whose path names no database for the middleware to read.
	for _, path := range []string{"/server", "/db/main/operations"} {
		code, _ := postTo(t, client, base+path, url.Values{
			"csrf_token": {csrf}, "action": {"create_db"}, "db_name": {"other"},
		})
		if code != http.StatusForbidden {
			t.Errorf("POST %s create_db=other outside the allowlist = %d, want 403", path, code)
		}
	}
}

// TestAllowlistWarnsAboutTheConsole: the allowlist restricts ROUTES, and while the
// console is enabled a user can still name any database in SQL. Promising more
// than that is the failure worth guarding against, so startup says so plainly.
func TestAllowlistWarnsAboutTheConsole(t *testing.T) {
	c := config.Default()
	c.Restrict.Databases = []string{"main"}
	var warned bool
	for _, msg := range c.Warnings() {
		if strings.Contains(msg, "database_allowlist") && strings.Contains(msg, "console") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("an allowlist with the console enabled produced no warning: %v", c.Warnings())
	}
	// With the console off it is a real confinement, and the warning would be noise.
	c.Restrict.AllowConsole = false
	for _, msg := range c.Warnings() {
		if strings.Contains(msg, "database_allowlist") {
			t.Errorf("the allowlist warned even with the console disabled: %s", msg)
		}
	}
}

// TestUnrestrictedByDefault: none of this may change anything for an operator who
// has not asked for it.
func TestUnrestrictedByDefault(t *testing.T) {
	if config.Default().Restrict.Restricted() {
		t.Error("the default configuration reports itself as restricted")
	}
	base, client := restrictedServer(t, func(*config.RestrictConfig) {})
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")
	code, _ := postTo(t, client, base+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"truncate"}, "tx_confirm": {"1"}})
	if code != http.StatusSeeOther {
		t.Errorf("a truncate with no restrictions = %d, want 303", code)
	}
	if code, _ := getBody(t, client, base+"/db/main/sql"); code != http.StatusOK {
		t.Errorf("the console with no restrictions = %d, want 200", code)
	}
}

// TestAnUnclassifiedRouteFailsClosed is the property that keeps this policy honest
// as the application grows: a state-changing route nobody thought to classify must
// be refused under allow_ddl = false, not waved through.
func TestAnUnclassifiedRouteFailsClosed(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.AllowConsole = true
		rc.AllowDDL = false
	})
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")
	// A path the classifier has never heard of. It would 404 at the router, so a
	// 403 proves the policy refused it FIRST.
	code, _ := postTo(t, client, base+"/db/main/table/widgets/no-such-operation",
		url.Values{"csrf_token": {csrf}})
	if code != http.StatusForbidden {
		t.Errorf("an unclassified state-changing route = %d, want 403 — the policy must fail closed", code)
	}
}

// --- what the UI shows ---------------------------------------------------------
//
// The tests above pin the ENFORCEMENT: every restriction holds against a request
// typed by hand. These pin the other half — that the UI does not offer what the
// request would refuse. The two stay separate on purpose: a hidden button is not a
// control, and a control whose button is still shown is a 403 the user did not
// deserve.

// TestRestrictedUIStatesThePolicy: a UI that silently drops half its features
// looks broken. The note has to reach the pages a restricted user lands on, and
// the htmx-swapped fragment too — a banner that vanished on the first navigation
// would be worse than none.
func TestRestrictedUIStatesThePolicy(t *testing.T) {
	for _, c := range []struct {
		name  string
		apply func(*config.RestrictConfig)
		want  string
	}{
		{"read_only", func(rc *config.RestrictConfig) { rc.ReadOnly = true }, "read-only"},
		{"no console", func(rc *config.RestrictConfig) { rc.AllowConsole = false }, "running SQL directly"},
		{"no ddl", func(rc *config.RestrictConfig) { rc.AllowDDL = false }, "changing schemas"},
		{"neither", func(rc *config.RestrictConfig) { rc.AllowConsole, rc.AllowDDL = false, false },
			"running SQL directly and changing schemas"},
	} {
		base, client := restrictedServer(t, c.apply)
		login(t, client, base)
		for _, u := range []string{"/", "/db/main", "/db/main/table/widgets"} {
			code, body := getBody(t, client, base+u)
			if code != http.StatusOK {
				t.Fatalf("%s: GET %s = %d", c.name, u, code)
			}
			if !strings.Contains(body, c.want) {
				t.Errorf("%s: GET %s does not state the policy (want %q)", c.name, u, c.want)
			}
		}
		// The htmx path renders the same swappable region, so the note survives a
		// navigation instead of appearing only on a full page load.
		req, err := http.NewRequest(http.MethodGet, base+"/db/main", nil)
		if err != nil {
			t.Fatalf("%s: build htmx request: %v", c.name, err)
		}
		req.Header.Set("HX-Request", "true")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: htmx GET: %v", c.name, err)
		}
		frag, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(frag), c.want) {
			t.Errorf("%s: the htmx fragment drops the policy note", c.name)
		}
	}

	// An unrestricted TableX says nothing at all — the note must not become
	// permanent furniture.
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	_, body := getBody(t, client, ts.URL+"/db/main")
	if strings.Contains(body, "This TableX") {
		t.Error("an unrestricted TableX shows a restriction note")
	}
	// The container too, not just its text: gating on a predicate rather than on
	// the notice itself would render an empty box, which no assertion about the
	// wording would catch.
	if strings.Contains(body, "tx-restricted-note") {
		t.Error("an unrestricted TableX renders the note element (empty)")
	}
}

// TestReadOnlyHidesTheWriteAffordances: under read_only, Browse is the screen a
// user spends their time on, and every one of its row actions posts to a route
// that answers 403.
func TestReadOnlyHidesTheWriteAffordances(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) { rc.ReadOnly = true })
	login(t, client, base)

	code, body := getBody(t, client, base+"/db/main/table/widgets")
	if code != http.StatusOK {
		t.Fatalf("browse under read_only = %d, want 200 (browsing is a read)", code)
	}
	// The data is still there: this is read-only, not closed.
	for _, want := range []string{"bolt", "nut", "qty"} {
		if !strings.Contains(body, want) {
			t.Errorf("browse lost read content %q under read_only", want)
		}
	}
	for _, gone := range []string{
		`aria-label="Delete row `, `aria-label="Edit row `, `aria-label="Copy row `,
		"With selected:", "Insert new row", "Check all",
	} {
		if strings.Contains(body, gone) {
			t.Errorf("browse still offers %q under read_only", gone)
		}
	}
	// Nothing on the page should point at the row-action hub.
	if strings.Contains(body, "/rows") {
		t.Error("browse still references the row-action hub under read_only")
	}

	// The structure page keeps its listing and loses its editor.
	code, structure := getBody(t, client, base+"/db/main/table/widgets/structure")
	if code != http.StatusOK {
		t.Fatalf("structure under read_only = %d", code)
	}
	if !strings.Contains(structure, "qty") {
		t.Error("the structure listing lost its columns under read_only")
	}
	for _, gone := range []string{"Add column", "drop_column", "add_index"} {
		if strings.Contains(structure, gone) {
			t.Errorf("structure still offers %q under read_only", gone)
		}
	}
}

// TestNoDDLHidesTheSchemaAffordances: allow_ddl = false keeps row editing, so the
// two have to come apart in the UI exactly as they do in the enforcement.
func TestNoDDLHidesTheSchemaAffordances(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) { rc.AllowDDL = false })
	login(t, client, base)

	// Tabs: the schema tabs go; the reads stay; SQL stays, because the console is
	// still allowed.
	_, dbPage := getBody(t, client, base+"/db/main")
	for _, gone := range []string{"/db/main/operations", "/db/main/privileges", "Create table"} {
		if strings.Contains(dbPage, gone) {
			t.Errorf("the database page still offers %q under allow_ddl = false", gone)
		}
	}
	for _, kept := range []string{"/db/main/sql", "/db/main/export", "/db/main/search"} {
		if !strings.Contains(dbPage, kept) {
			t.Errorf("the database page lost %q, which allow_ddl does not restrict", kept)
		}
	}

	// Row editing survives — the whole reason allow_ddl is separate from read_only.
	_, browse := getBody(t, client, base+"/db/main/table/widgets")
	for _, kept := range []string{`aria-label="Edit row `, "Insert new row"} {
		if !strings.Contains(browse, kept) {
			t.Errorf("browse lost %q under allow_ddl = false; row edits are not DDL", kept)
		}
	}
	// The structure editor does not.
	_, structure := getBody(t, client, base+"/db/main/table/widgets/structure")
	if strings.Contains(structure, "Add column") {
		t.Error("the structure editor is still offered under allow_ddl = false")
	}

	// The server level: no create-database control, no kill button.
	_, dbs := getBody(t, client, base+"/server")
	if strings.Contains(dbs, "create_db") {
		t.Error("the Databases page still offers a create-database form under allow_ddl = false")
	}
	// The exact hidden-field value the destructive partial renders, so this cannot
	// pass by matching prose that happens to contain the word.
	_, procs := getBody(t, client, base+"/server/processes")
	if strings.Contains(procs, `value="kill"`) {
		t.Error("the process list still offers a kill button under allow_ddl = false")
	}
}

// TestNoConsoleHidesTheConsole: the SQL and Import routes are refused whatever the
// method, so leaving their tabs in place would be a link to a 403.
func TestNoConsoleHidesTheConsole(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) { rc.AllowConsole = false })
	login(t, client, base)

	_, body := getBody(t, client, base+"/db/main")
	for _, gone := range []string{`href="/db/main/sql"`, `href="/db/main/import"`} {
		if strings.Contains(body, gone) {
			t.Errorf("the database page still links %q under allow_console = false", gone)
		}
	}
	// Export is not the console and stays.
	if !strings.Contains(body, `href="/db/main/export"`) {
		t.Error("Export was withheld with the console; it is a read")
	}

	// The home page's quick links honor the same rule: /server/sql and
	// /server/import 403 under allow_console = false, so the page must not
	// offer them.
	_, home := getBody(t, client, base+"/")
	for _, gone := range []string{`href="/server/sql"`, `href="/server/import"`} {
		if strings.Contains(home, gone) {
			t.Errorf("the home page still links %q under allow_console = false", gone)
		}
	}
	if !strings.Contains(home, `href="/server/export"`) {
		t.Error("the home page lost its Export link with the console; export is a read")
	}
	// And the schema editor is untouched — allow_console is not allow_ddl.
	_, structure := getBody(t, client, base+"/db/main/table/widgets/structure")
	if !strings.Contains(structure, "Add column") {
		t.Error("the structure editor went away with the console")
	}
}

// TestDatabaseAllowlistNarrowsEveryListing: the allowlist is the set of databases
// this TableX addresses, so it has to hold everywhere one is offered — including
// the server dump, whose route names no database at all and which would otherwise
// hand over in one click exactly what the sidebar declines to show.
func TestDatabaseAllowlistNarrowsEveryListing(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.Databases = []string{"no_such_database"} // deliberately excludes "main"
	})
	login(t, client, base)
	csrf := csrfFrom(t, client, base+"/")

	for _, u := range []string{"/", "/server"} {
		code, body := getBody(t, client, base+u)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d", u, code)
		}
		if strings.Contains(body, ">main<") {
			t.Errorf("GET %s still lists the excluded database", u)
		}
	}

	// The server dump is the case that matters most, and it is checked against
	// the BYTES it hands over rather than against the page that offers it: the
	// export page lists tables, not databases, so no markup assertion here could
	// have said anything. /server/export names no database in its route, so
	// without the listing filter it would dump everything the sidebar just
	// declined to show.
	code, dump := postTo(t, client, base+"/server/export",
		url.Values{"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"}})
	if code != http.StatusOK {
		t.Fatalf("server export = %d:\n%.400s", code, dump)
	}
	if strings.Contains(dump, "widgets") {
		t.Errorf("the server dump contains a table from the excluded database:\n%.600s", dump)
	}
}

// TestAllowlistReadsThePathTheRouterWILLRead: databaseOf ran before routing and
// split the DECODED path, in which a %2F has already become a real separator —
// while net/http splits the ESCAPED path and unescapes each segment afterwards.
// The two therefore disagreed about which database a request addresses.
//
// Every case is built from a RAW target, because setting URL.Path directly
// leaves RawPath empty and the whole test would pass vacuously.
func TestAllowlistReadsThePathTheRouterWILLRead(t *testing.T) {
	base, client := restrictedServer(t, func(rc *config.RestrictConfig) {
		rc.Databases = []string{"main"}
	})
	login(t, client, base)

	// The attacker direction. databaseOf saw "main" and allowed it, while the
	// router hands the handler PathValue("db") == "main/evil" — a database the
	// allowlist does not name.
	if code, body := getBody(t, client, base+"/db/main%2Fevil"); code != http.StatusForbidden {
		t.Errorf("GET /db/main%%2Fevil = %d, want 403 (the allowlist must see what the handler sees):\n%.400s", code, body)
	}
	// Deeper in the path, where the encoded segment is not the last one.
	if code, _ := getBody(t, client, base+"/db/main%2Fevil/table/widgets"); code != http.StatusForbidden {
		t.Errorf("GET /db/main%%2Fevil/table/widgets = %d, want 403", code)
	}
	// The allowlisted database itself still works, or the fix is just a refusal.
	if code, _ := getBody(t, client, base+"/db/main"); code != http.StatusOK {
		t.Errorf("GET /db/main = %d, want 200", code)
	}

	// And the case a HALF fix breaks: net/http compares its literal pattern
	// segments against the UNESCAPED segment, so /%64b/main really does route to
	// /db/{db} with db == "main". Unescaping only the extracted segment would
	// leave seg[0] as "%64b", return "" and skip the check entirely — a new
	// bypass in a case that already worked. Here "main" IS allowlisted, so the
	// check must run and PASS.
	if code, _ := getBody(t, client, base+"/%64b/main"); code != http.StatusOK {
		t.Errorf("GET /%%64b/main = %d, want 200 — it routes to /db/{db} with db=main", code)
	}
	// Same encoding, a database the allowlist does not name: the check must run
	// and REFUSE. A skipped check would answer 200 here.
	if code, _ := getBody(t, client, base+"/%64b/main%2Fevil"); code != http.StatusForbidden {
		t.Errorf("GET /%%64b/main%%2Fevil = %d, want 403", code)
	}
}
