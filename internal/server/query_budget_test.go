package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/config"
)

// runScript posts a script to the database-level SQL console and returns the
// rendered page.
func runScript(t *testing.T, client *http.Client, base, script string) string {
	t.Helper()
	csrf := csrfFrom(t, client, base+"/")
	code, body := postTo(t, client, base+"/db/main/sql",
		url.Values{"csrf_token": {csrf}, "sql_query": {script}})
	if code != http.StatusOK {
		t.Fatalf("console POST = %d, want 200; body:\n%.400s", code, body)
	}
	return body
}

// TestQueryBudgetTruncatesAScript: the budget refuses the statements past the
// allowance while keeping everything before them — a script is truncated at the
// budget, not dropped whole, and the refusal arrives through the same
// per-statement channel a SQL error does.
func TestQueryBudgetTruncatesAScript(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.SessionQueryBudget = 1
		c.SessionQueryWindow = time.Hour // long enough that nothing refills mid-test
	})
	login(t, client, ts.URL)

	// The budget is spent by the FIRST statement, so the refusal falls in the
	// MIDDLE of the script — which is where the contract has to hold: everything
	// before it ran, and NOTHING after it did. (What stops the rest here is the
	// budget itself, not the stop-at-first-error break: once the allowance is
	// spent every later statement is refused too. The break is what keeps the
	// script from reporting a refusal per remaining statement, which
	// TestQueryBudgetRefusalIsCounted pins.)
	body := runScript(t, client, ts.URL,
		"INSERT INTO widgets (name, qty) VALUES ('a', 1);\n"+
			"INSERT INTO widgets (name, qty) VALUES ('b', 2);\n"+
			"INSERT INTO widgets (name, qty) VALUES ('c', 3);\n")
	if !strings.Contains(body, "session_query_budget") {
		t.Fatalf("nothing was refused by the budget:\n%.1500s", body)
	}

	// Checked against the data rather than against the page: the statement inside
	// the allowance ran, and NEITHER statement after the refusal did.
	_, rows := getBody(t, client, ts.URL+"/db/main/table/widgets")
	if !strings.Contains(rows, ">a<") {
		t.Error("row \"a\" is missing; the statement inside the budget did not run")
	}
	for _, name := range []string{"b", "c"} {
		if strings.Contains(rows, ">"+name+"<") {
			t.Errorf("row %q exists; the script did not stop at the budget", name)
		}
	}
}

// TestQueryBudgetQuotesARealWait: a refusal that says "try again" without saying
// when is one a client can only answer by hammering.
func TestQueryBudgetQuotesARealWait(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.SessionQueryBudget = 1
		c.SessionQueryWindow = 30 * time.Second
	})
	login(t, client, ts.URL)

	body := runScript(t, client, ts.URL, "SELECT 1;\nSELECT 2;\n")
	if !strings.Contains(body, "session_query_budget") {
		t.Fatalf("the second statement was not refused:\n%.1200s", body)
	}
	// The window and a wait are both quoted. The wait is rendered in Go's
	// duration form, so "s" is enough of an anchor without pinning the exact
	// second the test happened to run in.
	if !strings.Contains(body, "1 statements per 30s") {
		t.Errorf("the refusal does not quote the configured budget and window:\n%.1200s", body)
	}
	if !strings.Contains(body, "Try again in ") {
		t.Errorf("the refusal does not quote a wait:\n%.1200s", body)
	}
}

// TestQueryBudgetIsPerSessionOverHTTP: the allowance belongs to a session. One
// user spending theirs must not refuse another's statement — the counter cannot
// live on the process.
func TestQueryBudgetIsPerSessionOverHTTP(t *testing.T) {
	ts, spent, _ := newTestServerWith(t, func(c *config.Config) {
		c.SessionQueryBudget = 1
		c.SessionQueryWindow = time.Hour
	})
	login(t, spent, ts.URL)
	if body := runScript(t, spent, ts.URL, "SELECT 1;\nSELECT 2;\n"); !strings.Contains(body, "session_query_budget") {
		t.Fatalf("the first session was not refused past its budget:\n%.1200s", body)
	}

	// A second, independent session on the same server.
	other := &http.Client{
		Jar:           newJar(t),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	login(t, other, ts.URL)
	if body := runScript(t, other, ts.URL, "SELECT 1;\n"); strings.Contains(body, "session_query_budget") {
		t.Errorf("a fresh session was refused because another had spent its budget:\n%.1200s", body)
	}
}

// TestQueryBudgetDoesNotChargeGeneratedQueries: the budget charges SQL the USER
// wrote. Charging the introspection and browse queries TableX generates would
// spend a browsing user's allowance on navigation — one page render costs several
// reads — and would make the feature unusable rather than protective.
func TestQueryBudgetDoesNotChargeGeneratedQueries(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.SessionQueryBudget = 1
		c.SessionQueryWindow = time.Hour
	})
	login(t, client, ts.URL)

	// Plenty of ordinary navigation: each of these runs several generated reads.
	for range 4 {
		for _, u := range []string{
			"/", "/db/main", "/db/main/table/widgets", "/db/main/table/widgets/structure",
			"/server/status", "/server/variables",
		} {
			if code, _ := getBody(t, client, ts.URL+u); code != http.StatusOK {
				t.Fatalf("GET %s = %d", u, code)
			}
		}
	}

	// The session's single hand-written statement is still available — AND the
	// second is still refused. Both halves matter: the first says browsing did not
	// spend the allowance, the second says the allowance is genuinely in force, so
	// this cannot pass by the budget being broken altogether.
	body := runScript(t, client, ts.URL, "SELECT 1;\nSELECT 2;\n")
	first, _, _ := strings.Cut(body, "session_query_budget")
	if !strings.Contains(body, "session_query_budget") {
		t.Fatalf("the budget refused nothing at all, so this test proves nothing:\n%.1200s", body)
	}
	if strings.Count(first, "SELECT 1") == 0 {
		t.Errorf("the first statement did not run, so browsing spent the session's budget:\n%.1200s", body)
	}
}

// TestQueryBudgetChargesEXPLAIN: EXPLAIN runs a statement on the database, so it
// is charged like any other.
func TestQueryBudgetChargesEXPLAIN(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.SessionQueryBudget = 1
		c.SessionQueryWindow = time.Hour
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	form := url.Values{"csrf_token": {csrf}, "sql_query": {"SELECT 1;\nSELECT 2;\n"}, "explain": {"1"}}
	code, body := postTo(t, client, ts.URL+"/db/main/sql", form)
	if code != http.StatusOK {
		t.Fatalf("EXPLAIN POST = %d", code)
	}
	if !strings.Contains(body, "session_query_budget") {
		t.Errorf("the second EXPLAIN was not charged against the budget:\n%.1200s", body)
	}
}

// TestQueryBudgetRefusalIsCounted: the refusal is visible to an operator, not just
// to the user who hit it.
func TestQueryBudgetRefusalIsCounted(t *testing.T) {
	base, client, _ := metricsServer(t, func(c *config.Config) {
		c.SessionQueryBudget = 1
		c.SessionQueryWindow = time.Hour
	})
	login(t, client, base)

	if before := samples(t, mustScrape(t, client, base))["tablex_query_budget_refused_total"]; before != 0 {
		t.Fatalf("query_budget_refused_total = %v before any refusal", before)
	}
	if body := runScript(t, client, base, "SELECT 1;\nSELECT 2;\nSELECT 3;\n"); !strings.Contains(body, "session_query_budget") {
		t.Fatalf("nothing was refused:\n%.1200s", body)
	}
	// One refusal, not two: forEachStatement stops at the first, exactly as it
	// does on a SQL error, so the third statement is never attempted.
	if got := samples(t, mustScrape(t, client, base))["tablex_query_budget_refused_total"]; got != 1 {
		t.Errorf("query_budget_refused_total = %v, want 1", got)
	}
}

// TestNoQueryBudgetByDefault: the default deployment has no budget at all, so a
// long script runs to completion.
func TestNoQueryBudgetByDefault(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	var script strings.Builder
	for range 60 {
		script.WriteString("SELECT 1;\n")
	}
	body := runScript(t, client, ts.URL, script.String())
	if strings.Contains(body, "session_query_budget") {
		t.Errorf("a budget was applied without being configured:\n%.1200s", body)
	}
}

// TestQueryBudgetChargesTheSQLImport: an import runs the user's own SQL, statement
// by statement, on a pinned connection — the same channel the console uses and the
// one with the most statements in it. It is charged for exactly that reason, and
// the wiring is separate from the console's, so it needs its own test.
func TestQueryBudgetChargesTheSQLImport(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.SessionQueryBudget = 2
		c.SessionQueryWindow = time.Hour
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Three CREATE TABLEs against a budget of two: the third must not be created.
	script := "CREATE TABLE imp_a (id INTEGER);\n" +
		"CREATE TABLE imp_b (id INTEGER);\n" +
		"CREATE TABLE imp_c (id INTEGER);\n"
	code, body := postTo(t, client, ts.URL+"/db/main/import",
		url.Values{"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {script}})
	if code != http.StatusOK {
		t.Fatalf("import POST = %d, want 200; body:\n%.400s", code, body)
	}
	if !strings.Contains(body, "session_query_budget") {
		t.Fatalf("the import ran past the session's budget unchecked:\n%.1500s", body)
	}

	// Verified against the schema, not the summary page.
	_, structure := getBody(t, client, ts.URL+"/db/main")
	for _, table := range []string{"imp_a", "imp_b"} {
		if !strings.Contains(structure, table) {
			t.Errorf("table %s is missing; a statement inside the budget did not run", table)
		}
	}
	if strings.Contains(structure, "imp_c") {
		t.Error("table imp_c exists; the import continued past the budget")
	}
}
