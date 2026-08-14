package server_test

// Bulk edit and copy, end to end. Two properties carry the weight:
//   - the form writes ONLY the rows it was given, and only the fields that
//     changed (the dirty tracking that protects lossy-rendered values has to
//     survive being prefixed per row);
//   - Edit updates and Copy inserts, and the choice is fixed when the form is
//     rendered — a form that could switch on submit is one mis-click from
//     doubling a table.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// widgetRows returns "id:name:qty" for every row, in id order.
func widgetRows(t *testing.T, path string) []string {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("inspect open: %v", err)
	}
	defer conn.Close()
	rs, err := conn.Query(context.Background(), "SELECT id, name, qty FROM widgets ORDER BY id", 100)
	if err != nil {
		t.Fatalf("inspect query: %v", err)
	}
	var out []string
	for _, row := range rs.Rows {
		out = append(out, fmt.Sprintf("%s:%s:%s", row[0].Str, row[1].Str, row[2].Str))
	}
	return out
}

// bulkForm posts a selection to the bulk hub and returns the rendered form.
func bulkForm(t *testing.T, client *http.Client, base, action string, tokens []string) string {
	t.Helper()
	form := url.Values{"csrf_token": {csrfFrom(t, client, base+"/")}, "action": {action}}
	form["rows[]"] = tokens
	code, body := postTo(t, client, base+"/db/main/table/widgets/rows", form)
	if code != http.StatusOK {
		t.Fatalf("bulk %s = %d, want 200\n%.1000s", action, code, body)
	}
	return body
}

// hiddenValue pulls a hidden input's value out of rendered HTML.
func hiddenValue(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no hidden input %q in:\n%.2000s", name, body)
	}
	return m[1]
}

func seedThreeWidgets(t *testing.T, path string) {
	t.Helper()
	execSQLite(t, path, `DELETE FROM widgets`)
	for _, s := range []string{
		`INSERT INTO widgets (id, name, qty) VALUES (1,'alpha',10)`,
		`INSERT INTO widgets (id, name, qty) VALUES (2,'bravo',20)`,
		`INSERT INTO widgets (id, name, qty) VALUES (3,'charlie',30)`,
	} {
		execSQLite(t, path, s)
	}
}

// TestBulkEditUpdatesOnlyChangedFields — the form renders one prefixed fieldset
// per selected row, and saving writes only what the user actually altered.
func TestBulkEditUpdatesOnlyChangedFields(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedThreeWidgets(t, path)
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "widgets")
	body := bulkForm(t, client, ts.URL, "edit", []string{tokens[0], tokens[1]})

	if !strings.Contains(body, `name="bulk_count" value="2"`) {
		t.Errorf("the form does not declare its row count:\n%.2000s", body)
	}
	if !strings.Contains(body, `name="mode" value="edit"`) {
		t.Error("the form does not pin its mode; the submit could switch to inserting")
	}
	// Each row's inputs must be namespaced, or two rows would overwrite each
	// other's values in one submission.
	for _, want := range []string{`name="r0_v_name"`, `name="r1_v_name"`, `name="r0_where"`, `name="r1_where"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in the bulk form:\n%.2500s", want, body)
		}
	}
	r0where := hiddenValue(t, body, "r0_where")
	r1where := hiddenValue(t, body, "r1_where")

	// Change row 0's name only. Row 1 is submitted untouched — its originals
	// match, so nothing should be written for it.
	code, _ := postTo(t, client, ts.URL+"/db/main/table/widgets/rows/apply", url.Values{
		"csrf_token": {csrfFrom(t, client, ts.URL+"/")},
		"mode":       {"edit"},
		"bulk_count": {"2"},
		"r0_where":   {r0where},
		"r0_v_id":    {"1"}, "r0_orig_id": {"1"},
		"r0_v_name": {"ALPHA"}, "r0_orig_name": {"alpha"},
		"r0_v_qty": {"10"}, "r0_orig_qty": {"10"},
		"r1_where": {r1where},
		"r1_v_id":  {"2"}, "r1_orig_id": {"2"},
		"r1_v_name": {"bravo"}, "r1_orig_name": {"bravo"},
		"r1_v_qty": {"20"}, "r1_orig_qty": {"20"},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("bulk save = %d, want 303", code)
	}
	got := widgetRows(t, path)
	want := []string{"1:ALPHA:10", "2:bravo:20", "3:charlie:30"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("after bulk save rows = %v, want %v", got, want)
	}
}

// TestBulkEditWritesEveryRow — the counterpart: when several rows change, all of
// them are written. Without this, "only changed fields" could be satisfied by a
// loop that writes nothing at all.
func TestBulkEditWritesEveryRow(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedThreeWidgets(t, path)
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "widgets")
	body := bulkForm(t, client, ts.URL, "edit", tokens)
	form := url.Values{
		"csrf_token": {csrfFrom(t, client, ts.URL+"/")},
		"mode":       {"edit"},
		"bulk_count": {"3"},
	}
	for i, orig := range []string{"alpha", "bravo", "charlie"} {
		p := fmt.Sprintf("r%d_", i)
		form.Set(p+"where", hiddenValue(t, body, p+"where"))
		form.Set(p+"v_name", strings.ToUpper(orig))
		form.Set(p+"orig_name", orig)
	}
	code, _ := postTo(t, client, ts.URL+"/db/main/table/widgets/rows/apply", form)
	if code != http.StatusSeeOther {
		t.Fatalf("bulk save = %d, want 303", code)
	}
	got := widgetRows(t, path)
	want := []string{"1:ALPHA:10", "2:BRAVO:20", "3:CHARLIE:30"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("after bulk save rows = %v, want %v", got, want)
	}
}

// TestBulkCopyInsertsNewRows — Copy duplicates the selection instead of changing
// it. The originals must survive untouched, and the auto-increment key must NOT
// be carried over (it would collide with the row being copied).
func TestBulkCopyInsertsNewRows(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedThreeWidgets(t, path)
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "widgets")
	body := bulkForm(t, client, ts.URL, "copy", []string{tokens[0], tokens[1]})
	if !strings.Contains(body, `name="mode" value="copy"`) {
		t.Fatalf("the copy form is not pinned to copy mode:\n%.2000s", body)
	}
	// The primary key is auto-increment here, so the copy form must offer it
	// blank — a prefilled key would make the INSERT collide.
	if regexp.MustCompile(`name="r0_v_id"[^>]*value="1"`).MatchString(body) {
		t.Errorf("the copy form prefilled the source row's auto-increment key:\n%.2500s", body)
	}
	// Copy mode must NOT emit dirty-tracking originals: there is no prior row to
	// compare against, and an "unchanged" field would be skipped from the INSERT.
	if strings.Contains(body, `name="r0_orig_name"`) {
		t.Error("the copy form carries edit-mode dirty markers; unchanged fields would be dropped from the INSERT")
	}

	code, _ := postTo(t, client, ts.URL+"/db/main/table/widgets/rows/apply", url.Values{
		"csrf_token": {csrfFrom(t, client, ts.URL+"/")},
		"mode":       {"copy"},
		"bulk_count": {"2"},
		"r0_v_id":    {""}, "r0_v_name": {"alpha"}, "r0_v_qty": {"10"},
		"r1_v_id": {""}, "r1_v_name": {"bravo"}, "r1_v_qty": {"20"},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("bulk copy = %d, want 303", code)
	}
	got := widgetRows(t, path)
	want := []string{"1:alpha:10", "2:bravo:20", "3:charlie:30", "4:alpha:10", "5:bravo:20"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("after bulk copy rows = %v,\nwant %v", got, want)
	}
}

// TestBulkApplyIsAllOrNothing — a failure partway through must roll back, not
// leave the first half of the selection written.
func TestBulkApplyIsAllOrNothing(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedThreeWidgets(t, path)
	execSQLite(t, path, `CREATE UNIQUE INDEX uq_widget_name ON widgets (name)`)
	login(t, client, ts.URL)

	tokens := browseRowTokens(t, client, ts.URL, "widgets")
	body := bulkForm(t, client, ts.URL, "edit", tokens)
	form := url.Values{
		"csrf_token": {csrfFrom(t, client, ts.URL+"/")},
		"mode":       {"edit"},
		"bulk_count": {"3"},
	}
	// Row 0 renames cleanly; row 1 collides with row 2's existing name, so the
	// second statement fails after the first has already run.
	for i, v := range []struct{ orig, next string }{
		{"alpha", "RENAMED"}, {"bravo", "charlie"}, {"charlie", "charlie"},
	} {
		p := fmt.Sprintf("r%d_", i)
		form.Set(p+"where", hiddenValue(t, body, p+"where"))
		form.Set(p+"v_name", v.next)
		form.Set(p+"orig_name", v.orig)
	}
	code, _ := postTo(t, client, ts.URL+"/db/main/table/widgets/rows/apply", form)
	if code == http.StatusSeeOther {
		t.Fatalf("the colliding save reported success (%d)", code)
	}
	got := widgetRows(t, path)
	want := []string{"1:alpha:10", "2:bravo:20", "3:charlie:30"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("a failed bulk save left rows partially written: %v,\nwant the untouched %v", got, want)
	}
}

// TestBulkApplyRejectsBadInput — the guards on the apply endpoint, which is
// reachable directly and must not trust its own form.
func TestBulkApplyRejectsBadInput(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedThreeWidgets(t, path)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")
	apply := ts.URL + "/db/main/table/widgets/rows/apply"

	for name, form := range map[string]url.Values{
		"no mode":        {"csrf_token": {csrf}, "bulk_count": {"1"}},
		"unknown mode":   {"csrf_token": {csrf}, "mode": {"obliterate"}, "bulk_count": {"1"}},
		"no count":       {"csrf_token": {csrf}, "mode": {"edit"}},
		"count over cap": {"csrf_token": {csrf}, "mode": {"edit"}, "bulk_count": {"100000"}},
		"bad row key":    {"csrf_token": {csrf}, "mode": {"edit"}, "bulk_count": {"1"}, "r0_where": {"nonsense!!"}},
	} {
		t.Run(name, func(t *testing.T) {
			code, _ := postTo(t, client, apply, form)
			if code != http.StatusBadRequest {
				t.Errorf("%s = %d, want 400", name, code)
			}
		})
	}
	// Nothing was written by any of them.
	if got := widgetRows(t, path); len(got) != 3 {
		t.Errorf("a rejected apply still changed the table: %v", got)
	}
}
