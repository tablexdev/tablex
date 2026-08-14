package server_test

// Row LIMIT/OFFSET on a table export — a sampling aid for a table too big to
// dump whole.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// exportWithRange posts a table export with the given row-range fields.
func exportWithRange(t *testing.T, client *http.Client, base, format, limit, offset string) string {
	t.Helper()
	form := url.Values{
		"csrf_token": {csrfFrom(t, client, base+"/")},
		"format":     {format}, "structure": {"1"}, "data": {"1"},
	}
	if limit != "" {
		form.Set("row_limit", limit)
	}
	if offset != "" {
		form.Set("row_offset", offset)
	}
	code, body := postTo(t, client, base+"/db/main/table/widgets/export", form)
	if code != http.StatusOK {
		t.Fatalf("export (limit=%q offset=%q) = %d\n%.600s", limit, offset, code, body)
	}
	return body
}

func TestExportRowRange(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `DELETE FROM widgets`)
	for i := 1; i <= 6; i++ {
		execSQLite(t, path, fmt.Sprintf(
			`INSERT INTO widgets (id, name, qty) VALUES (%d,'row%d',%d)`, i, i, i*10))
	}
	login(t, client, ts.URL)

	// A limit bounds the dump.
	body := exportWithRange(t, client, ts.URL, "sql", "2", "")
	for _, want := range []string{"row1", "row2"} {
		if !strings.Contains(body, want) {
			t.Errorf("limit=2 dropped %q:\n%.900s", want, body)
		}
	}
	for _, unwanted := range []string{"row3", "row4", "row5", "row6"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("limit=2 exported %q — the limit did not reach the query:\n%.900s", unwanted, body)
		}
	}
	// Structure is unaffected: a sampled dump still has to restore into a table.
	if !strings.Contains(body, "CREATE TABLE") {
		t.Error("a row-limited export dropped the structure")
	}

	// The offset moves the window.
	body = exportWithRange(t, client, ts.URL, "sql", "2", "2")
	for _, want := range []string{"row3", "row4"} {
		if !strings.Contains(body, want) {
			t.Errorf("offset=2 dropped %q:\n%.900s", want, body)
		}
	}
	if strings.Contains(body, "row1") || strings.Contains(body, "row5") {
		t.Errorf("offset=2 exported rows outside the window:\n%.900s", body)
	}

	// Every format honours it.
	for _, format := range []string{"csv", "json"} {
		body = exportWithRange(t, client, ts.URL, format, "2", "")
		if strings.Contains(body, "row3") {
			t.Errorf("%s export ignored the row limit:\n%.600s", format, body)
		}
		if !strings.Contains(body, "row1") {
			t.Errorf("%s export with a limit returned nothing:\n%.600s", format, body)
		}
	}
}

// TestExportRowRangeDefaults — the field is optional, and a nonsense value must
// mean "no limit" rather than "no rows": a silently empty dump is the worst
// possible reading of a fat-fingered field.
func TestExportRowRangeDefaults(t *testing.T) {
	ts, client, path := newTestServer(t)
	execSQLite(t, path, `DELETE FROM widgets`)
	for i := 1; i <= 3; i++ {
		execSQLite(t, path, fmt.Sprintf(
			`INSERT INTO widgets (id, name, qty) VALUES (%d,'row%d',%d)`, i, i, i))
	}
	login(t, client, ts.URL)

	for _, limit := range []string{"", "0", "-5", "abc"} {
		body := exportWithRange(t, client, ts.URL, "sql", limit, "")
		for i := 1; i <= 3; i++ {
			if !strings.Contains(body, fmt.Sprintf("row%d", i)) {
				t.Errorf("row_limit=%q dropped row%d; a non-positive or unparseable limit must mean NO limit:\n%.700s",
					limit, i, body)
			}
		}
	}

	// The form offers the control at table scope only.
	_, tform := getBody(t, client, ts.URL+"/db/main/table/widgets/export")
	if !strings.Contains(tform, `name="row_limit"`) {
		t.Error("the table export form has no row-limit control")
	}
	_, dform := getBody(t, client, ts.URL+"/db/main/export")
	if strings.Contains(dform, `name="row_limit"`) {
		t.Error(`the database export form offers a row limit; "the first N rows of every table" is not a coherent export`)
	}
}
