package server_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// Every htmx request now reports that it is running. The behaviour lives in
// app.js and there is no JS runner here, so what these tests can pin is the part
// the server owns — that the shell carries the bar exactly once, and that an
// htmx swap does not bring another one with it.
//
// That second half is the interesting one. The bar sits OUTSIDE #page_content on
// purpose: the fragment path re-renders page_main on every navigation, so a bar
// placed inside it would be replaced mid-request by the very response it was
// reporting on, and the page would accumulate one dead bar per click.
func TestProgressBarIsInTheShellAndNotInTheFragment(t *testing.T) {
	ts, client, _ := newTestServer(t)

	// The login page renders through the same layout, and its theme toggle is an
	// htmx request, so it needs the bar too.
	code, body := getBody(t, client, ts.URL+"/login")
	if code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", code)
	}
	if n := strings.Count(body, `id="tx-progress"`); n != 1 {
		t.Errorf("login page has %d progress bars, want exactly 1", n)
	}

	login(t, client, ts.URL)

	const page = "/db/main/table/widgets"
	code, full := getBody(t, client, ts.URL+page)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", page, code)
	}
	if n := strings.Count(full, `id="tx-progress"`); n != 1 {
		t.Errorf("full page has %d progress bars, want exactly 1", n)
	}
	// aria-hidden, because aria-busy on the swapped region is what a screen
	// reader is meant to hear.
	if !strings.Contains(full, `<div id="tx-progress" class="tx-progress" aria-hidden="true">`) {
		t.Error("the progress bar is not the inert aria-hidden element app.js expects")
	}

	frag := fragmentBody(t, client, ts.URL+page)
	if strings.Contains(frag, "tx-progress") {
		t.Error("the htmx fragment carries a progress bar; it would be swapped in " +
			"on every navigation and pile up outside the shell")
	}
	// Positive control: the fragment really is the page body, so the assertion
	// above is about placement and not about an empty response.
	if !strings.Contains(frag, `id="breadcrumb-list"`) {
		t.Fatalf("the fragment does not look like a rendered page: %.200s", frag)
	}
}

// fragmentBody fetches a page the way htmx does, so the server answers with the
// swap fragment rather than the whole document.
func fragmentBody(t *testing.T, client *http.Client, u string) string {
	t.Helper()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", u, err)
	}
	req.Header.Set("HX-Request", "true")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s as htmx: %v", u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", u, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s as htmx = %d, want 200", u, resp.StatusCode)
	}
	return string(b)
}
