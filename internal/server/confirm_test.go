package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestDestructiveActionNeedsConfirmation is the regression test for the gap
// docs/security.md used to record: confirmation was an `hx-confirm` attribute
// and nothing else, so with JavaScript off a Drop button acted on the first
// click.
//
// The two halves matter equally. Without the field the action must NOT have
// happened — a 200 that quietly dropped the table would satisfy "returns a
// page" while being the exact bug. With the field it must go through.
func TestDestructiveActionNeedsConfirmation(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// The table's own browse page is the existence probe: 200 while it is
	// there, and an error page once it is gone.
	tableGone := func() bool {
		code, _ := getBody(t, client, ts.URL+"/db/main/table/widgets")
		return code != http.StatusOK
	}
	if tableGone() {
		t.Fatal("fixture: widgets should exist before the drop")
	}

	// 1. No confirmation → the interstitial, and the table survives.
	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"drop"}})
	if err != nil {
		t.Fatalf("unconfirmed drop: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unconfirmed drop = %d, want 200 (the confirmation page)", resp.StatusCode)
	}
	if !strings.Contains(body, `name="tx_confirm"`) {
		t.Errorf("the confirmation page does not carry the confirmation field:\n%.1200s", body)
	}
	// The original request's fields must be re-posted, or confirming would
	// submit a different action than the one being confirmed.
	if !strings.Contains(body, `name="action" value="drop"`) {
		t.Errorf("the confirmation page does not re-post the action:\n%.1200s", body)
	}
	if tableGone() {
		t.Fatal("the table was dropped WITHOUT confirmation — the gate did nothing")
	}

	// 2. With the confirmation → it runs.
	resp, err = client.PostForm(ts.URL+"/db/main/table/widgets/operations",
		url.Values{"csrf_token": {csrf}, "action": {"drop"}, "tx_confirm": {"1"}})
	if err != nil {
		t.Fatalf("confirmed drop: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirmed drop = %d, want 303", resp.StatusCode)
	}
	if !tableGone() {
		t.Error("the table is still there after a confirmed drop")
	}
}

// TestConfirmationRunsAfterValidation pins the ordering the whole design rests
// on: the gate is the LAST step, so a request that would have been refused is
// still refused rather than being met with "are you sure?" about something that
// cannot happen.
func TestConfirmationRunsAfterValidation(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	for _, c := range []struct {
		name, path string
		form       url.Values
		want       int
	}{
		{"drop an unknown column", "/db/main/table/widgets/structure",
			url.Values{"action": {"drop_column"}, "column": {"nope"}}, http.StatusBadRequest},
		{"drop an unknown index", "/db/main/table/widgets/structure",
			url.Values{"action": {"drop_index"}, "index_name": {"nope"}}, http.StatusBadRequest},
	} {
		c.form.Set("csrf_token", csrf)
		resp, err := client.PostForm(ts.URL+c.path, c.form)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s = %d, want %d — validation must run BEFORE the confirmation gate",
				c.name, resp.StatusCode, c.want)
		}
	}
}
