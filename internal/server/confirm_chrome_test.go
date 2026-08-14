package server_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestConfirmPageChrome pins the no-JS confirmation interstitial's chrome
// across the three navigation shapes. It used to render an EMPTY breadcrumb
// and an empty bordered tab strip; requireConfirm now sets the breadcrumb from
// the request scope and deliberately omits tabs, and the layout hides the
// (always-emitted) tab container when there are none — on the full-page path,
// on an htmx navigation INTO the confirmation page (where the container is
// swapped out-of-band, not just its <ul>), and on an htmx navigation back OUT
// (which must restore a real tab strip).
func TestConfirmPageChrome(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// A drop WITHOUT tx_confirm reaches the interstitial. Full-page first.
	dropForm := func() url.Values {
		return url.Values{"csrf_token": {csrf}, "action": {"drop"}}
	}
	full, err := client.PostForm(ts.URL+"/db/main/table/widgets/operations", dropForm())
	if err != nil {
		t.Fatalf("full-page confirm: %v", err)
	}
	fullBody, _ := io.ReadAll(full.Body)
	full.Body.Close()
	if full.StatusCode != http.StatusOK {
		t.Fatalf("full-page confirm = %d, want 200; body:\n%.1000s", full.StatusCode, fullBody)
	}
	page := string(fullBody)
	// The breadcrumb names the object (server → main → widgets), not empty.
	if !strings.Contains(page, "widgets") || !strings.Contains(page, "breadcrumb") {
		t.Errorf("full-page confirmation has no populated breadcrumb:\n%.2000s", page)
	}
	// The tab container is present but hidden (d-none), never a bare strip.
	if !strings.Contains(page, `id="topmenucontainer"`) {
		t.Error("full-page confirmation dropped the tab container entirely (breaks the next htmx swap target)")
	}
	if !strings.Contains(page, "d-none") {
		t.Errorf("full-page confirmation's empty tab strip is not hidden:\n%.2000s", page)
	}

	// htmx navigation INTO the confirmation: the fragment swaps the WHOLE
	// container out-of-band, hidden, so no stale bordered strip remains.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/db/main/table/widgets/operations", strings.NewReader(dropForm().Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	hx, err := client.Do(req)
	if err != nil {
		t.Fatalf("htmx confirm: %v", err)
	}
	hxBody, _ := io.ReadAll(hx.Body)
	hx.Body.Close()
	frag := string(hxBody)
	if !strings.Contains(frag, `id="topmenucontainer"`) || !strings.Contains(frag, `hx-swap-oob="true"`) {
		t.Errorf("htmx confirmation must swap the tab CONTAINER out-of-band (not just its <ul>):\n%.2000s", frag)
	}
	if !strings.Contains(frag, "d-none") {
		t.Errorf("htmx confirmation's out-of-band tab container is not hidden:\n%.2000s", frag)
	}

	// htmx navigation OUT of the confirmation, to an ordinary tabbed page: the
	// container comes back visible (no d-none) and carries real tabs.
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/db/main/table/widgets/structure", nil)
	req.Header.Set("HX-Request", "true")
	out, err := client.Do(req)
	if err != nil {
		t.Fatalf("htmx back-out: %v", err)
	}
	outBody, _ := io.ReadAll(out.Body)
	out.Body.Close()
	restored := string(outBody)
	// The out-of-band container must be present and NOT hidden, and carry tabs.
	i := strings.Index(restored, `id="topmenucontainer"`)
	if i < 0 {
		t.Fatalf("htmx navigation out of the confirmation did not restore the tab container:\n%.2000s", restored)
	}
	container := restored[i:]
	if end := strings.Index(container, "</div>"); end >= 0 {
		container = container[:end]
	}
	if strings.Contains(container, "d-none") {
		t.Errorf("the restored tab container is still hidden:\n%.500s", container)
	}
	if !strings.Contains(restored, "id=\"topmenu\"") || !strings.Contains(restored, "Browse") {
		t.Errorf("the restored tab strip carries no real tabs:\n%.2000s", restored)
	}
}
