package server_test

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var assetRefRE = regexp.MustCompile(`(?:href|src)="(/static/[^"?]+)\?v=([0-9a-f]+)"`)

// The assets are versioned by the binary but their URLs were not, so a
// client revalidated every one of them once an hour — a dozen conditional GETs
// per hour per client for bytes that cannot change without a new build. The
// templates now stamp a build fingerprint on each URL, which is what makes it
// safe to answer with immutable.
func TestVersionedAssetsAreImmutable(t *testing.T) {
	ts, client, _ := newTestServer(t)
	code, body := getBody(t, client, ts.URL+"/login")
	if code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", code)
	}

	refs := assetRefRE.FindAllStringSubmatch(body, -1)
	if len(refs) < 4 {
		t.Fatalf("only %d versioned asset references on the page; the templates are "+
			"not stamping ?v=", len(refs))
	}
	// EVERY static reference, not merely several: one unstamped link is one asset
	// still revalidating hourly, and counting the stamped ones cannot see it.
	for _, m := range regexp.MustCompile(`(?:href|src)="(/static/[^"]+)"`).FindAllStringSubmatch(body, -1) {
		if !strings.Contains(m[1], "?v=") {
			t.Errorf("%s is referenced without ?v=; it will keep revalidating every hour", m[1])
		}
	}
	// One fingerprint for the whole tree: a mixture would mean the value is being
	// computed per reference rather than once for the build.
	ver := refs[0][2]
	for _, r := range refs {
		if r[2] != ver {
			t.Errorf("%s carries version %q but %s carries %q", r[1], r[2], refs[0][1], ver)
		}
	}
	if len(ver) < 8 {
		t.Errorf("asset version %q is too short to be a fingerprint", ver)
	}

	// The stamped URL is cached for a year.
	for _, r := range refs {
		url := ts.URL + r[1] + "?v=" + r[2]
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", url, resp.StatusCode)
			continue
		}
		cc := resp.Header.Get("Cache-Control")
		if !strings.Contains(cc, "immutable") || !strings.Contains(cc, "max-age=31536000") {
			t.Errorf("%s: Cache-Control = %q, want a year and immutable", r[1], cc)
		}
	}

	// A bare path, or last build's version, must NOT be frozen: its bytes can
	// change under that URL, and a client pinned to a stale asset never asks again.
	for _, u := range []string{"/static/css/tablex.css", "/static/css/tablex.css?v=deadbeef"} {
		resp, err := client.Get(ts.URL + u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		resp.Body.Close()
		cc := resp.Header.Get("Cache-Control")
		if strings.Contains(cc, "immutable") {
			t.Errorf("%s: Cache-Control = %q — an unversioned URL must not be immutable", u, cc)
		}
		if !strings.Contains(cc, "max-age=3600") {
			t.Errorf("%s: Cache-Control = %q, want the short lifetime", u, cc)
		}
	}

	// app.js loads CodeMirror lazily and needs the same fingerprint, so it is
	// published in the head rather than duplicated in script.
	if !strings.Contains(body, `<meta name="asset-version" content="`+ver+`">`) {
		t.Error("the asset version is not published for app.js; the lazily-loaded " +
			"CodeMirror files would be the only assets still revalidating hourly")
	}
}

// The sidebar was a <div role="navigation">. The element carries the
// landmark itself, and one of them is the markup the other is describing.
func TestSidebarIsANavElement(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	code, body := getBody(t, client, ts.URL+"/")
	if code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", code)
	}
	if !strings.Contains(body, `<nav id="tx_nav" class="tx-nav" aria-label="Database navigation">`) {
		t.Error("the sidebar is not a <nav> with its label")
	}
	if strings.Contains(body, `role="navigation"`) {
		t.Error("something still declares role=\"navigation\" instead of using <nav>")
	}
	if !strings.Contains(body, "</nav>") {
		t.Error("no closing </nav>; the sidebar markup is unbalanced")
	}
}
