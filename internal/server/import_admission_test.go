package server_test

// Import admission (#10).
//
// The upload is parsed by the CSRF middleware, ahead of the router, for any
// request whose token rides the form body — so by the time importer.go's
// acquireDBOp runs, the multipart parse and its temp-file spill are already
// done. Bounding concurrency therefore has to happen in the chain, before csrf,
// which is where all of these assertions are aimed.

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
)

// TestImportAdmissionRefusesOverTheCap: the cap is one, so the second concurrent
// import is turned away with the contract acquireDBOp defines — 503 with
// Retry-After, not a queued request holding an HTTP worker.
func TestImportAdmissionRefusesOverTheCap(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.MaxConcurrentImports = 1
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// A script slow enough that the two requests overlap: SQLite executes these
	// serially on one file, so the second is admitted only if the cap is not
	// working.
	script := strings.Repeat("CREATE TABLE IF NOT EXISTS t_adm (a int);\nDROP TABLE t_adm;\n", 400)

	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.PostForm(ts.URL+"/db/main/import", url.Values{
				"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {script},
			})
			if err != nil {
				return
			}
			resp.Body.Close()
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	if codes[http.StatusOK] == 0 {
		t.Errorf("no import succeeded at all: %v", codes)
	}
	if codes[http.StatusServiceUnavailable] == 0 {
		t.Errorf("six concurrent imports against a cap of one produced no 503: %v", codes)
	}
	for code := range codes {
		if code != http.StatusOK && code != http.StatusServiceUnavailable {
			t.Errorf("unexpected status %d: %v", code, codes)
		}
	}
}

// TestImportAdmissionReleasesTheSlot is the failure this cap would otherwise
// introduce: a slot leaked on ANY exit path silently shrinks the limit to zero,
// and the symptom is a 503 on a route that used to work. The CSRF 403 is the
// sharp case, because csrf runs DOWNSTREAM of admission.
func TestImportAdmissionReleasesTheSlot(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.MaxConcurrentImports = 1
	})
	login(t, client, ts.URL)

	// Several requests rejected by csrf, each of which held the slot.
	for i := 0; i < 3; i++ {
		resp, err := client.PostForm(ts.URL+"/db/main/import", url.Values{
			"csrf_token": {"wrong"}, "format": {"sql"}, "sql_script": {"SELECT 1;"},
		})
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a CSRF-invalid import = %d, want 403", resp.StatusCode)
		}
	}
	// And the route still works: if the slot had leaked this is a 503.
	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {"SELECT 1;"},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Fatal("the import slot leaked on the CSRF rejection path: the cap is now permanently exhausted")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("import after CSRF rejections = %d, want 200", resp.StatusCode)
	}
}

// TestImportAdmissionMatchesRoutesNotPaths pins why the route is resolved
// through the policy mux rather than by inspecting r.URL.Path. This middleware
// runs BEFORE routing, which is exactly where the two disagree.
func TestImportAdmissionMatchesRoutesNotPaths(t *testing.T) {
	// A cap of zero cannot refuse anything (<= 0 removes the cap), so the cap is
	// set to one and exhausted only by what genuinely routes to an import.
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.MaxConcurrentImports = 1
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// An UNROUTED path that ends in /import. A suffix test would admit it, hold a
	// slot, and at exhaustion answer 503 where the router answers 404 —
	// advertising capacity pressure on a route that does not exist.
	resp, err := client.PostForm(ts.URL+"/db/main/nope/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {"SELECT 1;"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Error("an unrouted …/import path was admitted against the import cap")
	}

	// And a percent-encoded database name, which a SEGMENT test over the decoded
	// path would miss entirely: this DOES route to POST /db/{db}/import with
	// db == "main/evil", so it must be admitted against the cap — the import
	// would otherwise proceed unbounded.
	resp, err = client.PostForm(ts.URL+"/db/main%2Fevil/import", url.Values{
		"csrf_token": {csrf}, "format": {"sql"}, "sql_script": {"SELECT 1;"},
	})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	// It reaches a handler (which then fails on the unknown database) rather
	// than being skipped by admission; the status is the handler's business.
	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("POST /db/main%%2Fevil/import = 404; it should route to the import handler")
	}
}

// TestImportAdmissionIgnoresUnauthenticated: sitting outside csrf, this
// middleware would otherwise answer an unauthenticated import POST with 503
// before csrf could issue its login redirect — changing protected-route
// behaviour and advertising that the route exists and is busy.
func TestImportAdmissionIgnoresUnauthenticated(t *testing.T) {
	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.MaxConcurrentImports = 1
	})
	// No login at all.
	for i := 0; i < 4; i++ {
		resp, err := client.PostForm(ts.URL+"/db/main/import", url.Values{
			"csrf_token": {"x"}, "format": {"sql"}, "sql_script": {"SELECT 1;"},
		})
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatal("an unauthenticated import POST was admitted against the cap and refused with 503")
		}
	}
}
