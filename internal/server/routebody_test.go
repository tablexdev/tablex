package server_test

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/auth"
	"github.com/tablexdev/tablex/internal/server"
)

// TestPostRoutesRefuseOversizedBodies drives every POST route in router.go
// with a body just past that route's own cap and pins the outcome: 413 for
// every route whose handler parses the body, and a named exception — with the
// reason — for the rest. A route added tomorrow that hand-rolls ParseForm and
// swallows the error surfaces here as a 400 (empty form) where 413 was
// expected; that is exactly how manageProgram's swallowed parse read as
// "Unknown operation." before it was fixed.
//
// Load-bearing request shape (see import_size_test.go, which pins the same
// mechanics for the import cap):
//   - Authenticated, or the auth gate redirects before the body is drained.
//   - CSRF token in the HEADER: the csrf middleware then skips its own bounded
//     parse and the oversized body surfaces in the handler as 413. In the form
//     field instead, the middleware's parse blows the cap first, the token
//     reads empty, and the request fails closed at 403 — never reaching the
//     handler under test.
//   - Path params resolve against the standard fixture (main / widgets),
//     because handlers touch the scope before or after parsing and either
//     order must land on a real object.
//   - Each body is sized from bodyLimitFor's own three-way rule, so the test
//     follows the middleware when a cap changes.
func TestPostRoutesRefuseOversizedBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("sends tens of megabytes per route")
	}

	patterns := postRoutePatterns(t)

	// The named exceptions, each with the reason it cannot answer 413.
	exceptions := map[string]int{
		// Login self-manages its parse (documented exception in handlers.go),
		// but an authenticated caller is redirected home before it: there is
		// no legitimate re-login flow over a live session.
		"/login": http.StatusSeeOther,
		// Logout never reads the body at all; any size gets the redirect.
		"/logout": http.StatusSeeOther,
	}

	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// One shared pad sized for the largest cap; every request slices it.
	maxCap := server.BodyLimitFor("/", true)
	const over = 4096 // how far past the cap each body reaches
	pad := append([]byte("pad="), bytes.Repeat([]byte{'a'}, int(maxCap)+over)...)

	// /logout runs last: a successful logout destroys the session, and every
	// route after it would read 303-to-login instead of its own outcome.
	patterns = append(slices.DeleteFunc(patterns, func(p string) bool { return p == "/logout" }), "/logout")

	for _, pattern := range patterns {
		path := strings.NewReplacer("{db}", "main", "{table}", "widgets").Replace(pattern)
		want := http.StatusRequestEntityTooLarge
		if status, ok := exceptions[path]; ok {
			want = status
		}
		size := server.BodyLimitFor(path, true) + over
		req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(pad[:4+int(size)]))
		if err != nil {
			t.Fatalf("new request %s: %v", path, err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(auth.CSRFHeader, csrf)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("POST %s: %v", path, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("POST %s with a body past its cap = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

// postRoutePatterns scans router.go for the POST route table. The parity check
// against a plain substring count means a route registered in a shape the
// regexp does not match fails the test rather than silently escaping it, and
// the floor keeps the scan from passing by matching nothing.
func postRoutePatterns(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("reading router.go: %v", err)
	}
	matches := regexp.MustCompile(`HandleFunc\("POST ([^"]+)"`).FindAllStringSubmatch(string(src), -1)
	if raw := strings.Count(string(src), `"POST `); len(matches) != raw {
		t.Fatalf("parsed %d POST routes but router.go contains %d %q markers; the route scan is missing some", len(matches), raw, `"POST `)
	}
	const floor = 33 // the POST route count when this test was written
	if len(matches) < floor {
		t.Fatalf("parsed %d POST routes, expected at least %d — this scan is not looking where it thinks", len(matches), floor)
	}
	routes := make([]string, 0, len(matches))
	for _, m := range matches {
		routes = append(routes, m[1])
	}
	return routes
}
