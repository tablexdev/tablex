package server

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
	"github.com/tablexdev/tablex/internal/server/handlers"
)

// The policy table is the whole of restricted mode, so it is worth reading twice
// — once in router.go where it is declared, and once here where every row is
// stated independently. A row that disagrees means somebody changed a route's
// authority, which should never be a silent edit.
//
// White-box because the policy mux is unexported and there is no other way to
// ask "what does this (method, path) resolve to" without issuing a real request
// per row and inferring the answer from a status code.
func TestEveryRouteResolvesToItsDeclaredNeed(t *testing.T) {
	read := need{}
	console := need{console: true}
	runSQL := need{write: true, console: true}
	rowWrite := need{write: true}
	schema := need{write: true, ddl: true}

	cases := []struct {
		method, path string
		want         need
	}{
		// Infrastructure. Public paths short-circuit before the policy is read;
		// they are declared anyway so the table is the whole route set.
		{"GET", "/healthz", read},
		{"GET", metricsPath, read},
		{"GET", "/favicon.ico", read},
		{"GET", "/static/css/tablex.css", read},

		// Auth and the SSO gate.
		{"GET", "/login", read},
		{"POST", "/login", read},
		{"POST", "/logout", read},
		{"GET", handlers.SSOStartPath, read},
		{"GET", handlers.SSOCallbackPath, read},

		// Home / server level.
		{"GET", "/", read},
		{"GET", "/server", read},
		{"POST", "/server", schema},
		{"GET", "/server/sql", console},
		{"POST", "/server/sql", runSQL},
		{"GET", "/server/status", read},
		{"GET", "/server/variables", read},
		{"GET", "/server/processes", read},
		{"POST", "/server/processes", schema},
		{"GET", "/server/users", read},
		{"POST", "/server/users", schema},
		{"GET", "/server/export", read},
		{"POST", "/server/export", read},
		{"GET", "/server/import", console},
		{"POST", "/server/import", runSQL},

		// Navigation fragments.
		{"GET", "/nav", read},
		{"GET", "/nav/children", read},

		// Database level. The {db} value is a user-chosen name, which is exactly
		// what the old last-segment classifier could not tell from a route verb.
		{"GET", "/db/main", read},
		{"GET", "/db/main/sql", console},
		{"POST", "/db/main/sql", runSQL},
		{"GET", "/db/main/search", read},
		{"POST", "/db/main/search", read},
		{"GET", "/db/main/qbe", read},
		{"POST", "/db/main/qbe", read},
		{"GET", "/db/main/designer", read},
		{"GET", "/db/main/export", read},
		{"POST", "/db/main/export", read},
		{"GET", "/db/main/import", console},
		{"POST", "/db/main/import", runSQL},
		{"GET", "/db/main/create-table", read},
		{"POST", "/db/main/create-table", schema},
		{"GET", "/db/main/operations", read},
		{"POST", "/db/main/operations", schema},
		{"GET", "/db/main/privileges", read},
		{"POST", "/db/main/privileges", schema},
		{"GET", "/db/main/routines", read},
		{"POST", "/db/main/routines", schema},
		{"GET", "/db/main/routines/edit", read},
		{"GET", "/db/main/routines/privileges", read},
		{"POST", "/db/main/routines/privileges", schema},
		{"GET", "/db/main/events", read},
		{"POST", "/db/main/events", schema},
		{"GET", "/db/main/events/edit", read},
		{"GET", "/db/main/triggers", read},
		{"POST", "/db/main/triggers", schema},
		{"GET", "/db/main/triggers/edit", read},
		{"GET", "/db/main/definition", read},

		// Table level.
		{"GET", "/db/main/table/widgets", read},
		{"GET", "/db/main/table/widgets/structure", read},
		{"POST", "/db/main/table/widgets/structure", schema},
		{"GET", "/db/main/table/widgets/sql", console},
		{"POST", "/db/main/table/widgets/sql", runSQL},
		{"GET", "/db/main/table/widgets/search", read},
		{"POST", "/db/main/table/widgets/search", read},
		{"GET", "/db/main/table/widgets/insert", read},
		{"POST", "/db/main/table/widgets/insert", rowWrite},
		{"GET", "/db/main/table/widgets/edit", read},
		{"POST", "/db/main/table/widgets/edit", rowWrite},
		{"POST", "/db/main/table/widgets/delete", rowWrite},
		{"POST", "/db/main/table/widgets/rows", rowWrite},
		{"POST", "/db/main/table/widgets/rows/apply", rowWrite},
		{"GET", "/db/main/table/widgets/export", read},
		{"POST", "/db/main/table/widgets/export", read},
		{"GET", "/db/main/table/widgets/import", console},
		{"POST", "/db/main/table/widgets/import", runSQL},
		{"GET", "/db/main/table/widgets/operations", read},
		{"POST", "/db/main/table/widgets/operations", schema},
		{"GET", "/db/main/table/widgets/triggers", read},
		{"POST", "/db/main/table/widgets/triggers", schema},
		{"GET", "/db/main/table/widgets/triggers/edit", read},
		{"GET", "/db/main/table/widgets/privileges", read},
		{"POST", "/db/main/table/widgets/privileges", schema},
	}

	s := newPolicyTestServer(t)
	for _, c := range cases {
		if got := s.needFor(httptest.NewRequest(c.method, c.path, nil)); got != c.want {
			t.Errorf("%s %s resolves to %+v, want %+v", c.method, c.path, got, c.want)
		}
	}

	// The table above must be the WHOLE route set, not a subset somebody stopped
	// extending. Counted from router.go's source because a ServeMux cannot be
	// asked what it holds.
	if registered := countRegistrations(t); len(cases) != registered {
		t.Errorf("this table has %d rows but router.go registers %d routes; every route needs a row here", len(cases), registered)
	}
}

// TestAnUnmatchedRequestFailsClosed covers the shapes that reach needFor without
// being a policy entry. Each one is a case a bare type assertion or a missing
// default would get wrong.
func TestAnUnmatchedRequestFailsClosed(t *testing.T) {
	s := newPolicyTestServer(t)
	closed := need{write: true, ddl: true}

	for _, c := range []struct {
		name, method, path string
		want               need
	}{
		// No pattern matches under any method: the mux answers with NotFound and
		// an empty pattern. This is the shape TestAnUnclassifiedRouteFailsClosed
		// exercises end to end.
		{"an unregistered path", "POST", "/db/main/table/widgets/no-such-operation", closed},
		// A registered path with an unregistered method: a 405 handler, also with
		// an empty pattern.
		{"a registered path, wrong method", "DELETE", "/db/main/table/widgets/structure", closed},
		// A safe method on both of the above needs nothing, because the fail-closed
		// default is keyed on the method too.
		{"an unregistered path, safe method", "GET", "/no-such-page", need{}},
	} {
		if got := s.needFor(httptest.NewRequest(c.method, c.path, nil)); got != c.want {
			t.Errorf("%s (%s %s) resolves to %+v, want %+v", c.name, c.method, c.path, got, c.want)
		}
	}

	// Redirect handlers are the reason the type assertion is comma-ok. Both of
	// these come back as *redirectHandler rather than a policyEntry, and the
	// first carries a NON-empty pattern — which is what a bare assertion panics
	// on. They must fail closed, not crash.
	for _, c := range []struct{ name, method, path string }{
		{"the /static subtree redirect", "POST", "/static"},
		{"a path needing cleaning", "POST", "//db/main"},
		{"a cleaned path matching nothing", "POST", "//no-such-page"},
	} {
		got := s.needFor(httptest.NewRequest(c.method, c.path, nil))
		if got != closed {
			t.Errorf("%s (%s %s) resolves to %+v, want the fail-closed %+v", c.name, c.method, c.path, got, closed)
		}
	}
}

// countRegistrations counts the routes router.go registers, whatever shape their
// pattern is built in — three are assembled from constants, so scanning for a
// quoted pattern would miss them.
func countRegistrations(t *testing.T) int {
	t.Helper()
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("reading router.go: %v", err)
	}
	// "rt.Handle(" is not a substring of "rt.HandleFunc(", so the two counts do
	// not overlap.
	n := strings.Count(string(src), "rt.HandleFunc(") + strings.Count(string(src), "rt.Handle(")
	if n < 60 {
		t.Fatalf("found only %d registrations in router.go; this scan is not looking where it thinks", n)
	}
	// Guard the scan itself: the registrar has exactly the two methods counted
	// above, so a third would be silently uncounted.
	methods := regexp.MustCompile(`func \(rt routes\) (\w+)\(`).FindAllStringSubmatch(string(src), -1)
	if len(methods) != 2 {
		t.Fatalf("routes has %d registrar methods, but this scan counts 2; add the new one", len(methods))
	}
	return n
}

func newPolicyTestServer(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy_test.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.Metrics.Enabled = true
	cfg.Metrics.Token = "policy-test-token"
	cfg.SSO = config.SSOConfig{}
	cfg.Servers = []config.ServerConfig{{Name: "testdb", Engine: "sqlite", FilePath: path}}

	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	// router() is what populates s.policy; New only stores the wrapped handler.
	_ = s.router()
	return s
}
