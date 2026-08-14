package handlers

// A dial failure on the stored-program routes is connError's 503 with its
// redacted warn line. These paths used to answer 502 and log nothing — the
// one place in the handler layer where the identical failure earned a
// different status depending on which handler was reached, and the only
// terminal dial failures that never reached the log.

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/session"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"
)

// authedRequest attaches a live session carrying uc to r, the way the session
// middleware plus a login would.
func authedRequest(t *testing.T, r *http.Request, uc *UserContext) *http.Request {
	t.Helper()
	mgr := session.NewManager(session.NewMemStore(), session.Config{
		CookieName: "s", IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour,
	})
	t.Cleanup(mgr.Shutdown)
	pre := mgr.Start(httptest.NewRecorder(), r)
	if pre == nil {
		t.Fatal("Start returned no session")
	}
	s, ok := mgr.Authenticate(httptest.NewRecorder(), pre, uc, func() {})
	if !ok {
		t.Fatal("Authenticate refused the session")
	}
	return r.WithContext(session.NewContext(r.Context(), s))
}

func TestProgramRoutesDialFailureIs503AndLogged(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	var logBuf bytes.Buffer
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&logBuf, nil))}
	d, ok := driver.Get("mysql")
	if !ok {
		t.Fatal("mysql dialect not registered")
	}
	// Port 1: nothing listens there, so ConnFor's pool open for a non-server
	// database dials and fails fast.
	uc := NewUserContext("srv", "srv", d,
		driver.ConnParams{Host: "127.0.0.1", Port: 1, User: "u", Password: "pw"},
		openTestConn(t), nil)

	cases := []struct {
		name   string
		invoke http.HandlerFunc
		req    func() *http.Request
	}{
		{"manageProgram (POST /db/{db}/routines)", h.DBRoutinesManage, func() *http.Request {
			form := url.Values{"action": {"drop"}, "name": {"x"}, "i": {"0"}}
			r := httptest.NewRequest(http.MethodPost, "/db/other/routines", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.SetPathValue("db", "other")
			return r
		}},
		{"programEditor (GET /db/{db}/routines/edit)", h.RoutineEditor, func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/db/other/routines/edit", nil)
			r.SetPathValue("db", "other")
			return r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logBuf.Reset()
			w := httptest.NewRecorder()
			tc.invoke(w, authedRequest(t, tc.req(), uc))
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("dial failure = %d, want 503 — a backend being unreachable is a service condition, not a bad upstream response", w.Code)
			}
			if !strings.Contains(logBuf.String(), "connection open failed") {
				t.Error("the dial failure produced no warn line; these were the only terminal dial failures that never reached the log")
			}
		})
	}
}
