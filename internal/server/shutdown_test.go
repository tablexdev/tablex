package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/config"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

var csrfShutdownRE = regexp.MustCompile(`csrf-token" content="([^"]+)"`)

// serveTestServer builds a Server backed by a seeded SQLite predefined server and
// starts it on a real loopback listener via the internal httpSrv (white-box) so
// that Server.Shutdown actually drains through httpSrv.Shutdown. wrap, when
// non-nil, wraps the handler chain (installed before Serve starts) — the
// force-close test uses it to observe its stuck request entering the server.
// Returns the server, its base URL, and a cookie-jar client.
func serveTestServer(t *testing.T, wrap func(http.Handler) http.Handler) (*Server, string, *http.Client) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shutdown_test.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.Security.LoginRateMax = 1000
	cfg.Servers = []config.ServerConfig{{Name: "testdb", Engine: "sqlite", FilePath: path}}

	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if wrap != nil {
		srv.httpSrv.Handler = wrap(srv.httpSrv.Handler)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.httpSrv.Serve(ln) }()
	// Mirror newTestServer's cleanup: an early t.Fatal must not leak the
	// listener/serve goroutine or the sessions' pools (an open SQLite pool
	// also blocks TempDir removal on Windows). Shutdown is idempotent, so
	// tests that shut down explicitly are unaffected.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	})
	base := "http://" + ln.Addr().String()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return srv, base, client
}

func loginTo(t *testing.T, client *http.Client, base string) {
	t.Helper()
	resp, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfShutdownRE.FindStringSubmatch(string(b))
	if len(m) < 2 {
		t.Fatal("no CSRF token on login page")
	}
	resp, err = client.PostForm(base+"/login", url.Values{"csrf_token": {m[1]}, "server": {"testdb"}})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
}

// TestServerShutdownIdempotent covers #6/#7: Shutdown closes the logged-in
// session's pool and is safe to call twice (no panic on the second close of
// stopCh / the session manager).
func TestServerShutdownIdempotent(t *testing.T) {
	srv, base, client := serveTestServer(t, nil)
	loginTo(t, client, base)

	// Authenticated home renders.
	resp, err := client.Get(base + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated / = %d, want 200", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("first Shutdown: %v", err)
	}
	// Second call must not panic (sync.Once guards close(stopCh) and the manager).
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("second Shutdown returned %v, want nil", err)
	}
}

// TestServerShutdownForceCloseOnTimeout covers #6: when the drain times out
// (a request stuck reading its body), Shutdown force-closes the HTTP server and
// STILL closes every session pool — it must not skip session shutdown on a
// timeout, which would leak pools and credentials.
func TestServerShutdownForceCloseOnTimeout(t *testing.T) {
	// Synchronize on the stuck request ACTUALLY entering the server (the
	// wrapper fires at dispatch, before the body read blocks) instead of a
	// fixed sleep that raced a loaded runner.
	entered := make(chan struct{})
	srv, base, client := serveTestServer(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Test-Stuck") != "" {
				close(entered)
			}
			next.ServeHTTP(w, r)
		})
	})
	loginTo(t, client, base)

	// Open a raw connection and send a POST whose body never completes, so the
	// handler blocks reading it and Shutdown's drain cannot finish.
	host := base[len("http://"):]
	raw, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	// Full headers, Content-Length larger than the bytes we actually send.
	fmt.Fprintf(raw, "POST /login HTTP/1.1\r\nHost: %s\r\nX-Test-Stuck: 1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4096\r\n\r\nserver=testdb", host)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("stuck request never entered the server")
	}

	// The logged-in session's pool is live before shutdown.
	if n := srv.sessions.ActiveSessions(); n == 0 {
		t.Fatal("expected a live session before shutdown")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = srv.Shutdown(ctx)
	if err == nil {
		t.Error("Shutdown with a stuck in-flight request should report a drain timeout")
	}
	if time.Since(start) > 4*time.Second {
		t.Error("force-close did not unstick the drain promptly")
	}

	// The property this test exists to prove: despite the drain timeout, Shutdown
	// STILL closed every session pool. ActiveSessions()==0 is deterministic —
	// Shutdown reaps and closes every session — so it can't leak pools/credentials.
	if n := srv.sessions.ActiveSessions(); n != 0 {
		t.Errorf("after force-close, %d session pool(s) still open — pools leaked on timeout", n)
	}

	// Despite the timeout, the server is force-closed: a new request is refused.
	if _, e := client.Get(base + "/"); e == nil {
		t.Error("server still accepting requests after force-close")
	}
}
