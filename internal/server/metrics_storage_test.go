package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/config"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// scrapeInternal performs an authorized scrape against ts and returns the body.
func scrapeInternal(t *testing.T, ts *httptest.Server, token string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+metricsPath, nil)
	if err != nil {
		t.Fatalf("build scrape request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read scrape body: %v", err)
	}
	return string(b)
}

// TestMetricsStorageDownIsVisible: tablex_storage_up has to be a real probe, not a
// restatement of the config. This is the one thing the black-box suite cannot
// reach — nothing over HTTP can take the metadata database away — so it closes the
// pool directly, which is precisely what "the metadata database went away" is.
//
// It also covers the degradation counter, whose whole purpose is to say that
// session durability is not currently being delivered even though TableX is still
// serving. Both are the signals an operator alarms on, and neither is otherwise
// observable outside the log.
func TestMetricsStorageDownIsVisible(t *testing.T) {
	dir := t.TempDir()
	appDB := filepath.Join(dir, "app.db")
	if err := os.WriteFile(appDB, nil, 0o600); err != nil {
		t.Fatalf("create app db: %v", err)
	}

	cfg := config.Default()
	cfg.Security.LoginRateMax = 1000
	cfg.Servers = []config.ServerConfig{{Name: "testdb", Engine: "sqlite", FilePath: appDB}}
	cfg.Storage = config.StorageConfig{Engine: "sqlite", FilePath: filepath.Join(dir, "meta.db")}
	const token = "probe-token"
	cfg.Metrics = config.MetricsConfig{Enabled: true, Token: token}

	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); _ = srv.Shutdown(context.Background()) })

	// A healthy store answers the probe, and has not degraded.
	body := scrapeInternal(t, ts, token)
	if !strings.Contains(body, "tablex_storage_up 1") {
		t.Errorf("a reachable metadata database is not reported up:\n%s", storageLines(body))
	}
	if !strings.Contains(body, "tablex_storage_degraded_total 0") {
		t.Errorf("a healthy store reports degradations:\n%s", storageLines(body))
	}

	// Take the metadata database away. TableX is designed to keep serving from its
	// own view when this happens, which is exactly why the fact has to reach
	// /metrics — nothing about the responses changes.
	if err := srv.storage.Close(); err != nil {
		t.Fatalf("closing the metadata pool: %v", err)
	}

	body = scrapeInternal(t, ts, token)
	if !strings.Contains(body, "tablex_storage_up 0") {
		t.Errorf("an unreachable metadata database is still reported up:\n%s", storageLines(body))
	}

	// A request that needs a session now falls back to this process's own view.
	// It still succeeds — that is the design — so the counter is the only place
	// the degradation shows up.
	resp, err := ts.Client().Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /login with the metadata database gone = %d, want 200 (it must degrade, not fail)", resp.StatusCode)
	}

	body = scrapeInternal(t, ts, token)
	if strings.Contains(body, "tablex_storage_degraded_total 0") {
		t.Errorf("the session store degraded but the counter still reads 0:\n%s", storageLines(body))
	}
}

// storageLines pulls just the storage samples out of an exposition, so a failure
// message shows the relevant lines instead of the whole scrape.
func storageLines(body string) string {
	var keep []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "tablex_storage") {
			keep = append(keep, line)
		}
	}
	if len(keep) == 0 {
		return "(no tablex_storage* samples at all)"
	}
	return strings.Join(keep, "\n")
}

// TestHistogramArithmetic exercises the exposition's numeric core directly,
// because two of its properties are unreachable over HTTP: an observation slower
// than the last bucket (no unit test may take eleven seconds) and a status class
// no handler can write. Both are exactly where a hand-written histogram goes
// wrong — the overflow slot is counted in NO explicit bucket, so leaving it out of
// the running total makes +Inf disagree with _count, and a scraper answers "how
// many requests" from +Inf.
func TestHistogramArithmetic(t *testing.T) {
	m := &metrics{}
	m.observe(http.MethodGet, 200, 3*time.Millisecond)    // an early bucket
	m.observe(http.MethodPost, 503, 400*time.Millisecond) // the middle
	m.observe(http.MethodGet, 200, 30*time.Second)        // past the last bucket
	m.observe("PROPFIND", 999, 7*time.Second)             // odd method, odd status

	var e exposition
	m.writeHTTP(&e)
	body := e.b.String()

	buckets, sum, count := parseHistogram(t, body)
	if len(buckets) != len(durationBuckets)+1 {
		t.Fatalf("emitted %d bucket samples, want %d (the ladder plus +Inf)", len(buckets), len(durationBuckets)+1)
	}
	for i := 1; i < len(buckets); i++ {
		if buckets[i] < buckets[i-1] {
			t.Errorf("bucket %d (%v) is below bucket %d (%v); buckets must be cumulative", i, buckets[i], i-1, buckets[i-1])
		}
	}
	if count != 4 {
		t.Errorf("_count = %v after four observations", count)
	}
	if inf := buckets[len(buckets)-1]; inf != count {
		t.Errorf("+Inf = %v but _count = %v; the overflow slot is missing from the total", inf, count)
	}
	// Only the 30s observation is past the last explicit bucket (7s still fits
	// under le=10), so that bucket must sit at 3 — one BELOW the total. If it
	// equalled the total, the overflow would be being counted twice.
	if last := buckets[len(buckets)-2]; last != 3 {
		t.Errorf("the le=10 bucket = %v, want 3 (everything but the 30s observation)", last)
	}
	// Seconds, not microseconds: 0.003 + 0.4 + 30 + 7.
	if want := 37.403; sum < want-0.05 || sum > want+0.05 {
		t.Errorf("_sum = %v, want about %v SECONDS", sum, want)
	}

	// The odd method and the impossible status are filed under the catch-alls
	// rather than dropped or given a series of their own.
	if !strings.Contains(body, `tablex_http_requests_total{method="other",status="5xx"} 1`) {
		t.Errorf("an unusual method/status pair was not filed under the catch-alls:\n%s", body)
	}
	if strings.Contains(body, "PROPFIND") || strings.Contains(body, "999") {
		t.Errorf("an unbounded label value reached the exposition:\n%s", body)
	}
}

// parseHistogram pulls the bucket ladder (in emitted order), the sum and the count
// out of a rendered histogram.
func parseHistogram(t *testing.T, body string) (buckets []float64, sum, count float64) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		name, value, found := strings.Cut(line, " ")
		if !found || strings.HasPrefix(line, "#") {
			continue
		}
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(name, "tablex_http_request_duration_seconds_bucket"):
			buckets = append(buckets, v)
		case name == "tablex_http_request_duration_seconds_sum":
			sum = v
		case name == "tablex_http_request_duration_seconds_count":
			count = v
		}
	}
	return buckets, sum, count
}

// TestLabelEscaping: build_info carries the only label value TableX does not
// choose itself, and an unescaped quote or newline in it would corrupt every
// series after it in the scrape.
func TestLabelEscaping(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`1.2.3`, `version="1.2.3"`},
		{`a"b`, `version="a\"b"`},
		{`a\b`, `version="a\\b"`},
		{"a\nb", `version="a\nb"`},
		{``, `version=""`},
	} {
		if got := label("version", c.in); got != c.want {
			t.Errorf("label(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}
