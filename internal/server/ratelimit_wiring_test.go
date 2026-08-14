package server

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// TestAccountRateLimiterIsWiredToTheSweeper is white-box because the defect was
// invisible from outside: the per-account limiter was built, handed to the
// handlers, and then held by nothing the server itself could reach — so
// sweepRateLimiter had no way to reclaim it, and every distinct username tried
// planted an entry that nothing would ever remove.
//
// A black-box test cannot see this. Sweep() has one caller, the sweep interval
// is floored at a minute, and the limiter exposes no size accessor, so from the
// outside a swept limiter and an unswept one are indistinguishable. What pins
// the wiring is that the Server holds the SAME limiter the handlers do.
func TestAccountRateLimiterIsWiredToTheSweeper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wiring_test.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.Servers = []config.ServerConfig{{Name: "testdb", Engine: "sqlite", FilePath: path}}

	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer s.Shutdown(context.Background())

	if s.accountRate == nil {
		t.Fatal("Server.accountRate is nil: the per-account limiter is unreachable from the sweeper")
	}
	if s.accountRate != s.handlers.AccountRate {
		t.Error("Server.accountRate is not the limiter the handlers throttle against; sweeping it would reclaim nothing")
	}
	// Two instances on purpose: the account key is shared by everyone typing the
	// same username, so its cap is deliberately higher than the per-IP one.
	if s.rate == s.accountRate {
		t.Error("the per-IP and per-account limiters are the same instance; their caps are meant to differ")
	}
}
