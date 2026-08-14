package driver_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
)

// wedgingInfoDialect wraps a real dialect and simulates a server that
// connects fine but wedges on the version/metadata query: with no deadline on
// the context, ServerInfo blocks until the caller gives up — which, for a
// deadline-free context, is forever.
type wedgingInfoDialect struct {
	driver.Dialect
}

func (d wedgingInfoDialect) ServerInfo(ctx context.Context, db *sql.DB) (driver.ServerInfo, error) {
	if _, ok := ctx.Deadline(); !ok {
		<-ctx.Done() // never fires for a deadline-free context
		return driver.ServerInfo{}, ctx.Err()
	}
	return d.Dialect.ServerInfo(ctx, db)
}

// TestOpenBoundsServerInfo covers 2.1: Open must derive a bounded context for
// the ServerInfo call — the production login passes a deadline-free
// r.Context(), and a wedged metadata query previously stalled login forever
// while holding a pooled connection.
func TestOpenBoundsServerInfo(t *testing.T) {
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	wrapped := wedgingInfoDialect{Dialect: d}
	path := filepath.Join(t.TempDir(), "open_test.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		conn, err := driver.Open(context.Background(), wrapped, driver.ConnParams{FilePath: path})
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Open with bounded ServerInfo failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Open hung: ServerInfo was called with an unbounded context")
	}
}
