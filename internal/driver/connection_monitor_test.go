package driver_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestMonitorPassthroughs: the Connection wrappers exist so the monitor reads
// run under the same readCtx (read_stmt_timeout) budget as every other
// generated read — the handlers used to call the dialect's Monitor methods
// against the bare pool, the only generated reads that could hold a pooled
// connection indefinitely. SQLite implements Monitor (PRAGMA-backed
// variables, an empty process list), and an already-canceled context must
// propagate, which is what proves the reads run under the context the
// wrapper derives.
func TestMonitorPassthroughs(t *testing.T) {
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	path := filepath.Join(t.TempDir(), "mon.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if !conn.CanMonitor() {
		t.Fatal("sqlite implements Monitor; CanMonitor must report it")
	}
	ctx := context.Background()
	vars, err := conn.Variables(ctx)
	if err != nil || len(vars) == 0 {
		t.Errorf("Variables = %d vars, err %v; want PRAGMA-backed values", len(vars), err)
	}
	if _, err := conn.Status(ctx); err != nil {
		t.Errorf("Status: %v", err)
	}
	if _, err := conn.Processes(ctx); err != nil {
		t.Errorf("Processes: %v", err)
	}

	// SQLite's Variables surfaces a failed PRAGMA read as an explicit
	// "(unavailable: …)" value rather than an error — so context propagation
	// shows up IN the values: every pragma read under an already-canceled
	// context must report the cancellation.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := conn.Variables(canceled)
	if err != nil {
		t.Fatalf("Variables under a canceled context: %v", err)
	}
	for _, v := range got {
		if !strings.Contains(v.Value, "context canceled") {
			t.Fatalf("variable %s = %q under a canceled context — the read is not running under the derived context", v.Name, v.Value)
		}
	}
	if len(got) == 0 {
		t.Fatal("no variables at all under a canceled context; this proves nothing")
	}
}
