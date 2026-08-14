package driver_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// specializingDialect wraps a real dialect with the optional ServerSpecializer
// hook, standing in for MySQL/PostgreSQL (SQLite carries no per-connection
// state, so the real unit-test engine cannot show the difference). It records
// the ServerInfo it was handed and reports a distinguishing profile, so a test
// can prove a connection path routed the dialect through driver.Specialize
// rather than storing the registered singleton verbatim.
type specializingDialect struct {
	driver.Dialect
	gotFlavor string
}

func (d specializingDialect) WithServerInfo(info driver.ServerInfo) driver.Dialect {
	d.gotFlavor = info.Flavor
	return d
}

// LexerProfile mirrors how the real dialects gate script behaviour on the facts
// WithServerInfo recorded: an unspecialized copy reports the conservative zero
// value, exactly as MySQL's does for an unknown flavor. driver.ProfileOf is what
// the console/import splitter consults, so this is the property that regressed.
func (d specializingDialect) LexerProfile() driver.LexerProfile {
	var p driver.LexerProfile
	p.Returning.Delete = d.gotFlavor != ""
	return p
}

// newSpecializeFixture returns the wrapped sqlite dialect and an empty database
// file to dial.
func newSpecializeFixture(t *testing.T) (specializingDialect, driver.ConnParams) {
	t.Helper()
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	path := filepath.Join(t.TempDir(), "specialize.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create temp db file: %v", err)
	}
	return specializingDialect{Dialect: d}, driver.ConnParams{FilePath: path}
}

// TestOpenSpecializesDialect pins the pooled path: Connection.Dialect must be
// the WithServerInfo copy, not the dialect Open was called with.
func TestOpenSpecializesDialect(t *testing.T) {
	d, params := newSpecializeFixture(t)
	conn, err := driver.Open(context.Background(), d, params)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	got, ok := conn.Dialect().(specializingDialect)
	if !ok {
		t.Fatalf("Connection.Dialect() = %T, want specializingDialect", conn.Dialect())
	}
	if got.gotFlavor == "" {
		t.Error("Connection.Dialect() is the unspecialized dialect; Open did not apply WithServerInfo")
	}
}

// TestOpenPinnedSpecializesDialect is a regression test. The pinned path
// (SQL console, SQL import) previously stored the dialect it was handed
// verbatim, so driver.ProfileOf saw the registered zero value: on MariaDB a
// `DELETE … RETURNING` was classified as a non-row statement, ran through Exec,
// and its returned rows were silently discarded.
func TestOpenPinnedSpecializesDialect(t *testing.T) {
	d, params := newSpecializeFixture(t)

	// A guard against the ordering trap this fix has to respect: OpenPinned caps
	// the pool at one connection and holds it, so ServerInfo must run BEFORE the
	// checkout or it blocks on an exhausted pool until the dial budget expires.
	done := make(chan *driver.Pinned, 1)
	errc := make(chan error, 1)
	go func() {
		p, err := driver.OpenPinned(context.Background(), d, params)
		if err != nil {
			errc <- err
			return
		}
		done <- p
	}()

	var pinned *driver.Pinned
	select {
	case pinned = <-done:
	case err := <-errc:
		t.Fatalf("OpenPinned: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("OpenPinned hung: ServerInfo ran against the exhausted single-connection pool")
	}
	defer pinned.Close()

	got, ok := pinned.Dialect().(specializingDialect)
	if !ok {
		t.Fatalf("Pinned.Dialect() = %T, want specializingDialect", pinned.Dialect())
	}
	if got.gotFlavor == "" {
		t.Fatal("Pinned.Dialect() is the unspecialized dialect; OpenPinned did not apply WithServerInfo")
	}
	// The consumer that actually regressed: the splitter reads its grammar and
	// its RETURNING gates through ProfileOf(conn.Dialect()).
	if !driver.ProfileOf(pinned.Dialect()).Returning.Delete {
		t.Error("driver.ProfileOf(Pinned.Dialect()) reports the conservative zero profile; " +
			"DELETE … RETURNING would run as Exec and discard its rows")
	}
}

// TestOpenAppliesTuning covers tail: pool sizing and the generated-read
// statement budget are operator config, carried down every dial on ConnParams
// rather than through a package-level variable.
func TestOpenAppliesTuning(t *testing.T) {
	d, params := newSpecializeFixture(t)
	params.Tuning = driver.Tuning{MaxOpenConns: 3, MaxIdleConns: 2, ReadStmtTimeout: 7 * time.Second}
	conn, err := driver.Open(context.Background(), d, params)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	if got := conn.DB().Stats().MaxOpenConnections; got != 3 {
		t.Errorf("pool MaxOpenConnections = %d, want 3", got)
	}
	if got := conn.Tuning(); got.MaxOpenConns != 3 || got.MaxIdleConns != 2 || got.ReadStmtTimeout != 7*time.Second {
		t.Errorf("Connection.Tuning() = %+v, want the configured values", got)
	}
	ctx, cancel := conn.WithReadTimeout(context.Background())
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("WithReadTimeout returned a deadline-free context")
	}
	if d := time.Until(dl); d > 7*time.Second || d < 5*time.Second {
		t.Errorf("read deadline is %v away, want ~7s (the configured budget)", d)
	}
}

// TestOpenTuningDefaults: a zero Tuning must resolve to the package defaults,
// and an idle count above the open cap must be clamped rather than silently
// disagreeing with what database/sql enforces.
func TestOpenTuningDefaults(t *testing.T) {
	d, params := newSpecializeFixture(t)
	conn, err := driver.Open(context.Background(), d, params)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()
	got := conn.Tuning()
	if got.MaxOpenConns != driver.DefaultMaxOpenConns || got.MaxIdleConns != driver.DefaultMaxIdleConns {
		t.Errorf("default Tuning = %+v, want the package defaults", got)
	}
	if got.ReadStmtTimeout != driver.ReadStmtTimeout {
		t.Errorf("default read budget = %v, want %v", got.ReadStmtTimeout, driver.ReadStmtTimeout)
	}

	d2, params2 := newSpecializeFixture(t)
	params2.Tuning = driver.Tuning{MaxOpenConns: 2, MaxIdleConns: 9}
	conn2, err := driver.Open(context.Background(), d2, params2)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn2.Close()
	if got := conn2.Tuning(); got.MaxIdleConns != 2 {
		t.Errorf("MaxIdleConns = %d, want it clamped to MaxOpenConns (2)", got.MaxIdleConns)
	}
}

// TestSpecializeWithoutHook covers the graceful path: an engine with no
// per-connection state (SQLite) is returned unchanged rather than rejected.
func TestSpecializeWithoutHook(t *testing.T) {
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("sqlite dialect not registered")
	}
	if got := driver.Specialize(d, driver.ServerInfo{Flavor: "SQLite"}); got != d {
		t.Errorf("Specialize on a dialect without the hook = %v, want the dialect unchanged", got)
	}
}
