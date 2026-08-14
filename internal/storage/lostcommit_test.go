package storage

// A database/sql driver whose Commit APPLIES and then reports failure, and the
// three fail-closed rules that need one.
//
// §6a's row counter and §6d's marker retention both turn on a distinction no
// broken schema can produce. A commit that was REACHED and answered with an
// error may still have applied, so it is not the same event as a statement that
// failed before any commit — and the store treats them differently on purpose:
// the counter moves and the marker stays for the first, neither happens for the
// second. Dropping the table underneath a transaction produces only the second
// (the DELETE fails first), which is what session_internal_test.go covers, so
// both post-commit branches were unreachable from any test.
//
// The seam stays entirely inside this file. openPool builds a SQLite pool with
// sql.Open(d.SQLDriverName(), dsn), so registering a wrapped database/sql driver
// under a second name — plus a dialect that answers with that name — reaches the
// store's real code with a real database behind it. No exported test hook, and
// no production edit.

import (
	"context"
	"database/sql"
	sqldriver "database/sql/driver"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/session"
)

// lostCommitEngine names both the database/sql driver and the dialect. One name
// for both is what routes storage.Open through the wrapper: the dialect's
// SQLDriverName is precisely what openPool hands to sql.Open.
const lostCommitEngine = "sqlite-lostcommit"

// errLostCommit is what an armed Commit answers with AFTER the real commit has
// succeeded — the response-was-lost shape, not a rollback.
var errLostCommit = errors.New("lostcommit: the commit applied but its response was lost")

// lostCommitArmed gates the behaviour, so the fixture is provably inert while a
// test writes its fixtures. Package-level because the driver is registered once
// per binary; tests in a package run one at a time unless they ask not to, and
// armLostCommit disarms on cleanup.
var lostCommitArmed atomic.Bool

// armLostCommit makes every subsequent Commit apply and then fail, until the
// test ends. Registered after newLostCommitStore's cleanup so it runs BEFORE the
// pool is closed.
func armLostCommit(t *testing.T) {
	t.Helper()
	lostCommitArmed.Store(true)
	t.Cleanup(func() { lostCommitArmed.Store(false) })
}

// --- the driver wrapper ---------------------------------------------------------

type lostCommitDriver struct{ inner sqldriver.Driver }

func (d lostCommitDriver) Open(name string) (sqldriver.Conn, error) {
	c, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	// The store always begins with a context, and database/sql only falls back
	// to the deprecated Conn.Begin for a connection that cannot do better.
	// Requiring ConnBeginTx here means the wrapper never has to reimplement that
	// fallback's semantics, and says so loudly if the driver ever changes.
	b, ok := c.(sqldriver.ConnBeginTx)
	if !ok {
		_ = c.Close()
		return nil, errors.New("lostcommit: the sqlite driver does not implement ConnBeginTx")
	}
	return lostCommitConn{Conn: c, tx: b}, nil
}

// lostCommitConn embeds the driver's own Conn, so Prepare and Close pass
// straight through. It deliberately does NOT re-export the optional interfaces
// (QueryerContext, ExecerContext, ConnPrepareContext, …): interface embedding
// promotes only Conn's own method set, so database/sql falls back to prepared
// statements for everything else — slower, universally supported, and enough.
type lostCommitConn struct {
	sqldriver.Conn
	tx sqldriver.ConnBeginTx
}

func (c lostCommitConn) Begin() (sqldriver.Tx, error) {
	return c.BeginTx(context.Background(), sqldriver.TxOptions{})
}

func (c lostCommitConn) BeginTx(ctx context.Context, opts sqldriver.TxOptions) (sqldriver.Tx, error) {
	tx, err := c.tx.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return lostCommitTx{Tx: tx}, nil
}

type lostCommitTx struct{ sqldriver.Tx }

// Commit applies and THEN fails, which is the entire fixture. The caller cannot
// tell this from a commit whose acknowledgement was lost on the wire, and that
// indistinguishability is why the store's rules are written the way they are.
func (t lostCommitTx) Commit() error {
	if err := t.Tx.Commit(); err != nil {
		return err
	}
	if lostCommitArmed.Load() {
		return errLostCommit
	}
	return nil
}

// --- the dialect shim -----------------------------------------------------------

// lostCommitDialect is the SQLite dialect under a second engine name. Interface
// embedding promotes only Dialect's own method set, which is what keeps the shim
// honest: it cannot accidentally become a PoolOpener (so driver.Open takes the
// plain sql.Open path) or a ServerSpecializer (so Specialize hands it back
// unchanged).
type lostCommitDialect struct{ driver.Dialect }

func (lostCommitDialect) Name() string          { return lostCommitEngine }
func (lostCommitDialect) SQLDriverName() string { return lostCommitEngine }

// StorageDDL has to be declared explicitly, and this is the one trap in the
// whole fixture: it is NOT part of Dialect. It lives on the optional StorageHost
// interface, which embedding does not promote, so without this method
// storage.Open refuses the engine before it dials anything.
//
// It DELEGATES rather than stubbing. TestEveryEngineCanTypeTheSchema
// (storage_test.go — package storage_test, but the same test binary) walks
// driver.All() and will inspect this dialect, so zero-valued type spellings
// would fail a test that is about the real engines.
func (d lostCommitDialect) StorageDDL() driver.StorageDDL {
	return d.Dialect.(driver.StorageHost).StorageDDL()
}

var (
	registerLostCommit sync.Once
	lostCommitRegErr   error
)

// newLostCommitStore opens a session store over a real SQLite file reached
// through the wrapped driver. Registration happens once per binary — both
// sql.Register and driver.Register panic on a duplicate name.
func newLostCommitStore(t *testing.T, maxSessions int) *SessionStore {
	t.Helper()
	registerLostCommit.Do(func() {
		base, ok := driver.Get("sqlite")
		if !ok {
			lostCommitRegErr = errors.New("the sqlite dialect is not registered")
			return
		}
		// A throwaway pool, opened purely to get at the driver VALUE to wrap.
		// The database behind it is never used.
		probe, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			lostCommitRegErr = err
			return
		}
		sql.Register(lostCommitEngine, lostCommitDriver{inner: probe.Driver()})
		_ = probe.Close()
		driver.Register(lostCommitDialect{Dialect: base})
	})
	if lostCommitRegErr != nil {
		t.Fatalf("registering the lost-commit engine: %v", lostCommitRegErr)
	}

	// A real FILE, not :memory:. bootstrapFile creates it before the dialect's
	// own existence check, and the metadata pool holds four connections — behind
	// a :memory: DSN each would open its own private empty database.
	st, err := Open(context.Background(), Config{
		Engine:   lostCommitEngine,
		FilePath: filepath.Join(t.TempDir(), "meta.db"),
	})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	// Closed explicitly: on Windows t.TempDir cannot remove a file the pool
	// still holds open.
	t.Cleanup(func() { _ = st.Close() })
	return NewSessionStore(st, SessionStoreConfig{
		IdleTimeout: 30 * time.Minute,
		MaxSessions: maxSessions,
	})
}

// --- the rules ------------------------------------------------------------------

// TestRowCounterCountsAnAppliedButUnacknowledgedCommit is §6a's fail-closed rule
// in the case that actually needs it. insert moves the counter on WHATEVER
// Commit returned, because the row may be there — and here it demonstrably is.
// Counting only the nil case UNDERCOUNTS, and an undercounted cap is a cap that
// lets the table grow past storage.max_sessions until the next reconcile.
func TestRowCounterCountsAnAppliedButUnacknowledgedCommit(t *testing.T) {
	s := newLostCommitStore(t, 10)
	s.Save(session.Adopt(newEnvelope("a")))
	if got := rowsHeld(s); got != 1 {
		t.Fatalf("row counter = %d after one clean save, want 1 — the fixture is not inert", got)
	}

	armLostCommit(t)
	s.Save(session.Adopt(newEnvelope("b")))

	// The row IS in the table: the commit applied, only its answer was lost.
	if got := countSessionRows(t, s); got != 2 {
		t.Fatalf("rows = %d, want 2 — the fixture must APPLY the commit before failing it", got)
	}
	if got := rowsHeld(s); got != 2 {
		t.Errorf("row counter = %d after an applied-but-unacknowledged commit, want 2; the cap is now counting fewer rows than the table holds", got)
	}
	// Save itself cannot know, so it degrades and keeps the id for repersist.
	if s.Degradations() == 0 {
		t.Error("an ambiguous commit did not raise degradeTotal")
	}
	if !s.isUnpersisted("b") {
		t.Error("an id whose write could not be confirmed was recorded as persisted")
	}
}

// TestAReplacementIsNotCountedOnAnAmbiguousCommit is the half a rule keyed on the
// commit alone gets wrong. insert captures `grew` from the DELETE's own row count
// BEFORE the insert, so re-saving an existing id reaches the very same failing
// Commit and must still leave the counter where it was.
func TestAReplacementIsNotCountedOnAnAmbiguousCommit(t *testing.T) {
	s := newLostCommitStore(t, 10)
	sess := session.Adopt(newEnvelope("a"))
	s.Save(sess)
	if got := rowsHeld(s); got != 1 {
		t.Fatalf("row counter = %d after one clean save, want 1", got)
	}

	armLostCommit(t)
	s.Save(sess) // the SAME id: row-neutral, however the commit ends

	if got := countSessionRows(t, s); got != 1 {
		t.Errorf("rows = %d after a re-save, want 1", got)
	}
	if got := rowsHeld(s); got != 1 {
		t.Errorf("row counter = %d after an ambiguous REPLACEMENT, want 1; keying the increment on the commit counts every replacement as a new row", got)
	}
}

// TestTheMarkerSurvivesAnAmbiguousCommit is §6d's asymmetry, on both writers.
//
// A marker with no row is harmless — it only keeps absence non-final until epoch
// pruning drops it — while a row with no marker is exactly the publication an
// in-flight scan retires. So a commit that was REACHED keeps the reservation
// whatever it answered, and only a known PRE-COMMIT failure releases it. Both
// halves are asserted, because keeping the marker unconditionally would be the
// same bug facing the other way: an id that never got a row would hold a slot
// until the next prune, under exactly the flood that fills the map.
func TestTheMarkerSurvivesAnAmbiguousCommit(t *testing.T) {
	s := newLostCommitStore(t, 0)
	// Written while the fixture is inert, so replaceRow below has a real row for
	// its DELETE to find.
	pre := session.Adopt(newEnvelope("pre"))
	s.Save(pre)

	armLostCommit(t)

	// insert.
	s.Save(session.Adopt(newEnvelope("pub")))
	if !rowExists(t, s, "pub") {
		t.Fatal("the fixture did not apply the insert's commit")
	}
	if markerOf(s, "pub") == 0 {
		t.Error("insert released the marker for a row that exists; an in-flight scan would retire that session")
	}

	// replaceRow, driven through Replace. It still reports SUCCESS — via the
	// degraded local fallback — so what is asserted is the marker, not the answer.
	post := session.Adopt(newEnvelope("post"))
	if !s.Replace(pre, post) {
		t.Fatal("a login failed outright on an ambiguous commit; errors degrade, they do not refuse")
	}
	if !rowExists(t, s, "post") {
		t.Fatal("the fixture did not apply replaceRow's commit")
	}
	if markerOf(s, "post") == 0 {
		t.Error("replaceRow released the marker for a row that exists; the session it had just authenticated would be retired")
	}

	// The contrast. A failure the store KNOWS came before any commit releases the
	// reservation, on both writers: nothing is in doubt there, and holding the
	// slot would leak one per failed write for the length of a whole scan.
	if _, err := s.st.DB().Exec("DROP TABLE " + s.st.Table(SessionsTable)); err != nil {
		t.Fatalf("drop the sessions table: %v", err)
	}
	s.Save(session.Adopt(newEnvelope("gone")))
	if got := markerOf(s, "gone"); got != 0 {
		t.Errorf("insert kept marker %d after a pre-commit failure", got)
	}
	if !s.Replace(post, session.Adopt(newEnvelope("gone2"))) {
		t.Fatal("a login failed outright while storage was broken; errors degrade to the local swap")
	}
	if got := markerOf(s, "gone2"); got != 0 {
		t.Errorf("replaceRow kept marker %d after a pre-commit failure", got)
	}
}
