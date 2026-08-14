package storage

// The durable session store's admission protocol, from INSIDE the package.
//
// session_test.go and storage_test.go are both package storage_test and can
// only reach exported API, but every property here is about unexported state —
// the row counter, the generation markers, the unpersisted map — or about a race
// that needs a scan paused mid-flight. Hence a second file rather than an
// exported test hook, which would widen the surface for tests alone.

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/session"
)

// newTestStore opens a fresh SQLite metadata database with the given cap. Its
// own helper rather than storage_test.go's: that file is package storage_test
// and cannot be reached from here.
func newTestStore(t *testing.T, maxSessions int) *SessionStore {
	t.Helper()
	st, err := Open(context.Background(), Config{
		Engine:   "sqlite",
		FilePath: filepath.Join(t.TempDir(), "meta.db"),
	})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	// Closed explicitly: the SQLite file lives under t.TempDir, whose cleanup
	// cannot remove a file the pool still holds open on Windows.
	t.Cleanup(func() { _ = st.Close() })
	return NewSessionStore(st, SessionStoreConfig{
		IdleTimeout: 30 * time.Minute,
		MaxSessions: maxSessions,
	})
}

// countSessionRows reads the table directly, so a test can check the row cap
// against reality rather than against the counter it is testing.
func countSessionRows(t *testing.T, s *SessionStore) int {
	t.Helper()
	var n int
	if err := s.st.DB().QueryRow("SELECT COUNT(*) FROM " + s.st.Table(SessionsTable)).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

func newEnvelope(id string) session.Envelope {
	now := time.Now()
	return session.Envelope{ID: id, CSRF: "csrf-" + id, Created: now, LastSeen: now}
}

// rowExists reports whether the table holds a row for one id, read directly for
// the same reason countSessionRows is: the point is what was really stored.
func rowExists(t *testing.T, s *SessionStore, id string) bool {
	t.Helper()
	var n int
	stmt := "SELECT COUNT(*) FROM " + s.st.Table(SessionsTable) + " WHERE " + s.st.Col("id") + " = " + s.st.Placeholder(1)
	if err := s.st.DB().QueryRow(stmt, id).Scan(&n); err != nil {
		t.Fatalf("count rows for %q: %v", id, err)
	}
	return n > 0
}

// markerOf reads an id's generation marker under the map's own guard. Zero
// means it holds none.
func markerOf(s *SessionStore, id string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generations[id]
}

// rowsHeld reads the row counter under the admission mutex, which is what
// guards it.
func rowsHeld(s *SessionStore) int {
	s.admit.Lock()
	defer s.admit.Unlock()
	return s.rows
}

// fillGenerations stands the store at n generation markers, so a test can put a
// publication against the cap. The map is written directly rather than through
// reserveGeneration: that bumps s.gen once per entry, which would leave every
// REAL marker looking older than a scan that has not started yet.
func fillGenerations(t *testing.T, s *SessionStore, n int) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range n {
		s.generations[string(rune(i))+"filler"] = 1
	}
}

// TestRowCapRefusesWithoutTouchingTheDatabase covers §6a. Over the cap the write
// is refused and the session runs process-local — and the REFUSAL itself must
// cost no SQL, because the flood this cap exists to shed is exactly what would
// otherwise pay for a BeginTx, a DELETE and a rollback per refused request.
func TestRowCapRefusesWithoutTouchingTheDatabase(t *testing.T) {
	s := newTestStore(t, 2)

	for i, id := range []string{"a", "b"} {
		s.Save(session.Adopt(newEnvelope(id)))
		if got := countSessionRows(t, s); got != i+1 {
			t.Fatalf("after saving %q the table holds %d rows, want %d", id, got, i+1)
		}
	}

	// At capacity: refused, and the session still works locally.
	s.Save(session.Adopt(newEnvelope("c")))
	if got := countSessionRows(t, s); got != 2 {
		t.Errorf("the table grew past the cap: %d rows", got)
	}
	if _, ok := s.Get("c"); !ok {
		t.Error("a session refused a durable row was lost; it must run process-local")
	}
	// Refused, not degraded: a configured cap doing its job must not raise the
	// one metric that means durability is broken.
	if s.CapRefusals() != 1 {
		t.Errorf("cap refusals = %d, want 1", s.CapRefusals())
	}
	if s.Degradations() != 0 {
		t.Errorf("a capacity refusal raised degradeTotal (%d); it is a policy, not a failure", s.Degradations())
	}
	// And its absence is NOT final, or the next lookup would sign it out.
	if s.absenceIsFinal("c", noScan) {
		t.Error("a session that could not be stored is treated as logged out")
	}
}

// TestRowCapExemptsARowNeutralResave covers the other half of §6a: insert is
// documented as replacing any row carrying the id, so a re-Save of a locally
// held session does not grow the table and must not be refused at the cap.
func TestRowCapExemptsARowNeutralResave(t *testing.T) {
	s := newTestStore(t, 1)
	sess := session.Adopt(newEnvelope("a"))
	s.Save(sess)
	if got := countSessionRows(t, s); got != 1 {
		t.Fatalf("rows = %d, want 1", got)
	}

	// At the cap, re-saving the SAME id: row-neutral, so it proceeds.
	s.Save(sess)
	if got := countSessionRows(t, s); got != 1 {
		t.Errorf("a re-save changed the row count: %d", got)
	}
	if s.CapRefusals() != 0 {
		t.Errorf("a row-neutral re-save was refused by the cap (%d refusals)", s.CapRefusals())
	}
	// The counter did not double-count it either, which is what would silently
	// exhaust the cap after a few re-saves.
	s.admit.Lock()
	rows := s.rows
	s.admit.Unlock()
	if rows != 1 {
		t.Errorf("row counter = %d after a replacement, want 1", rows)
	}
}

// TestReplaceIsExemptFromTheRowCap covers §6e: replaceRow deletes and inserts in
// ONE transaction, so a login never grows the table. Refusing it at the cap
// would fail logins under exactly the flood the cap exists to survive.
func TestReplaceIsExemptFromTheRowCap(t *testing.T) {
	s := newTestStore(t, 1)
	pre := session.Adopt(newEnvelope("pre"))
	s.Save(pre)

	authed := session.Adopt(newEnvelope("post"))
	if !s.Replace(pre, authed) {
		t.Fatal("a login was refused at the row cap; Replace is row-neutral and must be exempt")
	}
	if got := countSessionRows(t, s); got != 1 {
		t.Errorf("rows = %d after a login, want 1", got)
	}
	if _, ok := s.Get("post"); !ok {
		t.Error("the authenticated session is not resolvable")
	}
	if _, ok := s.Get("pre"); ok {
		t.Error("the pre-auth session survived the swap")
	}
}

// TestReplaceSucceedsForAnUnpersistedSession covers the hole §6a names: a
// session this process never managed to WRITE has no row for replaceRow's DELETE
// to find, so swapped == false — and reading that as "somebody else won" refuses
// the login. Absence is not evidence, the same rule absenceIsFinal encodes.
func TestReplaceSucceedsForAnUnpersistedSession(t *testing.T) {
	s := newTestStore(t, 1)
	// Fill the cap with an unrelated session, so the next Save is refused a row.
	s.Save(session.Adopt(newEnvelope("filler")))

	pre := session.Adopt(newEnvelope("pre"))
	s.Save(pre)
	if !s.isUnpersisted("pre") {
		t.Fatal("the fixture is wrong: pre was expected to be refused a durable row")
	}

	authed := session.Adopt(newEnvelope("post"))
	if !s.Replace(pre, authed) {
		t.Fatal("a login on a session that was never written was refused")
	}
	// The login must survive a SUBSEQUENT request, which is where the missing
	// unpersisted mark would show up: absenceIsFinal would read true, Get would
	// return nothing, and the user would be signed out right after logging in.
	if _, ok := s.Get("post"); !ok {
		t.Error("the session was signed out on the request after it logged in")
	}
	if !s.isUnpersisted("post") {
		t.Error("the new id was not marked unpersisted, so its absence would read as final")
	}
}

// TestAdoptionSurvivesAScanThatPredatesIt covers §6d's third publication site.
//
// Replica B creates the row; this replica's scan takes its snapshot BEFORE that;
// a request then arrives and adopts the row correctly — and the sweep, judging
// against its stale snapshot, finds the session locally, absent from the
// snapshot, and retires it as "ended on another replica". The user is signed out
// on the request after the one that adopted them.
func TestAdoptionSurvivesAScanThatPredatesIt(t *testing.T) {
	s := newTestStore(t, 0)

	// The scan's snapshot: taken before the row exists anywhere.
	epoch := s.scanEpoch()
	present := map[string]session.Envelope{}

	// Another replica writes the row (straight to the table, not through s).
	env := newEnvelope("remote")
	if _, err := s.st.DB().Exec(s.ins, env.ID, env.CSRF, Micros(env.Created), Micros(env.LastSeen)); err != nil {
		t.Fatalf("seed the peer's row: %v", err)
	}
	// This replica adopts it.
	live, ok := s.Get(env.ID)
	if !ok || live == nil {
		t.Fatal("the row was not adopted")
	}

	// Now the stale sweep's predicate runs.
	if _, stored := present[env.ID]; stored {
		t.Fatal("fixture: the id must be absent from the pre-dating snapshot")
	}
	if s.absenceIsFinal(env.ID, epoch) {
		t.Error("a session adopted after the scan began was retired as ended elsewhere")
	}
	// A scan starting AFTER the adoption sees it as old, so a genuine remote
	// logout is still honoured — the property that makes the store useful.
	if !s.absenceIsFinal(env.ID, s.scanEpoch()) {
		t.Error("after a later scan begins, a missing row must be final again")
	}
}

// TestGenerationsArePrunedByEpoch covers §6d's bound. Per-id state filled by
// anonymous requests is the bug being fixed; it does not get to reappear as the
// fix. Pruning is keyed on the scan epoch rather than on observation, because an
// id the local store evicted whose row was then deleted elsewhere reaches
// neither the row set nor the dead list.
func TestGenerationsArePrunedByEpoch(t *testing.T) {
	s := newTestStore(t, 0)
	for _, id := range []string{"a", "b", "c"} {
		s.reserveGeneration(id)
	}
	if got := len(s.generations); got != 3 {
		t.Fatalf("markers = %d, want 3", got)
	}
	// A scan that started after all three were stamped completes.
	s.pruneGenerations(s.scanEpoch())
	if got := len(s.generations); got != 0 {
		t.Errorf("markers = %d after pruning at a later epoch, want 0", got)
	}

	// A marker stamped DURING the scan survives its prune: that is the whole
	// point — it protects a publication that raced the scan.
	epoch := s.scanEpoch()
	s.reserveGeneration("during")
	s.pruneGenerations(epoch)
	if _, ok := s.generations["during"]; !ok {
		t.Error("a marker stamped after the scan began was pruned by it")
	}
}

// TestMarkerCapacityRefusesPublicationButNotAdoption covers §6d's two rules. A
// publisher over the cap runs process-local; an ADOPTION cannot decline, because
// refusing would sign out a session another replica owns.
func TestMarkerCapacityRefusesPublicationButNotAdoption(t *testing.T) {
	s := newTestStore(t, 0)
	fillGenerations(t, s, maxGenerationEntries)

	if s.reserveGeneration("new") {
		t.Error("a publication took a marker slot past the cap")
	}
	// An id that already holds one is not a new slot, so it still stamps.
	s.mu.Lock()
	s.generations["known"] = 1
	s.mu.Unlock()
	if !s.reserveGeneration("known") {
		t.Error("re-stamping an id that already held a marker consumed a new slot")
	}
}

// TestForgetDropsEveryPerIDMap covers §6f: three maps written from nine sites is
// how lifecycle state ended up in more than one place. forget is the single
// place that drops all of them.
func TestForgetDropsEveryPerIDMap(t *testing.T) {
	s := newTestStore(t, 0)
	s.mu.Lock()
	s.touched["x"] = time.Now()
	s.unpersisted["x"] = true
	s.generations["x"] = 1
	s.mu.Unlock()

	s.forget("x")

	s.mu.Lock()
	defer s.mu.Unlock()
	for name, present := range map[string]bool{
		"touched":     s.touched["x"] != time.Time{},
		"unpersisted": s.unpersisted["x"],
		"generations": s.generations["x"] != 0,
	} {
		if present {
			t.Errorf("forget left an entry in %s", name)
		}
	}
}

// TestEvictionPrunesTheBookkeeping covers §6f-bis. The local store evicts
// SILENTLY at its own capacity, so without a hook the per-id maps outlive the
// sessions they describe — which is finding #6's unbounded growth relocated from
// the table into memory, and it is unbounded for the whole length of a storage
// outage (Reap returns before its pruning passes when selectAll fails).
//
// This is NOT the cap unpersisted must never have: it removes the entry for a
// session that no longer exists here, and after eviction Get(id) returns
// (nil, false) down both branches either way.
func TestEvictionPrunesTheBookkeeping(t *testing.T) {
	if testing.Short() {
		t.Skip("creates more than the in-memory store's capacity")
	}
	// Drop the metadata table so every Save fails and lands in unpersisted —
	// simulating the outage during which nothing prunes.
	s := newTestStore(t, 0)
	if _, err := s.st.DB().Exec("DROP TABLE " + s.st.Table(SessionsTable)); err != nil {
		t.Fatalf("drop the sessions table: %v", err)
	}

	const n = 10500 // past the in-memory store's 10000
	for i := range n {
		s.Save(session.Adopt(newEnvelope("sess-" + string(rune('a'+i%26)) + "-" + itoa(i))))
	}
	s.mu.Lock()
	got := len(s.unpersisted)
	s.mu.Unlock()
	if got > 10000 {
		t.Errorf("unpersisted holds %d entries after %d failed saves; eviction must prune it", got, n)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestDeleteAndRepersistDoNotRace covers §6c: a logout landing between
// repersist's local.Get and its insert would RECREATE the row for a session the
// user just ended. Both take the admission mutex, so they serialize.
func TestDeleteAndRepersistDoNotRace(t *testing.T) {
	s := newTestStore(t, 0)
	sess := session.Adopt(newEnvelope("x"))
	s.Save(sess)
	// Pretend the write failed, so repersist has something to retry.
	s.setPersisted("x", false)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.Delete("x") }()
	go func() { defer wg.Done(); s.repersist(map[string]session.Envelope{}) }()
	wg.Wait()

	// Whichever order they ran in, a logged-out session must not be resolvable.
	if _, ok := s.Get("x"); ok {
		t.Error("a logout raced by repersist left the session alive")
	}
}

// TestRowCounterSurvivesAnAmbiguousCommit covers the PRE-COMMIT half of §6a's
// fail-closed rule, which is the half a DROP TABLE can reach: insert captures
// `grew` from the DELETE's row count and only touches the counter after the
// commit has been REACHED, so a failure before that point must leave it exactly
// where it was. Counting a transaction that never got as far as Commit would
// exhaust the cap on a storage outage rather than on real rows.
//
// The other half — a commit that APPLIED and then reported failure, where the
// counter must move — cannot be produced by breaking the schema, because the
// statements fail first. It lives in lostcommit_test.go, over a database/sql
// driver whose Commit does exactly that.
func TestRowCounterSurvivesAnAmbiguousCommit(t *testing.T) {
	s := newTestStore(t, 10)
	s.Save(session.Adopt(newEnvelope("a")))
	s.admit.Lock()
	before := s.rows
	s.admit.Unlock()
	if before != 1 {
		t.Fatalf("row counter = %d after one save, want 1", before)
	}
	// A failure BEFORE any commit must not move it.
	if _, err := s.st.DB().Exec("DROP TABLE " + s.st.Table(SessionsTable)); err != nil {
		t.Fatalf("drop: %v", err)
	}
	s.Save(session.Adopt(newEnvelope("b")))
	s.admit.Lock()
	after := s.rows
	s.admit.Unlock()
	if after != before {
		t.Errorf("row counter moved to %d on a pre-commit failure, want %d", after, before)
	}
	// That one IS a degradation, unlike a capacity refusal.
	if s.Degradations() == 0 {
		t.Error("a storage failure did not raise degradeTotal")
	}
}

// --- Replace at marker capacity (§6e) -------------------------------------------

// TestReplaceAtMarkerCapacityFallsBackLocally covers replaceLocally, the arm
// Replace takes when the generation map is full. The new session runs
// process-local and needs no marker at all — absenceIsFinal reads an unpersisted
// id as never-final — so the login proceeds rather than failing under exactly the
// flood that exhausted the markers.
//
// The fixture reproduces the realistic sequence rather than contriving the
// absence: Save stamps a marker for the pre-auth id, a completed sweep prunes it
// by epoch, and the login therefore arrives with no old marker to hand off and
// must take a fresh slot it cannot get.
func TestReplaceAtMarkerCapacityFallsBackLocally(t *testing.T) {
	s := newTestStore(t, 0)
	pre := session.Adopt(newEnvelope("pre"))
	s.Save(pre)
	if got := countSessionRows(t, s); got != 1 {
		t.Fatalf("rows = %d after saving the pre-auth session, want 1", got)
	}
	// A sweep that began after that publication finishes, spending its marker.
	s.pruneGenerations(s.scanEpoch())
	if got := markerOf(s, "pre"); got != 0 {
		t.Fatalf("fixture: the pre-auth marker survived the prune (%d)", got)
	}
	fillGenerations(t, s, maxGenerationEntries)
	before := rowsHeld(s)

	authed := session.Adopt(newEnvelope("post"))
	if !s.Replace(pre, authed) {
		t.Fatal("a login was refused because the generation map was full; marker capacity must not fail logins")
	}
	// The old row is DELETED, not abandoned. Leaving it would strand a row with
	// no local session behind it, holding a storage.max_sessions slot until the
	// abandoned-row path collects it at idle timeout — and under the flood that
	// exhausted the markers, those orphans are what keeps the row cap exhausted.
	if got := countSessionRows(t, s); got != 0 {
		t.Errorf("rows = %d after the local swap, want 0 — the pre-auth row was left behind", got)
	}
	if got := rowsHeld(s); got != before-1 {
		t.Errorf("row counter = %d after the delete, want %d; the counter and the table have diverged", got, before-1)
	}
	// Process-local, and MARKED as such: without this the new id's absence would
	// read as final and the next request would sign the user out.
	if !s.isUnpersisted("post") {
		t.Error("the new id was not marked unpersisted")
	}
	if s.absenceIsFinal("post", noScan) {
		t.Error("a session that could not be published is treated as logged out")
	}
	// A marker refusal is a POLICY turn-away — counted by Replace one line before
	// the fallback, and deliberately apart from degradeTotal, which must stay flat
	// because storage answered every statement it was given.
	if got := s.MarkerRefusals(); got != 1 {
		t.Errorf("marker refusals = %d, want 1", got)
	}
	if got := s.Degradations(); got != 0 {
		t.Errorf("a marker refusal raised degradeTotal (%d); it is a policy, not a failure", got)
	}
	if _, ok := s.Get("post"); !ok {
		t.Error("the authenticated session is not resolvable")
	}
	if _, ok := s.Get("pre"); ok {
		t.Error("the pre-auth session survived the swap")
	}
}

// TestReplaceAtMarkerCapacityRefusesAVanishedRow is the single-winner property on
// that same fallback path. The DELETE is the membership check: removing nothing
// means a logout, a reap or a competing login got there first, and this login has
// to lose rather than resurrect a session somebody else ended.
func TestReplaceAtMarkerCapacityRefusesAVanishedRow(t *testing.T) {
	s := newTestStore(t, 0)
	pre := session.Adopt(newEnvelope("pre"))
	s.Save(pre)
	s.pruneGenerations(s.scanEpoch())
	fillGenerations(t, s, maxGenerationEntries)

	// Somebody else ended it. pre is NOT unpersisted — this process wrote that
	// row successfully — so the missing row is evidence, not mere absence.
	if _, err := s.st.DB().Exec(s.del, "pre"); err != nil {
		t.Fatalf("delete the pre-auth row: %v", err)
	}
	if s.isUnpersisted("pre") {
		t.Fatal("fixture: pre must be a session this process really wrote")
	}

	authed := session.Adopt(newEnvelope("post"))
	if s.Replace(pre, authed) {
		t.Error("a login won a pre-auth session whose row had already been removed")
	}
	if _, ok := s.Get("post"); ok {
		t.Error("the losing login left a resolvable session behind")
	}
	if got := s.MarkerRefusals(); got != 1 {
		t.Errorf("marker refusals = %d, want 1", got)
	}
}

// TestReplaceStampsTheNewIDWithTheCurrentGeneration pins §6e's "re-stamped, never
// moved" on the published path. A pre-auth session may have been published
// minutes ago; carrying its old generation across would leave the new id looking
// OLDER than a scan that began in between, and that scan would retire a session
// which had just authenticated.
func TestReplaceStampsTheNewIDWithTheCurrentGeneration(t *testing.T) {
	s := newTestStore(t, 0)
	pre := session.Adopt(newEnvelope("pre"))
	s.Save(pre)

	// A scan begins here: after the pre-auth publication, before the login.
	epoch := s.scanEpoch()
	authed := session.Adopt(newEnvelope("post"))
	if !s.Replace(pre, authed) {
		t.Fatal("the login was refused")
	}
	if got := markerOf(s, "post"); got <= epoch {
		t.Errorf("the new id's marker = %d, which is not newer than the scan at %d — the old value was moved rather than re-stamped", got, epoch)
	}
	if s.absenceIsFinal("post", epoch) {
		t.Error("a session that authenticated after the scan began would be retired by it")
	}
	// And the old id's marker went with it: one marker per live id, not one per
	// id this process has ever seen.
	if got := markerOf(s, "pre"); got != 0 {
		t.Errorf("the pre-auth id kept marker %d after the swap", got)
	}
}

// --- races at the two bounds (§6d, §6g) -----------------------------------------

// TestPublishersAndAdoptionsCompeteForTheLastMarkerSlot runs the three
// publication sites at the generation map's cap with ONE slot left.
//
// What is asserted is the invariant, not a winner. The bound must hold whoever
// takes it; the adoption must never be refused, because declining would sign out
// a session another replica owns; and no PUBLISHER may end up with a durable row
// carrying no marker, which is precisely the publication an in-flight scan
// retires. The adopted id is excluded from that last rule deliberately: at
// capacity Get proceeds UNMARKED and self-heals on the next request, so if a
// publisher wins the slot the adoption legitimately holds a row with no marker.
func TestPublishersAndAdoptionsCompeteForTheLastMarkerSlot(t *testing.T) {
	s := newTestStore(t, 0)

	// The adoption's row: written by another replica, so this process holds
	// neither a marker nor a local session for it.
	peer := newEnvelope("adopt")
	if _, err := s.st.DB().Exec(s.ins, peer.ID, peer.CSRF, Micros(peer.Created), Micros(peer.LastSeen)); err != nil {
		t.Fatalf("seed the peer's row: %v", err)
	}
	// The login's pre-auth session, published and then pruned by a completed
	// sweep — so its handoff needs a fresh slot like any other publication.
	pre := session.Adopt(newEnvelope("pre"))
	s.Save(pre)
	s.pruneGenerations(s.scanEpoch())
	fillGenerations(t, s, maxGenerationEntries-1)

	var (
		wg         sync.WaitGroup
		adoptedOK  bool
		replacedOK bool
	)
	wg.Add(3)
	go func() { defer wg.Done(); s.Save(session.Adopt(newEnvelope("save"))) }()
	go func() { defer wg.Done(); replacedOK = s.Replace(pre, session.Adopt(newEnvelope("post"))) }()
	go func() { defer wg.Done(); _, adoptedOK = s.Get("adopt") }()
	wg.Wait()

	s.mu.Lock()
	markers := len(s.generations)
	s.mu.Unlock()
	if markers > maxGenerationEntries {
		t.Errorf("the generation map holds %d markers, past its cap of %d", markers, maxGenerationEntries)
	}
	if !adoptedOK {
		t.Error("an adoption lost the race for the last slot and the session was refused; only publications may be turned away")
	}
	if !replacedOK {
		t.Error("the login was refused; nothing here competes for the pre-auth row, so it must win either the handoff or the local fallback")
	}
	if rowExists(t, s, "save") && markerOf(s, "save") == 0 {
		t.Error("Save left a durable row with no generation marker behind it")
	}
	switch {
	case rowExists(t, s, "post"):
		if markerOf(s, "post") == 0 {
			t.Error("the login published a row for the new id with no generation marker behind it")
		}
	case !s.isUnpersisted("post"):
		t.Error("the login fell back to the local swap without marking the new id unpersisted, so its absence would read as final")
	}
}

// TestARemoteLogoutIsHonouredAcrossRepeatedSweepsAtTheBound is the property §6d
// gave up wholesale marker-clearing to keep. A logout performed on another
// replica has to take effect here, and it reaches this node only as a MISSING
// ROW — so if a missing marker ever read as "newer than the scan", no remote
// logout would ever be collected and the durable store would stop being durable.
//
// Run across SEVERAL sweeps, and at the row cap, because that is the state the
// rule has to hold in. A completed sweep spends the session's marker, so by the
// time the logout arrives the victim holds none at all and the verdict rests on
// the absent-marker case alone — the exact case a blanket "no marker means newer
// than the scan" would get wrong, and a session that has merely been alive for a
// minute is already in it. Meanwhile each refused save leaves an unpersisted
// entry for repersist to walk.
func TestARemoteLogoutIsHonouredAcrossRepeatedSweepsAtTheBound(t *testing.T) {
	s := newTestStore(t, 2)
	keep := session.Adopt(newEnvelope("keep"))
	victim := session.Adopt(newEnvelope("victim"))
	s.Save(keep)
	s.Save(victim)
	if got := countSessionRows(t, s); got != 2 {
		t.Fatalf("rows = %d, want 2", got)
	}

	never := func(*session.Session) bool { return false }
	// A first sweep with both rows still there. It changes nothing except the
	// markers, which is the point: it retires the publications.
	s.Reap(never)
	if got := markerOf(s, "victim"); got != 0 {
		t.Fatalf("fixture: the victim's marker survived a completed sweep (%d), so the case below is not the one being tested", got)
	}

	// Only now does another replica end the victim's session.
	if _, err := s.st.DB().Exec(s.del, "victim"); err != nil {
		t.Fatalf("delete the row out of band: %v", err)
	}

	var retired bool
	for i := range 3 {
		// Keep the bound pressed: at the cap each of these is refused a row and
		// lands in unpersisted, which is the state the sweep has to work around.
		s.Save(session.Adopt(newEnvelope("flood-" + itoa(i))))
		for _, dead := range s.Reap(never) {
			if dead.ID == "victim" {
				retired = true
			}
		}
	}
	if !retired {
		t.Error("a session ended on another replica was never retired here; its pools would be held until the process exits")
	}
	if _, ok := s.Get("victim"); ok {
		t.Error("a session ended on another replica is still resolvable")
	}
	// The sessions this replica really owns are untouched — a sweep that
	// collected a remote logout by collecting everything would be no fix at all.
	if _, ok := s.Get("keep"); !ok {
		t.Error("the sweep retired a live session whose row is still there")
	}
}

// TestNoMarkerSurvivesAnEvictionRacedByARemoteDeletion pairs with
// TestEvictionPrunesTheBookkeeping: that one holds the SIZE of one map, this one
// holds that a single evicted id leaves nothing in ANY of the three.
//
// The id here is the awkward one — the local store drops it silently at its own
// capacity while its row is being deleted somewhere else, so neither the row set
// nor the dead list will ever mention it again. Anything left behind is per-id
// state that nothing will ever collect.
func TestNoMarkerSurvivesAnEvictionRacedByARemoteDeletion(t *testing.T) {
	if testing.Short() {
		t.Skip("creates more than the in-memory store's capacity")
	}
	// The row cap is the cost control: past it every save in the flood below is
	// refused with ZERO SQL, so 10,500 sessions cost map writes rather than
	// 10,500 failed transactions — and, unlike dropping the table, it leaves a
	// real row for the remote deletion to remove.
	s := newTestStore(t, 1)

	victim := session.Adopt(newEnvelope("victim"))
	s.Save(victim) // a row, a marker and a local session
	if _, ok := s.Get("victim"); !ok {
		t.Fatal("fixture: the victim is not resolvable")
	} // ... and now a touched entry, from that page view's last_seen refresh
	// unpersisted is seeded rather than produced: one id cannot both have been
	// written and have failed to be. What is asserted below is that forget clears
	// ALL THREE maps, so each has to hold something going in.
	s.mu.Lock()
	s.unpersisted["victim"] = true
	s.mu.Unlock()

	// The remote deletion, racing the eviction below.
	if _, err := s.st.DB().Exec(s.del, "victim"); err != nil {
		t.Fatalf("delete the row out of band: %v", err)
	}

	const n = 10500 // past the in-memory store's 10000
	for i := range n {
		s.Save(session.Adopt(newEnvelope("flood-" + itoa(i))))
	}
	// Saved first, so the pre-auth FIFO evicted it first.
	if _, ok := s.Get("victim"); ok {
		t.Fatal("the victim was not evicted; the fixture proves nothing")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, present := range map[string]bool{
		"touched":     !s.touched["victim"].IsZero(),
		"unpersisted": s.unpersisted["victim"],
		"generations": s.generations["victim"] != 0,
	} {
		if present {
			t.Errorf("an eviction raced by a remote deletion left an entry in %s; nothing will ever collect it", name)
		}
	}
}
