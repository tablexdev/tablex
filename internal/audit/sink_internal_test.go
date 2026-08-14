package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileSinkRevivesAfterFailedRotationReopen: rotateLocked clears s.f before
// renaming, so when its reopen fails the sink is left fileless — and Write's
// nil-guard used to read that as "closed", failing every later event for the
// life of the process after one transient open failure at the rotation
// boundary. A fileless-but-not-Closed sink must retry the open and revive;
// only a deliberate Close refuses writes permanently. White-box: the fileless
// state is constructed directly, because injecting a failure between rename
// and reopen from outside the package is not possible portably.
func TestFileSinkRevivesAfterFailedRotationReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := OpenFile(path, 1<<20)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := s.Write(Event{Kind: KindAction, Target: "before"}); err != nil {
		t.Fatalf("baseline write: %v", err)
	}

	// The exact state a failed rotation-reopen leaves behind: no handle, not
	// closed.
	s.mu.Lock()
	if err := s.f.Close(); err != nil {
		s.mu.Unlock()
		t.Fatalf("constructing fileless state: %v", err)
	}
	s.f = nil
	s.mu.Unlock()

	if err := s.Write(Event{Kind: KindAction, Target: "revived"}); err != nil {
		t.Fatalf("Write on a fileless (not closed) sink = %v, want a retried open to revive it", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	for _, want := range []string{"before", "revived"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("file lacks the %q event:\n%s", want, b)
		}
	}
	// The retried open must track the true file length, or the next write
	// re-enters rotation against a phantom size.
	s.mu.Lock()
	if info, statErr := s.f.Stat(); statErr != nil || s.size != info.Size() {
		t.Errorf("size = %d, want the file's true %v (stat err %v)", s.size, info, statErr)
	}
	s.mu.Unlock()

	// Close still means closed — the revival path must not have weakened it.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Write(Event{Kind: KindAction, Target: "after-close"}); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("Write after Close = %v, want fs.ErrClosed", err)
	}
}
