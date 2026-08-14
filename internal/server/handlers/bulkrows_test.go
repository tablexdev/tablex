package handlers

// The flash deciders for the two multi-row mutations, extracted pure so the
// countless-driver arm is testable: some drivers legitimately cannot report
// RowsAffected, and before the countKnown flag TableDelete answered
// "No rows were deleted — nothing matched the selected row keys." AFTER its
// DELETEs committed (total stayed 0), while the bulk apply reported a wrong
// "0 row(s) updated.".

import (
	"strings"
	"testing"
)

func TestDeleteFlashHonestWithoutCounts(t *testing.T) {
	t.Run("countless success never claims nothing matched", func(t *testing.T) {
		f := deleteFlash(0, 0, 3, false, false)
		if strings.Contains(f.Message, "nothing matched") || strings.Contains(f.Message, "No rows were deleted") {
			t.Fatalf("a countless committed delete reads %q — a false claim after committed DELETEs", f.Message)
		}
		if !strings.Contains(f.Message, "does not report") {
			t.Errorf("the countless success does not say the count is unavailable: %q", f.Message)
		}
	})
	t.Run("partial counts keep the honest floor", func(t *testing.T) {
		f := deleteFlash(2, 0, 3, false, false)
		if !strings.Contains(f.Message, "at least 2") {
			t.Errorf("with two counted deletes and one uncounted, the message should carry the floor: %q", f.Message)
		}
	})
	t.Run("an unknown count does not suppress the no-PK warning", func(t *testing.T) {
		f := deleteFlash(2, 0, 3, true, false)
		if f.Kind != "warning" || !strings.Contains(f.Message, "no primary key") {
			t.Errorf("the still-true multi-row warning was suppressed: kind=%q %q", f.Kind, f.Message)
		}
	})
	t.Run("an unknown count does not suppress the skipped note", func(t *testing.T) {
		f := deleteFlash(0, 1, 3, false, false)
		if !strings.Contains(f.Message, "skipped as invalid") {
			t.Errorf("the still-true skipped note was suppressed: %q", f.Message)
		}
	})
	t.Run("known counts keep their exact messages", func(t *testing.T) {
		if f := deleteFlash(0, 0, 2, false, true); !strings.Contains(f.Message, "nothing matched") {
			t.Errorf("a genuine zero with known counts must still say so: %q", f.Message)
		}
		if f := deleteFlash(2, 0, 2, false, true); f.Message != "2 row(s) deleted." {
			t.Errorf("the plain success changed: %q", f.Message)
		}
		if f := deleteFlash(0, 2, 2, false, true); !strings.Contains(f.Message, "all 2 selected row key(s) were invalid") {
			t.Errorf("the all-skipped arm changed: %q", f.Message)
		}
	})
}

func TestBulkApplyFlashHonestWithoutCounts(t *testing.T) {
	t.Run("countless update never reports zero", func(t *testing.T) {
		f := bulkApplyFlash("edit", 0, 0, 2, false)
		if strings.Contains(f.Message, "0 row(s) updated") {
			t.Fatalf("a countless committed update reads %q — a wrong number", f.Message)
		}
		if !strings.Contains(f.Message, "does not report") {
			t.Errorf("the countless success does not say the count is unavailable: %q", f.Message)
		}
	})
	t.Run("the still-true no-changes note survives", func(t *testing.T) {
		f := bulkApplyFlash("edit", 0, 1, 3, false)
		if !strings.Contains(f.Message, "1 row(s) had no changes") {
			t.Errorf("the unchanged note was suppressed by the unknown count: %q", f.Message)
		}
	})
	t.Run("countless copy never reports zero", func(t *testing.T) {
		f := bulkApplyFlash("copy", 0, 0, 2, false)
		if strings.Contains(f.Message, "0 row(s) inserted") {
			t.Fatalf("a countless committed copy reads %q", f.Message)
		}
	})
	t.Run("known counts keep their exact messages", func(t *testing.T) {
		if f := bulkApplyFlash("edit", 2, 1, 3, true); f.Message != "2 row(s) updated. 1 row(s) had no changes." {
			t.Errorf("the counted update message changed: %q", f.Message)
		}
		if f := bulkApplyFlash("copy", 2, 0, 2, true); f.Message != "2 row(s) inserted as copies." {
			t.Errorf("the counted copy message changed: %q", f.Message)
		}
		if f := bulkApplyFlash("edit", 0, 2, 2, true); f.Kind != "info" {
			t.Errorf("the every-row-untouched arm changed: kind=%q %q", f.Kind, f.Message)
		}
	})
}
