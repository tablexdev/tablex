package driver_test

// The split stays split. mysql.go and sqlite.go carried 4,300 lines between
// them until the 2026-08 decomposition; this ratchet is what keeps the next
// god-file from growing back. A single ceiling cannot work at either scope —
// the shared layer holds the largest files, and a ceiling loose enough for
// them would hand a 200-line engine file five-fold headroom — so every file
// gets max(its pinned baseline, 900): files already above 900 are pinned at
// their own size and cannot grow at all, new files get 900. When the ratchet
// trips, split by role (docs/adding-an-engine.md) rather than raising the
// number; lower or delete a pin when a split beats it, never raise one to
// make a red build green.

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// defaultCeiling is the limit for any file without a pin.
const defaultCeiling = 900

// fileSizeBaselines pins the files that were already above the ceiling when
// the ratchet was written (post-split sizes). They may shrink; they may not
// grow by a single line.
var fileSizeBaselines = map[string]int{
	// Lowered 2026-08-11 across several splits: the DCL passthroughs
	// (connection_dcl.go) and statement-observer seam (observer.go) out of the
	// two files; the account/privilege/role/session administration contracts to
	// admin.go and the read-addressing value types (Scope/TableRef/Pagination/
	// Sort) to scope.go, both out of driver.go; and the generic query/exec
	// primitives to connection_exec.go out of connection.go.
	//
	// Lowered again 2026-08-12: the transaction-outcome audit marker pushed
	// connection.go past its pin, so the pure input VALIDATORS (identifier,
	// account, privilege and create-table shape — none of which take a
	// Connection) moved to validate.go, per this ratchet's own rule that a
	// baseline is lowered by a split rather than raised to make a build green.
	"connection.go": 1001,
	"driver.go":     966,
	// postgres/dump_table.go's pin was deleted when the partition writers
	// split into dump_partition.go took it under the ceiling; likewise
	// postgres/dump_routines.go's when the aggregate pass split into
	// dump_aggregates.go.
	"postgres/introspect.go": 1062,
	"postgres/dump_types.go": 935,
}

func TestDriverFilesStaySplit(t *testing.T) {
	seen := map[string]bool{}
	scanned := 0
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(p)
		seen[rel] = true
		scanned++
		lines := bytes.Count(b, []byte("\n"))
		limit := defaultCeiling
		if pin, ok := fileSizeBaselines[rel]; ok {
			limit = pin
		}
		if lines > limit {
			t.Errorf("%s is %d lines (limit %d): split it by role — see docs/adding-an-engine.md — rather than raising this number; a baseline is lowered when a split beats it, never raised to make a red build green",
				rel, lines, limit)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/driver: %v", err)
	}
	const floor = 35 // 41 non-test files when the ratchet was written
	if scanned < floor {
		t.Fatalf("scanned %d non-test files, expected at least %d — this test is not looking where it thinks", scanned, floor)
	}

	for p, pin := range fileSizeBaselines {
		if !seen[p] {
			t.Errorf("baseline pins %s, which no longer exists — delete the entry", p)
		}
		if pin <= defaultCeiling {
			t.Errorf("baseline pins %s at %d, at or under the %d ceiling — the pin is dead weight, delete it", p, pin, defaultCeiling)
		}
	}
}

// TestTheRatchetDocNamesThePinnedFiles: docs/adding-an-engine.md describes this
// ratchet to whoever is adding an engine, and listed six pinned files long
// after two pins had been retired by the splits that beat them. A reader who
// trusts the doc goes looking for a constraint that is not there. The map is
// the authority, so the doc is checked against it — every pinned file named,
// and no retired one still named.
func TestTheRatchetDocNamesThePinnedFiles(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "adding-an-engine.md"))
	if err != nil {
		t.Fatalf("read the engine guide: %v", err)
	}
	doc := string(b)
	for p := range fileSizeBaselines {
		// The doc names files by BASENAME in prose ("`introspect.go`"), since
		// it has already said which package each belongs to.
		name := "`" + filepath.Base(p) + "`"
		if !strings.Contains(doc, name) {
			t.Errorf("docs/adding-an-engine.md does not name %s, which this ratchet pins — a reader cannot find the constraint they are told about", name)
		}
	}
	// The two pins retired by splits. Named literally: the failure this guards
	// is a doc that still advertises a constraint the code dropped, and only a
	// literal check can see that.
	for _, retired := range []string{"`dump_table.go`", "`dump_routines.go`"} {
		if strings.Contains(doc, retired) {
			t.Errorf("docs/adding-an-engine.md still lists %s among the pinned files; its pin was retired when a split took it under the ceiling", retired)
		}
	}
}
