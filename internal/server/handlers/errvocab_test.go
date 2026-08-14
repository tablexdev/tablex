package handlers

// The error vocabulary has one spelling per tier. "Connection failed" is the
// TERMINAL tier's literal and belongs to connError alone: the section and
// empty-state tiers carry their own wording ("Database unreachable: …",
// "…unavailable: …"), because when a failure and an empty result render
// differently BY TYPE, a shared literal is the one thing that could quietly
// merge them back together. One occurrence, not one file — a file can hold two
// spellings.

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestConnectionFailedHasOneSpelling(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	re := regexp.MustCompile(`(?i)connection failed`)

	var hits []string
	scanned := 0
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".reference", "node_modules", "bin", "dist", ".claude", ".idea":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for _, m := range re.FindAllIndex(b, -1) {
			line := 1 + bytes.Count(b[:m[0]], []byte("\n"))
			rel, _ := filepath.Rel(repoRoot, path)
			hits = append(hits, fmt.Sprintf("%s:%d: %q", filepath.ToSlash(rel), line, b[m[0]:m[1]]))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	const floor = 90 // 99 non-test .go files when this test was written
	if scanned < floor {
		t.Fatalf("scanned %d non-test .go files, expected at least %d — this walk is not looking where it thinks", scanned, floor)
	}

	if len(hits) != 1 {
		t.Fatalf("%q appears %d times in non-test Go source, want exactly once (connError's terminal literal):\n%s",
			"connection failed", len(hits), strings.Join(hits, "\n"))
	}
	// The one occurrence must be the canonical literal, in connError's home.
	if !strings.HasPrefix(hits[0], "internal/server/handlers/handlers.go:") {
		t.Errorf("the one occurrence is not in handlers.go (connError's home): %s", hits[0])
	}
	if !strings.Contains(hits[0], `"Connection failed"`) {
		t.Errorf("the one occurrence is not the canonical spelling %q: %s", "Connection failed", hits[0])
	}
}
