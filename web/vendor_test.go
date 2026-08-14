package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"
)

// TestVendorManifestHashes enforces the MANIFEST integrity baseline that was
// previously documentation-only: every vendored front-end bundle's SHA-256
// must match its recorded hash (a silently-modified vendor file fails the
// build instead of shipping), and every vendored file must be listed in the
// MANIFEST (a new bundle cannot ship without provenance).
func TestVendorManifestHashes(t *testing.T) {
	raw, err := FS.ReadFile("static/vendor/MANIFEST")
	if err != nil {
		t.Fatalf("read MANIFEST: %v", err)
	}

	// Parse the "[path]" sections and their "sha256 = <hex>" rows.
	baseline := map[string]string{} // vendor-relative path -> sha256 hex
	var cur string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			cur = line[1 : len(line)-1]
		case strings.HasPrefix(line, "sha256"):
			_, v, ok := strings.Cut(line, "=")
			if !ok || cur == "" {
				t.Fatalf("malformed sha256 row %q (section %q)", line, cur)
			}
			baseline[cur] = strings.TrimSpace(v)
		}
	}
	if len(baseline) == 0 {
		t.Fatal("no sha256 baselines parsed from MANIFEST")
	}

	// Every baseline entry matches the vendored bytes.
	for path, want := range baseline {
		b, err := FS.ReadFile("static/vendor/" + path)
		if err != nil {
			t.Errorf("MANIFEST entry %q has no vendored file: %v", path, err)
			continue
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("vendored %s sha256 = %s, MANIFEST records %s — the bundle changed without a MANIFEST update (or was tampered with)", path, got, want)
		}
	}

	// Every vendored file has a baseline (MANIFEST itself excepted).
	err = fs.WalkDir(FS, "static/vendor", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(p, "static/vendor/")
		if rel == "MANIFEST" {
			return nil
		}
		if _, ok := baseline[rel]; !ok {
			t.Errorf("vendored file %s has no MANIFEST sha256 entry", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk vendor dir: %v", err)
	}
}
