package view

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/web"
)

var iconCallRE = regexp.MustCompile(`icon\s+"([a-z0-9-]+)"`)

// TestIconsReconciled keeps the three icon surfaces — the iconAlias map, the
// vendored icons/*.svg files, and the templates' {{icon "…"}} calls — from
// drifting apart: every alias must point at a real file, every template call
// must resolve to a real file (via alias or directly), and every vendored
// file must be reachable (an orphan SVG is dead weight in the binary).
func TestIconsReconciled(t *testing.T) {
	files := map[string]bool{}
	entries, err := fs.ReadDir(web.FS, "static/img/icons")
	if err != nil {
		t.Fatalf("read icons dir: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".svg") {
			files[strings.TrimSuffix(e.Name(), ".svg")] = true
		}
	}
	if len(files) == 0 {
		t.Fatal("no icon files found")
	}

	// Every alias target exists.
	for name, target := range iconAlias {
		if !files[target] {
			t.Errorf("iconAlias[%q] targets missing file icons/%s.svg", name, target)
		}
	}

	// Every template {{icon "…"}} call resolves; collect the files they reach.
	reachable := map[string]bool{}
	err = fs.WalkDir(web.FS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(web.FS, p)
		if err != nil {
			return err
		}
		for _, m := range iconCallRE.FindAllStringSubmatch(string(b), -1) {
			name := m[1]
			target, ok := iconAlias[name]
			if !ok {
				target = name // Icon() falls back to the direct file name
			}
			if !files[target] {
				return fmt.Errorf("%s: {{icon %q}} resolves to missing icons/%s.svg", p, name, target)
			}
			reachable[target] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Every vendored file is reachable: hit directly by a template call above,
	// or the target of some alias (aliases are the API templates may use next).
	for _, target := range iconAlias {
		reachable[target] = true
	}
	for f := range files {
		if !reachable[f] {
			t.Errorf("icons/%s.svg is orphaned: no alias targets it and no template references it", f)
		}
	}
}
