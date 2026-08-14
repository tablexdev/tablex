package driver_test

// Doc-coherence guards that have to live in THIS package, because what they hold
// the docs to is an unexported test identifier or a value only a specialized
// dialect can produce. cmd/tablex/docs_test.go holds the rest.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

const engineDoc = "../../docs/adding-an-engine.md"

var backticked = regexp.MustCompile("`([A-Za-z][A-Za-z0-9]*)`")

// TestEngineDocListsEveryOptionalInterface: docs/adding-an-engine.md §4 is the
// contract a new engine is written against, and it was missing two of the 48
// interfaces entirely — ExportConnAdjuster and VersionFloor. An interface nobody
// documents is one nobody implements, and these are discovered by RUNTIME TYPE
// ASSERTION, so a missing one does not fail a build: the feature just silently
// is not there.
//
// Compared as a set in BOTH directions, because a doc row naming an interface
// that no longer exists is the same class of defect pointing the other way.
func TestEngineDocListsEveryOptionalInterface(t *testing.T) {
	documented := optionalInterfacesInDoc(t)

	code := map[string]bool{}
	for _, oi := range optionalInterfaces {
		code[oi.name] = true
	}

	var missing, unknown []string
	for name := range code {
		if !documented[name] {
			missing = append(missing, name)
		}
	}
	for name := range documented {
		if !code[name] {
			unknown = append(unknown, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("docs/adding-an-engine.md §4 does not list %d optional interface(s): %s",
			len(missing), strings.Join(sorted(missing), ", "))
	}
	if len(unknown) > 0 {
		t.Errorf("docs/adding-an-engine.md §4 lists %d name(s) that are not optional interfaces: %s",
			len(unknown), strings.Join(sorted(unknown), ", "))
	}
}

// optionalInterfacesInDoc parses §4's table rows. It reads the FIRST CELL of
// every line in the section that starts with a pipe and is not a delimiter row —
// which tolerates the section holding more than one table, as it does: a
// blockquote terminates a GFM table, so the rows after it re-open with their own
// header.
//
// A header row's first cell has no backticks, so it contributes nothing and
// needs no special case. Multi-name cells are split on " / ".
func optionalInterfacesInDoc(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(engineDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", engineDoc, err)
	}
	_, section, ok := strings.Cut(string(b), "## 4. The optional interfaces")
	if !ok {
		t.Fatalf("%s no longer has a '## 4. The optional interfaces' section — this guard is not looking where it thinks", engineDoc)
	}
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}

	out := map[string]bool{}
	rows := 0
	// inTable tracks whether a pipe-row would actually RENDER as one. It is set
	// by a delimiter row and cleared by anything that is not a table line —
	// which is how a blockquote terminates a table under GFM. 25 rows of this
	// section once displayed as a paragraph of literal pipe characters for
	// exactly that reason, so the structure is checked, not assumed.
	inTable := false
	lines := strings.Split(section, "\n")
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "|---"):
			inTable = true
			continue
		case !strings.HasPrefix(line, "|"):
			inTable = false
			continue
		}
		// A header row is a pipe-line whose successor is the delimiter. It is not
		// yet "in" a table and contributes no identifiers, but it is legitimate.
		if !inTable {
			if i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "|---") {
				continue
			}
			t.Errorf("%s §4, line %d of the section: this row is not inside a rendered table — it displays as literal '|' characters:\n\t%.80s",
				engineDoc, i+1, line)
		}
		rows++
		cell, _, _ := strings.Cut(strings.TrimPrefix(line, "|"), "|")
		for _, part := range strings.Split(cell, " / ") {
			for _, m := range backticked.FindAllStringSubmatch(part, -1) {
				out[m[1]] = true
			}
		}
	}
	const rowFloor = 40 // 48 interfaces over 45 rows when this guard was written
	if rows < rowFloor {
		t.Fatalf("parsed %d table rows in §4, expected at least %d — the table has stopped rendering, or this scan has stopped matching", rows, rowFloor)
	}
	return out
}

// TestEngineDocStatesTheFileSizeCeiling: §1 told a new engine's author to split
// at "~800 lines" while the ratchet ran at 900, so following the doc produced a
// split nothing asked for. The rule is also not a single number, and the doc has
// to say so or the next author reads 900 as universal.
func TestEngineDocStatesTheFileSizeCeiling(t *testing.T) {
	b, err := os.ReadFile(engineDoc)
	if err != nil {
		t.Fatalf("reading %s: %v", engineDoc, err)
	}
	doc := string(b)

	if want := "**900 lines**"; !strings.Contains(doc, want) {
		t.Errorf("%s no longer states the ceiling as %s; filesize_test.go's defaultCeiling is %d",
			engineDoc, want, defaultCeiling)
	}
	// The rule, not just the number: a file already over the ceiling is pinned at
	// its own size and cannot grow at all.
	if !strings.Contains(doc, "max(the file's pinned baseline, 900)") {
		t.Errorf("%s no longer states the max(baseline, ceiling) rule; a bare number reads as a universal limit, which it is not", engineDoc)
	}
	// Every pinned file must be named, or "six files are pinned" becomes a
	// number nobody can check.
	for path := range fileSizeBaselines {
		base := path
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		if !strings.Contains(doc, base) {
			t.Errorf("%s does not name %s, which is pinned above the ceiling", engineDoc, path)
		}
	}
	if len(fileSizeBaselines) < 4 {
		t.Fatalf("only %d pinned files; this guard is not looking where it thinks", len(fileSizeBaselines))
	}
}

// TestDocumentedEngineFloorsMatchTheCode holds every place a version floor is
// WRITTEN DOWN to the number ServerBelowFloor actually compares against. The
// site advertised CI's oldest images (8.0, 10.6) as the supported versions,
// which is a different and looser claim than the floors (8.0.13, 10.2.7).
//
// The floors have to be obtained through driver.Specialize with a synthetic
// below-floor ServerInfo, per FLAVOUR. An unspecialized dialect answers
// ("", false) — its version is unparsed — so a guard that skipped that step
// would compare every doc against the empty string and pass unconditionally.
func TestDocumentedEngineFloorsMatchTheCode(t *testing.T) {
	floors := map[string]string{}
	for _, c := range []struct {
		label, engine string
		info          driver.ServerInfo
	}{
		{"MySQL", "mysql", driver.ServerInfo{Flavor: "MySQL", Version: "5.0.0"}},
		{"MariaDB", "mysql", driver.ServerInfo{Flavor: "MariaDB", Version: "5.5.5-5.1.0-MariaDB"}},
		{"PostgreSQL", "postgres", driver.ServerInfo{Flavor: "PostgreSQL", Version: "9.0"}},
	} {
		d, ok := driver.Get(c.engine)
		if !ok {
			t.Fatalf("no %s dialect registered", c.engine)
		}
		vf, ok := driver.Specialize(d, c.info).(driver.VersionFloor)
		if !ok {
			t.Fatalf("the specialized %s dialect does not implement VersionFloor", c.label)
		}
		floor, below := vf.ServerBelowFloor()
		if !below || floor == "" {
			t.Fatalf("%s: a synthetic %s server reported floor=%q below=%v; this guard is comparing against nothing",
				c.label, c.info.Version, floor, below)
		}
		floors[c.label] = floor
	}

	// SQLite is exempt, and explicitly rather than by omission: it implements no
	// VersionFloor at all, because the library is compiled into the binary and
	// there is no operator's server that could be too old. Its 3.26+/3.31+ rows
	// in the docs are FEATURE requirements on a database file, not a login check.
	if d, ok := driver.Get("sqlite"); ok {
		info := driver.ServerInfo{Flavor: "SQLite", Version: "3.0.0"}
		if _, isFloor := driver.Specialize(d, info).(driver.VersionFloor); isFloor {
			t.Error("SQLite now declares a VersionFloor; this guard exempts it on the grounds that it does not")
		}
	}

	for _, f := range []struct {
		path        string
		mustContain []string
	}{
		{"../../README.md", []string{
			"MySQL **" + floors["MySQL"] + "+**",
			"MariaDB **" + floors["MariaDB"] + "+**",
			"PostgreSQL **" + floors["PostgreSQL"] + "+**",
		}},
		{"../../docs/database-drivers.md", []string{
			"| MySQL | **" + floors["MySQL"] + "+**",
			"| MariaDB | **" + floors["MariaDB"] + "+**",
			"| PostgreSQL | **" + floors["PostgreSQL"] + "+**",
		}},
		// Anchored to the engine TABLE ROW, not to a bare version substring:
		// the stylesheet in this file carries "13.5px/1.5" and "13px/1.55", so a
		// file-wide search for "13" would pass whatever the table said.
		{"../../site/index.html", []string{
			"<tr><td>MySQL</td><td>" + floors["MySQL"] + " and newer</td>",
			"<tr><td>MariaDB</td><td>" + floors["MariaDB"] + " and newer</td>",
			"<tr><td>PostgreSQL</td><td>" + floors["PostgreSQL"] + " and newer</td>",
		}},
	} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("reading %s: %v", f.path, err)
		}
		for _, want := range f.mustContain {
			if !strings.Contains(string(b), want) {
				t.Errorf("%s does not state %q; the documented floor has drifted from ServerBelowFloor", f.path, want)
			}
		}
	}

	// CI is the sixth file that talks about floors, and the one that used to
	// call its oldest IMAGES the floors. It must not: those images (8.0, 10.6)
	// are newer than the real floors, so naming them that way overstates what is
	// verified.
	b, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("reading ci.yml: %v", err)
	}
	for _, banned := range []string{"engine-floors", "MariaDB 10.6 floors"} {
		if strings.Contains(string(b), banned) {
			t.Errorf("ci.yml still says %q; 8.0 and 10.6 are the oldest images CI runs, not the documented floors (%s, %s)",
				banned, floors["MySQL"], floors["MariaDB"])
		}
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
