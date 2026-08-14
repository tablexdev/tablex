package main

// Two more coherence guards, in the same spirit as docs_test.go: check the
// things a paragraph NAMES, since no test can check whether it is still true.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// brokenContinuation matches a backslash followed only by whitespace and/or a
// trailing '#' comment. That is the shape that breaks: the shell sees the
// backslash escaping a SPACE rather than the newline, so the line does not
// continue and the argument list is silently wrong.
//
// Narrow on purpose. "any backslash not at end of line" would be simpler and
// would trip on the first legitimate `printf '%s\n'` or `grep 'v1\.'` anybody
// adds to a fence — a guard that fires on correct code gets disabled.
var brokenContinuation = regexp.MustCompile(`\\[ \t]+(#.*)?$`)

// TestDocShellFencesHaveNoBrokenContinuations.
//
// README's download-verification block was not valid bash: its `# 1.` / `# 2.` /
// `# 3.` labels sat AFTER a line-continuation backslash, so each backslash
// escaped a space and the block ran as two bogus commands, exit 127. Copy-paste
// instructions are the one kind of documentation a reader executes verbatim.
//
// Why not `bash -n`: it is wrong in both directions here. It PASSES the broken
// block above (escaping a space is legal syntax, just not what was meant), and
// it FAILS SECURITY.md's container-signature example, where `<tag>` is a
// deliberate placeholder that lexes as a redirection. This predicate is pure Go,
// needs no shell, and skips nothing.
func TestDocShellFencesHaveNoBrokenContinuations(t *testing.T) {
	files := shellDocFiles(t)
	// Root and docs/ both, enumerated dynamically: a guard hard-coded to the
	// files that happen to have fences today stops covering the next one added.
	//
	// Both floors count TRACKED files only. CLAUDE.md is local-only (see
	// untrackedDocs in docs_test.go), so a working tree holds one markdown file
	// more than a checkout does; counting it made this guard pass for every
	// contributor and fail on every runner. Lowering the floor by one instead
	// would have hidden the same gap the other way round — a tracked doc that
	// really did go missing would still clear the floor locally. Local-only
	// files are still SCANNED for broken continuations, which is where they are
	// edited; they just do not prop up the floors. (13 tracked markdown files
	// when the docs consolidated into design.md.)
	const fileFloor = 13
	tracked := 0
	for _, rel := range files {
		if !untrackedDocs[rel] {
			tracked++
		}
	}
	if tracked < fileFloor {
		t.Fatalf("found %d tracked markdown files, expected at least %d — this guard is not looking where it thinks", tracked, fileFloor)
	}

	fences := 0
	for _, rel := range files {
		body := read(t, rel)
		counts := !untrackedDocs[rel]
		lines := strings.Split(body, "\n")
		inFence := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "```") {
				if inFence {
					inFence = false
					continue
				}
				// Shell fences only. powershell and bat have their own
				// continuation characters and are not this guard's business.
				switch strings.ToLower(strings.TrimPrefix(trimmed, "```")) {
				case "bash", "sh", "console", "shell":
					inFence = true
					if counts {
						fences++
					}
				}
				continue
			}
			if !inFence {
				continue
			}
			if brokenContinuation.MatchString(line) {
				t.Errorf("%s:%d: a line-continuation backslash is followed by more than a newline, so the shell escapes a SPACE and the command does not continue:\n\t%s",
					rel, i+1, line)
			}
		}
		if inFence {
			t.Errorf("%s: a shell fence is never closed; the scan above stopped making sense partway through", rel)
		}
	}
	const fenceFloor = 5
	if fences < fenceFloor {
		t.Fatalf("inspected %d shell fences in tracked files, expected at least %d — the fence scan has stopped matching", fences, fenceFloor)
	}
}

// shellDocFiles returns every tracked-looking markdown file worth scanning:
// the repo root and all of docs/. Enumerated rather than listed, because the
// five root files are exactly the kind of set that grows by one unnoticed.
func shellDocFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	rootEntries, err := os.ReadDir(repoRoot)
	if err != nil {
		t.Fatalf("read repo root: %v", err)
	}
	for _, e := range rootEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			out = append(out, e.Name())
		}
	}
	err = fs.WalkDir(os.DirFS(filepath.Join(repoRoot, "docs")), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".md") {
			out = append(out, filepath.ToSlash(filepath.Join("docs", p)))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs/: %v", err)
	}
	return out
}

// TestDocumentedFormatsMatchTheDispatch.
//
// The CHANGELOG claimed export AND import in all four formats. Import is SQL
// plus CSV. The README's export half omitted XML. Both are the sort of claim a
// reader acts on and then finds untrue.
//
// TWO anchors, because export and import are different sets and there is a third
// list that is neither. isDataFormat (csv/json/xml) is the ROW-STREAMING set and
// deliberately excludes sql; anchoring to it would quietly assert that SQL is
// not an export format.
func TestDocumentedFormatsMatchTheDispatch(t *testing.T) {
	export := exportFormats(t)  // the download dispatch switch
	imports := importFormats(t) // importFormatFromName

	if want := []string{"csv", "json", "xml", "sql"}; !sameSet(export, want) {
		t.Fatalf("export dispatch parsed as %v, expected %v — the anchor has moved", export, want)
	}
	if want := []string{"csv", "sql"}; !sameSet(imports, want) {
		t.Fatalf("import format detection parsed as %v, expected %v — the anchor has moved", imports, want)
	}

	// Each doc claim is an export+import PAIR, so each is checked against both
	// anchors. Naming the formats explicitly rather than deriving prose from a
	// set: the sentence has to stay readable, and what is being held is that it
	// still names the right ones.
	for _, c := range []struct{ file, claim string }{
		{"README.md", "SQL / CSV / JSON / XML"},
		{"CHANGELOG.md", "export in SQL, CSV, JSON and XML"},
		{"docs/design.md", "SQL dump (structure/data), CSV, JSON, **XML**"},
	} {
		if !strings.Contains(read(t, c.file), c.claim) {
			t.Errorf("%s no longer says %q; the export format list has drifted from the dispatch switch", c.file, c.claim)
		}
	}
	// The import half, which is where the false claim was.
	for _, c := range []struct{ file, claim string }{
		{"README.md", "CSV with header→column mapping at table scope"},
		{"CHANGELOG.md", "import in SQL,\n  and in CSV at table scope"},
	} {
		if !strings.Contains(read(t, c.file), c.claim) {
			t.Errorf("%s no longer says %q; the import format list has drifted", c.file, c.claim)
		}
	}
	// JSON and XML are export-only: the set difference, stated as such.
	if !strings.Contains(read(t, "docs/design.md"), "**JSON and XML are export-only**") {
		t.Error("docs/design.md no longer states that JSON and XML are export-only, which is exactly the export-minus-import difference")
	}

	// isDataFormat is the third list, and the guard says so rather than
	// conflating it: it is export minus sql.
	data := dataFormats(t)
	if want := []string{"csv", "json", "xml"}; !sameSet(data, want) {
		t.Errorf("isDataFormat parsed as %v, expected %v (the export set minus sql)", data, want)
	}
}

var caseRE = regexp.MustCompile(`case ([^:\n]+):`)

// exportFormats reads the download dispatch switch — the authority on what can
// be exported, since its `default` arm is the SQL path.
func exportFormats(t *testing.T) []string {
	t.Helper()
	src := read(t, "internal/server/handlers/export.go")
	// Anchored from the SQL fallback BACKWARDS to its own switch. Cutting
	// forwards from the first "switch format {" finds isDataFormat's instead —
	// the third list, whose cases would then be folded into this one.
	end := strings.Index(src, "\n\tdefault: // sql")
	if end < 0 {
		t.Fatal(`export.go's dispatch switch no longer ends in "default: // sql"; the SQL fallback is what makes this list complete`)
	}
	start := strings.LastIndex(src[:end], "\tswitch format {")
	if start < 0 {
		t.Fatal("export.go no longer has the format dispatch switch this guard reads")
	}
	return append(quotedCases(src[start:end]), "sql")
}

// importFormats reads importFormatFromName, whose else-branch is the SQL path.
func importFormats(t *testing.T) []string {
	t.Helper()
	src := read(t, "internal/server/handlers/importer.go")
	_, after, ok := strings.Cut(src, "func importFormatFromName(")
	if !ok {
		t.Fatal("importer.go no longer defines importFormatFromName")
	}
	body, _, _ := strings.Cut(after, "\n}")
	var out []string
	for _, m := range regexp.MustCompile(`return "(\w+)"`).FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// dataFormats reads isDataFormat, the row-streaming set.
func dataFormats(t *testing.T) []string {
	t.Helper()
	src := read(t, "internal/server/handlers/export.go")
	_, after, ok := strings.Cut(src, "func isDataFormat(")
	if !ok {
		t.Fatal("export.go no longer defines isDataFormat")
	}
	body, _, _ := strings.Cut(after, "\n}")
	return quotedCases(body)
}

func quotedCases(src string) []string {
	var out []string
	for _, m := range caseRE.FindAllStringSubmatch(src, -1) {
		for _, q := range regexp.MustCompile(`"(\w+)"`).FindAllStringSubmatch(m[1], -1) {
			out = append(out, q[1])
		}
	}
	return out
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}
