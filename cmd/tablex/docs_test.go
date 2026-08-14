package main

// Documentation coherence, checked rather than trusted.
//
// The docs have repeatedly described something the code did not do — a control
// that did not exist, a package that had moved, tests that were never written.
// Each was fixed individually. These tests exist so the CLASS stops recurring: a package added
// without a line in the layout, a doc file nothing links to, a link to a file
// that was renamed.
//
// They are deliberately structural. No test can tell whether a paragraph is still
// true; what it can tell is whether the things a paragraph names still exist.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// repoRoot is two levels up from cmd/tablex, where `go test` runs.
const repoRoot = "../.."

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// untrackedDocs are the repository's LOCAL-ONLY documents: present in a working
// tree, absent from a clone. CLAUDE.md is .gitignore'd (and .dockerignore'd), so
// a CI checkout does not have it — a guard that read it unconditionally passed
// on every contributor's machine and failed on every runner, which is the least
// useful place to find out.
//
// Declared here rather than derived by shelling out to `git check-ignore`: these
// tests must run from an exported tree with no git binary and no work tree, and
// a guard that needs git to decide what to check is a guard that skips silently
// wherever git is missing.
var untrackedDocs = map[string]bool{"CLAUDE.md": true}

// readDoc reads a document that MAY be local-only, reporting whether it was
// there. The absence is tolerated for exactly the files named in untrackedDocs;
// a missing TRACKED file stays fatal, because that is a typo'd path or a
// renamed file — the defect this whole file exists to catch — and not an
// environment. Callers that skip must still floor the number of files they did
// read, so a set that quietly empties out cannot pass as a clean run.
func readDoc(t *testing.T, rel string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if errors.Is(err, fs.ErrNotExist) && untrackedDocs[rel] {
		return "", false
	}
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b), true
}

// TestArchitectureDocListsEveryPackage: internal/dump and internal/sqlscript were
// extracted from god-files and the layout diagram was not updated, so the map of
// the codebase quietly stopped matching the codebase.
//
// The walk is RECURSIVE. A top-level-only version passed while
// internal/driver/drivertest — the conformance suite every engine is held to —
// went unmentioned, because the packages that get extracted and forgotten are
// exactly the nested ones.
//
// The match is on the BASENAME plus a slash, which is the shape the layout block
// writes. That is a real limit and worth naming rather than pretending away:
// `mysql/` anywhere in the document satisfies internal/driver/mysql, so this
// catches a package the map has never heard of, not one filed in the wrong
// place.
func TestArchitectureDocListsEveryPackage(t *testing.T) {
	arch := read(t, "docs/architecture.md")

	var missing []string
	var checked int
	root := filepath.Join(repoRoot, "internal")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || p == root {
			return nil
		}
		checked++
		if !strings.Contains(arch, d.Name()+"/") {
			rel, _ := filepath.Rel(repoRoot, p)
			missing = append(missing, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/: %v", err)
	}
	const floor = 14 // 16 packages under internal/ when the walk went recursive
	if checked < floor {
		t.Fatalf("only %d packages found under internal/, expected at least %d; this test is not looking where it thinks", checked, floor)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("docs/architecture.md does not mention %d package(s): %s",
			len(missing), strings.Join(missing, ", "))
	}
}

// TestEveryDocIsLinked: a doc nothing links to is a doc nobody reads, and it is
// how a stale file survives long enough to become misleading.
func TestEveryDocIsLinked(t *testing.T) {
	index := read(t, "docs/README.md")
	entries, err := os.ReadDir(filepath.Join(repoRoot, "docs"))
	if err != nil {
		t.Fatalf("read docs/: %v", err)
	}
	var orphans []string
	var checked int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		checked++
		if !strings.Contains(index, name) {
			orphans = append(orphans, name)
		}
	}
	if checked < 5 {
		t.Fatalf("only %d docs found; this test is not looking where it thinks", checked)
	}
	if len(orphans) > 0 {
		sort.Strings(orphans)
		t.Errorf("docs/README.md links to neither of %d file(s): %s",
			len(orphans), strings.Join(orphans, ", "))
	}
}

var mdLinkRE = regexp.MustCompile(`\]\((\.{1,2}/[^)#\s]+)`)

// TestEveryRelativeDocLinkResolves walks every Markdown file in the repo and
// checks each relative link. A dead link is the cheapest possible doc defect to
// introduce (rename a file) and the most annoying to hit.
func TestEveryRelativeDocLinkResolves(t *testing.T) {
	var mds []string
	err := fs.WalkDir(os.DirFS(repoRoot), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Untracked local directories (tool scratch space, editor state)
			// may hold markdown of their own; it is not ours to keep coherent.
			switch d.Name() {
			case ".git", ".reference", "node_modules", ".claude", ".idea":
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".md") {
			mds = append(mds, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(mds) < 8 {
		t.Fatalf("only %d markdown files found; this test is not looking where it thinks", len(mds))
	}

	var checked int
	for _, md := range mds {
		body := read(t, md)
		dir := filepath.Dir(filepath.Join(repoRoot, md))
		for _, m := range mdLinkRE.FindAllStringSubmatch(body, -1) {
			target := m[1]
			checked++
			if _, err := os.Stat(filepath.Join(dir, target)); err != nil {
				t.Errorf("%s: link to %q does not resolve", md, target)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d relative links inspected; the link pattern has stopped matching", checked)
	}
}

// TestPlannedMeansNotPresent: "planned" in the docs must mean absent from the
// tree. staticcheck, Dependabot and the SBOM/cosign release steps were all
// implemented while docs/tech-stack.md's tooling table kept calling them
// "planned — not yet". Every tooling row marked planned is checked against the
// workflows and the repo root; the FLOOR is on the rows parsed, not the
// planned subset — the planned subset must be allowed to be empty (it is,
// now), but the table this test claims to read must never be.
func TestPlannedMeansNotPresent(t *testing.T) {
	stack := read(t, "docs/tech-stack.md")
	_, tooling, found := strings.Cut(stack, "## 6. Tooling")
	if !found {
		t.Fatal("docs/tech-stack.md no longer has a '## 6. Tooling' section — this test is not looking where it thinks")
	}
	if next := strings.Index(tooling, "\n## "); next >= 0 {
		tooling = tooling[:next]
	}

	// Everything a planned row names in backticks is a tool that must not be
	// wired in yet.
	var workflows []string
	wfDir := filepath.Join(repoRoot, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("read workflows: %v", err)
	}
	var wired strings.Builder
	for _, e := range entries {
		workflows = append(workflows, e.Name())
		b, err := os.ReadFile(filepath.Join(wfDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		wired.Write(b)
	}
	if len(workflows) < 2 {
		t.Fatalf("only %d workflow files found; this test is not looking where it thinks", len(workflows))
	}
	rootEntries, err := os.ReadDir(filepath.Join(repoRoot, ".github"))
	if err == nil {
		for _, e := range rootEntries {
			wired.WriteString(e.Name() + "\n")
		}
	}

	tickRE := regexp.MustCompile("`([^`]+)`")
	rows, planned := 0, 0
	for _, line := range strings.Split(tooling, "\n") {
		if !strings.HasPrefix(line, "|") || strings.HasPrefix(line, "|--") || strings.Contains(line, "| Concern |") {
			continue
		}
		rows++
		if !strings.Contains(line, "_(planned") {
			continue
		}
		planned++
		for _, m := range tickRE.FindAllStringSubmatch(line, -1) {
			tool := strings.TrimSpace(m[1])
			if tool == "" || strings.ContainsAny(tool, " /") {
				continue // commands with paths/args are prose, not tool names
			}
			if strings.Contains(wired.String(), tool) {
				t.Errorf("the tooling table calls %q planned, but it appears in .github/ — the doc is describing work that already happened", tool)
			}
		}
	}
	const rowFloor = 6 // tooling rows when this test was written
	if rows < rowFloor {
		t.Fatalf("parsed %d tooling rows, expected at least %d — this test is not looking where it thinks", rows, rowFloor)
	}
	t.Logf("tooling rows: %d, still planned: %d", rows, planned)
}

// TestGoldenFileClaimsMatchReality: docs/architecture.md claimed golden-file
// template tests while no testdata/ existed anywhere; the testing table in
// design.md correctly said the opposite in the same repository.
// The claim phrases and the directory must agree in BOTH directions.
func TestGoldenFileClaimsMatchReality(t *testing.T) {
	claims := false
	docs, err := os.ReadDir(filepath.Join(repoRoot, "docs"))
	if err != nil {
		t.Fatalf("read docs/: %v", err)
	}
	scanned := 0
	for _, e := range docs {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		scanned++
		body := read(t, filepath.Join("docs", e.Name()))
		// The positive claim phrasings that existed; the deliberate denial in
		// the testing table says "golden-file snapshots" and matches neither.
		if strings.Contains(body, "golden-file tests") || strings.Contains(body, "golden templates") {
			claims = true
		}
	}
	// The floor the other four guards have and this one did not. Both switch
	// arms below are currently dead — nothing claims golden files and no
	// testdata/ exists — so without it the test would keep passing if docs/
	// moved, emptied, or stopped being readable.
	const docFloor = 5
	if scanned < docFloor {
		t.Fatalf("scanned %d docs, expected at least %d — this test is not looking where it thinks", scanned, docFloor)
	}

	var testdata []string
	err = fs.WalkDir(os.DirFS(repoRoot), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".reference", "node_modules", ".claude", ".idea":
				return fs.SkipDir
			case "testdata":
				testdata = append(testdata, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	switch {
	case claims && len(testdata) == 0:
		t.Error("a doc claims golden-file template tests, but no testdata/ exists anywhere — the claim describes tests that were never written")
	case !claims && len(testdata) > 0:
		t.Errorf("testdata/ exists (%s) but no doc mentions golden files; document what it is for, or the next reader has to work it out from scratch", strings.Join(testdata, ", "))
	}
}

// --- guards for claims that documents once made ahead of the code -------------
//
// Each of these pins an invariant that a document asserted BEFORE the code made
// it true. They are anchored to the code rather than to a copy of the sentence,
// so the class ("a doc describes something the code does not do") is what stops
// recurring, not the individual wording.

// TestUserSQLPathsAreEnumeratedConsistently: the four places a user's own SQL
// reaches the database were enumerated in five documents, and three of them
// listed only two or three. A partial list reads as a complete one, and the
// missing entries were exactly the two enforced in a handler rather than by the
// route table — the ones a reader is least likely to already know about.
func TestUserSQLPathsAreEnumeratedConsistently(t *testing.T) {
	// The four names must appear TOGETHER, in the single passage that enumerates
	// them — not merely somewhere in the file. A whole-file search is vacuous
	// here: the console is named in a dozen unrelated places, so it would stay
	// green even if the enumeration were deleted outright. Scope to one paragraph,
	// as docguards_test.go's optionalInterfacesInDoc scopes to §4.
	want := []string{"console", "import", "stored program", "predicate"}
	files := []string{
		"docs/security.md",
		"CLAUDE.md",
		"CONTRIBUTING.md",
		"SECURITY.md",
	}
	// The enumeration is a single LIST ITEM in every file, and the four names
	// must all fall inside it. A blank-line paragraph is too coarse — security.md
	// keeps the whole numbered list in one block, and the surrounding items name
	// the console and the predicate on their own, so a paragraph (or whole-file)
	// search stays green even with item 4 deleted. Group by list marker instead:
	// a new item begins at a line starting with `N.` or a bullet, and its
	// continuation lines belong to it until the next marker (RE2 has no lookahead,
	// so this is line-based rather than a split).
	itemStart := regexp.MustCompile(`^[ \t]*(?:\d+\.|[-*+])[ \t]`)
	checked := 0
	for _, f := range files {
		body, ok := readDoc(t, f)
		if !ok {
			continue // local-only (untrackedDocs); floored below
		}
		checked++
		var items []string
		var cur strings.Builder
		flush := func() {
			if cur.Len() > 0 {
				items = append(items, cur.String())
				cur.Reset()
			}
		}
		for _, line := range strings.Split(body, "\n") {
			if itemStart.MatchString(line) {
				flush()
			}
			cur.WriteString(line)
			cur.WriteByte('\n')
		}
		flush()

		enumerated := false
		for _, item := range items {
			li := strings.ToLower(item)
			all := true
			for _, w := range want {
				if !strings.Contains(li, w) {
					all = false
					break
				}
			}
			if all {
				enumerated = true
				break
			}
		}
		if !enumerated {
			t.Errorf("%s does not enumerate all four user-SQL paths (%s) in a single list item — a partial or deleted enumeration reads as a complete one", f, strings.Join(want, ", "))
		}
	}
	// Only the untracked entry may be skipped, so every other file in the list
	// must have been read. Stated as a floor rather than assumed: a skip that
	// spread past CLAUDE.md would otherwise turn this guard into a no-op that
	// still reports success.
	if want := len(files) - 1; checked < want {
		t.Fatalf("read %d of the %d enumerating documents, expected at least %d — this test is not looking where it thinks", checked, len(files), want)
	}
}

// TestSSOHandshakeLifecycleDocMatchesTheCode: the doc once said the handshake
// is "cleared at the top of the callback". The code deliberately does NOT do
// that — an early clear would let an unauthenticated GET with a garbage state
// cancel a login mid-flight — and consumes the handshake atomically at the
// state check instead (ConsumeSSOHandshake; the callback's own comment states
// the boundary rule). A doc-driven "fix" toward the old sentence would open
// that hole, so pin both halves: the code keeps the atomic consume, and the
// doc keeps describing it rather than the early clear.
func TestSSOHandshakeLifecycleDocMatchesTheCode(t *testing.T) {
	code := read(t, "internal/server/handlers/sso.go")
	if !strings.Contains(code, "ConsumeSSOHandshake(func(stored string) bool") {
		t.Error("the SSO callback no longer consumes the handshake via ConsumeSSOHandshake's atomic state match; docs/security.md describes that lifecycle")
	}
	doc := read(t, "docs/security.md")
	if strings.Contains(doc, "cleared at the top") {
		t.Error(`docs/security.md again describes the handshake as "cleared at the top" of the callback — the code refuses that on purpose (it would be a logout-CSRF hole); describe the atomic compare-and-consume instead`)
	}
	if !strings.Contains(doc, "compare-and-consume") {
		t.Error("docs/security.md no longer describes the handshake's atomic compare-and-consume; keep the doc aligned with ConsumeSSOHandshake")
	}
}

// TestTheIndexPredicateGuardIsDescribedAsTheLexer: the documented basis was a
// hand-rolled scan ("one statement only (no ';')") which tracked only `'`, so
// every other quoting form an engine has walked straight past it. The guard is
// now the dialect's own splitter, and the docs must not describe the scan that
// was replaced.
func TestTheIndexPredicateGuardIsDescribedAsTheLexer(t *testing.T) {
	// The code really does split under the dialect's grammar…
	code := read(t, "internal/server/handlers/structure.go")
	if !strings.Contains(code, "sqlscript.Split(w, prof)") {
		t.Error("indexPredicate no longer splits under the dialect's lexer profile; the docs below describe that it does")
	}
	// …and no document still advertises the check it replaced. The Go comment
	// spelled it (no ';') and security.md spelled it (no `;`), so both forms are
	// refused.
	files := []string{"docs/security.md", "internal/server/handlers/structure.go", "CLAUDE.md"}
	checked := 0
	for _, f := range files {
		body, ok := readDoc(t, f)
		if !ok {
			continue // local-only (untrackedDocs); floored below
		}
		checked++
		for _, stale := range []string{"(no ';')", "(no `;`)"} {
			if strings.Contains(body, stale) {
				t.Errorf("%s still describes the predicate guard as %s, which is not what it checks", f, stale)
			}
		}
	}
	if want := len(files) - 1; checked < want {
		t.Fatalf("read %d of the %d documents, expected at least %d — this test is not looking where it thinks", checked, len(files), want)
	}
}

// TestHandlerEnforcedConsoleChecksAreCountedRight: three comments and one doc
// bullet said the stored-program editor was "the only one outside the
// middleware". Adding the partial-index gate made all four false at once, which
// is what a count in prose does when the thing it counts grows.
func TestHandlerEnforcedConsoleChecksAreCountedRight(t *testing.T) {
	// Both handler-level checks exist…
	if code := read(t, "internal/server/handlers/programs.go"); !strings.Contains(code, "RefuseByPolicy") {
		t.Error("saveProgram no longer carries its own console check")
	}
	if code := read(t, "internal/server/handlers/structure.go"); !strings.Contains(code, "RefuseByPolicy") {
		t.Error("runStructureOp no longer carries the partial-index console check")
	}
	// …and nothing claims there is one.
	for _, f := range []string{
		"docs/security.md",
		"internal/server/handlers/programs.go",
		"internal/server/handlers/metadata.go",
		"internal/server/router.go",
		"internal/server/restrict.go",
		"internal/view/allowance.go",
	} {
		body := read(t, f)
		for _, stale := range []string{
			"the only one outside the middleware",
			"One exception, and it is in the handler",
			"the second enforcement point in programs.go",
		} {
			if strings.Contains(body, stale) {
				t.Errorf("%s still says %q; there are two handler-level console checks", f, stale)
			}
		}
	}
}

// TestTheColumnDefaultDocMatchesTheForm: §4 said the DEFAULT control let a user
// choose "between a literal default and an expression default", which the form
// cannot express — columnform.go says so in as many words. A doc that invents a
// capability sends a reader looking for a guard that has nothing to guard.
func TestTheColumnDefaultDocMatchesTheForm(t *testing.T) {
	if code := read(t, "internal/server/handlers/columnform.go"); !strings.Contains(code, "The form can only express literals") {
		t.Error("columnform.go no longer states that the form can only express literals; docs/security.md §4 cites it")
	}
	if !strings.Contains(read(t, "docs/security.md"), "The form can only express literals") {
		t.Error("docs/security.md §4 no longer cites the comment that bounds what the DEFAULT control accepts")
	}
}

// TestTheMiddlewareChainIsDescribedInBothPlaces: the chain is spelled out layer
// by layer in two documents, and a layer added to one and not the other leaves a
// reader with a map that is missing a step — which for import admission is the
// step that explains why the cap is not simply inside the handler.
func TestTheMiddlewareChainIsDescribedInBothPlaces(t *testing.T) {
	code := read(t, "internal/server/middleware.go")
	if !strings.Contains(code, "s.importAdmission(h)") {
		t.Fatal("the chain no longer installs import admission")
	}
	if !strings.Contains(code, "import admission") {
		t.Error("chain()'s own comment does not name the import-admission layer")
	}
	if !strings.Contains(read(t, "docs/architecture.md"), "importAdmission") {
		t.Error("docs/architecture.md's request lifecycle does not name the import-admission layer")
	}
}

// TestTheSessionScanBoundIsNotStatedAsAFact: migrate.go justified having no
// index on last_seen with "bounded by the number of live sessions — a few
// thousand rows at the very most", which nothing enforced. It is now
// storage.max_sessions, which an operator can also set to zero.
func TestTheSessionScanBoundIsNotStatedAsAFact(t *testing.T) {
	body := read(t, "internal/storage/migrate.go")
	if strings.Contains(body, "a few thousand rows at the very most") {
		t.Error("migrate.go still asserts an unenforced bound on the sessions table")
	}
	if !strings.Contains(body, "storage.max_sessions") {
		t.Error("migrate.go does not name the setting that actually bounds the scan")
	}
}
