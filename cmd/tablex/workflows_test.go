package main

// Guards over the release automation's cross-file couplings. The release
// workflow's containment logic names things that live in ANOTHER workflow
// file; nothing in YAML, actionlint or shellcheck checks that those names
// still exist, and the failure is silent in the worst direction — a rename
// makes the classifier match nothing, so a genuinely broken release keeps the
// `latest` tag with only a red run to notice. These tests are the coupling.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// checkAllowRE matches the release workflow's allowlist calls:
//
//	check_allow "verify-packages" "The .deb installs and runs"
var checkAllowRE = regexp.MustCompile(`check_allow\s+"([^"]+)"\s+"([^"]+)"`)

// workflowJobsAndSteps extracts {job: [step names]} from a workflow file. It
// is deliberately line-based rather than a YAML parse: the repo ships four
// modules and none is a YAML library, and what is being checked here is the
// literal text a shell comparison will make — `.name == "…"` matches the
// rendered string, not a parsed node.
func workflowJobsAndSteps(t *testing.T, rel string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var (
		out     = map[string][]string{}
		jobRE   = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`)
		stepRE  = regexp.MustCompile(`^\s+- name:\s*(.+?)\s*$`)
		inJobs  bool
		current string
	)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "jobs:") {
			inJobs = true
			continue
		}
		// Any other column-0 key ends the jobs block.
		if inJobs && len(line) > 0 && line[0] != ' ' && line[0] != '#' {
			inJobs = false
		}
		if !inJobs {
			continue
		}
		if m := jobRE.FindStringSubmatch(line); m != nil {
			current = m[1]
			if _, ok := out[current]; !ok {
				out[current] = nil
			}
			continue
		}
		if m := stepRE.FindStringSubmatch(line); m != nil && current != "" {
			name := strings.Trim(m[1], `"'`)
			out[current] = append(out[current], name)
		}
	}
	return out
}

// TestReleaseDemotionAllowlistMatchesInstallVerify: the release workflow demotes
// a stable release from `latest` only when an ALLOWLISTED (job, step) pair
// reports a failure, and it spells those pairs as literal strings inside a
// shell script — matched against `gh run view --json jobs` output at runtime,
// in a different workflow file. Renaming a step there (this very feature
// renamed all three), or turning a job into a matrix so its rendered name gains
// a " (x)" suffix, makes every comparison match nothing: the classifier reports
// "indeterminate", a genuinely broken release silently keeps `latest`, and
// actionlint, go test and CI all stay green on the rename. Containment that
// rots invisibly is worse than none, so the names are pinned in both
// directions.
func TestReleaseDemotionAllowlistMatchesInstallVerify(t *testing.T) {
	release, err := os.ReadFile(filepath.Join(repoRoot, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	pairs := checkAllowRE.FindAllStringSubmatch(string(release), -1)
	// The floor: three deterministic, release-bound assertions. A drop to zero
	// (the shell rewritten, the helper renamed) would otherwise make this test
	// vacuously green — exactly the silence it exists to prevent.
	const floor = 3
	if len(pairs) < floor {
		t.Fatalf("found %d check_allow pairs in release.yml, expected at least %d — this guard is not looking where it thinks", len(pairs), floor)
	}

	jobs := workflowJobsAndSteps(t, ".github/workflows/install-verify.yml")
	if len(jobs) < 4 {
		t.Fatalf("parsed %d jobs from install-verify.yml, expected at least 4 — the parse has stopped matching", len(jobs))
	}
	for _, p := range pairs {
		job, step := p[1], p[2]
		steps, ok := jobs[job]
		if !ok {
			t.Errorf("release.yml's demotion allowlist names job %q, which install-verify.yml does not define (jobs: %v)", job, keysOf(jobs))
			continue
		}
		found := false
		for _, s := range steps {
			if s == step {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("release.yml's demotion allowlist names step %q in job %q, which install-verify.yml does not define; the classifier would match nothing and a broken stable release would keep `latest`. Steps in that job: %v", step, job, steps)
		}
	}
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
