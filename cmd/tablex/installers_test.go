package main

// Guards over the three install scripts the README advertises. They are fetched
// over the network and executed verbatim on machines this project never sees,
// so the things that can break them are worth catching before a release rather
// than during one.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestInstallScriptsAreASCII: PowerShell's own linter refuses a non-ASCII .ps1
// that carries no UTF-8 BOM (PSScriptAnalyzer's
// PSUseBOMForUnicodeEncodedFile), because Windows PowerShell 5.1 — the edition
// a stock Windows box runs, and the one the install one-liner targets — decodes
// a BOM-less file as the system ANSI codepage and mangles anything outside it.
// Three em dashes reached install.ps1 in prose that matches this repo's
// comment style everywhere else, and CI was the first thing to notice: the
// analyzer runs only there.
//
// ASCII rather than a BOM is the fix, for all three scripts together. Adding a
// BOM would satisfy the linter but put bytes in front of a file that is also
// piped straight into an interpreter (irm | iex, curl | sh), which is a
// different class of problem to debug; keeping the files ASCII has no such
// edge and needs no per-interpreter reasoning. install.cmd is included because
// batch files are read by the console codepage, which is the same trap wearing
// a different hat.
func TestInstallScriptsAreASCII(t *testing.T) {
	scripts := []string{"install.ps1", "install.sh", "install.cmd"}
	checked := 0
	for _, name := range scripts {
		b, err := os.ReadFile(filepath.Join(repoRoot, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		checked++
		line := 1
		for i, c := range b {
			if c == '\n' {
				line++
				continue
			}
			if c > 127 {
				t.Errorf("%s:%d contains a non-ASCII byte %#x; keep the install scripts ASCII (an em dash in a comment is the usual cause) or PSScriptAnalyzer will refuse the .ps1 for having no BOM", name, line, b[i])
				break // one report per file is enough to act on
			}
		}
	}
	if checked != len(scripts) {
		t.Fatalf("checked %d of %d install scripts", checked, len(scripts))
	}
}
