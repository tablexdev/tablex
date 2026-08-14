package view

import (
	"strings"
	"testing"
)

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{-1, "—"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.in); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHumanInt(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{-1, "—"},
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1234567, "1,234,567"},
	}
	for _, c := range cases {
		if got := HumanInt(c.in); got != c.want {
			t.Errorf("HumanInt(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate(3, "hello"); got != "hel…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate(10, "hi"); got != "hi" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate(-1, "hi"); got != "…" {
		t.Errorf("truncate negative n = %q, want %q (clamped to 0, no panic)", got, "…")
	}
	// The rune-walk rewrite must count RUNES, not bytes — a multi-byte
	// string is longer in bytes than in runes, so the byte fast path must not
	// short-circuit it, and the cut must land on a rune boundary.
	if got := truncate(3, "héllo"); got != "hél…" {
		t.Errorf("truncate multi-byte = %q, want %q", got, "hél…")
	}
	if got := truncate(5, "héllo"); got != "héllo" {
		t.Errorf("truncate exactly n runes (6 bytes) = %q, want the string unchanged", got)
	}
	if got := truncate(0, "x"); got != "…" {
		t.Errorf("truncate(0) = %q, want %q", got, "…")
	}
	if got := truncate(3, ""); got != "" {
		t.Errorf("truncate of the empty string = %q, want empty", got)
	}
}

// BenchmarkTruncateLargeCell guards the allocation fix: materializing
// []rune(s) cost four bytes per input byte, so previewing 200 characters of a
// large TEXT cell allocated several times the cell itself — per cell, on a page
// of hundreds of rows. The rune walk must be allocation-flat in the input size.
func BenchmarkTruncateLargeCell(b *testing.B) {
	s := strings.Repeat("abcdefghij", 200_000) // 2 MB
	b.ReportAllocs()
	for b.Loop() {
		_ = truncate(200, s)
	}
}

func TestTemplateHelpers(t *testing.T) {
	// Smoke-test the retained generic helpers (full template parsing is covered by
	// the web package integration tests).
	if got := list(1, "a", true); len(got) != 3 || got[1] != "a" {
		t.Errorf("list helper failed: %v", got)
	}
	if got := add(2, 3); got != 5 {
		t.Errorf("add helper = %d, want 5", got)
	}
}
