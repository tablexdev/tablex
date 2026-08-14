package driver

import (
	"strings"
	"testing"
)

// TestCollationMarkerRoundTrip pins the non-lossy field encoding: object
// names containing newlines, comment delimiters, quotes, the marker prefix
// itself, and non-ASCII must survive format → parse byte-exact (dump comments
// scrub control characters lossily via commentSafe — markers must not).
func TestCollationMarkerRoundTrip(t *testing.T) {
	names := []string{
		"simple",
		"line\nbreak", "cr\rhere",
		"comment */ tail", "-- dashes; DROP TABLE x",
		"-- tablex:v1 db-collation kind=routine name=00 value=00", // the prefix itself
		"quo'te\"s`", `back\slash`,
		"日本語ルーチン",
	}
	for _, name := range names {
		line := FormatCollationMarker("routine", name, "utf8mb4_general_ci")
		if strings.ContainsAny(line, "\r\n") {
			t.Errorf("marker for %q is not a single line: %q", name, line)
			continue
		}
		m, ok := ParseCollationMarker(line)
		if !ok {
			t.Errorf("marker for %q did not parse: %q", name, line)
			continue
		}
		if m.Kind != "routine" || m.Name != name || m.Collation != "utf8mb4_general_ci" {
			t.Errorf("round-trip mismatch for %q: %+v", name, m)
		}
	}
	// CRLF tolerance: a single trailing \r (textarea/CRLF mangling) still parses.
	if _, ok := ParseCollationMarker(FormatCollationMarker("event", "e", "latin1_swedish_ci") + "\r"); !ok {
		t.Error("marker with trailing \\r did not parse")
	}
}

// TestCollationMarkerRejectsMalformed pins "recognition validates the full
// grammar": malformed or oversized marker-like lines are ordinary comments,
// never events.
func TestCollationMarkerRejectsMalformed(t *testing.T) {
	valid := FormatCollationMarker("trigger", "trg", "utf8mb4_bin")
	if _, ok := ParseCollationMarker(valid); !ok {
		t.Fatalf("control line did not parse: %q", valid)
	}
	bad := []string{
		"",
		"-- an ordinary comment",
		"-- tablex:v1 db-collation",              // no fields
		"-- tablex:v1 db-collation kind=routine", // missing fields
		"-- tablex:v1 db-collation kind=table name=00 value=00",       // unknown kind
		"-- tablex:v1 db-collation kind=routine name= value=00",       // empty hex
		"-- tablex:v1 db-collation kind=routine name=0 value=00",      // odd-length hex
		"-- tablex:v1 db-collation kind=routine name=AB value=00",     // uppercase hex
		"-- tablex:v1 db-collation kind=routine name=zz value=00",     // non-hex
		"-- tablex:v1 db-collation kind=routine name=00 value=00 x=1", // trailing field
		"-- tablex:v2 db-collation kind=routine name=00 value=00",     // future version
		"--tablex:v1 db-collation kind=routine name=00 value=00",      // wrong prefix spacing
		" " + valid, // leading space (not exact-line)
		"-- tablex:v1 db-collation kind=routine name=00 value=" + strings.Repeat("00", 1024), // oversized
	}
	for _, line := range bad {
		if m, ok := ParseCollationMarker(line); ok {
			t.Errorf("malformed line parsed as marker %+v: %q", m, line)
		}
	}
}

// TestFrameMarker pins the frame-marker grammar and delimiter validation.
func TestFrameMarker(t *testing.T) {
	for _, tok := range []string{"$$", ";;", "@@", "//", "$$3$$"} {
		line := FormatFrameMarker(tok)
		got, ok := ParseFrameMarker(line)
		if !ok || got != tok {
			t.Errorf("frame marker round-trip for %q: got %q ok=%v (line %q)", tok, got, ok, line)
		}
	}
	bad := []string{
		"-- tablex:v1 frame",                                      // no delimiter
		"-- tablex:v1 frame delimiter=",                           // empty
		"-- tablex:v1 frame delimiter=a b",                        // whitespace
		"-- tablex:v1 frame delimiter='x'",                        // quote characters
		"-- tablex:v1 frame delimiter=x\\y",                       // backslash
		"-- tablex:v1 frame delimiter=" + strings.Repeat("$", 17), // too long
		"-- tablex:v1 frame delimiter=$$ extra",                   // trailing field
	}
	for _, line := range bad {
		if tok, ok := ParseFrameMarker(line); ok {
			t.Errorf("malformed frame line parsed (tok %q): %q", tok, line)
		}
	}
}

// TestChooseFrameDelimiter: the chosen token must never occur in the body.
func TestChooseFrameDelimiter(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{"CREATE PROCEDURE p() BEGIN SELECT 1; END", "$$"},
		{"SELECT a$$b", ";;"},                      // $$ occurs (identifier chars)
		{"$$ ;; @@", "//"},                         // first three all occur
		{"$$ ;; @@ //", "$$1$$"},                   // every fixed candidate occurs → numbered
		{"$$ ;; @@ // $$1$$", "$$2$$"},             // and the numbering advances
		{"body ending in $", "$$"},                 // a bare '$' does not contain "$$"
		{"$js$ var x = 1 $js$", "$$"},              // single-$ runs are fine for "$$"
		{"$$ ;; @@ // $$1$$ $$2$$ $$3$$", "$$4$$"}, // contiguous run 1..N → N+1
		{"$$ ;; @@ // $$1$$2$$", "$$3$$"},          // overlapping $$2$$ (shares a $$) is still occupied
	}
	for _, c := range cases {
		if got := ChooseFrameDelimiter(c.body); got != c.want {
			t.Errorf("ChooseFrameDelimiter(%q) = %q, want %q", c.body, got, c.want)
		}
		if strings.Contains(c.body, c.want) {
			t.Errorf("test case broken: %q contains %q", c.body, c.want)
		}
	}
}
