package driver

import "testing"

// TestCommentSafe pins: control characters in an object name or error string
// embedded in a dump comment are neutralized to spaces, so a name like
// `x` + newline + `DROP TABLE users;--` cannot smuggle an executable statement
// onto the next line of the generated dump. Printable content is untouched.
// (Moved here with the implementation, which the dump writers and the dialects
// now share; dump.CommentSafe re-exports it.)
func TestCommentSafe(t *testing.T) {
	cases := []struct{ in, want string }{
		{"orders", "orders"},
		{"x\nDROP TABLE users;--", "x DROP TABLE users;--"},
		{"a\r\nb\tc", "a  b c"},
		{"tab\x7fdel", "tab del"},
		{"unicode ünïcode ✓", "unicode ünïcode ✓"},
	}
	for _, c := range cases {
		if got := CommentSafe(c.in); got != c.want {
			t.Errorf("CommentSafe(%q) = %q, want %q", c.in, got, c.want)
		}
		// No C0 control char or DEL may survive.
		for _, r := range CommentSafe(c.in) {
			if r < 0x20 || r == 0x7f {
				t.Errorf("CommentSafe(%q) left a control char %U", c.in, r)
			}
		}
	}
}
