package driver

import "testing"

// TestDefaultLexerProfile pins the profile-less fallback: PostgreSQL-style
// quoting extensions and a PERMISSIVE Returning set (a profile-less dialect
// keeps the historical behavior of treating RETURNING on any DML as a query).
func TestDefaultLexerProfile(t *testing.T) {
	p := DefaultLexerProfile()
	if !p.EscapeStringE || !p.DollarQuotes || !p.NestedBlockComments {
		t.Errorf("DefaultLexerProfile grammar flags = %+v", p)
	}
	if p.BackslashStrings || p.HashComments || p.DelimiterDirectives {
		t.Errorf("DefaultLexerProfile should not set MySQL-only flags: %+v", p)
	}
	want := ReturningCaps{Insert: true, Update: true, Delete: true, Replace: true, Merge: true}
	if p.Returning != want {
		t.Errorf("DefaultLexerProfile Returning = %+v, want all-true %+v", p.Returning, want)
	}
}

// TestReturningCapsAllows pins the keyword→capability mapping, including the
// case-sensitivity contract (callers uppercase the leading keyword first).
func TestReturningCapsAllows(t *testing.T) {
	rc := ReturningCaps{Insert: true, Delete: true} // Update/Replace/Merge off
	if !rc.Allows("INSERT") || !rc.Allows("DELETE") {
		t.Error("Allows should be true for enabled keywords")
	}
	for _, k := range []string{"UPDATE", "REPLACE", "MERGE", "SELECT", "insert", ""} {
		if rc.Allows(k) {
			t.Errorf("Allows(%q) = true, want false", k)
		}
	}
}
