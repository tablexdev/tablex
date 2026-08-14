package driver

import "strings"

// CommentSafe maps every C0 control character (and DEL) in s to a space so an
// object name or error string embedded in a "-- " / "# " dump comment cannot
// smuggle an executable statement onto the next line via a newline (a quoted
// SQL identifier may legally contain newlines/semicolons — the mysqldump
// CVE-2016-5483 class). Lossy scrubbing is safe: the round-tripping DDL uses
// QuoteIdent, which preserves the true name.
//
// It lives here, in the package both the dump engine and the dialects already
// depend on, so the SQL/CSV writers and a dialect that builds its own comment
// line (PostgreSQL's partition-child objects) share ONE implementation rather
// than each carrying a copy that could drift.
func CommentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
