package audit

import "regexp"

// sqlStringLit matches one SQL string literal: single-quoted, escaping a quote
// by doubling it, plus backslash escapes (MySQL); or double-quoted (a string in
// MySQL's default mode; an identifier elsewhere, where masking one is
// harmless).
//
// Written as prose rather than showing the doubled quote: gofmt reformats doc
// comments with godoc's typographic convention, which turns two apostrophes
// into a right double quotation mark — so the literal spelling cannot survive
// here, and reads as corruption when it does not.
const sqlStringLit = `('(?:[^'\\]|\\.|'')*'|"(?:[^"\\]|\\.|"")*")`

// credentialLiteralREs match the positions where a SQL statement embeds a
// credential as a literal. The list is the union of the supported engines'
// account-DCL grammars; each pattern's group 1 is the keyword run to keep and
// group 2 the literal to mask.
var credentialLiteralREs = []*regexp.Regexp{
	// MySQL/MariaDB: CREATE/ALTER USER ... IDENTIFIED BY 'pw', or the hash
	// form IDENTIFIED BY PASSWORD 'hash'.
	regexp.MustCompile(`(?i)\b(identified\s+by\s+(?:password\s+)?)` + sqlStringLit),
	// MariaDB: IDENTIFIED VIA/WITH <plugin> USING/AS 'hash'.
	// MySQL 8: IDENTIFIED WITH <plugin> BY 'pw' (the plugin form of a plain
	// password, not a hash).
	regexp.MustCompile(`(?i)\b(identified\s+(?:via|with)\s+\S+\s+(?:using|as|by)\s+)` + sqlStringLit),
	// MySQL 8: ALTER USER ... IDENTIFIED BY 'new' REPLACE 'current' — the
	// REPLACE clause carries the account's CURRENT password. REPLACE INTO and
	// the REPLACE() function never put a string literal right after the bare
	// keyword, so they don't match; anything else that does loses a literal to
	// the mask, the accepted trade described below.
	regexp.MustCompile(`(?i)\b(replace\s+)` + sqlStringLit),
	// PostgreSQL: CREATE/ALTER ROLE|USER ... [ENCRYPTED] PASSWORD 'pw'.
	// MySQL: SET PASSWORD [FOR u] = 'pw' | PASSWORD('pw') | OLD_PASSWORD('pw')
	// (the FOR arm reaches past the account term to the assigned literal; the
	// account itself is not a secret and stays). The assignment form also
	// masks `password = 'literal'` in DML, on purpose: an UPDATE writing a
	// password column's literal is a credential too, and the cost of a false
	// positive is a masked literal, not a lie.
	regexp.MustCompile(`(?i)\b((?:old_)?password\s*(?:for\s+\S+\s*=\s*|\(\s*|=\s*|\s+))` + sqlStringLit),
}

// RedactCredentialLiterals masks the string literal in every password-bearing
// position of s with '***'. It exists for SQL the USER wrote: the console and
// SQL import record statements verbatim, and nothing upstream knows which
// literal inside a typed CREATE USER is the secret — unlike TableX-generated
// DCL, whose exact password rides StatementEvent.Redact as a needle. This scan
// is grammar-shaped, not a parser, and errs only toward masking: a statement
// that merely LOOKS like it assigns a password loses that literal from the
// trail, while a credential never survives into it. Both properties matter,
// because the trail's contract (audit.Event) is that nothing recorded can be
// replayed to gain access.
func RedactCredentialLiterals(s string) string {
	for _, re := range credentialLiteralREs {
		s = re.ReplaceAllString(s, "${1}'***'")
	}
	return s
}
