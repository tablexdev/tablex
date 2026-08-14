package sqlite

import (
	"regexp"
	"strings"
)

var reInlinePKDesc = regexp.MustCompile(`(?i)PRIMARY\s+KEY\s+DESC\b`)

// ddlHasInlinePKDesc reports whether the DDL declares an inline
// "... PRIMARY KEY DESC" column (a documented quirk that is NOT a rowid alias).
// The match is scoped to the top-level column-definition text (via
// columnDefsRegion, which elides string literals, quoted identifiers and nested
// parentheses such as CHECK(...) or type(n)), so a literal "PRIMARY KEY DESC"
// inside a default/CHECK or a quoted column name cannot false-trip it. The
// trailing \b stops "DESC" matching "DESCRIPTION"/"DESCENDING"; whitespace is
// tolerated because SQLite allows arbitrary spacing between keywords.
func ddlHasInlinePKDesc(ddl string) bool {
	return reInlinePKDesc.MatchString(columnDefsRegion(ddl))
}

// skipDDLComment reports whether ddl[i] begins a "--" line comment or a "/* */"
// block comment and, if so, returns the index of the comment's last character
// (the caller's loop i++ then advances past it). A comment must be skipped BEFORE
// the paren/quote scanning so a "PRIMARY KEY DESC" / "WITHOUT ROWID" token — or a
// stray paren — inside a comment cannot flip the auto-increment/rowid detection.
func skipDDLComment(ddl string, i int) (int, bool) {
	if i+1 >= len(ddl) {
		return i, false
	}
	switch {
	case ddl[i] == '-' && ddl[i+1] == '-':
		j := i + 2
		for j < len(ddl) && ddl[j] != '\n' {
			j++
		}
		return j - 1, true // stop before '\n' (the caller keeps it as a separator)
	case ddl[i] == '/' && ddl[i+1] == '*':
		j := i + 2
		for j+1 < len(ddl) && !(ddl[j] == '*' && ddl[j+1] == '/') {
			j++
		}
		if j+1 < len(ddl) {
			return j + 1, true // consume through the closing '/'
		}
		return len(ddl) - 1, true // unterminated: consume to end
	}
	return i, false
}

// parseGeneratedExprs maps each generated column's declared name to its
// generation expression (without the surrounding parens), parsed from the
// CREATE TABLE text — PRAGMA table_xinfo exposes the generated FLAG but not the
// formula. A definition that cannot be parsed is simply absent from the map, so
// the structure page keeps the generated marker without a formula rather than
// failing. Quoted identifiers, bracket names, string literals and nested parens
// in the expression are all handled.
func parseGeneratedExprs(ddl string) map[string]string {
	out := map[string]string{}
	for _, def := range splitColumnDefs(ddl) {
		open := findGeneratedAs(def)
		if open < 0 {
			continue // not a generated column (no top-level "AS (" clause)
		}
		expr, ok := balancedParen(def, open)
		if !ok {
			continue
		}
		name, ok := leadingIdent(def)
		if !ok {
			continue
		}
		out[name] = expr
	}
	return out
}

func isIdentByte(b byte) bool {
	return b == '_' || b == '$' || (b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// findGeneratedAs returns the index of the '(' opening a column's
// "[GENERATED ALWAYS] AS (expr)" generation clause, or -1. Paren depth is tracked
// and quoted/bracketed regions skipped, so an "AS (" inside a type length, a
// CHECK() body or a string literal never matches — only a top-level AS keyword.
func findGeneratedAs(def string) int {
	depth := 0
	for i := 0; i < len(def); i++ {
		switch c := def[i]; c {
		case '\'', '"', '`':
			i++
			for i < len(def) {
				if def[i] == c {
					if i+1 < len(def) && def[i+1] == c {
						i++
					} else {
						break
					}
				}
				i++
			}
		case '[':
			for i < len(def) && def[i] != ']' {
				i++
			}
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth != 0 || (c != 'a' && c != 'A') {
				continue
			}
			if i+1 >= len(def) || (def[i+1] != 's' && def[i+1] != 'S') {
				continue
			}
			if i > 0 && isIdentByte(def[i-1]) {
				continue // not a word boundary before "AS"
			}
			j := i + 2
			if j < len(def) && isIdentByte(def[j]) {
				continue // "ASSERT"/"ASSET"… — not the AS keyword
			}
			for j < len(def) && (def[j] == ' ' || def[j] == '\t' || def[j] == '\n' || def[j] == '\r') {
				j++
			}
			if j < len(def) && def[j] == '(' {
				return j
			}
		}
	}
	return -1
}

// splitColumnDefs returns the top-level (depth-1) comma-separated items of the
// first parenthesised group of a CREATE TABLE — the column and table-constraint
// definitions — with nested parens PRESERVED (unlike columnDefsRegion, which
// elides them). Comments, string literals, quoted identifiers and bracket names
// are scanned so a comma inside them never splits an item. Returns nil when no
// column list is found.
func splitColumnDefs(ddl string) []string {
	var items []string
	var cur strings.Builder
	depth := 0
	started := false
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			items = append(items, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(ddl); i++ {
		if j, ok := skipDDLComment(ddl, i); ok {
			if started {
				cur.WriteByte(' ')
			}
			i = j
			continue
		}
		switch c := ddl[i]; c {
		case '\'', '"', '`':
			start := i
			i++
			for i < len(ddl) {
				if ddl[i] == c {
					if i+1 < len(ddl) && ddl[i+1] == c {
						i++
					} else {
						break
					}
				}
				i++
			}
			if started {
				cur.WriteString(ddl[start:min(i+1, len(ddl))])
			}
		case '[':
			start := i
			for i < len(ddl) && ddl[i] != ']' {
				i++
			}
			if started {
				cur.WriteString(ddl[start:min(i+1, len(ddl))])
			}
		case '(':
			if depth == 0 {
				started = true
				depth++
				continue // the column-list opener itself is not part of any item
			}
			depth++
			cur.WriteByte(c)
		case ')':
			if depth == 1 {
				flush()
				return items // close of the column list
			}
			if depth > 1 {
				depth--
			}
			cur.WriteByte(c)
		case ',':
			if depth == 1 {
				flush()
			} else if started {
				cur.WriteByte(c)
			}
		default:
			if started {
				cur.WriteByte(c)
			}
		}
	}
	flush()
	return items
}

// balancedParen assumes s[open] == '(' and returns the inner text up to the
// matching close paren (trimmed, without the outer parens). String literals,
// backtick/double-quoted identifiers and bracket names are skipped so a paren
// inside them does not unbalance the scan.
func balancedParen(s string, open int) (string, bool) {
	if open < 0 || open >= len(s) || s[open] != '(' {
		return "", false
	}
	depth := 0
	start := open + 1
	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '\'', '"', '`':
			i++
			for i < len(s) {
				if s[i] == c {
					if i+1 < len(s) && s[i+1] == c {
						i++
					} else {
						break
					}
				}
				i++
			}
		case '[':
			for i < len(s) && s[i] != ']' {
				i++
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return strings.TrimSpace(s[start:i]), true
			}
		}
	}
	return "", false
}

// leadingIdent extracts the first identifier of a column definition, unquoting a
// "double", `back` or [bracket] spelling (doubled inner quotes collapsed).
func leadingIdent(def string) (string, bool) {
	def = strings.TrimSpace(def)
	if def == "" {
		return "", false
	}
	switch q := def[0]; q {
	case '"', '`':
		var b strings.Builder
		for i := 1; i < len(def); i++ {
			if def[i] == q {
				if i+1 < len(def) && def[i+1] == q {
					b.WriteByte(q)
					i++
					continue
				}
				return b.String(), b.Len() > 0
			}
			b.WriteByte(def[i])
		}
		return "", false
	case '[':
		if j := strings.IndexByte(def, ']'); j > 1 {
			return def[1:j], true
		}
		return "", false
	default:
		j := 0
		for j < len(def) && def[j] != ' ' && def[j] != '\t' && def[j] != '\n' && def[j] != '\r' && def[j] != '(' {
			j++
		}
		if j == 0 {
			return "", false
		}
		return def[:j], true
	}
}

// columnDefsRegion returns the top-level text of the column-definition list (the
// depth-1 content of the first parenthesised group), with string literals,
// quoted identifiers and nested-parenthesis content elided to spaces so a literal
// or sub-expression cannot be mistaken for a top-level clause. Returns "" when no
// column list is found.
func columnDefsRegion(ddl string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(ddl); i++ {
		if j, ok := skipDDLComment(ddl, i); ok {
			if depth == 1 {
				b.WriteByte(' ') // elide the comment to a separator
			}
			i = j
			continue
		}
		switch c := ddl[i]; c {
		case '\'', '"', '`':
			// Skip the quoted region (quote doubled to escape), eliding it.
			i++
			for i < len(ddl) {
				if ddl[i] == c {
					if i+1 < len(ddl) && ddl[i+1] == c {
						i++
					} else {
						break
					}
				}
				i++
			}
			if depth == 1 {
				b.WriteByte(' ')
			}
		case '[':
			for i < len(ddl) && ddl[i] != ']' {
				i++
			}
			if depth == 1 {
				b.WriteByte(' ')
			}
		case '(':
			if depth == 1 {
				b.WriteByte(' ') // a nested group opens — elide its content
			}
			depth++
		case ')':
			if depth == 1 {
				return b.String() // close of the column list
			}
			if depth > 0 {
				depth--
			}
		default:
			if depth == 1 {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// ddlIsWithoutRowid reports whether the CREATE TABLE declares WITHOUT ROWID.
// It inspects only the table-options clause that follows the column-definition
// list (the matching close-paren of the first top-level "("), so a literal
// "WITHOUT ROWID" inside a string default or a CHECK constraint — both of which
// live inside the column list — never false-trips it, and a legitimate
// "... ) WITHOUT ROWID, STRICT" options list (order-independent) still matches.
// The tail is comment/quote-elided first (elideDDLTail) so a trailing
// "/* WITHOUT ROWID */" comment cannot flip the detection either — the same
// skipDDLComment guarantee the column-list scanners document.
func ddlIsWithoutRowid(ddl string) bool {
	opts := strings.ToUpper(strings.Join(strings.Fields(elideDDLTail(tableOptions(ddl))), " "))
	return strings.Contains(opts, "WITHOUT ROWID")
}

// elideDDLTail returns s with comments, quoted regions and bracketed
// identifiers elided to spaces, using the same skipDDLComment/quote-skip logic
// as columnDefsRegion — which cannot be reused directly here because it only
// emits depth-1 (column-list) text and the options tail is depth-0.
func elideDDLTail(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if j, ok := skipDDLComment(s, i); ok {
			b.WriteByte(' ')
			i = j
			continue
		}
		switch c := s[i]; c {
		case '\'', '"', '`':
			// Skip a quoted region; SQLite escapes the quote char by doubling it.
			i++
			for i < len(s) {
				if s[i] == c {
					if i+1 < len(s) && s[i+1] == c {
						i++
					} else {
						break
					}
				}
				i++
			}
			b.WriteByte(' ')
		case '[':
			for i < len(s) && s[i] != ']' { // bracketed identifier, no doubling
				i++
			}
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// tableOptions returns the text after the column-definition list's matching
// close-paren — the table-options clause. It balances parentheses while skipping
// quoted identifiers ('...', "...", `...`, [...]) so parens or quotes inside
// column definitions do not confuse the scan. Returns "" when no balanced
// top-level group is found.
func tableOptions(ddl string) string {
	depth, start := 0, -1
	for i := 0; i < len(ddl); i++ {
		if j, ok := skipDDLComment(ddl, i); ok {
			i = j
			continue
		}
		switch c := ddl[i]; c {
		case '\'', '"', '`':
			// Skip a quoted region; SQLite escapes the quote char by doubling it.
			i++
			for i < len(ddl) {
				if ddl[i] == c {
					if i+1 < len(ddl) && ddl[i+1] == c {
						i++ // doubled quote → stays inside the literal
					} else {
						break
					}
				}
				i++
			}
		case '[':
			for i < len(ddl) && ddl[i] != ']' { // bracketed identifier, no doubling
				i++
			}
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					return ddl[i+1:]
				}
			}
		}
	}
	return ""
}
