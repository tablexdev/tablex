package driver

import "strings"

// Sequence-reference rewriting. A table-scope PostgreSQL export can
// reference a sequence the export does not emit (an inherited serial default,
// a default naming a standalone or cross-schema sequence). The dialect
// materializes a replacement sequence and records the mapping in
// DumpPlan.SequenceRewrites; the handler then routes the emitted table DDL
// through RewriteSequenceRefs, which rebinds the quoted literal inside
// nextval('…'::regclass) / nextval('…'::text) to the replacement. The scanner
// is quote-aware (doubled '' inside literals, "…" identifiers that may contain
// quotes), so a hostile identifier cannot desynchronize it.

// SeqRefKey builds the canonical lookup key for a schema-qualified sequence
// reference. NUL-separated so a dotted relation name cannot collide with a
// schema qualification.
func SeqRefKey(schema, name string) string { return schema + "\x00" + name }

// RewriteSequenceRefs replaces the content of every single-quoted literal in
// ddl that is cast to ::regclass or ::text AND parses as a schema-qualified
// identifier matching a rewrites key (SeqRefKey-shaped) with the mapped
// replacement (also SeqRefKey-shaped), rendered with PostgreSQL identifier
// quoting. Unqualified literals never match — a rewrite must never guess a
// search_path. A nil/empty map returns ddl unchanged.
func RewriteSequenceRefs(ddl string, rewrites map[string]string) string {
	if len(rewrites) == 0 || !strings.ContainsRune(ddl, '\'') {
		return ddl
	}
	var b strings.Builder
	b.Grow(len(ddl))
	i, n := 0, len(ddl)
	for i < n {
		switch ddl[i] {
		case '"':
			// A quoted identifier may contain ' — copy it opaquely.
			j := skipQuotedIdent(ddl, i)
			b.WriteString(ddl[i:j])
			i = j
		case '\'':
			content, end, ok := scanSQLLiteral(ddl, i)
			if !ok {
				// Unterminated literal: emit the tail verbatim.
				b.WriteString(ddl[i:])
				return b.String()
			}
			if cast := literalCastType(ddl, end); cast == "regclass" || cast == "text" {
				if schema, name, ok := parseQualifiedIdent(content); ok {
					if repl, hit := rewrites[SeqRefKey(schema, name)]; hit {
						rs, rn, _ := strings.Cut(repl, "\x00")
						b.WriteByte('\'')
						b.WriteString(strings.ReplaceAll(renderQualifiedIdent(rs, rn), "'", "''"))
						b.WriteByte('\'')
						i = end
						continue
					}
				}
			}
			b.WriteString(ddl[i:end])
			i = end
		default:
			b.WriteByte(ddl[i])
			i++
		}
	}
	return b.String()
}

// NextvalTextRefs scans one deparsed default expression for LATE-BOUND
// sequence references — deparsed as nextval(('literal'::text)::regclass) —
// returning the literal contents, plus dynamic=true when any nextval argument
// is not a plain (possibly parenthesized) quoted literal: an expression or
// concatenation cannot be resolved or rewritten and the caller warns.
// Early-bound '…'::regclass arguments are ignored here — pg_depend already
// records those edges.
func NextvalTextRefs(expr string) (refs []string, dynamic bool) {
	i, n := 0, len(expr)
	for i < n {
		switch {
		case expr[i] == '"':
			i = skipQuotedIdent(expr, i)
		case expr[i] == '\'':
			if _, end, ok := scanSQLLiteral(expr, i); ok {
				i = end
			} else {
				return refs, dynamic
			}
		case isIdentStart(expr[i]):
			k := i + 1
			for k < n && isIdentChar(expr[k]) {
				k++
			}
			word := strings.ToLower(expr[i:k])
			i = k
			if word != "nextval" {
				continue
			}
			j := skipSQLSpaces(expr, k)
			if j >= n || expr[j] != '(' {
				continue
			}
			// The argument may sit inside extra parens (the deparsed
			// late-bound shape wraps the ::text cast before re-casting).
			j = skipSQLSpaces(expr, j+1)
			for j < n && expr[j] == '(' {
				j = skipSQLSpaces(expr, j+1)
			}
			if j >= n || expr[j] != '\'' {
				dynamic = true
				continue
			}
			content, end, ok := scanSQLLiteral(expr, j)
			if !ok {
				return refs, true
			}
			castType, after := literalCastAt(expr, end)
			// A plain literal argument is immediately closed after its cast; an
			// operator following it (a concatenation) makes it dynamic.
			rest := skipSQLSpaces(expr, after)
			closed := rest >= n || expr[rest] == ')'
			switch {
			case castType == "text" && closed:
				refs = append(refs, content)
			case castType == "regclass" && closed:
				// early-bound: pg_depend covers it
			default:
				dynamic = true
			}
			i = end
		default:
			i++
		}
	}
	return refs, dynamic
}

// ParseQualifiedSeqLiteral parses a late-bound literal's content into
// (schema, name). ok is false for an unqualified or malformed reference —
// binding one against an unknown restore-time search_path would be a guess.
func ParseQualifiedSeqLiteral(content string) (schema, name string, ok bool) {
	return parseQualifiedIdent(content)
}

// scanSQLLiteral scans the single-quoted literal whose opening quote is at
// s[i], and returns its unescaped content plus the index just past the closing
// quote. A quote doubled inside the literal collapses to one (PostgreSQL
// escaping).
func scanSQLLiteral(s string, i int) (content string, end int, ok bool) {
	var c strings.Builder
	j := i + 1
	for j < len(s) {
		if s[j] == '\'' {
			if j+1 < len(s) && s[j+1] == '\'' {
				c.WriteByte('\'')
				j += 2
				continue
			}
			return c.String(), j + 1, true
		}
		c.WriteByte(s[j])
		j++
	}
	return "", 0, false
}

// skipQuotedIdent returns the index just past the double-quoted identifier
// starting at s[i] == '"' (doubled "" stays inside it).
func skipQuotedIdent(s string, i int) int {
	j := i + 1
	for j < len(s) {
		if s[j] == '"' {
			if j+1 < len(s) && s[j+1] == '"' {
				j += 2
				continue
			}
			return j + 1
		}
		j++
	}
	return len(s)
}

// literalCastType returns the lower-cased cast type name immediately following
// index i ("regclass", "text", …), tolerating whitespace and an optional
// pg_catalog. qualifier, or "" when no ::cast follows.
func literalCastType(s string, i int) string {
	typ, _ := literalCastAt(s, i)
	return typ
}

// literalCastAt is literalCastType plus the index just past the cast tokens
// (or i unchanged when no cast follows), so a caller can inspect what comes
// AFTER the cast — the plain-literal vs concatenation distinction.
func literalCastAt(s string, i int) (string, int) {
	j := skipSQLSpaces(s, i)
	if j+1 >= len(s) || s[j] != ':' || s[j+1] != ':' {
		return "", i
	}
	j = skipSQLSpaces(s, j+2)
	word := func() string {
		k := j
		for k < len(s) && isIdentChar(s[k]) {
			k++
		}
		w := s[j:k]
		j = k
		return w
	}
	w := word()
	if strings.EqualFold(w, "pg_catalog") && j < len(s) && s[j] == '.' {
		j++
		w = word()
	}
	return strings.ToLower(w), j
}

func skipSQLSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || c == '$' || (c >= '0' && c <= '9')
}

// parseQualifiedIdent splits a regclass/text literal's content into exactly
// two identifier parts, applying PostgreSQL rules: "quoted" parts keep case
// (doubled "" collapses), unquoted parts fold to lower case with surrounding
// whitespace trimmed. Anything else — unqualified, three-part, empty part,
// stray quote — returns ok=false (the reference is left untouched/warned).
func parseQualifiedIdent(s string) (schema, name string, ok bool) {
	var parts []string
	i := 0
	for {
		i = skipSQLSpaces(s, i)
		var p strings.Builder
		if i < len(s) && s[i] == '"' {
			j := i + 1
			closed := false
			for j < len(s) {
				if s[j] == '"' {
					if j+1 < len(s) && s[j+1] == '"' {
						p.WriteByte('"')
						j += 2
						continue
					}
					j++
					closed = true
					break
				}
				p.WriteByte(s[j])
				j++
			}
			if !closed || p.Len() == 0 {
				return "", "", false
			}
			i = j
		} else {
			for i < len(s) && s[i] != '.' {
				if s[i] == '"' {
					return "", "", false
				}
				p.WriteByte(s[i])
				i++
			}
			trimmed := strings.TrimSpace(p.String())
			if trimmed == "" {
				return "", "", false
			}
			p.Reset()
			p.WriteString(strings.ToLower(trimmed))
		}
		parts = append(parts, p.String())
		i = skipSQLSpaces(s, i)
		if i >= len(s) {
			break
		}
		if s[i] != '.' {
			return "", "", false
		}
		i++
	}
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// renderQualifiedIdent renders schema.name with each part quoted only when it
// is not a safe lower-case identifier — matching how PostgreSQL itself prints
// a regclass.
func renderQualifiedIdent(schema, name string) string {
	return maybeQuoteIdentPart(schema) + "." + maybeQuoteIdentPart(name)
}

func maybeQuoteIdentPart(p string) string {
	safe := p != ""
	for i := 0; i < len(p) && safe; i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c == '_':
		case (c >= '0' && c <= '9' || c == '$') && i > 0:
		default:
			safe = false
		}
	}
	if safe {
		return p
	}
	return `"` + strings.ReplaceAll(p, `"`, `""`) + `"`
}
