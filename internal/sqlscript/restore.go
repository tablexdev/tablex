package sqlscript

import (
	"errors"
	"fmt"
	"strings"
)

// Section is a chunk of a restore script bound to one database
// (db == "" means the import target).
type Section struct {
	DB     string
	Script string
}

// SplitRestoreSections splits a script on lines holding psql-style \connect
// (or \c) markers. Text before the first marker belongs to the import target.
// Recognition is gated: only a PostgreSQL server-scope import (allowConnect)
// honors markers — TableX emits them only in that dump shape, and honoring one
// in a db/table-scoped import would silently execute part of the script
// against another database. When enabled, the scan is quote-aware with
// PostgreSQL rules: a \connect line inside a '…' / E'…' / "…" / $tag$…$tag$
// span or a comment is content, never a marker. A recognized marker with an
// unterminated quoted name is a hard error, not a mis-split.
//
// max bounds the number of SECTIONS (<= 0 means no bound). Without it, millions
// of tiny \connect lines build an unbounded []Section before a single statement
// is lexed — the same exhaustion ScanLimit closes one level down. Changed in
// place rather than twinned like ScanLimit: this function already returns an
// error, so no caller is kept compiling by a second name, and allowConnect must
// not be droppable — it is the gate that makes the whole script ONE inert
// section for a db/table-scoped import, and a bounded variant without it would
// silently honour \connect on every import.
func SplitRestoreSections(script string, allowConnect bool, max int) ([]Section, error) {
	if !allowConnect {
		if s := strings.TrimSpace(script); s != "" {
			return []Section{{Script: s}}, nil
		}
		return nil, nil
	}
	var sections []Section
	n := len(script)
	cur := ""
	segStart := 0
	overflow := false
	flush := func(end int) {
		if s := strings.TrimSpace(script[segStart:end]); s != "" {
			if max > 0 && len(sections) >= max {
				overflow = true
				return
			}
			sections = append(sections, Section{DB: cur, Script: s})
		}
	}
	lineStart := true // nothing but whitespace seen since the last newline
	for i := 0; i < n && !overflow; {
		c := script[i]
		switch {
		case c == '\n':
			lineStart = true
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '\'' || c == '"':
			lineStart = false
			i = skipStringLiteral(script, i, c == '\'' && isEscStringQuote(script, i))
		case c == '$':
			lineStart = false
			if end, ok := skipDollarQuoted(script, i); ok {
				i = end
			} else {
				i++
			}
		case c == '-' && i+1 < n && script[i+1] == '-':
			for i < n && script[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && script[i+1] == '*':
			// A block comment is content on its line: a \connect that follows it
			// on the SAME line is not line-leading, so it stays content (matching
			// the "backslash first on its own line" contract). A \connect inside
			// the comment body was already consumed by the skip.
			lineStart = false
			i = skipBlockComment(script, i, true)
		case c == '\\' && lineStart:
			// A psql meta-command occupies its own line, backslash first.
			eol := i
			for eol < n && script[eol] != '\n' {
				eol++
			}
			db, ok, err := ParseConnectLine(script[i:eol])
			if err != nil {
				return nil, err
			}
			if ok {
				flush(i)
				cur, segStart = db, eol // the marker line itself is consumed
				i = eol
				continue
			}
			lineStart = false
			i++
		default:
			lineStart = false
			i++
		}
	}
	flush(n)
	if overflow {
		// Nothing partial: a prefix of a restore is a half-applied restore.
		return nil, ErrTooManyStatements
	}
	return sections, nil
}

// ParseConnectLine recognizes a `\connect dbname` / `\c dbname` line and
// extracts the database name with psql's tokenization: the name ends at the
// first unquoted whitespace (trailing username/host/port arguments are
// ignored), double-quoted segments may embed doubled quotes and concatenate
// with adjacent unquoted text, and an unterminated quote is an error — psql
// would not read it as a name, so silently targeting a mangled one is worse
// than failing the import.
func ParseConnectLine(line string) (db string, ok bool, err error) {
	s := strings.TrimSpace(line)
	var rest string
	switch {
	case strings.HasPrefix(s, `\connect`):
		rest = s[len(`\connect`):]
	case strings.HasPrefix(s, `\c`):
		rest = s[len(`\c`):]
	default:
		return "", false, nil
	}
	// The prefix must be the whole command word: `\cd x` is not `\c d x`.
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return "", false, nil
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false, nil
	}
	name, err := parseConnectTarget(rest)
	if err != nil {
		return "", false, fmt.Errorf("%v (in %q)", err, s)
	}
	if name == "" {
		return "", false, nil
	}
	return name, true, nil
}

// parseConnectTarget reads the first psql-tokenized argument of rest: unquoted
// runs end at whitespace, "…" runs may embed "" and splice with adjacent text.
func parseConnectTarget(rest string) (string, error) {
	runes := []rune(rest)
	var name strings.Builder
	for i := 0; i < len(runes); {
		switch c := runes[i]; c {
		case '"':
			closed := false
			for i++; i < len(runes); i++ {
				if runes[i] == '"' {
					if i+1 < len(runes) && runes[i+1] == '"' {
						name.WriteRune('"')
						i++
						continue
					}
					i++
					closed = true
					break
				}
				name.WriteRune(runes[i])
			}
			if !closed {
				return "", errors.New(`unterminated quoted name in \connect`)
			}
		case ' ', '\t', '\r':
			return name.String(), nil
		default:
			name.WriteRune(c)
			i++
		}
	}
	return name.String(), nil
}
