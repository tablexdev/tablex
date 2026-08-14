// Package sqlscript lexes and splits SQL scripts.
//
// The console and the importer both need to break an uploaded or typed script
// into statements, and doing that correctly means a full quote/comment-aware
// lexer: string escapes, dollar quoting, bracket identifiers, DELIMITER
// directives, TableX's opaque frames and procedural BEGIN…END bodies. That is
// ~800 lines of pure text processing which lived inside the HTTP handler
// package, importing nothing from net/http.
//
// The grammar itself is not defined here: it comes from the dialect, as a
// driver.LexerProfile, so the splitter never branches on an engine name.
package sqlscript

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/driver"
)

// Event is one item of a scanned script, in source order: an executable
// statement (marker == nil), or a validated TableX db-collation marker the
// import path surfaces as a warning check. The console path ignores markers.
type Event struct {
	Stmt   string
	Marker *driver.DumpMarker
}

// ErrTooManyStatements is returned by ScanLimit/SplitLimit/SplitRestoreSections
// when a script would produce more events than the caller allowed. It is a
// distinct error so a caller can tell a refused-by-policy script from a lexer
// state, and it is returned INSTEAD of a partial result: a truncated script
// executes a prefix, which for an import means committing half a restore — worse
// than the exhaustion the cap exists to prevent.
var ErrTooManyStatements = errors.New("sqlscript: too many statements")

// Split splits a SQL script into individual statements on top-level
// statement separators, dropping marker events (see Scan).
func Split(script string, p driver.LexerProfile) []string {
	out, _ := SplitLimit(script, p, 0)
	return out
}

// SplitLimit is Split with a cap on the number of events the script may
// produce. max <= 0 means no cap, matching every other cap in the config.
func SplitLimit(script string, p driver.LexerProfile, max int) ([]string, error) {
	events, err := ScanLimit(script, p, max)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(events))
	for _, ev := range events {
		if ev.Marker == nil {
			out = append(out, ev.Stmt)
		}
	}
	return out, nil
}

// Scan tokenizes a SQL script into executable statements plus validated
// TableX marker events, in source order. Lexing is grammar-driven via the
// dialect's driver.LexerProfile:
//
//   - single/double/backtick quoted strings with doubled-quote escapes (all
//     engines), plus backslash escapes inside '...' / "..." strings where the
//     profile says so (MySQL) and inside E'…' escape strings (PostgreSQL);
//   - `--` and /* */ comments; `#` line comments and the "-- must be followed
//     by whitespace" rule are profile-gated (MySQL);
//   - dollar-quoted strings ($$...$$ / $tag$...$tag$) where enabled
//     (PostgreSQL) — `$` is an ordinary identifier character in MySQL and
//     SQLite (a$$b must not open a quote);
//   - mysql-client `DELIMITER` directives, so dumped routine/trigger bodies
//     round-trip exactly as the mysql CLI would run them. Ordinary DELIMITER
//     blocks keep full quote-aware lexing — an uploaded script may legally
//     carry its delimiter inside a string literal ('a//b' under DELIMITER //);
//   - TableX opaque frames (a frame marker line + DELIMITER wrap around a
//     binary-fetched object body): the framed bytes are replayed VERBATIM as
//     one statement with no string/comment interpretation and no re-encoding —
//     the body may be non-UTF-8 or authored under NO_BACKSLASH_ESCAPES, where
//     ordinary lexing would mis-split. Opacity is keyed strictly on TableX's
//     own marker, never on "any non-default delimiter";
//   - BEGIN...END procedural bodies of routine-creating statements (profile
//     regex), so the semicolons inside a trigger or routine body do not split
//     the statement;
//   - chunks containing only comments are dropped: they execute as nothing,
//     and some drivers (modernc.org/sqlite) return a nil result for them.
//
// Statements are emitted as trimmed spans of the ORIGINAL script bytes —
// lexing tracks byte offsets, never a rune rebuild, so invalid UTF-8 passes
// through unreplaced (no U+FFFD substitution).
func Scan(script string, p driver.LexerProfile) []Event {
	out, _ := ScanLimit(script, p, 0)
	return out
}

// ScanLimit is Scan with a cap on how many events the script may produce, so a
// pathological body cannot be materialized in full before anything runs. Scan
// builds the WHOLE slice up front, and the realistic worst case is a script of
// bare `a;` — 128 MiB of that is ~67 million events at 24 bytes each, ~1.6 GB
// before append growth, and a Go allocation failure is not something the panic
// middleware can recover.
//
// It FAILS rather than truncating: see ErrTooManyStatements. The limit is a
// PARAMETER rather than a config read because this package imports nothing but
// strings, unicode and internal/driver — that import list is what keeps it free
// of both net/http and config — so the caller threads it in beside the profile.
//
// max <= 0 means no cap.
func ScanLimit(script string, p driver.LexerProfile, max int) ([]Event, error) {
	return scanCapped(script, p, max, false)
}

// EventBudget is one aggregate scanner-event cap shared across several scans.
// The import preflight lexes EVERY restore section of a script under one
// MaxScriptStatements budget before anything executes — a per-section cap
// cannot do that job, because the executing loop commits earlier sections as
// it goes, so an over-limit later section would abort a HALF-APPLIED restore.
// A caller-maintained remaining counter has two failure modes this type
// exists to remove: a remainder of exactly 0 fed back into SplitLimit means
// "no cap" (the preflight would disable itself at the boundary, and every
// later section with it), and decrementing by a statement count undercounts
// scripts whose events include markers — ScanLimit's cap counts EVENTS.
type EventBudget struct {
	remaining int
	capped    bool
}

// NewEventBudget returns a budget of max events; max <= 0 means no cap,
// matching the package's other entry points.
func NewEventBudget(max int) *EventBudget {
	return &EventBudget{remaining: max, capped: max > 0}
}

// Consume lexes script against the remaining budget and decrements it by the
// script's event count. It returns ErrTooManyStatements as soon as the script
// would push the aggregate past the cap — including on an EXHAUSTED budget,
// where any event at all overflows (only a script lexing to nothing passes).
func (b *EventBudget) Consume(script string, p driver.LexerProfile) error {
	if !b.capped {
		return nil
	}
	events, err := scanCapped(script, p, b.remaining, true)
	if err != nil {
		return err
	}
	b.remaining -= len(events)
	return nil
}

// scanCapped is ScanLimit's implementation. strict repurposes max as a hard
// REMAINING budget for EventBudget: 0 means exhausted (the first event
// overflows) instead of the public entry points' "no cap" sentinel.
func scanCapped(script string, p driver.LexerProfile, max int, strict bool) ([]Event, error) {
	var out []Event
	n := len(script)
	// Counted at the APPEND, not per statement: frame bodies and collation
	// markers consume entries too, and a script of nothing but markers would
	// otherwise be uncapped.
	overflow := false
	emit := func(ev Event) {
		if (max > 0 || (strict && max == 0)) && len(out) >= max {
			overflow = true
			return
		}
		out = append(out, ev)
	}

	delim := ";"
	start := 0          // byte offset where the current statement span begins
	depth := 0          // BEGIN/CASE nesting inside a routine body
	pendingEnd := false // saw an END token; the next token classifies it
	routineKnown := false
	inRoutine := false
	hasContent := false // statement has non-comment, non-whitespace content
	wordStart := -1

	flush := func(end int) {
		s := strings.TrimSpace(script[start:end])
		depth, pendingEnd, routineKnown, inRoutine, hasContent = 0, false, false, false, false
		if s == "" || stripLeadingComments(s, p) == "" {
			return
		}
		emit(Event{Stmt: s})
	}

	// token updates the procedural-block state for a completed word ending at
	// end (so the routine matcher sees the statement span including the word).
	token := func(word string, end int) {
		if p.RoutineBodyRe == nil || word == "" {
			return
		}
		up := strings.ToUpper(word)
		if pendingEnd {
			pendingEnd = false
			switch up {
			case "IF", "LOOP", "WHILE", "REPEAT":
				// END IF / END LOOP / END WHILE / END REPEAT terminate compounds
				// whose openers are not counted; no depth change, and the keyword
				// itself opens nothing.
				return
			case "CASE":
				if depth > 0 {
					depth-- // END CASE closes a counted CASE
				}
				return
			default:
				if depth > 0 {
					depth-- // bare END closes a BEGIN block or an expression CASE
				}
			}
		}
		switch up {
		case "BEGIN", "CASE":
			// Count block openers only inside routine-creating statements, so a
			// top-level BEGIN (transaction) or CASE in a plain SELECT is untouched.
			if !routineKnown {
				inRoutine = p.RoutineBodyRe.MatchString(stripLeadingComments(strings.TrimSpace(script[start:end]), p))
				routineKnown = true
			}
			if inRoutine {
				depth++
			}
		case "END":
			if depth > 0 {
				pendingEnd = true
			}
		}
	}

	endWord := func(end int) {
		if wordStart >= 0 {
			token(script[wordStart:end], end)
			wordStart = -1
		}
	}

	for i := 0; i < n && !overflow; {
		// An active custom delimiter replaces ';' as the only separator.
		if delim != ";" && strings.HasPrefix(script[i:], delim) {
			endWord(i)
			flush(i)
			i += len(delim)
			start = i
			continue
		}

		// A client-side batch separator (T-SQL "GO") on a line of its own ends
		// the statement and is itself never sent to the server. Only at depth 0:
		// an engine with batches cannot have one inside a routine body, and this
		// keeps a column named GO inside a BEGIN…END block from terminating it.
		if p.BatchSeparator != "" && depth == 0 && (i == 0 || script[i-1] == '\n') {
			if line, eol := scriptLine(script, i); strings.EqualFold(strings.TrimSpace(line), p.BatchSeparator) {
				endWord(i)
				flush(i)
				if eol < n {
					eol++ // consume the newline too
				}
				i = eol
				start = i
				continue
			}
		}

		c, size := decodeRune(script, i)

		if isWordRune(c, p.DollarInWords) {
			if wordStart < 0 {
				// mysql-client DELIMITER directive: only recognized as the first
				// word of a statement; consumes the rest of its line.
				if p.DelimiterDirectives && !hasContent && hasWordAt(script, i, "DELIMITER") {
					j := i + len("DELIMITER")
					for j < n && (script[j] == ' ' || script[j] == '\t') {
						j++
					}
					// The delimiter is the FIRST whitespace-terminated (or quoted)
					// token, matching the mysql client — `DELIMITER $$ -- x` sets $$,
					// never the whole rest of the line.
					var nd string
					if j < n && (script[j] == '\'' || script[j] == '"' || script[j] == '`') {
						q := script[j]
						k := j + 1
						for k < n && script[k] != q && script[k] != '\n' {
							k++
						}
						if k < n && script[k] == q {
							nd = script[j+1 : k]
						}
					} else {
						k := j
						for k < n {
							r, rs := decodeRune(script, k)
							if unicode.IsSpace(r) {
								break
							}
							k += rs
						}
						nd = script[j:k]
					}
					for j < n && script[j] != '\n' {
						j++ // the directive (and any trailing junk) consumes its line
					}
					if nd != "" {
						delim = nd
					}
					if j < n {
						j++ // skip the newline
					}
					// Anything buffered before the directive is client-side, not SQL.
					i = j
					start = i
					continue
				}
				wordStart = i
			}
			hasContent = true
			i += size
			continue
		}
		endWord(i)

		switch c {
		case '\'', '"', '`':
			hasContent = true
			// Backslash escapes the next character inside MySQL string literals
			// ('...' and "..." but not backtick identifiers) and inside a
			// PostgreSQL E'…' escape-string literal.
			backslash := (p.BackslashStrings && c != '`') || (p.EscapeStringE && c == '\'' && isEscStringQuote(script, i))
			i = skipStringLiteral(script, i, backslash)
		case '-':
			// `--` line comment. MySQL requires whitespace (or EOL) right after the
			// `--`, so `a--b` stays an expression there; PostgreSQL/SQLite always
			// treat `--` as a comment.
			if i+1 < n && script[i+1] == '-' && dashIsComment(script, i, p) {
				// TableX marker recognition happens BEFORE comment elision, and
				// only for an exact marker line sitting between statements (own
				// line, no statement content yet, default delimiter, outside any
				// routine body) — marker-like text inside statements, strings,
				// block comments or opaque frames is never an event.
				if !hasContent && depth == 0 && delim == ";" && (i == 0 || script[i-1] == '\n') {
					line, eol := scriptLine(script, i)
					if p.DelimiterDirectives {
						if fd, ok := driver.ParseFrameMarker(line); ok {
							if body, next, ok := consumeFrame(script, eol, fd); ok {
								flush(i) // at most comment-only content — discarded
								if body != "" {
									// Verbatim frame bytes: deliberately NOT trimmed.
									emit(Event{Stmt: body})
								}
								i = next
								start = i
								continue
							}
							// Malformed frame (no DELIMITER line): fall through — the
							// marker stays an ordinary comment and any following
							// DELIMITER directive gets ordinary quote-aware lexing.
						}
					}
					if m, ok := driver.ParseCollationMarker(line); ok {
						// Emit the event; the line itself stays in place as an
						// inert comment.
						emit(Event{Marker: &m})
					}
				}
				for i < n && script[i] != '\n' {
					i++
				}
				if i < n {
					i++ // keep the newline: it terminates the comment
				}
			} else {
				hasContent = true
				i += size
			}
		case '$':
			// PostgreSQL dollar-quoting: skip the body verbatim so its semicolons
			// are not treated as separators. A bare '$' (e.g. the $1 placeholder)
			// falls through to ordinary handling.
			hasContent = true
			if !p.DollarQuotes {
				i += size
				break
			}
			end, ok := skipDollarQuoted(script, i)
			if !ok {
				i += size
				break
			}
			i = end
		case '[':
			// [bracket-quoted identifier] (T-SQL, and SQLite's Access-compatible
			// form). Where the profile does not enable it, '[' is an operator
			// character (PostgreSQL array subscripts) and falls through.
			hasContent = true
			if !p.BracketIdentifiers {
				i += size
				break
			}
			end, ok := skipBracketIdent(script, i)
			if !ok {
				i += size
				break
			}
			i = end
		case '#':
			// `#` is a line comment only in MySQL; elsewhere it is an operator
			// character (e.g. PostgreSQL's `#>` / `#-` JSON operators).
			if p.HashComments {
				for i < n && script[i] != '\n' {
					i++
				}
				if i < n {
					i++ // keep the newline: it terminates the comment
				}
			} else {
				hasContent = true
				i += size
			}
		case '/':
			if i+1 < n && script[i+1] == '*' {
				i = skipBlockComment(script, i, p.NestedBlockComments)
			} else {
				hasContent = true
				i += size
			}
		case ';':
			if delim != ";" {
				hasContent = true
				i += size
				break
			}
			if pendingEnd {
				pendingEnd = false
				if depth > 0 {
					depth--
				}
			}
			if depth > 0 {
				// A separator inside a routine body belongs to the body.
				hasContent = true
				i += size
				break
			}
			flush(i)
			i += size
			start = i
		default:
			if !unicode.IsSpace(c) {
				hasContent = true
			}
			i += size
		}
	}
	endWord(n)
	flush(n)
	if overflow {
		return nil, ErrTooManyStatements
	}
	return out, nil
}

// scriptLine returns the line beginning at i — without its terminating
// newline, and with a single trailing '\r' stripped so CRLF input still
// parses — plus the index of the terminating '\n' (len(script) when the line
// runs to EOF).
func scriptLine(script string, i int) (string, int) {
	eol := strings.IndexByte(script[i:], '\n')
	if eol < 0 {
		return strings.TrimSuffix(script[i:], "\r"), len(script)
	}
	eol += i
	return strings.TrimSuffix(script[i:eol], "\r"), eol
}

// consumeFrame parses a TableX opaque frame whose marker line ends at eol:
//
//	-- tablex:v1 frame delimiter=<tok>
//	DELIMITER <tok>
//	<raw body bytes>
//	<tok>
//	DELIMITER ;
//
// The body is returned VERBATIM — no trimming, no string/comment
// interpretation, no re-encoding — which is the frame's whole point: the
// bytes may be non-UTF-8 or authored under NO_BACKSLASH_ESCAPES, where
// ordinary lexing would mangle or mis-split them. The terminator matches as
// an exact line (the dump always emits it on its own line, so a body merely
// ending in a token prefix cannot splice into it). ok is false when the
// mandatory DELIMITER line is missing — the caller then degrades to ordinary
// comment/directive lexing. next is the offset just past the terminator line;
// the trailing `DELIMITER ;` is left to the ordinary directive handler (a
// no-op reset). A frame with no terminator (truncated dump) yields the
// remaining bytes so the truncation fails loudly on execution instead of
// vanishing.
func consumeFrame(script string, eol int, tok string) (body string, next int, ok bool) {
	if eol >= len(script) {
		return "", 0, false // marker at EOF: no frame content
	}
	line, lineEnd := scriptLine(script, eol+1)
	if line != "DELIMITER "+tok {
		return "", 0, false
	}
	if lineEnd >= len(script) {
		return "", len(script), true // empty, unterminated frame
	}
	bodyStart := lineEnd + 1
	at := bodyStart
	for {
		line, lineEnd = scriptLine(script, at)
		if line == tok {
			if at > bodyStart {
				body = script[bodyStart : at-1] // exclude the newline before the terminator
			}
			if lineEnd < len(script) {
				return body, lineEnd + 1, true
			}
			return body, len(script), true
		}
		if lineEnd >= len(script) {
			return script[bodyStart:], len(script), true
		}
		at = lineEnd + 1
	}
}

// decodeRune returns the rune starting at s[i] and its byte width. Invalid
// UTF-8 decodes to RuneError with width 1 and classifies as ordinary non-word
// content; the bytes themselves are never rewritten, so they reach the
// emitted statement verbatim.
func decodeRune(s string, i int) (rune, int) {
	if c := s[i]; c < utf8.RuneSelf {
		return rune(c), 1
	}
	return utf8.DecodeRuneInString(s[i:])
}

// isWordRune reports whether c can be part of a bare SQL word (identifier or
// keyword). `$` counts as a word character only when withDollar is set (MySQL
// and SQLite, where it is an identifier character); in dollar-quoting engines
// it must stay special so the '$' switch case can detect dollar quoting.
func isWordRune(c rune, withDollar bool) bool {
	return c == '_' || (withDollar && c == '$') || unicode.IsLetter(c) || unicode.IsDigit(c)
}

// hasWordAt reports whether the ASCII word occurs case-insensitively at s[i]
// followed by a non-word rune (or end of input). Only used for the MySQL
// DELIMITER directive, so word runes include '$'.
func hasWordAt(s string, i int, word string) bool {
	if i+len(word) > len(s) {
		return false
	}
	for k := 0; k < len(word); k++ {
		c := s[i+k]
		if c != word[k] && c != word[k]+('a'-'A') {
			return false
		}
	}
	if i+len(word) == len(s) {
		return true
	}
	r, _ := decodeRune(s, i+len(word))
	return !isWordRune(r, true)
}

// dashIsComment reports whether a `--` at s[i] starts a comment. MySQL
// requires the `--` to be followed by whitespace or end-of-line; other engines
// treat any `--` as a comment.
func dashIsComment(s string, i int, p driver.LexerProfile) bool {
	if !p.DashCommentNeedsSpace {
		return true
	}
	j := i + 2
	if j >= len(s) {
		return true
	}
	switch s[j] {
	case ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

// isEscStringQuote reports whether the quote at s[i] opens a PostgreSQL E'…'
// escape-string literal: immediately preceded by a lone E/e word token. The
// token-boundary check keeps an identifier that merely ends in e (as in
// TABLE une'…') on plain-string semantics. Callers gate on the profile.
func isEscStringQuote(s string, i int) bool {
	if i < 1 || (s[i-1] != 'E' && s[i-1] != 'e') {
		return false
	}
	r, size := utf8.DecodeLastRuneInString(s[:i-1])
	if size == 0 {
		return true // the E is the first character
	}
	return !isWordRune(r, false)
}

// skipStringLiteral returns the index just past the closing quote of the
// string literal whose opening quote is at s[i] (or len(s) when
// unterminated). Doubled closing quotes always escape; backslashEsc adds
// \-escapes (MySQL '…'/"…" and PostgreSQL E'…', where both forms coexist).
// Byte scanning is safe: quote and backslash are ASCII, and a multi-byte
// rune's continuation bytes (0x80+) can never match them.
func skipStringLiteral(s string, i int, backslashEsc bool) int {
	quote := s[i]
	for i++; i < len(s); i++ {
		switch {
		case backslashEsc && s[i] == '\\':
			i++ // the escaped byte is literal content
		case s[i] == quote:
			if i+1 < len(s) && s[i+1] == quote {
				i++ // doubled-quote escape
				continue
			}
			return i + 1
		}
	}
	return len(s)
}

// skipBlockComment returns the index just past the closing */ of the block
// comment opening at s[i] (which must be "/*"), or len(s) when unterminated.
// nested counts inner /* … */ pairs (PostgreSQL block comments nest;
// MySQL/SQLite close at the first */). Pair-wise scanning keeps the
// degenerate "/*/" from being mistaken for a complete comment.
func skipBlockComment(s string, i int, nested bool) int {
	n := len(s)
	depth := 1
	for i += 2; i < n; {
		switch {
		case nested && s[i] == '/' && i+1 < n && s[i+1] == '*':
			i += 2
			depth++
		case s[i] == '*' && i+1 < n && s[i+1] == '/':
			i += 2
			depth--
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return n
}

// skipBracketIdent returns the index just past the closing ']' of the
// bracket-quoted identifier opening at s[i] (which is '['). A doubled ']]' is
// an escaped literal ']' and does not close the identifier.
//
// ok is false for an UNTERMINATED identifier, and the caller then treats the
// '[' as an ordinary character: a stray bracket in a malformed script must not
// swallow the rest of it into one statement, which would turn a syntax error
// into a silently truncated script.
func skipBracketIdent(s string, i int) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		if s[j] != ']' {
			continue
		}
		if j+1 < len(s) && s[j+1] == ']' {
			j++ // an escaped ]]; the loop's own j++ steps past the second
			continue
		}
		return j + 1, true
	}
	return 0, false
}

// skipDollarQuoted returns the index just past the closing $tag$ of the
// dollar-quoted literal opening at s[i] (len(s) when unterminated), or
// ok=false when s[i] does not open one (e.g. a $1 placeholder).
func skipDollarQuoted(s string, i int) (int, bool) {
	tag, ok := dollarTag(s, i)
	if !ok {
		return i, false
	}
	if j := strings.Index(s[i+len(tag):], tag); j >= 0 {
		return i + len(tag) + j + len(tag), true
	}
	return len(s), true
}

// dollarTag returns the dollar-quote opening delimiter ($tag$, with an optional
// identifier-shaped tag) starting at s[i], or ok=false when s[i] is a plain
// '$' (such as a $1 positional placeholder, which has no closing '$').
func dollarTag(s string, i int) (string, bool) {
	for j := i + 1; j < len(s); {
		r, size := decodeRune(s, j)
		if r == '$' {
			return s[i : j+1], true
		}
		if r == '_' || unicode.IsLetter(r) || (j > i+1 && unicode.IsDigit(r)) {
			j += size
			continue
		}
		return "", false
	}
	return "", false
}

// queryKeywords are leading keywords that produce a result set (vs. affecting
// rows). Used to decide between Query and Exec in the console.
var queryKeywords = map[string]bool{
	"SELECT": true, "WITH": true, "SHOW": true, "EXPLAIN": true,
	"PRAGMA": true, "DESCRIBE": true, "DESC": true, "VALUES": true, "TABLE": true,
}

// returningDenySet holds the tokens that, when they immediately precede a
// `returning` token, mark it as an identifier (a column/table/alias/CTE name)
// rather than the RETURNING clause keyword. Kept deliberately minimal: growing
// it converts documented false positives (a bare `returning` in an expression,
// e.g. `SET a = returning`) into false negatives (a genuine clause whose
// predecessor is a keyword, e.g. `… WHERE a AND 'x' RETURNING id`, where the
// blanked literal leaves AND as the predecessor). Both directions are cosmetic —
// the statement always executes; only grid-vs-affected-count presentation can
// misroute. `,` and `.` are handled separately (they are single-byte tokens).
var returningDenySet = map[string]bool{
	"WITH": true, "FROM": true, "INTO": true, "UPDATE": true, "JOIN": true,
	"ONLY": true, "AS": true, "SET": true, "WHERE": true, "AND": true,
	"OR": true, "ON": true, "BY": true,
}

// IsQuery reports whether stmt should be run as a row-returning query
// (p is the dialect's lexer profile, as for Scan). Keywords are matched
// on a skeleton with string literals and comments blanked out, so a literal
// value like INSERT ... VALUES ('RETURNING') cannot mis-route the statement.
func IsQuery(stmt string, p driver.LexerProfile) bool {
	stmt = stripLeadingComments(strings.TrimSpace(stmt), p)
	if stmt == "" {
		return false
	}
	up := strings.ToUpper(stmtSkeleton(stmt, p))
	lead := leadingKeyword(up)
	// A genuine RETURNING clause yields rows even on INSERT/UPDATE/DELETE/MERGE,
	// but only where the engine+version supports it for that statement kind and
	// only when the token is a real clause (see hasReturningClause).
	if p.Returning.Allows(lead) && hasReturningClause(up) {
		return true
	}
	if lead == "WITH" {
		return true // unparseable WITH: keep the historical query default
	}
	return queryKeywords[lead]
}

// leadingKeyword returns the main-statement keyword an uppercased skeleton
// begins with, resolving a leading WITH to the first main-statement keyword the
// CTE list feeds (at paren depth 0). Returns "WITH" only when that resolution
// fails (an unparseable CTE).
func leadingKeyword(up string) string {
	// A statement may open with parentheses — (SELECT 1) UNION (SELECT 2) is a
	// plain query — and '(' doubles as a separator in the split below, so strip
	// leading parens (with any interleaved whitespace) from the LOCAL copy
	// first, or the keyword truncates to "" and the console runs the query
	// through Exec, throwing its rows away. up itself must stay untrimmed:
	// firstTopLevelKeyword's paren-depth counter needs the original skeleton.
	word := strings.TrimLeft(up, " \t\n\r(")
	if i := strings.IndexAny(word, " \t\n\r("); i >= 0 {
		word = word[:i]
	}
	if word == "WITH" {
		if kw := firstTopLevelKeyword(up); kw != "" {
			return kw
		}
		return "WITH"
	}
	return word
}

// hasReturningClause reports whether up (an uppercased skeleton) contains a
// genuine RETURNING clause: a RETURNING token at paren depth 0 whose immediately
// preceding significant token is not one that would make it an identifier.
// Parenthesized occurrences (a column list, ON CONFLICT target, subquery) sit at
// depth >= 1 and are excluded by the depth gate, not the deny set.
func hasReturningClause(up string) bool {
	depth := 0
	prev := "" // last significant token: a word, "(", ")", "," or "."
	for i := 0; i < len(up); {
		switch c := up[i]; {
		case c == '(':
			depth++
			prev = "("
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			prev = ")"
			i++
		case c == ',' || c == '.':
			prev = string(c)
			i++
		case c == '_' || c == '$' || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			j := i
			for j < len(up) && (up[j] == '_' || up[j] == '$' ||
				(up[j] >= 'A' && up[j] <= 'Z') || (up[j] >= '0' && up[j] <= '9')) {
				j++
			}
			w := up[i:j]
			if depth == 0 && w == "RETURNING" && !returningDenySet[prev] && prev != "," && prev != "." {
				return true
			}
			prev = w
			i = j
		default:
			i++ // whitespace / other punctuation is not a significant token
		}
	}
	return false
}

// mainStmtKeywords are the keywords that can begin the main statement a WITH
// clause feeds. Any other depth-0 token (CTE names, AS, MATERIALIZED, SEARCH/
// CYCLE clause words) is skipped by firstTopLevelKeyword.
var mainStmtKeywords = map[string]bool{
	"SELECT": true, "VALUES": true, "TABLE": true,
	"INSERT": true, "UPDATE": true, "DELETE": true, "MERGE": true, "REPLACE": true,
}

// firstTopLevelKeyword scans an uppercased statement skeleton for the first
// main-statement keyword at parenthesis depth 0. String literals and comments
// are already blanked (stmtSkeleton), so parens and words are real SQL tokens.
func firstTopLevelKeyword(up string) string {
	depth := 0
	for i := 0; i < len(up); {
		c := up[i]
		switch {
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth > 0 {
				depth--
			}
			i++
		case depth == 0 && (c == '_' || (c >= 'A' && c <= 'Z')):
			j := i
			for j < len(up) && (up[j] == '_' || up[j] == '$' ||
				(up[j] >= 'A' && up[j] <= 'Z') || (up[j] >= '0' && up[j] <= '9')) {
				j++
			}
			if w := up[i:j]; mainStmtKeywords[w] {
				return w
			}
			i = j
		default:
			i++
		}
	}
	return ""
}

// stmtSkeleton returns stmt with string-literal bodies and comments replaced by
// a single space, so keyword regexes only ever see real SQL tokens. Quote and
// comment rules follow the profile exactly as Scan does (backslash
// escapes and '#' comments in MySQL; dollar quotes, E'…' strings and nested
// block comments in PostgreSQL).
func stmtSkeleton(stmt string, p driver.LexerProfile) string {
	n := len(stmt)
	var b strings.Builder
	for i := 0; i < n; {
		c := stmt[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			backslash := (p.BackslashStrings && c != '`') || (p.EscapeStringE && c == '\'' && isEscStringQuote(stmt, i))
			i = skipStringLiteral(stmt, i, backslash)
			b.WriteByte(' ')
		case c == '$' && p.DollarQuotes:
			if end, ok := skipDollarQuoted(stmt, i); ok {
				i = end
				b.WriteByte(' ')
			} else {
				b.WriteByte(c)
				i++
			}
		case c == '-' && i+1 < n && stmt[i+1] == '-' && dashIsComment(stmt, i, p):
			for i < n && stmt[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case c == '#' && p.HashComments:
			for i < n && stmt[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
		case c == '/' && i+1 < n && stmt[i+1] == '*':
			i = skipBlockComment(stmt, i, p.NestedBlockComments)
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// stripLeadingComments removes any leading line/block comments so the first real
// keyword can be inspected. `#` comments and the "-- must be followed by
// whitespace" rule are profile-gated (MySQL, mirroring the main lexer);
// NestedBlockComments enables PostgreSQL nested block comments.
func stripLeadingComments(stmt string, p driver.LexerProfile) string {
	for {
		switch {
		case strings.HasPrefix(stmt, "--") && (!p.DashCommentNeedsSpace || len(stmt) == 2 ||
			stmt[2] == ' ' || stmt[2] == '\t' || stmt[2] == '\n' || stmt[2] == '\r'),
			p.HashComments && strings.HasPrefix(stmt, "#"):
			i := strings.IndexByte(stmt, '\n')
			if i < 0 {
				return ""
			}
			stmt = strings.TrimSpace(stmt[i+1:])
		case strings.HasPrefix(stmt, "/*"):
			// skipBlockComment is the one nested-aware scanner (shared with
			// stmtSkeleton); an unterminated comment yields len(stmt), so the
			// remainder is empty and the next iteration returns "".
			stmt = strings.TrimSpace(stmt[skipBlockComment(stmt, 0, p.NestedBlockComments):])
		default:
			return stmt
		}
	}
}
