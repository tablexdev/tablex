package mysql

// The flavor-aware DEFAULT classification: how a COLUMN_DEFAULT value is
// decoded into a literal, an expression or the explicit NULL keyword, and the
// MariaDB string-literal grammar that decoding depends on. Split from
// introspect.go by role (the file-size ratchet keeps it that way).

import (
	"context"
	"database/sql"
	"strings"
)

// mysqlDefaultKind classifies a column's COLUMN_DEFAULT into the value to
// store, whether it is an expression (so the editor keeps it verbatim and
// parenthesizes it, instead of re-quoting it into a string literal), and
// whether it is the explicit keyword NULL (DEFAULT NULL) — kept distinct from
// the literal string 'NULL' so a modify round-trip cannot silently rewrite
// one into the other.
//
// The two flavors disagree: MySQL 8 marks every expression default
// (CURRENT_TIMESTAMP, (uuid()), …) with DEFAULT_GENERATED in EXTRA and stores
// literal string defaults unquoted; an explicit MySQL DEFAULT NULL arrives as
// SQL NULL (the caller's def.Valid guard, indistinguishable from — and
// semantically equivalent to — no default), so isNull is never true there and
// the 4-char string "NULL" is a literal. MariaDB has no marker but renders
// literal string defaults in COLUMN_DEFAULT as a QUOTED STRING LITERAL in the
// server's own grammar (expressions stay unquoted) and an explicit DEFAULT
// NULL as the bare keyword NULL. So on MariaDB a quoted value is a literal —
// decoded through the full literal grammar by unescapeMariaDBLiteral, in the
// session's escape mode, so a modify round-trip re-quotes the same bytes the
// writer (QuoteString) emitted rather than compounding an escape per Save —
// the bare NULL keyword is the explicit null default, and anything else
// unquoted is an expression.
func mysqlDefaultKind(mariadb, noBackslashEscapes bool, def sql.NullString, extra string) (value string, isExpr, isNull bool) {
	v := def.String
	if strings.Contains(strings.ToUpper(extra), "DEFAULT_GENERATED") {
		return v, true, false // MySQL 8 expression default, carried verbatim
	}
	if mariadb {
		if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
			return unescapeMariaDBLiteral(v[1:len(v)-1], noBackslashEscapes), false, false // quoted literal
		}
		if strings.EqualFold(v, "NULL") {
			return v, false, true // explicit DEFAULT NULL (keyword)
		}
		return v, true, false // unquoted, non-NULL → expression
	}
	return v, false, false // MySQL literal (stored unquoted, no marker)
}

// unescapeMariaDBLiteral decodes the BODY of a MariaDB quoted string literal
// (the text between COLUMN_DEFAULT's outer quotes) into the raw value. MariaDB
// renders a literal default back through its string-literal grammar, so the
// reader must invert BOTH escape forms the writer (QuoteString) can emit:
// a doubled quote and — outside NO_BACKSLASH_ESCAPES — the backslash
// escapes \0 \' \" \b \n \r \t \Z \\. Collapsing only the doubled quote left the display
// wrong by one backslash escape, and every column-modify Save re-quoted the
// displayed text, adding another. Two carve-outs from the server's own
// grammar: \% and \_ KEEP their backslash (they exist for LIKE patterns; a
// string literal preserves them verbatim), and an unknown escape yields the
// escaped character itself. Under NO_BACKSLASH_ESCAPES a backslash is an
// ordinary character, so only quote collapsing applies — the same mode split
// the writer makes.
func unescapeMariaDBLiteral(body string, noBackslashEscapes bool) string {
	if noBackslashEscapes {
		return strings.ReplaceAll(body, "''", "'")
	}
	var b strings.Builder
	b.Grow(len(body))
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\'' && i+1 < len(body) && body[i+1] == '\'':
			b.WriteByte('\'')
			i++
		case c == '\\' && i+1 < len(body):
			i++
			switch e := body[i]; e {
			case '0':
				b.WriteByte(0)
			case 'b':
				b.WriteByte('\b')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'Z':
				b.WriteByte(0x1a)
			case '%', '_':
				// LIKE-pattern escapes: the literal keeps the backslash.
				b.WriteByte('\\')
				b.WriteByte(e)
			default:
				// \' \" \\ and every unknown escape: the character itself.
				b.WriteByte(e)
			}
		default:
			// Ordinary byte — including a trailing lone backslash, which a
			// well-formed literal cannot end with but must not be dropped.
			b.WriteByte(c)
		}
	}
	return b.String()
}

// isMariaDB reports whether the server is MariaDB via a VERSION() probe. It is a
// FALLBACK used only when the flavor wasn't threaded from ServerInfo via the
// context (Connection.Columns threads it, so the normal path skips this query).
// A VERSION() failure falls back to false — the MySQL marker-only
// classification — rather than failing Columns over this extra metadata.
func isMariaDB(ctx context.Context, db *sql.DB) bool {
	var version string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(version), "mariadb")
}
