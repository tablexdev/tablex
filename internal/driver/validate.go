package driver

// Input validators and SQL-fragment builders: the pure functions that decide
// what may be built into a statement at all. They take no Connection — they
// guard the INPUT (a new identifier, an account spelling, a privilege keyword,
// a create-table shape) before any of it reaches a dialect builder, which is
// why they live apart from the connection behaviour in connection.go. Split by
// role; the file-size ratchet keeps it that way.

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ValidNewIdentifier reports whether s is acceptable as the name of an object
// being CREATED or RENAMED-to (table, database, column, index, constraint).
// It is deliberately permissive: names with spaces, hyphens, dots, leading
// digits or non-Latin scripts are legal in every supported engine and already
// browsable/editable in TableX — refusing to create them was an asymmetry, not
// a protection, since QuoteIdent makes them safe. It still rejects what could
// only be an injection attempt or an unusable name: empty/blank or space-padded
// names, control bytes, quote characters, backslashes, semicolons, and a
// length beyond the engine's own limit. The length rule is dialect-aware in
// both its size and its UNIT — PostgreSQL counts bytes (caps.IdentifierMaxBytes;
// it silently truncates a >63-byte identifier, so validate-first prevents
// creating the object under a truncated name) while MySQL/MariaDB counts
// characters (caps.IdentifierMaxChars) and raises a clean error. Measuring
// MySQL's limit in bytes would refuse a 22-character CJK name it accepts
// happily, recreating the create-vs-browse asymmetry described above. Callers
// must still quote via QuoteIdent.
//
// Do NOT use safeSortColumn for this: its contract assumes the name was
// already matched against live introspection, which a new name never is.
func ValidNewIdentifier(caps Capabilities, s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	if caps.IdentifierMaxBytes > 0 && len(s) > caps.IdentifierMaxBytes {
		return false
	}
	if caps.IdentifierMaxChars > 0 && utf8.RuneCountInString(s) > caps.IdentifierMaxChars {
		return false
	}
	return !HasUnsafeIdentifierRune(s)
}

// HasUnsafeIdentifierRune reports whether s contains a rune no
// identifier-shaped input may carry: control characters INCLUDING DEL (0x7f),
// quote characters, backtick, semicolon, or backslash. It is the single
// reject set behind ValidNewIdentifier, the handlers' account-name validator
// and safeSortColumn.
//
// Unifying on one set was a deliberate hardening, not behavior-neutral: sort
// columns previously accepted DEL and now reject it (a column literally named
// with a 0x7f byte loses sortability — an acceptable trade for one shared,
// strictest-common reject set).
func HasUnsafeIdentifierRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '`' || r == ';' || r == '\\' {
			return true
		}
	}
	return false
}

// ValidPrivilegeKeyword reports whether s has the shape of a SQL privilege
// keyword: uppercase A–Z words separated by single spaces, at most 32 bytes
// ("SELECT", "ALL PRIVILEGES", "CREATE TEMPORARY TABLES"). It is the
// defence-in-depth gate on the introspection-driven revoke path (and on MySQL
// *_PRIVILEGES strings) — membership in the displayed grants or the grant
// allowlist is the primary check; this guarantees that whatever passed it can
// only ever be a keyword, never an injection fragment.
func ValidPrivilegeKeyword(s string) bool {
	if s == "" || len(s) > 32 || s[0] == ' ' || s[len(s)-1] == ' ' {
		return false
	}
	prevSpace := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			prevSpace = false
		case c == ' ':
			if prevSpace {
				return false
			}
			prevSpace = true
		default:
			return false
		}
	}
	return true
}

// SplitAccount parses a "user@host" (or "'user'@'host'") account string on the
// LAST "@": the host is the substring after the final @, since user names may
// themselves contain @. Each part is trimmed of surrounding ' ` " quote
// characters (strings.Trim strips any run of them, not just one). This is the
// handler-facing account decoder, shared so handlers need not
// import a concrete dialect. It decodes the account <select> value (built from
// an already-decoded model.User Name@Host) and the server-reported
// CURRENT_USER() string — NEITHER of which uses information_schema's
// doubled-quote escaping. It therefore deliberately does NOT collapse doubled
// quotes; the mysql dialect's internal splitGrantee is the companion variant
// that DOES, because it decodes raw information_schema.*_PRIVILEGES grantees.
func SplitAccount(s string) (user, host string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return strings.Trim(s[:i], "'`\""), strings.Trim(s[i+1:], "'`\"")
	}
	return strings.Trim(s, "'`\""), ""
}

// ValidateCreateTable applies the CreateTableSQL contract checks shared by all
// engines: at least one column, no duplicate column names, and every PRIMARY
// KEY entry present among the columns.
func ValidateCreateTable(cols []ColumnSpec, pk []string) error {
	if len(cols) == 0 {
		return errors.New("a table needs at least one column")
	}
	names := make(map[string]bool, len(cols))
	for _, c := range cols {
		if names[c.Name] {
			return fmt.Errorf("duplicate column name %q", c.Name)
		}
		names[c.Name] = true
	}
	for _, p := range pk {
		if !names[p] {
			return fmt.Errorf("primary-key column %q is not among the columns", p)
		}
	}
	return nil
}

// NormalizePrivileges trims and upper-cases submitted privilege keywords and
// re-validates each with check before a dialect emits them verbatim. Shared by
// the GrantSQL builders (check = allowlist membership) and RevokeSQL builders
// (check = ValidPrivilegeKeyword).
func NormalizePrivileges(privs []string, check func(string) bool) ([]string, error) {
	if len(privs) == 0 {
		return nil, errors.New("no privileges specified")
	}
	out := make([]string, len(privs))
	for i, p := range privs {
		p = strings.ToUpper(strings.TrimSpace(p))
		if !check(p) {
			return nil, fmt.Errorf("invalid privilege %q", p)
		}
		out[i] = p
	}
	return out, nil
}

// PrivilegeList renders the privilege list of a GRANT or REVOKE. With no
// columns it is the bare comma-joined keywords; with columns each keyword
// carries the SAME parenthesised column list — "SELECT (a, b), UPDATE (a, b)"
// — which is the MySQL and PostgreSQL grammar both engines share, so the two
// dialects need not each re-derive it.
//
// privs must already have passed NormalizePrivileges and cols must already have
// been matched against introspection; quote is the dialect's QuoteIdent. cols
// is emitted in the caller's order, which is the introspected column order, so
// two identical grants produce byte-identical SQL.
func PrivilegeList(privs, cols []string, quote func(string) string) string {
	if len(cols) == 0 {
		return strings.Join(privs, ", ")
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = quote(c)
	}
	list := " (" + strings.Join(quoted, ", ") + ")"
	out := make([]string, len(privs))
	for i, p := range privs {
		out[i] = p + list
	}
	return strings.Join(out, ", ")
}

// safeSortColumn is a defensive check for a sort column before it is quoted into
// generated SQL. It is deliberately loose — callers have already matched the
// name against live introspection, and QuoteIdent safely quotes arbitrary names
// — so it accepts real-world columns with spaces, leading digits or hyphens,
// while still rejecting characters that signal an injection attempt (the
// shared HasUnsafeIdentifierRune set — which newly rejects DEL here, see its
// doc).
func safeSortColumn(s string) bool {
	return s != "" && !HasUnsafeIdentifierRune(s)
}
