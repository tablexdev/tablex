package driver

import "regexp"

// LexerProfile describes the statement-lexing grammar of an engine's SQL
// scripts. The handler-side statement splitter consumes it instead of
// branching on raw engine names, so an engine's script grammar lives with its
// dialect: string-escape rules, comment forms, dollar quoting, mysql-client
// DELIMITER directives and procedural BEGIN…END body tracking.
type LexerProfile struct {
	// BackslashStrings: a backslash escapes the next character inside '…' and
	// "…" string literals (MySQL default mode; never backtick identifiers).
	BackslashStrings bool
	// EscapeStringE: E'…' literals honor backslash escapes even though plain
	// '…' strings do not (PostgreSQL).
	EscapeStringE bool
	// DollarQuotes: $tag$…$tag$ dollar-quoted literals (PostgreSQL). Engines
	// where '$' is an identifier character must leave this off, or a$$b would
	// open a quote.
	DollarQuotes bool
	// HashComments: '#' starts a line comment (MySQL).
	HashComments bool
	// DashCommentNeedsSpace: a `--` line comment requires following whitespace
	// or end-of-line (MySQL); otherwise any `--` starts a comment.
	DashCommentNeedsSpace bool
	// NestedBlockComments: /* … */ block comments nest (PostgreSQL).
	NestedBlockComments bool
	// DelimiterDirectives: mysql-client DELIMITER directives are recognized,
	// including the TableX opaque frames dumped routine bodies travel in.
	DelimiterDirectives bool
	// DollarInWords: '$' is an ordinary identifier character (MySQL/SQLite).
	DollarInWords bool
	// BracketIdentifiers: [name] is a quoted identifier, with ]] escaping a
	// literal ']' — the T-SQL / Microsoft Access convention, which SQLite also
	// accepts. Engines where '[' is an operator (PostgreSQL array subscripts)
	// must leave this off. Without it a separator inside a bracket-quoted name
	// (`[a;b]`) splits the statement.
	BracketIdentifiers bool
	// BatchSeparator, when non-empty, is a CLIENT-SIDE batch terminator
	// recognized as the only content on its own line, case-insensitively —
	// T-SQL's `GO`. It ends the current statement the way the statement
	// separator does, but the word itself is never sent to the server. Empty
	// (every engine here today) means the engine has none.
	BatchSeparator string
	// RoutineBodyRe, when non-nil, matches routine-creating statements whose
	// BEGIN…END bodies hold internal semicolons, so the splitter tracks block
	// depth instead of splitting inside the body. Engines whose bodies are
	// quoted strings (PostgreSQL dollar quoting) leave it nil.
	RoutineBodyRe *regexp.Regexp
	// Returning describes which DML statement kinds support a RETURNING clause
	// on this engine+version, so the SQL console can classify a RETURNING-bearing
	// INSERT/UPDATE/DELETE/REPLACE/MERGE as row-returning (grid) rather than a
	// bare Exec. Populated per dialect from flavor/version.
	Returning ReturningCaps
}

// ReturningCaps records, per leading statement keyword, whether a RETURNING
// clause is supported. A false gate means a `… RETURNING …` on that statement
// is run as a plain Exec (the statement still executes; only the grid-vs-count
// presentation differs), which is correct on engines/versions lacking RETURNING
// there and avoids misrouting an unquoted identifier named `returning`.
type ReturningCaps struct {
	Insert, Update, Delete, Replace, Merge bool
}

// Allows reports whether an uppercased leading keyword supports RETURNING.
func (rc ReturningCaps) Allows(keyword string) bool {
	switch keyword {
	case "INSERT":
		return rc.Insert
	case "UPDATE":
		return rc.Update
	case "DELETE":
		return rc.Delete
	case "REPLACE":
		return rc.Replace
	case "MERGE":
		return rc.Merge
	}
	return false
}

// StatementLexer is an optional Dialect capability supplying the engine's
// script-lexing grammar. Dialects that omit it get DefaultLexerProfile.
type StatementLexer interface {
	LexerProfile() LexerProfile
}

// DefaultLexerProfile is the grammar assumed for a dialect without a
// StatementLexer: standard-conforming quoting with PostgreSQL's extensions
// (dollar quotes, E'…' strings, nested block comments) — the same fallback the
// splitter's engine-name era used for unknown engines.
func DefaultLexerProfile() LexerProfile {
	return LexerProfile{
		EscapeStringE:       true,
		DollarQuotes:        true,
		NestedBlockComments: true,
		// Permissive: a profile-less dialect keeps the historical behavior of
		// treating a RETURNING clause on any DML kind as row-returning.
		Returning: ReturningCaps{Insert: true, Update: true, Delete: true, Replace: true, Merge: true},
	}
}

// ProfileOf returns d's LexerProfile, or DefaultLexerProfile when the dialect
// does not implement StatementLexer.
func ProfileOf(d Dialect) LexerProfile {
	if l, ok := d.(StatementLexer); ok {
		return l.LexerProfile()
	}
	return DefaultLexerProfile()
}
