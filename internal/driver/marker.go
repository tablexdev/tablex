package driver

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// TableX dump markers are inert, versioned, exact-line SQL comments that
// TableX's own SQL dumps embed and its splitter/importer recognize (the same
// convention family as the PostgreSQL server-dump \connect sections). Two
// marker types exist:
//
//   - frame markers introduce an opaque DELIMITER frame around a
//     binary-fetched MySQL object body, telling the splitter to treat the
//     framed bytes as opaque (no string/comment interpretation — the body may
//     be non-UTF-8 or authored under NO_BACKSLASH_ESCAPES);
//   - db-collation markers disclose the source `Database Collation` of a
//     routine/trigger/event so the importer can warn when the target
//     database's collation differs (fidelity by disclosure — the target is
//     never ALTERed).
//
// Every external SQL client sees plain comments. Field values are hex-encoded
// (bounded, non-lossy — dump comments deliberately scrub control characters
// via commentSafe, which markers must not), and recognition validates the
// full grammar: a malformed or oversized marker-like line is an ordinary
// comment, never an event.

// markerPrefix opens every TableX marker line. The version is part of the
// prefix: a future grammar change bumps it, and older TableX versions then
// ignore the unrecognized lines.
const markerPrefix = "-- tablex:v1 "

// Marker field bounds. MySQL identifiers cap at 64 characters (≤ 256 bytes in
// utf8mb4) and collation names at 64 bytes, so these are generous while still
// bounding a hostile line.
const (
	maxMarkerHexField  = 1024 // hex chars: 512 raw bytes
	maxFrameDelimBytes = 16
)

// DumpMarker is one validated TableX db-collation disclosure marker.
type DumpMarker struct {
	Kind      string // "routine", "trigger" or "event"
	Name      string // object name, decoded
	Collation string // the source database's collation as recorded at dump time
}

// CollationProber is an optional Dialect capability backing the SQL import's
// db-collation marker verification: the single-row, two-column statement
// reporting the session's current database and that database's default
// collation. Engines whose dumps carry no collation markers omit it and the
// importer ignores marker events.
type CollationProber interface {
	CollationProbeSQL() string
}

// collationMarkerKinds are the object kinds a db-collation marker may carry —
// exactly the SHOW CREATE shapes that report a `Database Collation` column
// (views report only the two charset columns and never get a marker).
var collationMarkerKinds = map[string]bool{"routine": true, "trigger": true, "event": true}

// FormatCollationMarker renders the disclosure marker line for one object.
// The caller guarantees kind is a collationMarkerKinds member.
func FormatCollationMarker(kind, name, collation string) string {
	return markerPrefix + "db-collation kind=" + kind +
		" name=" + hex.EncodeToString([]byte(name)) +
		" value=" + hex.EncodeToString([]byte(collation))
}

// ParseCollationMarker validates line (without its trailing newline) against
// the full db-collation marker grammar and decodes it. ok is false for
// anything else — including marker-like lines with unknown types, malformed
// fields or trailing garbage, which stay ordinary comments.
func ParseCollationMarker(line string) (DumpMarker, bool) {
	rest, ok := cutMarker(line, "db-collation")
	if !ok {
		return DumpMarker{}, false
	}
	fields := strings.Split(rest, " ")
	if len(fields) != 3 {
		return DumpMarker{}, false
	}
	kind, ok := strings.CutPrefix(fields[0], "kind=")
	if !ok || !collationMarkerKinds[kind] {
		return DumpMarker{}, false
	}
	name, ok := markerHexField(fields[1], "name=")
	if !ok || name == "" {
		return DumpMarker{}, false
	}
	collation, ok := markerHexField(fields[2], "value=")
	if !ok || collation == "" {
		return DumpMarker{}, false
	}
	return DumpMarker{Kind: kind, Name: name, Collation: collation}, true
}

// FormatFrameMarker renders the opaque-frame marker line for a frame using
// delim (chosen via ChooseFrameDelimiter, so it is always grammar-valid).
func FormatFrameMarker(delim string) string {
	return markerPrefix + "frame delimiter=" + delim
}

// ParseFrameMarker validates line against the full frame marker grammar and
// returns the frame's delimiter token. ok is false for anything else.
func ParseFrameMarker(line string) (delim string, ok bool) {
	rest, ok := cutMarker(line, "frame")
	if !ok {
		return "", false
	}
	delim, ok = strings.CutPrefix(rest, "delimiter=")
	if !ok || !validFrameDelimiter(delim) {
		return "", false
	}
	return delim, true
}

// cutMarker strips the marker prefix, an optional trailing \r (a CRLF-mangled
// upload keeps parsing; the fields themselves are \r-free by grammar), and the
// marker-type word, returning the space-separated field tail.
func cutMarker(line, markerType string) (rest string, ok bool) {
	line = strings.TrimSuffix(line, "\r")
	rest, ok = strings.CutPrefix(line, markerPrefix)
	if !ok {
		return "", false
	}
	return strings.CutPrefix(rest, markerType+" ")
}

// markerHexField decodes one "key=<hex>" marker field: bounded, lowercase,
// even-length hex only.
func markerHexField(field, key string) (string, bool) {
	h, ok := strings.CutPrefix(field, key)
	if !ok || h == "" || len(h) > maxMarkerHexField || len(h)%2 != 0 {
		return "", false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// validFrameDelimiter bounds a frame delimiter token: 1–16 printable ASCII
// bytes, excluding whitespace and the quote/backslash characters that would
// collide with string-literal lexing in external clients.
func validFrameDelimiter(s string) bool {
	if s == "" || len(s) > maxFrameDelimBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c > '~' || c == '\'' || c == '"' || c == '`' || c == '\\' {
			return false
		}
	}
	return true
}

// ChooseFrameDelimiter picks a DELIMITER token for an opaque frame around
// body: one that occurs nowhere in the body, so neither TableX's exact-line
// terminator match nor an external client's substring scan can fire early.
// The terminator is always emitted on its own line, so a body merely *ending*
// in a token prefix (e.g. '$' before a '$$' token) cannot splice into it.
func ChooseFrameDelimiter(body string) string {
	for _, cand := range []string{"$$", ";;", "@@", "//"} {
		if !strings.Contains(body, cand) {
			return cand
		}
	}
	// Collect every $$<digits>$$-shaped token already present in the body in a
	// single O(len(body)) scan (advancing one byte at a time catches tokens that
	// share a `$$` with a neighbour). With N numbered tokens occupied, pigeonhole
	// guarantees a free candidate in 1…N+1, so the pick below always terminates —
	// well within the width cap, since a numbered token costs ≥5 bytes so reaching
	// even a 12-digit value would need a multi-terabyte body. The digit scan is
	// bounded by the delimiter width cap: a longer run cannot be a valid token
	// (and is never generated), so ignoring it risks no collision.
	occupied := make(map[string]bool)
	for i := 0; i+3 < len(body); i++ {
		if body[i] != '$' || body[i+1] != '$' {
			continue
		}
		j := i + 2
		for j < len(body) && body[j] >= '0' && body[j] <= '9' && j-i <= maxFrameDelimBytes {
			j++
		}
		if j > i+2 && j+1 < len(body) && body[j] == '$' && body[j+1] == '$' {
			occupied[body[i+2:j]] = true
		}
	}
	for i := 1; ; i++ {
		if n := strconv.Itoa(i); !occupied[n] {
			return "$$" + n + "$$"
		}
	}
}
