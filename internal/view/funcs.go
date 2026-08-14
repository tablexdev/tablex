package view

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tablexdev/tablex/internal/driver"
)

// HumanBytes formats a byte count using IEC units (KiB, MiB, …). A negative
// value (our "unknown" sentinel) renders as an em dash rather than a zero.
// The IEC formatting itself is the shared driver.HumanBytesIEC.
func HumanBytes(n int64) string {
	if n < 0 {
		return "—"
	}
	return driver.HumanBytesIEC(n)
}

// HumanInt formats an integer with thousands separators; negative renders as an
// em dash (unknown).
func HumanInt(n int64) string {
	if n < 0 {
		return "—"
	}
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		// len(s) > 3 here, so a partial leading group always has full groups
		// after it — the comma is unconditional.
		b.WriteString(s[:pre])
		b.WriteByte(',')
	}
	for i := pre; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// list collects its arguments into a slice (for ranging in templates).
func list(values ...any) []any { return values }

// dict builds a map from alternating key/value arguments, so a partial can take
// named parameters instead of a positional slice. Keys must be strings; an odd
// argument count is a template error rather than a silently dropped value.
//
// Ranging a map in html/template visits keys in sorted order, so a dict used
// for a set of form fields renders deterministically.
func dict(pairs ...any) (map[string]any, error) {
	if len(pairs)%2 != 0 {
		return nil, fmt.Errorf("dict: got %d arguments, want an even number of key/value pairs", len(pairs))
	}
	m := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		k, ok := pairs[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict: key %d is %T, want string", i/2, pairs[i])
		}
		m[k] = pairs[i+1]
	}
	return m, nil
}

func add(a, b int) int { return a + b }

// def returns val unless it is empty/zero, in which case fallback.
func def(val, fallback any) any {
	if isEmpty(val) {
		return fallback
	}
	return val
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case int:
		return x == 0
	case int64:
		return x == 0
	case bool:
		return !x
	}
	return false
}

// fmtTime formats an optional timestamp (e.g. model.Table.Created). Templates
// guard nil with {{if}} — a nil *time.Time is falsy there — rather than the
// default helper: isEmpty misses typed-nil pointers boxed in any and default
// would render "<nil>" instead of the fallback.
func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

func lower(s string) string { return strings.ToLower(s) }

func yesno(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// truncate shortens s to n runes, appending an ellipsis if cut. A negative n
// (only reachable from a template author, never user data) clamps to 0 rather
// than panicking on a negative slice bound.
//
// It never materializes []rune(s): that allocated four bytes per byte of input,
// so rendering a 200-character preview of a large TEXT cell cost several times
// the cell itself — per cell, on a page of hundreds of rows. A string of at most
// n BYTES can hold at most n runes, which makes the common short case a single
// length compare; otherwise it walks at most n+1 rune boundaries.
func truncate(n int, s string) string {
	if n < 0 {
		n = 0
	}
	if len(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i] + "…"
		}
		count++
	}
	return s
}
