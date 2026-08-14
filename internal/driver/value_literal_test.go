package driver_test

import (
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestIsNumericLiteral pins the shared bare-numeric gate behind BOTH the SQL
// dump's unquoted literals and the JSON export's json.Number (the case table
// moved here from internal/dump when the predicate was hoisted). Everything
// that fails is emitted quoted — restore-safe for a genuine number via
// implicit cast — so strictness can only trade bareness for safety.
func TestIsNumericLiteral(t *testing.T) {
	for _, s := range []string{
		"0", "1", "42", "-42", "-0", "-3.14", "10.50", "3.14159",
		"1e10", "1.5E-3", "1e+06",
		"9223372036854775807",               // int64 max
		"123456789012345678901234567890",    // bigint far past float64 exact range
		"123456789012345678901234567890.42", // high-precision DECIMAL text — must stay bare
	} {
		if !driver.IsNumericLiteral(s) {
			t.Errorf("IsNumericLiteral(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"", "NaN", "Infinity", "-Infinity", "abc", "12abc", "1.2.3", "1,000",
		" 10", "  1", "01", "00042", "0x1f", "+5",
		"0, NULL);DROP TABLE notes;--", // the breakout shape the gate exists for
	} {
		if driver.IsNumericLiteral(s) {
			t.Errorf("IsNumericLiteral(%q) = true, want false", s)
		}
	}
}

// TestValueLiteralNumericGate pins the bare-vs-quoted decision per engine.
// Statically typed engines (MySQL/PostgreSQL) decide by the DECLARED column
// type gated on IsNumericLiteral — DECIMAL and huge integers arrive as text
// and must stay bare for precision, while planted text in a numeric column
// must be quoted or it breaks out of its INSERT on restore. SQLite
// (DynamicTyper) decides by the value's RUNTIME kind instead.
func TestValueLiteralNumericGate(t *testing.T) {
	const evil = "0, NULL);DROP TABLE notes;--"
	cases := []struct {
		engine string
		col    driver.ResultColumn
		v      driver.Value
		want   string
	}{
		// (b) literal breakout: declared-numeric text is QUOTED on every engine.
		{"mysql", driver.ResultColumn{Numeric: true}, driver.Value{Str: evil}, "'" + evil + "'"},
		{"postgres", driver.ResultColumn{Numeric: true}, driver.Value{Str: evil}, "'" + evil + "'"},
		{"sqlite", driver.ResultColumn{Numeric: true}, driver.Value{Str: evil}, "'" + evil + "'"},
		// DECIMAL / big-integer text stays BARE — full precision, no float64 trip.
		{"mysql", driver.ResultColumn{Numeric: true}, driver.Value{Str: "123456789012345678901234567890.42"}, "123456789012345678901234567890.42"},
		{"postgres", driver.ResultColumn{Numeric: true}, driver.Value{Str: "123456789012345678901234567890.42"}, "123456789012345678901234567890.42"},
		// MySQL ZEROFILL text fails the strict gate and quotes — restore-safe.
		{"mysql", driver.ResultColumn{Numeric: true}, driver.Value{Str: "00042"}, "'00042'"},
		// Non-finite handling still runs before the gate.
		{"postgres", driver.ResultColumn{Numeric: true}, driver.Value{Numeric: true, Str: "NaN"}, "'NaN'"},
		{"mysql", driver.ResultColumn{Numeric: true}, driver.Value{Str: "NaN"}, "NULL"},
		// (a) SQLite: the runtime kind decides, not the declared type. A
		// no-affinity INTEGER dumps bare (typeof survives restore) …
		{"sqlite", driver.ResultColumn{}, driver.Value{Numeric: true, Str: "1"}, "1"},
		{"sqlite", driver.ResultColumn{}, driver.Value{Numeric: true, Str: "1.5"}, "1.5"},
		// … while runtime TEXT stays quoted even when it looks numeric or the
		// column is declared numeric.
		{"sqlite", driver.ResultColumn{}, driver.Value{Str: "1"}, "'1'"},
		{"sqlite", driver.ResultColumn{Numeric: true}, driver.Value{Str: "12abc"}, "'12abc'"},
	}
	for _, c := range cases {
		d, ok := driver.Get(c.engine)
		if !ok {
			t.Fatalf("dialect %s not registered", c.engine)
		}
		du, ok := d.(driver.Dumper)
		if !ok {
			t.Fatalf("dialect %s does not implement Dumper", c.engine)
		}
		if got := du.ValueLiteral(c.col, c.v); got != c.want {
			t.Errorf("%s ValueLiteral(colNumeric=%v, vNumeric=%v, %q) = %q, want %q",
				c.engine, c.col.Numeric, c.v.Numeric, c.v.Str, got, c.want)
		}
	}
}

// TestDynamicTyperAgreesWithValueLiteral pins the pairing the two halves of
// the decision must keep: a dialect's ValueLiteral prefers the value's
// runtime kind (ValueLiteralHooks.PreferValueKind) if and ONLY if the dialect
// implements DynamicTyper (which the JSON writer consults). If they drift,
// the SQL and JSON exports classify the same cell differently.
func TestDynamicTyperAgreesWithValueLiteral(t *testing.T) {
	for _, d := range driver.All() {
		du, ok := d.(driver.Dumper)
		if !ok {
			continue
		}
		// A runtime-numeric value in a declared-NON-numeric column dumps bare
		// only under kind preference.
		prefersKind := du.ValueLiteral(driver.ResultColumn{}, driver.Value{Numeric: true, Str: "1"}) == "1"
		if prefersKind != driver.PrefersValueKind(d) {
			t.Errorf("%s: ValueLiteral kind preference = %v but DynamicTyper = %v — SQL and JSON exports disagree",
				d.Name(), prefersKind, driver.PrefersValueKind(d))
		}
	}
}
