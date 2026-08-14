package driver

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"
)

func TestIsNumericDBType(t *testing.T) {
	numeric := []string{"INT", "integer", "BIGINT", "INT(11)", "int unsigned",
		// go-sql-driver's leading-UNSIGNED spellings (Theme G) must classify numeric.
		"UNSIGNED INT", "UNSIGNED BIGINT", "unsigned int(10)",
		"DECIMAL(10,2)", "NUMERIC", "FLOAT8", "DOUBLE PRECISION", "YEAR", "serial",
		// SQLite declared types: any INT-containing declaration has INTEGER
		// affinity, and a pure digit suffix stays numeric.
		"INT64"}
	for _, s := range numeric {
		if !isNumericDBType(s) {
			t.Errorf("isNumericDBType(%q) = false, want true", s)
		}
	}
	// Number-adjacent types that must export quoted (not as bare numerals).
	notNumeric := []string{"INTERVAL", "MONEY", "BIT", "BIT(8)", "VARCHAR", "TEXT",
		"DATE", "TIMESTAMP", "BOOLEAN", "JSON", "",
		// PostgreSQL range types: digits followed by letters. Range values like
		// [1,11) must export quoted, or the restore INSERT fails to parse.
		"INT4RANGE", "INT8RANGE", "INT4MULTIRANGE", "INT8MULTIRANGE", "NUMRANGE", "NUMMULTIRANGE"}
	for _, s := range notNumeric {
		if isNumericDBType(s) {
			t.Errorf("isNumericDBType(%q) = true, want false", s)
		}
	}
}

// TestFormatValueKeepBytes pins the BLOB-memory contract: buffered results
// (browse, console) carry only the size placeholder, while the streaming export
// path keeps the raw bytes it needs for hex literals.
func TestFormatValueKeepBytes(t *testing.T) {
	blob := []byte{0x00, 0xff, 0x10}

	buffered := formatValue(blob, true, "BLOB", false)
	if !buffered.Binary || buffered.Bytes != nil {
		t.Errorf("buffered BLOB = %+v, want Binary with nil Bytes", buffered)
	}
	if buffered.Str == "" {
		t.Error("buffered BLOB lost its placeholder")
	}

	streamed := formatValue(blob, true, "BLOB", true)
	if !streamed.Binary || string(streamed.Bytes) != string(blob) {
		t.Errorf("streamed BLOB = %+v, want the raw bytes kept", streamed)
	}

	// Text in []byte clothing (MySQL) is unaffected by the flag.
	text := formatValue([]byte("hello"), false, "VARCHAR", false)
	if text.Binary || text.Str != "hello" {
		t.Errorf("text bytes = %+v", text)
	}
}

// TestCapCell covers: display results must not retain an unbounded text
// cell. The []byte branch's 1 MiB heuristic never reached the string branch, and
// pgx returns PostgreSQL text/json as string — so those cells were uncapped.
func TestCapCell(t *testing.T) {
	// Under the cap: returned untouched.
	if got := capCell("hello", 16); got != "hello" {
		t.Errorf("capCell under cap = %q, want hello", got)
	}
	// Exactly at the cap: still untouched (the compare is <=).
	if got := capCell("abcd", 4); got != "abcd" {
		t.Errorf("capCell at cap = %q, want abcd", got)
	}
	// cap <= 0 disables the cap entirely (ScanResultVerbatim).
	long := strings.Repeat("x", 4096)
	if got := capCell(long, 0); got != long {
		t.Errorf("capCell with cap 0 trimmed a %d-byte value to %d", len(long), len(got))
	}
	// Over the cap: trimmed to the cap.
	if got := capCell(long, 100); len(got) != 100 {
		t.Errorf("capCell(4096 bytes, 100) kept %d bytes, want 100", len(got))
	}

	// The cut lands on a rune boundary: "é" is two bytes, so a cap that would
	// split the 8th rune must back up rather than leave half a rune behind.
	multi := strings.Repeat("é", 20) // 40 bytes
	got := capCell(multi, 15)        // 15 is mid-rune (odd offset)
	if !utf8.ValidString(got) {
		t.Errorf("capCell split a multi-byte rune: %q", got)
	}
	if len(got) != 14 {
		t.Errorf("capCell(é×20, 15) kept %d bytes, want 14 (backed up one byte)", len(got))
	}

	// The trimmed prefix must be a COPY: resliced, it would pin the whole
	// oversized original and defeat the cap. Compare backing-array identity via
	// unsafe.StringData rather than trusting the copy by inspection.
	huge := strings.Repeat("y", 1<<20)
	trimmed := capCell(huge, 64)
	if unsafe.StringData(trimmed) == unsafe.StringData(huge) {
		t.Error("capCell resliced instead of cloning; the oversized original stays reachable")
	}
}

// panicResult is a sql.Result that panics the way database/sql's wrapper does
// when a driver hands back a nil driver.Result (modernc.org/sqlite, for input
// that compiles to no statement — a comment-only script).
type panicResult struct{ p any }

func (panicResult) LastInsertId() (int64, error) { return 0, nil }
func (r panicResult) RowsAffected() (int64, error) {
	panic(r.p)
}

// errResult is a driver that simply does not track affected rows.
type errResult struct{}

func (errResult) LastInsertId() (int64, error) { return 0, errors.New("unsupported") }
func (errResult) RowsAffected() (int64, error) { return 0, errors.New("unsupported") }

// okResult is a well-behaved driver result.
type okResult struct{ n int64 }

func (okResult) LastInsertId() (int64, error)   { return 0, nil }
func (r okResult) RowsAffected() (int64, error) { return r.n, nil }

// TestResultStatsNarrowRecover covers: the blanket `defer func(){ _ =
// recover() }()` swallowed ANY panic in reach, hiding real bugs, and discarded
// the RowsAffected error entirely. The recover is now scoped to the one case it
// exists for — a runtime error out of that single call — and everything else
// re-panics with its stack intact.
func TestResultStatsNarrowRecover(t *testing.T) {
	// nil result: no panic, no error, zero rows.
	if got, err := resultStats(nil); err != nil || got.RowsAffected != 0 {
		t.Errorf("resultStats(nil) = (%+v, %v), want zero and no error", got, err)
	}

	// A healthy driver reports its count.
	if got, err := resultStats(okResult{n: 7}); err != nil || got.RowsAffected != 7 {
		t.Errorf("resultStats(ok) = (%+v, %v), want 7 rows and no error", got, err)
	}

	// The known nil-driver-Result case surfaces as an error rather than being
	// silently swallowed.
	got, err := resultStats(panicResult{p: newRuntimeError()})
	if err == nil {
		t.Error("a runtime error from RowsAffected should be reported, not swallowed")
	}
	if got.RowsAffected != 0 {
		t.Errorf("failed resultStats reported %d rows", got.RowsAffected)
	}

	// A NON-runtime panic is a genuine bug and must keep propagating.
	func() {
		defer func() {
			if p := recover(); p == nil {
				t.Error("a non-runtime panic was swallowed; only the nil-driver-Result case may be recovered")
			} else if s, _ := p.(string); s != "boom" {
				t.Errorf("re-panicked with %v, want the original value", p)
			}
		}()
		_, _ = resultStats(panicResult{p: "boom"})
	}()

	// A driver that does not track affected rows is an error, not a panic —
	// and runExec degrades it to zero rather than failing a statement that ran.
	if _, err := resultStats(errResult{}); err == nil {
		t.Error("a RowsAffected error should be reported, not discarded")
	}
}

// newRuntimeError produces a genuine runtime.Error (a nil map write panics with
// one) without depending on unexported types.
func newRuntimeError() (err runtime.Error) {
	defer func() { err = recover().(runtime.Error) }()
	var m map[string]int
	//lint:ignore SA5000 The nil-map write IS the subject: it is the cheapest way
	// to obtain a real runtime.Error without reaching for an unexported type.
	m["x"] = 1
	return nil
}

// TestScanResultCellCap pins which scan applies the cap. ScanResult is the
// display path; ScanResultVerbatim backs the row-edit prefill, which is posted
// back as the row's new value and so must never be truncated.
func TestScanResultCellCap(t *testing.T) {
	if MaxCellBytes <= 0 {
		t.Fatalf("MaxCellBytes = %d, want a positive cap", MaxCellBytes)
	}
	over := strings.Repeat("z", MaxCellBytes+512)
	if got := capCell(over, MaxCellBytes); len(got) != MaxCellBytes {
		t.Errorf("display scan would keep %d bytes of an oversized cell, want %d", len(got), MaxCellBytes)
	}
	if got := capCell(over, 0); len(got) != len(over) {
		t.Errorf("verbatim scan trimmed an oversized cell to %d bytes, want %d", len(got), len(over))
	}
}

func TestFormatTime(t *testing.T) {
	midnight := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	noon := time.Date(2024, 3, 1, 12, 30, 45, 0, time.UTC)
	kolkata := time.FixedZone("IST", 5*3600+1800)
	offset := time.Date(2024, 3, 1, 12, 30, 45, 0, kolkata)
	cases := []struct {
		in     time.Time
		dbType string
		want   string
	}{
		{midnight, "DATE", "2024-03-01"},
		{midnight, "DATETIME", "2024-03-01 00:00:00"}, // midnight DATETIME must NOT collapse to a date
		{noon, "TIMESTAMP", "2024-03-01 12:30:45"},
		{noon, "TIME", "12:30:45"},
		{noon, "", "2024-03-01 12:30:45"}, // unknown type → full timestamp
		// Offset-bearing types keep the offset, or a restore session would
		// reinterpret the naive wall clock in its own time zone.
		{offset, "TIMESTAMPTZ", "2024-03-01 12:30:45+05:30"},
		{noon, "TIMESTAMPTZ", "2024-03-01 12:30:45+00:00"},
		{offset, "TIMETZ", "12:30:45+05:30"},
	}
	for _, c := range cases {
		if got := formatTime(c.in, c.dbType); got != c.want {
			t.Errorf("formatTime(%v, %q) = %q, want %q", c.in, c.dbType, got, c.want)
		}
	}
}

// TestFormatValueAutoBinary pins: a []byte cell on a NON-binary column is
// still shown/dumped as a BLOB when its bytes are not printable UTF-8 (MySQL
// returns most values as bytes), while a printable []byte reads as text.
func TestFormatValueAutoBinary(t *testing.T) {
	// Non-UTF-8 bytes on a text column → auto-detected binary.
	v := formatValue([]byte{0xff, 0xfe, 0x00}, false, "TEXT", true)
	if !v.Binary || v.Str != "[BLOB 3 B]" {
		t.Errorf("non-UTF8 text cell = %+v, want Binary with [BLOB 3 B]", v)
	}
	if len(v.Bytes) != 3 {
		t.Errorf("keepBytes should retain the raw bytes, got %d", len(v.Bytes))
	}
	// Printable UTF-8 bytes on a text column → plain text.
	if v := formatValue([]byte("héllo"), false, "VARCHAR", false); v.Binary || v.Str != "héllo" {
		t.Errorf("printable UTF-8 cell = %+v, want text", v)
	}
	// An embedded NUL forces binary even for otherwise-ASCII content.
	if v := formatValue([]byte("a\x00b"), false, "TEXT", false); !v.Binary {
		t.Errorf("NUL-containing cell should be binary, got %+v", v)
	}
}

func TestIsPrintableUTF8(t *testing.T) {
	if !isPrintableUTF8([]byte("hello\tworld\n")) {
		t.Error("plain text with tab/newline should be printable")
	}
	if isPrintableUTF8([]byte{0xff, 0xfe}) {
		t.Error("invalid UTF-8 should not be printable")
	}
	if isPrintableUTF8([]byte("a\x00b")) {
		t.Error("NUL byte should not be printable")
	}
	if isPrintableUTF8([]byte{0x07}) {
		t.Error("a control char (BEL) should not be printable")
	}
	// The 1 MiB cap: valid UTF-8 above the cap classifies as binary.
	big := make([]byte, (1<<20)+1)
	for i := range big {
		big[i] = 'a'
	}
	if isPrintableUTF8(big) {
		t.Error("valid text above the 1 MiB cap should classify as binary")
	}
}

func TestHumanBytesIEC(t *testing.T) {
	cases := map[int64]string{
		0: "0 B", 512: "512 B", 1023: "1023 B",
		1024: "1.0 KiB", 1536: "1.5 KiB",
		1 << 20: "1.0 MiB", 1 << 30: "1.0 GiB", 1 << 40: "1.0 TiB",
	}
	for n, want := range cases {
		if got := HumanBytesIEC(n); got != want {
			t.Errorf("HumanBytesIEC(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestIsBinaryDBType(t *testing.T) {
	for _, tp := range []string{"BLOB", "tinyblob", "BYTEA", "BINARY", "varbinary", "IMAGE", "LONG BLOB", "varbinary(16)"} {
		if !isBinaryDBType(tp) {
			t.Errorf("isBinaryDBType(%q) = false, want true", tp)
		}
	}
	for _, tp := range []string{"VARCHAR", "text", "int", "json", "geometry", "uuid"} {
		if isBinaryDBType(tp) {
			t.Errorf("isBinaryDBType(%q) = true, want false", tp)
		}
	}
}
