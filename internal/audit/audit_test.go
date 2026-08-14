package audit_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/audit"
)

// readLines parses a JSON Lines audit file.
func readLines(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("line is not valid JSON (%v): %s", err, line)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}

func TestFileSinkWritesOneJSONObjectPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := audit.OpenFile(path, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	l := audit.New(nil, s)
	l.Emit(audit.Event{Kind: audit.KindAuth, Account: "root@localhost", Remote: "10.0.0.1"})
	l.Emit(audit.Event{Kind: audit.KindAction, Target: "sales.orders", Status: 303, Outcome: audit.OutcomeOK})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := readLines(t, path)
	if len(got) != 2 {
		t.Fatalf("wrote %d events, want 2", len(got))
	}
	if got[0].Kind != audit.KindAuth || got[0].Account != "root@localhost" {
		t.Errorf("first event = %+v", got[0])
	}
	if got[1].Target != "sales.orders" || got[1].Status != 303 {
		t.Errorf("second event = %+v", got[1])
	}
	// Time is stamped for the caller, and an omitted outcome defaults rather
	// than serialising as an empty string an auditor would have to interpret.
	for i, e := range got {
		if e.Time.IsZero() {
			t.Errorf("event %d has no timestamp", i)
		}
		if e.Outcome == "" {
			t.Errorf("event %d has no outcome", i)
		}
	}
	// The file must not be group- or world-readable: it names accounts and client
	// addresses, and once statement auditing is on it carries SQL that may
	// contain row data. Windows does not model POSIX bits, so the assertion is
	// made where it means something — which includes CI.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Logf("audit file mode is %v (POSIX bits are not modelled on Windows)", info.Mode().Perm())
	} else if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("audit file mode is %v, want no group or other access", perm)
	}
}

// TestFileSinkAppends: a restart must not truncate the trail.
func TestFileSinkAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for range 3 {
		s, err := audit.OpenFile(path, 0)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		audit.New(nil, s).Emit(audit.Event{Kind: audit.KindAuth})
		s.Close()
	}
	if got := readLines(t, path); len(got) != 3 {
		t.Errorf("after three opens the file holds %d events, want 3 — reopening truncated the trail", len(got))
	}
}

// TestFileSinkRotates covers the disk-filling floor: past the threshold the file
// is renamed to ".1" and a fresh one started, losing nothing across that
// rotation.
//
// It stops at the FIRST rotation rather than emitting a fixed count, because the
// number of events per file depends on how long a line happens to be — and
// because past the second rotation events legitimately are discarded, which the
// next test states outright.
func TestFileSinkRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := audit.OpenFile(path, 400) // small, so a handful of events crosses it
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	l := audit.New(nil, s)
	emitted := 0
	for range 200 {
		l.Emit(audit.Event{Kind: audit.KindAction, Target: fmt.Sprintf("db.t%03d", emitted)})
		emitted++
		if _, err := os.Stat(path + ".1"); err == nil {
			break
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("nothing rotated after %d events; this test proves nothing", emitted)
	}

	current, rotated := readLines(t, path), readLines(t, path+".1")
	if total := len(current) + len(rotated); total != emitted {
		t.Errorf("%d events across the live file and .1, want %d — the rotation dropped events", total, emitted)
	}
	// The live file holds the NEWEST events, which is what tailing it implies.
	if len(current) == 0 || current[len(current)-1].Target != fmt.Sprintf("db.t%03d", emitted-1) {
		t.Errorf("the live file does not end with the newest event: %+v", current)
	}
	if len(rotated) == 0 || rotated[0].Target != "db.t000" {
		t.Errorf(".1 does not begin with the oldest event: %+v", rotated)
	}
}

// TestFileSinkRotationFailureDoesNotDropTheEvent: a failed rotation must cost
// at most the ROTATION, never the event — rotateLocked reopens the original
// on a failed rename, and Write appends whenever a usable file is open,
// surfacing the failure out of band (the reporter) instead of through its
// error return, which the Logger would count as a dropped record. The rename
// is forced to fail portably by planting a non-empty DIRECTORY at <path>.1.
func TestFileSinkRotationFailureDoesNotDropTheEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// A non-empty directory at the rotation target makes os.Rename fail on
	// every platform.
	if err := os.MkdirAll(filepath.Join(path+".1", "occupied"), 0o700); err != nil {
		t.Fatalf("plant blocker: %v", err)
	}
	s, err := audit.OpenFile(path, 400)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	var reported int
	s.SetFailureReporter(func(error) { reported++ })

	const n = 40 // comfortably past several rotation attempts at maxBytes 400
	for i := range n {
		if err := s.Write(audit.Event{Kind: audit.KindAction, Target: fmt.Sprintf("db.t%03d", i)}); err != nil {
			t.Fatalf("write %d returned %v — a survived rotation failure must not read as a dropped event", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if reported == 0 {
		t.Fatal("the rename never failed, so this test proves nothing (the blocker directory did not block)")
	}
	lines := readLines(t, path)
	if len(lines) != n {
		t.Errorf("%d of %d events survived — a failed rotation dropped events", len(lines), n)
	}
	if lines[len(lines)-1].Target != fmt.Sprintf("db.t%03d", n-1) {
		t.Errorf("the newest event is missing: file ends with %+v", lines[len(lines)-1])
	}
}

// TestFileSinkKeepsOneGeneration states the limit rather than implying more than
// is delivered: rotation is a floor against filling a disk unattended, NOT a
// retention policy, so a second rotation discards the first generation. An
// operator who needs retention points audit.file somewhere their own rotation
// handles, or ships the lines — which is what JSON Lines is for.
func TestFileSinkKeepsOneGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s, err := audit.OpenFile(path, 400)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	l := audit.New(nil, s)
	const n = 200
	for i := range n {
		l.Emit(audit.Event{Kind: audit.KindAction, Target: fmt.Sprintf("db.t%03d", i)})
	}
	l.Close()

	kept := len(readLines(t, path)) + len(readLines(t, path+".1"))
	if kept >= n {
		t.Fatalf("%d of %d events survived; the threshold was never crossed twice, so this proves nothing", kept, n)
	}
	// No third generation is created — the file count is bounded, which is the
	// property that stops the disk filling.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("audit directory holds %v, want exactly the live file and one .1", names)
	}
	// And what survives is the most recent, not an arbitrary window.
	current := readLines(t, path)
	if len(current) == 0 || current[len(current)-1].Target != fmt.Sprintf("db.t%03d", n-1) {
		t.Error("the newest event did not survive rotation")
	}
}

// TestDisabledLoggerIsInert: with no sinks there is no logger, and every method
// tolerates that, so no caller has to guard.
func TestDisabledLoggerIsInert(t *testing.T) {
	var l *audit.Logger
	if l.Enabled() {
		t.Error("a nil Logger reports itself enabled")
	}
	l.Emit(audit.Event{Kind: audit.KindAuth}) // must not panic
	if err := l.Close(); err != nil {
		t.Errorf("Close on a nil Logger = %v", err)
	}
	if audit.New(nil) != nil {
		t.Error("New with no sinks should be nil, so that 'off' has exactly one representation")
	}
}

// TestSetOutcomeIfUnsetPrecedence pins the outcome layering the action log
// relies on: a specific outcome a policy/capacity layer pre-set (SetOutcome)
// must survive the generic responders' later SetOutcomeIfUnset — a capacity
// refusal pre-sets denied and then renders a 503, whose status-derived class
// would be error — while a request nobody classified takes the first IfUnset.
func TestSetOutcomeIfUnsetPrecedence(t *testing.T) {
	var p audit.Pending
	p.SetOutcome(audit.OutcomeDenied, "capacity")
	p.SetOutcomeIfUnset(audit.OutcomeError, "generic 503 classification")
	if o, d := p.Outcome(); o != audit.OutcomeDenied || d != "capacity" {
		t.Errorf("pre-set outcome clobbered: got (%q, %q), want (denied, capacity)", o, d)
	}

	var q audit.Pending
	q.SetOutcomeIfUnset(audit.OutcomeInvalid, "first classification")
	q.SetOutcomeIfUnset(audit.OutcomeError, "later classification")
	if o, d := q.Outcome(); o != audit.OutcomeInvalid || d != "first classification" {
		t.Errorf("unset case: got (%q, %q), want the FIRST IfUnset to stick", o, d)
	}

	// nil stays tolerated, like every Pending method.
	var nilP *audit.Pending
	nilP.SetOutcomeIfUnset(audit.OutcomeOK, "") // must not panic
}

// failingSink stands in for a full disk.
type failingSink struct {
	mu sync.Mutex
	n  int
}

func (s *failingSink) Write(audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return errors.New("no space left on device")
}
func (s *failingSink) Close() error { return nil }

// TestSinkFailureIsReportedLoudlyAndOnce: an audit trail that has silently
// stopped recording is worse than one that was never started, so the failure is
// an ERROR — but one per event would bury the log, so it is throttled with a
// count.
func TestSinkFailureIsReportedLoudlyAndOnce(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fs := &failingSink{}
	l := audit.New(log, fs)

	for range 5 {
		l.Emit(audit.Event{Kind: audit.KindAction})
	}
	out := buf.String()
	if n := strings.Count(out, "level=ERROR"); n != 1 {
		t.Errorf("five failed writes logged %d ERROR lines, want 1 (throttled):\n%s", n, out)
	}
	if !strings.Contains(out, "LOST") {
		t.Errorf("the failure report does not say events are being lost:\n%s", out)
	}
	if fs.n != 5 {
		t.Errorf("the sink was called %d times, want 5 — throttling the REPORT must not throttle the writes", fs.n)
	}
}

func TestTarget(t *testing.T) {
	for _, c := range []struct{ path, query, want string }{
		{"/db/sales", "", "sales"},
		{"/db/sales/structure", "", "sales"},
		{"/db/sales/table/orders", "", "sales.orders"},
		{"/db/sales/table/orders/operations", "", "sales.orders"},
		{"/db/sales/table/orders", "schema=public", "sales.public.orders"},
		{"/db/sales", "schema=reporting", "sales.reporting"},
		// No single object: these are server-scope or auth routes.
		{"/server/users", "", ""},
		{"/login", "", ""},
		{"/", "", ""},
		{"/db", "", ""},
		{"/db/", "", ""},
		// Percent-encoding. Target runs before routing, so it segments the
		// ESCAPED path and unescapes each segment itself — the way net/http does.
		// Splitting the decoded path made a %2F look like a real separator, so
		// the trail named a different object from the one the handler operated on.
		{"/db/app%2Fbackup", "", "app/backup"},
		{"/db/app%2Fbackup/table/or%2Fders", "", "app/backup.or/ders"},
		{"/db/sales/table/order%20lines", "", "sales.order lines"},
		// EVERY segment, not just the two extracted: net/http compares its
		// literal pattern segments against the UNESCAPED segment, so this really
		// does route to /db/{db}. Leaving seg[0] as "%64b" would return "".
		{"/%64b/sales", "", "sales"},
		{"/%64b/sales/%74able/orders", "", "sales.orders"},
		// A double-encoded value must survive ONE decode, not two: %2525 is the
		// literal text "%25", and a second pass would corrupt it to "%".
		{"/db/a%2525b", "", "a%25b"},
	} {
		u := c.path
		if c.query != "" {
			u += "?" + c.query
		}
		if got := audit.Target(httptest.NewRequest("POST", u, nil)); got != c.want {
			t.Errorf("Target(%q) = %q, want %q", u, got, c.want)
		}
	}
}

func TestOutcomeForStatus(t *testing.T) {
	for status, want := range map[int]audit.Outcome{
		200: audit.OutcomeOK,
		303: audit.OutcomeOK,
		400: audit.OutcomeInvalid,
		401: audit.OutcomeDenied,
		403: audit.OutcomeDenied,
		404: audit.OutcomeInvalid,
		429: audit.OutcomeInvalid,
		500: audit.OutcomeError,
		503: audit.OutcomeError,
	} {
		if got := audit.OutcomeForStatus(status); got != want {
			t.Errorf("OutcomeForStatus(%d) = %q, want %q", status, got, want)
		}
	}
}

// TestNameIsBounded: a rejected login records whatever username was posted, so
// this field is attacker-controlled on exactly the events an auditor reads most.
func TestNameIsBounded(t *testing.T) {
	if got := audit.Name("  root@localhost  "); got != "root@localhost" {
		t.Errorf("Name trimmed to %q", got)
	}
	long := strings.Repeat("a", 5000)
	got := audit.Name(long)
	if len(got) >= len(long) {
		t.Errorf("Name did not bound a %d-byte identity (got %d)", len(long), len(got))
	}
	// A multi-byte name cut at a byte boundary must not leave a broken rune in
	// the record.
	multi := strings.Repeat("é", 500)
	if cut := audit.Name(multi); !isValidUTF8(cut) {
		t.Errorf("Name produced invalid UTF-8 when cutting a multi-byte identity: %q", cut)
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' && !strings.Contains(s, "\uFFFD") {
			return false
		}
	}
	return len(strings.ToValidUTF8(s, "\x00")) == len(s)
}

// TestPendingCarriesIdentityAcrossTheChain: the whole reason Pending exists is
// that the layer which learns the identity and the layer which emits the event
// are different, and hold different request objects.
func TestPendingCarriesIdentityAcrossTheChain(t *testing.T) {
	p := &audit.Pending{}
	outer := httptest.NewRequest("POST", "/db/sales/table/orders/operations", nil)
	outer = outer.WithContext(audit.NewContext(outer.Context(), p))

	// A deeper layer, holding its own derived request.
	inner := outer.WithContext(outer.Context())
	audit.FromContext(inner.Context()).SetIdentity("root@localhost", "prod", "mysql")
	audit.FromContext(inner.Context()).SetOutcome(audit.OutcomeDenied, "refused")

	account, server, engine := p.Identity()
	if account != "root@localhost" || server != "prod" || engine != "mysql" {
		t.Errorf("identity set on the inner request did not reach the outer one: %q %q %q", account, server, engine)
	}
	if o, detail := p.Outcome(); o != audit.OutcomeDenied || detail != "refused" {
		t.Errorf("outcome override = %q %q", o, detail)
	}
	// A nil Pending is usable, so no layer needs a guard.
	var nilp *audit.Pending
	nilp.SetIdentity("x", "y", "z")
	nilp.SetOutcome(audit.OutcomeError, "e")
	if a, _, _ := nilp.Identity(); a != "" {
		t.Error("a nil Pending returned an identity")
	}
	if audit.FromContext(httptest.NewRequest("GET", "/", nil).Context()) != nil {
		t.Error("FromContext invented a Pending for a request that has none")
	}
}

// TestLogSinkEmitsEveryEventField: FileSink marshals the whole Event, while
// LogSink names its attributes by hand — so the two can quietly disagree about
// what an audit trail contains, and did. Subject, Email and UserSQL were
// populated by the handlers, documented on Event and written to the file, but
// never reached the logger: on a deployment with `log = true` and no file, the
// SSO identity was simply absent from the trail.
//
// Reflective on purpose. A field added to Event and forgotten in LogSink.Write
// must fail here rather than go missing from somebody's log for a year.
func TestLogSinkEmitsEveryEventField(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	if err := audit.NewLogSink(log).Write(audit.Event{
		Time: time.Now(), Kind: audit.KindStatement, Outcome: audit.OutcomeOK,
		Request: "req-1", Account: "tablex", Subject: "sub-abc", Email: "a@example.com",
		Server: "prod", Engine: "postgres", Remote: "203.0.113.7",
		Method: "POST", Path: "/db/sales/sql", Target: "sales.orders", Status: 200,
		Statement: "DROP TABLE orders", Rows: 3, UserSQL: true,
		Detail: "none", Millis: 12,
	}); err != nil {
		t.Fatalf("LogSink.Write: %v", err)
	}
	out := buf.String()

	// Event.Time is deliberately NOT passed through as an attribute: slog stamps
	// the record's own time, and a second one would be redundant and could
	// disagree.
	exempt := map[string]string{"time": "slog stamps the record time itself"}

	rt := reflect.TypeOf(audit.Event{})
	checked := 0
	for i := range rt.NumField() {
		f := rt.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == "" || tag == "-" {
			continue
		}
		if _, ok := exempt[tag]; ok {
			continue
		}
		checked++
		// Space-delimited so a short key cannot match inside a longer one.
		if !strings.Contains(out, " "+tag+"=") {
			t.Errorf("LogSink never emits %q (Event.%s) — the log sink and the file sink disagree about what the trail holds:\n%s",
				tag, f.Name, out)
		}
	}
	const floor = 15 // Event carried 19 fields when this was written
	if checked < floor {
		t.Fatalf("inspected %d Event fields, expected at least %d — this test is not looking where it thinks", checked, floor)
	}
}

func TestLogSinkEmitsThroughSlog(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	l := audit.New(nil, audit.NewLogSink(log))
	l.Emit(audit.Event{
		Kind: audit.KindStatement, Outcome: audit.OutcomeOK,
		Account: "tablex", Target: "sales.orders", Statement: "DROP TABLE orders", Rows: 3,
		Millis: 12, Time: time.Now(),
	})
	out := buf.String()
	for _, want := range []string{`msg=audit`, `kind=statement`, `account=tablex`, `target=sales.orders`, `rows=3`, `DROP TABLE orders`} {
		if !strings.Contains(out, want) {
			t.Errorf("log sink output missing %q:\n%s", want, out)
		}
	}
}
