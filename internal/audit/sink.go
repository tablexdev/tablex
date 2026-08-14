package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// FileSink appends events to a file as JSON Lines: one self-contained JSON object
// per line, which is what every log shipper and every `jq` invocation expects,
// and which stays readable after a truncated write.
type FileSink struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	size     int64
	maxBytes int64
	// closed distinguishes a deliberately Closed sink from one whose rotation
	// reopen failed: only the former refuses writes permanently. Without it,
	// one transient open failure at the rotation boundary (an AV scanner or
	// log shipper briefly holding the path) killed the sink for the life of
	// the process.
	closed bool
	// report receives OUT-OF-BAND failures: a rotation whose rename failed but
	// whose event still landed. Write's own error return means "the event was
	// lost" (the Logger counts it dropped), which a survived rotation is not.
	report func(error)
}

// SetFailureReporter installs fn for out-of-band failures (see the report
// field). Call before the sink is shared; there is no locking around the
// assignment because at that point there is nothing to race.
func (s *FileSink) SetFailureReporter(fn func(error)) { s.report = fn }

// DefaultMaxBytes is the rotation threshold when the operator sets none.
const DefaultMaxBytes int64 = 64 << 20 // 64 MiB

// OpenFile opens (creating if needed) an audit file. The mode is 0600: the file
// records account names, client addresses and — once statement auditing is on —
// SQL that may contain row data, so it is not world-readable. The DIRECTORY must
// already exist; guessing where an operator meant to keep an audit trail is not
// TableX's business.
func OpenFile(path string, maxBytes int64) (*FileSink, error) {
	path = filepath.Clean(path)
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	return &FileSink{f: f, path: path, size: info.Size(), maxBytes: maxBytes}, nil
}

// Write appends one event.
func (s *FileSink) Write(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		if s.closed {
			return fs.ErrClosed
		}
		// Fileless but not Closed: a rotation's reopen failed (rotateLocked
		// clears s.f before renaming). The condition can be transient, so
		// retry on every write — each failure is still returned (and counted
		// dropped), but the first success revives the trail instead of one
		// bad moment at the rotation boundary silencing it forever.
		f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("audit: reopening %s: %w", s.path, err)
		}
		s.f, s.size = f, 0
		if info, statErr := f.Stat(); statErr == nil {
			// Track the true length or the next write re-enters rotation.
			s.size = info.Size()
		}
	}
	if s.size+int64(len(line)) > s.maxBytes {
		// A failed rotation must cost at most the ROTATION, never the event:
		// rotateLocked reopens a usable file on every path it can (a failed
		// rename falls through to the original), so the line is appended
		// whenever one is open and the rotation failure is surfaced out of
		// band. Returning the error before writing dropped one event per
		// rotation attempt — against rotateLocked's own contract that this is
		// a floor against filling a disk, not a retention policy.
		reopened, rerr := s.rotateLocked()
		if !reopened {
			return rerr
		}
		if rerr != nil && s.report != nil {
			s.report(rerr)
		}
	}
	n, err := s.f.Write(line)
	s.size += int64(n)
	return err
}

// rotateLocked renames the current file to "<path>.1" and starts a fresh one.
//
// Exactly one generation is kept, deliberately: this is a floor that stops an
// unattended TableX filling a disk, not a retention policy. An operator who needs
// retention should point this at a path their own log rotation handles, or ship
// the lines elsewhere — which is the normal arrangement and is why the format is
// JSON Lines.
// reopened reports whether a usable file is open on return — SEPARATELY from
// the error, so Write can append the event a merely-failed rename (a
// root-owned directory, a Windows log shipper holding <path>.1) would
// otherwise cost. The close error clears s.f and falls through to the reopen
// too: returning with the closed handle still in place left every later
// write failing forever.
func (s *FileSink) rotateLocked() (reopened bool, err error) {
	closeErr := s.f.Close()
	s.f = nil
	// A failed rename must not leave the sink without a file: fall through and
	// reopen the original path either way, so the worst case is a file that grows
	// past the threshold rather than an audit trail that has stopped.
	renameErr := os.Rename(s.path, s.path+".1")
	f, openErr := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if openErr != nil {
		return false, fmt.Errorf("audit: reopening %s after rotation: %w", s.path, openErr)
	}
	s.f, s.size = f, 0
	if renameErr != nil {
		if info, statErr := f.Stat(); statErr == nil {
			// The original is still in place (and reopened): size must track
			// its true length, or every later write re-enters rotation.
			s.size = info.Size()
		}
		return true, fmt.Errorf("audit: rotating %s: %w", s.path, renameErr)
	}
	if closeErr != nil {
		return true, fmt.Errorf("audit: closing %s during rotation: %w", s.path, closeErr)
	}
	return true, nil
}

// Close closes the file. Only Close makes the sink refuse writes permanently
// (see the closed field).
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// LogSink writes events through an *slog.Logger, which on a standard deployment
// means stderr — and therefore the container's log stream, journald, or whatever
// the operator already collects. It is how syslog is reached without TableX
// speaking syslog: log/syslog does not build on Windows, and a hand-rolled RFC
// 5424 client would be a network dependency for something every host already has
// a collector for.
type LogSink struct {
	log   *slog.Logger
	level slog.Level
}

// NewLogSink returns a sink over log. Events are emitted at INFO with the message
// "audit", so they are trivially separable from the access log's "request".
func NewLogSink(log *slog.Logger) *LogSink {
	return &LogSink{log: log, level: slog.LevelInfo}
}

// Write emits one event as structured attributes.
func (s *LogSink) Write(e Event) error {
	if s.log == nil {
		return nil
	}
	attrs := []any{"kind", string(e.Kind), "outcome", string(e.Outcome)}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, k, v)
		}
	}
	add("request", e.Request)
	add("account", e.Account)
	// The PERSON, when an SSO gate is configured. FileSink marshals the whole
	// Event, so leaving these out here made the two sinks disagree about what an
	// audit trail contains: on a deployment with `log = true` and no file, the
	// provider identity never reached the trail at all.
	add("subject", e.Subject)
	add("email", e.Email)
	add("server", e.Server)
	add("engine", e.Engine)
	add("remote", e.Remote)
	add("method", e.Method)
	add("path", e.Path)
	add("target", e.Target)
	if e.Status != 0 {
		attrs = append(attrs, "status", e.Status)
	}
	add("statement", e.Statement)
	if e.Rows != 0 {
		attrs = append(attrs, "rows", e.Rows)
	}
	// Only when true: it marks SQL the user WROTE rather than SQL TableX
	// generated for them, and "user_sql=false" on every generated statement
	// would be noise. Matches the omitempty the JSON sink gives it.
	if e.UserSQL {
		attrs = append(attrs, "user_sql", true)
	}
	add("detail", e.Detail)
	if e.Millis != 0 {
		attrs = append(attrs, "ms", e.Millis)
	}
	s.log.Log(context.Background(), s.level, "audit", attrs...)
	return nil
}

// Close is a no-op: the logger's writer is owned by the process.
func (s *LogSink) Close() error { return nil }
