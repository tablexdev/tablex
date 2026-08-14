package handlers

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/view"
	"github.com/tablexdev/tablex/web"

	_ "github.com/tablexdev/tablex/internal/driver/mysql"
)

// TestConnErrorStatusAndRedaction pins connError's contract: a connection-open
// failure is a 503 (service condition), not dbError's 400 (bad statement), and
// neither the page nor the log line may echo the session password or the DSN
// that embeds it — a failed dial is the one post-login error that can.
func TestConnErrorStatusAndRedaction(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	var logBuf bytes.Buffer
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&logBuf, nil))}

	d, ok := driver.Get("mysql")
	if !ok {
		t.Fatal("mysql dialect not registered")
	}
	params := driver.ConnParams{Host: "127.0.0.1", Port: 1, User: "u", Password: "s3cr3t-pw"}
	uc := NewUserContext("srv", "srv", d, params, openTestConn(t), nil)
	dsn, err := d.BuildDSN(params)
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}
	// A dial error that echoes both secrets, like a worst-case driver would.
	dialErr := fmt.Errorf("dial tcp 127.0.0.1:1: auth failed for password %q (dsn %s)", params.Password, dsn)

	// Full-page request: real 503 status, redacted body and log.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/db/x", nil)
	h.connError(w, r, uc, dialErr)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("connError full-page status = %d, want 503", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Connection failed") {
		t.Errorf("error page should carry the connection-failure message:\n%.1000s", body)
	}
	for name, leak := range map[string]string{"password": params.Password, "dsn": dsn} {
		if strings.Contains(body, leak) {
			t.Errorf("%s leaked into the error page", name)
		}
		if strings.Contains(logBuf.String(), leak) {
			t.Errorf("%s leaked into the log", name)
		}
	}

	// htmx request: the panel swaps into #page_content at HTTP 200 by design
	// (htmx does not swap non-2xx responses) — but for an unauthenticated
	// request renderError redirects to login instead of rendering a panel.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/db/x", nil)
	r.Header.Set("HX-Request", "true")
	h.connError(w, r, uc, dialErr)
	if w.Code != http.StatusOK {
		t.Errorf("connError htmx status = %d, want 200 (fragment contract)", w.Code)
	}
}

// TestParseFormOr400 pins the H3 contract: an over-cap body yields a semantic
// 413 (full-page → wire 413), a well-formed multipart body is actually parsed
// (its fields read back), and a malformed multipart body yields 400 rather than
// a silently empty form.
func TestParseFormOr400(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}

	// 413: a body over the installed MaxBytesReader cap.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/db/x/sql", strings.NewReader("sql_query="+strings.Repeat("a", 100)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Body = http.MaxBytesReader(w, r.Body, 10)
	if h.parseFormOr400(w, r) {
		t.Error("oversized body: parseFormOr400 = true, want false")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body status = %d, want 413", w.Code)
	}

	// multipart dispatch: a well-formed multipart body parses and the field reads.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("sql_query", "SELECT 1")
	mw.Close()
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/db/x/sql", &buf)
	r2.Header.Set("Content-Type", mw.FormDataContentType())
	if !h.parseFormOr400(w2, r2) {
		t.Fatalf("well-formed multipart: parseFormOr400 = false (status %d)", w2.Code)
	}
	if got := r2.PostFormValue("sql_query"); got != "SELECT 1" {
		t.Errorf("multipart field = %q, want SELECT 1", got)
	}

	// malformed multipart: a bad body yields 400, not a silent empty form.
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodPost, "/db/x/sql", strings.NewReader("not a real multipart body"))
	r3.Header.Set("Content-Type", "multipart/form-data; boundary=zzz")
	if h.parseFormOr400(w3, r3) {
		t.Error("malformed multipart: parseFormOr400 = true, want false")
	}
	if w3.Code != http.StatusBadRequest {
		t.Errorf("malformed multipart status = %d, want 400", w3.Code)
	}
}

// TestDBErrorStagedRedactsOnlyThePreExecutionPath covers #8, whose real content
// turned out to be two mistakes the CALLER could not avoid rather than a pgx
// leak (pgx v5.10.0 prints only user=/database= from a ConnectError and runs
// redactPW over a ParseConfigError, so it cannot emit the password itself).
//
// dropDatabase returns before the DROP when no maintenance connection opens and
// after it when the rebind fails, and the caller rendered BOTH with the DROP
// statement attached — telling a user their DROP had failed when it had never
// been issued. The pre-DROP error is also a failed DIAL, the one kind whose text
// can carry a DSN, and it went through a path that shows err.Error() verbatim.
func TestDBErrorStagedRedactsOnlyThePreExecutionPath(t *testing.T) {
	renderer, err := view.New(web.FS)
	if err != nil {
		t.Fatalf("view.New: %v", err)
	}
	var logBuf bytes.Buffer
	h := &Handlers{View: renderer, Log: slog.New(slog.NewTextHandler(&logBuf, nil))}

	d, ok := driver.Get("mysql")
	if !ok {
		t.Fatal("mysql dialect not registered")
	}
	params := driver.ConnParams{Host: "127.0.0.1", Port: 1, User: "u", Password: "s3cr3t-pw"}
	uc := NewUserContext("srv", "srv", d, params, openTestConn(t), nil)
	dsn, err := d.BuildDSN(params)
	if err != nil {
		t.Fatalf("BuildDSN: %v", err)
	}

	const stmt = "DROP DATABASE `app`"
	req := func() *http.Request { return httptest.NewRequest(http.MethodPost, "/db/app/operations", nil) }

	// Never executed: the maintenance dial failed, so the statement was never
	// issued and the error text can echo the DSN.
	dialErr := &stagedError{Stage: "maintenance-connect", Executed: false,
		Err: fmt.Errorf("cannot drop the database this session is connected to (dial %s: auth failed for password %q)", dsn, params.Password)}
	w := httptest.NewRecorder()
	h.dbErrorStaged(w, req(), uc, dialErr, stmt)
	body := w.Body.String()
	for name, leak := range map[string]string{"password": params.Password, "dsn": dsn} {
		if strings.Contains(body, leak) {
			t.Errorf("%s leaked into the error page", name)
		}
		if strings.Contains(logBuf.String(), leak) {
			t.Errorf("%s leaked into the log", name)
		}
	}
	if strings.Contains(body, "DROP DATABASE") {
		t.Error("a statement that was never issued was shown as though it had been tried")
	}

	// Executed: today's behaviour exactly — the FULL driver message and the
	// statement. Trimming this one to its first line would take back what the
	// user is entitled to see for their own query, which is a decided trade-off.
	ranErr := &stagedError{Stage: "drop", Executed: true,
		Err: errors.New("ERROR: database is being accessed by other users\nDETAIL: there is 1 other session")}
	w = httptest.NewRecorder()
	h.dbErrorStaged(w, req(), uc, ranErr, stmt)
	body = w.Body.String()
	if !strings.Contains(body, "is being accessed by other users") {
		t.Error("the executed path lost the driver message")
	}
	if !strings.Contains(body, "DETAIL: there is 1 other session") {
		t.Error("the executed path was trimmed to its first line; a statement error must stay whole")
	}
	if !strings.Contains(body, "DROP DATABASE") {
		t.Error("the executed path dropped the statement it ran")
	}

	// A bare error (no stage) is treated as executed, so wrapping is opt-in and
	// an unstaged caller keeps dbError's behaviour.
	w = httptest.NewRecorder()
	h.dbErrorStaged(w, req(), uc, errors.New("plain failure"), stmt)
	if !strings.Contains(w.Body.String(), "DROP DATABASE") {
		t.Error("an unstaged error must default to executed")
	}
}
