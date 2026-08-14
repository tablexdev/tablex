package handlers

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
)

// TestLoginRateKeys pins the throttle key set, including the #26 bypass fix:
// blanking/rotating the posted username on a selected predefined server still
// yields a per-(IP, predefined-server) key, so the attempt is still counted.
func TestLoginRateKeys(t *testing.T) {
	// Ad-hoc with username: per-IP + per-(IP,user).
	got := loginRateKeys("1.2.3.4", "Root", "")
	wantContains(t, got, "1.2.3.4", "1.2.3.4|root")
	if len(got) != 2 {
		t.Fatalf("ad-hoc keys = %v, want 2", got)
	}

	// Predefined server with a BLANK username: per-IP + per-(IP,predef) — the
	// per-(IP,user) key is correctly absent, but the predefined key remains.
	got = loginRateKeys("1.2.3.4", "", "prod-db")
	wantContains(t, got, "1.2.3.4", "1.2.3.4|predef:prod-db")
	for _, k := range got {
		if strings.HasPrefix(k, "1.2.3.4|") && !strings.HasPrefix(k, "1.2.3.4|predef:") {
			t.Errorf("blank username should not add a per-(IP,user) key, got %q", k)
		}
	}

	// Predefined server WITH a username: all three keys.
	got = loginRateKeys("1.2.3.4", "admin", "prod-db")
	wantContains(t, got, "1.2.3.4", "1.2.3.4|admin", "1.2.3.4|predef:prod-db")
}

// TestLoginRateKeysBounded covers: the posted username was embedded in the
// limiter key verbatim, bounded only by the 1 MiB pre-auth body cap — so each
// attempt could plant a kilobytes-wide key in a map the sweeper prunes only
// every few minutes.
func TestLoginRateKeysBounded(t *testing.T) {
	long := strings.Repeat("a", 4096)
	for _, k := range loginRateKeys("1.2.3.4", long, strings.Repeat("s", 4096)) {
		if len(k) > len("1.2.3.4|predef:")+maxRateKeyPart {
			t.Errorf("limiter key is %d bytes; the attacker-controlled part is unbounded: %.80q…", len(k), k)
		}
	}

	// Real account names are untouched — 64 bytes is MySQL's identifier maximum.
	name := strings.Repeat("u", maxRateKeyPart)
	keys := loginRateKeys("1.2.3.4", name, "")
	wantContains(t, keys, "1.2.3.4|"+name)

	// The cut lands on a rune boundary, so a key never carries half a rune.
	multi := strings.Repeat("é", 64) // 128 bytes
	if got := boundRateKeyPart(multi); !utf8.ValidString(got) {
		t.Errorf("bounded key part split a rune: %q", got)
	}
}

func wantContains(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("rate keys %v missing %q", got, w)
		}
	}
}

// TestRedactConnError proves the log-safe error rendering strips the supplied
// secrets (posted/effective passwords and the full DSN, which embeds the
// password) so credentials never reach the log, while keeping a useful clause.
func TestRedactConnError(t *testing.T) {
	pw := "s3cr3t-pw"
	dsn := "user:s3cr3t-pw@tcp(db.internal:3306)/app?tls=skip-verify"
	err := errors.New("dial tcp db.internal:3306: connect: connection refused (dsn " + dsn + ")")
	out := redactConnError(err, pw, dsn)
	if strings.Contains(out, pw) {
		t.Errorf("redacted error still contains the password: %q", out)
	}
	if strings.Contains(out, dsn) {
		t.Errorf("redacted error still contains the DSN: %q", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Errorf("redacted error dropped the useful clause: %q", out)
	}

	// A percent-encoded password (postgres URL DSNs escape specials) makes the
	// DSN needle textually DIFFERENT from the raw password: password redaction
	// alone cannot rewrite it, so this case exercises the dsn-substring
	// removal on its own. (With an identical spelling, the password pass
	// already rewrites the DSN and the dsn needle is vacuous.)
	encPW := "p@ss w0rd"
	encDSN := "postgres://user:p%40ss%20w0rd@db.internal:5432/app?sslmode=require"
	encErr := errors.New("pgx dial failed for " + encDSN + ": connection refused")
	out = redactConnError(encErr, encPW, encDSN)
	if strings.Contains(out, "p%40ss%20w0rd") || strings.Contains(out, encDSN) {
		t.Errorf("redacted error still contains the percent-encoded DSN: %q", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Errorf("redacted error dropped the useful clause: %q", out)
	}

	// Multi-line errors keep only the first clause.
	multi := errors.New("first line\nsecond line with " + pw)
	if out := redactConnError(multi, pw); strings.Contains(out, "second line") {
		t.Errorf("multi-line error not trimmed to first clause: %q", out)
	}

	// Empty secrets and a nil error are handled.
	if redactConnError(nil, pw) != "" {
		t.Error("nil error should redact to empty string")
	}
}

// TestSSLModeFor pins the capability gate (Capabilities().ShowsSSLModeUI):
// only an engine whose login form exposes the sslmode selector receives the
// posted value. Both network engines do now — MySQL's dialect maps every token
// it accepts, so discarding the value produced plaintext under a control that
// said otherwise. SQLite still gets "", and always will: it has no transport.
func TestSSLModeFor(t *testing.T) {
	cases := []struct {
		engine, sslmode, want string
	}{
		{"postgres", "prefer", "prefer"},
		{"postgres", "verify-full", "verify-full"},
		{"postgres", "", ""},
		{"mysql", "prefer", "prefer"},
		{"mysql", "require", "require"},
		{"sqlite", "prefer", ""},
	}
	for _, c := range cases {
		d, ok := driver.Get(c.engine)
		if !ok {
			t.Fatalf("dialect %s not registered", c.engine)
		}
		if got := sslModeFor(d, c.sslmode); got != c.want {
			t.Errorf("sslModeFor(%q, %q) = %q, want %q", c.engine, c.sslmode, got, c.want)
		}
	}
}

// TestLoginViewModelIsEngineAgnostic pins: the login form is built from the
// registry and Capabilities().IsNetworkEngine, with no engine named in the
// handler. A file-backed engine is never offered for ad-hoc login (that would
// be an unauthenticated arbitrary file open), and the pre-selected engine and
// port are simply the first offered engine's — not the literals "mysql"/"3306"
// the handler used to carry.
func TestLoginViewModelIsEngineAgnostic(t *testing.T) {
	h := &Handlers{Cfg: config.Default()}
	h.Cfg.Security.AllowAdHoc = true
	h.Cfg.Servers = []config.ServerConfig{
		{Name: "file", Engine: "sqlite", FilePath: "/data/app.db"},
		{Name: "net", Engine: "postgres", Host: "db.example"},
		{Name: "net-with-creds", Engine: "postgres", Host: "db.example", User: "u", Password: "p"},
	}
	vm := h.loginViewModel()

	if len(vm.Engines) == 0 {
		t.Fatal("no engines offered")
	}
	for _, e := range vm.Engines {
		d, ok := driver.Get(e.Name)
		if !ok {
			t.Errorf("offered engine %q is not registered", e.Name)
			continue
		}
		if !d.Capabilities().IsNetworkEngine {
			t.Errorf("engine %q is file-backed and must not be offered for ad-hoc login", e.Name)
		}
	}

	// The default selection tracks the first offered engine rather than a
	// hardcoded name, so removing or adding an engine cannot leave the form
	// pre-selecting one that is no longer offered.
	first := vm.Engines[0]
	if vm.Engine != first.Name {
		t.Errorf("default engine = %q, want the first offered engine %q", vm.Engine, first.Name)
	}
	if want := strconv.Itoa(first.DefaultPort); first.DefaultPort > 0 && vm.Port != want {
		t.Errorf("default port = %q, want %q (%s's default)", vm.Port, want, first.Name)
	}

	// Credentials are collected only for network engines whose config leaves
	// the field empty.
	byName := map[string]serverOption{}
	for _, s := range vm.Servers {
		byName[s.Name] = s
	}
	if s := byName["file"]; s.NeedsUser || s.NeedsPassword {
		t.Errorf("file-backed server asks for credentials: %+v", s)
	}
	if s := byName["net"]; !s.NeedsUser || !s.NeedsPassword {
		t.Errorf("network server with no configured credentials should ask for both: %+v", s)
	}
	if s := byName["net-with-creds"]; s.NeedsUser || s.NeedsPassword {
		t.Errorf("network server with configured credentials should ask for neither: %+v", s)
	}
}

// TestIsNetworkEngineUnregistered pins the defensive answer for a name config
// validation would have rejected: false, so the form does not prompt for
// credentials it could never use.
func TestIsNetworkEngineUnregistered(t *testing.T) {
	if isNetworkEngine("no-such-engine") {
		t.Error("an unregistered engine must not be treated as a network engine")
	}
}

// TestParamsFromConfig proves the predefined-server contract (H4): only user and
// password are collectible at login (resolved via firstNonEmpty); the connection
// topology — database/sslmode/file — comes solely from config, never from a
// posted value. paramsFromConfig is pure, so this needs no database.
func TestParamsFromConfig(t *testing.T) {
	cases := []struct {
		name                    string
		sc                      config.ServerConfig
		user, password          string
		wantUser, wantPass      string
		wantDB, wantSSL, wantFP string
	}{
		{
			name:     "config topology used verbatim; login supplies creds",
			sc:       config.ServerConfig{Engine: "postgres", Host: "h", Database: "app", SSLMode: "require"},
			user:     "alice",
			password: "secret",
			wantUser: "alice", wantPass: "secret", wantDB: "app", wantSSL: "require",
		},
		{
			name:     "config user/password win over posted",
			sc:       config.ServerConfig{Engine: "mysql", User: "cfguser", Password: "cfgpass"},
			user:     "posted",
			password: "posted",
			wantUser: "cfguser", wantPass: "cfgpass",
		},
		{
			name:     "empty config sslmode/database stay empty (no posted fallback)",
			sc:       config.ServerConfig{Engine: "postgres"},
			user:     "u",
			password: "p",
			wantUser: "u", wantPass: "p",
		},
		{
			name:   "sqlite ignores posted creds and topology",
			sc:     config.ServerConfig{Engine: "sqlite", FilePath: "/data/app.db"},
			user:   "x",
			wantFP: "/data/app.db",
		},
	}
	for _, c := range cases {
		d, ok := driver.Get(c.sc.Engine)
		if !ok {
			t.Fatalf("%s: dialect %s not registered", c.name, c.sc.Engine)
		}
		params := paramsFromConfig(d, c.sc, c.user, c.password)
		if params.User != c.wantUser {
			t.Errorf("%s: User = %q, want %q", c.name, params.User, c.wantUser)
		}
		if params.Password != c.wantPass {
			t.Errorf("%s: Password = %q, want %q", c.name, params.Password, c.wantPass)
		}
		if params.Database != c.wantDB {
			t.Errorf("%s: Database = %q, want %q", c.name, params.Database, c.wantDB)
		}
		if params.SSLMode != c.wantSSL {
			t.Errorf("%s: SSLMode = %q, want %q", c.name, params.SSLMode, c.wantSSL)
		}
		if params.FilePath != c.wantFP {
			t.Errorf("%s: FilePath = %q, want %q", c.name, params.FilePath, c.wantFP)
		}
	}
}

// TestSSLModeNoteIsPerEngine: the sslmode vocabulary is shared and the
// BEHAVIOUR is not, which is the whole reason the selector could not simply be
// switched on for MySQL without a note beside it. `prefer` falls back to
// plaintext on both, but `require` authenticates the server on NEITHER — and on
// MySQL the twelve accepted tokens collapse to four behaviours.
//
// Sourced from Capabilities, not LoginFormHinter: that interface is scoped to
// the login form's DATABASE field, and MySQL lists it under "deliberately not
// implemented" because the generic database field needs no engine wording.
func TestSSLModeNoteIsPerEngine(t *testing.T) {
	notes := map[string]string{}
	for _, engine := range []string{"postgres", "mysql"} {
		d, ok := driver.Get(engine)
		if !ok {
			t.Fatalf("dialect %s not registered", engine)
		}
		caps := d.Capabilities()
		if !caps.ShowsSSLModeUI {
			t.Errorf("%s does not show the sslmode selector", engine)
		}
		if caps.SSLModeNote == "" {
			t.Errorf("%s shows the sslmode selector with no note explaining what its values mean", engine)
		}
		notes[engine] = caps.SSLModeNote
	}
	if notes["postgres"] == notes["mysql"] {
		t.Error("both engines carry the SAME note; the point is that the behaviour differs")
	}
	// SQLite has no transport at all, so it must offer neither.
	if d, ok := driver.Get("sqlite"); ok {
		if caps := d.Capabilities(); caps.ShowsSSLModeUI || caps.SSLModeNote != "" {
			t.Error("SQLite offers an sslmode control")
		}
	}
}
