package config

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"

	// Validate now checks a predefined server's engine against the driver
	// registry rather than a config-local copy of the engine list, so these
	// tests must register the dialects the way package main does.
	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.Listen != ":8080" {
		t.Errorf("default listen = %q", c.Listen)
	}
	if !c.Security.AllowAdHoc {
		t.Error("ad-hoc login should default on")
	}
	if c.Session.IdleTimeout != 30*time.Minute {
		t.Errorf("idle timeout = %v", c.Session.IdleTimeout)
	}
}

func TestLoadFlagsOverride(t *testing.T) {
	c, err := Load([]string{"-listen", "127.0.0.1:9000"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != "127.0.0.1:9000" {
		t.Errorf("listen = %q", c.Listen)
	}
	if !c.Security.AllowAdHoc {
		t.Error("ad-hoc should remain enabled by default")
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("TABLEX_LISTEN", "0.0.0.0:7777")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != "0.0.0.0:7777" {
		t.Errorf("env listen = %q", c.Listen)
	}
}

func TestPerformanceKnobs(t *testing.T) {
	c := Default()
	if c.MaxExactCount != 50000 {
		t.Errorf("default max_exact_count = %d, want 50000", c.MaxExactCount)
	}
	if c.PoolCap != 32 {
		t.Errorf("default pool_cap = %d, want 32", c.PoolCap)
	}
	// Pool sizing, the generated-read budget and the in-flight cap on
	// private-connection operations are all operator-tunable, defaulted to the
	// values that used to be hardcoded.
	if c.PoolMaxConns != 8 || c.PoolIdleConns != 4 {
		t.Errorf("default pool sizing = %d/%d, want 8/4", c.PoolMaxConns, c.PoolIdleConns)
	}
	if c.ReadStmtTimeout != 60*time.Second {
		t.Errorf("default read_stmt_timeout = %v, want 1m", c.ReadStmtTimeout)
	}
	if c.MaxConcurrentDBOps != 16 {
		t.Errorf("default max_concurrent_db_ops = %d, want 16", c.MaxConcurrentDBOps)
	}

	t.Setenv("TABLEX_MAX_EXACT_COUNT", "1234")
	t.Setenv("TABLEX_POOL_CAP", "5")
	t.Setenv("TABLEX_POOL_MAX_CONNS", "3")
	t.Setenv("TABLEX_POOL_IDLE_CONNS", "2")
	t.Setenv("TABLEX_MAX_CONCURRENT_DB_OPS", "4")
	t.Setenv("TABLEX_READ_STMT_TIMEOUT", "90s")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.MaxExactCount != 1234 {
		t.Errorf("env max_exact_count = %d", c.MaxExactCount)
	}
	if c.PoolCap != 5 {
		t.Errorf("env pool_cap = %d", c.PoolCap)
	}
	if c.PoolMaxConns != 3 || c.PoolIdleConns != 2 {
		t.Errorf("env pool sizing = %d/%d, want 3/2", c.PoolMaxConns, c.PoolIdleConns)
	}
	if c.MaxConcurrentDBOps != 4 {
		t.Errorf("env max_concurrent_db_ops = %d", c.MaxConcurrentDBOps)
	}
	if c.ReadStmtTimeout != 90*time.Second {
		t.Errorf("env read_stmt_timeout = %v, want 1m30s", c.ReadStmtTimeout)
	}

	// A garbage env value refuses startup (fail-closed) rather than silently
	// keeping the previous value, which would erase the evidence of a typo.
	t.Setenv("TABLEX_MAX_EXACT_COUNT", "lots")
	if _, err := Load(nil); err == nil {
		t.Error("malformed TABLEX_MAX_EXACT_COUNT should refuse startup")
	}
	t.Setenv("TABLEX_MAX_EXACT_COUNT", "1234")
	t.Setenv("TABLEX_POOL_CAP", "notanumber")
	if _, err := Load(nil); err == nil {
		t.Error("malformed TABLEX_POOL_CAP should refuse startup")
	}
}

// TestDurationKnobs covers TABLEX_IDLE_TIMEOUT / TABLEX_ABSOLUTE_TIMEOUT: a
// valid value overrides; a malformed value refuses startup (M1 fail-closed).
func TestDurationKnobs(t *testing.T) {
	t.Setenv("TABLEX_IDLE_TIMEOUT", "45m")
	t.Setenv("TABLEX_ABSOLUTE_TIMEOUT", "12h")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Session.IdleTimeout != 45*time.Minute {
		t.Errorf("idle timeout = %v, want 45m", c.Session.IdleTimeout)
	}
	if c.Session.AbsoluteTimeout != 12*time.Hour {
		t.Errorf("absolute timeout = %v, want 12h", c.Session.AbsoluteTimeout)
	}

	t.Setenv("TABLEX_IDLE_TIMEOUT", "garbage")
	if _, err := Load(nil); err == nil {
		t.Error("malformed TABLEX_IDLE_TIMEOUT should refuse startup")
	}
}

// TestParseHelpers exercises the parse helpers directly: the widened boolean
// vocabulary is accepted and any other token is a hard error (M1 fail-closed).
func TestParseHelpers(t *testing.T) {
	for _, s := range []string{"true", "on", "yes", "1", "TRUE", "Off", "no"} {
		if _, err := parseBool(s); err != nil {
			t.Errorf("parseBool(%q) should be valid: %v", s, err)
		}
	}
	for _, s := range []string{"notabool", "", "maybe", "2"} {
		if _, err := parseBool(s); err == nil {
			t.Errorf("parseBool(%q) should error", s)
		}
	}
	if b, err := parseBool("no"); err != nil || b {
		t.Errorf("parseBool(no) = %v,%v want false,nil", b, err)
	}
	if _, err := parseDuration("nope"); err == nil {
		t.Error("parseDuration(garbage) should error")
	}
	if d, err := parseDuration("90s"); err != nil || d != 90*time.Second {
		t.Errorf("parseDuration(90s) = %v,%v want 90s,nil", d, err)
	}
	if _, err := parseInt("lots"); err == nil {
		t.Error("parseInt(garbage) should error")
	}
	if n, err := parseInt("42"); err != nil || n != 42 {
		t.Errorf("parseInt(42) = %v,%v want 42,nil", n, err)
	}
}

// TestMalformedAllowAdhocFlag covers the flag-override path (M1): a bad
// -allow-adhoc value refuses startup instead of silently keeping the default,
// and the widened vocabulary ("no") is actually applied (not dropped).
func TestMalformedAllowAdhocFlag(t *testing.T) {
	// A valid true token loads (ad-hoc stays enabled).
	if _, err := Load([]string{"-allow-adhoc=true"}); err != nil {
		t.Errorf("-allow-adhoc=true should load: %v", err)
	}
	// "no" parses to false (before M1 it was silently ignored, keeping the
	// default true). With no predefined servers Validate then rejects it — the
	// no-login error proves the flag was applied, not a parse failure.
	_, err := Load([]string{"-allow-adhoc=no"})
	if err == nil || strings.Contains(err.Error(), "invalid boolean") {
		t.Errorf("-allow-adhoc=no should parse to false and fail validation, got %v", err)
	}
	// A token outside the accepted vocabulary is a hard parse error.
	_, err = Load([]string{"-allow-adhoc=bogus"})
	if err == nil || !strings.Contains(err.Error(), "invalid boolean") {
		t.Errorf("malformed -allow-adhoc should be a parse error, got %v", err)
	}
}

// TestUnexpectedArgRejected covers Theme N: stdlib flag stops at the first
// non-flag argument (silently dropping later flags), so a stray positional arg
// must refuse startup.
func TestUnexpectedArgRejected(t *testing.T) {
	if _, err := Load([]string{"unexpected"}); err == nil {
		t.Error("a stray positional argument should refuse startup")
	}
	// A flag after a stray arg is dropped by stdlib flag, so this must also error.
	if _, err := Load([]string{"stray", "-listen=:9999"}); err == nil {
		t.Error("a stray arg before a flag should refuse startup")
	}
	// -version still short-circuits before the arg check.
	if _, err := Load([]string{"-version", "extra"}); !IsVersionRequest(err) {
		t.Errorf("-version should short-circuit, got %v", err)
	}
}

// TestHealthcheckFlag covers the container HEALTHCHECK path (Theme P): -healthcheck
// short-circuits before Validate (so it works regardless of login/server policy)
// and carries the resolved listen address.
func TestHealthcheckFlag(t *testing.T) {
	t.Setenv("TABLEX_LISTEN", "127.0.0.1:9123")
	cfg, err := Load([]string{"-healthcheck"})
	if !IsHealthcheckRequest(err) {
		t.Fatalf("Load(-healthcheck) err = %v, want healthcheck sentinel", err)
	}
	if cfg.Listen != "127.0.0.1:9123" {
		t.Errorf("healthcheck cfg.Listen = %q, want the resolved listen addr", cfg.Listen)
	}
}

func TestTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("TABLEX_TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 172.17.0.1 ,")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Security.TrustedProxyCIDRs) != 2 ||
		c.Security.TrustedProxyCIDRs[0] != "10.0.0.0/8" ||
		c.Security.TrustedProxyCIDRs[1] != "172.17.0.1" {
		t.Errorf("env trusted_proxy_cidrs = %v", c.Security.TrustedProxyCIDRs)
	}

	bad := Default()
	bad.Security.TrustedProxyCIDRs = []string{"definitely-not-a-cidr"}
	if err := bad.Validate(); err == nil {
		t.Error("invalid trusted_proxy_cidrs entry should fail validation")
	}

	// Bare trusted_proxy without CIDRs warns (XFF stays untrusted).
	w := Default()
	w.Security.TrustedProxy = true
	warned := false
	for _, msg := range w.Warnings() {
		if strings.Contains(msg, "trusted_proxy_cidrs") {
			warned = true
		}
	}
	if !warned {
		t.Error("trusted_proxy without CIDRs should produce a startup warning")
	}
}

// TestSSLModeWarnings covers: sslmode = "require" reads as the strict option
// and does force TLS, but it authenticates nothing — no CA chain, no hostname
// check — so it gives no protection against a man-in-the-middle. That is libpq
// parity, hence an advisory rather than an error, but an operator who wrote it
// in tablex.toml expected otherwise and only a startup warning says so.
func TestSSLModeWarnings(t *testing.T) {
	warnFor := func(mode string) string {
		c := Default()
		c.Servers = []ServerConfig{{Name: "db1", Engine: "postgres", Host: "h", SSLMode: mode}}
		for _, msg := range c.Warnings() {
			if strings.Contains(msg, "sslmode") {
				return msg
			}
		}
		return ""
	}

	for _, mode := range []string{"require", "REQUIRE", " require ", "skip-verify", "skip_verify", "prefer", "allow", "preferred"} {
		msg := warnFor(mode)
		if msg == "" {
			t.Errorf("sslmode = %q produced no warning", mode)
			continue
		}
		if !strings.Contains(msg, `"db1"`) {
			t.Errorf("sslmode warning for %q does not name the server: %s", mode, msg)
		}
		if !strings.Contains(msg, "verify-full") {
			t.Errorf("sslmode warning for %q does not point at the fix: %s", mode, msg)
		}
	}

	// The modes that DO authenticate the server, and the zero-config empty
	// value (plaintext to a local database), must stay quiet — a warning on
	// those would bury the ones that look secure and aren't.
	for _, mode := range []string{"", "verify-full", "verify-ca", "true", "disable", "false"} {
		if msg := warnFor(mode); msg != "" {
			t.Errorf("sslmode = %q should not warn, got: %s", mode, msg)
		}
	}
}

func TestFlagBeatsEnv(t *testing.T) {
	t.Setenv("TABLEX_LISTEN", "0.0.0.0:7777")
	c, err := Load([]string{"-listen", ":1234"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != ":1234" {
		t.Errorf("flag should beat env: %q", c.Listen)
	}
}

// TestTOMLLoadAndPrecedence exercises the whole TOML tier, which the other
// precedence tests never load: scalar/duration decoding, the [session] and
// [security] tables, [[servers]] array decoding, the Load-time host
// canonicalization, and the default < TOML < env < flag ordering on a real
// conflict.
func TestTOMLLoadAndPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tablex.toml")
	content := `
listen = ":7000"
max_exact_count = 123

[session]
cookie_name  = "toml_cookie"
idle_timeout = "45m"

[security]
allow_adhoc    = true
block_private  = true
host_allowlist = ["db.internal", "[2001:db8::7]"]

[[servers]]
name   = "app"
engine = "sqlite"
file   = "/data/app.db"

[[servers]]
name = "pg"
engine = "postgres"
host = "[::1]"
port = 5433
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	// TOML alone overrides the defaults.
	c, err := Load([]string{"-config", path})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != ":7000" {
		t.Errorf("listen = %q, want TOML value :7000", c.Listen)
	}
	if c.MaxExactCount != 123 {
		t.Errorf("max_exact_count = %d, want 123", c.MaxExactCount)
	}
	if c.Session.CookieName != "toml_cookie" {
		t.Errorf("cookie_name = %q, want toml_cookie", c.Session.CookieName)
	}
	if c.Session.IdleTimeout != 45*time.Minute {
		t.Errorf("idle_timeout = %v, want 45m", c.Session.IdleTimeout)
	}
	if !c.Security.BlockPrivate {
		t.Error("block_private not decoded from TOML")
	}
	if len(c.Servers) != 2 || c.Servers[0].Name != "app" || c.Servers[0].FilePath != "/data/app.db" ||
		c.Servers[1].Engine != "postgres" || c.Servers[1].Port != 5433 {
		t.Errorf("servers not decoded: %+v", c.Servers)
	}
	// Load canonicalizes bracketed IPv6 spellings in the lists and server hosts.
	if len(c.Security.HostAllowlist) != 2 || c.Security.HostAllowlist[1] != "2001:db8::7" {
		t.Errorf("allowlist not canonicalized: %v", c.Security.HostAllowlist)
	}
	if c.Servers[1].Host != "::1" {
		t.Errorf("server host not canonicalized: %q", c.Servers[1].Host)
	}

	// Env beats TOML; flag beats both.
	t.Setenv("TABLEX_LISTEN", ":7100")
	if c, err = Load([]string{"-config", path}); err != nil || c.Listen != ":7100" {
		t.Errorf("env should beat TOML: %q (%v)", c.Listen, err)
	}
	if c, err = Load([]string{"-config", path, "-listen", ":7200"}); err != nil || c.Listen != ":7200" {
		t.Errorf("flag should beat env and TOML: %q (%v)", c.Listen, err)
	}
	// Untouched keys keep the TOML tier under the overrides.
	if c.MaxExactCount != 123 || c.Session.CookieName != "toml_cookie" {
		t.Errorf("overrides clobbered unrelated TOML values: %d %q", c.MaxExactCount, c.Session.CookieName)
	}
}

func TestValidate(t *testing.T) {
	c := Default()
	c.TLSCert = "cert.pem" // key missing
	if err := c.Validate(); err == nil {
		t.Error("TLS cert without key should be invalid")
	}

	c = Default()
	c.Security.AllowAdHoc = false // and no predefined servers
	if err := c.Validate(); err == nil {
		t.Error("no ad-hoc and no servers should be invalid (nobody could log in)")
	}

	c = Default()
	c.Servers = []ServerConfig{{Name: "a", Engine: "mysql"}, {Name: "a", Engine: "sqlite"}}
	if err := c.Validate(); err == nil {
		t.Error("duplicate server names should be invalid")
	}
}

// TestValidateRejectsInMemorySQLite covers #7: an in-memory SQLite predefined
// server cannot work behind the connection pool (each pooled or transient
// connection opens its own private empty database), so config validation
// refuses every in-memory spelling with a clear error instead of shipping a
// server that appears empty or inconsistent.
func TestValidateRejectsInMemorySQLite(t *testing.T) {
	for _, file := range []string{
		":memory:",
		"file::memory:",
		"file::memory:?cache=shared",
		"file:mem.db?mode=memory&cache=shared",
	} {
		c := Default()
		c.Servers = []ServerConfig{{Name: "mem", Engine: "sqlite", FilePath: file}}
		if err := c.Validate(); err == nil {
			t.Errorf("in-memory sqlite file %q should be rejected", file)
		} else if !strings.Contains(err.Error(), "in-memory") {
			t.Errorf("rejection for %q should explain the in-memory limitation, got: %v", file, err)
		}
	}
	// A real file path stays valid.
	c := Default()
	c.Servers = []ServerConfig{{Name: "ok", Engine: "sqlite", FilePath: "/data/app.db"}}
	if err := c.Validate(); err != nil {
		t.Errorf("file-backed sqlite server should validate: %v", err)
	}
}

// TestValidateLoginRateWindow covers #58: a non-positive window with throttling
// on silently disables brute-force protection, so it must be rejected — while a
// disabled limiter (max <= 0) stays valid for any window.
func TestValidateLoginRateWindow(t *testing.T) {
	c := Default()
	c.Security.LoginRateMax = 10
	c.Security.LoginRateWindow = 0
	if err := c.Validate(); err == nil {
		t.Error("login_rate_max > 0 with a zero window must be rejected (throttling silently disabled)")
	}
	c.Security.LoginRateWindow = -time.Minute
	if err := c.Validate(); err == nil {
		t.Error("login_rate_max > 0 with a negative window must be rejected")
	}

	// max <= 0 deliberately disables limiting; any window must validate.
	c = Default()
	c.Security.LoginRateMax = 0
	c.Security.LoginRateWindow = 0
	if err := c.Validate(); err != nil {
		t.Errorf("disabled limiter (max=0) must validate for any window: %v", err)
	}

	// The default (max>0, positive window) is valid.
	if err := Default().Validate(); err != nil {
		t.Errorf("default config must validate: %v", err)
	}
}

func TestServerByName(t *testing.T) {
	c := Default()
	c.Servers = []ServerConfig{{Name: "local", Engine: "sqlite", FilePath: "/tmp/a.db"}}
	if s, ok := c.ServerByName("local"); !ok || s.Engine != "sqlite" {
		t.Errorf("ServerByName failed: %+v ok=%v", s, ok)
	}
	if _, ok := c.ServerByName("nope"); ok {
		t.Error("unknown server should not be found")
	}
}

// TestValidateEnginesComeFromTheRegistry pins: the engine allowlist IS the
// driver registry, so registering a fifth dialect makes it configurable with no
// edit to this package. Previously a config-local map and a hand-written error
// string both had to be updated, and a new engine failed validation until they
// were.
func TestValidateEnginesComeFromTheRegistry(t *testing.T) {
	names := driver.RegisteredNames()
	if len(names) == 0 {
		t.Fatal("no dialects registered; this test file must blank-import them")
	}
	for _, name := range names {
		s := ServerConfig{Name: "s", Engine: name}
		if d, ok := driver.Get(name); ok && !d.Capabilities().IsNetworkEngine {
			s.FilePath = "/data/app.db" // file-backed engines need a path
		}
		c := Default()
		c.Servers = []ServerConfig{s}
		if err := c.Validate(); err != nil {
			t.Errorf("registered engine %q rejected by config validation: %v", name, err)
		}
	}

	c := Default()
	c.Servers = []ServerConfig{{Name: "s", Engine: "no-such-engine"}}
	err := c.Validate()
	if err == nil {
		t.Fatal("an unregistered engine must be rejected")
	}
	// The message enumerates the registry, so it can never go stale.
	for _, name := range names {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("rejection message omits registered engine %q: %v", name, err)
		}
	}
}

// TestValidateFilePathIsDelegated pins that the file-path rules for a
// file-backed engine come from the dialect (driver.FilePathValidator), not from
// an engine name branch in this package.
func TestValidateFilePathIsDelegated(t *testing.T) {
	c := Default()
	c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite"}}
	if err := c.Validate(); err == nil {
		t.Error("a file-backed server with no file path must be rejected")
	} else if !strings.Contains(err.Error(), "file path") {
		t.Errorf("rejection should name the missing file path: %v", err)
	}
}

// TestValidateRejectsSQLiteTimeConversionParams covers #42: an ENABLED
// _texttotime/_inttotime driver parameter makes a text- or integer-stored
// column scan as time.Time, which TableX's browse, export and row-edit paths
// would silently narrow or misencode. Config validation refuses it at startup —
// in a predefined server's params AND in [storage.params], both of which reach
// the same DSN builder — via the optional driver.ParamsValidator capability.
// Only an enabled value is refused; disabled or unrelated values must still
// start.
func TestValidateRejectsSQLiteTimeConversionParams(t *testing.T) {
	// Every spelling strconv.ParseBool reads as true, across both keys.
	enabled := []map[string]string{
		{"_texttotime": "1"},
		{"_texttotime": "true"},
		{"_texttotime": "TRUE"},
		{"_texttotime": "t"},
		{"_inttotime": "1"},
		{"_inttotime": "true"},
	}
	// Disabled, absent, or unrelated: must still start. A non-boolean value is
	// left to the driver, which rejects it precisely at connect, not to us.
	inert := []map[string]string{
		{"_texttotime": "0"},
		{"_texttotime": "false"},
		{"_texttotime": "FALSE"},
		{"_inttotime": "false"},
		{"_texttotime": "maybe"},         // not a bool: the driver's problem, not config's
		{"_TextToTime": "1"},             // wrong case: the driver never reads it
		{"_pragma": "journal_mode(WAL)"}, // an unrelated param is untouched
		{},
	}

	// (1) In a predefined server's params.
	for _, params := range enabled {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db", Params: params}}
		err := c.Validate()
		if err == nil {
			t.Errorf("server params %v: accepted, want a rejection", params)
			continue
		}
		if !strings.Contains(err.Error(), "not supported") {
			t.Errorf("server params %v: rejection = %v, want it to explain the refusal", params, err)
		}
	}
	for _, params := range inert {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db", Params: params}}
		if err := c.Validate(); err != nil {
			t.Errorf("server params %v should validate: %v", params, err)
		}
	}

	// (2) In [storage.params] — the same DSN builder, so the same rule applies.
	for _, params := range enabled {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db"}}
		c.Storage = StorageConfig{Engine: "sqlite", FilePath: "/var/lib/tablex/tablex.db", Params: params}
		err := c.Validate()
		if err == nil {
			t.Errorf("storage.params %v: accepted, want a rejection", params)
			continue
		}
		if !strings.Contains(err.Error(), "storage.params") {
			t.Errorf("storage.params %v: rejection = %v, want it to name storage.params", params, err)
		}
	}
	for _, params := range inert {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db"}}
		c.Storage = StorageConfig{Engine: "sqlite", FilePath: "/var/lib/tablex/tablex.db", Params: params}
		if err := c.Validate(); err != nil {
			t.Errorf("storage.params %v should validate: %v", params, err)
		}
	}
}

// TestValidateStorage covers the [storage] block. The interesting case is the
// PARTLY filled one: a block that names a host and a password but no engine
// would be silently ignored, and an operator who filled it in expects something
// to happen.
func TestValidateStorage(t *testing.T) {
	base := func() Config {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db"}}
		return c
	}

	// Not configured at all: valid, and the default behaviour.
	if err := base().Validate(); err != nil {
		t.Fatalf("no storage block should validate: %v", err)
	}
	if base().Storage.Enabled() {
		t.Error("an empty storage block reports itself as enabled")
	}

	for _, c := range []struct {
		name   string
		mutate func(*Config)
		want   string // substring the rejection must contain
	}{
		{"a host with no engine", func(c *Config) { c.Storage.Host = "db.internal" }, "storage.engine is empty"},
		{"a password with no engine", func(c *Config) { c.Storage.Password = "s3cret" }, "storage.engine is empty"},
		{"an unknown engine", func(c *Config) { c.Storage.Engine = "no-such-engine" }, "not a known engine"},
		{"a file-backed engine with no file", func(c *Config) { c.Storage.Engine = "sqlite" }, "storage.file is required"},
		{"an in-memory metadata database", func(c *Config) {
			c.Storage.Engine = "sqlite"
			c.Storage.FilePath = ":memory:"
		}, "in-memory"},
		{"a network engine with no database named", func(c *Config) {
			c.Storage.Engine = "postgres"
			c.Storage.Host = "db.internal"
		}, "storage.database is required"},
	} {
		cfg := base()
		c.mutate(&cfg)
		err := cfg.Validate()
		if err == nil {
			t.Errorf("%s: accepted, want a rejection", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: rejection = %v, want it to mention %q", c.name, err, c.want)
		}
	}

	// The two shapes that must be accepted.
	ok := base()
	ok.Storage = StorageConfig{Engine: "sqlite", FilePath: "/var/lib/tablex/tablex.db"}
	if err := ok.Validate(); err != nil {
		t.Errorf("a file-backed metadata database should validate: %v", err)
	}
	ok.Storage = StorageConfig{Engine: "postgres", Host: "db.internal", Database: "tablex", User: "tablex"}
	if err := ok.Validate(); err != nil {
		t.Errorf("a networked metadata database should validate: %v", err)
	}
}

// TestStorageEngineComesFromTheCapability pins that eligibility is decided by
// driver.StorageHost rather than by a name list in this package: every engine
// that implements it must be accepted, and the check must be the assertion.
func TestStorageEngineComesFromTheCapability(t *testing.T) {
	for _, d := range driver.All() {
		if _, ok := d.(driver.StorageHost); !ok {
			continue
		}
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db"}}
		c.Storage = StorageConfig{Engine: d.Name(), FilePath: "/var/lib/tablex/tablex.db", Host: "db.internal", Database: "tablex"}
		if err := c.Validate(); err != nil {
			t.Errorf("engine %q implements driver.StorageHost but config refused it: %v", d.Name(), err)
		}
	}
}

// TestStorageWarnings: the metadata database holds live session ids, so it earns
// the same TLS advisory a user's server gets — plus one of its own, because a
// file cannot be shared between replicas.
func TestStorageWarnings(t *testing.T) {
	c := Default()
	c.Storage = StorageConfig{Engine: "postgres", Host: "db.internal", Database: "tablex", SSLMode: "require"}
	var tls, shared bool
	for _, msg := range c.Warnings() {
		if strings.Contains(msg, "sslmode") && strings.Contains(msg, "metadata database") {
			tls = true
		}
		if strings.Contains(msg, "replicas") {
			shared = true
		}
	}
	if !tls {
		t.Errorf("an unauthenticated sslmode on the metadata database produced no warning: %v", c.Warnings())
	}
	if shared {
		t.Errorf("a networked metadata database should not be warned about sharing: %v", c.Warnings())
	}

	c.Storage = StorageConfig{Engine: "sqlite", FilePath: "/var/lib/tablex/tablex.db"}
	shared = false
	for _, msg := range c.Warnings() {
		if strings.Contains(msg, "replicas") {
			shared = true
		}
	}
	if !shared {
		t.Errorf("a file-backed metadata database should warn that it cannot be shared: %v", c.Warnings())
	}
}

// TestStorageEnvOverrides: a password belongs in the environment on most
// deployments, so every field has an override.
func TestStorageEnvOverrides(t *testing.T) {
	t.Setenv("TABLEX_STORAGE_ENGINE", "postgres")
	t.Setenv("TABLEX_STORAGE_HOST", "meta.internal")
	t.Setenv("TABLEX_STORAGE_PORT", "6432")
	t.Setenv("TABLEX_STORAGE_DATABASE", "tablex_meta")
	t.Setenv("TABLEX_STORAGE_USER", "tablex")
	t.Setenv("TABLEX_STORAGE_PASSWORD", "from-the-env")
	t.Setenv("TABLEX_STORAGE_SSLMODE", "verify-full")
	t.Setenv("TABLEX_STORAGE_TABLE_PREFIX", "tx_")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := StorageConfig{
		Engine: "postgres", Host: "meta.internal", Port: 6432, Database: "tablex_meta",
		User: "tablex", Password: "from-the-env", SSLMode: "verify-full", TablePrefix: "tx_",
	}
	// Field by field rather than a struct compare: StorageConfig carries a
	// Params map, so it is not comparable.
	for _, f := range []struct{ name, got, want string }{
		{"engine", c.Storage.Engine, want.Engine},
		{"host", c.Storage.Host, want.Host},
		{"database", c.Storage.Database, want.Database},
		{"user", c.Storage.User, want.User},
		{"password", c.Storage.Password, want.Password},
		{"sslmode", c.Storage.SSLMode, want.SSLMode},
		{"table_prefix", c.Storage.TablePrefix, want.TablePrefix},
	} {
		if f.got != f.want {
			t.Errorf("storage %s from env = %q, want %q", f.name, f.got, f.want)
		}
	}
	if c.Storage.Port != want.Port {
		t.Errorf("storage port from env = %d, want %d", c.Storage.Port, want.Port)
	}
}

// TestDisabledStorageRefusesEveryField: [storage] without an engine must refuse
// EVERY set field, not seven of ten — port, params and table_prefix were
// silently ignored, which is precisely the failure the block's own doc comment
// says it exists to prevent.
func TestDisabledStorageRefusesEveryField(t *testing.T) {
	cases := []struct {
		field  string
		mutate func(*StorageConfig)
	}{
		{"port", func(s *StorageConfig) { s.Port = 5432 }},
		{"params", func(s *StorageConfig) { s.Params = map[string]string{"sslmode": "disable"} }},
		{"table_prefix", func(s *StorageConfig) { s.TablePrefix = "tx_" }},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg.Storage)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("storage.%s with no engine validated; it would be silently ignored", tc.field)
			}
			if !strings.Contains(err.Error(), "storage."+tc.field) {
				t.Errorf("refusal %q does not name storage.%s", err, tc.field)
			}
		})
	}
}

// TestMultiFieldRefusalsAreDeterministic: each disabled-block validator used to
// iterate a map, so with several fields set the reported field name was
// randomized. Each case sets several and requires the FIRST in block order,
// every time — against a map iteration, twenty passes in a row are a
// (1/n)^20 coincidence.
func TestMultiFieldRefusalsAreDeterministic(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*Config)
		wantField string
	}{
		{"storage", func(c *Config) {
			c.Storage.Port = 5432
			c.Storage.SSLMode = "verify-full"
			c.Storage.TablePrefix = "tx_"
		}, "storage.port"},
		{"sso", func(c *Config) {
			c.SSO.ClientSecret = "s"
			c.SSO.RedirectURL = "https://tablex.example/cb"
		}, "sso.client_secret"},
		{"audit", func(c *Config) {
			c.Audit.MaxBytes = 1024
			c.Audit.Statements = true
		}, "audit.max_bytes"},
		{"metrics", func(c *Config) {
			c.Metrics.Token = "t"
			c.Metrics.AllowCIDRs = []string{"10.0.0.0/8"}
		}, "metrics.token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := range 20 {
				cfg := Default()
				tc.mutate(&cfg)
				err := cfg.Validate()
				if err == nil {
					t.Fatalf("the half-configured %s block validated", tc.name)
				}
				if !strings.Contains(err.Error(), tc.wantField) {
					t.Fatalf("iteration %d: refusal %q does not name %s; the reported field is not deterministic", i, err, tc.wantField)
				}
			}
		})
	}
}

// TestAuditMaxBytesEnvIs64Bit: audit.max_bytes is int64, but its env override
// went through parseInt (Atoi, machine-sized) — so on a 32-bit build a value
// over 2 GiB was a hard startup refusal from the environment while the same
// value in TOML was accepted. The interesting run of this test is the CI
// test-386 job, where int is 32 bits.
func TestAuditMaxBytesEnvIs64Bit(t *testing.T) {
	t.Setenv("TABLEX_AUDIT_MAX_BYTES", "4294967296") // 4 GiB, past any int32
	t.Setenv("TABLEX_AUDIT_LOG", "true")             // a destination, so the tuned block validates
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("Load with a >2^31 audit.max_bytes from the environment: %v", err)
	}
	if want := int64(4) << 30; c.Audit.MaxBytes != want {
		t.Errorf("Audit.MaxBytes = %d, want %d", c.Audit.MaxBytes, want)
	}
}

// TestSSOEnvOverrides: the example config has promised TABLEX_SSO_CLIENT_SECRET
// since the [sso] block was added, and before this worked the ONLY way to run
// SSO was a plaintext secret in a TOML file on disk. Every SSOConfig field has
// an override.
func TestSSOEnvOverrides(t *testing.T) {
	t.Setenv("TABLEX_SSO_ISSUER", "https://login.example.com")
	t.Setenv("TABLEX_SSO_CLIENT_ID", "tablex")
	t.Setenv("TABLEX_SSO_CLIENT_SECRET", "from-the-env")
	t.Setenv("TABLEX_SSO_REDIRECT_URL", "https://tablex.example.com/auth/sso/callback")
	t.Setenv("TABLEX_SSO_SCOPES", "openid, profile ,email")
	t.Setenv("TABLEX_SSO_ALLOWED_EMAILS", "contractor@elsewhere.example")
	t.Setenv("TABLEX_SSO_ALLOWED_DOMAINS", "example.com, example.org")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, f := range []struct{ name, got, want string }{
		{"issuer", c.SSO.Issuer, "https://login.example.com"},
		{"client_id", c.SSO.ClientID, "tablex"},
		{"client_secret", c.SSO.ClientSecret, "from-the-env"},
		{"redirect_url", c.SSO.RedirectURL, "https://tablex.example.com/auth/sso/callback"},
	} {
		if f.got != f.want {
			t.Errorf("sso %s from env = %q, want %q", f.name, f.got, f.want)
		}
	}
	for _, f := range []struct {
		name      string
		got, want []string
	}{
		{"scopes", c.SSO.Scopes, []string{"openid", "profile", "email"}},
		{"allowed_emails", c.SSO.AllowedEmails, []string{"contractor@elsewhere.example"}},
		{"allowed_domains", c.SSO.AllowedDomains, []string{"example.com", "example.org"}},
	} {
		if !slices.Equal(f.got, f.want) {
			t.Errorf("sso %s from env = %v, want %v", f.name, f.got, f.want)
		}
	}
}

// TestSSOEnvListClears pins the inherited listEnv semantics on the SSO lists: a
// separator-only value REPLACES the configured list with an empty one (so an
// env-only deployment can clear a file-provided allowlist), and clearing means
// "anyone the provider vouches for" — never a blank entry, which
// PermitsIdentity would otherwise have to treat as a wildcard.
func TestSSOEnvListClears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tablex.toml")
	toml := "[sso]\n" +
		"issuer = \"https://login.example.com\"\n" +
		"client_id = \"tablex\"\n" +
		"client_secret = \"s\"\n" +
		"redirect_url = \"https://tablex.example.com/auth/sso/callback\"\n" +
		"allowed_domains = [\"example.com\"]\n"
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TABLEX_SSO_ALLOWED_DOMAINS", " , ")
	c, err := Load([]string{"-config", path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.SSO.AllowedDomains) != 0 {
		t.Errorf("allowed_domains after a separator-only override = %v, want cleared", c.SSO.AllowedDomains)
	}
	for _, d := range c.SSO.AllowedDomains {
		if strings.TrimSpace(d) == "" {
			t.Error("a blank allowlist entry survived; that is one PermitsIdentity bug away from a wildcard")
		}
	}
}

// TestValidateAudit: the block is on when it names a destination and off
// otherwise, and a block that TUNES the trail without giving it anywhere to write
// is refused. Getting that wrong is exactly the mistake an audit requirement
// exists to prevent, so it must not be a warning.
func TestValidateAudit(t *testing.T) {
	base := func() Config {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db"}}
		return c
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("no audit block should validate: %v", err)
	}
	if base().Audit.Enabled() {
		t.Error("an empty audit block reports itself as enabled")
	}

	for _, c := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"max_bytes with no destination", func(c *Config) { c.Audit.MaxBytes = 1 << 20 }, "no destination"},
		{"statements with no destination", func(c *Config) { c.Audit.Statements = true }, "no destination"},
		{"a file in a directory that does not exist", func(c *Config) {
			c.Audit.File = filepath.Join(t.TempDir(), "no", "such", "dir", "audit.jsonl")
		}, "does not exist"},
	} {
		cfg := base()
		c.mutate(&cfg)
		err := cfg.Validate()
		if err == nil {
			t.Errorf("%s: accepted, want a rejection", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: rejection = %v, want it to mention %q", c.name, err, c.want)
		}
	}

	// The accepted shapes.
	ok := base()
	ok.Audit = AuditConfig{Log: true}
	if err := ok.Validate(); err != nil {
		t.Errorf("audit.log alone should validate: %v", err)
	}
	if !ok.Audit.Enabled() {
		t.Error("audit.log = true does not enable the trail")
	}
	ok.Audit = AuditConfig{File: filepath.Join(t.TempDir(), "audit.jsonl"), MaxBytes: 1 << 20, Statements: true}
	if err := ok.Validate(); err != nil {
		t.Errorf("a file destination should validate: %v", err)
	}
}

func TestAuditEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TABLEX_AUDIT_FILE", filepath.Join(dir, "audit.jsonl"))
	t.Setenv("TABLEX_AUDIT_LOG", "true")
	t.Setenv("TABLEX_AUDIT_STATEMENTS", "yes")
	t.Setenv("TABLEX_AUDIT_MAX_BYTES", "1048576")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Audit.File != filepath.Join(dir, "audit.jsonl") {
		t.Errorf("audit file from env = %q", c.Audit.File)
	}
	if !c.Audit.Log || !c.Audit.Statements {
		t.Errorf("audit log/statements from env = %v/%v, want true/true", c.Audit.Log, c.Audit.Statements)
	}
	if c.Audit.MaxBytes != 1<<20 {
		t.Errorf("audit max_bytes from env = %d, want %d", c.Audit.MaxBytes, 1<<20)
	}

	// A malformed size refuses startup rather than silently keeping the default.
	t.Setenv("TABLEX_AUDIT_MAX_BYTES", "big")
	if _, err := Load(nil); err == nil {
		t.Error("a malformed TABLEX_AUDIT_MAX_BYTES was accepted")
	}
}

// TestRestrictDefaultsArePermissive: the allow_* settings default to true, and
// that default has to come from Default() — a Go bool is false when a TOML key is
// absent, so an inferred default would silently restrict everybody.
func TestRestrictDefaultsArePermissive(t *testing.T) {
	c := Default()
	if !c.Restrict.AllowConsole || !c.Restrict.AllowDDL {
		t.Errorf("restrict defaults = console %v / ddl %v, want both true", c.Restrict.AllowConsole, c.Restrict.AllowDDL)
	}
	if c.Restrict.ReadOnly || len(c.Restrict.Databases) > 0 {
		t.Error("read_only or an allowlist is set by default")
	}
	if c.Restrict.Restricted() {
		t.Error("the default configuration reports itself as restricted")
	}
	// And a TOML file can turn them off, which is the whole reason the default
	// lives in Default() rather than in the zero value.
	dir := t.TempDir()
	path := filepath.Join(dir, "tablex.toml")
	if err := os.WriteFile(path, []byte("[restrict]\nallow_console = false\nallow_ddl = false\nread_only = true\ndatabase_allowlist = [\"one\", \"two\"]\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	got, err := Load([]string{"-config", path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Restrict.AllowConsole || got.Restrict.AllowDDL || !got.Restrict.ReadOnly {
		t.Errorf("TOML did not override the restrict defaults: %+v", got.Restrict)
	}
	if len(got.Restrict.Databases) != 2 {
		t.Errorf("database_allowlist = %v, want two entries", got.Restrict.Databases)
	}
}

func TestRestrictEnvOverrides(t *testing.T) {
	t.Setenv("TABLEX_READ_ONLY", "yes")
	t.Setenv("TABLEX_ALLOW_CONSOLE", "no")
	t.Setenv("TABLEX_ALLOW_DDL", "off")
	t.Setenv("TABLEX_DATABASE_ALLOWLIST", " sales , reporting ,, ")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Restrict.ReadOnly || c.Restrict.AllowConsole || c.Restrict.AllowDDL {
		t.Errorf("restrict from env = %+v", c.Restrict)
	}
	if len(c.Restrict.Databases) != 2 || c.Restrict.Databases[0] != "sales" || c.Restrict.Databases[1] != "reporting" {
		t.Errorf("allowlist from env = %v, want [sales reporting] with blanks dropped", c.Restrict.Databases)
	}
	// A malformed boolean refuses startup rather than silently leaving the
	// permissive default in place — which for a restriction is the dangerous way
	// to fail.
	t.Setenv("TABLEX_READ_ONLY", "sortof")
	if _, err := Load(nil); err == nil {
		t.Error("a malformed TABLEX_READ_ONLY was accepted, leaving TableX writable")
	}
}

func TestDatabaseAllowed(t *testing.T) {
	open := RestrictConfig{}
	if !open.DatabaseAllowed("anything") {
		t.Error("an empty allowlist should permit every database")
	}
	limited := RestrictConfig{Databases: []string{"sales", "reporting"}}
	for _, name := range []string{"sales", "reporting"} {
		if !limited.DatabaseAllowed(name) {
			t.Errorf("%q should be allowed", name)
		}
	}
	for _, name := range []string{"other", "SALES", "sale", "sales2", ""} {
		if limited.DatabaseAllowed(name) {
			t.Errorf("%q should NOT be allowed (matching must be exact)", name)
		}
	}
}

// TestValidateMetrics: /metrics exposes internal state, so enabling it without a
// way to authorize a scrape is a startup failure rather than a warning — the
// mistake is otherwise silent, because a scrape succeeds either way.
func TestValidateMetrics(t *testing.T) {
	base := func() Config {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db"}}
		return c
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("no metrics block should validate: %v", err)
	}

	for _, c := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"enabled with no way in", func(c *Config) {
			c.Metrics.Enabled = true
		}, "authorize a scrape"},
		{"a token on a disabled endpoint", func(c *Config) {
			c.Metrics.Token = "s3cret"
		}, "metrics.enabled is false"},
		{"an allowlist on a disabled endpoint", func(c *Config) {
			c.Metrics.AllowCIDRs = []string{"10.0.0.0/8"}
		}, "metrics.enabled is false"},
		{"a malformed CIDR", func(c *Config) {
			c.Metrics.Enabled, c.Metrics.AllowCIDRs = true, []string{"10.0.0.0/8", "not-a-network"}
		}, "not a CIDR"},
	} {
		cfg := base()
		c.mutate(&cfg)
		err := cfg.Validate()
		if err == nil {
			t.Errorf("%s: accepted, want a rejection", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: rejection = %v, want it to mention %q", c.name, err, c.want)
		}
	}

	// The accepted shapes: either control alone is enough, and both together is
	// the strict case.
	for _, c := range []struct {
		name string
		mc   MetricsConfig
	}{
		{"token alone", MetricsConfig{Enabled: true, Token: "s3cret"}},
		{"allowlist alone", MetricsConfig{Enabled: true, AllowCIDRs: []string{"10.0.0.0/8", "127.0.0.1"}}},
		{"both", MetricsConfig{Enabled: true, Token: "s3cret", AllowCIDRs: []string{"::1"}}},
	} {
		cfg := base()
		cfg.Metrics = c.mc
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s should validate: %v", c.name, err)
		}
	}
}

// TestMetricsAuthorizes: the two controls are independent, and an empty or
// whitespace-only token is not a control at all.
func TestMetricsAuthorizes(t *testing.T) {
	for _, c := range []struct {
		name           string
		mc             MetricsConfig
		token, network bool
	}{
		{"nothing", MetricsConfig{}, false, false},
		{"token", MetricsConfig{Token: "t"}, true, false},
		{"blank token is no token", MetricsConfig{Token: "   "}, false, false},
		{"allowlist", MetricsConfig{AllowCIDRs: []string{"::1"}}, false, true},
		{"both", MetricsConfig{Token: "t", AllowCIDRs: []string{"::1"}}, true, true},
	} {
		gotToken, gotNet := c.mc.Authorizes()
		if gotToken != c.token || gotNet != c.network {
			t.Errorf("%s: Authorizes() = %v/%v, want %v/%v", c.name, gotToken, gotNet, c.token, c.network)
		}
	}
}

func TestMetricsEnvOverrides(t *testing.T) {
	t.Setenv("TABLEX_METRICS_ENABLED", "yes")
	t.Setenv("TABLEX_METRICS_TOKEN", "from-env")
	t.Setenv("TABLEX_METRICS_ALLOW_CIDRS", " 10.0.0.0/8 , 127.0.0.1 ,, ")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Metrics.Enabled || c.Metrics.Token != "from-env" {
		t.Errorf("metrics from env = %+v", c.Metrics)
	}
	if len(c.Metrics.AllowCIDRs) != 2 || c.Metrics.AllowCIDRs[0] != "10.0.0.0/8" || c.Metrics.AllowCIDRs[1] != "127.0.0.1" {
		t.Errorf("allow_cidrs from env = %v, want two entries with blanks dropped", c.Metrics.AllowCIDRs)
	}

	// An env list holding only separators CLEARS a list from the config file —
	// otherwise an env-only deployment could never narrow one.
	dir := t.TempDir()
	path := filepath.Join(dir, "tablex.toml")
	if err := os.WriteFile(path, []byte("[metrics]\nenabled = true\ntoken = \"from-file\"\nallow_cidrs = [\"192.168.0.0/16\"]\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("TABLEX_METRICS_ALLOW_CIDRS", ",,")
	cleared, err := Load([]string{"-config", path})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cleared.Metrics.AllowCIDRs) != 0 {
		t.Errorf("allow_cidrs = %v, want the file's list cleared by the env override", cleared.Metrics.AllowCIDRs)
	}
	// And the env token still beats the file's.
	if cleared.Metrics.Token != "from-env" {
		t.Errorf("token = %q, want the env value to win", cleared.Metrics.Token)
	}
}

// TestMetricsTokenWithoutTLSWarns: a bearer token over cleartext is a credential
// on the wire on every scrape, which is worth saying out loud but not worth
// refusing to start over.
func TestMetricsTokenWithoutTLSWarns(t *testing.T) {
	c := Default()
	c.Metrics = MetricsConfig{Enabled: true, Token: "s3cret"}
	// Matched on "scrape token", not on "cleartext": the exposed-bind warning
	// says cleartext too, and a needle that both messages satisfy would let this
	// one pass with the token warning gone entirely.
	if !hasWarning(c.Warnings(), "scrape token") {
		t.Errorf("no cleartext-token warning in %v", c.Warnings())
	}
	// Declaring TLS termination removes it.
	c.Security.SecureCookies = true
	if hasWarning(c.Warnings(), "scrape token") {
		t.Errorf("still warning about cleartext behind a declared TLS proxy: %v", c.Warnings())
	}
	// An address allowlist is not a secret, so it never draws the warning.
	plain := Default()
	plain.Metrics = MetricsConfig{Enabled: true, AllowCIDRs: []string{"10.0.0.0/8"}}
	if hasWarning(plain.Warnings(), "scrape token") {
		t.Errorf("an allowlist should not warn about a token: %v", plain.Warnings())
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// TestValidateSessionQueryBudget: a budget counted over a non-positive window
// would reset on every charge and never refuse anything — the same silent-no-op
// trap the login-throttle window has.
func TestValidateSessionQueryBudget(t *testing.T) {
	base := func() Config {
		c := Default()
		c.Servers = []ServerConfig{{Name: "s", Engine: "sqlite", FilePath: "/data/app.db"}}
		return c
	}
	if got := Default().SessionQueryBudget; got != 0 {
		t.Errorf("default session_query_budget = %d, want 0 (no budget)", got)
	}
	if got := Default().SessionQueryWindow; got != time.Minute {
		t.Errorf("default session_query_window = %v, want 1m so enabling the budget is one key", got)
	}

	bad := base()
	bad.SessionQueryBudget, bad.SessionQueryWindow = 100, 0
	if err := bad.Validate(); err == nil {
		t.Error("a budget with a zero window was accepted; it would never refuse anything")
	} else if !strings.Contains(err.Error(), "session_query_window") {
		t.Errorf("rejection = %v, want it to name session_query_window", err)
	}

	// A window with no budget is harmless — the budget is what switches it on.
	idle := base()
	idle.SessionQueryWindow = 0
	if err := idle.Validate(); err != nil {
		t.Errorf("a zero window with no budget should validate: %v", err)
	}

	ok := base()
	ok.SessionQueryBudget, ok.SessionQueryWindow = 100, 30*time.Second
	if err := ok.Validate(); err != nil {
		t.Errorf("a budget with a positive window should validate: %v", err)
	}
}

func TestSessionQueryBudgetEnvOverrides(t *testing.T) {
	t.Setenv("TABLEX_SESSION_QUERY_BUDGET", "250")
	t.Setenv("TABLEX_SESSION_QUERY_WINDOW", "45s")
	c, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.SessionQueryBudget != 250 || c.SessionQueryWindow != 45*time.Second {
		t.Errorf("budget/window from env = %d/%v, want 250/45s", c.SessionQueryBudget, c.SessionQueryWindow)
	}
	t.Setenv("TABLEX_SESSION_QUERY_BUDGET", "lots")
	if _, err := Load(nil); err == nil {
		t.Error("a malformed TABLEX_SESSION_QUERY_BUDGET was accepted")
	}
}

// TestStorageMaxSessionsIsPresenceTracked: max_sessions is the one [storage]
// key whose non-zero default made "set" undetectable from the value alone —
// 0 is a documented explicit value meaning uncapped, so the default cannot be
// dropped and re-seeded without silently re-capping a deliberate 0. It is now
// presence-tracked (the decoder's MetaData plus applyEnv's non-empty-only env
// semantics) and joins the block's partly-configured refusal, closing the
// trap tablex.example.toml's own commented block invites.
func TestStorageMaxSessionsIsPresenceTracked(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "tablex.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return path
	}

	// TOML: positive, explicit ZERO (documented, still "set") and negative all
	// count as configured — engineless, each refuses startup.
	for _, val := range []string{"5000", "0", "-1"} {
		if _, err := Load([]string{"-config", write(t, "[storage]\nmax_sessions = "+val+"\n")}); err == nil || !strings.Contains(err.Error(), "storage.max_sessions") {
			t.Errorf("max_sessions=%s without an engine: err = %v, want the partly-configured refusal naming it", val, err)
		}
	}
	// A COMPLETE block keeps working, explicit zero included.
	dbfile := filepath.Join(t.TempDir(), "meta.db")
	full := write(t, "[storage]\nmax_sessions = 0\nengine = \"sqlite\"\nfile = '"+dbfile+"'\n")
	if cfg, err := Load([]string{"-config", full}); err != nil {
		t.Errorf("a complete storage block with an explicit max_sessions must start: %v", err)
	} else if cfg.Storage.MaxSessions != 0 {
		t.Errorf("explicit max_sessions = 0 read back as %d — the documented uncapped value was re-capped", cfg.Storage.MaxSessions)
	}
	// Absent entirely: the built-in default alone never trips the rule.
	if _, err := Load(nil); err != nil {
		t.Errorf("no configuration at all must start: %v", err)
	}
	// Env: a non-empty override is "set" (engineless → refusal); an empty one
	// is ABSENT, matching applyEnv's only-when-non-empty semantics.
	t.Setenv("TABLEX_STORAGE_MAX_SESSIONS", "123")
	if _, err := Load(nil); err == nil || !strings.Contains(err.Error(), "storage.max_sessions") {
		t.Errorf("env-set max_sessions without an engine: err = %v, want the refusal", err)
	}
	t.Setenv("TABLEX_STORAGE_MAX_SESSIONS", "")
	if _, err := Load(nil); err != nil {
		t.Errorf("an empty env override reads as absent and must start: %v", err)
	}
}

// TestUnknownConfigKeysRefuseStartup pins the RUNTIME decode path (loadTOML,
// the one Load takes) — not just the shipped example file below: an unknown
// or misplaced key refuses startup instead of silently keeping its permissive
// default. This is a deliberate BREAKING upgrade behaviour: a config file the
// previous binary accepted (TOML ignored the stray key) now stops the new
// binary, and the refusal names the key so the operator can fix or delete it;
// the previous binary still accepts the same file, so rollback is safe. The
// two free-form maps are the stated exception — sub-keys of [storage.params]
// and [[servers]].params are absorbed as decoded and must NOT trip the guard.
func TestUnknownConfigKeysRefuseStartup(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "tablex.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		return path
	}

	// A misplaced hardening key: [restrict] spells it read_only. The typo'd
	// instance used to leave the console fully writable while the operator
	// believed the instance read-only.
	var cfg Config
	if _, err := loadTOML(write(t, "[restrict]\nreadonly = true\n"), &cfg); err == nil || !strings.Contains(err.Error(), "restrict.readonly") {
		t.Errorf("a misplaced [restrict] key must refuse startup naming the key, got: %v", err)
	}
	// A known key at the wrong level: database_allowlist belongs under [restrict].
	cfg = Config{}
	if _, err := loadTOML(write(t, "database_allowlist = [\"app\"]\n"), &cfg); err == nil || !strings.Contains(err.Error(), "database_allowlist") {
		t.Errorf("a top-level database_allowlist must refuse startup, got: %v", err)
	}
	// No false positive: params sub-keys are free-form by design.
	cfg = Config{}
	if _, err := loadTOML(write(t, "[[servers]]\nname = \"s\"\nengine = \"sqlite\"\nfile = \"x.db\"\n[servers.params]\nanything_at_all = \"1\"\n"), &cfg); err != nil {
		t.Errorf("a [[servers]].params sub-key must not trip the unknown-key guard: %v", err)
	}
	// The full Load path surfaces the refusal (the runtime entry point).
	if _, err := Load([]string{"-config", write(t, "[security]\nsecure_cookys = true\n")}); err == nil || !strings.Contains(err.Error(), "security.secure_cookys") {
		t.Errorf("Load must refuse a config with an unknown key, got: %v", err)
	}
}

// TestUnknownEnvVarsRefuseStartup is the environment-side sibling of the TOML
// guard above: container deployments configure TableX primarily via env, and a
// mistyped override (TABLEX_READONLY for TABLEX_READ_ONLY) used to leave the
// permissive default silently in force while the operator, having read that
// unknown CONFIG keys refuse startup, assumed the same protection. The known
// set is built by applyEnv's own reads, so the carve-outs are the only list
// maintained by hand: TABLEX_TEST_* (live-test credentials in the same
// process environment) and the install scripts' variables.
func TestUnknownEnvVarsRefuseStartup(t *testing.T) {
	// A known override first: without this half, refusing every TABLEX_* var
	// would also pass.
	t.Setenv("TABLEX_READ_ONLY", "true")
	cfg := Default()
	if errs := applyEnv(&cfg); len(errs) != 0 {
		t.Fatalf("a KNOWN override was refused: %v", errs)
	}
	if !cfg.Restrict.ReadOnly {
		t.Fatal("the known override did not apply")
	}

	t.Setenv("TABLEX_READONLY", "true") // the typo the guard exists for
	cfg = Default()
	errs := applyEnv(&cfg)
	found := false
	for _, err := range errs {
		if strings.Contains(err.Error(), "TABLEX_READONLY") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unknown TABLEX_* variable must refuse startup naming it, got: %v", errs)
	}

	// The carve-outs: live-test credentials and the install scripts' own
	// variables share a process environment with the binary and must not trip
	// the guard. (TABLEX_READONLY is still set — clear it via subtest scoping
	// is not possible with t.Setenv, so assert on the error CONTENT instead.)
	exempt := []string{"TABLEX_TEST_POSTGRES_HOST", "TABLEX_VERSION", "TABLEX_INSTALL_DIR",
		"TABLEX_BASE_URL", "TABLEX_NO_MODIFY_PATH", "TABLEX_PS1_URL"}
	t.Setenv("TABLEX_TEST_POSTGRES_HOST", "127.0.0.1")
	t.Setenv("TABLEX_VERSION", "v9.9.9")
	t.Setenv("TABLEX_INSTALL_DIR", "/tmp/x")
	t.Setenv("TABLEX_BASE_URL", "https://example.test")
	t.Setenv("TABLEX_NO_MODIFY_PATH", "1")
	t.Setenv("TABLEX_PS1_URL", "https://example.test/install.ps1")
	cfg = Default()
	for _, err := range applyEnv(&cfg) {
		for _, name := range exempt {
			if strings.Contains(err.Error(), name) {
				t.Errorf("exempt variable %s tripped the guard: %v", name, err)
			}
		}
	}

	// The exempt list must match the install scripts: every TABLEX_* variable
	// a script exports or documents has to be carved out, or the installed
	// binary refuses to start in the very environment the installer created.
	// (TABLEX_BASE_URL appears in install.sh/install.ps1; TABLEX_PS1_URL only
	// in install.cmd.) The scripts live at the repository root.
	scriptVars := map[string]bool{}
	for _, script := range []string{"install.sh", "install.ps1", "install.cmd"} {
		data, err := os.ReadFile(filepath.Join("..", "..", script))
		if err != nil {
			t.Fatalf("read %s: %v", script, err)
		}
		for _, m := range regexp.MustCompile(`TABLEX_[A-Z0-9_]+`).FindAllString(string(data), -1) {
			scriptVars[m] = true
		}
	}
	for name := range scriptVars {
		if !installerEnvVars[name] {
			t.Errorf("install scripts use %s but installerEnvVars does not exempt it — the installed binary would refuse to start", name)
		}
	}
	for name := range installerEnvVars {
		if !scriptVars[name] {
			t.Errorf("installerEnvVars exempts %s but no install script uses it — stale carve-outs weaken the unknown-variable guard", name)
		}
	}
}

// TestExampleConfigMatchesTheCode: tablex.example.toml is what operators copy, and
// TOML decoding IGNORES keys it does not recognise — so a renamed field, or a typo
// in the example, ships as a setting that silently does nothing. BurntSushi's
// Undecoded() is exactly the list that must be empty.
//
// It also asserts the example's active values land where they claim to, since a
// key in the right shape but the wrong place would decode into nothing and still
// pass the check above.
func TestExampleConfigMatchesTheCode(t *testing.T) {
	path := filepath.Join("..", "..", "tablex.example.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg Config
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		t.Fatalf("tablex.example.toml does not parse: %v", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		t.Errorf("tablex.example.toml sets keys the config does not understand: %v", undecoded)
	}

	// Spot-check that the documented defaults are the real ones. A drifting
	// example is a lie an operator has no way to detect.
	got := Default()
	if err := toml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal onto defaults: %v", err)
	}
	if got.SessionQueryWindow != Default().SessionQueryWindow {
		t.Errorf("example session_query_window = %v, but the default is %v", got.SessionQueryWindow, Default().SessionQueryWindow)
	}
	if got.SessionQueryBudget != Default().SessionQueryBudget {
		t.Errorf("example session_query_budget = %d, but the default is %d", got.SessionQueryBudget, Default().SessionQueryBudget)
	}
	if got.MaxConcurrentDBOps != Default().MaxConcurrentDBOps {
		t.Errorf("example max_concurrent_db_ops = %d, but the default is %d", got.MaxConcurrentDBOps, Default().MaxConcurrentDBOps)
	}
	// The example must not ship anything switched on that would change behaviour.
	if got.Metrics.Enabled || got.Audit.Enabled() || got.Storage.Enabled() || got.Restrict.Restricted() {
		t.Errorf("tablex.example.toml enables an optional subsystem out of the box: %+v", got)
	}
}

// TestSSOConfigValidation: a gate that silently does not engage is the one
// outcome an operator who configured SSO must never get, so a half-configured
// provider refuses startup — the same rule [metrics] follows.
func TestSSOConfigValidation(t *testing.T) {
	full := func() SSOConfig {
		return SSOConfig{
			Issuer:       "https://idp.example",
			ClientID:     "id",
			ClientSecret: "secret",
			RedirectURL:  "https://tablex.example/auth/sso/callback",
		}
	}
	cases := []struct {
		name    string
		sso     SSOConfig
		wantErr string
	}{
		{"absent is fine", SSOConfig{}, ""},
		{"fully configured", full(), ""},
		{"loopback issuer may be plaintext (that is how it is tested)",
			SSOConfig{Issuer: "http://127.0.0.1:8081", ClientID: "id", ClientSecret: "s",
				RedirectURL: "http://localhost:8080/auth/sso/callback"}, ""},

		{"no client_id", func() SSOConfig { s := full(); s.ClientID = ""; return s }(), "sso.client_id"},
		{"no client_secret", func() SSOConfig { s := full(); s.ClientSecret = ""; return s }(), "sso.client_secret"},
		{"no redirect_url", func() SSOConfig { s := full(); s.RedirectURL = ""; return s }(), "sso.redirect_url"},
		{"plaintext remote issuer",
			func() SSOConfig { s := full(); s.Issuer = "http://idp.example"; return s }(),
			"must be https"},
		{"issuer is not a URL",
			func() SSOConfig { s := full(); s.Issuer = "not-a-url"; return s }(),
			"not an absolute URL"},
		{"redirect_url is relative",
			func() SSOConfig { s := full(); s.RedirectURL = "/auth/sso/callback"; return s }(),
			"not an absolute URL"},

		// "@ example.com" normalizes to "example.com" (shared with the
		// matcher), so it is accepted; a domain with INTERIOR whitespace can
		// never match anyone and refuses startup instead of being a silently
		// dead entry.
		{"@-space domain entry is accepted as its normalized form",
			func() SSOConfig { s := full(); s.AllowedDomains = []string{"@ example.com"}; return s }(), ""},
		{"a domain entry with interior whitespace could never match",
			func() SSOConfig { s := full(); s.AllowedDomains = []string{"exam ple.com"}; return s }(),
			"contains whitespace"},

		// Keys set with no issuer: nothing would be applied, which is exactly the
		// silent no-op this refuses.
		{"client_id without issuer",
			SSOConfig{ClientID: "id"}, "sso.issuer is not"},
		{"allowlist without issuer",
			SSOConfig{AllowedDomains: []string{"example.com"}}, "sso.issuer is not"},
		{"scopes without issuer",
			SSOConfig{Scopes: []string{"profile"}}, "sso.issuer is not"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.SSO = tc.sso
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want no error", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("Validate() = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestCookieNameValidation: an RFC-6265-invalid cookie name is the worst kind
// of misconfiguration — http.SetCookie silently writes nothing, so the server
// starts clean and login just never sticks. Validate refuses it loudly, along
// with the __Host-/__Secure- prefixes the session layer manages itself.
func TestCookieNameValidation(t *testing.T) {
	cases := []struct {
		name, cookie, wantErr string
	}{
		{"default", "tablex_session", ""},
		{"dash and underscore", "my-cookie_2", ""},
		{"every punctuation token char", "!#$%&'*+-.^_`|~", ""},
		{"empty", "", "must not be empty"},
		{"space", "my cookie", "not an RFC 6265 token"},
		{"semicolon", "a;b", "not an RFC 6265 token"},
		{"equals", "a=b", "not an RFC 6265 token"},
		{"non-ASCII", "séssion", "not an RFC 6265 token"},
		{"__Host- prefix", "__Host-x", "must not start with"},
		{"__Secure- prefix", "__Secure-x", "must not start with"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Session.CookieName = tc.cookie
			err := cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want no error", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want an error mentioning %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("Validate() = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestSSOScopesWithoutIssuerRefusedFromEnvAndTOML: the disabled-block refusal
// must hold on both input paths — TABLEX_SSO_SCOPES made the TOML-only check
// reachable from the environment.
func TestSSOScopesWithoutIssuerRefusedFromEnvAndTOML(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		t.Setenv("TABLEX_SSO_SCOPES", "profile")
		if _, err := Load(nil); err == nil || !strings.Contains(err.Error(), "sso.scopes") {
			t.Fatalf("Load with TABLEX_SSO_SCOPES and no issuer = %v, want a refusal naming sso.scopes", err)
		}
	})
	t.Run("toml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tablex.toml")
		if err := os.WriteFile(path, []byte("[sso]\nscopes = [\"profile\"]\n"), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		if _, err := Load([]string{"-config", path}); err == nil || !strings.Contains(err.Error(), "sso.scopes") {
			t.Fatalf("Load with sso.scopes and no issuer = %v, want a refusal naming sso.scopes", err)
		}
	})
}

func TestSSOResolvedScopesAlwaysIncludesOpenID(t *testing.T) {
	// Without openid the provider is not doing OIDC at all and returns no ID
	// token, so the flow would fail at the last step with a confusing error.
	for _, in := range [][]string{nil, {}, {"email"}, {"openid"}, {"profile", "openid"}} {
		got := SSOConfig{Scopes: in}.ResolvedScopes()
		if len(got) == 0 || got[0] != "openid" {
			t.Errorf("ResolvedScopes(%v) = %v, want openid first", in, got)
		}
		seen := map[string]int{}
		for _, s := range got {
			seen[s]++
			if seen[s] > 1 {
				t.Errorf("ResolvedScopes(%v) = %v, %q is duplicated", in, got, s)
			}
		}
	}
}

func TestSSOPermitsIdentity(t *testing.T) {
	cases := []struct {
		name  string
		sso   SSOConfig
		email string
		want  bool
	}{
		{"no allowlist admits anyone the provider vouched for",
			SSOConfig{}, "anyone@anywhere.example", true},
		{"exact email", SSOConfig{AllowedEmails: []string{"dana@example.com"}}, "dana@example.com", true},
		{"exact email is case-insensitive",
			SSOConfig{AllowedEmails: []string{"Dana@Example.com"}}, "dana@EXAMPLE.com", true},
		{"other email refused", SSOConfig{AllowedEmails: []string{"dana@example.com"}}, "eve@example.com", false},
		{"domain", SSOConfig{AllowedDomains: []string{"example.com"}}, "anyone@example.com", true},
		{"domain with a leading @", SSOConfig{AllowedDomains: []string{"@example.com"}}, "anyone@example.com", true},
		{"other domain refused", SSOConfig{AllowedDomains: []string{"example.com"}}, "eve@evil.example", false},
		// An allowlist is configured but the provider reported no email: there is
		// nothing to match, and the operator asked for something narrower than
		// "anyone", so the only safe reading is to refuse.
		{"no email with an allowlist configured", SSOConfig{AllowedDomains: []string{"example.com"}}, "", false},
		{"no email with no allowlist", SSOConfig{}, "", true},
		// A blank entry is a plausible config typo (a trailing comma in a TOML
		// array). validate() refuses it at startup; these pin the DEFENSIVE
		// skip in the matching loops with a NON-EMPTY email whose domain part
		// is empty ("x@") — the case that actually reaches the domain loop.
		// The earlier form of these cases passed email == "", which only ever
		// exercised the empty-email short-circuit and proved nothing about
		// the loops.
		{"a blank email entry must not become a wildcard",
			SSOConfig{AllowedEmails: []string{"dana@example.com", ""}}, "", false},
		{"a blank domain entry must not match an empty domain part",
			SSOConfig{AllowedDomains: []string{"example.com", ""}}, "x@", false},
		{"a blank-only domain list admits nobody, never everybody",
			SSOConfig{AllowedDomains: []string{""}}, "x@", false},
		{"a real entry still matches beside a blank one",
			SSOConfig{AllowedDomains: []string{"", "example.com"}}, "dana@example.com", true},
		// "@ example.com": the validator accepts it (normalized to
		// "example.com"), so the matcher must apply the SAME normalization —
		// the two once differed by exactly the inner trim, making the entry a
		// silently dead one that validation claimed to have checked.
		{"an @-space entry matches what validation accepted it as",
			SSOConfig{AllowedDomains: []string{"@ example.com"}}, "dana@example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.sso.PermitsIdentity(tc.email); got != tc.want {
				t.Errorf("PermitsIdentity(%q) = %v, want %v", tc.email, got, tc.want)
			}
		})
	}
}

// TestSSOValidateRefusesBlankAllowlistEntries: the startup half of the pair —
// a blank entry cannot name anyone, and DROPPING it silently would be a
// security regression (a blank-only list would flip HasAllowlist to false and
// admit every provider-verified identity), so it refuses startup, the same
// fail-closed shape as every other block validator.
func TestSSOValidateRefusesBlankAllowlistEntries(t *testing.T) {
	base := func() SSOConfig {
		return SSOConfig{
			Issuer:       "https://login.example.com",
			ClientID:     "tablex",
			ClientSecret: "s",
			RedirectURL:  "https://tablex.example.com/auth/sso/callback",
		}
	}
	if err := base().validate(); err != nil {
		t.Fatalf("the base block must validate: %v", err)
	}
	blankEmail := base()
	blankEmail.AllowedEmails = []string{"dana@example.com", " "}
	if err := blankEmail.validate(); err == nil || !strings.Contains(err.Error(), "allowed_emails") {
		t.Errorf("a blank allowed_emails entry must refuse startup, got %v", err)
	}
	blankDomain := base()
	blankDomain.AllowedDomains = []string{""}
	if err := blankDomain.validate(); err == nil || !strings.Contains(err.Error(), "allowed_domains") {
		t.Errorf("a blank-only allowed_domains list must refuse startup, got %v", err)
	}
	atOnly := base()
	atOnly.AllowedDomains = []string{"@"}
	if err := atOnly.validate(); err == nil || !strings.Contains(err.Error(), "allowed_domains") {
		t.Errorf("a bare-@ allowed_domains entry must refuse startup, got %v", err)
	}
	real := base()
	real.AllowedDomains = []string{"@example.com", "example.org"}
	real.AllowedEmails = []string{"dana@example.com"}
	if err := real.validate(); err != nil {
		t.Errorf("real allowlist entries must validate: %v", err)
	}
}

func TestAccountLockoutWarning(t *testing.T) {
	cfg := Default()
	if cfg.Security.LoginAccountMax <= 0 {
		t.Fatal("the global account lockout should be ON by default; a gap closed only when an operator finds the knob is not closed")
	}
	cfg.Security.LoginAccountMax = 0
	var found bool
	for _, w := range cfg.Warnings() {
		if strings.Contains(w, "login_account_max") {
			found = true
		}
	}
	if !found {
		t.Errorf("disabling the account lockout produced no warning; warnings = %v", cfg.Warnings())
	}
}

// TestExposedBindWarning: the default listen address is ":8080" — every
// interface — and TableX takes database credentials through a form. Saying so at
// startup is the whole point, so the DEFAULT is a row in this table: a test that
// only covered concrete hosts would pass with the polarity inverted.
//
// The classification is the INVERSE of healthcheckURL's, which maps an empty or
// wildcard host to loopback because that is how you probe a wildcard listener
// from inside a container. Reusing that rule here would suppress exactly the
// case worth warning about.
func TestExposedBindWarning(t *testing.T) {
	const needle = "reachable from outside this machine"
	warned := func(t *testing.T, mutate func(*Config)) bool {
		t.Helper()
		c := Default()
		mutate(&c)
		for _, msg := range c.Warnings() {
			if strings.Contains(msg, needle) {
				return true
			}
		}
		return false
	}

	for _, tc := range []struct {
		listen string
		want   bool
	}{
		{"", true},              // no host at all
		{":8080", true},         // THE DEFAULT: every interface
		{"0.0.0.0:8080", true},  // explicit IPv4 wildcard
		{"[::]:8080", true},     // explicit IPv6 wildcard
		{"10.0.0.5:8080", true}, // a concrete routable address
		{"db.example.com:8080", true},
		{"not a host:port:8080", true}, // unparseable: fail loud
		{"127.0.0.1:8080", false},
		{"[::1]:8080", false},
		{"localhost:8080", false},
		{"[::1%25lo0]:8080", false}, // zone-scoped loopback
	} {
		t.Run(tc.listen, func(t *testing.T) {
			got := warned(t, func(c *Config) { c.Listen = tc.listen })
			if got != tc.want {
				t.Errorf("listen = %q warned = %v, want %v", tc.listen, got, tc.want)
			}
		})
	}

	// TLS is the point of the warning, so declaring it silences it — both ways
	// TableX can be serving over TLS.
	if warned(t, func(c *Config) { c.Listen = ":8080"; c.TLSCert, c.TLSKey = "c.pem", "k.pem" }) {
		t.Error("warned about an exposed bind while TableX is serving TLS directly")
	}
	if warned(t, func(c *Config) { c.Listen = ":8080"; c.Security.SecureCookies = true }) {
		t.Error("warned about an exposed bind while a TLS-terminating proxy is declared")
	}
}
