package config

// Every config field has an environment override, or a recorded reason it does
// not. This is the test that would have caught the [sso] block shipping with a
// documented-but-unimplemented TABLEX_SSO_CLIENT_SECRET, and storage.socket /
// storage.params drifting out of the docs: config_test.go's example-file test
// only checks example → struct, never struct → env.
//
// It targets applyEnv directly, deliberately: Load would run Validate, and a
// config with every sentinel set at once fails validation for reasons that
// have nothing to do with the overrides (flipping default-true allow_adhoc
// demands predefined servers; TABLEX_CONFIG is loader metadata that would
// redirect the whole load). Sentinels are compared against a DEFAULT config,
// not zero values, and the test refuses a sentinel that equals the default —
// such a row would pass vacuously.

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// envOverride is one row of the override table: the variable, a sentinel that
// must differ from the field's default, and how to read the field back.
type envOverride struct {
	env   string
	value string
	get   func(*Config) any
	want  any
}

// envOverrides maps every overridable leaf field (by Go path) to its variable.
// A field added to Config must land here or in envExemptions, or this test
// fails — which is the point.
var envOverrides = map[string]envOverride{
	"Listen":               {"TABLEX_LISTEN", "0.0.0.0:7777", func(c *Config) any { return c.Listen }, "0.0.0.0:7777"},
	"TLSCert":              {"TABLEX_TLS_CERT", "/certs/tablex.pem", func(c *Config) any { return c.TLSCert }, "/certs/tablex.pem"},
	"TLSKey":               {"TABLEX_TLS_KEY", "/certs/tablex.key", func(c *Config) any { return c.TLSKey }, "/certs/tablex.key"},
	"MaxExactCount":        {"TABLEX_MAX_EXACT_COUNT", "1234", func(c *Config) any { return c.MaxExactCount }, 1234},
	"PoolCap":              {"TABLEX_POOL_CAP", "77", func(c *Config) any { return c.PoolCap }, 77},
	"PoolMaxConns":         {"TABLEX_POOL_MAX_CONNS", "9", func(c *Config) any { return c.PoolMaxConns }, 9},
	"PoolIdleConns":        {"TABLEX_POOL_IDLE_CONNS", "3", func(c *Config) any { return c.PoolIdleConns }, 3},
	"ReadStmtTimeout":      {"TABLEX_READ_STMT_TIMEOUT", "91s", func(c *Config) any { return c.ReadStmtTimeout }, 91 * time.Second},
	"MaxConcurrentDBOps":   {"TABLEX_MAX_CONCURRENT_DB_OPS", "11", func(c *Config) any { return c.MaxConcurrentDBOps }, 11},
	"MaxScriptStatements":  {"TABLEX_MAX_SCRIPT_STATEMENTS", "1234", func(c *Config) any { return c.MaxScriptStatements }, 1234},
	"MaxConcurrentImports": {"TABLEX_MAX_CONCURRENT_IMPORTS", "9", func(c *Config) any { return c.MaxConcurrentImports }, 9},
	"SessionQueryBudget":   {"TABLEX_SESSION_QUERY_BUDGET", "222", func(c *Config) any { return c.SessionQueryBudget }, 222},
	"SessionQueryWindow":   {"TABLEX_SESSION_QUERY_WINDOW", "2m", func(c *Config) any { return c.SessionQueryWindow }, 2 * time.Minute},

	"Session.CookieName":      {"TABLEX_COOKIE_NAME", "tx_test", func(c *Config) any { return c.Session.CookieName }, "tx_test"},
	"Session.IdleTimeout":     {"TABLEX_IDLE_TIMEOUT", "45m", func(c *Config) any { return c.Session.IdleTimeout }, 45 * time.Minute},
	"Session.AbsoluteTimeout": {"TABLEX_ABSOLUTE_TIMEOUT", "13h", func(c *Config) any { return c.Session.AbsoluteTimeout }, 13 * time.Hour},

	"Security.AllowAdHoc":        {"TABLEX_ALLOW_ADHOC", "false", func(c *Config) any { return c.Security.AllowAdHoc }, false},
	"Security.BlockPrivate":      {"TABLEX_BLOCK_PRIVATE", "true", func(c *Config) any { return c.Security.BlockPrivate }, true},
	"Security.SecureCookies":     {"TABLEX_SECURE_COOKIES", "true", func(c *Config) any { return c.Security.SecureCookies }, true},
	"Security.TrustedProxy":      {"TABLEX_TRUSTED_PROXY", "true", func(c *Config) any { return c.Security.TrustedProxy }, true},
	"Security.TrustedProxyCIDRs": {"TABLEX_TRUSTED_PROXY_CIDRS", "10.0.0.0/8", func(c *Config) any { return c.Security.TrustedProxyCIDRs }, []string{"10.0.0.0/8"}},

	"Restrict.ReadOnly":     {"TABLEX_READ_ONLY", "true", func(c *Config) any { return c.Restrict.ReadOnly }, true},
	"Restrict.AllowConsole": {"TABLEX_ALLOW_CONSOLE", "false", func(c *Config) any { return c.Restrict.AllowConsole }, false},
	"Restrict.AllowDDL":     {"TABLEX_ALLOW_DDL", "false", func(c *Config) any { return c.Restrict.AllowDDL }, false},
	"Restrict.Databases":    {"TABLEX_DATABASE_ALLOWLIST", "one,two", func(c *Config) any { return c.Restrict.Databases }, []string{"one", "two"}},

	"Storage.Engine":      {"TABLEX_STORAGE_ENGINE", "postgres", func(c *Config) any { return c.Storage.Engine }, "postgres"},
	"Storage.Host":        {"TABLEX_STORAGE_HOST", "meta.internal", func(c *Config) any { return c.Storage.Host }, "meta.internal"},
	"Storage.Port":        {"TABLEX_STORAGE_PORT", "6432", func(c *Config) any { return c.Storage.Port }, 6432},
	"Storage.Socket":      {"TABLEX_STORAGE_SOCKET", "/run/pg.sock", func(c *Config) any { return c.Storage.Socket }, "/run/pg.sock"},
	"Storage.Database":    {"TABLEX_STORAGE_DATABASE", "tablex_meta", func(c *Config) any { return c.Storage.Database }, "tablex_meta"},
	"Storage.FilePath":    {"TABLEX_STORAGE_FILE", "/var/lib/tablex/meta.db", func(c *Config) any { return c.Storage.FilePath }, "/var/lib/tablex/meta.db"},
	"Storage.User":        {"TABLEX_STORAGE_USER", "tablex", func(c *Config) any { return c.Storage.User }, "tablex"},
	"Storage.Password":    {"TABLEX_STORAGE_PASSWORD", "from-the-env", func(c *Config) any { return c.Storage.Password }, "from-the-env"},
	"Storage.SSLMode":     {"TABLEX_STORAGE_SSLMODE", "verify-full", func(c *Config) any { return c.Storage.SSLMode }, "verify-full"},
	"Storage.TablePrefix": {"TABLEX_STORAGE_TABLE_PREFIX", "tx_", func(c *Config) any { return c.Storage.TablePrefix }, "tx_"},
	// 777 rather than the 20000 default: a sentinel equal to the default makes
	// the row vacuous, which this file errors on.
	"Storage.MaxSessions": {"TABLEX_STORAGE_MAX_SESSIONS", "777", func(c *Config) any { return c.Storage.MaxSessions }, 777},

	"Audit.File":       {"TABLEX_AUDIT_FILE", "/var/log/tablex/audit.jsonl", func(c *Config) any { return c.Audit.File }, "/var/log/tablex/audit.jsonl"},
	"Audit.MaxBytes":   {"TABLEX_AUDIT_MAX_BYTES", "4294967296", func(c *Config) any { return c.Audit.MaxBytes }, int64(4) << 30},
	"Audit.Log":        {"TABLEX_AUDIT_LOG", "true", func(c *Config) any { return c.Audit.Log }, true},
	"Audit.Statements": {"TABLEX_AUDIT_STATEMENTS", "true", func(c *Config) any { return c.Audit.Statements }, true},

	"Metrics.Enabled":    {"TABLEX_METRICS_ENABLED", "true", func(c *Config) any { return c.Metrics.Enabled }, true},
	"Metrics.Token":      {"TABLEX_METRICS_TOKEN", "scrape-token", func(c *Config) any { return c.Metrics.Token }, "scrape-token"},
	"Metrics.AllowCIDRs": {"TABLEX_METRICS_ALLOW_CIDRS", "192.168.0.0/16", func(c *Config) any { return c.Metrics.AllowCIDRs }, []string{"192.168.0.0/16"}},

	"SSO.Issuer":         {"TABLEX_SSO_ISSUER", "https://login.example.com", func(c *Config) any { return c.SSO.Issuer }, "https://login.example.com"},
	"SSO.ClientID":       {"TABLEX_SSO_CLIENT_ID", "tablex", func(c *Config) any { return c.SSO.ClientID }, "tablex"},
	"SSO.ClientSecret":   {"TABLEX_SSO_CLIENT_SECRET", "shh", func(c *Config) any { return c.SSO.ClientSecret }, "shh"},
	"SSO.RedirectURL":    {"TABLEX_SSO_REDIRECT_URL", "https://tablex.example.com/auth/sso/callback", func(c *Config) any { return c.SSO.RedirectURL }, "https://tablex.example.com/auth/sso/callback"},
	"SSO.Scopes":         {"TABLEX_SSO_SCOPES", "openid,profile", func(c *Config) any { return c.SSO.Scopes }, []string{"openid", "profile"}},
	"SSO.AllowedEmails":  {"TABLEX_SSO_ALLOWED_EMAILS", "dana@example.com", func(c *Config) any { return c.SSO.AllowedEmails }, []string{"dana@example.com"}},
	"SSO.AllowedDomains": {"TABLEX_SSO_ALLOWED_DOMAINS", "example.com", func(c *Config) any { return c.SSO.AllowedDomains }, []string{"example.com"}},
}

// envExemptions is the fields that deliberately have NO environment override.
// Adding a field here means saying out loud why it has none.
var envExemptions = map[string]string{
	// Security tuning that shapes the login attack surface: deliberately
	// file-only, so a compromised process environment cannot loosen it.
	"Security.HostAllowlist":   "file-only by design: the SSRF allowlist must not be loosenable from the process environment",
	"Security.HostDenylist":    "file-only by design: the SSRF denylist must not be loosenable from the process environment",
	"Security.LoginRateWindow": "file-only by design: login throttling must not be loosenable from the process environment",
	"Security.LoginRateMax":    "file-only by design: login throttling must not be loosenable from the process environment",
	"Security.LoginAccountMax": "file-only by design: login throttling must not be loosenable from the process environment",
	// Same class: this one gates session CREATION, which is the pre-login attack
	// surface an anonymous flood aims at.
	"Security.SessionCreateWindow": "file-only by design: login throttling must not be loosenable from the process environment",
	"Security.SessionCreateMax":    "file-only by design: login throttling must not be loosenable from the process environment",
	// The predefined-server collection is structured data (a list of tables);
	// it is file-only by design, every ServerConfig field included.
	"Servers": "file-only by design: a list of structured server definitions has no environment encoding",
	// A map no environment variable can express; tablex.example.toml says so.
	"Storage.Params": "map[string]string: no environment form (do not invent one)",
}

func TestEveryConfigFieldHasAnEnvOverride(t *testing.T) {
	// 1. Enumerate every leaf field reflectively, so a new field cannot skip
	// this test by never being added to either table.
	var paths []string
	var walk func(prefix string, rt reflect.Type)
	walk = func(prefix string, rt reflect.Type) {
		for i := range rt.NumField() {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			path := f.Name
			if prefix != "" {
				path = prefix + "." + f.Name
			}
			// Only a struct is descended into; everything else is a leaf. That
			// one test is enough on its own for the two cases people reach for a
			// special case on: a time.Duration is an int64, and Servers is a
			// []ServerConfig — neither is a Struct, so both are already leaves.
			// (Servers being one leaf is what the exemption list expects.)
			if f.Type.Kind() == reflect.Struct {
				walk(path, f.Type)
				continue
			}
			paths = append(paths, path)
		}
	}
	walk("", reflect.TypeOf(Config{}))
	const floor = 54 // leaf count when this test was written (47 overridden + 7 exempt)
	if len(paths) < floor {
		t.Fatalf("enumerated %d config leaves, expected at least %d — this walk is not looking where it thinks", len(paths), floor)
	}

	for _, p := range paths {
		_, overridden := envOverrides[p]
		_, exempted := envExemptions[p]
		switch {
		case overridden && exempted:
			t.Errorf("%s appears in both the override table and the exemption list", p)
		case !overridden && !exempted:
			t.Errorf("config field %s has no environment override and no recorded exemption: add TABLEX_* handling in applyEnv (and a row here), or an exemption with its reason", p)
		}
	}
	for p := range envOverrides {
		if !slices.Contains(paths, p) {
			t.Errorf("override table names %s, which is not a Config field", p)
		}
	}
	for p := range envExemptions {
		if !slices.Contains(paths, p) {
			t.Errorf("exemption list names %s, which is not a Config field", p)
		}
	}

	// 2. Behavioural: every sentinel set at once, one applyEnv, every field
	// must move — and no sentinel may equal its default, or its row proves
	// nothing.
	for _, row := range envOverrides {
		t.Setenv(row.env, row.value)
	}
	cfg := Default()
	if errs := applyEnv(&cfg); len(errs) > 0 {
		t.Fatalf("applyEnv refused the sentinel set: %v", errs)
	}
	def := Default()
	for p, row := range envOverrides {
		if reflect.DeepEqual(row.get(&def), row.want) {
			t.Errorf("%s: the sentinel equals the field's default; this row is vacuous — pick another sentinel", p)
			continue
		}
		if got := row.get(&cfg); !reflect.DeepEqual(got, row.want) {
			t.Errorf("%s: %s=%q did not reach the field: got %#v, want %#v", p, row.env, row.value, got, row.want)
		}
	}
}

// TestEveryEnvOverrideIsDocumented: tablex.example.toml is the canonical table
// of environment overrides, so every variable applyEnv honours must appear
// there by name.
func TestEveryEnvOverrideIsDocumented(t *testing.T) {
	example, err := os.ReadFile("../../tablex.example.toml")
	if err != nil {
		t.Fatalf("reading tablex.example.toml: %v", err)
	}
	for path, row := range envOverrides {
		if !strings.Contains(string(example), row.env) {
			t.Errorf("%s (%s) is not documented in tablex.example.toml — it is the canonical override table", row.env, path)
		}
	}
}

// TestOptionalBlockCountMatchesTheDocs holds the docs' stated subsystem count
// to the config structure, so "four optional subsystems" cannot survive a
// fifth being added (it already had, once).
func TestOptionalBlockCountMatchesTheDocs(t *testing.T) {
	// The optional subsystems: config blocks that are ABSENT rather than idle
	// when unconfigured. session and security are always-on tuning; servers
	// is data.
	optionalBlocks := []string{"storage", "audit", "restrict", "metrics", "sso"}

	// Guard the list itself against typos: every entry must be a real block.
	rt := reflect.TypeOf(Config{})
	tags := map[string]bool{}
	for i := range rt.NumField() {
		tags[rt.Field(i).Tag.Get("toml")] = true
	}
	for _, b := range optionalBlocks {
		if !tags[b] {
			t.Fatalf("optionalBlocks names %q, which is not a Config toml block", b)
		}
	}

	spelled := map[int]string{3: "Three", 4: "Four", 5: "Five", 6: "Six", 7: "Seven"}
	want, ok := spelled[len(optionalBlocks)]
	if !ok {
		t.Fatalf("no spelling for %d — extend the map", len(optionalBlocks))
	}

	arch, err := os.ReadFile("../../docs/architecture.md")
	if err != nil {
		t.Fatalf("reading docs/architecture.md: %v", err)
	}
	for _, phrase := range []string{
		want + " optional subsystems",
		want + " subsystems an organization needs",
	} {
		if !strings.Contains(string(arch), phrase) {
			t.Errorf("docs/architecture.md does not say %q; its subsystem count has drifted from the config structure", phrase)
		}
	}
	for n, word := range spelled {
		if n == len(optionalBlocks) {
			continue
		}
		if strings.Contains(string(arch), word+" optional subsystems") {
			t.Errorf("docs/architecture.md still says %q optional subsystems; there are %d", word, len(optionalBlocks))
		}
	}

	plan, err := os.ReadFile("../../docs/design.md")
	if err != nil {
		t.Fatalf("reading docs/design.md: %v", err)
	}
	// The optional-subsystems sentence must name every optional block.
	marker := "behaviour is byte-for-byte what it was"
	idx := strings.Index(string(plan), marker)
	if idx < 0 {
		t.Fatalf("docs/design.md no longer contains %q — this test is not looking where it thinks", marker)
	}
	lineStart := strings.LastIndexByte(string(plan)[:idx], '\n') + 1
	line := string(plan)[lineStart : idx+len(marker)]
	for _, b := range optionalBlocks {
		if !strings.Contains(line, "[") || !strings.Contains(line, fmt.Sprintf("`[%s]`", b)) {
			t.Errorf("the optional-subsystems sentence does not name `[%s]`: %q", b, line)
		}
	}
}
