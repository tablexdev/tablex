package server_test

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tablexdev/tablex/internal/audit"
	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/session"
	"github.com/tablexdev/tablex/internal/storage"
)

// The metadata store's whole design rests on a claim the unit tests cannot check:
// that one portable schema works on every engine that says it can host it. SQLite
// exercises the logic, but SQLite's types are advisory — it would accept
// "VARCHAR(64) PRIMARY KEY" and "BIGINT" whatever they meant. Only a real MySQL
// and a real PostgreSQL can show that the type spellings, the primary key, the
// transaction Replace depends on and the microsecond instants all behave.
//
// Gated on the same TABLEX_TEST_<ENGINE>_* variables as the other live tests.
// The scratch database is named with the liveDB prefix so it is tolerated by
// requireIsolatedServerScope, and it is dropped with a defer rather than
// t.Cleanup — cleanup runs after the function's defers, which would close the
// admin connection first.

func TestLiveMetadataStoreMySQL(t *testing.T) {
	liveMetadataStore(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMetadataStoreMariaDB(t *testing.T) {
	liveMetadataStore(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

func TestLiveMetadataStorePostgres(t *testing.T) {
	liveMetadataStore(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// metaDB is the scratch database the metadata tables are created in.
const metaDB = liveDB + "_meta"

func liveMetadataStore(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
	}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	drop := func() {
		stmt := "DROP DATABASE IF EXISTS " + d.QuoteIdent(metaDB)
		if env.engine == "postgres" {
			stmt += " WITH (FORCE)"
		}
		if _, err := admin.Exec(context.Background(), stmt); err != nil {
			t.Errorf("drop %s: %v", metaDB, err)
		}
	}
	drop()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+d.QuoteIdent(metaDB)); err != nil {
		t.Fatalf("create %s: %v", metaDB, err)
	}
	defer drop()

	cfg := storage.Config{
		Engine:   env.engine,
		Host:     env.host,
		Port:     env.port,
		User:     env.user,
		Password: env.pass,
		Database: metaDB,
	}
	st, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("storage.Open on live %s: %v", env.label, err)
	}
	// Closed before the database is dropped: PostgreSQL will not drop a database
	// with an open connection (WITH (FORCE) aside), and MySQL would leave the
	// pool dangling.
	defer st.Close()

	if got := st.SchemaVersion(); got != 1 {
		t.Errorf("schema version on %s = %d, want 1", env.label, got)
	}
	// Reopening must be a no-op, which is what makes a rolling restart and two
	// replicas booting at once safe.
	again, err := storage.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("second storage.Open on live %s: %v", env.label, err)
	}
	if got := again.SchemaVersion(); got != 1 {
		t.Errorf("schema version after reopen on %s = %d, want 1", env.label, got)
	}

	// Two replicas over the one database, as in production.
	a := storage.NewSessionStore(st, storage.SessionStoreConfig{IdleTimeout: 30 * time.Minute})
	b := storage.NewSessionStore(again, storage.SessionStoreConfig{IdleTimeout: 30 * time.Minute})
	defer again.Close()

	// A microsecond-precision instant, to prove the integer representation
	// survives this engine's own type handling.
	created := time.Date(2026, 7, 30, 9, 8, 7, 654321000, time.UTC)
	envelopeFor := func(id, csrf string) session.Envelope {
		return session.Envelope{ID: id, CSRF: csrf, Created: created, LastSeen: created}
	}
	pre := session.Adopt(envelopeFor("live-pre-auth", "live-csrf-token"))
	a.Save(pre)

	got, ok := b.Get(pre.ID)
	if !ok {
		t.Fatalf("%s: the second replica cannot see a session the first stored", env.label)
	}
	if got.Token() != pre.CSRF {
		t.Errorf("%s: adopted CSRF = %q, want %q", env.label, got.Token(), pre.CSRF)
	}
	if !got.Created.Equal(created) {
		t.Errorf("%s: adopted Created = %v, want %v — the microsecond instant did not survive the round trip", env.label, got.Created, created)
	}

	// The atomic swap, which on this engine is a real transaction: exactly one of
	// two logins on the same pre-auth session may win.
	next := session.Adopt(envelopeFor("live-authenticated", "live-csrf-2"))
	if !a.Replace(pre, next) {
		t.Fatalf("%s: the first login was refused", env.label)
	}
	if b.Replace(got, session.Adopt(envelopeFor("live-loser", "x"))) {
		t.Errorf("%s: a second login on the same pre-auth session succeeded", env.label)
	}
	if _, ok := b.Get(next.ID); !ok {
		t.Errorf("%s: the authenticated session is not visible to the other replica", env.label)
	}
	if _, ok := b.Get(pre.ID); ok {
		t.Errorf("%s: the pre-auth session is still accepted after the swap", env.label)
	}

	// A logout on one replica ends it on the other, and hands the holder its
	// session back so the pools can be closed.
	b.Delete(next.ID)
	if _, ok := a.Get(next.ID); ok {
		t.Errorf("%s: a session deleted on one replica is still accepted on the other", env.label)
	}
	dead := a.Reap(func(*session.Session) bool { return false })
	if len(dead) != 1 || dead[0].ID != next.ID {
		t.Errorf("%s: Reap returned %d sessions, want the one whose row is gone", env.label, len(dead))
	}

	// Finally, the transaction Replace depends on — proven rather than assumed.
	// Force the INSERT half to collide, and the DELETE half must be undone,
	// leaving the session that was being replaced still stored.
	//
	// This is the assertion that fails on a non-transactional table: MySQL on
	// MyISAM accepts BEGIN/COMMIT and ignores them, so a failed swap would
	// silently destroy the session it was re-keying. Only the ROW is asserted on
	// — a swap that ERRORS falls back to the local store by design, so its
	// return value is not what is under test.
	//
	// On its own replica, whose local view is disposable, so nothing above is
	// disturbed by the fallback.
	c := storage.NewSessionStore(st, storage.SessionStoreConfig{IdleTimeout: 30 * time.Minute})
	blocker := session.Adopt(envelopeFor("live-blocker", "b"))
	victim := session.Adopt(envelopeFor("live-victim", "v"))
	c.Save(blocker)
	c.Save(victim)
	c.Replace(victim, session.Adopt(envelopeFor(blocker.ID, "collides")))
	if _, ok := b.Get(victim.ID); !ok {
		t.Errorf("%s: a swap whose INSERT failed destroyed the session it was replacing — the DELETE was not rolled back, so this table is not transactional", env.label)
	}
}

// TestLiveAuditRecordsTheServerReportedAccount closes the one hole the
// SQLite-backed audit tests cannot: SQLite has no accounts, so the identity field
// on an action event is legitimately empty there and a broken identity path would
// look identical to a correct one. An engine with real accounts is the only place
// that assertion means anything.
//
// It also pins WHICH identity is recorded. Not the username that was typed — the
// one the server resolved, which on MySQL includes the host part it chose. That
// is the form a grant is written against, and therefore the answer to "whose
// privileges did this run under".
func TestLiveAuditRecordsTheServerReportedAccountMySQL(t *testing.T) {
	liveAuditAccount(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveAuditRecordsTheServerReportedAccountPostgres(t *testing.T) {
	liveAuditAccount(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func liveAuditAccount(t *testing.T, env liveEnv) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	db := "postgres"
	if env.engine != "postgres" {
		db = ""
	}
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath}
		cfg.Servers = []config.ServerConfig{{
			Name: testServerName, Engine: env.engine,
			Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: db,
		}}
	})

	login(t, client, ts.URL)
	// Any state-changing request will do; the point is the identity on it, not
	// the operation. A no-op console statement keeps this independent of the
	// engine's DDL.
	csrf := csrfFrom(t, client, ts.URL+"/")
	// postForm, not client.PostForm: the console answers with a rendered page, and
	// the action record is emitted by the outermost middleware AFTER that page is
	// already streaming. Only reading the body to EOF orders the emit before the
	// read below — see postForm.
	resp := postForm(t, client, ts.URL+"/server/sql", url.Values{"csrf_token": {csrf}, "sql_query": {"SELECT 1"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: console = %d, want 200 — nothing ran, so the record below would prove nothing", env.label, resp.StatusCode)
	}

	events := auditEvents(t, auditPath)
	in, ok := firstOf(events, audit.KindAuth, "/login")
	if !ok {
		t.Fatalf("%s: no auth event for the login; got %+v", env.label, events)
	}
	if in.Account == "" {
		t.Errorf("%s: the login recorded no account, but this engine has accounts", env.label)
	}
	if !strings.Contains(in.Account, env.user) {
		t.Errorf("%s: login account = %q, want it to name %q as the server resolved it", env.label, in.Account, env.user)
	}
	act, ok := firstOf(events, audit.KindAction, "/server/sql")
	if !ok {
		t.Fatalf("%s: no action event for the console POST; got %+v", env.label, events)
	}
	if act.Account != in.Account {
		t.Errorf("%s: action account = %q, want %q — the identity did not reach the emitting middleware", env.label, act.Account, in.Account)
	}
	if act.Engine != env.engine {
		t.Errorf("%s: action engine = %q, want %q", env.label, act.Engine, env.engine)
	}
}

// TestLiveAuditStatementRedaction: with audit.statements on, creating an
// account and setting its password DO write the CREATE/ALTER statements into
// the trail — with the password stripped, in both its raw and engine-quoted
// forms. Both engines, because their DCL differs (MySQL `IDENTIFIED BY '…'`
// vs PostgreSQL `PASSWORD '…'`/E'…') and each quotes the password
// differently. The password deliberately carries a quote AND a backslash so
// the quoted needle differs from the raw bytes on both engines. The
// assertions read the DECODED events, not the raw JSONL — JSON escaping would
// hide an unredacted backslash-bearing password from a raw Contains.
func TestLiveAuditStatementRedactionMySQL(t *testing.T) {
	liveAuditStatementRedaction(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveAuditStatementRedactionPostgres(t *testing.T) {
	liveAuditStatementRedaction(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func liveAuditStatementRedaction(t *testing.T, env liveEnv) {
	const account = "tablex_redact_probe"
	const password = `unmistakable-aud1t-p4ss'\word`

	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	loginDB := ""
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
		loginDB = "postgres"
	}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s: %v", env.label, err)
	}
	defer admin.Close()
	dropAccount := func() {
		stmt := "DROP USER IF EXISTS '" + account + "'@'%'"
		if env.engine == "postgres" {
			stmt = "DROP ROLE IF EXISTS " + d.QuoteIdent(account)
		}
		if _, err := admin.Exec(context.Background(), stmt); err != nil {
			t.Errorf("drop probe account: %v", err)
		}
	}
	dropAccount()
	defer dropAccount()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath, Statements: true}
		cfg.Servers = []config.ServerConfig{{
			Name: testServerName, Engine: env.engine,
			Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: loginDB,
		}}
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp := postForm(t, client, ts.URL+"/server/users", url.Values{
		"csrf_token": {csrf}, "action": {"create_user"},
		"user_name": {account}, "password": {password}, "attr_login": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%s: create_user = %d, want 303 — no DCL ran, so this test would prove nothing", env.label, resp.StatusCode)
	}
	host := ""
	if env.engine == "mysql" {
		host = "%"
	}
	resp = postForm(t, client, ts.URL+"/server/users", url.Values{
		"csrf_token": {csrf}, "action": {"set_password"},
		"user_name": {account}, "user_host": {host}, "password": {password},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%s: set_password = %d, want 303", env.label, resp.StatusCode)
	}

	quoted := d.QuoteString(password)
	var recorded int
	for _, e := range auditEvents(t, auditPath) {
		for _, field := range []struct{ name, value string }{
			{"statement", e.Statement}, {"detail", e.Detail},
		} {
			if strings.Contains(field.value, password) {
				t.Errorf("%s: the audit trail's %s field contains the raw password: %q", env.label, field.name, field.value)
			}
			if strings.Contains(field.value, quoted) {
				t.Errorf("%s: the audit trail's %s field contains the quoted password: %q", env.label, field.name, field.value)
			}
		}
		// The DCL itself must still be recorded — redaction, not omission —
		// with the password's place marked.
		if e.Kind == audit.KindStatement && strings.Contains(e.Statement, account) && strings.Contains(e.Statement, "***") {
			recorded++
		}
	}
	if recorded < 2 {
		t.Errorf("%s: want >= 2 redacted DCL statement records (CREATE + ALTER) naming %q, got %d — redaction must not become omission",
			env.label, account, recorded)
	}
}

// TestLiveBlankPasswordRefused: submitting a BLANK password to either
// password-carrying branch (create-account and per-row Set) must be a 400
// before any DCL is built. The engines diverge on what a blank would do —
// MySQL/MariaDB create an account that authenticates with an EMPTY password,
// PostgreSQL emits PASSWORD NULL and removes password authentication — and
// both were silently flashed as success. One test per engine, both branches.
func TestLiveBlankPasswordRefusedMySQL(t *testing.T) {
	liveBlankPasswordRefused(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveBlankPasswordRefusedPostgres(t *testing.T) {
	liveBlankPasswordRefused(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func liveBlankPasswordRefused(t *testing.T, env liveEnv) {
	const account = "tablex_blankpw_probe"
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	loginDB := ""
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
		loginDB = "postgres"
	}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s: %v", env.label, err)
	}
	defer admin.Close()
	dropAccount := func() {
		stmt := "DROP USER IF EXISTS '" + account + "'@'%'"
		if env.engine == "postgres" {
			stmt = "DROP ROLE IF EXISTS " + d.QuoteIdent(account)
		}
		if _, err := admin.Exec(context.Background(), stmt); err != nil {
			t.Errorf("drop probe account: %v", err)
		}
	}
	dropAccount()
	defer dropAccount()

	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Servers = []config.ServerConfig{{
			Name: testServerName, Engine: env.engine,
			Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: loginDB,
		}}
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	// Branch 1: create_user with a blank password → 400, and NO account exists.
	resp := postForm(t, client, ts.URL+"/server/users", url.Values{
		"csrf_token": {csrf}, "action": {"create_user"},
		"user_name": {account}, "password": {""}, "attr_login": {"1"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("%s: blank-password create_user = %d, want 400", env.label, resp.StatusCode)
	}
	countQ := "SELECT count(*) FROM mysql.user WHERE user = '" + account + "'"
	if env.engine == "postgres" {
		countQ = "SELECT count(*) FROM pg_roles WHERE rolname = '" + account + "'"
	}
	if got := queryRows(t, admin, countQ); strings.Join(got, "") != "0" {
		t.Fatalf("%s: blank-password create_user still created the account: %v", env.label, got)
	}

	// Seed a real account through the same form (the success path still works),
	// then Branch 2: set_password with a blank → 400, credential untouched.
	resp = postForm(t, client, ts.URL+"/server/users", url.Values{
		"csrf_token": {csrf}, "action": {"create_user"},
		"user_name": {account}, "password": {"probe-pw-1"}, "attr_login": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%s: real create_user = %d, want 303", env.label, resp.StatusCode)
	}
	host := ""
	if env.engine == "mysql" {
		host = "%"
	}
	resp = postForm(t, client, ts.URL+"/server/users", url.Values{
		"csrf_token": {csrf}, "action": {"set_password"},
		"user_name": {account}, "user_host": {host}, "password": {""},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("%s: blank set_password = %d, want 400", env.label, resp.StatusCode)
	}
	credQ, want := "SELECT authentication_string <> '' FROM mysql.user WHERE user = '"+account+"'", "1"
	if env.engine == "postgres" {
		credQ, want = "SELECT rolpassword IS NOT NULL FROM pg_authid WHERE rolname = '"+account+"'", "true"
	}
	if got := queryRows(t, admin, credQ); strings.Join(got, "") != want {
		t.Errorf("%s: blank set_password altered the credential: %v (want %s)", env.label, got, want)
	}
}

// TestLiveAuditRecordsGeneratedSQLOnADerivedPool closes the last gap in the
// statement observer's coverage.
//
// The observer rides ConnParams so that every DERIVED dial inherits it. Two of
// those paths are exercised by the SQLite tests (the login pool directly, and a
// pinned connection for the console), but the third — the per-database pool
// ConnFor opens — is not: on SQLite the file IS the database, so ConnFor hands
// back the login connection and the inheritance is never tested. On an engine with
// real databases it opens a second pool, and if OnStatement did not travel with
// the params, every structure change would go unrecorded.
func TestLiveAuditGeneratedSQLOnADerivedPoolMySQL(t *testing.T) {
	liveAuditDerivedPool(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveAuditGeneratedSQLOnADerivedPoolPostgres(t *testing.T) {
	liveAuditDerivedPool(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// auditDB is the scratch database the derived-pool test works in.
const auditDB = liveDB + "_audit"

func liveAuditDerivedPool(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	loginDB := ""
	if env.engine == "postgres" {
		adminParams.Database = "postgres"
		loginDB = "postgres"
	}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s: %v", env.label, err)
	}
	defer admin.Close()

	drop := func() {
		stmt := "DROP DATABASE IF EXISTS " + d.QuoteIdent(auditDB)
		if env.engine == "postgres" {
			stmt += " WITH (FORCE)"
		}
		if _, err := admin.Exec(context.Background(), stmt); err != nil {
			t.Errorf("drop %s: %v", auditDB, err)
		}
	}
	drop()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+d.QuoteIdent(auditDB)); err != nil {
		t.Fatalf("create %s: %v", auditDB, err)
	}
	defer drop()

	seedParams := adminParams
	seedParams.Database = auditDB
	seed, err := driver.Open(ctx, d, seedParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", auditDB, err)
	}
	if _, err := seed.Exec(ctx, "CREATE TABLE audited (id INTEGER NOT NULL)"); err != nil {
		seed.Close()
		t.Fatalf("seed: %v", err)
	}
	seed.Close()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, client, _ := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Audit = config.AuditConfig{File: auditPath, Statements: true}
		// The login binds to a DIFFERENT database than the one edited, so the edit
		// has to go through a pool ConnFor opens rather than the login pool.
		cfg.Servers = []config.ServerConfig{{
			Name: testServerName, Engine: env.engine,
			Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: loginDB,
		}}
	})
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp := postForm(t, client, ts.URL+"/db/"+auditDB+"/table/audited/structure", url.Values{
		"csrf_token": {csrf}, "action": {"add_column"},
		"col_name": {"note"}, "col_type": {"TEXT"}, "col_nullable": {"1"}, "default_mode": {"none"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%s: add_column = %d, want 303 — nothing changed, so this proves nothing", env.label, resp.StatusCode)
	}

	var found bool
	for _, e := range auditEvents(t, auditPath) {
		if e.Kind == audit.KindStatement && strings.Contains(strings.ToUpper(e.Statement), "ALTER TABLE") {
			found = true
			if e.UserSQL {
				t.Errorf("%s: generated DDL is marked as user-authored", env.label)
			}
			if e.Account == "" {
				t.Errorf("%s: the statement record names no account", env.label)
			}
		}
	}
	if !found {
		t.Errorf("%s: the ALTER TABLE run through a per-database pool was not recorded — the observer did not travel with ConnParams", env.label)
	}
}
