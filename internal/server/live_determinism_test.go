package server_test

// Dump determinism: two exports of an unchanged database must be byte-identical,
// so an operator can diff two dumps and see only real schema drift.

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/config"
	"github.com/tablexdev/tablex/internal/driver"
)

func TestLivePostgresDumpDeterminism(t *testing.T) {
	liveDumpDeterminism(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

// liveDumpDeterminism is a regression test. dumpTypes ranged over the
// `domains` MAP while appending constraint-comment entries to plan.PostData,
// and the post-data sort is stable on rank — so equal-rank entries keep
// insertion order. Two domains with commented constraints therefore emitted in
// a random relative order and two dumps of the same database differed.
//
// The fixture needs several commented domain constraints: with one, any
// ordering is the same ordering, and Go's map iteration would hide the bug.
func liveDumpDeterminism(t *testing.T, env liveEnv) {
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	stmts := []string{
		`CREATE DOMAIN dom_a AS integer CONSTRAINT dom_a_pos CHECK (VALUE > 0)`,
		`COMMENT ON CONSTRAINT dom_a_pos ON DOMAIN dom_a IS 'must be positive'`,
		`CREATE DOMAIN dom_b AS text CONSTRAINT dom_b_len CHECK (length(VALUE) < 32)`,
		`COMMENT ON CONSTRAINT dom_b_len ON DOMAIN dom_b IS 'bounded length'`,
		`CREATE DOMAIN dom_c AS numeric CONSTRAINT dom_c_scale CHECK (VALUE < 1000)`,
		`COMMENT ON CONSTRAINT dom_c_scale ON DOMAIN dom_c IS 'bounded magnitude'`,
		`CREATE DOMAIN dom_d AS integer CONSTRAINT dom_d_even CHECK (VALUE % 2 = 0)`,
		`COMMENT ON CONSTRAINT dom_d_even ON DOMAIN dom_d IS 'even only'`,
		`CREATE TABLE uses_domains (id integer PRIMARY KEY, a dom_a, b dom_b, c dom_c, e dom_d)`,
		`INSERT INTO uses_domains VALUES (1, 5, 'hi', 12.5, 4)`,
	}
	for _, s := range stmts {
		if _, err := seed.Exec(ctx, s); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", s, err)
		}
	}
	seed.Close()

	ts, client, _ := newTestServerWith(t, func(c *config.Config) {
		c.Servers = append(c.Servers, config.ServerConfig{
			Name: "live", Engine: env.engine, Host: env.host, Port: env.port,
		})
	})
	csrf := csrfFrom(t, client, ts.URL+"/login")
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"csrf_token": {csrf}, "server": {"live"},
		"username": {env.user}, "password": {env.pass},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("live login = %d, want 303", resp.StatusCode)
	}
	csrf = csrfFrom(t, client, ts.URL+"/")

	dumpOnce := func() string {
		t.Helper()
		resp, err := client.PostForm(ts.URL+"/db/"+liveDB+"/export", url.Values{
			"csrf_token": {csrf}, "format": {"sql"}, "structure": {"1"}, "data": {"1"},
		})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export = %d:\n%.2000s", resp.StatusCode, b)
		}
		return string(b)
	}

	// Several rounds: with 4 domains a single unlucky-free pair proves little,
	// since Go randomizes map iteration per range rather than per process.
	first := dumpOnce()
	for i := 2; i <= 6; i++ {
		next := dumpOnce()
		if next == first {
			continue
		}
		// Report the first differing line rather than two multi-KB dumps.
		a, b := strings.Split(first, "\n"), strings.Split(next, "\n")
		for j := 0; j < len(a) && j < len(b); j++ {
			if a[j] != b[j] {
				t.Fatalf("dump %d differs from dump 1 at line %d:\n  1: %s\n  %d: %s", i, j+1, a[j], i, b[j])
			}
		}
		t.Fatalf("dump %d differs from dump 1 in length (%d vs %d lines)", i, len(b), len(a))
	}
}
