package server_test

// PostgreSQL's standard_conforming_strings, live.
//
// QuoteString emits an E'…' escape string for any value carrying a backslash,
// so the literal means the same thing whether the GUC is on or off. This file
// pins the defence-in-depth half: BuildDSN appends `-c
// standard_conforming_strings=on` to the libpq options, so every session TableX
// opens has it on even when the DATABASE has been configured otherwise.
//
// It owns its own database rather than the suite's shared tablex_rt, because
// ALTER DATABASE … SET persists into every later session on that database and
// would leak into every test that follows.

import (
	"context"
	"strings"
	"syscall"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
)

// scsDB is deliberately NOT liveDB: the ALTER below is durable database state.
const scsDB = "tablex_scs"

func TestLivePostgresStandardConformingStrings(t *testing.T) {
	env := liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres")
	ctx := context.Background()
	d, ok := driver.Get(env.engine)
	if !ok {
		t.Fatalf("dialect %s not registered", env.engine)
	}
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass, Database: "postgres"}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s at %s:%d: %v", env.label, env.host, env.port, err)
	}
	defer admin.Close()

	drop := func() {
		// FORCE (PG 13+) terminates the pooled connections the checks below left.
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+scsDB+" WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", scsDB, err)
		}
	}
	drop()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+scsDB); err != nil {
		t.Fatalf("create %s: %v", scsDB, err)
	}
	// Unconditional: a failed assertion below must not leave a database whose
	// literals parse differently from every other one on this server.
	defer drop()

	// The hostile configuration. It applies to every session that connects to
	// this database from now on, which is exactly the condition the pin exists
	// for — an operator can set it per database, per role or per session.
	if _, err := admin.Exec(ctx, "ALTER DATABASE "+scsDB+" SET standard_conforming_strings = off"); err != nil {
		t.Fatalf("alter %s: %v", scsDB, err)
	}

	dbParams := adminParams
	dbParams.Database = scsDB

	// Both OpenPool branches: DialControl == nil takes sql.Open on the shared
	// stdlib registration, non-nil takes pgx.ParseConfig + stdlib.OpenDB. The
	// pin rides BuildDSN, which runs before that branch, so both must carry it —
	// and pgx stdlib's ResetSession is a noop, so a pooled connection keeps
	// whatever the startup packet set.
	for _, tc := range []struct {
		name string
		dial func(network, address string, c syscall.RawConn) error
	}{
		{"predefined server (sql.Open)", nil},
		{"ad-hoc login (pgx.Config + DialControl)", func(string, string, syscall.RawConn) error { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := dbParams
			p.DialControl = tc.dial
			// A FRESH pool: the point is what a newly opened session inherits.
			conn, err := driver.Open(ctx, d, p)
			if err != nil {
				t.Fatalf("connect to %s: %v", scsDB, err)
			}
			defer conn.Close()

			if got := queryRows(t, conn, "SHOW standard_conforming_strings"); len(got) != 1 || strings.TrimSpace(got[0]) != "on" {
				t.Fatalf("standard_conforming_strings = %v on a database configured off; the DSN pin did not reach the session", got)
			}

			// And the literal QuoteString actually builds round-trips to the
			// bytes it names. Under `off` with a plain '…' literal this value
			// would come back with the backslash doubled — or end the literal
			// early, which is the finding.
			lit := d.QuoteString(`a\'b`)
			if !strings.HasPrefix(lit, "E'") {
				t.Fatalf("QuoteString(%q) = %q; want an E'…' escape string", `a\'b`, lit)
			}
			if got := queryRows(t, conn, "SELECT "+lit); len(got) != 1 || got[0] != `a\'b` {
				t.Errorf("SELECT %s = %v, want [%q]", lit, got, `a\'b`)
			}
		})
	}
}
