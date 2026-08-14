package server_test

// Live SQL-console tests. The console is the one place a user's own SQL reaches
// the engine verbatim, so its statement classifier (driver.ProfileOf over the
// session dialect) has to see the REAL server flavor and version — a fact only a
// live server can supply.

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

func TestLiveMariaDBConsoleDeleteReturning(t *testing.T) {
	liveConsoleDeleteReturning(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveConsoleDeleteReturning is a regression test. The session dialect used
// to be the registered singleton (flavor "", version 0.0.0) rather than the copy
// driver.Open specialized from the detected server, so LexerProfile reported no
// RETURNING support: the console classified `DELETE … RETURNING` as a non-row
// statement, ran it through Exec, and reported "1 row(s) affected" while
// silently discarding the rows MariaDB returned.
//
// MariaDB has supported DELETE … RETURNING since 10.0.5, below the documented
// 10.2.7 floor, so no version gate is needed here.
func liveConsoleDeleteReturning(t *testing.T, env liveEnv) {
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

	// Guard the fixture: the same test function pointed at MySQL proper would
	// fail on the RETURNING syntax itself, which would be a confusing failure.
	if flavor := admin.Info().Flavor; !strings.EqualFold(flavor, "MariaDB") {
		t.Skipf("TABLEX_TEST_MARIADB_* points at %q, not MariaDB; RETURNING is a MariaDB extension", flavor)
	}

	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	seed, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	for _, stmt := range []string{
		"CREATE TABLE ret (id INT NOT NULL PRIMARY KEY, tag VARCHAR(32) NOT NULL)",
		"INSERT INTO ret (id, tag) VALUES (1, 'keep'), (2, 'gone')",
	} {
		if _, err := seed.Exec(ctx, stmt); err != nil {
			seed.Close()
			t.Fatalf("seed %q: %v", stmt, err)
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

	resp, err = client.PostForm(ts.URL+"/db/"+liveDB+"/sql", url.Values{
		"csrf_token": {csrf},
		"sql_query":  {"DELETE FROM ret WHERE id = 2 RETURNING id, tag"},
	})
	if err != nil {
		t.Fatalf("console POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("console POST = %d, want 200:\n%.2000s", resp.StatusCode, body)
	}
	page := string(body)

	// The returned row must be RENDERED. "row(s) affected" is the Exec branch of
	// sql_console.html — reaching it means the classifier threw the rows away.
	if strings.Contains(page, "row(s) affected") {
		t.Errorf("DELETE … RETURNING ran through Exec: the returned rows were discarded\n%.3000s", page)
	}
	if !strings.Contains(page, "gone") {
		t.Errorf("console did not render the RETURNING row (expected the deleted tag %q):\n%.3000s", "gone", page)
	}

	// And it must really have deleted: RETURNING is not a dry run.
	check, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("verify connect: %v", err)
	}
	defer check.Close()
	rows := queryRows(t, check, "SELECT id FROM ret ORDER BY id")
	if len(rows) != 1 || rows[0] != "1" {
		t.Errorf("after DELETE … RETURNING, rows = %v, want just id 1", rows)
	}
}
