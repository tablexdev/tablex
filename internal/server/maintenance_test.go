package server_test

// Table maintenance. The engines share no vocabulary here — OPTIMIZE/CHECK on
// MySQL, VACUUM/REINDEX on PostgreSQL, ANALYZE on SQLite — so the offered set is
// data supplied by the dialect, and the point of the tests is that only that set
// runs, and that output which matters is not thrown away.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
)

// TestMaintenanceOffersOnlyWhatTheEngineHas — SQLite has ANALYZE and nothing
// else, because its VACUUM rebuilds the whole database file rather than a table.
func TestMaintenanceOffersOnlyWhatTheEngineHas(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/table/widgets/operations")
	if code != http.StatusOK {
		t.Fatalf("operations page = %d, want 200", code)
	}
	if !strings.Contains(body, `name="op" value="analyze"`) {
		t.Errorf("SQLite's ANALYZE is not offered:\n%s", body)
	}
	for _, absent := range []string{`value="optimize"`, `value="vacuum"`, `value="reindex"`, `value="repair"`} {
		if strings.Contains(body, absent) {
			t.Errorf("an operation this engine does not have is offered: %s", absent)
		}
	}
}

// TestMaintenanceRuns exercises the round trip and confirms the report area
// renders.
func TestMaintenanceRuns(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/operations", url.Values{
		"csrf_token": {csrf}, "action": {"maintain"}, "op": {"analyze"},
	})
	if err != nil {
		t.Fatalf("maintain POST: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("maintain = %d, want 200 (it renders in place, it does not redirect):\n%.1000s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Analyze finished") {
		t.Errorf("no confirmation was shown:\n%.2000s", body)
	}
	// SQLite's ANALYZE reports nothing; the page must say so rather than render
	// an empty grid that looks like a failure.
	if !strings.Contains(body, "reports nothing further") {
		t.Errorf("a no-output operation did not explain itself:\n%.2000s", body)
	}
}

// TestMaintenanceRejectsUnofferedOps — the form is not the authority. The
// endpoint is reachable directly, so an operation this engine never listed must
// be refused rather than passed to the dialect.
func TestMaintenanceRejectsUnofferedOps(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)
	csrf := csrfFrom(t, client, ts.URL+"/")

	for _, op := range []string{"optimize", "vacuum_full", "repair", "", "; DROP TABLE widgets"} {
		resp, err := client.PostForm(ts.URL+"/db/main/table/widgets/operations", url.Values{
			"csrf_token": {csrf}, "action": {"maintain"}, "op": {op},
		})
		if err != nil {
			t.Fatalf("POST %q: %v", op, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("op %q = %d, want 400", op, resp.StatusCode)
		}
	}
	// And the table is still there.
	if code, _ := getBody(t, client, ts.URL+"/db/main/table/widgets"); code != http.StatusOK {
		t.Fatalf("widgets browse = %d — a refused maintenance op still ran", code)
	}
}

// TestMaintenanceNotOfferedForViews — a view has no storage to maintain.
func TestMaintenanceNotOfferedForViews(t *testing.T) {
	ts, client, path := newTestServer(t)
	seedSQLiteView(t, path)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+"/db/main/table/widget_names/operations")
	if code != http.StatusOK {
		t.Fatalf("view operations page = %d, want 200", code)
	}
	if strings.Contains(body, `name="op" value=`) {
		t.Errorf("maintenance is offered for a view:\n%s", body)
	}

	csrf := csrfFrom(t, client, ts.URL+"/")
	resp, err := client.PostForm(ts.URL+"/db/main/table/widget_names/operations", url.Values{
		"csrf_token": {csrf}, "action": {"maintain"}, "op": {"analyze"},
	})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("maintaining a view = %d, want 400", resp.StatusCode)
	}
}

func seedSQLiteView(t *testing.T, path string) {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Exec(context.Background(), `CREATE VIEW widget_names AS SELECT name FROM widgets`); err != nil {
		t.Fatalf("seed view: %v", err)
	}
}

func TestLiveMySQLTableMaintenance(t *testing.T) {
	liveTableMaintenance(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"), true)
}

func TestLiveMariaDBTableMaintenance(t *testing.T) {
	liveTableMaintenance(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"), true)
}

func TestLivePostgresTableMaintenance(t *testing.T) {
	liveTableMaintenance(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"), false)
}

// liveTableMaintenance runs every operation the engine offers against a real
// table. reportsRows says whether this family answers with a status table:
// MySQL's CHECK/REPAIR do, and dropping that output would make the feature
// pointless, so it is asserted rather than assumed.
func liveTableMaintenance(t *testing.T, env liveEnv, reportsRows bool) {
	ctx := context.Background()
	d, _ := driver.Get(env.engine)
	adminParams := driver.ConnParams{Host: env.host, Port: env.port, User: env.user, Password: env.pass}
	admin, err := driver.Open(ctx, d, adminParams)
	if err != nil {
		t.Fatalf("connect %s: %v", env.label, err)
	}
	defer admin.Close()
	liveDropDB(t, admin, env.engine)
	liveCreateDB(t, admin)
	defer liveDropDB(t, admin, env.engine)

	dbParams := adminParams
	dbParams.Database = liveDB
	conn, err := driver.Open(ctx, d, dbParams)
	if err != nil {
		t.Fatalf("connect to %s: %v", liveDB, err)
	}
	defer conn.Close()
	for _, s := range []string{
		`CREATE TABLE t (id int PRIMARY KEY, tag varchar(32))`,
		`INSERT INTO t (id, tag) VALUES (1,'a'), (2,'b'), (3,'c')`,
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}

	ops := conn.TableMaintenanceOps()
	if len(ops) == 0 {
		t.Fatalf("%s offers no maintenance operations", env.label)
	}
	ref := driver.TableRef{Database: liveDB, Table: "t"}
	if env.engine == "postgres" {
		ref.Schema = "public"
	}

	sawRows := false
	for _, op := range ops {
		set, err := conn.RunTableMaintenance(ctx, ref, op.Name)
		if err != nil {
			// REPAIR is only implemented by some storage engines; a server
			// refusing it is a real answer, not a defect in the builder.
			if op.Name == "repair" {
				t.Logf("%s: %s not supported by this table's storage engine: %v", env.label, op.Name, err)
				continue
			}
			t.Errorf("%s %s: %v", env.label, op.Name, err)
			continue
		}
		if set != nil && len(set.Rows) > 0 {
			sawRows = true
		}
	}
	if reportsRows && !sawRows {
		t.Errorf("%s reported no rows for any operation; CHECK/OPTIMIZE output is being discarded", env.label)
	}

	// The table still has its rows: maintenance is not destructive.
	set, err := conn.Query(ctx, "SELECT id FROM "+conn.QualifiedName(ref)+" ORDER BY id", 10)
	if err != nil {
		t.Fatalf("verify select: %v", err)
	}
	if len(set.Rows) != 3 {
		t.Errorf("after maintenance the table has %d rows, want 3", len(set.Rows))
	}

	// An operation this engine never offered is refused by the dialect too, not
	// only by the handler.
	if _, err := conn.RunTableMaintenance(ctx, ref, "definitely_not_an_op"); err == nil {
		t.Error("the dialect accepted an unknown maintenance operation")
	}
}
