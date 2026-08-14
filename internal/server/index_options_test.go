package server_test

// Index options end to end. The unit tests in internal/server/handlers pin the
// validation; these pin what the engines actually build — that a partial index
// really is partial, that a descending key part is recorded as descending, and
// that a prefix length is honoured where it exists and never offered where it
// does not.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/model"
)

// TestIndexFormOffersOnlyWhatTheEngineHas — SQLite has DESC key parts and
// partial indexes, but no access-method choice and no prefix lengths.
func TestIndexFormOffersOnlyWhatTheEngineHas(t *testing.T) {
	ts, client, _ := newTestServer(t)
	login(t, client, ts.URL)

	code, body := getBody(t, client, ts.URL+structureURL)
	if code != http.StatusOK {
		t.Fatalf("structure page = %d, want 200", code)
	}
	for _, want := range []string{`name="index_where"`, `name="index_desc_0"`} {
		if !strings.Contains(body, want) {
			t.Errorf("SQLite supports it but the control is missing: %s", want)
		}
	}
	for _, absent := range []string{`name="index_method"`, `name="index_prefix_0"`} {
		if strings.Contains(body, absent) {
			t.Errorf("a control this engine cannot honour is offered: %s", absent)
		}
	}
}

// TestAddPartialDescIndex builds an index using every option SQLite has and
// reads it back from introspection.
func TestAddPartialDescIndex(t *testing.T) {
	ts, client, path := newTestServer(t)
	login(t, client, ts.URL)

	if code, body := postStructureOp(t, client, ts.URL, url.Values{
		"action": {"add_index"}, "index_name": {"idx_partial"},
		"index_columns": {"qty", "", "name"},
		"index_desc_0":  {"1"},
		"index_where":   {"qty > 0"},
	}); code != http.StatusSeeOther {
		t.Fatalf("add_index = %d, want 303:\n%.800s", code, body)
	}

	idx, ok := findIndex(sqliteIndexes(t, path, "widgets"), "idx_partial")
	if !ok {
		t.Fatal("the index was not created")
	}
	if len(idx.Columns) != 2 || idx.Columns[0].Name != "qty" || idx.Columns[1].Name != "name" {
		t.Errorf("key parts = %+v; want (qty, name) in that order", idx.Columns)
	}
	if !idx.Columns[0].Descending {
		t.Error("the first key part is not descending")
	}
	if idx.Columns[1].Descending {
		t.Error("the second key part should be ascending")
	}
	if idx.Predicate == "" {
		t.Error("the index is not partial; the WHERE clause was dropped")
	}
}

// TestAddIndexRejectsUnsupportedOptions — the form is not the authority. A
// prefix or a method posted directly to an engine that has neither must be
// refused, not silently dropped into an index that is not what was asked for.
func TestAddIndexRejectsUnsupportedOptions(t *testing.T) {
	ts, client, path := newTestServer(t)
	login(t, client, ts.URL)

	for _, tc := range []struct {
		name  string
		extra url.Values
		want  string
	}{
		{"prefix", url.Values{"index_prefix_0": {"4"}}, "prefix"},
		{"method", url.Values{"index_method": {"btree"}}, "index method"},
		{"statement in the predicate", url.Values{"index_where": {"1=1; DROP TABLE widgets"}}, "single expression"},
		{"comment in the predicate", url.Values{"index_where": {"1=1 -- x"}}, "comment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				"action": {"add_index"}, "index_name": {"idx_bad"}, "index_columns": {"name"},
			}
			for k, v := range tc.extra {
				form[k] = v
			}
			code, body := postStructureOp(t, client, ts.URL, form)
			if code != http.StatusBadRequest {
				t.Errorf("= %d, want 400", code)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("refusal does not mention %q:\n%.600s", tc.want, body)
			}
		})
	}
	if _, ok := findIndex(sqliteIndexes(t, path, "widgets"), "idx_bad"); ok {
		t.Error("a refused index was created anyway")
	}
	// The table survived the predicate that tried to drop it.
	if code, _ := getBody(t, client, ts.URL+"/db/main/table/widgets"); code != http.StatusOK {
		t.Fatalf("widgets browse = %d — a rejected predicate still executed", code)
	}
}

func sqliteIndexes(t *testing.T, path, table string) []model.Index {
	t.Helper()
	d, _ := driver.Get("sqlite")
	conn, err := driver.Open(context.Background(), d, driver.ConnParams{FilePath: path})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer conn.Close()
	idxs, err := conn.Indexes(context.Background(), driver.TableRef{Table: table})
	if err != nil {
		t.Fatalf("indexes: %v", err)
	}
	return idxs
}

func findIndex(idxs []model.Index, name string) (model.Index, bool) {
	for _, i := range idxs {
		if i.Name == name {
			return i, true
		}
	}
	return model.Index{}, false
}

func TestLivePostgresIndexOptions(t *testing.T) {
	liveIndexOptions(t, liveEnvFor(t, "POSTGRES", "postgres", 5432, "postgres"))
}

func TestLiveMySQLIndexOptions(t *testing.T) {
	liveIndexOptions(t, liveEnvFor(t, "MYSQL", "mysql", 3306, "root"))
}

func TestLiveMariaDBIndexOptions(t *testing.T) {
	liveIndexOptions(t, liveEnvFor(t, "MARIADB", "mysql", 3306, "root"))
}

// liveIndexOptions builds one index per option the engine claims and requires
// the server to accept it — the only check that separates "we emitted the
// clause" from "the engine understood it".
func liveIndexOptions(t *testing.T, env liveEnv) {
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
	ref := driver.TableRef{Database: liveDB, Table: "t"}
	if env.engine == "postgres" {
		ref.Schema = "public"
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE `+conn.QualifiedName(ref)+
		` (id int PRIMARY KEY, tag varchar(64), qty int)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	editor := conn.Dialect().(driver.SchemaEditor)
	opts := driver.IndexOptions{}
	if o, ok := conn.Dialect().(driver.IndexOptioner); ok {
		opts = o.IndexOptions()
	}
	create := func(what string, spec driver.IndexSpec) {
		t.Helper()
		stmts, err := editor.AddIndexSQL(ref, spec)
		if err != nil {
			t.Fatalf("%s build %s: %v", env.label, what, err)
		}
		if err := conn.ExecScript(ctx, stmts, conn.Capabilities().SupportsTransactionalDDL); err != nil {
			t.Errorf("%s %s (%s): %v", env.label, what, strings.Join(stmts, "; "), err)
		}
	}

	create("plain", driver.IndexSpec{Name: "i_plain", Columns: []driver.IndexColumn{{Name: "qty"}}})
	if opts.SupportsDesc {
		create("desc", driver.IndexSpec{Name: "i_desc", Columns: []driver.IndexColumn{{Name: "qty", Desc: true}}})
	}
	if opts.SupportsPrefix {
		create("prefix", driver.IndexSpec{Name: "i_prefix", Columns: []driver.IndexColumn{{Name: "tag", Prefix: 8}}})
	}
	if opts.SupportsPartial {
		create("partial", driver.IndexSpec{
			Name: "i_partial", Columns: []driver.IndexColumn{{Name: "qty"}}, Where: "qty > 0",
		})
	}
	// Every method the engine offers must build an index on SOME column — btree
	// and hash take an int, the rest are type-specific, so a method that errors
	// for this column type is reported rather than silently skipped.
	for _, m := range opts.Methods {
		if m != "btree" && m != "hash" && m != "brin" {
			continue // gin/gist/spgist need an indexable operator class we have not created
		}
		create("using "+m, driver.IndexSpec{
			Name: "i_" + m, Columns: []driver.IndexColumn{{Name: "qty"}}, Method: m,
		})
	}

	idxs, err := conn.Indexes(ctx, ref)
	if err != nil {
		t.Fatalf("indexes: %v", err)
	}
	seen := map[string]model.Index{}
	for _, i := range idxs {
		seen[i.Name] = i
	}
	if _, ok := seen["i_plain"]; !ok {
		t.Fatalf("%s: the plain index is missing from %v", env.label, seen)
	}
	if opts.SupportsPartial {
		if p, ok := seen["i_partial"]; !ok || p.Predicate == "" {
			t.Errorf("%s: the partial index lost its predicate: %+v", env.label, p)
		}
	}
	if opts.SupportsDesc {
		i := seen["i_desc"]
		if len(i.Columns) != 1 || !i.Columns[0].Descending {
			t.Errorf("%s: the descending key part came back ascending: %+v", env.label, i.Columns)
		}
	}
	if opts.SupportsPrefix {
		i := seen["i_prefix"]
		if len(i.Columns) != 1 || i.Columns[0].Prefix != 8 {
			t.Errorf("%s: the prefix length was lost: %+v", env.label, i.Columns)
		}
	}
}
