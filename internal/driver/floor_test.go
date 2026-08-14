package driver_test

import (
	"strings"
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	_ "github.com/tablexdev/tablex/internal/driver/mysql"
	_ "github.com/tablexdev/tablex/internal/driver/postgres"
	_ "github.com/tablexdev/tablex/internal/driver/sqlite"
)

// E6: TableX performed no version check at all, so connecting a server older
// than the documented floor degraded in place — a missing catalog column showed
// up as an empty listing or a confusing error at the point of use, with nothing
// pointing at the cause.
//
// The check runs on the SPECIALIZED dialect, because that is where the version
// has been parsed. These cases therefore go through driver.Specialize exactly as
// Open does, rather than poking at a dialect's private fields.
func TestServerVersionFloor(t *testing.T) {
	dialectFor := func(t *testing.T, engine string) driver.Dialect {
		t.Helper()
		d, ok := driver.Get(engine)
		if !ok {
			t.Fatalf("no %s dialect registered", engine)
		}
		return d
	}

	cases := []struct {
		name    string
		engine  string
		info    driver.ServerInfo
		want    bool   // expect a warning
		floorIn string // the floor the message must cite
	}{
		// MySQL: 8.0.13 introduced the DEFAULT_GENERATED marker.
		{"MySQL below the floor", "mysql",
			driver.ServerInfo{Flavor: "MySQL", Version: "8.0.12"}, true, "8.0.13"},
		{"MySQL at the floor", "mysql",
			driver.ServerInfo{Flavor: "MySQL", Version: "8.0.13"}, false, ""},
		{"MySQL well above", "mysql",
			driver.ServerInfo{Flavor: "MySQL", Version: "8.4.0"}, false, ""},
		{"MySQL 5.7 is far below", "mysql",
			driver.ServerInfo{Flavor: "MySQL", Version: "5.7.44"}, true, "8.0.13"},

		// MariaDB has its own floor AND its own version string shape: it prefixes
		// "5.5.5-" for old-client compatibility, so a naive parse reads 5.5.5 and
		// would report every modern MariaDB as ancient.
		{"MariaDB below the floor", "mysql",
			driver.ServerInfo{Flavor: "MariaDB", Version: "5.5.5-10.2.6-MariaDB"}, true, "10.2.7"},
		{"MariaDB at the floor", "mysql",
			driver.ServerInfo{Flavor: "MariaDB", Version: "5.5.5-10.2.7-MariaDB"}, false, ""},
		{"MariaDB 11.4 behind the compat prefix", "mysql",
			driver.ServerInfo{Flavor: "MariaDB", Version: "5.5.5-11.4.2-MariaDB-1:11.4.2+maria~ubu2404"}, false, ""},

		// PostgreSQL: 13 for DROP DATABASE ... WITH (FORCE).
		{"PostgreSQL below the floor", "postgres",
			driver.ServerInfo{Flavor: "PostgreSQL", Version: "12.19"}, true, "13"},
		{"PostgreSQL at the floor", "postgres",
			driver.ServerInfo{Flavor: "PostgreSQL", Version: "13.16"}, false, ""},
		{"PostgreSQL current", "postgres",
			driver.ServerInfo{Flavor: "PostgreSQL", Version: "18.0"}, false, ""},

		// An unparseable version must stay silent rather than cry wolf.
		{"MySQL with an unreadable version", "mysql",
			driver.ServerInfo{Flavor: "MySQL", Version: "some-vendor-build"}, false, ""},
		{"PostgreSQL with an unreadable version", "postgres",
			driver.ServerInfo{Flavor: "PostgreSQL", Version: "unknown"}, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := driver.Specialize(dialectFor(t, tc.engine), tc.info)
			got := driver.FloorWarning(d, tc.info)
			if (got != "") != tc.want {
				t.Fatalf("FloorWarning(%s %s) = %q, want warning=%v",
					tc.info.Flavor, tc.info.Version, got, tc.want)
			}
			if !tc.want {
				return
			}
			// The message has to be actionable: which server, and which floor.
			for _, must := range []string{tc.info.Flavor, tc.info.Version, tc.floorIn} {
				if !strings.Contains(got, must) {
					t.Errorf("warning %q does not mention %q", got, must)
				}
			}
		})
	}
}

// SQLite is compiled into the binary, so there is no server that could be older
// than a floor — it must declare none rather than assert a version it controls.
func TestSQLiteDeclaresNoFloor(t *testing.T) {
	d, ok := driver.Get("sqlite")
	if !ok {
		t.Fatal("no sqlite dialect registered")
	}
	info := driver.ServerInfo{Flavor: "SQLite", Version: "3.20.0"} // below the doc'd 3.26
	if got := driver.FloorWarning(driver.Specialize(d, info), info); got != "" {
		t.Errorf("SQLite produced a floor warning (%q); the library is vendored, so "+
			"the version is TableX's own build, not an operator's server", got)
	}
}

// An engine that declares no floor at all must not break the check.
type noFloorDialect struct{ driver.Dialect }

func TestFloorWarningIgnoresDialectsWithoutAFloor(t *testing.T) {
	base, _ := driver.Get("sqlite")
	if got := driver.FloorWarning(noFloorDialect{base}, driver.ServerInfo{Flavor: "X", Version: "1"}); got != "" {
		t.Errorf("a dialect with no VersionFloor produced %q, want no warning", got)
	}
}
