package driver_test

import (
	"testing"

	"github.com/tablexdev/tablex/internal/driver"
	"github.com/tablexdev/tablex/internal/driver/drivertest"
)

// TestDialectConformance runs the shared suite over every REGISTERED dialect,
// so a fifth engine is covered the moment its package is blank-imported here —
// no per-engine test to remember to write.
func TestDialectConformance(t *testing.T) {
	all := driver.All()
	if len(all) == 0 {
		t.Fatal("no dialects registered")
	}
	for _, d := range all {
		t.Run(d.Name(), func(t *testing.T) {
			drivertest.RunDialectSuite(t, d)
		})
	}
}

// TestSQLiteConnectionConformance runs the connection half against a real
// database. SQLite needs no Docker, so the model-population contract is
// enforced on every `go test ./...`; the live suite runs the same function
// against MySQL, MariaDB and PostgreSQL.
func TestSQLiteConnectionConformance(t *testing.T) {
	conn := openTempSQLite(t)
	drivertest.RunConnectionSuite(t, conn, driver.Scope{Database: "main"})
}
