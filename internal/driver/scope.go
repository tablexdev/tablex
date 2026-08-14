package driver

// This file holds the engine-neutral value types that ADDRESS a read: what to
// introspect (Scope), which table (TableRef), how to page it (Pagination) and
// how to order it (Sort). Split out of driver.go so it stays a single role.

// Scope identifies what to introspect: a database, optionally narrowed to a
// schema. For engines without schemas, Schema is empty.
type Scope struct {
	Database string
	Schema   string
}

// TableRef identifies a single table within a database/schema.
type TableRef struct {
	Database string
	Schema   string
	Table    string
}

// Pagination is the engine-neutral limit/offset for browse pages. Offset is
// int64 so a 32-bit build can still address rows beyond 2^31.
type Pagination struct {
	Limit  int
	Offset int64
	// ByteBudget caps the cumulative retained TEXT of one scan, stopping at a
	// whole-row boundary once exceeded (Browse's "Show all" sets it; 0 disables
	// it). It is a SCAN-side bound and engine-neutral — it must never reach a
	// dialect's LimitClause, which shapes the SQL. Whole-row rather than
	// per-cell so every retained cell stays byte-exact (see rowKeyFor and
	// narrowProcessList, which act on Value.Str as the exact value).
	ByteBudget int
}

// Sort describes an ORDER BY clause built from a validated column name.
type Sort struct {
	Column     string // must be validated against real columns before use
	Descending bool
}
