package driver

// Connection's Monitor passthroughs. They exist so the server status,
// variables and process pages run under the same read_stmt_timeout budget
// (readCtx) as every other generated read: the handlers used to call the
// dialect's Monitor methods against the bare pool, which made these three the
// only generated reads that could hold a pooled connection until the client
// disconnected — a wedged SHOW GLOBAL STATUS, times DefaultMaxOpenConns,
// exhausts the pool.

import (
	"context"

	"github.com/tablexdev/tablex/internal/model"
)

// CanMonitor reports whether the engine exposes status, variables and a
// process list (driver.Monitor).
func (c *Connection) CanMonitor() bool {
	_, ok := c.dialect.(Monitor)
	return ok
}

// Status returns the engine's runtime status counters.
func (c *Connection) Status(ctx context.Context) ([]model.Variable, error) {
	m, ok := c.dialect.(Monitor)
	if !ok {
		return nil, ErrUnsupported
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return m.Status(ctx, c.db)
}

// Variables returns the engine's configuration variables.
func (c *Connection) Variables(ctx context.Context) ([]model.Variable, error) {
	m, ok := c.dialect.(Monitor)
	if !ok {
		return nil, ErrUnsupported
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return m.Variables(ctx, c.db)
}

// Processes returns the engine's process/connection list.
func (c *Connection) Processes(ctx context.Context) (*ResultSet, error) {
	m, ok := c.dialect.(Monitor)
	if !ok {
		return nil, ErrUnsupported
	}
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	return m.Processes(ctx, c.db)
}
