package driver

import (
	"context"
	"sync"
)

// DumpMemo caches a dump's schema-wide catalog reads so a dialect's per-table
// builders can share one query instead of repeating it per table.
//
// The problem it solves is structural: the dump planner calls DumpTableCreate
// once per table, and a dialect's builder may need facts (PostgreSQL identity
// options, for one) that are cheapest to read for the whole schema at once. The
// builder cannot see the table list, and the planner cannot see what the
// builder needs — so the memo rides the context between them, next to
// WithServerFlavor.
//
// The contract is deliberately weak: a MISS simply computes the value. With no
// memo attached — every caller outside the dump path — every lookup misses, so
// the memoized and unmemoized paths return identical results and the memo can
// only change how many queries run, never what they produce. That is what keeps
// this an optimization rather than a second code path with its own bugs.
//
// The load function runs under the memo's lock, so a value is computed exactly
// once even though the dump path is sequential today.
type DumpMemo struct {
	mu sync.Mutex
	m  map[string]memoEntry
}

type memoEntry struct {
	v   any
	err error
}

type dumpMemoKey struct{}

// WithDumpMemo attaches a fresh memo to ctx. Call it once per dump, before the
// per-table builders run. The memo is scoped to that context and dies with it,
// so nothing is cached across requests and a catalog change between dumps
// cannot be served stale.
func WithDumpMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, dumpMemoKey{}, &DumpMemo{})
}

// HasDumpMemo reports whether a dump memo is attached, which is the same
// question as "is there more than one table to amortize a schema-wide read
// across?" — the planner attaches one only for a multi-table dump. A dialect
// whose amortized read would otherwise scan a whole schema to serve ONE table
// (a table-scope export, or the display path) uses this to narrow that read
// instead. It changes only the width and count of the queries, never their
// results, which is the same contract the memo itself keeps.
func HasDumpMemo(ctx context.Context) bool {
	_, ok := ctx.Value(dumpMemoKey{}).(*DumpMemo)
	return ok
}

// MemoizedDump returns the value for key, calling load on a miss. Errors are
// cached too: a failed catalog read would fail the same way for every table, so
// re-running it per table only multiplies the latency before the same failure.
//
// key must identify everything load depends on — the schema at minimum.
func MemoizedDump(ctx context.Context, key string, load func() (any, error)) (any, error) {
	memo, _ := ctx.Value(dumpMemoKey{}).(*DumpMemo)
	if memo == nil {
		return load()
	}
	memo.mu.Lock()
	defer memo.mu.Unlock()
	if e, ok := memo.m[key]; ok {
		return e.v, e.err
	}
	v, err := load()
	if memo.m == nil {
		memo.m = make(map[string]memoEntry)
	}
	memo.m[key] = memoEntry{v, err}
	return v, err
}
