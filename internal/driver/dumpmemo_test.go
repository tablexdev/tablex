package driver

import (
	"context"
	"errors"
	"testing"
)

// TestMemoizedDumpCachesPerKey pins the memo's whole contract: with a memo
// attached each key is computed once, different keys are independent, and
// errors are cached too (a failing catalog read fails the same way for every
// table, so re-running it per table only multiplies latency before the same
// failure).
func TestMemoizedDumpCachesPerKey(t *testing.T) {
	ctx := WithDumpMemo(context.Background())
	calls := map[string]int{}
	load := func(key string, v any, err error) func() (any, error) {
		return func() (any, error) {
			calls[key]++
			return v, err
		}
	}

	for range 3 {
		got, err := MemoizedDump(ctx, "a", load("a", 1, nil))
		if err != nil || got != 1 {
			t.Fatalf(`key "a": got %v, %v; want 1, nil`, got, err)
		}
	}
	if calls["a"] != 1 {
		t.Errorf(`key "a" computed %d times, want 1`, calls["a"])
	}

	if got, _ := MemoizedDump(ctx, "b", load("b", 2, nil)); got != 2 {
		t.Errorf(`key "b": got %v, want 2 (keys must be independent)`, got)
	}

	boom := errors.New("catalog read failed")
	for range 2 {
		if _, err := MemoizedDump(ctx, "c", load("c", nil, boom)); !errors.Is(err, boom) {
			t.Fatalf(`key "c": got err %v, want %v`, err, boom)
		}
	}
	if calls["c"] != 1 {
		t.Errorf(`failing key "c" computed %d times, want 1 (errors are cached)`, calls["c"])
	}
}

// TestMemoizedDumpWithoutMemoAlwaysLoads is the property that makes the memo an
// optimization rather than a second code path: with no memo on the context —
// every caller outside the dump planner — a lookup simply computes, so the
// memoized and unmemoized paths return the same value.
func TestMemoizedDumpWithoutMemoAlwaysLoads(t *testing.T) {
	calls := 0
	for range 3 {
		got, err := MemoizedDump(context.Background(), "a", func() (any, error) {
			calls++
			return calls, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != calls {
			t.Fatalf("got %v, want the freshly computed %v", got, calls)
		}
	}
	if calls != 3 {
		t.Errorf("loaded %d times without a memo, want 3", calls)
	}
}

// TestDumpMemoIsPerContext pins that nothing is cached across dumps: two
// contexts do not share entries, so a catalog change between two exports
// cannot be served stale.
func TestDumpMemoIsPerContext(t *testing.T) {
	first, second := WithDumpMemo(context.Background()), WithDumpMemo(context.Background())
	calls := 0
	load := func() (any, error) { calls++; return calls, nil }
	if got, _ := MemoizedDump(first, "k", load); got != 1 {
		t.Fatalf("first context: got %v, want 1", got)
	}
	if got, _ := MemoizedDump(second, "k", load); got != 2 {
		t.Fatalf("second context: got %v, want 2 (memos must not be shared)", got)
	}
}
