package driver

import (
	"sort"
	"sync"
)

var (
	mu       sync.RWMutex
	dialects = map[string]Dialect{}
)

// Register adds a dialect to the global registry. Engine packages call this
// from their init(); cmd/tablex blank-imports them so registration happens at
// startup. Registering the same name twice panics (a programming error).
func Register(d Dialect) {
	mu.Lock()
	defer mu.Unlock()
	name := d.Name()
	if _, dup := dialects[name]; dup {
		panic("driver: duplicate dialect registered: " + name)
	}
	dialects[name] = d
}

// Get returns the dialect registered under name.
func Get(name string) (Dialect, bool) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := dialects[name]
	return d, ok
}

// RegisteredNames returns every registered dialect's name, sorted. It exists so
// callers that only need to validate or display the engine list (config
// validation, error messages) do not have to hold Dialect values — and, more
// importantly, so no second copy of the list has to be maintained by hand.
//
// The registry is populated by each engine package's init() via the blank
// imports in package main, so a build that omits a driver reports an engine
// list that matches what the binary can actually open.
func RegisteredNames() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(dialects))
	for name := range dialects {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// All returns every registered dialect, sorted by Name for stable UI ordering.
func All() []Dialect {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Dialect, 0, len(dialects))
	for _, d := range dialects {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
