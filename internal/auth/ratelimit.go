package auth

import (
	"math"
	"sync"
	"time"
)

// RetryAfterSeconds renders a limiter window as a Retry-After header value:
// at least 1, rounded UP. The window is the contract's upper bound on the
// wait — prune frees a slot only after the FULL window has passed — so both
// prior spellings under-promised: truncation turned a sub-second window into
// no header at all, and rounding-to-nearest told a client behind a 1.4s
// window to retry at 1s, where it was refused again. One helper, one answer,
// for every throttled responder (login, session creation, the SSO routes).
func RetryAfterSeconds(window time.Duration) int {
	secs := int(math.Ceil(window.Seconds()))
	if secs < 1 {
		return 1
	}
	return secs
}

// RateLimiter is a simple sliding-window counter used to throttle login
// attempts per key, mitigating brute force. Login uses three keys: the bare IP,
// (IP, username), and (IP, predefined-server). It is safe for concurrent use.
type RateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
	now    func() time.Time // injectable for tests
}

// NewRateLimiter returns a limiter allowing at most max events per window.
// A max <= 0 disables limiting.
func NewRateLimiter(window time.Duration, max int) *RateLimiter {
	return &RateLimiter{
		window: window,
		max:    max,
		hits:   make(map[string][]time.Time),
		now:    time.Now,
	}
}

// Reserve atomically checks every key's remaining budget and, when all have
// room, records one attempt against each. The check and the recording share
// one critical section: with separate Allowed/Record calls, a concurrent burst
// of logins could all pass the check before any recording landed, exceeding
// the cap (check-then-act race). When any key is exhausted nothing is
// recorded and Reserve reports false. The login reservation is TWO-STAGE: the
// csrf middleware reserves the coarse bare-IP key before the body is parsed,
// and the Login handler reserves the identity keys — so each stage's keys are
// reserved atomically as a group (not across the two groups). Reset the identity
// keys on success; the bare-IP hit is deliberately retained.
func (rl *RateLimiter) Reserve(keys ...string) bool {
	if rl == nil || rl.max <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for _, k := range keys {
		if len(rl.prune(k)) >= rl.max {
			return false
		}
	}
	now := rl.now()
	for _, k := range keys {
		rl.hits[k] = append(rl.hits[k], now)
	}
	return true
}

// Reset clears a key's history (call on successful login).
func (rl *RateLimiter) Reset(key string) {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.hits, key)
}

// Sweep prunes expired timestamps from every key, reclaiming memory for keys
// that are never touched again (e.g. one-off attacker-controlled IP|user
// combinations that would otherwise linger until next accessed). Call it
// periodically from a background goroutine.
func (rl *RateLimiter) Sweep() {
	if rl == nil {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for key := range rl.hits {
		rl.prune(key) // prune deletes the key when it has no live timestamps left
	}
}

// prune drops timestamps older than the window. Caller holds the lock.
func (rl *RateLimiter) prune(key string) []time.Time {
	cutoff := rl.now().Add(-rl.window)
	src := rl.hits[key]
	kept := src[:0]
	for _, t := range src {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(rl.hits, key)
		return nil
	}
	rl.hits[key] = kept
	return kept
}
