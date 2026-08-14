package auth

import (
	"testing"
	"time"
)

// TestRetryAfterSeconds pins the one shared Retry-After spelling: at least 1,
// rounded UP. The window is the contract's UPPER BOUND on the wait (prune
// frees a slot only after the full window), so both prior spellings
// under-promised — truncation gave a sub-second window no header at all, and
// rounding-to-nearest told a client behind a 1.4s window to retry at 1s where
// it was refused again.
func TestRetryAfterSeconds(t *testing.T) {
	cases := []struct {
		window time.Duration
		want   int
	}{
		{0, 1},                      // floor
		{500 * time.Millisecond, 1}, // sub-second: header still present
		{time.Second, 1},
		{1400 * time.Millisecond, 2}, // must NOT truncate/round to 1
		{time.Minute, 60},
		{90 * time.Second, 90},
		{-1 * time.Second, 1}, // negative floors to 1
	}
	for _, c := range cases {
		if got := RetryAfterSeconds(c.window); got != c.want {
			t.Errorf("RetryAfterSeconds(%v) = %d, want %d", c.window, got, c.want)
		}
	}
}
