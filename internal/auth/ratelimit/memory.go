package ratelimit

import (
	"strings"
	"sync"
	"time"
)

type MemoryLimiter struct {
	mu       sync.Mutex
	attempts map[string]attemptState
	limit    int
	window   time.Duration
	now      func() time.Time
}

type attemptState struct {
	Count   int
	ResetAt time.Time
}

func NewMemoryLimiter(limit int, window time.Duration) *MemoryLimiter {
	if limit <= 0 {
		limit = 5
	}
	if window <= 0 {
		window = time.Minute
	}

	return &MemoryLimiter{
		attempts: make(map[string]attemptState),
		limit:    limit,
		window:   window,
		now:      time.Now,
	}
}

func (l *MemoryLimiter) Allow(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	state, ok := l.attempts[normalized]
	if !ok || now.After(state.ResetAt) {
		l.attempts[normalized] = attemptState{
			Count:   1,
			ResetAt: now.Add(l.window),
		}
		return true
	}

	if state.Count >= l.limit {
		return false
	}

	state.Count++
	l.attempts[normalized] = state
	return true
}

func (l *MemoryLimiter) Reset(key string) {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, normalized)
}
