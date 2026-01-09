package limiter

import (
	"sync"
	"time"
)

// Limiter implements a simple in-memory rate limiter
type Limiter struct {
	mu           sync.Mutex
	requests     map[string][]time.Time
	limit        int
	window       time.Duration
	cleanupTimer *time.Ticker
}

// New creates a new Limiter
func New(limit int, window time.Duration) *Limiter {
	l := &Limiter{
		requests:     make(map[string][]time.Time),
		limit:        limit,
		window:       window,
		cleanupTimer: time.NewTicker(10 * time.Minute),
	}

	// Background cleanup
	go l.cleanupLoop()

	return l
}

// Allow checks if the request is allowed for the given key (IP)
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	// Filter out old requests
	var active []time.Time
	if reqs, exists := l.requests[key]; exists {
		for _, t := range reqs {
			if t.After(cutoff) {
				active = append(active, t)
			}
		}
	}

	if len(active) >= l.limit {
		// Update the map with cleaned up slice even if rejected
		l.requests[key] = active
		return false
	}

	// Add new request
	active = append(active, now)
	l.requests[key] = active
	return true
}

func (l *Limiter) cleanupLoop() {
	for range l.cleanupTimer.C {
		l.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-l.window)
		for key, reqs := range l.requests {
			var active []time.Time
			for _, t := range reqs {
				if t.After(cutoff) {
					active = append(active, t)
				}
			}
			if len(active) == 0 {
				delete(l.requests, key)
			} else {
				l.requests[key] = active
			}
		}
		l.mu.Unlock()
	}
}
