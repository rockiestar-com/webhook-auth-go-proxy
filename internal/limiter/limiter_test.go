package limiter

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	// 5 requests per 1 second
	l := New(5, 1*time.Second)

	key := "127.0.0.1"

	// Should allow 5 requests
	for i := 0; i < 5; i++ {
		if !l.Allow(key) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Should block 6th request
	if l.Allow(key) {
		t.Error("Request 6 should be blocked")
	}

	// Wait for window to pass
	time.Sleep(1100 * time.Millisecond)

	// Should allow again
	if !l.Allow(key) {
		t.Error("Request after window should be allowed")
	}
}

func TestLimiterCleanup(t *testing.T) {
	l := New(1, 1*time.Millisecond) // Very short window

	l.Allow("ip1")
	l.Allow("ip2")

	// Verify entries exist
	l.mu.Lock()
	if len(l.requests) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(l.requests))
	}
	l.mu.Unlock()

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Force cleanup by running the logic manually or waiting for ticker (too slow for test)
	// Let's rely on Allow() lazy cleanup or manual cleanup trigger if exposed.
	// Since cleanupLoop is private and runs on ticker, we can test Allow() lazy cleanup side-effect
	// or just trust the logic. The logic in Allow() cleans up *that specific key*.
	// The cleanupLoop cleans up *all* keys.

	// Let's test Allow() cleanup
	l.Allow("ip1") // This triggers cleanup for ip1

	l.mu.Lock()
	if len(l.requests["ip1"]) != 1 {
		t.Errorf("Expected ip1 to have 1 entry after expiry and new request, got %d", len(l.requests["ip1"]))
	}
	l.mu.Unlock()
}
