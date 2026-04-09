package ratelimit

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

func TestAllow_WithinBurst(t *testing.T) {
	l := NewLimiter(10, 5, slog.Default())

	for i := 0; i < 5; i++ {
		if !l.Allow("key") {
			t.Fatalf("expected Allow to return true on call %d", i+1)
		}
	}
}

func TestAllow_BurstExhausted(t *testing.T) {
	l := NewLimiter(1, 3, slog.Default())

	// Exhaust the burst.
	for i := 0; i < 3; i++ {
		if !l.Allow("key") {
			t.Fatalf("expected Allow to return true on call %d", i+1)
		}
	}

	// Next call should be denied.
	if l.Allow("key") {
		t.Fatal("expected Allow to return false after burst exhausted")
	}
}

func TestAllow_TokensRefill(t *testing.T) {
	// Rate of 10 tokens/sec, burst of 2.
	l := NewLimiter(10, 2, slog.Default())

	// Exhaust tokens.
	for i := 0; i < 2; i++ {
		l.Allow("key")
	}
	if l.Allow("key") {
		t.Fatal("expected Allow to return false after exhausting burst")
	}

	// Simulate time passing by directly manipulating the bucket's lastCheck.
	l.mu.Lock()
	l.buckets["key"].lastCheck = time.Now().Add(-1 * time.Second)
	l.mu.Unlock()

	// After 1 second at 10 tokens/sec we should have refilled tokens.
	if !l.Allow("key") {
		t.Fatal("expected Allow to return true after token refill")
	}
}

func TestAllow_IndependentKeys(t *testing.T) {
	l := NewLimiter(1, 1, slog.Default())

	if !l.Allow("alice") {
		t.Fatal("expected Allow for alice to return true")
	}
	if l.Allow("alice") {
		t.Fatal("expected Allow for alice to return false after exhaustion")
	}

	// Bob should still be allowed — independent bucket.
	if !l.Allow("bob") {
		t.Fatal("expected Allow for bob to return true")
	}
}

func TestNewLimiter_NilLogger(t *testing.T) {
	// Passing nil logger should fall back to slog.Default() without panicking.
	l := NewLimiter(10, 5, nil)
	if l == nil {
		t.Fatal("expected non-nil limiter")
	}
	// Should work without panicking.
	if !l.Allow("key") {
		t.Error("expected Allow to return true for first request")
	}
}

func TestStartCleanup_RemovesStaleBuckets(t *testing.T) {
	l := NewLimiter(1, 1, slog.Default())

	// Create a bucket with a stale lastCheck.
	l.mu.Lock()
	l.buckets["stale"] = &bucket{
		tokens:    1,
		lastCheck: time.Now().Add(-31 * time.Minute),
	}
	l.buckets["fresh"] = &bucket{
		tokens:    1,
		lastCheck: time.Now(),
	}
	l.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run cleanup with a very short interval so it fires quickly.
	l.StartCleanup(ctx, 10*time.Millisecond)

	// Wait long enough for at least one cleanup cycle.
	time.Sleep(50 * time.Millisecond)

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, ok := l.buckets["stale"]; ok {
		t.Fatal("expected stale bucket to be removed")
	}
	if _, ok := l.buckets["fresh"]; !ok {
		t.Fatal("expected fresh bucket to still exist")
	}
}
