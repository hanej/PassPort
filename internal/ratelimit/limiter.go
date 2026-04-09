package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Limiter implements an in-memory token-bucket rate limiter with per-key buckets.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   int     // max tokens
	logger  *slog.Logger
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewLimiter creates a new rate limiter. rate is the number of tokens added per
// second. burst is the maximum number of tokens a bucket can hold.
func NewLimiter(rate float64, burst int, logger *slog.Logger) *Limiter {
	if logger == nil {
		logger = slog.Default()
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		logger:  logger,
	}
}

// Allow consumes one token from the bucket identified by key and returns true
// if the request is allowed. Tokens are refilled based on elapsed time since
// the last check, capped at the burst limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			tokens:    float64(l.burst),
			lastCheck: now,
		}
		l.buckets[key] = b
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastCheck = now

	if b.tokens < 1 {
		l.logger.Debug("rate limit exceeded", "key", key)
		return false
	}

	b.tokens--
	return true
}

// StartCleanup runs a background goroutine that periodically removes buckets
// that have not been accessed for 30 minutes. It stops when ctx is cancelled.
func (l *Limiter) StartCleanup(ctx context.Context, interval time.Duration) {
	const staleThreshold = 30 * time.Minute

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.cleanup(staleThreshold)
			}
		}
	}()
}

func (l *Limiter) cleanup(staleThreshold time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, b := range l.buckets {
		if now.Sub(b.lastCheck) > staleThreshold {
			delete(l.buckets, key)
			removed++
		}
	}
	if removed > 0 {
		l.logger.Debug("cleaned up stale rate limit buckets", "removed", removed, "remaining", len(l.buckets))
	}
}
