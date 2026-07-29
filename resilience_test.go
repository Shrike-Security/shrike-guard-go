package shrike

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreaker_ClosedToOpen(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureThreshold: 3,
		Timeout:          100 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// 3 failures should open the circuit
	for i := 0; i < 3; i++ {
		_ = cb.Execute(func() error {
			return errors.New("fail")
		})
	}

	if cb.State() != CircuitOpen {
		t.Errorf("expected CircuitOpen, got %v", cb.State())
	}

	// Next call should get ErrCircuitOpen
	err := cb.Execute(func() error { return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_OpenToHalfOpen(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return errors.New("fail") })
	}

	if cb.State() != CircuitOpen {
		t.Fatalf("expected CircuitOpen, got %v", cb.State())
	}

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Should be half-open now
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected CircuitHalfOpen, got %v", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenToClosedOnSuccess(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return errors.New("fail") })
	}

	time.Sleep(60 * time.Millisecond)

	// Two successes in half-open should close
	for i := 0; i < 2; i++ {
		err := cb.Execute(func() error { return nil })
		if err != nil {
			t.Fatalf("unexpected error in half-open: %v", err)
		}
	}

	if cb.State() != CircuitClosed {
		t.Errorf("expected CircuitClosed, got %v", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenToOpenOnFailure(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
	}
	cb := NewCircuitBreaker(cfg)

	// Trip the breaker
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return errors.New("fail") })
	}

	time.Sleep(60 * time.Millisecond)

	// Failure in half-open should reopen
	_ = cb.Execute(func() error { return errors.New("fail again") })

	// Should be open again (not half-open)
	err := cb.Execute(func() error { return nil })
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen after half-open failure, got %v", err)
	}
}

func TestCircuitBreaker_SuccessResetsClosed(t *testing.T) {
	cfg := CircuitBreakerConfig{FailureThreshold: 3}
	cb := NewCircuitBreaker(cfg)

	// 2 failures (below threshold)
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return errors.New("fail") })
	}

	// A success should reset the counter
	_ = cb.Execute(func() error { return nil })

	// 2 more failures should not trip (counter was reset)
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return errors.New("fail") })
	}

	if cb.State() != CircuitClosed {
		t.Errorf("expected CircuitClosed after reset, got %v", cb.State())
	}
}

func TestCircuitBreaker_StateChangeCallback(t *testing.T) {
	var mu sync.Mutex
	var changes []struct{ from, to CircuitState }
	done := make(chan struct{}, 1)
	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
		OnStateChange: func(from, to CircuitState) {
			mu.Lock()
			changes = append(changes, struct{ from, to CircuitState }{from, to})
			mu.Unlock()
			select {
			case done <- struct{}{}:
			default:
			}
		},
	}
	cb := NewCircuitBreaker(cfg)

	// Trip it
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error { return errors.New("fail") })
	}

	// Wait for the async callback deterministically (timeout safety net at 1s).
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("state-change callback did not fire within 1s")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(changes) != 1 || changes[0].from != CircuitClosed || changes[0].to != CircuitOpen {
		t.Errorf("expected Closed→Open callback, got %+v", changes)
	}
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())

	_ = cb.Execute(func() error { return nil })
	_ = cb.Execute(func() error { return errors.New("fail") })

	stats := cb.Stats()
	if stats.State != CircuitClosed {
		t.Errorf("expected closed state")
	}
	if stats.FailureCount != 1 {
		t.Errorf("expected 1 failure, got %d", stats.FailureCount)
	}
}

func TestRetry_SuccessOnFirstAttempt(t *testing.T) {
	var attempts int32
	err := Retry(context.Background(), DefaultRetryConfig(), func() error {
		atomic.AddInt32(&attempts, 1)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestRetry_SuccessAfterRetries(t *testing.T) {
	var attempts int32
	cfg := RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 10 * time.Millisecond,
		Multiplier:     2.0,
		MaxBackoff:     1 * time.Second,
	}

	err := Retry(context.Background(), cfg, func() error {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return errors.New("transient")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetry_ExhaustedAttempts(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 5 * time.Millisecond,
		Multiplier:     1.0,
		MaxBackoff:     50 * time.Millisecond,
	}

	err := Retry(context.Background(), cfg, func() error {
		return errors.New("persistent")
	})

	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
}

func TestRetry_NonRetryableError(t *testing.T) {
	var attempts int32
	cfg := RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 5 * time.Millisecond,
		IsRetryable: func(err error) bool {
			return err.Error() != "permanent"
		},
	}

	err := Retry(context.Background(), cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return errors.New("permanent")
	})

	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected 1 attempt for non-retryable error, got %d", attempts)
	}
	if err == nil || err.Error() != "permanent" {
		t.Errorf("expected permanent error, got %v", err)
	}
}

func TestRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := RetryConfig{
		MaxAttempts:    5,
		InitialBackoff: 1 * time.Second, // long backoff so context cancels first
		Multiplier:     1.0,
		MaxBackoff:     5 * time.Second,
	}

	var attempts int32
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := Retry(ctx, cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return errors.New("fail")
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestRetry_DoesNotRetryCircuitBreakerErrors(t *testing.T) {
	var attempts int32
	cfg := DefaultRetryConfig()
	cfg.InitialBackoff = 5 * time.Millisecond

	err := Retry(context.Background(), cfg, func() error {
		atomic.AddInt32(&attempts, 1)
		return ErrCircuitOpen
	})

	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("should not retry circuit breaker errors, got %d attempts", attempts)
	}
}
