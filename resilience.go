package shrike

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Circuit breaker errors.
var (
	// ErrCircuitOpen is returned when the circuit breaker is in open state.
	ErrCircuitOpen = errors.New("shrike: circuit breaker is open")

	// ErrTooManyRequests is returned when too many requests are in-flight
	// during the half-open state.
	ErrTooManyRequests = errors.New("shrike: too many requests in half-open state")
)

// CircuitState represents the state of the circuit breaker.
type CircuitState int

const (
	// CircuitClosed is the normal operating state.
	CircuitClosed CircuitState = iota
	// CircuitOpen is the failing state — requests are rejected.
	CircuitOpen
	// CircuitHalfOpen is the recovery testing state.
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig configures the circuit breaker.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening.
	// Default: 5
	FailureThreshold uint32

	// SuccessThreshold is the number of successes in half-open before closing.
	// Default: 2
	SuccessThreshold uint32

	// Timeout is the duration the circuit stays open before transitioning
	// to half-open. Default: 30s
	Timeout time.Duration

	// MaxHalfOpenRequests is the max concurrent requests allowed in half-open.
	// Default: 3
	MaxHalfOpenRequests uint32

	// OnStateChange is called when the circuit breaker state changes.
	OnStateChange func(from, to CircuitState)
}

// DefaultCircuitBreakerConfig returns sensible defaults for SDK use.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:    5,
		SuccessThreshold:    2,
		Timeout:             30 * time.Second,
		MaxHalfOpenRequests: 3,
	}
}

// CircuitBreakerStats provides read-only stats about the circuit breaker.
type CircuitBreakerStats struct {
	State           CircuitState
	FailureCount    uint32
	SuccessCount    uint32
	LastStateChange time.Time
	LastFailureTime time.Time
}

// CircuitBreaker implements the three-state circuit breaker pattern.
type CircuitBreaker struct {
	config          CircuitBreakerConfig
	mu              sync.RWMutex
	state           CircuitState
	failureCount    uint32
	successCount    uint32
	halfOpenCount   atomic.Int32
	lastStateChange time.Time
	lastFailureTime time.Time
	openedAt        time.Time
}

// NewCircuitBreaker creates a new circuit breaker with the given config.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.SuccessThreshold == 0 {
		cfg.SuccessThreshold = 2
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxHalfOpenRequests == 0 {
		cfg.MaxHalfOpenRequests = 3
	}

	return &CircuitBreaker{
		config:          cfg,
		state:           CircuitClosed,
		lastStateChange: time.Now(),
	}
}

// Execute runs fn through the circuit breaker.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	err := fn()
	cb.afterRequest(err)
	return err
}

// ExecuteWithContext runs fn with context through the circuit breaker.
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func(context.Context) error) error {
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	err := fn(ctx)
	cb.afterRequest(err)
	return err
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Check if open circuit should transition to half-open
	if cb.state == CircuitOpen && time.Since(cb.openedAt) >= cb.config.Timeout {
		return CircuitHalfOpen
	}
	return cb.state
}

// Stats returns circuit breaker statistics.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return CircuitBreakerStats{
		State:           cb.state,
		FailureCount:    cb.failureCount,
		SuccessCount:    cb.successCount,
		LastStateChange: cb.lastStateChange,
		LastFailureTime: cb.lastFailureTime,
	}
}

func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return nil
	case CircuitOpen:
		// Check if timeout has elapsed → transition to half-open
		if time.Since(cb.openedAt) >= cb.config.Timeout {
			cb.setState(CircuitHalfOpen)
			cb.halfOpenCount.Store(1)
			return nil
		}
		return ErrCircuitOpen
	case CircuitHalfOpen:
		// Allow limited concurrent requests
		count := cb.halfOpenCount.Add(1)
		if count > int32(cb.config.MaxHalfOpenRequests) {
			cb.halfOpenCount.Add(-1)
			return ErrTooManyRequests
		}
		return nil
	default:
		return nil
	}
}

func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.onFailure()
	} else {
		cb.onSuccess()
	}
}

func (cb *CircuitBreaker) onSuccess() {
	switch cb.state {
	case CircuitClosed:
		cb.failureCount = 0
		cb.successCount++
	case CircuitHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.config.SuccessThreshold {
			cb.setState(CircuitClosed)
			cb.failureCount = 0
			cb.successCount = 0
			cb.halfOpenCount.Store(0)
		}
	}
}

func (cb *CircuitBreaker) onFailure() {
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitClosed:
		cb.failureCount++
		if cb.failureCount >= cb.config.FailureThreshold {
			cb.setState(CircuitOpen)
			cb.openedAt = time.Now()
		}
	case CircuitHalfOpen:
		// Any failure in half-open reopens immediately
		cb.setState(CircuitOpen)
		cb.openedAt = time.Now()
		cb.successCount = 0
		cb.halfOpenCount.Store(0)
	}
}

func (cb *CircuitBreaker) setState(to CircuitState) {
	from := cb.state
	if from == to {
		return
	}
	cb.state = to
	cb.lastStateChange = time.Now()

	if cb.config.OnStateChange != nil {
		// Call asynchronously to avoid holding the lock
		go cb.config.OnStateChange(from, to)
	}
}

// RetryConfig configures retry behavior with exponential backoff.
type RetryConfig struct {
	// MaxAttempts is the maximum number of attempts (including the first).
	// Default: 3
	MaxAttempts int

	// InitialBackoff is the delay before the first retry.
	// Default: 200ms
	InitialBackoff time.Duration

	// MaxBackoff is the maximum delay between retries.
	// Default: 5s
	MaxBackoff time.Duration

	// Multiplier is the backoff multiplier between retries.
	// Default: 2.0
	Multiplier float64

	// IsRetryable determines whether an error should be retried.
	// Default: retries all errors except ErrCircuitOpen and ErrTooManyRequests
	IsRetryable func(error) bool
}

// DefaultRetryConfig returns sensible defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 200 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		Multiplier:     2.0,
	}
}

// Retry executes fn with exponential backoff retry.
// It respects context cancellation and does not retry circuit breaker errors.
func Retry(ctx context.Context, cfg RetryConfig, fn func() error) error {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 200 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 5 * time.Second
	}
	if cfg.Multiplier <= 0 {
		cfg.Multiplier = 2.0
	}

	isRetryable := cfg.IsRetryable
	if isRetryable == nil {
		isRetryable = func(err error) bool {
			return !errors.Is(err, ErrCircuitOpen) && !errors.Is(err, ErrTooManyRequests)
		}
	}

	var lastErr error
	backoff := cfg.InitialBackoff

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Don't retry non-retryable errors
		if !isRetryable(lastErr) {
			return lastErr
		}

		// Don't wait after the last attempt
		if attempt == cfg.MaxAttempts-1 {
			break
		}

		// Wait with context cancellation support
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}

		// Calculate next backoff
		nextBackoff := time.Duration(float64(backoff) * cfg.Multiplier)
		if nextBackoff > cfg.MaxBackoff {
			nextBackoff = cfg.MaxBackoff
		}
		backoff = nextBackoff
	}

	return lastErr
}

// jitteredBackoff adds random jitter to avoid thundering herd.
// Not used currently but available for future use.
func jitteredBackoff(base time.Duration, attempt int, multiplier float64, max time.Duration) time.Duration {
	backoff := time.Duration(float64(base) * math.Pow(multiplier, float64(attempt)))
	if backoff > max {
		backoff = max
	}
	return backoff
}
