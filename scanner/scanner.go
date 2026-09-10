// Package scanner provides the HTTP client for the Shrike scan API.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	shrike "github.com/shrike-security/shrike-guard-go"
)

// Phase 8b: Client-side size limits to fail fast before network round-trip.
// These limits match the backend limits for consistency.
const (
	MaxContentSize = 100 * 1024 // 100KB - matches backend MaxRequestBodySize
)

// ScanResult is the customer-visible result of a scan operation, after
// sanitization. It carries the four-state governance surface (Action /
// RefuseTier / Recovery / SessionState) on BOTH safe and refuse verdicts —
// the contract-symmetry contract shared with the TS and Python SDKs.
//
// Internal detection attribution (layer timings, per-detector confidences,
// pattern names, policy IDs) is stripped by the sanitizer and never appears
// here. Confidence is a bucketed level ("high"/"medium"/"low"), not a raw
// score, to avoid exposing detection thresholds.
type ScanResult struct {
	Safe       bool                     `json:"safe"`
	Reason     string                   `json:"reason,omitempty"`
	ThreatType string                   `json:"threat_type,omitempty"`
	Severity   string                   `json:"severity,omitempty"`
	Confidence string                   `json:"confidence,omitempty"`
	Guidance   string                   `json:"guidance,omitempty"`
	Violations []map[string]interface{} `json:"violations,omitempty"`
	// Action is the server-authoritative proceed/refuse signal
	// (allow / warn / require_approval / block). IsBlocked consumes it.
	Action string `json:"action,omitempty"`
	// RefuseTier mirrors Action for callers reading the refuse tier directly.
	RefuseTier string `json:"refuse_tier,omitempty"`
	// Recovery guidance, present on refuse verdicts.
	Recovery map[string]interface{} `json:"recovery,omitempty"`
	// SessionState carries L9 session correlation outcome state (customer-visible).
	SessionState map[string]interface{} `json:"session_state,omitempty"`
	// ContentType is the specialized scan input type, e.g. "sql"/"file_path".
	ContentType string `json:"content_type,omitempty"`
	// ContentOrigin says where the scanned content came from — who is
	// answerable for it:
	//
	//   human_prompt   the operator typed it
	//   agent_output   the model generated it
	//   agent_action   the agent is about to do it (every act-plane surface)
	//   third_party    it arrived from outside: a tool result, a retrieved
	//                  document, a peer agent
	//
	// This answers the question a verdict alone cannot: was that my prompt, or
	// the agent acting on its own? Use it to decide who a refusal message is
	// addressed to. Unknown content types resolve to agent_action, never to
	// human_prompt — attributing an unattributable action to the operator is
	// the one error that is never safe to make.
	ContentOrigin string `json:"content_origin,omitempty"`
	// ApprovalInfo is present on require_approval verdicts.
	ApprovalInfo map[string]interface{} `json:"approval_info,omitempty"`
	// HeldByScope is true when the agent's declared scope held this action
	// (expired, tool outside the scope, or action ceiling reached). The hold
	// never skips the content scan: a content block wins and stands as the
	// verdict; otherwise the verdict is require_approval and ContentVerdict
	// carries what the content scan said.
	HeldByScope bool `json:"held_by_scope,omitempty"`
	// ContentVerdict is the content scan's own answer on a held action:
	// safe, refuse_tier, threat_type, severity. Present only when
	// HeldByScope is true and the content was not blocked.
	ContentVerdict map[string]interface{} `json:"content_verdict,omitempty"`
	// ClientSessionRotation carries client-side session rotation guidance.
	ClientSessionRotation interface{} `json:"client_session_rotation,omitempty"`
	// Degraded is true for a fail-open verdict returned without a completed
	// scan (failMode=open and the backend was unreachable). Lets a caller
	// distinguish "scanned and clean" from "not scanned, allowed anyway."
	Degraded bool `json:"degraded,omitempty"`
}

// Per-process session + agent identifiers included in the scan context so the
// backend's L9 session correlation sees a stable session for the life of the
// process. Mirrors the TS getSessionId()/getAgentId() behaviour.
var (
	processSessionID = uuid.New().String()
	processAgentID   = uuid.New().String()
)

var processSessionWarnOnce sync.Once

// warnOnceAboutTheProcessSession logs, once per process, that scans are using
// the process-wide session id.
//
// The process-wide default suits a CLI, a worker or a single agent, and gives
// those callers multi-turn correlation without configuration.
//
// It does not suit a server handling many end users: session identity is the
// key the backend accumulates risk against, so every user sharing one id shares
// one risk score, and one user's refusal counts against the next user's action.
// The SDK cannot tell the two deployments apart, so the default is kept and
// stated once. Pass WithSession, or derive a per-request client with
// ForSession, and the message is not emitted.
//
// Silence it with SHRIKE_SUPPRESS_SESSION_WARNING=1.
func warnOnceAboutTheProcessSession() {
	processSessionWarnOnce.Do(func() {
		if os.Getenv("SHRIKE_SUPPRESS_SESSION_WARNING") != "" {
			return
		}
		log.Printf("[shrike-guard] Using the process-wide session id. This suits a single " +
			"agent; a server handling many end users should use scanner.WithSession(id) " +
			"or client.ForSession(<per-request id>) so each user has its own session. " +
			"Set SHRIKE_SUPPRESS_SESSION_WARNING=1 to silence this message.")
	})
}

// sessionContext builds the context object sent with every scan (session_id,
// agent_id, source_application) merged with any per-call extras (e.g. database
// name for SQL scans).
//
// Method on Client rather than a package function: the identity belongs to the
// client, so a per-request client carries a per-request session.
func (c *Client) sessionContext(extra map[string]interface{}) map[string]interface{} {
	sessionID := c.sessionID
	if sessionID == "" {
		warnOnceAboutTheProcessSession()
		sessionID = processSessionID
	}

	// Client option, then SHRIKE_AGENT_ID, then the generated process id. The
	// env override is the shared contract across the three SDKs
	// (canonical-request-shapes.json, agent_id_env_override). Read at call
	// time rather than at init so a value set after import takes effect, and
	// so the contract can be tested in-process.
	agentID := c.agentID
	if agentID == "" {
		agentID = os.Getenv("SHRIKE_AGENT_ID")
	}
	if agentID == "" {
		agentID = processAgentID
	}

	ctx := map[string]interface{}{
		"session_id":         sessionID,
		"agent_id":           agentID,
		"source_application": "shrike-guard-go",
	}
	for k, v := range extra {
		ctx[k] = v
	}
	return ctx
}

// sizeLimitResult builds the local block verdict returned when content exceeds
// MaxContentSize (fail fast, no network round-trip).
func sizeLimitResult(reason, unit string) *ScanResult {
	return &ScanResult{
		Safe:       false,
		Reason:     reason,
		ThreatType: "size_limit_exceeded",
		Severity:   "low",
		Confidence: "high",
		Action:     "block",
		RefuseTier: "block",
		Violations: []map[string]interface{}{
			{
				"type":        "size_limit",
				"description": fmt.Sprintf("%s exceeds maximum size of %dKB", unit, MaxContentSize/1024),
			},
		},
	}
}

// Client is the HTTP client for the Shrike scan API.
type Client struct {
	apiKey     string
	endpoint   string
	timeout    time.Duration
	httpClient *http.Client
	failMode   shrike.FailMode
	cb         *shrike.CircuitBreaker
	retryCfg   shrike.RetryConfig
	cache      *shrike.ContentCache
	// sessionID and agentID override the process-wide identity. Empty means
	// "use the process default" — see sessionContext.
	sessionID string
	agentID   string
}

// Option is a function that configures a Client.
type Option func(*Client)

// WithSession sets the session this client scans under.
//
// Session identity is the key the backend accumulates multi-turn risk against,
// so it should mean one unit of work: one agent run, one conversation, one
// user's request. The default is a process-wide id, which suits a CLI or a
// worker but not a server serving many end users, where each user needs its
// own session.
//
// For the per-request case prefer ForSession, which reuses the parent's
// connection pool and circuit breaker.
func WithSession(sessionID string) Option {
	return func(c *Client) {
		c.sessionID = sessionID
	}
}

// WithAgentID sets the agent this client scans as.
//
// Defaults to the process-wide id (SHRIKE_AGENT_ID when set). Set it when one
// process drives several distinct agents, so scope enforcement and agent
// attribution land on the right one.
func WithAgentID(agentID string) Option {
	return func(c *Client) {
		c.agentID = agentID
	}
}

// ForSession returns a view of this client that scans under sessionID.
//
// The returned client SHARES this one's HTTP client, circuit breaker and
// cache, so calling it per request is cheap — that is the point. Build one
// Client at startup and derive a per-request view from it:
//
//	guard := scanner.NewClient(key)              // once, at startup
//
//	func handle(w http.ResponseWriter, r *http.Request) {   // per request
//	    scoped := guard.ForSession(sessionIDFor(r))
//	    verdict, err := scoped.ScanCommand(r.Context(), cmd, "")
//	}
//
// Without this, every end user shares one session id and therefore one risk
// score, and one user's refusal counts against the next user's action.
//
// Sharing the circuit breaker is deliberate: breaker state is a property of the
// backend, not of a session, and a per-request breaker would never accumulate
// enough failures to open.
func (c *Client) ForSession(sessionID string) *Client {
	view := *c
	view.sessionID = sessionID
	return &view
}

// WithEndpoint sets a custom endpoint URL.
func WithEndpoint(endpoint string) Option {
	return func(c *Client) {
		c.endpoint = strings.TrimSuffix(endpoint, "/")
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.timeout = timeout
		c.httpClient = &http.Client{Timeout: timeout}
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithFailMode sets the fail mode (open or closed).
// FailModeClosed (default): block requests when scan fails.
// FailModeOpen: allow requests when scan fails.
func WithFailMode(mode shrike.FailMode) Option {
	return func(c *Client) {
		c.failMode = mode
	}
}

// WithCircuitBreaker sets a custom circuit breaker configuration.
func WithCircuitBreaker(cfg shrike.CircuitBreakerConfig) Option {
	return func(c *Client) {
		c.cb = shrike.NewCircuitBreaker(cfg)
	}
}

// WithRetry sets a custom retry configuration.
func WithRetry(cfg shrike.RetryConfig) Option {
	return func(c *Client) {
		c.retryCfg = cfg
	}
}

// WithCache enables content-hash caching with the given TTL and max size.
//
// The cache is OFF unless you call this. It is keyed on the CONTENT ALONE, so
// a verdict shaped by one session's state can be replayed to another session,
// or to the same session after its state has changed, including an allow
// cached before a quarantine and served after it. Enable it only where a stale
// allow is acceptable: a single-tenant advisory check, or a batch pass over
// static content. Leave it off wherever the scan is an enforcement gate.
//
// Note that a non-positive ttl or maxSize means "use the default", so
// WithCache(0, 0) enables a 5-minute cache rather than disabling one.
func WithCache(ttl time.Duration, maxSize int) Option {
	return func(c *Client) {
		c.cache = shrike.NewContentCache(ttl, maxSize)
	}
}

// WithoutCache turns the client's content cache off.
//
// This is the default as of v1.2.0, so the option is only needed to undo a
// WithCache passed earlier in the same option list.
func WithoutCache() Option {
	return func(c *Client) {
		c.cache = nil
	}
}

// NewClient creates a new scan client.
// All scanning is done via backend API (tier-based: community=L1-L5, pro=L1-L9)
// No local scanning - backend has full regex patterns and normalizers.
//
// By default the client includes:
//   - Circuit breaker (5 failures → open, 30s timeout, 2 successes to close)
//   - Retry with exponential backoff (3 attempts, 200ms initial, 2x multiplier)
//   - Fail-closed mode (block requests when scan fails)
//
// Content-hash caching is OFF by default, because a cached verdict is keyed on
// content alone and can outlive the session state that shaped it. Opt in with
// WithCache when a stale allow is acceptable.
func NewClient(apiKey string, opts ...Option) *Client {
	retryCfg := shrike.DefaultRetryConfig()
	retryCfg.IsRetryable = func(err error) bool {
		// Don't retry circuit breaker errors or 4xx client errors
		if errors.Is(err, shrike.ErrCircuitOpen) || errors.Is(err, shrike.ErrTooManyRequests) {
			return false
		}
		var nre *nonRetryableError
		if errors.As(err, &nre) {
			return false
		}
		return true
	}

	c := &Client{
		apiKey:     apiKey,
		endpoint:   shrike.DefaultEndpoint,
		timeout:    shrike.DefaultScanTimeout,
		httpClient: &http.Client{Timeout: shrike.DefaultScanTimeout},
		failMode:   shrike.DefaultFailMode,
		cb:         shrike.NewCircuitBreaker(shrike.DefaultCircuitBreakerConfig()),
		retryCfg:   retryCfg,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CircuitBreakerState returns the current circuit breaker state.
func (c *Client) CircuitBreakerState() shrike.CircuitState {
	return c.cb.State()
}

// CircuitBreakerStats returns circuit breaker statistics.
func (c *Client) CircuitBreakerStats() shrike.CircuitBreakerStats {
	return c.cb.Stats()
}

// CacheStats returns content cache statistics. Zero value when the cache is
// off (see WithoutCache).
func (c *Client) CacheStats() shrike.CacheStats {
	if c.cache == nil {
		return shrike.CacheStats{}
	}
	return c.cache.Stats()
}

// ClearCache clears the content cache. No-op when the cache is off.
func (c *Client) ClearCache() {
	if c.cache == nil {
		return
	}
	c.cache.Clear()
}

// GetScanHeaders returns headers for scan API requests.
func GetScanHeaders(apiKey, requestID string) map[string]string {
	if requestID == "" {
		requestID = uuid.New().String()
	}
	return map[string]string{
		"Authorization":        fmt.Sprintf("Bearer %s", apiKey),
		"Content-Type":         "application/json",
		"X-Shrike-SDK":         shrike.SDKName,
		"X-Shrike-SDK-Version": shrike.Version,
		"X-Shrike-Request-ID":  requestID,
	}
}

// Scan scans a prompt for security threats via the backend enforce endpoint.
// Backend handles tier-based scanning:
//   - Free tier (no API key): L1-L5 (regex, unicode, encoding, token, semantic)
//   - Paid tier: L1-L9 (full cascade including LLM + session correlation)
func (c *Client) Scan(ctx context.Context, prompt string) (*ScanResult, error) {
	if strings.TrimSpace(prompt) == "" {
		return &ScanResult{Safe: true, Reason: "No content to scan"}, nil
	}
	return c.remoteScan(ctx, prompt, "")
}

// ScanWithContext scans a prompt with conversation context via the backend.
func (c *Client) ScanWithContext(ctx context.Context, prompt, contextStr string) (*ScanResult, error) {
	if strings.TrimSpace(prompt) == "" {
		return &ScanResult{Safe: true, Reason: "No content to scan"}, nil
	}
	return c.remoteScan(ctx, prompt, contextStr)
}

// remoteScan performs a full scan via the Shrike backend enforce endpoint.
// Backend handles tier-based scanning automatically based on API key presence.
//
// Flow: size check → cache check → circuit breaker → retry → HTTP → sanitize → cache store
func (c *Client) remoteScan(ctx context.Context, prompt, contextStr string) (*ScanResult, error) {
	// Phase 8b: Client-side size validation to fail fast
	totalSize := len(prompt) + len(contextStr)
	if totalSize > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("Content too large (%dKB > %dKB limit)", totalSize/1024, MaxContentSize/1024),
			"Content",
		), nil
	}

	// Check content-hash cache
	cacheKey := shrike.HashContent(prompt + contextStr)
	if c.cache != nil {
		if cached, ok := c.cache.Get(cacheKey); ok {
			if result, ok := cached.(*ScanResult); ok {
				return result, nil
			}
		}
	}

	payload := map[string]interface{}{
		"prompt":    prompt,
		"scan_type": "full",
		"context":   c.sessionContext(nil),
	}
	if contextStr != "" {
		payload["conversation_history"] = contextStr
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var result *ScanResult

	// Circuit breaker + retry wrapper
	cbErr := c.cb.Execute(func() error {
		return shrike.Retry(ctx, c.retryCfg, func() error {
			httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/scan/enforce", bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			for k, v := range GetScanHeaders(c.apiKey, "") {
				httpReq.Header.Set(k, v)
			}

			resp, err := c.httpClient.Do(httpReq)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 500 {
				return fmt.Errorf("scan API server error: %d", resp.StatusCode)
			}
			if resp.StatusCode != http.StatusOK {
				// 4xx errors are not retryable
				return &nonRetryableError{fmt.Errorf("scan API returned error: %d", resp.StatusCode)}
			}

			var raw map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			result = SanitizeScanResponse(raw)
			return nil
		})
	})

	if cbErr != nil {
		return c.handleScanError(cbErr)
	}

	// Cache the result
	if result != nil && c.cache != nil {
		c.cache.Set(cacheKey, result)
	}

	return result, nil
}

// handleScanError applies the fail mode policy to scan errors.
func (c *Client) handleScanError(err error) (*ScanResult, error) {
	if c.failMode == shrike.FailModeOpen {
		return &ScanResult{
			Safe:     true,
			Reason:   "scan_unavailable_fail_open",
			Degraded: true,
		}, nil
	}
	// Fail-closed: return the error
	return nil, shrike.NewScanError(fmt.Sprintf("scan failed: %v", err))
}

// nonRetryableError wraps errors that should not be retried (4xx).
type nonRetryableError struct {
	err error
}

func (e *nonRetryableError) Error() string { return e.err.Error() }
func (e *nonRetryableError) Unwrap() error { return e.err }

// ScanSQL scans a SQL query for injection attacks via the enforce endpoint.
func (c *Client) ScanSQL(ctx context.Context, query, database string, allowDestructive bool) (*ScanResult, error) {
	if len(query) > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("SQL query too large (%dKB > %dKB limit)", len(query)/1024, MaxContentSize/1024),
			"Query",
		), nil
	}

	toolCtx := map[string]interface{}{}
	if database != "" {
		toolCtx["database"] = database
	}
	if allowDestructive {
		toolCtx["allow_destructive"] = "true"
	}

	payload := map[string]interface{}{
		"content":      query,
		"content_type": "sql",
		"context":      c.sessionContext(toolCtx),
	}
	return c.doSpecializedScan(ctx, payload, "sql:"+query)
}

// ScanFile scans a file path (and optional content) for security risks.
func (c *Client) ScanFile(ctx context.Context, path, content string) (*ScanResult, error) {
	if len(path)+len(content) > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("File content too large (%dKB > %dKB limit)", (len(path)+len(content))/1024, MaxContentSize/1024),
			"Content",
		), nil
	}

	contentType := "file_path"
	toolCtx := map[string]interface{}{}
	if content != "" {
		contentType = "file_content"
		toolCtx["file_content"] = content
	}

	payload := map[string]interface{}{
		"content":      path,
		"content_type": contentType,
		"context":      c.sessionContext(toolCtx),
	}
	return c.doSpecializedScan(ctx, payload, contentType+":"+path)
}

// doSpecializedScan posts a specialized-content payload to the enforce endpoint
// and returns the sanitized result. cacheSeed is the content-derived cache key
// seed (content_type + ":" + content).
func (c *Client) doSpecializedScan(ctx context.Context, payload map[string]interface{}, cacheSeed string) (*ScanResult, error) {
	cacheKey := shrike.HashContent(cacheSeed)
	if c.cache != nil {
		if cached, ok := c.cache.Get(cacheKey); ok {
			if result, ok := cached.(*ScanResult); ok {
				return result, nil
			}
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var result *ScanResult

	cbErr := c.cb.Execute(func() error {
		return shrike.Retry(ctx, c.retryCfg, func() error {
			httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/scan/enforce/specialized", bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			for k, v := range GetScanHeaders(c.apiKey, "") {
				httpReq.Header.Set(k, v)
			}

			resp, err := c.httpClient.Do(httpReq)
			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 500 {
				respBody, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("scan API server error: %d - %s", resp.StatusCode, string(respBody))
			}
			if resp.StatusCode != http.StatusOK {
				respBody, _ := io.ReadAll(resp.Body)
				return &nonRetryableError{fmt.Errorf("scan API returned error: %d - %s", resp.StatusCode, string(respBody))}
			}

			var raw map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}

			result = SanitizeScanResponse(raw)
			return nil
		})
	})

	if cbErr != nil {
		return c.handleScanError(cbErr)
	}

	if result != nil && c.cache != nil {
		c.cache.Set(cacheKey, result)
	}

	return result, nil
}
