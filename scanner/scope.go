package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	shrike "github.com/shrike-security/shrike-guard-go"
)

// DeclareScopeOptions declares the tool scope an agent is permitted to operate
// within. Subsequent scans for that agent are enforced against it.
//
// Refreshing: once a scope exists, a later call from the agent's own key is a
// refresh. Every field left unset is inherited from the scope on file, so
// DeclareScopeOptions{AgentID: id, MaxDurationSeconds: 7200} is a complete
// refresh: the time limit starts again and everything else stays as the
// operator set it. A refresh may narrow but never widen; the backend answers
// 403 with reason "widening" otherwise, or reason "ceiling_reached" once the
// operator's renewal window has closed.
type DeclareScopeOptions struct {
	// AgentID is the agent identity this scope applies to (required).
	AgentID string
	// AllowedTools are the exact tool names permitted; []string{"*"} = any.
	// Required on a first declaration; leave nil on a refresh to inherit.
	AllowedTools []string
	// ForbiddenTools, when set, win over AllowedTools.
	ForbiddenTools []string
	// Purpose is an optional audit + dashboard label.
	Purpose string
	// MaxDurationSeconds is an optional TTL measured from the latest declaration.
	MaxDurationSeconds int
	// ExpiresAt is an optional ISO-8601 absolute expiry.
	ExpiresAt string
	// RenewableSeconds is the renewal window: how long, from the operator's
	// grant, the agent's own key may keep refreshing this scope. Honoured on a
	// first declaration; on a refresh the stored value always wins.
	RenewableSeconds int
}

// DeclareScopeResult is the persisted scope row returned by
// POST /api/v1/agent/scope/declare, plus derived active_until + expired fields.
type DeclareScopeResult struct {
	ScopeID            string   `json:"scope_id,omitempty"`
	AgentID            string   `json:"agent_id,omitempty"`
	Purpose            string   `json:"purpose,omitempty"`
	AllowedTools       []string `json:"allowed_tools,omitempty"`
	ForbiddenTools     []string `json:"forbidden_tools,omitempty"`
	MaxDurationSeconds int      `json:"max_duration_seconds,omitempty"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	ActiveUntil        string   `json:"active_until,omitempty"`
	Expired            bool     `json:"expired,omitempty"`
	// RenewableSeconds / RenewableUntil / CeilingReached describe the renewal
	// window: until when this key may refresh the scope itself, and whether
	// that has passed. Empty RenewableUntil means no ceiling.
	RenewableSeconds int    `json:"renewable_seconds,omitempty"`
	RenewableUntil   string `json:"renewable_until,omitempty"`
	CeilingReached   bool   `json:"ceiling_reached,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// DeclareScope declares an agent's tool scope. It POSTs to
// /api/v1/agent/scope/declare and returns the persisted scope row.
func (c *Client) DeclareScope(ctx context.Context, opts DeclareScopeOptions) (*DeclareScopeResult, error) {
	payload := map[string]interface{}{
		"agent_id": opts.AgentID,
	}
	// nil = omitted (inherit on a refresh); an explicit empty slice is sent
	// as [] and means "no tools", which is a valid narrowing.
	if opts.AllowedTools != nil {
		payload["allowed_tools"] = opts.AllowedTools
	}
	if opts.Purpose != "" {
		payload["purpose"] = opts.Purpose
	}
	if opts.ForbiddenTools != nil {
		payload["forbidden_tools"] = opts.ForbiddenTools
	}
	if opts.MaxDurationSeconds > 0 {
		payload["max_duration_seconds"] = opts.MaxDurationSeconds
	}
	if opts.ExpiresAt != "" {
		payload["expires_at"] = opts.ExpiresAt
	}
	if opts.RenewableSeconds > 0 {
		payload["renewable_seconds"] = opts.RenewableSeconds
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/v1/agent/scope/declare", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range GetScanHeaders(c.apiKey, "") {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("declareScope request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(resp.Body)
		msg := fmt.Sprintf("declareScope failed: %d", resp.StatusCode)
		if t := strings.TrimSpace(string(text)); t != "" {
			msg += " — " + t
		}
		return nil, shrike.NewScanError(msg)
	}

	var result DeclareScopeResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode declareScope response: %w", err)
	}
	return &result, nil
}
