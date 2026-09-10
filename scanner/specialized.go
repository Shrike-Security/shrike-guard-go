package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	shrike "github.com/shrike-security/shrike-guard-go"
)

// A2AOptions is optional context for an agent-to-agent message scan.
type A2AOptions struct {
	SenderAgentID   string
	ReceiverAgentID string
	TaskID          string
	// Role is "user" or "agent".
	Role string
}

// ScanA2AMessage scans an agent-to-agent (A2A) protocol message.
func (c *Client) ScanA2AMessage(ctx context.Context, message string, opts A2AOptions) (*ScanResult, error) {
	if len(message) > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("Message too large (%dKB > %dKB limit)", len(message)/1024, MaxContentSize/1024),
			"Content",
		), nil
	}

	toolCtx := map[string]interface{}{}
	if opts.SenderAgentID != "" {
		toolCtx["sender_agent_id"] = opts.SenderAgentID
	}
	if opts.ReceiverAgentID != "" {
		toolCtx["receiver_agent_id"] = opts.ReceiverAgentID
	}
	if opts.TaskID != "" {
		toolCtx["task_id"] = opts.TaskID
	}
	if opts.Role != "" {
		toolCtx["role"] = opts.Role
	}

	payload := map[string]interface{}{
		"content":      message,
		"content_type": "a2a_message",
		"context":      c.sessionContext(toolCtx),
	}
	return c.doSpecializedScan(ctx, payload, "a2a_message:"+message)
}

// ScanAgentCard scans an A2A AgentCard JSON. verifySignature is reserved for
// future JWS signature verification.
func (c *Client) ScanAgentCard(ctx context.Context, agentCard string, verifySignature bool) (*ScanResult, error) {
	if len(agentCard) > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("Agent card too large (%dKB > %dKB limit)", len(agentCard)/1024, MaxContentSize/1024),
			"Content",
		), nil
	}

	toolCtx := map[string]interface{}{}
	if verifySignature {
		toolCtx["verify_signature"] = "true"
	}

	payload := map[string]interface{}{
		"content":      agentCard,
		"content_type": "agent_card",
		"context":      c.sessionContext(toolCtx),
	}
	return c.doSpecializedScan(ctx, payload, "agent_card:"+agentCard)
}

// ScanCommand scans a shell command before executing it.
//
// The highest-volume act-plane surface, and one this SDK could not reach until
// 4.1.0. Catches destructive operations, fetch-and-execute chains, reverse
// shells, credential reads, anti-forensics, and SQL injection carried inside a
// database CLI argument (`psql -c "..."`) that a shell-only rule cannot see.
//
// cwd is optional working-directory context.
func (c *Client) ScanCommand(ctx context.Context, command, cwd string) (*ScanResult, error) {
	if len(command) > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("Command too large (%dKB > %dKB limit)", len(command)/1024, MaxContentSize/1024),
			"Content",
		), nil
	}

	toolCtx := map[string]interface{}{}
	if cwd != "" {
		toolCtx["cwd"] = cwd
	}

	payload := map[string]interface{}{
		"content":      command,
		"content_type": "command",
		"context":      c.sessionContext(toolCtx),
	}
	return c.doSpecializedScan(ctx, payload, "command:"+command)
}

// ScanWebSearch scans a web search query before it reaches an external engine.
//
// Catches PII and credentials leaving through a search box, credential
// dorking, evasion tradecraft, illicit acquisition and attack-tool
// acquisition, while leaving ordinary defensive research alone.
func (c *Client) ScanWebSearch(ctx context.Context, query string) (*ScanResult, error) {
	if len(query) > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("Query too large (%dKB > %dKB limit)", len(query)/1024, MaxContentSize/1024),
			"Content",
		), nil
	}

	payload := map[string]interface{}{
		"content":      query,
		"content_type": "web_search",
		"context":      c.sessionContext(nil),
	}
	return c.doSpecializedScan(ctx, payload, "web_search:"+query)
}

// ScanRagContext scans retrieved context before it is fed to the model.
//
// RAG chunks are untrusted text somebody else wrote — the standard carrier for
// indirect prompt injection. Scan on the way in, not after the model has acted
// on them. query is the optional user query the chunks were retrieved for.
//
// Chunks are serialized as a JSON array so the backend can split them apart
// again; joining them into one string would lose the boundary an injection
// usually sits on.
func (c *Client) ScanRagContext(ctx context.Context, chunks []string, query string) (*ScanResult, error) {
	var content string
	if len(chunks) == 1 {
		content = chunks[0]
	} else {
		encoded, err := json.Marshal(chunks)
		if err != nil {
			return nil, fmt.Errorf("failed to encode chunks: %w", err)
		}
		content = string(encoded)
	}

	if len(content) > MaxContentSize {
		return sizeLimitResult(
			fmt.Sprintf("RAG context too large (%dKB > %dKB limit)", len(content)/1024, MaxContentSize/1024),
			"Content",
		), nil
	}

	toolCtx := map[string]interface{}{}
	if query != "" {
		toolCtx["query"] = query
	}

	payload := map[string]interface{}{
		"content":      content,
		"content_type": "rag_context",
		"context":      c.sessionContext(toolCtx),
	}
	return c.doSpecializedScan(ctx, payload, "rag_context:"+content)
}

// ScanMCPSchema scans a single MCP tool definition before trusting or
// registering it.
//
// Detects tool poisoning: instructions hidden in a tool's own description,
// which an agent reads as guidance and acts on without the tool ever
// executing. Call this on every entry of a tools/list response from a server
// you do not control. Screening happens once per tool at registration, not on
// every call.
//
// This is NOT a specialized content type: it has its own endpoint and its own
// detector, so it does not go through doSpecializedScan.
func (c *Client) ScanMCPSchema(ctx context.Context, name, description string, inputSchema map[string]interface{}) (*ScanResult, error) {
	payload := map[string]interface{}{
		"name":        name,
		"description": description,
	}
	if inputSchema != nil {
		payload["input_schema"] = inputSchema
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var result *ScanResult

	cbErr := c.cb.Execute(func() error {
		return shrike.Retry(ctx, c.retryCfg, func() error {
			httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/api/scan/mcp_schema", bytes.NewReader(body))
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
				return fmt.Errorf("mcp schema scan API server error: %d - %s", resp.StatusCode, string(respBody))
			}
			if resp.StatusCode != http.StatusOK {
				respBody, _ := io.ReadAll(resp.Body)
				return &nonRetryableError{fmt.Errorf("mcp schema scan API returned error: %d - %s", resp.StatusCode, string(respBody))}
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

	return result, nil
}
