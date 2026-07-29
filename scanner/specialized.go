package scanner

import (
	"context"
	"fmt"
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
		"context":      sessionContext(toolCtx),
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
		"context":      sessionContext(toolCtx),
	}
	return c.doSpecializedScan(ctx, payload, "agent_card:"+agentCard)
}
