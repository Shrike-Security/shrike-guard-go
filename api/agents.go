package api

import (
	"context"
	"fmt"
	"time"
)

// RegisterAgentRequest is the agent registration request.
type RegisterAgentRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	PolicyID    string `json:"policy_id,omitempty"`
}

// Agent represents an agent.
type Agent struct {
	AgentID       string    `json:"agent_id"`
	CustomerID    string    `json:"customer_id"`
	Name          string    `json:"name"`
	Description   string    `json:"description,omitempty"`
	APIKey        string    `json:"api_key"`
	PolicyID      string    `json:"policy_id,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	LastHeartbeat time.Time `json:"last_heartbeat,omitempty"`
}

// HeartbeatResponse is the heartbeat response.
type HeartbeatResponse struct {
	Status     string    `json:"status"`
	ServerTime time.Time `json:"server_time"`
}

// AgentPolicy is the agent policy.
type AgentPolicy struct {
	PolicyID string       `json:"policy_id"`
	Name     string       `json:"name"`
	Rules    []PolicyRule `json:"rules"`
}

// PolicyRule is a policy rule.
type PolicyRule struct {
	Type      string  `json:"type"`
	Action    string  `json:"action"`
	Threshold float64 `json:"threshold,omitempty"`
}

// AgentClient is the agent management client.
type AgentClient struct {
	*BaseClient
}

// NewAgentClient creates a new agent client.
func NewAgentClient(opts ClientOptions) *AgentClient {
	return &AgentClient{
		BaseClient: NewBaseClient(opts),
	}
}

// Register registers a new agent.
func (c *AgentClient) Register(ctx context.Context, req RegisterAgentRequest) (*Agent, error) {
	var resp Agent
	err := c.Post(ctx, "/api/v1/agents/register", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Heartbeat sends a heartbeat from an agent.
func (c *AgentClient) Heartbeat(ctx context.Context) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	err := c.Post(ctx, "/api/v1/agents/heartbeat", nil, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetPolicies gets the policies assigned to this agent.
func (c *AgentClient) GetPolicies(ctx context.Context) ([]AgentPolicy, error) {
	var resp []AgentPolicy
	err := c.Get(ctx, "/api/v1/agents/policies", &resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// List lists all agents for the current customer.
func (c *AgentClient) List(ctx context.Context) ([]Agent, error) {
	var resp []Agent
	err := c.Get(ctx, "/api/v1/agents", &resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetAgent gets an agent by ID.
func (c *AgentClient) GetAgent(ctx context.Context, agentID string) (*Agent, error) {
	var resp Agent
	err := c.Get(ctx, fmt.Sprintf("/api/v1/agents/%s", agentID), &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteAgent deletes an agent.
func (c *AgentClient) DeleteAgent(ctx context.Context, agentID string) error {
	return c.Delete(ctx, fmt.Sprintf("/api/v1/agents/%s", agentID))
}
