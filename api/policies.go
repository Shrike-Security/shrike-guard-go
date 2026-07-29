package api

import (
	"context"
	"fmt"
	"time"
)

// Policy represents a security policy.
type Policy struct {
	PolicyID    string       `json:"policy_id"`
	CustomerID  string       `json:"customer_id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Rules       []PolicyRule `json:"rules"`
	IsDefault   bool         `json:"is_default"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// CreatePolicyRequest is the create policy request.
type CreatePolicyRequest struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Rules       []PolicyRule `json:"rules"`
	IsDefault   bool         `json:"is_default,omitempty"`
}

// UpdatePolicyRequest is the update policy request.
type UpdatePolicyRequest struct {
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	Rules       []PolicyRule `json:"rules,omitempty"`
	IsDefault   *bool        `json:"is_default,omitempty"`
}

// PolicyClient is the policy management client.
type PolicyClient struct {
	*BaseClient
}

// NewPolicyClient creates a new policy client.
func NewPolicyClient(opts ClientOptions) *PolicyClient {
	return &PolicyClient{
		BaseClient: NewBaseClient(opts),
	}
}

// List lists all policies for the current customer.
func (c *PolicyClient) List(ctx context.Context) ([]Policy, error) {
	var resp []Policy
	err := c.Get(ctx, "/api/v1/policies", &resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetPolicy gets a policy by ID.
func (c *PolicyClient) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	var resp Policy
	err := c.Get(ctx, fmt.Sprintf("/api/v1/policies/%s", policyID), &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Create creates a new policy.
func (c *PolicyClient) Create(ctx context.Context, req CreatePolicyRequest) (*Policy, error) {
	var resp Policy
	err := c.Post(ctx, "/api/v1/policies", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Update updates an existing policy.
func (c *PolicyClient) Update(ctx context.Context, policyID string, req UpdatePolicyRequest) (*Policy, error) {
	var resp Policy
	err := c.Put(ctx, fmt.Sprintf("/api/v1/policies/%s", policyID), req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeletePolicy deletes a policy.
func (c *PolicyClient) DeletePolicy(ctx context.Context, policyID string) error {
	return c.Delete(ctx, fmt.Sprintf("/api/v1/policies/%s", policyID))
}
