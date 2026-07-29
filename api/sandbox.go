package api

import (
	"context"

	"github.com/shrike-security/shrike-guard-go/scanner"
)

// SandboxScanRequest is a quota-free sandbox scan request.
type SandboxScanRequest struct {
	Prompt  string `json:"prompt"`
	Context string `json:"context,omitempty"`
	Model   string `json:"model,omitempty"`
}

// SandboxClient scans prompts in sandbox mode — for testing without affecting
// production metrics or counting against quotas.
type SandboxClient struct {
	*BaseClient
}

// NewSandboxClient creates a new sandbox client.
func NewSandboxClient(opts ClientOptions) *SandboxClient {
	return &SandboxClient{
		BaseClient: NewBaseClient(opts),
	}
}

// Scan runs a sandbox scan (POST /api/v1/sandbox/scan). The response is
// sanitized through the same path as production scans, so internal detection
// attribution never reaches the caller.
func (c *SandboxClient) Scan(ctx context.Context, req SandboxScanRequest) (*scanner.ScanResult, error) {
	var raw map[string]interface{}
	if err := c.Post(ctx, "/api/v1/sandbox/scan", req, &raw); err != nil {
		return nil, err
	}
	return scanner.SanitizeScanResponse(raw), nil
}
