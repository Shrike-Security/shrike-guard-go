// Package anthropic provides a Shrike-protected Anthropic client wrapper.
//
// It wraps github.com/anthropics/anthropic-sdk-go so every message is scanned
// against your Shrike policy BEFORE it reaches the Anthropic API. Unsafe
// requests are refused with a *shrike.BlockedError; scan failures follow the
// configured fail mode (fail-closed by default).
package anthropic

import (
	"context"
	"fmt"
	"strings"

	anthropicsdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/ssestream"
	shrike "github.com/shrike-security/shrike-guard-go"
	"github.com/shrike-security/shrike-guard-go/scanner"
)

// ClientOptions contains options for creating a ShrikeAnthropic client.
type ClientOptions struct {
	// AnthropicAPIKey is the Anthropic API key.
	AnthropicAPIKey string

	// ShrikeAPIKey is the Shrike API key for authentication.
	ShrikeAPIKey string

	// ShrikeEndpoint is the Shrike API endpoint URL.
	ShrikeEndpoint string

	// FailMode defines behavior on scan failure (default: fail-closed).
	FailMode shrike.FailMode

	// ScanTimeout is the timeout for scan requests, in milliseconds.
	ScanTimeout int
}

// Client is a drop-in wrapper around the Anthropic SDK with Shrike protection.
type Client struct {
	anthropic anthropicsdk.Client
	scanner   *scanner.Client
	failMode  shrike.FailMode
}

// NewClient creates a new Shrike-protected Anthropic client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.AnthropicAPIKey == "" {
		return nil, shrike.NewConfigError("Anthropic API key is required")
	}

	endpoint := opts.ShrikeEndpoint
	if endpoint == "" {
		endpoint = shrike.DefaultEndpoint
	}

	failMode := opts.FailMode
	if failMode == "" {
		failMode = shrike.DefaultFailMode
	}

	scannerOpts := []scanner.Option{
		scanner.WithEndpoint(endpoint),
		scanner.WithFailMode(failMode),
	}
	if opts.ScanTimeout > 0 {
		scannerOpts = append(scannerOpts, scanner.WithTimeout(shrike.DefaultScanTimeout))
	}

	return &Client{
		anthropic: anthropicsdk.NewClient(option.WithAPIKey(opts.AnthropicAPIKey)),
		scanner:   scanner.NewClient(opts.ShrikeAPIKey, scannerOpts...),
		failMode:  failMode,
	}, nil
}

// CreateMessage scans the user content, then proxies to Messages.New.
// Returns a *shrike.BlockedError if the request is refused.
func (c *Client) CreateMessage(
	ctx context.Context,
	params anthropicsdk.MessageNewParams,
	opts ...option.RequestOption,
) (*anthropicsdk.Message, error) {
	if err := c.guard(ctx, params); err != nil {
		return nil, err
	}
	return c.anthropic.Messages.New(ctx, params, opts...)
}

// CreateMessageStream scans the user content BEFORE streaming starts, then
// proxies to Messages.NewStreaming. Returns a *shrike.BlockedError if refused.
func (c *Client) CreateMessageStream(
	ctx context.Context,
	params anthropicsdk.MessageNewParams,
	opts ...option.RequestOption,
) (*ssestream.Stream[anthropicsdk.MessageStreamEventUnion], error) {
	if err := c.guard(ctx, params); err != nil {
		return nil, err
	}
	return c.anthropic.Messages.NewStreaming(ctx, params, opts...), nil
}

// guard runs the scan and returns a BlockedError / ScanError, or nil to proceed.
// It is the single enforcement point shared by CreateMessage and
// CreateMessageStream — proceed/refuse is decided by scanner.IsBlocked.
func (c *Client) guard(ctx context.Context, params anthropicsdk.MessageNewParams) error {
	content := extractUserContent(params.Messages)
	if strings.TrimSpace(content) == "" {
		return nil
	}

	result, err := c.scanner.Scan(ctx, content)
	if err != nil {
		if c.failMode == shrike.FailModeClosed {
			return shrike.NewScanError(err.Error())
		}
		return nil // fail open — proceed
	}
	if result != nil && scanner.IsBlocked(result) {
		return shrike.NewBlockedError(
			fmt.Sprintf("Request blocked: %s", result.Reason),
			result.ThreatType,
			result.Confidence,
			result.Violations,
		)
	}
	return nil
}

// extractUserContent joins the text of all user-role messages.
func extractUserContent(messages []anthropicsdk.MessageParam) string {
	var parts []string
	for _, m := range messages {
		if m.Role != anthropicsdk.MessageParamRoleUser {
			continue
		}
		for _, block := range m.Content {
			if block.OfText != nil {
				parts = append(parts, block.OfText.Text)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// ScanSQL scans a SQL query for injection attacks.
func (c *Client) ScanSQL(ctx context.Context, query, database string, allowDestructive bool) (*scanner.ScanResult, error) {
	result, err := c.scanner.ScanSQL(ctx, query, database, allowDestructive)
	if err != nil {
		if c.failMode == shrike.FailModeOpen {
			return &scanner.ScanResult{Safe: true, Reason: fmt.Sprintf("Scan error: %v", err), Degraded: true}, nil
		}
		return nil, shrike.NewScanError(err.Error())
	}
	return result, nil
}

// ScanFile scans a file path (and optional content) for security risks.
func (c *Client) ScanFile(ctx context.Context, path, content string) (*scanner.ScanResult, error) {
	result, err := c.scanner.ScanFile(ctx, path, content)
	if err != nil {
		if c.failMode == shrike.FailModeOpen {
			return &scanner.ScanResult{Safe: true, Reason: fmt.Sprintf("Scan error: %v", err), Degraded: true}, nil
		}
		return nil, shrike.NewScanError(err.Error())
	}
	return result, nil
}

// Anthropic returns the underlying Anthropic client for direct access.
func (c *Client) Anthropic() *anthropicsdk.Client {
	return &c.anthropic
}
