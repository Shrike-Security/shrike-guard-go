// Package gemini provides a Shrike-protected Google Gemini client wrapper.
//
// It wraps google.golang.org/genai (the unified Google GenAI SDK) so every
// request is scanned against your Shrike policy BEFORE it reaches the Gemini
// API. Unsafe requests are refused with a *shrike.BlockedError; scan failures
// follow the configured fail mode (fail-closed by default).
package gemini

import (
	"context"
	"fmt"
	"iter"
	"strings"

	shrike "github.com/shrike-security/shrike-guard-go"
	"github.com/shrike-security/shrike-guard-go/scanner"
	"google.golang.org/genai"
)

// ClientOptions contains options for creating a ShrikeGemini client.
type ClientOptions struct {
	// GeminiAPIKey is the Google Gemini API key.
	GeminiAPIKey string

	// ShrikeAPIKey is the Shrike API key for authentication.
	ShrikeAPIKey string

	// ShrikeEndpoint is the Shrike API endpoint URL.
	ShrikeEndpoint string

	// FailMode defines behavior on scan failure (default: fail-closed).
	FailMode shrike.FailMode

	// ScanTimeout is the timeout for scan requests, in milliseconds.
	ScanTimeout int

	// BaseURL optionally overrides the Gemini API endpoint. Point this at a
	// Gemini-compatible gateway or proxy to route model calls elsewhere.
	// Applied via genai.HTTPOptions.BaseURL on the underlying client.
	BaseURL string
}

// Client is a drop-in wrapper around the Gemini SDK with Shrike protection.
type Client struct {
	genai    *genai.Client
	scanner  *scanner.Client
	failMode shrike.FailMode
}

// NewClient creates a new Shrike-protected Gemini client. It uses the Gemini
// Developer API backend (an API key); for Vertex AI, construct your own
// genai.Client and call the scanner directly.
func NewClient(ctx context.Context, opts ClientOptions) (*Client, error) {
	if opts.GeminiAPIKey == "" {
		return nil, shrike.NewConfigError("Gemini API key is required")
	}

	geminiCfg := &genai.ClientConfig{
		APIKey:  opts.GeminiAPIKey,
		Backend: genai.BackendGeminiAPI,
	}
	if opts.BaseURL != "" {
		geminiCfg.HTTPOptions = genai.HTTPOptions{BaseURL: opts.BaseURL}
	}
	gc, err := genai.NewClient(ctx, geminiCfg)
	if err != nil {
		return nil, shrike.NewConfigError(fmt.Sprintf("failed to create Gemini client: %v", err))
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
		genai:    gc,
		scanner:  scanner.NewClient(opts.ShrikeAPIKey, scannerOpts...),
		failMode: failMode,
	}, nil
}

// GenerateContent scans the user content, then proxies to Models.GenerateContent.
// Returns a *shrike.BlockedError if the request is refused.
func (c *Client) GenerateContent(
	ctx context.Context,
	model string,
	contents []*genai.Content,
	config *genai.GenerateContentConfig,
) (*genai.GenerateContentResponse, error) {
	if err := c.guard(ctx, contents); err != nil {
		return nil, err
	}
	return c.genai.Models.GenerateContent(ctx, model, contents, config)
}

// GenerateContentStream scans the user content BEFORE streaming starts, then
// proxies to Models.GenerateContentStream. Returns a *shrike.BlockedError if
// refused (before any tokens are produced).
func (c *Client) GenerateContentStream(
	ctx context.Context,
	model string,
	contents []*genai.Content,
	config *genai.GenerateContentConfig,
) (iter.Seq2[*genai.GenerateContentResponse, error], error) {
	if err := c.guard(ctx, contents); err != nil {
		return nil, err
	}
	return c.genai.Models.GenerateContentStream(ctx, model, contents, config), nil
}

// guard runs the scan and returns a BlockedError / ScanError, or nil to proceed.
// Proceed/refuse is decided by scanner.IsBlocked.
func (c *Client) guard(ctx context.Context, contents []*genai.Content) error {
	text := extractUserContent(contents)
	if strings.TrimSpace(text) == "" {
		return nil
	}

	result, err := c.scanner.Scan(ctx, text)
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

// extractUserContent joins the text of all user-role parts. A content with an
// empty role defaults to "user" (per the Gemini contract), so it is scanned;
// "model" turns are skipped.
func extractUserContent(contents []*genai.Content) string {
	var parts []string
	for _, ct := range contents {
		if ct == nil {
			continue
		}
		if ct.Role != "" && ct.Role != "user" {
			continue
		}
		for _, p := range ct.Parts {
			if p != nil && p.Text != "" {
				parts = append(parts, p.Text)
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

// Gemini returns the underlying genai client for direct access.
func (c *Client) Gemini() *genai.Client {
	return c.genai
}
