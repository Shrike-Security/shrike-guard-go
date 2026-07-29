// Package openai provides a Shrike-protected OpenAI client wrapper.
package openai

import (
	"context"
	"fmt"
	"strings"

	"github.com/sashabaranov/go-openai"
	shrike "github.com/shrike-security/shrike-guard-go"
	"github.com/shrike-security/shrike-guard-go/scanner"
)

// ClientOptions contains options for creating a ShrikeOpenAI client.
type ClientOptions struct {
	// OpenAIAPIKey is the OpenAI API key.
	OpenAIAPIKey string

	// ShrikeAPIKey is the Shrike API key for authentication.
	ShrikeAPIKey string

	// ShrikeEndpoint is the Shrike API endpoint URL.
	ShrikeEndpoint string

	// FailMode defines behavior on scan failure.
	FailMode shrike.FailMode

	// ScanTimeout is the timeout for scan requests.
	ScanTimeout int // milliseconds

	// OpenAIConfig is optional custom OpenAI client config.
	OpenAIConfig *openai.ClientConfig
}

// Client is a drop-in replacement for go-openai.Client with Shrike protection.
type Client struct {
	openai    *openai.Client
	scanner   *scanner.Client
	failMode  shrike.FailMode
	shrikeKey string
	shrikeURL string
}

// NewClient creates a new Shrike-protected OpenAI client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.OpenAIAPIKey == "" {
		return nil, shrike.NewConfigError("OpenAI API key is required")
	}

	// Create OpenAI client
	var openaiClient *openai.Client
	if opts.OpenAIConfig != nil {
		openaiClient = openai.NewClientWithConfig(*opts.OpenAIConfig)
	} else {
		openaiClient = openai.NewClient(opts.OpenAIAPIKey)
	}

	// Set defaults
	endpoint := opts.ShrikeEndpoint
	if endpoint == "" {
		endpoint = shrike.DefaultEndpoint
	}

	failMode := opts.FailMode
	if failMode == "" {
		failMode = shrike.DefaultFailMode
	}

	// Create scanner client
	scannerOpts := []scanner.Option{
		scanner.WithEndpoint(endpoint),
		scanner.WithFailMode(failMode),
	}
	if opts.ScanTimeout > 0 {
		scannerOpts = append(scannerOpts, scanner.WithTimeout(
			shrike.DefaultScanTimeout,
		))
	}
	scanClient := scanner.NewClient(opts.ShrikeAPIKey, scannerOpts...)

	return &Client{
		openai:    openaiClient,
		scanner:   scanClient,
		failMode:  failMode,
		shrikeKey: opts.ShrikeAPIKey,
		shrikeURL: endpoint,
	}, nil
}

// CreateChatCompletion creates a chat completion with security scanning.
func (c *Client) CreateChatCompletion(
	ctx context.Context,
	request openai.ChatCompletionRequest,
) (openai.ChatCompletionResponse, error) {
	// 1. Scan messages
	scanResult, err := c.scanMessages(ctx, request.Messages)
	if err != nil {
		if c.failMode == shrike.FailModeClosed {
			return openai.ChatCompletionResponse{}, shrike.NewScanError(err.Error())
		}
		// Fail open - continue with request
	} else if scanResult != nil && scanner.IsBlocked(scanResult) {
		// 2. Block if refused (block / require_approval per the enforce contract)
		return openai.ChatCompletionResponse{}, shrike.NewBlockedError(
			fmt.Sprintf("Request blocked: %s", scanResult.Reason),
			scanResult.ThreatType,
			scanResult.Confidence,
			scanResult.Violations,
		)
	}

	// 3. Proxy to OpenAI
	return c.openai.CreateChatCompletion(ctx, request)
}

// CreateChatCompletionStream creates a streaming chat completion with security scanning.
func (c *Client) CreateChatCompletionStream(
	ctx context.Context,
	request openai.ChatCompletionRequest,
) (*openai.ChatCompletionStream, error) {
	// 1. Scan messages BEFORE streaming starts
	scanResult, err := c.scanMessages(ctx, request.Messages)
	if err != nil {
		if c.failMode == shrike.FailModeClosed {
			return nil, shrike.NewScanError(err.Error())
		}
		// Fail open - continue with request
	} else if scanResult != nil && scanner.IsBlocked(scanResult) {
		// 2. Block if refused (block / require_approval per the enforce contract)
		return nil, shrike.NewBlockedError(
			fmt.Sprintf("Request blocked: %s", scanResult.Reason),
			scanResult.ThreatType,
			scanResult.Confidence,
			scanResult.Violations,
		)
	}

	// 3. Proxy to OpenAI
	return c.openai.CreateChatCompletionStream(ctx, request)
}

// ScanSQL scans a SQL query for injection attacks.
func (c *Client) ScanSQL(ctx context.Context, query, database string, allowDestructive bool) (*scanner.ScanResult, error) {
	result, err := c.scanner.ScanSQL(ctx, query, database, allowDestructive)
	if err != nil {
		if c.failMode == shrike.FailModeOpen {
			return &scanner.ScanResult{Safe: true, Reason: fmt.Sprintf("Scan error: %v", err)}, nil
		}
		return nil, shrike.NewScanError(err.Error())
	}
	return result, nil
}

// ScanFile scans a file path for security risks.
func (c *Client) ScanFile(ctx context.Context, path, content string) (*scanner.ScanResult, error) {
	result, err := c.scanner.ScanFile(ctx, path, content)
	if err != nil {
		if c.failMode == shrike.FailModeOpen {
			return &scanner.ScanResult{Safe: true, Reason: fmt.Sprintf("Scan error: %v", err)}, nil
		}
		return nil, shrike.NewScanError(err.Error())
	}
	return result, nil
}

// OpenAI returns the underlying OpenAI client.
func (c *Client) OpenAI() *openai.Client {
	return c.openai
}

// extractUserContent extracts all user message content from messages.
func (c *Client) extractUserContent(messages []openai.ChatCompletionMessage) string {
	var contents []string

	for _, msg := range messages {
		if msg.Role != openai.ChatMessageRoleUser {
			continue
		}

		// Handle simple string content
		if msg.Content != "" {
			contents = append(contents, msg.Content)
		}

		// Handle multimodal content
		if len(msg.MultiContent) > 0 {
			for _, part := range msg.MultiContent {
				if part.Type == openai.ChatMessagePartTypeText {
					contents = append(contents, part.Text)
				}
			}
		}
	}

	return strings.Join(contents, "\n")
}

// scanMessages scans user messages for security threats.
func (c *Client) scanMessages(ctx context.Context, messages []openai.ChatCompletionMessage) (*scanner.ScanResult, error) {
	userContent := c.extractUserContent(messages)

	if strings.TrimSpace(userContent) == "" {
		return &scanner.ScanResult{Safe: true, Reason: "No user content to scan"}, nil
	}

	return c.scanner.Scan(ctx, userContent)
}
