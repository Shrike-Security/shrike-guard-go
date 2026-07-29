// Package api provides API clients for Shrike backend services.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	shrike "github.com/shrike-security/shrike-guard-go"
	"github.com/shrike-security/shrike-guard-go/scanner"
)

// ClientOptions contains options for API clients.
type ClientOptions struct {
	// APIKey is the API key for authentication.
	APIKey string

	// BaseURL is the base URL for the API.
	BaseURL string

	// Timeout is the request timeout.
	Timeout time.Duration

	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client
}

// BaseClient is the base HTTP client for Shrike API.
type BaseClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewBaseClient creates a new base API client.
func NewBaseClient(opts ClientOptions) *BaseClient {
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = shrike.DefaultEndpoint
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	return &BaseClient{
		apiKey:     opts.APIKey,
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

// Request makes an HTTP request to the API.
func (c *BaseClient) Request(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range scanner.GetScanHeaders(c.apiKey, "") {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: %d - %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// Get makes a GET request.
func (c *BaseClient) Get(ctx context.Context, path string, result interface{}) error {
	return c.Request(ctx, "GET", path, nil, result)
}

// Post makes a POST request.
func (c *BaseClient) Post(ctx context.Context, path string, body, result interface{}) error {
	return c.Request(ctx, "POST", path, body, result)
}

// Put makes a PUT request.
func (c *BaseClient) Put(ctx context.Context, path string, body, result interface{}) error {
	return c.Request(ctx, "PUT", path, body, result)
}

// Delete makes a DELETE request.
func (c *BaseClient) Delete(ctx context.Context, path string) error {
	return c.Request(ctx, "DELETE", path, nil, nil)
}
