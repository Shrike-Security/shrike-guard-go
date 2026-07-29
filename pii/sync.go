package pii

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SyncOptions configures SyncPatterns.
type SyncOptions struct {
	// Endpoint is the backend base URL, e.g. https://api.shrikesecurity.com.
	Endpoint string
	// APIKey is sent as "Authorization: Bearer <key>" when non-empty.
	APIKey string
	// Timeout for the fetch; defaults to 5s when zero.
	Timeout time.Duration
}

type backendPIIEntry struct {
	Pattern    string  `json:"pattern"`
	ThreatType string  `json:"threat_type"`
	Confidence float64 `json:"confidence"`
	Prefix     string  `json:"prefix"`
}

type backendPIIResponse struct {
	Patterns []backendPIIEntry `json:"patterns"`
	Total    int               `json:"total"`
	Version  string            `json:"version"`
}

// SyncPatterns fetches the canonical PII patterns from the Shrike backend and
// applies them to the client-side redactor so detection coverage matches the
// backend's set.
//
// It NEVER fails the caller destructively: on any failure (network, timeout,
// malformed response, zero usable patterns) it leaves the bootstrap patterns in
// place and returns (false, err) — pattern sync is a quality feature, not a
// security boundary, so failing closed on it would block legitimate work. On
// success it returns (true, nil). Callers may ignore the error and just use the
// bool.
func SyncPatterns(ctx context.Context, opts SyncOptions) (bool, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := strings.TrimRight(opts.Endpoint, "/") + "/api/pii/patterns"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("pii sync: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if opts.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("pii sync: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("pii sync: backend returned %d", resp.StatusCode)
	}

	var data backendPIIResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return false, fmt.Errorf("pii sync: malformed response: %w", err)
	}
	if len(data.Patterns) == 0 {
		return false, fmt.Errorf("pii sync: backend returned 0 patterns")
	}

	converted := make([]Pattern, 0, len(data.Patterns))
	confidenceByName := map[string]float64{}
	for _, entry := range data.Patterns {
		if entry.ThreatType == "" || entry.Pattern == "" {
			continue
		}
		// Backend regexes are written for Go's RE2 syntax — compile directly.
		re, err := regexp.Compile(entry.Pattern)
		if err != nil {
			continue // skip unparseable, don't fail the whole sync
		}
		prefix := entry.Prefix
		if prefix == "" {
			prefix = fallbackPrefixFor(entry.ThreatType)
		}
		name := threatTypeToName(entry.ThreatType)
		if entry.Confidence > confidenceByName[name] {
			confidenceByName[name] = entry.Confidence
		}
		converted = append(converted, Pattern{Name: name, Regex: re, Prefix: prefix})
	}

	if len(converted) == 0 {
		return false, fmt.Errorf("pii sync: all %d backend patterns failed conversion", len(data.Patterns))
	}

	// Higher-confidence patterns first (stable for equal confidence).
	sort.SliceStable(converted, func(i, j int) bool {
		return confidenceByName[converted[i].Name] > confidenceByName[converted[j].Name]
	})

	UpdatePatterns(converted)
	return true, nil
}

// fallbackPrefixFor derives a redaction prefix from a threat_type when the
// backend ships without one: strip a leading "pii_" and uppercase. Never empty
// (unknown types become their own uppercase tag, e.g. pii_wallet_eth →
// WALLET_ETH). Mirrors the backend's derivePIIPrefix.
func fallbackPrefixFor(threatType string) string {
	stripped := strings.TrimPrefix(threatType, "pii_")
	if up := strings.ToUpper(stripped); up != "" {
		return up
	}
	return "PII"
}

func threatTypeToName(threatType string) string {
	return strings.TrimPrefix(threatType, "pii_")
}
