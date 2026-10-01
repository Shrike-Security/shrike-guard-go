package shrike

// PII Pattern Sync — fetches canonical PII patterns from the Shrike backend
// at startup and updates the client-side redactor so detection coverage
// matches the backend's canonical set.
//
// On any failure (network, timeout, malformed response, unrecognized threat
// type) sync keeps the hardcoded bootstrap patterns. Pattern sync is a
// quality feature, NOT a security boundary — failing closed on it would
// block legitimate scans.
//
// Mirrors mcp/src/utils/piiSync.ts to keep client-side coverage uniform
// across MCP server and SDK consumers.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// piiPatternEntry is one entry in the backend's pattern response.
type piiPatternEntry struct {
	Pattern     string  `json:"pattern"`
	ThreatType  string  `json:"threat_type"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// piiPatternsResponse is the backend's response to GET /api/pii/patterns.
type piiPatternsResponse struct {
	Patterns []piiPatternEntry `json:"patterns"`
	Total    int               `json:"total"`
	Version  string            `json:"version"`
}

// prefixMap maps backend threat_type strings to client-side token prefixes.
// Backend pii_ssn -> token [SSN_1], [SSN_2], etc.
// Must stay in sync with mcp/src/utils/piiSync.ts:PREFIX_MAP.
var prefixMap = map[string]string{
	"pii_ssn":               "SSN",
	"pii_ssn_alt":           "SSN",
	"pii_credit_card":       "CARD",
	"pii_email":             "EMAIL",
	"pii_phone":             "PHONE",
	"pii_phone_intl":        "PHONE",
	"pii_street_address":    "ADDR",
	"pii_city_state_zip":    "ADDR",
	"pii_bank_account":      "ACCOUNT",
	"pii_routing_number":    "ROUTING",
	"pii_iban":              "IBAN",
	"pii_swift":             "SWIFT",
	"pii_medical_record":    "MRN",
	"pii_health_insurance":  "HEALTHID",
	"pii_drivers_license":   "DL",
	"pii_passport":          "PASSPORT",
	"pii_dob":               "DOB",
	"pii_medical_diagnosis": "MEDINFO",
	"pii_medical_code":      "MEDCODE",
	"pii_prescription":      "RX",
	"pii_ein":               "TAXID",
	"pii_tin":               "TAXID",
	"pii_potential_name":    "NAME",
}

// DefaultSyncTimeout is how long SyncPIIPatterns waits for the backend before
// keeping the fallback patterns.
const DefaultSyncTimeout = 5 * time.Second

func threatTypeToName(threatType string) string {
	if strings.HasPrefix(threatType, "pii_") {
		return threatType[4:]
	}
	return threatType
}

// SyncPIIPatternsOptions configures a SyncPIIPatterns call.
type SyncPIIPatternsOptions struct {
	// Endpoint is the Shrike backend base URL (e.g. https://api.shrikesecurity.com).
	// SyncPIIPatterns appends /api/pii/patterns.
	Endpoint string

	// APIKey is sent as "Authorization: Bearer <key>" when non-empty.
	// The endpoint is currently unauthenticated, but sending the key keeps
	// the client forward-compatible.
	APIKey string

	// Timeout is the HTTP timeout. Zero falls back to DefaultSyncTimeout.
	Timeout time.Duration

	// HTTPClient lets callers inject a custom *http.Client (for testing,
	// custom transports, instrumented round-trippers). Zero falls back to
	// a client with the configured Timeout.
	HTTPClient *http.Client
}

// SyncPIIPatterns fetches canonical PII patterns from the Shrike backend and
// applies them to the client-side redactor.
//
// Never returns an error that blocks scans — pattern sync is a quality feature.
// The returned error is informational only; the redactor is guaranteed to
// remain in a usable state regardless of the outcome.
//
//	err := shrike.SyncPIIPatterns(ctx, shrike.SyncPIIPatternsOptions{
//	    Endpoint: "https://api.shrikesecurity.com",
//	    APIKey:   os.Getenv("SHRIKE_API_KEY"),
//	})
func SyncPIIPatterns(ctx context.Context, opts SyncPIIPatternsOptions) error {
	fallbackCount := GetPIIPatternCount()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultSyncTimeout
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	endpoint := strings.TrimRight(opts.Endpoint, "/")
	url := endpoint + "/api/pii/patterns"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w (kept %d fallback patterns)", err, fallbackCount)
	}
	req.Header.Set("Accept", "application/json")
	if opts.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+opts.APIKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("pii pattern sync failed (%w); kept %d fallback patterns", err, fallbackCount)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pii pattern sync: backend returned %d; kept %d fallback patterns", resp.StatusCode, fallbackCount)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("pii pattern sync: read body: %w (kept %d fallback patterns)", err, fallbackCount)
	}

	var data piiPatternsResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("pii pattern sync: malformed JSON: %w (kept %d fallback patterns)", err, fallbackCount)
	}

	if len(data.Patterns) == 0 {
		return fmt.Errorf("pii pattern sync: backend returned 0 patterns; kept %d fallback patterns", fallbackCount)
	}

	converted := make([]PIIPattern, 0, len(data.Patterns))
	confidenceByName := make(map[string]float64, len(data.Patterns))

	for _, entry := range data.Patterns {
		prefix, ok := prefixMap[entry.ThreatType]
		if !ok {
			continue // unknown threat type
		}

		// Backend patterns are authored lowercase without a `(?i)` inline
		// flag — the convention is "match case-insensitively on the
		// client side". The MCP TypeScript sync enforces this with the
		// `'gi'` constructor flag; mirror that here by prepending `(?i)`
		// so Go detection coverage matches MCP byte-for-byte. Double-`(?i)`
		// (when a backend pattern is already prefixed) is harmless in RE2.
		pattern := entry.Pattern
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue // unparseable pattern, skip and continue
		}

		name := threatTypeToName(entry.ThreatType)
		if entry.Confidence > confidenceByName[name] {
			confidenceByName[name] = entry.Confidence
		}
		converted = append(converted, PIIPattern{
			Name:   name,
			Regex:  re,
			Prefix: prefix,
		})
	}

	if len(converted) == 0 {
		return fmt.Errorf("pii pattern sync: all %d backend patterns failed conversion; kept %d fallback", len(data.Patterns), fallbackCount)
	}

	// Higher confidence first so more specific patterns win the document-order dedup.
	sort.SliceStable(converted, func(i, j int) bool {
		return confidenceByName[converted[i].Name] > confidenceByName[converted[j].Name]
	})

	UpdatePIIPatterns(converted)
	return nil
}
