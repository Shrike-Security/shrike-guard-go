package shrike

import "time"

// FailMode defines behavior when scan operations fail
// (timeout, network error, backend 5xx).
type FailMode string

const (
	// FailModeOpen allows the request to proceed when the scanner cannot decide.
	// Use this when availability is strictly prioritized over enforcement
	// (e.g. non-production experiments, internal tools where outages must not
	// block users). Note: a fail-open SDK provides no guard during backend
	// outages, which is when adversarial pressure is highest.
	FailModeOpen FailMode = "open"

	// FailModeClosed blocks the request and returns an error when the scanner
	// cannot decide. This is the Zero Trust posture promised by the Shrike
	// platform — if the guard cannot evaluate the action, the action does not
	// proceed. This is the default (see DefaultFailMode).
	FailModeClosed FailMode = "closed"
)

// Default configuration values.
const (
	// DefaultScanTimeout is the default timeout for scan requests.
	DefaultScanTimeout = 10 * time.Second

	// DefaultEndpoint is the default Shrike API endpoint (uses load balancer for scalability).
	// Override with WithEndpoint() for VPC deployments.
	DefaultEndpoint = "https://api.shrikesecurity.com/agent"

	// Note: All scanning is done via backend API (tier-based: community=L1-L4, pro=L1-L8)
	// No local patterns needed - backend handles all detection logic

	// SDKName identifies this SDK in API requests.
	SDKName = "go"

	// SDKUserAgent is the user agent string for this SDK.
	SDKUserAgent = "shrike-guard-go"
)

// Note: DefaultLocalPatterns removed - all scanning done via backend API
// Backend has full regex patterns (~50+) and normalizers (L1-L4)

// DefaultFailMode is the default fail mode. Set to FailModeClosed to match the
// Shrike platform's Zero Trust contract: when the scanner cannot decide, the
// request is blocked. Override at the call site with WithFailMode(FailModeOpen)
// if you need availability over enforcement.
var DefaultFailMode = FailModeClosed

// Config holds configuration for Shrike clients.
type Config struct {
	// APIKey is the Shrike API key for authentication.
	APIKey string

	// Endpoint is the Shrike API endpoint URL.
	Endpoint string

	// FailMode defines behavior when scan operations fail.
	FailMode FailMode

	// ScanTimeout is the timeout for scan requests.
	ScanTimeout time.Duration
}

// DefaultConfig returns a configuration with default values.
func DefaultConfig(apiKey string) Config {
	return Config{
		APIKey:      apiKey,
		Endpoint:    DefaultEndpoint,
		FailMode:    DefaultFailMode,
		ScanTimeout: DefaultScanTimeout,
	}
}
