package shrike

import "fmt"

// ShrikeError is the base error type for all Shrike SDK errors.
type ShrikeError struct {
	Message string
	Details map[string]interface{}
}

func (e *ShrikeError) Error() string {
	return e.Message
}

// ScanError is returned when a scan operation fails and fail_mode is 'closed'
// (the default; fail-closed).
//
// This error is returned when:
// - The Shrike API times out
// - A network error occurs
// - The API returns an unexpected error
//
// When fail_mode is explicitly set to 'open', these errors are silently
// handled and the request is allowed to proceed (use this only when
// availability must outrank enforcement).
type ScanError struct {
	ShrikeError
}

// NewScanError creates a new ScanError.
func NewScanError(message string) *ScanError {
	return &ScanError{
		ShrikeError: ShrikeError{
			Message: message,
			Details: make(map[string]interface{}),
		},
	}
}

// BlockedError is returned when a prompt is blocked by Shrike security checks.
//
// This error indicates that the prompt was scanned and determined
// to be unsafe.
type BlockedError struct {
	ShrikeError

	// ThreatType is the type of threat detected (e.g., 'prompt_injection', 'pii')
	ThreatType string

	// Confidence is the bucketed confidence level ("high"/"medium"/"low").
	// Buckets protect IP by not exposing exact detection thresholds.
	Confidence string

	// Violations is the sanitized list of specific violations detected.
	Violations []map[string]interface{}
}

// NewBlockedError creates a new BlockedError.
func NewBlockedError(message, threatType, confidence string, violations []map[string]interface{}) *BlockedError {
	if violations == nil {
		violations = make([]map[string]interface{}, 0)
	}
	return &BlockedError{
		ShrikeError: ShrikeError{
			Message: message,
			Details: map[string]interface{}{
				"threat_type": threatType,
				"confidence":  confidence,
				"violations":  violations,
			},
		},
		ThreatType: threatType,
		Confidence: confidence,
		Violations: violations,
	}
}

func (e *BlockedError) Error() string {
	if e.ThreatType != "" {
		return fmt.Sprintf("%s (threat_type: %s, confidence: %s)", e.Message, e.ThreatType, e.Confidence)
	}
	return e.Message
}

// ConfigError is returned when there's a configuration error in the SDK.
type ConfigError struct {
	ShrikeError
}

// NewConfigError creates a new ConfigError.
func NewConfigError(message string) *ConfigError {
	return &ConfigError{
		ShrikeError: ShrikeError{
			Message: message,
			Details: make(map[string]interface{}),
		},
	}
}
