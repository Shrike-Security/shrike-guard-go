// Response sanitization for IP protection.
//
// Mirrors the TypeScript SDK's sanitizer.ts and the Python SDK's sanitizer.py
// (which in turn mirror the MCP server's responseFormatter) so Go SDK responses
// never expose internal detection methodology, layer details, or patterns.
//
// The sanitizer strips internal detection attribution (layer timings,
// per-detector confidences, pattern names, policy IDs) — NOT outcome state.
// It preserves the four-state governance surface (action, refuse_tier, recovery,
// session_state) so callers can distinguish allow / warn / require_approval /
// block. Contract symmetry: safe and refuse verdicts carry the same governance
// fields.

package scanner

import "strings"

// threatTypeMap maps internal threat-type variants to the standard enum exposed
// to SDK users (matches MCP ThreatType enum + TS THREAT_TYPE_MAP).
var threatTypeMap = map[string]string{
	// Prompt injection variants
	"prompt_injection":     "prompt_injection",
	"injection":            "prompt_injection",
	"inject":               "prompt_injection",
	"instruction_override": "prompt_injection",
	"role_hijacking":       "prompt_injection",
	"context_manipulation": "prompt_injection",
	"token_manipulation":   "prompt_injection",
	"indirect_injection":   "prompt_injection",
	"context_poisoning":    "prompt_injection",
	"function_injection":   "prompt_injection",
	"memory_injection":     "prompt_injection",
	"topic_mismatch":       "prompt_injection",
	// Jailbreak
	"jailbreak":          "jailbreak",
	"jailbreak_attempt":  "jailbreak",
	"safety_bypass":      "jailbreak",
	"roleplay":           "jailbreak",
	"hypothetical":       "jailbreak",
	"completion_baiting": "jailbreak",
	"override":           "jailbreak",
	"manipulate":         "jailbreak",
	// L8 tonality drift — backend normalizes profanity + hostile as toxic_content;
	// casual stays as jailbreak (matches platform/common/models/response.go).
	"tonality_drift_profanity": "toxic_content",
	"tonality_drift_hostile":   "toxic_content",
	"tonality_drift_casual":    "jailbreak",
	// System prompt leak
	"system_prompt_leak":       "system_prompt_leak",
	"system_prompt_extraction": "system_prompt_leak",
	// Data exfiltration
	"data_exfiltration":      "data_exfiltration",
	"exfiltration":           "data_exfiltration",
	"exfiltrate":             "data_exfiltration",
	"extract":                "data_exfiltration",
	"data_leak":              "data_exfiltration",
	"information_disclosure": "data_exfiltration",
	"credential_extraction":  "data_exfiltration",
	// SQL injection
	"sql_injection":   "sql_injection",
	"sqli":            "sql_injection",
	"tautology":       "sql_injection",
	"tautology_or":    "sql_injection",
	"tautology_and":   "sql_injection",
	"union_injection": "sql_injection",
	"stacked_query":   "sql_injection",
	// Path traversal
	"path_traversal":      "path_traversal",
	"directory_traversal": "path_traversal",
	"path_violation":      "path_traversal",
	"file_access":         "path_traversal",
	"sensitive_path":      "path_traversal",
	"sensitive_extension": "path_traversal",
	"blocked_extension":   "path_traversal",
	// Secrets
	"secrets_exposure":  "secrets_exposure",
	"secrets":           "secrets_exposure",
	"api_key":           "secrets_exposure",
	"credential":        "secrets_exposure",
	"sensitive_file":    "secrets_exposure",
	"content_violation": "secrets_exposure",
	"sensitive_content": "secrets_exposure",
	"secret_key":        "secrets_exposure",
	"aws_key":           "secrets_exposure",
	"private_key":       "secrets_exposure",
	// PII
	"pii_exposure":           "pii_exposure",
	"pii":                    "pii_exposure",
	"pii_leak":               "pii_exposure",
	"personal_data":          "pii_exposure",
	"pii_in_search":          "pii_exposure",
	"pii_extraction":         "pii_exposure",
	"ssn":                    "pii_exposure",
	"credit_card":            "pii_exposure",
	"email_exposure":         "pii_exposure",
	"phone_number":           "pii_exposure",
	"unexpected_pii_leakage": "pii_exposure",
	// Domain blocking
	"blocked_domain":    "blocked_domain",
	"suspicious_tld":    "blocked_domain",
	"suspicious_domain": "blocked_domain",
	"malicious_url":     "blocked_domain",
	// Toxic content (canonical name as of the L7 rewrite). `toxicity` kept as a
	// legacy alias so older backend builds + customer code don't break.
	"toxic_content":   "toxic_content",
	"toxicity":        "toxic_content",
	"harmful_content": "toxic_content",
	// Malicious code
	"malicious_content": "malicious_code",
	"malicious_code":    "malicious_code",
	"reverse_shell":     "malicious_code",
	"web_shell":         "malicious_code",
	"fork_bomb":         "malicious_code",
	"crypto_miner":      "malicious_code",
	"persistence":       "malicious_code",
	"shell_injection":   "malicious_code",
	// Harmful intent
	"harmful_intent":    "harmful_intent",
	"dangerous_request": "harmful_intent",
	// Social engineering
	"social_engineering": "social_engineering",
	"emotional":          "social_engineering",
	"authority_claim":    "social_engineering",
	// Privilege escalation
	"privilege_escalation": "privilege_escalation",
	// Destructive operation
	"destructive_operation": "destructive_operation",
	// L9 multi-turn correlation pseudo-category (see prefix check below).
	"multi_turn_attack": "multi_turn_attack",
	// Errors
	"scan_error":          "scan_error",
	"size_limit_exceeded": "size_limit_exceeded",
	"size_limit":          "size_limit_exceeded",
	"timeout":             "scan_error",
}

// threatGuidance maps normalized threat types to user-friendly guidance
// (matches MCP THREAT_GUIDANCE + TS THREAT_GUIDANCE).
var threatGuidance = map[string]string{
	"prompt_injection":      "This prompt contains patterns consistent with instruction override attempts.",
	"jailbreak":             "This prompt attempts to bypass safety guidelines. The request has been blocked.",
	"system_prompt_leak":    "The response contains system prompt disclosure. The response has been blocked.",
	"data_exfiltration":     "This prompt may attempt to extract sensitive information.",
	"sql_injection":         "This query contains potentially dangerous SQL patterns.",
	"path_traversal":        "This file path attempts to access directories outside the allowed scope.",
	"secrets_exposure":      "This content contains patterns matching API keys, tokens, or credentials.",
	"pii_exposure":          "This content contains personally identifiable information.",
	"blocked_domain":        "This web search targets a restricted domain.",
	"toxic_content":         "This content contains potentially harmful or inappropriate language.",
	"toxicity":              "This content contains potentially harmful or inappropriate language.",
	"multi_turn_attack":     "A pattern was detected across multiple turns of this session that suggests a coordinated attempt to bypass safety controls.",
	"malicious_code":        "This content contains patterns associated with malicious code.",
	"harmful_intent":        "This request contains content associated with harmful intent.",
	"social_engineering":    "This prompt contains social engineering patterns.",
	"privilege_escalation":  "This query attempts to escalate privileges or gain unauthorized access.",
	"destructive_operation": "This query contains destructive operations. Review carefully.",
	"scan_error":            "The security scan could not be completed. Blocked as precaution.",
	"size_limit_exceeded":   "The content exceeds the maximum allowed size.",
	"unknown":               "A security concern was detected. Please review the content.",
}

// threatSeverity maps normalized threat types to default severity
// (critical > high > medium > low). Matches TS THREAT_SEVERITY.
var threatSeverity = map[string]string{
	"prompt_injection":      "high",
	"jailbreak":             "high",
	"system_prompt_leak":    "high",
	"data_exfiltration":     "high",
	"sql_injection":         "critical",
	"path_traversal":        "high",
	"secrets_exposure":      "critical",
	"pii_exposure":          "high",
	"blocked_domain":        "medium",
	"toxic_content":         "medium",
	"toxicity":              "medium",
	"multi_turn_attack":     "high",
	"malicious_code":        "critical",
	"harmful_intent":        "high",
	"social_engineering":    "medium",
	"privilege_escalation":  "critical",
	"destructive_operation": "critical",
	"scan_error":            "medium",
	"size_limit_exceeded":   "low",
	"unknown":               "medium",
}

// internalFields expose internal detection methodology — must be stripped.
var internalFields = map[string]struct{}{
	"detected_by":         {},
	"policy_id":           {},
	"policy_name":         {},
	"matched_pattern":     {},
	"matched_text":        {},
	"pattern":             {},
	"scan_stage":          {},
	"ai_reasoning":        {},
	"llm_analysis":        {},
	"performance_metrics": {},
	"performance":         {},
}

// preservedGovernanceFields are the governance-outcome fields the sanitizer
// preserves verbatim on BOTH safe and unsafe branches — the contract-symmetry
// surface (safe / refuse_tier / recovery / session_state on every response).
// This slice documents the contract; assignment is explicit in
// SanitizeScanResponse to stay type-safe.
var preservedGovernanceFields = []string{
	"action",
	"refuse_tier",
	"recovery",
	"session_state",
	"content_type",
	"content_origin",
	"approval_info",
	"client_session_rotation",
}

// AttributableToOperator reports whether the operator is answerable for the
// scanned content — i.e. a person typed it. Everything else was produced by
// the agent or arrived from outside, and a refusal on it is not something the
// operator did.
//
// Use it to decide who a refusal message is addressed to: telling a user
// "your request was blocked" when the agent poisoned its own context is both
// wrong and unhelpful.
func AttributableToOperator(origin string) bool {
	return origin == "human_prompt"
}

// NormalizeThreatType normalizes an internal threat-type string to the standard
// enum. Unknown types collapse to "unknown"; any multi_turn_* pattern collapses
// to "multi_turn_attack" (mirrors the prefix logic in
// platform/common/models/response.go).
func NormalizeThreatType(rawType string) string {
	if rawType == "" {
		return "unknown"
	}
	normalized := strings.ReplaceAll(strings.ToLower(rawType), "-", "_")
	if mapped, ok := threatTypeMap[normalized]; ok {
		return mapped
	}
	if strings.HasPrefix(normalized, "multi_turn_") {
		return "multi_turn_attack"
	}
	return "unknown"
}

// DeriveSeverity returns a validated severity. If the backend supplies a valid
// severity it is passed through (lowercased); otherwise severity is derived from
// the normalized threat type.
func DeriveSeverity(threatType, rawSeverity string) string {
	switch strings.ToLower(rawSeverity) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(rawSeverity)
	}
	if s, ok := threatSeverity[threatType]; ok {
		return s
	}
	return "medium"
}

// BucketConfidence converts a raw confidence score to a bucketed level,
// protecting IP by not exposing exact detection thresholds. A nil score
// (field absent on the wire) buckets to "medium".
func BucketConfidence(score *float64) string {
	if score == nil {
		return "medium"
	}
	switch {
	case *score >= 0.9:
		return "high"
	case *score >= 0.7:
		return "medium"
	default:
		return "low"
	}
}

// SanitizeViolation strips internal attribution fields from one entry of the
// backend violations[] array, keeping customer-visible outcome fields
// (severity, action, threat_type, owasp_category, user_message,
// suggested_action). Returns nil for a non-object entry.
func SanitizeViolation(raw interface{}) map[string]interface{} {
	source, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]interface{}, len(source))
	for k, v := range source {
		if _, internal := internalFields[k]; !internal {
			out[k] = v
		}
	}
	return out
}

// SanitizeScanResponse sanitizes a raw backend scan response (decoded JSON) for
// IP protection and returns a customer-safe ScanResult. It preserves the
// four-state governance surface so callers can distinguish
// allow/warn/require_approval/block, and it fails safe on missing fields.
//
// Taking a decoded map (rather than a fixed struct) means additive backend
// fields are ignored gracefully — the forward-compatibility contract.
func SanitizeScanResponse(raw map[string]interface{}) *ScanResult {
	safe := true
	if v, ok := raw["safe"].(bool); ok {
		safe = v
	}
	result := &ScanResult{Safe: safe}

	// Governance-outcome fields pass through on BOTH branches. This is the
	// symmetric contract — a `warn` verdict (safe=true, action="warn") must
	// carry recovery/refuse_tier the same as a `block` (safe=false).
	result.Action = getString(raw, "action")
	result.RefuseTier = getString(raw, "refuse_tier")
	result.Recovery = getMap(raw, "recovery")
	result.SessionState = getMap(raw, "session_state")
	result.ContentType = getString(raw, "content_type")
	result.ContentOrigin = getString(raw, "content_origin")
	result.ApprovalInfo = getMap(raw, "approval_info")
	if v, ok := raw["client_session_rotation"]; ok && v != nil {
		result.ClientSessionRotation = v
	}

	// violations[] — pass each entry through per-item sanitization; drop the
	// array entirely if empty (noise).
	if rawViolations, ok := raw["violations"].([]interface{}); ok && len(rawViolations) > 0 {
		cleaned := make([]map[string]interface{}, 0, len(rawViolations))
		for _, v := range rawViolations {
			if sv := SanitizeViolation(v); sv != nil {
				cleaned = append(cleaned, sv)
			}
		}
		if len(cleaned) > 0 {
			result.Violations = cleaned
		}
	}

	if safe {
		// Safe branch: reason may carry advisory copy for warn tier.
		result.Reason = getString(raw, "reason")
		return result
	}

	// Unsafe branch: derive threat classification. Backend /api/scan/enforce
	// returns top-level threat_type=null and puts detail inside violations[];
	// prefer the first violation's threat_type when the top-level is missing.
	rawThreatType := getString(raw, "threat_type")
	if rawThreatType == "" {
		if rawViolations, ok := raw["violations"].([]interface{}); ok && len(rawViolations) > 0 {
			if first, ok := rawViolations[0].(map[string]interface{}); ok {
				if ft, ok := first["threat_type"].(string); ok {
					rawThreatType = ft
				}
			}
		}
	}

	threatType := NormalizeThreatType(rawThreatType)
	confidence := BucketConfidence(getFloatPtr(raw, "confidence"))
	severity := DeriveSeverity(threatType, getString(raw, "severity"))
	guidance := threatGuidance[threatType]
	if guidance == "" {
		guidance = threatGuidance["unknown"]
	}

	result.ThreatType = threatType
	result.Severity = severity
	result.Confidence = confidence
	if reason := getString(raw, "reason"); reason != "" {
		result.Reason = reason
	} else {
		result.Reason = guidance
	}
	result.Guidance = guidance
	return result
}

// IsBlocked decides whether a scan verdict should be enforced as a block.
//
// Prefers the server-authoritative `action` field emitted by /api/scan/enforce;
// falls back to the `safe` boolean for verdicts that predate the enforce
// endpoint (older backends, fail-open synthetic verdicts, cached responses).
//
//	action = "block"            → true
//	action = "require_approval" → true (held at the tool-call boundary)
//	action = "allow"            → false
//	action = "warn"             → false (advisory; surface, don't refuse)
//	action absent / unknown     → fall back to !safe (fails closed on a new
//	                              blocking tier, which also sets safe:false)
//
// Contract-symmetry pin: mirrors TS isBlocked and Python _is_blocked. If any of
// the three diverges, that is a bug in one of them.
func IsBlocked(r *ScanResult) bool {
	switch r.Action {
	case "allow", "warn":
		return false
	case "block", "require_approval":
		return true
	}
	// Unknown/future tier: do NOT fail open on an unrecognized name — fall
	// through to `safe`. Forward-compat contract, see contract_test.go.
	return !r.Safe
}

// --- small typed accessors over a decoded JSON map ---

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func getFloatPtr(m map[string]interface{}, key string) *float64 {
	if v, ok := m[key].(float64); ok {
		return &v
	}
	return nil
}
