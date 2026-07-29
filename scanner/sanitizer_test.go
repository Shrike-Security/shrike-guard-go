package scanner

import "testing"

func TestNormalizeThreatType(t *testing.T) {
	cases := map[string]string{
		"prompt_injection":       "prompt_injection",
		"instruction_override":   "prompt_injection",
		"INJECTION":              "prompt_injection", // case-insensitive
		"jailbreak-attempt":      "jailbreak",        // hyphen normalized
		"sqli":                   "sql_injection",
		"toxicity":               "toxic_content",
		"multi_turn_crescendo":   "multi_turn_attack", // prefix collapse
		"multi_turn_blocked_try": "multi_turn_attack",
		"":                       "unknown",
		"some_future_threat":     "unknown",
	}
	for in, want := range cases {
		if got := NormalizeThreatType(in); got != want {
			t.Errorf("NormalizeThreatType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeriveSeverity(t *testing.T) {
	// Valid raw severity passes through (lowercased).
	if got := DeriveSeverity("prompt_injection", "CRITICAL"); got != "critical" {
		t.Errorf("valid raw severity should pass through, got %q", got)
	}
	// Invalid raw severity falls back to the threat-type default.
	if got := DeriveSeverity("sql_injection", "bogus"); got != "critical" {
		t.Errorf("sql_injection default should be critical, got %q", got)
	}
	// Unknown threat type with no raw severity → medium.
	if got := DeriveSeverity("unknown", ""); got != "medium" {
		t.Errorf("unknown default should be medium, got %q", got)
	}
}

func TestBucketConfidence(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	cases := []struct {
		in   *float64
		want string
	}{
		{nil, "medium"}, // absent
		{f(0.95), "high"},
		{f(0.90), "high"}, // boundary
		{f(0.80), "medium"},
		{f(0.70), "medium"}, // boundary
		{f(0.50), "low"},
		{f(0.0), "low"},
	}
	for _, c := range cases {
		if got := BucketConfidence(c.in); got != c.want {
			t.Errorf("BucketConfidence(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeViolation(t *testing.T) {
	raw := map[string]interface{}{
		"threat_type":     "instruction_override",
		"severity":        "high",
		"owasp_category":  "LLM01",
		"user_message":    "blocked",
		"policy_id":       "pol_123",    // internal — strip
		"matched_pattern": "ignore all", // internal — strip
		"ai_reasoning":    "model said", // internal — strip
	}
	out := SanitizeViolation(raw)
	if out == nil {
		t.Fatal("expected sanitized violation, got nil")
	}
	for _, internal := range []string{"policy_id", "matched_pattern", "ai_reasoning"} {
		if _, ok := out[internal]; ok {
			t.Errorf("internal field %q must be stripped", internal)
		}
	}
	for _, keep := range []string{"threat_type", "severity", "owasp_category", "user_message"} {
		if _, ok := out[keep]; !ok {
			t.Errorf("customer-visible field %q must be preserved", keep)
		}
	}
	if SanitizeViolation("not a map") != nil {
		t.Error("non-object violation should sanitize to nil")
	}
}

func TestSanitizeScanResponse_SafeBranch(t *testing.T) {
	raw := map[string]interface{}{
		"safe":          true,
		"action":        "warn",
		"refuse_tier":   "warn",
		"reason":        "advisory copy",
		"recovery":      map[string]interface{}{"instruction": "proceed with caution"},
		"session_state": map[string]interface{}{"session_risk_score": 0.3},
		"content_type":  "sql",
	}
	res := SanitizeScanResponse(raw)
	if !res.Safe {
		t.Error("expected safe")
	}
	if res.Action != "warn" || res.RefuseTier != "warn" {
		t.Errorf("governance action/refuse_tier not preserved: %+v", res)
	}
	if res.Recovery == nil || res.SessionState == nil {
		t.Error("recovery + session_state must be preserved on the safe branch (contract symmetry)")
	}
	if res.ContentType != "sql" {
		t.Errorf("content_type not preserved, got %q", res.ContentType)
	}
	if res.Reason != "advisory copy" {
		t.Errorf("reason not preserved, got %q", res.Reason)
	}
}

func TestSanitizeScanResponse_UnsafeStripsAndNormalizes(t *testing.T) {
	raw := map[string]interface{}{
		"safe":       false,
		"action":     "block",
		"confidence": 0.95,
		// top-level internal attribution — must never surface
		"policy_id":    "pol_should_not_appear",
		"ai_reasoning": "model chain of thought",
		"violations": []interface{}{
			map[string]interface{}{
				"threat_type":     "instruction_override",
				"severity":        "high",
				"matched_pattern": "ignore previous",
			},
		},
	}
	res := SanitizeScanResponse(raw)
	if res.Safe {
		t.Error("expected unsafe")
	}
	if res.ThreatType != "prompt_injection" {
		t.Errorf("threat_type should normalize from violation to prompt_injection, got %q", res.ThreatType)
	}
	if res.Confidence != "high" {
		t.Errorf("confidence should bucket to high, got %q", res.Confidence)
	}
	if res.Severity != "high" {
		t.Errorf("severity should derive to high, got %q", res.Severity)
	}
	if res.Guidance == "" {
		t.Error("guidance should be populated on block verdicts")
	}
	if len(res.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(res.Violations))
	}
	if _, leaked := res.Violations[0]["matched_pattern"]; leaked {
		t.Error("matched_pattern must be stripped from the violation")
	}
}
