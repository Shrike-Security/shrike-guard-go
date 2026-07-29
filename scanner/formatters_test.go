package scanner

import (
	"strings"
	"testing"
)

func TestFormatBlockFeedback_Block(t *testing.T) {
	r := &ScanResult{
		Action:     "block",
		ThreatType: "data_exfiltration",
		Reason:     "Command routes IMDS credentials to external endpoint",
		SessionState: map[string]interface{}{
			"session_risk_score":  0.85,
			"session_turn_number": float64(4),
			"session_patterns":    []interface{}{"multi_turn_reconnaissance"},
		},
	}
	out := FormatBlockFeedback(r)
	for _, want := range []string{
		"Shrike blocked your last tool call.",
		"Reason: Command routes IMDS credentials to external endpoint",
		"Threat type: data_exfiltration",
		"Session risk: 0.85 (turn 4)",
		"Patterns triggered: multi_turn_reconnaissance",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestFormatBlockFeedback_Prefixes(t *testing.T) {
	if !strings.HasPrefix(FormatBlockFeedback(&ScanResult{Action: "warn"}), warnPrefix) {
		t.Error("warn prefix wrong")
	}
	if !strings.HasPrefix(FormatBlockFeedback(&ScanResult{Action: "require_approval"}), approvalPrefix) {
		t.Error("approval prefix wrong")
	}
	if FormatBlockFeedback(nil) != blockPrefix {
		t.Error("nil verdict should default to the block prefix")
	}
}

func TestFormatBlockFeedback_ReasonFallsBackToGuidance(t *testing.T) {
	out := FormatBlockFeedback(&ScanResult{Action: "block", Guidance: "advisory guidance text"})
	if !strings.Contains(out, "Reason: advisory guidance text") {
		t.Errorf("reason should fall back to guidance, got:\n%s", out)
	}
}

func TestFormatBlockFeedback_RecoveryPatternsPreferred(t *testing.T) {
	r := &ScanResult{
		Action: "require_approval",
		Recovery: map[string]interface{}{
			"instruction":        "Ask a human to approve",
			"available_tools":    []interface{}{"session_status"},
			"patterns_triggered": []interface{}{"gradual_escalation"},
		},
		SessionState: map[string]interface{}{
			"session_patterns": []interface{}{"whole_session_pattern"},
		},
	}
	out := FormatBlockFeedback(r)
	if !strings.Contains(out, "Patterns triggered: gradual_escalation") {
		t.Errorf("recovery.patterns_triggered should win, got:\n%s", out)
	}
	if strings.Contains(out, "whole_session_pattern") {
		t.Error("session_patterns must be overridden by recovery.patterns_triggered")
	}
	if !strings.Contains(out, "Recovery: Ask a human to approve") {
		t.Error("missing recovery instruction")
	}
	if !strings.Contains(out, "Available tools: session_status") {
		t.Error("missing available tools")
	}
}
