package scanner

import (
	"fmt"
	"strconv"
	"strings"
)

// Canonical prefixes for the block-feedback layer. Stable across SDK versions
// so cookbook prompt templates can teach a model to recognize them. Must match
// the TS/Python formatters and the SystemPrompt block verbatim.
const (
	blockPrefix    = "Shrike blocked your last tool call."
	warnPrefix     = "Shrike flagged your last tool call (advisory)."
	approvalPrefix = "Shrike is holding your last tool call for approval."
)

// FormatBlockFeedback renders a canonical prompt-shape string from a scan
// verdict, suitable for injection as a system message into the model's next
// turn so it reads Shrike's reason + recovery guidance and adjusts rather than
// looping on the same blocked action.
//
// The prefix is selected from the verdict's Action (block / warn /
// require_approval); a nil or action-less verdict defaults to the block prefix.
// Mirrors the TS formatBlockFeedback and Python format_block_feedback.
func FormatBlockFeedback(r *ScanResult) string {
	lines := []string{blockPrefix}
	if r == nil {
		return lines[0]
	}

	switch strings.ToLower(r.Action) {
	case "warn":
		lines[0] = warnPrefix
	case "require_approval":
		lines[0] = approvalPrefix
	default:
		lines[0] = blockPrefix
	}

	reason := r.Reason
	if reason == "" {
		reason = r.Guidance
	}
	if reason != "" {
		lines = append(lines, "Reason: "+reason)
	}

	if r.ThreatType != "" {
		lines = append(lines, "Threat type: "+r.ThreatType)
	}

	if risk, ok := floatField(r.SessionState, "session_risk_score"); ok {
		if turn, ok := floatField(r.SessionState, "session_turn_number"); ok {
			lines = append(lines, fmt.Sprintf("Session risk: %s (turn %d)", formatNumber(risk), int(turn)))
		} else {
			lines = append(lines, "Session risk: "+formatNumber(risk))
		}
	}

	// Prefer recovery.patterns_triggered (scoped to THIS event) over
	// session_state.session_patterns (whole-session accumulator).
	patterns := stringSliceField(r.Recovery, "patterns_triggered")
	if len(patterns) == 0 {
		patterns = stringSliceField(r.SessionState, "session_patterns")
	}
	if len(patterns) > 0 {
		lines = append(lines, "Patterns triggered: "+strings.Join(patterns, ", "))
	}

	if instr := stringField(r.Recovery, "instruction"); instr != "" {
		lines = append(lines, "Recovery: "+instr)
	}

	if tools := stringSliceField(r.Recovery, "available_tools"); len(tools) > 0 {
		lines = append(lines, "Available tools: "+strings.Join(tools, ", "))
	}

	return strings.Join(lines, "\n")
}

// formatNumber renders a float the way TS template interpolation does — no
// trailing zeros ("0.85", not "0.850000").
func formatNumber(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func floatField(m map[string]interface{}, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key].(float64)
	return v, ok
}

func stringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func stringSliceField(m map[string]interface{}, key string) []string {
	if m == nil {
		return nil
	}
	arr, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
