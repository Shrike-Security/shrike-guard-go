package scanner

import "testing"

// TestContractSymmetry pins the four-state governance surface: a warn verdict
// (safe=true) must carry the SAME governance fields as a block verdict
// (safe=false). Prose drifts; fields don't. Mirrors the TS
// contract-symmetry.test.ts and Python test_contract_symmetry.py.
func TestContractSymmetry(t *testing.T) {
	governance := map[string]interface{}{
		"refuse_tier":   "warn",
		"recovery":      map[string]interface{}{"instruction": "surface to user"},
		"session_state": map[string]interface{}{"session_turn_number": float64(3)},
	}

	// Warn branch (safe=true, action=warn).
	warn := map[string]interface{}{"safe": true, "action": "warn"}
	for k, v := range governance {
		warn[k] = v
	}
	// Block branch (safe=false, action=block).
	block := map[string]interface{}{"safe": false, "action": "block"}
	for k, v := range governance {
		block[k] = v
	}

	warnRes := SanitizeScanResponse(warn)
	blockRes := SanitizeScanResponse(block)

	// Both branches must expose refuse_tier / recovery / session_state.
	for _, r := range []*ScanResult{warnRes, blockRes} {
		if r.RefuseTier == "" {
			t.Error("refuse_tier missing — contract-symmetry violation")
		}
		if r.Recovery == nil {
			t.Error("recovery missing — contract-symmetry violation")
		}
		if r.SessionState == nil {
			t.Error("session_state missing — contract-symmetry violation")
		}
	}
	// Behavioural asymmetry is correct: warn proceeds, block refuses.
	if IsBlocked(warnRes) {
		t.Error("warn must proceed")
	}
	if !IsBlocked(blockRes) {
		t.Error("block must refuse")
	}
}

// TestIsBlocked pins the single proceed-vs-refuse decision. Mirrors TS isBlocked
// and Python _is_blocked exactly — if any diverges it is a bug in one of them.
func TestIsBlocked(t *testing.T) {
	cases := []struct {
		name   string
		result ScanResult
		want   bool
	}{
		{"allow proceeds", ScanResult{Action: "allow", Safe: true}, false},
		{"warn proceeds", ScanResult{Action: "warn", Safe: true}, false},
		{"block refuses", ScanResult{Action: "block", Safe: false}, true},
		{"require_approval refuses", ScanResult{Action: "require_approval", Safe: false}, true},
		{"no action, safe → proceed", ScanResult{Safe: true}, false},
		{"no action, unsafe → refuse", ScanResult{Safe: false}, true},
	}
	for _, c := range cases {
		if got := IsBlocked(&c.result); got != c.want {
			t.Errorf("%s: IsBlocked = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestForwardCompat pins the distribution-stability contract: an unknown/future
// refuse tier the client has never seen must FAIL CLOSED (not fail open), and
// additive unknown fields on the wire must not crash the sanitizer. Mirrors TS
// contract-forward-compat.test.ts and Python test_contract_forward_compat.py.
func TestForwardCompat(t *testing.T) {
	t.Run("unknown blocking tier fails closed", func(t *testing.T) {
		// Backend adds a future "quarantine" tier that also sets safe:false.
		// The client doesn't know the name → must fall through to !safe → refuse.
		r := &ScanResult{Action: "quarantine", Safe: false}
		if !IsBlocked(r) {
			t.Error("unknown blocking tier must fail closed (refuse)")
		}
	})

	t.Run("unknown non-blocking tier with safe=true proceeds", func(t *testing.T) {
		r := &ScanResult{Action: "quarantine", Safe: true}
		if IsBlocked(r) {
			t.Error("unknown tier with safe=true should proceed")
		}
	})

	t.Run("additive unknown fields do not crash the sanitizer", func(t *testing.T) {
		raw := map[string]interface{}{
			"safe":          false,
			"action":        "block",
			"confidence":    0.88,
			"future_field":  "some new value",
			"nested_future": map[string]interface{}{"a": 1},
			"future_scores": []interface{}{0.1, 0.2},
			"violations": []interface{}{
				map[string]interface{}{"threat_type": "jailbreak", "future_v_field": true},
			},
		}
		// Must not panic and must still produce a coherent verdict.
		res := SanitizeScanResponse(raw)
		if res == nil || res.Safe {
			t.Fatal("expected a non-nil unsafe result")
		}
		if res.ThreatType != "jailbreak" {
			t.Errorf("expected jailbreak, got %q", res.ThreatType)
		}
		// Unknown top-level fields are dropped (only known fields are copied).
		if !IsBlocked(res) {
			t.Error("block must refuse")
		}
	})
}
