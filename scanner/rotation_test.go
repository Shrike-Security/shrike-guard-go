package scanner

import "testing"

func fptr(v float64) *float64 { return &v }

func TestEvaluateRotation_NoTrigger(t *testing.T) {
	if EvaluateRotation(RotationTriggerInput{
		SessionRiskScore:   fptr(0.5),
		EffectiveSessionID: "s1", ModuleSessionID: "s1",
	}) != nil {
		t.Error("below threshold with no lock should not trigger")
	}
	if EvaluateRotation(RotationTriggerInput{EffectiveSessionID: "s1", ModuleSessionID: "s1"}) != nil {
		t.Error("no risk and no lock should not trigger")
	}
}

func TestEvaluateRotation_ModuleOwned(t *testing.T) {
	rot := EvaluateRotation(RotationTriggerInput{
		SessionRiskScore:   fptr(0.9),
		EffectiveSessionID: "mod", ModuleSessionID: "mod",
	})
	if rot == nil {
		t.Fatal("expected a rotation")
	}
	if !rot.Rotated || rot.Owner != "sdk_client" {
		t.Errorf("expected module-owned rotation, got %+v", rot)
	}
	if rot.Reason != "risk_threshold_exceeded" {
		t.Errorf("reason = %s", rot.Reason)
	}
	if rot.PreviousSessionID != "mod" || rot.NewSessionID == "" || rot.NewSessionID == "mod" {
		t.Errorf("bad session ids: %+v", rot)
	}
	if rot.ConfiguredThreshold != RotationThreshold {
		t.Error("configured threshold not recorded")
	}
}

func TestEvaluateRotation_CallerOwned(t *testing.T) {
	rot := EvaluateRotation(RotationTriggerInput{
		SessionRiskScore:   fptr(0.95),
		EffectiveSessionID: "caller-sid", ModuleSessionID: "mod",
	})
	if rot == nil {
		t.Fatal("expected a rotation recommendation")
	}
	if rot.Rotated || !rot.RotationRecommended || rot.Owner != "caller" {
		t.Errorf("expected caller-owned recommendation, got %+v", rot)
	}
	if rot.CurrentSessionID != "caller-sid" || rot.SuggestedNewSessionID == "" {
		t.Errorf("bad caller ids: %+v", rot)
	}
}

// A locked session is never rotated and never recommended for rotation. The
// lock is the control; a fresh session id sidesteps it rather than clearing
// it. This test asserts the DECISION, not just the reason label — the earlier
// version checked only Reason and so passed whatever the decision was.
func TestEvaluateRotation_SessionLockedDoesNotRotate(t *testing.T) {
	rot := EvaluateRotation(RotationTriggerInput{
		ThreatType:         "session_locked",
		EffectiveSessionID: "mod", ModuleSessionID: "mod",
	})
	if rot == nil {
		t.Fatal("session_locked should emit a notice, got nil")
	}
	if rot.Reason != "session_locked" {
		t.Errorf("Reason = %q, want session_locked", rot.Reason)
	}
	if rot.Rotated {
		t.Error("Rotated = true; a locked session must never rotate")
	}
	if rot.RotationRecommended {
		t.Error("RotationRecommended = true; rotating is not the way past a lock")
	}
	if rot.Owner != "sdk_client" {
		t.Errorf("Owner = %q, want sdk_client", rot.Owner)
	}
	if rot.CurrentSessionID != "mod" {
		t.Errorf("CurrentSessionID = %q, want mod", rot.CurrentSessionID)
	}
	if rot.NewSessionID != "" || rot.SuggestedNewSessionID != "" {
		t.Errorf("a lock notice must offer no new id, got new=%q suggested=%q",
			rot.NewSessionID, rot.SuggestedNewSessionID)
	}
}

// The ordering is the whole fix: a locked session is ALREADY above the score
// threshold, so checking the score first would rotate it.
func TestEvaluateRotation_SessionLockedBeatsThreshold(t *testing.T) {
	score := 0.95
	rot := EvaluateRotation(RotationTriggerInput{
		ThreatType:         "session_locked",
		SessionRiskScore:   &score,
		EffectiveSessionID: "mod", ModuleSessionID: "mod",
	})
	if rot == nil {
		t.Fatal("session_locked should emit a notice, got nil")
	}
	if rot.Rotated || rot.RotationRecommended {
		t.Errorf("a locked session must not rotate on the score trigger either, got %+v", rot)
	}
	if rot.TriggeringRiskScore == nil || *rot.TriggeringRiskScore != score {
		t.Error("the notice should still carry the score that was seen")
	}
}

// A caller who owns the session must not be told that minting a new id is the
// way past a lock either.
func TestEvaluateRotation_SessionLockedCallerOwnedSuggestsNothing(t *testing.T) {
	rot := EvaluateRotation(RotationTriggerInput{
		ThreatType:         "session_locked",
		EffectiveSessionID: "caller-supplied", ModuleSessionID: "mod",
	})
	if rot == nil {
		t.Fatal("session_locked should emit a notice, got nil")
	}
	if rot.Owner != "caller" {
		t.Errorf("Owner = %q, want caller", rot.Owner)
	}
	if rot.RotationRecommended {
		t.Error("RotationRecommended = true on a lock; the system prompt acts on this field")
	}
	if rot.SuggestedNewSessionID != "" {
		t.Errorf("SuggestedNewSessionID = %q; a lock notice offers no id", rot.SuggestedNewSessionID)
	}
	if rot.CurrentSessionID != "caller-supplied" {
		t.Errorf("CurrentSessionID = %q, want the caller's own id echoed back", rot.CurrentSessionID)
	}
}

// The Go struct collapses the three shapes the TS/Python SDKs express as
// distinct types, so a consumer reading NewSessionID on a lock gets "" with no
// error at all. IsLocked and SessionID exist so that cannot happen quietly.
func TestSessionRotation_IsLockedAndSessionID(t *testing.T) {
	score := 0.9
	cases := []struct {
		name       string
		in         RotationTriggerInput
		wantLocked bool
		wantID     bool // an id is on offer
	}{
		{
			name:       "locked, module-owned",
			in:         RotationTriggerInput{ThreatType: "session_locked", EffectiveSessionID: "mod", ModuleSessionID: "mod"},
			wantLocked: true,
			wantID:     false,
		},
		{
			name:       "locked, caller-owned",
			in:         RotationTriggerInput{ThreatType: "session_locked", EffectiveSessionID: "caller", ModuleSessionID: "mod"},
			wantLocked: true,
			wantID:     false,
		},
		{
			name:       "score trigger, module-owned",
			in:         RotationTriggerInput{SessionRiskScore: &score, EffectiveSessionID: "mod", ModuleSessionID: "mod"},
			wantLocked: false,
			wantID:     true,
		},
		{
			name:       "score trigger, caller-owned",
			in:         RotationTriggerInput{SessionRiskScore: &score, EffectiveSessionID: "caller", ModuleSessionID: "mod"},
			wantLocked: false,
			wantID:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rot := EvaluateRotation(tc.in)
			if rot == nil {
				t.Fatal("expected a record, got nil")
			}
			if got := rot.IsLocked(); got != tc.wantLocked {
				t.Errorf("IsLocked() = %v, want %v", got, tc.wantLocked)
			}
			id, ok := rot.SessionID()
			if ok != tc.wantID {
				t.Errorf("SessionID() ok = %v, want %v", ok, tc.wantID)
			}
			if !tc.wantID && id != "" {
				t.Errorf("SessionID() = %q; a lock must offer no id", id)
			}
			if tc.wantID && id == "" {
				t.Error("SessionID() returned ok with an empty id")
			}
		})
	}
}

// A nil record is the no-trigger case. Both helpers must tolerate it, because
// the idiomatic call site is `rot := EvaluateRotation(in)` with one nil check.
func TestSessionRotation_NilIsSafe(t *testing.T) {
	var rot *SessionRotation
	if rot.IsLocked() {
		t.Error("nil record reported as locked")
	}
	if id, ok := rot.SessionID(); ok || id != "" {
		t.Errorf("nil record offered an id: %q, %v", id, ok)
	}
}

func TestModuleSessionID(t *testing.T) {
	if ModuleSessionID() == "" {
		t.Error("module session id should be non-empty")
	}
}
