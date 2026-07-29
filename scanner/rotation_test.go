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

func TestEvaluateRotation_SessionLocked(t *testing.T) {
	rot := EvaluateRotation(RotationTriggerInput{
		ThreatType:         "session_locked",
		EffectiveSessionID: "mod", ModuleSessionID: "mod",
	})
	if rot == nil || rot.Reason != "session_locked" {
		t.Errorf("session_locked should trigger, got %+v", rot)
	}
}

func TestModuleSessionID(t *testing.T) {
	if ModuleSessionID() == "" {
		t.Error("module session id should be non-empty")
	}
}
