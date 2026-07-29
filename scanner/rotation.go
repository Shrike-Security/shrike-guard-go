package scanner

import "github.com/google/uuid"

// RotationThreshold is the accumulated session risk score at or above which
// EvaluateRotation emits a risk_threshold_exceeded recommendation. Mirrors the
// TS/Python ROTATION_THRESHOLD.
const RotationThreshold = 0.7

// ModuleSessionID returns the SDK's per-process session id — the id ride-along
// on every scan when the caller does not supply their own. Pass it as
// ModuleSessionID in RotationTriggerInput so EvaluateRotation can decide whether
// a rotation is module-owned or caller-owned.
func ModuleSessionID() string {
	return processSessionID
}

// RotationTriggerInput is the light verdict shape EvaluateRotation inspects. It
// carries no dependency on a concrete response type — pass a threat_type and/or
// a session risk score plus the two session ids used for ownership detection.
type RotationTriggerInput struct {
	// ThreatType is the (raw) threat type from the verdict. "session_locked"
	// triggers rotation directly.
	ThreatType string
	// SessionRiskScore is the L9 accumulated risk (nil if none was returned).
	SessionRiskScore *float64
	// EffectiveSessionID is the session id actually used for this scan.
	EffectiveSessionID string
	// ModuleSessionID is the SDK's per-process session id (see ModuleSessionID()).
	ModuleSessionID string
}

// SessionRotation describes what rotation happened (or should happen). It
// collapses the two TS shapes (ModuleOwnedRotation, CallerOwnedRotation-
// Recommendation) — discriminate on Rotated: true = module-owned, the caller
// should adopt NewSessionID for its module session id; false (with
// RotationRecommended true) = caller-owned, the caller may adopt
// SuggestedNewSessionID inside its own control flow.
//
// EvaluateRotation is pure — it never mutates any module state. Rotating the
// module session id is the caller's responsibility once they act on a
// module-owned result.
type SessionRotation struct {
	Rotated             bool
	RotationRecommended bool
	// Owner is "sdk_client" (module-owned) or "caller" (caller-owned).
	Owner string
	// Reason is "session_locked" or "risk_threshold_exceeded".
	Reason string
	// Module-owned fields.
	PreviousSessionID string
	NewSessionID      string
	// Caller-owned fields.
	CurrentSessionID      string
	SuggestedNewSessionID string
	// TriggeringRiskScore is the score that crossed (nil for a pure lock).
	TriggeringRiskScore *float64
	ConfiguredThreshold float64
}

// EvaluateRotation inspects a verdict and returns a SessionRotation record when
// rotation is warranted, or nil when no trigger fired.
//
// Triggers:
//   - ThreatType == "session_locked" — the backend told the SDK the session is done.
//   - SessionRiskScore >= RotationThreshold — L9 risk crossed the safe floor.
//
// Ownership: when EffectiveSessionID differs from ModuleSessionID the caller
// supplied their own session id (caller-owned recommendation); otherwise the
// SDK's module session id was in force (module-owned rotation).
func EvaluateRotation(input RotationTriggerInput) *SessionRotation {
	locked := input.ThreatType == "session_locked"
	overThreshold := input.SessionRiskScore != nil && *input.SessionRiskScore >= RotationThreshold
	if !locked && !overThreshold {
		return nil
	}

	reason := "risk_threshold_exceeded"
	if locked {
		reason = "session_locked"
	}

	if input.EffectiveSessionID != input.ModuleSessionID {
		return &SessionRotation{
			Rotated:               false,
			RotationRecommended:   true,
			Owner:                 "caller",
			Reason:                reason,
			CurrentSessionID:      input.EffectiveSessionID,
			SuggestedNewSessionID: uuid.New().String(),
			TriggeringRiskScore:   input.SessionRiskScore,
			ConfiguredThreshold:   RotationThreshold,
		}
	}

	return &SessionRotation{
		Rotated:             true,
		Owner:               "sdk_client",
		Reason:              reason,
		PreviousSessionID:   input.ModuleSessionID,
		NewSessionID:        uuid.New().String(),
		TriggeringRiskScore: input.SessionRiskScore,
		ConfiguredThreshold: RotationThreshold,
	}
}
