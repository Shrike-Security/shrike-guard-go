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

// SessionRotation describes what rotation happened, or should happen. Three
// cases; discriminate on Rotated, then on RotationRecommended:
//
//   - Rotated true: module-owned. Adopt NewSessionID.
//   - Rotated false, RotationRecommended true: caller-owned. The caller may
//     adopt SuggestedNewSessionID.
//   - Both false: the session is LOCKED. Neither id is set, and minting one
//     sidesteps the lock instead of clearing it.
//
// EvaluateRotation is pure. Rotating the module session id is the caller's
// responsibility once they act on a module-owned result.
type SessionRotation struct {
	Rotated             bool
	RotationRecommended bool
	// Owner is "sdk_client" (module-owned) or "caller" (caller-owned).
	Owner string
	// Reason is "session_locked" (only when both flags are false) or
	// "risk_threshold_exceeded". Branch on the decision, not on this; see
	// IsLocked.
	Reason string
	// Module-owned fields.
	PreviousSessionID string
	NewSessionID      string
	// Caller-owned fields, and the locked session's own id.
	CurrentSessionID      string
	SuggestedNewSessionID string
	// TriggeringRiskScore is the score that crossed (nil for a pure lock).
	TriggeringRiskScore *float64
	ConfiguredThreshold float64
}

// IsLocked reports whether this record is a locked-session notice rather than
// a rotation. Check it before reading NewSessionID or SuggestedNewSessionID: on
// a lock both are empty, so an unguarded read assigns "".
func (r *SessionRotation) IsLocked() bool {
	return r != nil && !r.Rotated && !r.RotationRecommended
}

// SessionID returns the id to adopt after acting on this record, and whether
// one is on offer. Returns ("", false) on a lock.
func (r *SessionRotation) SessionID() (string, bool) {
	switch {
	case r == nil || r.IsLocked():
		return "", false
	case r.Rotated:
		return r.NewSessionID, r.NewSessionID != ""
	default:
		return r.SuggestedNewSessionID, r.SuggestedNewSessionID != ""
	}
}

// EvaluateRotation inspects a verdict and returns a SessionRotation record when
// rotation is warranted, or nil when no trigger fired.
//
// Outcomes:
//   - ThreatType "session_locked": a notice with both flags false and no new
//     id. Checked FIRST, since a locked session is already above the score
//     threshold and would otherwise fall through and rotate. A lock lifts by a
//     self-release under a live declared scope, or by an operator.
//   - SessionRiskScore >= RotationThreshold and not locked: rotation warranted.
//
// Ownership: when EffectiveSessionID differs from ModuleSessionID the caller
// supplied their own session id (caller-owned recommendation); otherwise the
// SDK's module session id was in force (module-owned rotation).
func EvaluateRotation(input RotationTriggerInput) *SessionRotation {
	locked := input.ThreatType == "session_locked"
	overThreshold := input.SessionRiskScore != nil && *input.SessionRiskScore >= RotationThreshold
	callerOwned := input.EffectiveSessionID != input.ModuleSessionID

	if locked {
		owner := "sdk_client"
		if callerOwned {
			owner = "caller"
		}
		return &SessionRotation{
			Rotated:             false,
			RotationRecommended: false,
			Owner:               owner,
			Reason:              "session_locked",
			CurrentSessionID:    input.EffectiveSessionID,
			TriggeringRiskScore: input.SessionRiskScore,
			ConfiguredThreshold: RotationThreshold,
		}
	}

	if !overThreshold {
		return nil
	}

	reason := "risk_threshold_exceeded"

	if callerOwned {
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
