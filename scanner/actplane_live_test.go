package scanner

// Live integration tests: real backend, real HTTP, no mocks.
//
// The unit suites assert what the SDK sends, against an httptest server. Only
// the backend can confirm that it accepts the request and returns the fields
// the SDK documents: an unrecognized content_type, a renamed endpoint, a
// rejected auth header, or a response field that is present on one route and
// absent on another all look identical to a passing mock.
//
// Skipped unless both are set:
//
//	SHRIKE_LIVE_ENDPOINT   e.g. https://api.shrikesecurity.com/agent
//	SHRIKE_LIVE_API_KEY
//
// Run:  SHRIKE_LIVE_ENDPOINT=... SHRIKE_LIVE_API_KEY=... go test ./scanner -run Live -v
//
// These probes write real scan rows, including refused scans, to the account
// the key belongs to. Use a dedicated test account.
//
// Assertions are deliberately coarse. Which layer catches a probe may change
// freely; that the call round-trips and returns a well-formed governance
// verdict may not. No exact prose, no confidences, no severities: those are
// attribution and are allowed to change.
//
// Contract-symmetric with tests/test_actplane_live.py (Python) and
// tests/integration/actplane-live.test.ts (TypeScript). If the three disagree
// about what the backend returns, one of them is a bug.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The suite identifies itself: one agent id per SDK suite and one session id
// per run, so its rows are recognisable on the Agents screen and in incidents.
// The session id is fresh each run because backend session state persists
// between runs; a reused id would carry the previous run's history into this
// one.
const liveAgentID = "sdk-live-test-go"

var liveRunSessionID = liveAgentID + "-run-" + uuid.New().String()[:12]

// liveClient builds a client against the live backend, or skips the test when
// none is configured. Every client from here scans as the suite's agent under
// the suite's run session; extra options are applied last.
func liveClient(t *testing.T, opts ...Option) *Client {
	t.Helper()

	endpoint := os.Getenv("SHRIKE_LIVE_ENDPOINT")
	apiKey := os.Getenv("SHRIKE_LIVE_API_KEY")
	if endpoint == "" || apiKey == "" {
		t.Skip("live backend not configured (set SHRIKE_LIVE_ENDPOINT + SHRIKE_LIVE_API_KEY)")
	}

	all := append([]Option{
		WithEndpoint(endpoint),
		WithTimeout(30 * time.Second),
		WithSession(liveRunSessionID),
		WithAgentID(liveAgentID),
	}, opts...)
	return NewClient(apiKey, all...)
}

var liveTiers = map[string]bool{
	"allow":            true,
	"warn":             true,
	"require_approval": true,
	"block":            true,
}

var liveOrigins = map[string]bool{
	"human_prompt": true,
	"agent_output": true,
	"agent_action": true,
	"third_party":  true,
}

// assertWellFormed checks the four-state governance surface on every verdict.
//
// Contract symmetry is a shipped promise: safe / refuse_tier / recovery /
// session_state on every response, refused or not. A live check is the only
// place that promise is tested against the thing that actually makes it.
func assertWellFormed(t *testing.T, r *ScanResult, err error, label string) string {
	t.Helper()

	if err != nil {
		t.Fatalf("%s: live call failed: %v", label, err)
	}
	if r == nil {
		t.Fatalf("%s: no result", label)
	}

	tier := r.RefuseTier
	if tier == "" {
		tier = r.Action
	}
	if tier == "" {
		t.Fatalf("%s: no refuse_tier and no action — contract symmetry broken", label)
	}
	if !liveTiers[tier] {
		t.Fatalf("%s: unknown refuse_tier %q", label, tier)
	}
	return tier
}

// TestLiveChannelsRoundTrip proves every act-plane channel this SDK exposes is
// one the backend accepts. Benign content per channel: the point is that the
// REQUEST is accepted and a verdict comes back, not that anything is caught.
//
// A mock cannot fail this. Only the backend can.
func TestLiveChannelsRoundTrip(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()

	cases := []struct {
		channel string
		call    func() (*ScanResult, error)
	}{
		{"command", func() (*ScanResult, error) { return c.ScanCommand(ctx, "git status", "/tmp") }},
		{"sql", func() (*ScanResult, error) {
			return c.ScanSQL(ctx, "SELECT id FROM users WHERE id = 1", "postgres", false)
		}},
		{"file_path", func() (*ScanResult, error) { return c.ScanFile(ctx, "/tmp/report.csv", "") }},
		{"file_content", func() (*ScanResult, error) {
			return c.ScanFile(ctx, "/tmp/notes.txt", "meeting notes for thursday")
		}},
		{"web_search", func() (*ScanResult, error) {
			return c.ScanWebSearch(ctx, "sql injection prevention owasp cheat sheet")
		}},
		{"rag_context", func() (*ScanResult, error) {
			return c.ScanRagContext(ctx, []string{"the refund window is 30 days"}, "refunds")
		}},
		{"a2a_message", func() (*ScanResult, error) {
			return c.ScanA2AMessage(ctx, "task complete, 3 records updated", A2AOptions{Role: "agent"})
		}},
		{"agent_card", func() (*ScanResult, error) {
			return c.ScanAgentCard(ctx, `{"name":"reporter","version":"1.0"}`, false)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.channel, func(t *testing.T) {
			r, err := tc.call()
			assertWellFormed(t, r, err, tc.channel)
		})
	}
}

// TestLiveMCPSchemaNotYetInContract records current behaviour rather than the
// target behaviour: /api/scan/mcp_schema does not yet return refuse_tier,
// recovery or session_state, and does not accept a session context. Once the
// endpoint adopts the response contract this fails and is replaced by an
// ordinary assertWellFormed round-trip.
func TestLiveMCPSchemaNotYetInContract(t *testing.T) {
	c := liveClient(t)
	r, err := c.ScanMCPSchema(
		context.Background(),
		"read_report",
		"Reads a report file from the reports directory and returns its contents.",
		map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{"path": map[string]interface{}{"type": "string"}},
		},
	)
	if err != nil {
		t.Fatalf("mcp_schema: live call failed: %v", err)
	}
	if r == nil {
		t.Fatal("mcp_schema: no result")
	}
	if r.RefuseTier != "" || r.Action != "" {
		t.Fatalf("mcp_schema now returns refuse_tier %q / action %q; "+
			"replace this test with an assertWellFormed round-trip", r.RefuseTier, r.Action)
	}
}

func TestLiveGeneralScanRoundTrips(t *testing.T) {
	c := liveClient(t)
	r, err := c.ScanWithContext(
		context.Background(),
		"summarize the quarterly report",
		"user asked about Q3 earlier",
	)
	assertWellFormed(t, r, err, "general scan")
}

// TestLiveContentOriginArrives asserts the half nobody had checked.
//
// content_origin is the field 1.2.0 exists to deliver and the README
// documents. It was computed by the backend and dropped by every SDK's
// sanitizer for months; then, once all three preserved it, it turned out the
// enforce route never sent it at all.
func TestLiveContentOriginArrives(t *testing.T) {
	c := liveClient(t)
	r, err := c.ScanCommand(context.Background(), "ls -la", "/tmp")
	assertWellFormed(t, r, err, "content_origin probe")

	if r.ContentOrigin == "" {
		t.Fatal("backend sent no content_origin on an act-plane scan")
	}
	if !liveOrigins[r.ContentOrigin] {
		t.Fatalf("unknown content_origin %q", r.ContentOrigin)
	}
	if r.ContentOrigin == "human_prompt" {
		t.Error("an act-plane scan must never be attributed to the operator — " +
			"unknown content types resolve to agent_action by design")
	}
}

// TestLiveBenignWorkIsNotRefused is the other half of the gate. A detector
// that refuses ordinary work is a detector nobody keeps switched on.
//
// Ordering matters: this runs before the attack probes below, and `go test`
// executes a file's Test functions in source order. Every client from
// liveClient scans under the run's session id, so every such scan in this
// package lands in one session. Run these after that session has accumulated
// enough risk and they come back held, correctly, and read as false positives
// that are not there.
//
// A client derived with ForSession is a different session and is not subject
// to this; see TestLiveSessionsAreIsolated. A false-positive probe on the run
// session added below the attack probes will fail for a reason unrelated to
// false positives.
func TestLiveBenignWorkIsNotRefused(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()

	cases := []struct {
		label string
		call  func() (*ScanResult, error)
	}{
		{"git pathspec separator", func() (*ScanResult, error) {
			return c.ScanCommand(ctx, "git log --oneline -5 --", "")
		}},
		{"defensive research", func() (*ScanResult, error) {
			return c.ScanWebSearch(ctx, "owasp top 10 for llm applications")
		}},
		{"legitimate union", func() (*ScanResult, error) {
			return c.ScanSQL(ctx, "SELECT name FROM staff UNION SELECT name FROM contractors", "postgres", false)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			r, err := tc.call()
			tier := assertWellFormed(t, r, err, tc.label)
			if tier != "allow" {
				t.Errorf("FALSE POSITIVE on the live backend: %s was %q, expected allow",
					tc.label, tier)
			}
		})
	}
}

// TestLiveEnforcementEnforces is one end-to-end proof that enforcement
// actually enforces, plus the session accumulation that follows it.
//
// Coarse on purpose: refuse_tier must escalate past allow. Which layer caught
// it, at what confidence, is attribution and may change freely.
//
// Nothing that asserts "allow" may run after this function — see the note at
// the end of this file.
func TestLiveEnforcementEnforces(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()

	r, err := c.ScanCommand(ctx, `psql -c "SELECT * FROM users WHERE id = 1 OR 1=1--"`, "")
	tier := assertWellFormed(t, r, err, "sqli in a command")
	if tier == "allow" {
		t.Fatal("SQL injection carried inside a database CLI argument was ALLOWED " +
			"by the live backend — this is the exact case the command channel exists for")
	}

	// Once a session's accumulated risk crosses the quarantine threshold, later
	// actions in that session are held. Quarantine is a function of
	// accumulated session risk, not of a single refusal: by this point the run
	// session carries a dozen turns of history plus a refused injection, which
	// is what takes it over the threshold. A fresh session's first refusal
	// does not; see TestLiveSessionsAreIsolated. It is also end-to-end proof
	// that this SDK's session identity reaches the backend: with no
	// session_id, nothing accumulates and this comes back allow.
	r2, err2 := c.ScanCommand(ctx, "git log --oneline -5 --", "")
	tier2 := assertWellFormed(t, r2, err2, "post-refusal benign command")
	if tier2 == "allow" {
		t.Error("a benign command was ALLOWED in a session that just refused a SQL " +
			"injection — session correlation is not accumulating, which means the " +
			"session identity is not reaching the backend")
	}
}

// sessionNumber reads a numeric field from the verdict's session_state.
// JSON numbers decode as float64; ok is false when the field is absent.
func sessionNumber(r *ScanResult, key string) (float64, bool) {
	if r == nil || r.SessionState == nil {
		return 0, false
	}
	v, ok := r.SessionState[key].(float64)
	return v, ok
}

// TestLiveSessionsAreIsolated proves that two views derived with ForSession
// are two sessions to the backend.
//
// Session correlation keys on (customer, session, agent), so two views with
// different session ids are separate sessions even though they share the agent
// id, the HTTP client and the circuit breaker. The proof is what the backend
// reports on every response: session_state.session_turn_number and
// session_state.session_risk_score. Session A's turns must count up and carry
// risk after its refusal; session B, scanning right after, must be on its
// first turn with no risk and allowed.
//
// Not asserted: that A's next action is held. Quarantine is a function of
// accumulated session risk, and a fresh session's single refusal stays below
// the threshold.
//
// Fresh ids per run, on purpose: backend session state persists across runs,
// so a fixed id would carry a previous run's history into this one and the
// test would fail for a reason unrelated to isolation.
//
// The cache is switched off for this test: the same benign command is scanned
// in both sessions, and with the default content-keyed cache session B's
// answer would be session A's replayed rather than the backend's verdict for
// B. That behaviour is recorded by TestContentCacheCrossesSessions.
func TestLiveSessionsAreIsolated(t *testing.T) {
	c := liveClient(t, WithoutCache())
	ctx := context.Background()

	a := c.ForSession(liveAgentID + "-iso-a-" + uuid.New().String()[:12])
	b := c.ForSession(liveAgentID + "-iso-b-" + uuid.New().String()[:12])

	refused, err := a.ScanCommand(ctx, `psql -c "SELECT * FROM users WHERE id = 1 OR 1=1--"`, "")
	if tier := assertWellFormed(t, refused, err, "session A: sqli in a command"); tier == "allow" {
		t.Fatal("session A's attack probe was allowed")
	}

	after, err := a.ScanCommand(ctx, "git log --oneline -5 --", "")
	assertWellFormed(t, after, err, "session A: benign command after its own refusal")

	clean, err := b.ScanCommand(ctx, "git log --oneline -5 --", "")
	cleanTier := assertWellFormed(t, clean, err, "session B: same benign command, different session")

	// Session A correlates its own turns: the id from ForSession reached the
	// backend and the backend kept state under it.
	if turn, ok := sessionNumber(after, "session_turn_number"); !ok || turn != 2 {
		t.Errorf("session A's second scan was turn %v (present=%v), expected 2 — "+
			"the session id from ForSession is not being correlated", turn, ok)
	}
	if risk, _ := sessionNumber(after, "session_risk_score"); !(risk > 0) {
		t.Error("session A carries no risk after its own refusal — nothing accumulated")
	}

	// Session B is a different session to the backend: first turn, no risk,
	// allowed. A's refusal did not touch it.
	if cleanTier != "allow" {
		t.Errorf("session B was %q because of session A's refusal — sessions are not "+
			"isolated, which is the cross-user hold ForSession exists to prevent", cleanTier)
	}
	if turn, ok := sessionNumber(clean, "session_turn_number"); !ok || turn != 1 {
		t.Errorf("session B's first scan was turn %v (present=%v), expected 1 — "+
			"B is being correlated into another session", turn, ok)
	}
	if risk, _ := sessionNumber(clean, "session_risk_score"); risk != 0 {
		t.Errorf("session B carries risk %v it never earned", risk)
	}
}

// Ordering: no probe below TestLiveEnforcementEnforces may assert "allow" on
// the run session. Once that session has accumulated enough risk, every later
// scan in it is legitimately held. See TestLiveBenignWorkIsNotRefused. Probes
// on explicit fresh sessions (ForSession) are not subject to this; see
// TestLiveSessionsAreIsolated.
//
// Not yet exposed by any SDK: a session reset. The backend and the MCP server
// provide one.
