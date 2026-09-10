package scanner

// Session identity is configured per client, not per process.
//
// Session identity is the key the backend accumulates multi-turn risk against.
// Every caller sharing one id shares one risk score, so a server that scans on
// behalf of many end users must give each user its own session; otherwise one
// user's refusal counts against the next user's action.
//
// Contract-symmetric with tests/test_session_identity.py and
// tests/unit/session-identity.test.ts: if the three disagree about what lands
// in the request context, one of them is a bug.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// capturedContext runs one scan against a stub backend and returns the
// "context" object the SDK put on the wire.
func capturedContext(t *testing.T, c *Client, call func(*Client) error) map[string]interface{} {
	t.Helper()

	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safe":true,"action":"allow","refuse_tier":"allow","recovery":{},"session_state":{}}`))
	}))
	defer srv.Close()

	scoped := *c
	scoped.endpoint = srv.URL
	if err := call(&scoped); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	ctx, _ := body["context"].(map[string]interface{})
	if ctx == nil {
		t.Fatal("request carried no context object")
	}
	return ctx
}

func scanCmd(c *Client) error {
	_, err := c.ScanCommand(context.Background(), "ls -la", "")
	return err
}

// --- the override reaches the wire ---------------------------------------

func TestWithSessionIsWhatGetsSent(t *testing.T) {
	c := NewClient("k", WithSession("sess-explicit"))
	ctx := capturedContext(t, c, scanCmd)

	if got := ctx["session_id"]; got != "sess-explicit" {
		t.Errorf("session_id = %v, want sess-explicit", got)
	}
	// The identity block stays complete — an override replaces one value, it
	// does not drop the others.
	for _, key := range []string{"session_id", "agent_id", "source_application"} {
		if _, ok := ctx[key]; !ok {
			t.Errorf("%s missing from the scan context", key)
		}
	}
	if got := ctx["source_application"]; got != "shrike-guard-go" {
		t.Errorf("source_application = %v, want shrike-guard-go", got)
	}
}

func TestWithAgentIDIsWhatGetsSent(t *testing.T) {
	c := NewClient("k", WithAgentID("agent-billing"))
	if got := capturedContext(t, c, scanCmd)["agent_id"]; got != "agent-billing" {
		t.Errorf("agent_id = %v, want agent-billing", got)
	}
}

// TestDefaultStillSendsTheProcessIdentity pins that there is no regression for
// the single-agent caller. Removing the default would silently delete
// multi-turn correlation for every CLI and worker that never sets a session id.
// The default stays; the warning is what changed.
func TestDefaultStillSendsTheProcessIdentity(t *testing.T) {
	ctx := capturedContext(t, NewClient("k"), scanCmd)

	if got := ctx["session_id"]; got != processSessionID {
		t.Errorf("session_id = %v, want the process id %v", got, processSessionID)
	}
	if got := ctx["agent_id"]; got != processAgentID {
		t.Errorf("agent_id = %v, want the process id %v", got, processAgentID)
	}
}

// TestAgentIDEnvOverrideIsHonoured pins the shared contract that the variable
// named by the fixture (agent_id_env_override, SHRIKE_AGENT_ID) names the
// process's agent. The variable name is read from the fixture so the three
// SDKs cannot drift on it.
func TestAgentIDEnvOverrideIsHonoured(t *testing.T) {
	envVar := loadRequestShapes(t).SessionIdentity.AgentIDEnvOverride
	if envVar == "" {
		t.Fatal("fixture declares no agent_id_env_override — the contract moved")
	}
	t.Setenv(envVar, "agent-from-env")

	// The env override beats the generated process id.
	if got := capturedContext(t, NewClient("k"), scanCmd)["agent_id"]; got != "agent-from-env" {
		t.Errorf("agent_id = %v, want agent-from-env from %s", got, envVar)
	}

	// An explicit client option beats the env override.
	if got := capturedContext(t, NewClient("k", WithAgentID("agent-explicit")), scanCmd)["agent_id"]; got != "agent-explicit" {
		t.Errorf("agent_id = %v, want agent-explicit — WithAgentID must outrank %s", got, envVar)
	}
}

// --- ForSession ------------------------------------------------------------

func TestForSessionSendsTheDerivedID(t *testing.T) {
	guard := NewClient("k")
	if got := capturedContext(t, guard.ForSession("sess-request-42"), scanCmd)["session_id"]; got != "sess-request-42" {
		t.Errorf("session_id = %v, want sess-request-42", got)
	}
}

// TestTwoDerivedClientsDoNotShareASession is the whole point: two end users
// must not accumulate into one risk score.
//
// The two probes scan DIFFERENT content deliberately. Identical content would
// be served from the shared content cache on the second call, no request would
// leave the process, and this test would fail for a reason that has nothing to
// do with session identity. That is not a quirk of the test — see
// TestContentCacheCrossesSessions.
func TestTwoDerivedClientsDoNotShareASession(t *testing.T) {
	guard := NewClient("k")
	ctx := context.Background()

	aliceCtx := capturedContext(t, guard.ForSession("sess-alice"), func(c *Client) error {
		_, err := c.ScanCommand(ctx, "ls -la /alice", "")
		return err
	})
	bobCtx := capturedContext(t, guard.ForSession("sess-bob"), func(c *Client) error {
		_, err := c.ScanCommand(ctx, "ls -la /bob", "")
		return err
	})

	alice, bob := aliceCtx["session_id"], bobCtx["session_id"]
	if alice != "sess-alice" {
		t.Errorf("alice session_id = %v, want sess-alice", alice)
	}
	if bob != "sess-bob" {
		t.Errorf("bob session_id = %v, want sess-bob", bob)
	}
	if alice == bob {
		t.Error("two derived clients shared one session id — one user's refusal " +
			"would hold the next user's action")
	}
}

// TestDefaultScansEverySession is the inverse of the known-gap test it
// replaced. Content-hash caching is off unless the caller opts in, so no
// verdict is reused: user A's allow is never served to user B, and an allow
// cached before a session's state changed cannot be served after it.
//
// This is the enforcement-gate default. A client that cannot see server-side
// session state cannot safely cache a verdict shaped by it, and adding the
// session id to the key would fix only the cross-session half. The Python and
// TypeScript SDKs have no equivalent cache, so this also restores parity.
//
// If this test starts failing, a cache has been re-enabled by default and the
// gate can fail open. That is a release blocker, not a performance tuning
// question.
func TestDefaultScansEverySession(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safe":true,"action":"allow","refuse_tier":"allow","recovery":{},"session_state":{}}`))
	}))
	defer srv.Close()

	guard := NewClient("k", WithEndpoint(srv.URL))
	ctx := context.Background()

	if _, err := guard.ForSession("sess-alice").ScanCommand(ctx, "ls -la", ""); err != nil {
		t.Fatalf("alice scan failed: %v", err)
	}
	if _, err := guard.ForSession("sess-bob").ScanCommand(ctx, "ls -la", ""); err != nil {
		t.Fatalf("bob scan failed: %v", err)
	}

	if requests != 2 {
		t.Errorf("backend saw %d requests, want 2 — each session must be scanned "+
			"on its own. A shared verdict means a cache is on by default and an "+
			"allow can outlive the session state that produced it.", requests)
	}
}

// TestWithCacheOptInReplaysAcrossSessions keeps the hazard on the record for
// callers who opt in. WithCache is keyed on content alone, so enabling it
// deliberately re-introduces cross-session replay. That is an acceptable
// trade only where a stale allow is acceptable; this test exists so the
// behaviour is documented rather than discovered.
func TestWithCacheOptInReplaysAcrossSessions(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safe":true,"action":"allow","refuse_tier":"allow","recovery":{},"session_state":{}}`))
	}))
	defer srv.Close()

	guard := NewClient("k", WithEndpoint(srv.URL), WithCache(5*time.Minute, 100))
	ctx := context.Background()

	if _, err := guard.ForSession("sess-alice").ScanCommand(ctx, "ls -la", ""); err != nil {
		t.Fatalf("alice scan failed: %v", err)
	}
	if _, err := guard.ForSession("sess-bob").ScanCommand(ctx, "ls -la", ""); err != nil {
		t.Fatalf("bob scan failed: %v", err)
	}

	if requests != 1 {
		t.Errorf("backend saw %d requests, want 1 — WithCache should reuse the "+
			"content-keyed verdict. If this changed, update the WithCache doc "+
			"comment, which warns callers about exactly this replay.", requests)
	}
}

// TestWithoutCacheScansEverySession is the escape hatch for the gap above:
// with the cache off, every session is scanned on its own, so a stale allow
// cannot be replayed across sessions or across a quarantine.
func TestWithoutCacheScansEverySession(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safe":true,"action":"allow","refuse_tier":"allow","recovery":{},"session_state":{}}`))
	}))
	defer srv.Close()

	guard := NewClient("k", WithEndpoint(srv.URL), WithoutCache())
	ctx := context.Background()

	if _, err := guard.ForSession("sess-alice").ScanCommand(ctx, "ls -la", ""); err != nil {
		t.Fatalf("alice scan failed: %v", err)
	}
	if _, err := guard.ForSession("sess-bob").ScanCommand(ctx, "ls -la", ""); err != nil {
		t.Fatalf("bob scan failed: %v", err)
	}
	// Same session, same content, scanned again — this is the quarantine case:
	// the second answer must come from the backend, not from the first answer.
	if _, err := guard.ForSession("sess-alice").ScanCommand(ctx, "ls -la", ""); err != nil {
		t.Fatalf("alice rescan failed: %v", err)
	}

	if requests != 3 {
		t.Errorf("backend saw %d requests, want 3 — WithoutCache did not turn the cache off", requests)
	}

	// The cache accessors must not panic with the cache off.
	_ = guard.CacheStats()
	guard.ClearCache()
}

// TestWithCacheZeroDoesNotDisableTheCache pins that WithCache(0, 0) restores
// the default cache rather than disabling it: NewContentCache treats
// non-positive arguments as "use the default". WithoutCache is the way to turn
// the cache off.
func TestWithCacheZeroDoesNotDisableTheCache(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safe":true,"action":"allow","refuse_tier":"allow","recovery":{},"session_state":{}}`))
	}))
	defer srv.Close()

	c := NewClient("k", WithEndpoint(srv.URL), WithCache(0, 0))
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.ScanCommand(ctx, "ls -la", ""); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
	}

	if requests != 1 {
		t.Errorf("backend saw %d requests with WithCache(0, 0), want 1 — if zeroes "+
			"now disable the cache, update WithoutCache's doc comment", requests)
	}
}

// TestForSessionSharesTheExpensiveParts pins that deriving per request is
// cheap, or nobody will do it per request. The circuit breaker matters most: a
// per-request breaker would never accumulate enough failures to open, so
// fail-mode behaviour would silently stop working.
func TestForSessionSharesTheExpensiveParts(t *testing.T) {
	guard := NewClient("k")
	scoped := guard.ForSession("sess-1")

	if scoped.httpClient != guard.httpClient {
		t.Error("derived client did not share the HTTP client — a per-request " +
			"client would open its own connection pool")
	}
	if scoped.cb != guard.cb {
		t.Error("derived client did not share the circuit breaker — a per-request " +
			"breaker never accumulates enough failures to open")
	}
	if scoped.cache != guard.cache {
		t.Error("derived client did not share the content cache")
	}
}

func TestForSessionLeavesTheParentAlone(t *testing.T) {
	guard := NewClient("k", WithSession("sess-parent"))
	_ = guard.ForSession("sess-child")

	if guard.sessionID != "sess-parent" {
		t.Errorf("ForSession mutated the parent: sessionID = %q, want sess-parent",
			guard.sessionID)
	}
}

func TestForSessionInheritsTheAgentID(t *testing.T) {
	guard := NewClient("k", WithAgentID("agent-parent"))
	if got := capturedContext(t, guard.ForSession("sess-1"), scanCmd)["agent_id"]; got != "agent-parent" {
		t.Errorf("agent_id = %v, want agent-parent inherited from the parent client", got)
	}
}

// TestEveryChannelCarriesTheDerivedSession checks that one method wired to the
// client identity is not enough — all of them.
//
// This is the shape of bug the act-plane work kept finding: the value exists,
// one path uses it, another path was never connected.
//
// ScanMCPSchema is deliberately absent — see TestMCPSchemaCarriesNoSessionIdentity.
func TestEveryChannelCarriesTheDerivedSession(t *testing.T) {
	guard := NewClient("k")
	scoped := guard.ForSession("sess-everywhere")
	ctx := context.Background()

	channels := []struct {
		name string
		call func(*Client) error
	}{
		{"Scan", func(c *Client) error { _, err := c.Scan(ctx, "summarize this"); return err }},
		{"ScanCommand", scanCmd},
		{"ScanSQL", func(c *Client) error { _, err := c.ScanSQL(ctx, "SELECT 1", "postgres", false); return err }},
		{"ScanFile", func(c *Client) error { _, err := c.ScanFile(ctx, "/tmp/a.txt", ""); return err }},
		{"ScanWebSearch", func(c *Client) error { _, err := c.ScanWebSearch(ctx, "owasp"); return err }},
		{"ScanRagContext", func(c *Client) error { _, err := c.ScanRagContext(ctx, []string{"chunk"}, ""); return err }},
		{"ScanA2AMessage", func(c *Client) error {
			_, err := c.ScanA2AMessage(ctx, "done", A2AOptions{Role: "agent"})
			return err
		}},
		{"ScanAgentCard", func(c *Client) error {
			_, err := c.ScanAgentCard(ctx, `{"name":"a"}`, false)
			return err
		}},
	}

	for _, ch := range channels {
		t.Run(ch.name, func(t *testing.T) {
			if got := capturedContext(t, scoped, ch.call)["session_id"]; got != "sess-everywhere" {
				t.Errorf("%s did not carry the client's session id (got %v) — it is "+
					"reading the process default instead of the client", ch.name, got)
			}
		})
	}
}

// TestMCPSchemaCarriesNoSessionIdentity records current behaviour rather than
// the target behaviour. /api/scan/mcp_schema is not yet part of the session
// contract: its request accepts no context object, and its response carries
// no refuse_tier, recovery or session_state. When the endpoint adopts the
// contract, this test fails and mcp_schema moves into
// TestEveryChannelCarriesTheDerivedSession.
func TestMCPSchemaCarriesNoSessionIdentity(t *testing.T) {
	var body map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safe":true,"content_type":"mcp_schema"}`))
	}))
	defer srv.Close()

	c := NewClient("k", WithEndpoint(srv.URL)).ForSession("sess-everywhere")
	if _, err := c.ScanMCPSchema(context.Background(), "t", "desc", nil); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if _, ok := body["context"]; ok {
		t.Error("ScanMCPSchema now sends a context; if the backend reads it, " +
			"delete this test and add mcp_schema to " +
			"TestEveryChannelCarriesTheDerivedSession")
	}
}
