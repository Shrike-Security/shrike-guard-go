package scanner

// Act-plane parity and wire-shape tests.
//
// Two jobs in one file, because they fail for different reasons:
//
//   PARITY   — every channel the backend scans must be reachable from this
//              SDK. "The backend supports it" and "a customer can call it"
//              are two facts, and this is what compares them.
//
//   TRANSPORT — parity only proves a method EXISTS. It cannot see a wrong
//              endpoint, a misspelled content_type, or an argument that never
//              reaches the payload, and it cannot see a response field the
//              backend emits being dropped by the sanitizer's allow-list.
//
// Contract-symmetric with tests/unit/actplane-transport.test.ts and
// tests/test_actplane_transport.py. If they disagree on a body shape, one of
// them is a bug.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// requestShapes is the shared request-shape declaration. One file, three
// consumers (this suite, the TypeScript suite, the Python suite), so a
// divergence is a CI failure rather than something someone notices by eye.
// Sibling of canonical-backend-responses.json, which does the same job for the
// response.
//
// Only the fields these tests read are modelled; the fixture carries prose
// explaining each one.
type requestShapes struct {
	SpecializedEndpoint string `json:"specialized_endpoint"`
	GeneralEndpoint     string `json:"general_endpoint"`
	GeneralScan         struct {
		RequiredBodyKeys       []string `json:"required_body_keys"`
		ScanType               string   `json:"scan_type"`
		ConversationHistoryKey string   `json:"conversation_history_key"`
	} `json:"general_scan"`
	SessionIdentity struct {
		RequiredContextKeys    []string          `json:"required_context_keys"`
		SourceApplicationBySDK map[string]string `json:"source_application_by_sdk"`
		AgentIDEnvOverride     string            `json:"agent_id_env_override"`
	} `json:"session_identity"`
	Auth struct {
		AcceptedHeaders  []string `json:"accepted_headers"`
		ForbiddenHeaders []string `json:"forbidden_headers"`
	} `json:"auth"`
	Channels map[string]struct {
		ContentType string `json:"content_type"`
	} `json:"channels"`
	NonSpecialized map[string]struct {
		Endpoint string `json:"endpoint"`
	} `json:"non_specialized"`
}

func loadRequestShapes(t *testing.T) requestShapes {
	t.Helper()
	// The vendored copy ships with the module so the suite runs from any
	// checkout; TestVendoredFixtureMatchesCanonical keeps it identical to the
	// canonical fixture shared with the other SDKs.
	path := filepath.Join("testdata", "contract-symmetry", "canonical-request-shapes.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared request-shape fixture at %s: %v", path, err)
	}
	var shapes requestShapes
	if err := json.Unmarshal(raw, &shapes); err != nil {
		t.Fatalf("parse request-shape fixture: %v", err)
	}
	if len(shapes.Channels) == 0 {
		t.Fatal("request-shape fixture declares no channels — the parser broke, not the data")
	}
	return shapes
}

// specializedContentTypes mirrors models.SpecializedContentTypes() in the Go
// backend (common/models/policy.go). Duplicated on purpose: this SDK ships
// without the backend source, so it cannot import the list, and a silent
// divergence is exactly what this guards. When the backend adds a channel,
// this list and a method move together — which is the point.
var specializedContentTypes = []string{
	"sql",
	"file_path",
	"file_content",
	"web_search",
	"command",
	"a2a_message",
	"agent_card",
	"rag_context",
}

// channelMethods maps each channel to the exported method that reaches it.
// file_path and file_content share ScanFile (it decides by whether content was
// supplied), which is why this is a mapping rather than a name transformation.
var channelMethods = map[string]string{
	"sql":          "ScanSQL",
	"file_path":    "ScanFile",
	"file_content": "ScanFile",
	"web_search":   "ScanWebSearch",
	"command":      "ScanCommand",
	"a2a_message":  "ScanA2AMessage",
	"agent_card":   "ScanAgentCard",
	"rag_context":  "ScanRagContext",
}

func TestActPlaneParity(t *testing.T) {
	clientType := reflect.TypeOf(&Client{})

	for _, ct := range specializedContentTypes {
		method, ok := channelMethods[ct]
		if !ok {
			t.Errorf("content type %q has no SDK method declared. A channel the "+
				"backend scans but the SDK cannot reach is a channel our customers "+
				"do not have.", ct)
			continue
		}
		if _, found := clientType.MethodByName(method); !found {
			t.Errorf("Client has no %s() for content type %q", method, ct)
		}
	}

	// Not a specialized content type — its own endpoint and detector — but an
	// act-plane surface. Tool poisoning needs no execution, so a caller that
	// cannot screen a tools/list response has no defence against it at all.
	if _, found := clientType.MethodByName("ScanMCPSchema"); !found {
		t.Error("Client cannot screen an MCP tool definition (ScanMCPSchema missing)")
	}
}

// --- transport --------------------------------------------------------------

type captured struct {
	path string
	body map[string]interface{}
	hdrs http.Header
}

// newCapturingServer returns a server that records the request and replies
// with the given verdict body.
func newCapturingServer(t *testing.T, got *captured, verdict map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.hdrs = r.Header.Clone()
		if err := json.NewDecoder(r.Body).Decode(&got.body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		json.NewEncoder(w).Encode(verdict)
	}))
}

func safeVerdict() map[string]interface{} {
	return map[string]interface{}{
		"safe":           true,
		"action":         "allow",
		"refuse_tier":    "allow",
		"content_origin": "agent_action",
	}
}

// TestActPlaneContentTypes: the shared doSpecializedScan means adding a channel
// is one line. The risk that creates is that the one line is wrong, and every
// channel looks identical from the outside.
func TestActPlaneContentTypes(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		call        func(*Client, context.Context) (*ScanResult, error)
	}{
		{"ScanCommand", "command", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanCommand(ctx, "ls -la", "")
		}},
		{"ScanSQL", "sql", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanSQL(ctx, "SELECT 1", "", false)
		}},
		{"ScanWebSearch", "web_search", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanWebSearch(ctx, "owasp")
		}},
		{"ScanRagContext", "rag_context", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanRagContext(ctx, []string{"chunk"}, "")
		}},
		{"ScanA2AMessage", "a2a_message", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanA2AMessage(ctx, "hello", A2AOptions{})
		}},
		{"ScanAgentCard", "agent_card", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanAgentCard(ctx, "{}", false)
		}},
		{"ScanFile path", "file_path", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanFile(ctx, "/etc/passwd", "")
		}},
		// One method, two channels, decided by an argument. Getting this
		// backwards would scan a file body against path-traversal rules.
		{"ScanFile content", "file_content", func(c *Client, ctx context.Context) (*ScanResult, error) {
			return c.ScanFile(ctx, "/tmp/config.py", `api_key = "sk-x"`)
		}},
	}

	shapes := loadRequestShapes(t)

	// The fixture is the channel list. A channel declared there without a case
	// here is a channel nobody checks the wire shape of.
	exercised := map[string]bool{}
	for _, tc := range cases {
		exercised[tc.contentType] = true
	}
	for ct := range shapes.Channels {
		if !exercised[ct] {
			t.Errorf("channel %q is declared in the shared fixture but has no wire-shape test here", ct)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got captured
			server := newCapturingServer(t, &got, safeVerdict())
			defer server.Close()

			client := NewClient("test-key", WithEndpoint(server.URL))
			if _, err := tc.call(client, context.Background()); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}

			if got.path != shapes.SpecializedEndpoint {
				t.Errorf("expected %s, got %s", shapes.SpecializedEndpoint, got.path)
			}
			want := shapes.Channels[tc.contentType].ContentType
			if got.body["content_type"] != want {
				t.Errorf("expected content_type %q, got %v", want, got.body["content_type"])
			}
			if _, ok := got.body["content"].(string); !ok {
				t.Errorf("content missing or not a string: %v", got.body["content"])
			}

			// Identity rides on every act-plane request.
			ctx, _ := got.body["context"].(map[string]interface{})
			for _, key := range shapes.SessionIdentity.RequiredContextKeys {
				if v, _ := ctx[key].(string); v == "" {
					t.Errorf("%s: context is missing %s", tc.contentType, key)
				}
			}
			if ctx["source_application"] != shapes.SessionIdentity.SourceApplicationBySDK["go"] {
				t.Errorf("source_application = %v, want %q",
					ctx["source_application"], shapes.SessionIdentity.SourceApplicationBySDK["go"])
			}
		})
	}
}

func TestScanCommandCarriesCwd(t *testing.T) {
	var got captured
	server := newCapturingServer(t, &got, safeVerdict())
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	if _, err := client.ScanCommand(context.Background(), "git status", "/srv/app"); err != nil {
		t.Fatalf("ScanCommand: %v", err)
	}

	ctx, _ := got.body["context"].(map[string]interface{})
	if ctx["cwd"] != "/srv/app" {
		t.Errorf("expected cwd in context, got %v", ctx["cwd"])
	}
}

func TestScanRagContextSerialization(t *testing.T) {
	// The backend splits chunks back apart. Joining them into one string would
	// merge two documents and lose the boundary an injection usually sits on.
	var got captured
	server := newCapturingServer(t, &got, safeVerdict())
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	if _, err := client.ScanRagContext(context.Background(), []string{"first", "second"}, "why"); err != nil {
		t.Fatalf("ScanRagContext: %v", err)
	}

	if got.body["content"] != `["first","second"]` {
		t.Errorf("expected a JSON array of chunks, got %v", got.body["content"])
	}
	ctx, _ := got.body["context"].(map[string]interface{})
	if ctx["query"] != "why" {
		t.Errorf("expected query in context, got %v", ctx["query"])
	}
}

func TestScanMCPSchemaEndpointAndBody(t *testing.T) {
	// Not a specialized content type: its own route, its own detector, and a
	// body that is not {content, content_type}. Routing it through the
	// specialized endpoint would scan the description as opaque text.
	var got captured
	server := newCapturingServer(t, &got, safeVerdict())
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	_, err := client.ScanMCPSchema(context.Background(), "read_file", "Reads a file from disk.", nil)
	if err != nil {
		t.Fatalf("ScanMCPSchema: %v", err)
	}

	shapes := loadRequestShapes(t)
	if got.path != shapes.NonSpecialized["mcp_schema"].Endpoint {
		t.Errorf("expected %s, got %s", shapes.NonSpecialized["mcp_schema"].Endpoint, got.path)
	}
	if got.body["name"] != "read_file" {
		t.Errorf("expected name to be forwarded, got %v", got.body["name"])
	}
	if _, present := got.body["content_type"]; present {
		t.Error("mcp_schema body must not carry content_type")
	}
	if _, present := got.body["input_schema"]; present {
		t.Error("input_schema must be omitted when nil")
	}
}

// TestContentOriginSurvivesSanitizer pins the 4.1.0 bug.
//
// The sanitizer is an ALLOW-LIST: a field the backend sends is dropped unless
// it is named in preservedGovernanceFields AND assigned in
// SanitizeScanResponse. content_origin shipped on the backend and reached zero
// callers in the TS and Python SDKs for exactly that reason. This SDK had the
// same hole until 4.1.0.
func TestContentOriginSurvivesSanitizer(t *testing.T) {
	var got captured
	verdict := safeVerdict()
	verdict["content_origin"] = "third_party"
	server := newCapturingServer(t, &got, verdict)
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	res, err := client.ScanRagContext(context.Background(), []string{"retrieved text"}, "")
	if err != nil {
		t.Fatalf("ScanRagContext: %v", err)
	}

	if res.ContentOrigin != "third_party" {
		t.Errorf("content_origin dropped by the sanitizer: got %q", res.ContentOrigin)
	}
	if AttributableToOperator(res.ContentOrigin) {
		t.Error("third_party content must not be attributed to the operator")
	}
	if !AttributableToOperator("human_prompt") {
		t.Error("human_prompt must be attributable to the operator")
	}
}

func TestGovernanceSurfaceSurvivesRefusal(t *testing.T) {
	var got captured
	server := newCapturingServer(t, &got, map[string]interface{}{
		"safe":           false,
		"action":         "block",
		"refuse_tier":    "block",
		"threat_type":    "sql_injection",
		"content_origin": "agent_action",
		"recovery":       map[string]interface{}{"instruction": "use bound parameters"},
		"session_state":  map[string]interface{}{"session_risk_score": 0.4},
	})
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	res, err := client.ScanCommand(context.Background(), `psql -c "SELECT 1 OR 1=1--"`, "")
	if err != nil {
		t.Fatalf("ScanCommand: %v", err)
	}

	if res.Safe {
		t.Error("expected an unsafe verdict")
	}
	if res.RefuseTier != "block" {
		t.Errorf("expected refuse_tier block, got %q", res.RefuseTier)
	}
	if len(res.Recovery) == 0 {
		t.Error("recovery block dropped")
	}
	if len(res.SessionState) == 0 {
		t.Error("session_state dropped")
	}
	if res.ContentOrigin != "agent_action" {
		t.Errorf("content_origin dropped on a refusal: got %q", res.ContentOrigin)
	}
}

func TestActPlaneSendsScanAuthHeader(t *testing.T) {
	// OptionalAuth reads Authorization: Bearer or X-Shrike-API-Key only. An
	// X-API-Key request carries no recognized credential, silently resolves to
	// the anonymous tier, and every scan looks like a fast L1-L5 pass.
	var got captured
	server := newCapturingServer(t, &got, safeVerdict())
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	if _, err := client.ScanCommand(context.Background(), "ls", ""); err != nil {
		t.Fatalf("ScanCommand: %v", err)
	}

	shapes := loadRequestShapes(t)
	for _, forbidden := range shapes.Auth.ForbiddenHeaders {
		if got.hdrs.Get(forbidden) != "" {
			t.Errorf("%s must never be sent — it resolves to the anonymous tier", forbidden)
		}
	}
	accepted := false
	for _, h := range shapes.Auth.AcceptedHeaders {
		if got.hdrs.Get(h) != "" {
			accepted = true
		}
	}
	if !accepted {
		t.Errorf("no recognized scan auth header was sent (want one of %s)",
			strings.Join(shapes.Auth.AcceptedHeaders, ", "))
	}
}

// TestGeneralScanSendsIdentityAndHistorySeparately covers the general prompt
// path.
//
// A string `context` is not the identity object: the backend treats it as a
// source label and leaves session and agent identity empty, so session
// correlation has no key to group turns by and scope enforcement has no agent
// to attribute the scan to. All three SDKs send the object, with the history
// in its own field.
func TestGeneralScanSendsIdentityAndHistorySeparately(t *testing.T) {
	shapes := loadRequestShapes(t)

	var got captured
	server := newCapturingServer(t, &got, safeVerdict())
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	if _, err := client.ScanWithContext(context.Background(), "hello", "earlier turn"); err != nil {
		t.Fatalf("ScanWithContext: %v", err)
	}

	if got.path != shapes.GeneralEndpoint {
		t.Errorf("expected %s, got %s", shapes.GeneralEndpoint, got.path)
	}
	for _, key := range shapes.GeneralScan.RequiredBodyKeys {
		if _, present := got.body[key]; !present {
			t.Errorf("general scan body is missing %s", key)
		}
	}
	if got.body["scan_type"] != shapes.GeneralScan.ScanType {
		t.Errorf("scan_type = %v, want %q", got.body["scan_type"], shapes.GeneralScan.ScanType)
	}

	ctx, ok := got.body["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("context must be an object; a string is parsed into "+
			"SourceApplication and silently discards the session identity. got %T",
			got.body["context"])
	}
	for _, key := range shapes.SessionIdentity.RequiredContextKeys {
		if v, _ := ctx[key].(string); v == "" {
			t.Errorf("general scan context is missing %s", key)
		}
	}
	if ctx["source_application"] != shapes.SessionIdentity.SourceApplicationBySDK["go"] {
		t.Errorf("source_application = %v, want %q",
			ctx["source_application"], shapes.SessionIdentity.SourceApplicationBySDK["go"])
	}
	if got.body[shapes.GeneralScan.ConversationHistoryKey] != "earlier turn" {
		t.Errorf("conversation history not forwarded: %v",
			got.body[shapes.GeneralScan.ConversationHistoryKey])
	}
}
