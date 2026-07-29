package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSandboxClient_Scan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sandbox/scan" {
			t.Errorf("expected sandbox path, got %s", r.URL.Path)
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["prompt"] != "test prompt" {
			t.Errorf("prompt = %v", body["prompt"])
		}
		// Raw response carrying an internal field that MUST be stripped.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"safe":       false,
			"action":     "block",
			"confidence": 0.9,
			"policy_id":  "should_be_stripped",
			"violations": []map[string]interface{}{{"threat_type": "jailbreak", "matched_pattern": "x"}},
		})
	}))
	defer server.Close()

	client := NewSandboxClient(ClientOptions{BaseURL: server.URL, APIKey: "k"})
	res, err := client.Scan(context.Background(), SandboxScanRequest{Prompt: "test prompt"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Safe {
		t.Error("expected unsafe result")
	}
	if res.ThreatType != "jailbreak" {
		t.Errorf("expected jailbreak, got %s", res.ThreatType)
	}
	if len(res.Violations) == 1 {
		if _, leaked := res.Violations[0]["matched_pattern"]; leaked {
			t.Error("matched_pattern must be stripped from sandbox results")
		}
	}
}
