package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanA2AMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/scan/enforce/specialized" {
			t.Errorf("expected specialized enforce path, got %s", r.URL.Path)
		}
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["content_type"] != "a2a_message" {
			t.Errorf("content_type = %v", payload["content_type"])
		}
		ctx, _ := payload["context"].(map[string]interface{})
		if ctx == nil || ctx["sender_agent_id"] != "agent_a" || ctx["role"] != "agent" {
			t.Errorf("a2a context not forwarded: %v", payload["context"])
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"safe": true, "action": "allow"})
	}))
	defer server.Close()

	client := NewClient("k", WithEndpoint(server.URL))
	res, err := client.ScanA2AMessage(context.Background(), "hello peer", A2AOptions{SenderAgentID: "agent_a", Role: "agent"})
	if err != nil {
		t.Fatalf("ScanA2AMessage: %v", err)
	}
	if !res.Safe {
		t.Error("expected safe result")
	}
}

func TestScanAgentCard(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["content_type"] != "agent_card" {
			t.Errorf("content_type = %v", payload["content_type"])
		}
		ctx, _ := payload["context"].(map[string]interface{})
		if ctx == nil || ctx["verify_signature"] != "true" {
			t.Errorf("verify_signature not forwarded: %v", payload["context"])
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"safe":       false,
			"action":     "block",
			"violations": []map[string]interface{}{{"threat_type": "prompt_injection"}},
		})
	}))
	defer server.Close()

	client := NewClient("k", WithEndpoint(server.URL))
	res, err := client.ScanAgentCard(context.Background(), `{"name":"evil"}`, true)
	if err != nil {
		t.Fatalf("ScanAgentCard: %v", err)
	}
	if !IsBlocked(res) {
		t.Error("expected blocked result")
	}
}
