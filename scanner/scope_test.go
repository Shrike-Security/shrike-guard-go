package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeclareScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/scope/declare" {
			t.Errorf("expected scope declare path, got %s", r.URL.Path)
		}
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["agent_id"] != "agent_1" {
			t.Errorf("expected agent_id agent_1, got %v", payload["agent_id"])
		}
		if payload["purpose"] != "unit test" {
			t.Errorf("expected purpose to be forwarded, got %v", payload["purpose"])
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scope_id":      "scope_123",
			"agent_id":      "agent_1",
			"allowed_tools": []string{"read_file"},
			"active_until":  "2026-08-01T00:00:00Z",
		})
	}))
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	res, err := client.DeclareScope(context.Background(), DeclareScopeOptions{
		AgentID:      "agent_1",
		AllowedTools: []string{"read_file"},
		Purpose:      "unit test",
	})
	if err != nil {
		t.Fatalf("DeclareScope: %v", err)
	}
	if res.ScopeID != "scope_123" {
		t.Errorf("scope_id = %s", res.ScopeID)
	}
	if res.ActiveUntil == "" {
		t.Error("active_until missing")
	}
}

func TestDeclareScope_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid scope"))
	}))
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	_, err := client.DeclareScope(context.Background(), DeclareScopeOptions{
		AgentID:      "a",
		AllowedTools: []string{"*"},
	})
	if err == nil {
		t.Fatal("expected an error on HTTP 400")
	}
}
