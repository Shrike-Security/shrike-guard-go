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

// TestDeclareScope_RefreshBodyInherits pins the refresh contract: a call with
// only AgentID + MaxDurationSeconds sends exactly those two keys, so the
// backend inherits every other bound from the scope on file. Sending an
// empty allowed_tools here would read as "no tools" (narrowing) and a missing
// max_actions used to read as a cleared budget (widening), so the body must
// carry neither.
func TestDeclareScope_RefreshBodyInherits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if len(payload) != 2 || payload["agent_id"] != "agent_1" || payload["max_duration_seconds"] != float64(7200) {
			t.Errorf("refresh body must be {agent_id, max_duration_seconds} only, got %v", payload)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scope_id":        "scope_123",
			"agent_id":        "agent_1",
			"renewable_until": "2026-09-06T12:00:00Z",
			"ceiling_reached": false,
		})
	}))
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	res, err := client.DeclareScope(context.Background(), DeclareScopeOptions{AgentID: "agent_1", MaxDurationSeconds: 7200})
	if err != nil {
		t.Fatalf("DeclareScope refresh: %v", err)
	}
	if res.RenewableUntil != "2026-09-06T12:00:00Z" || res.CeilingReached {
		t.Errorf("renewal fields not decoded: %+v", res)
	}
}

// TestDeclareScope_RenewableSecondsForwarded: a first declaration may set the
// renewal window.
func TestDeclareScope_RenewableSecondsForwarded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["renewable_seconds"] != float64(86400) {
			t.Errorf("renewable_seconds not forwarded: %v", payload)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"scope_id": "scope_123"})
	}))
	defer server.Close()

	client := NewClient("test-key", WithEndpoint(server.URL))
	if _, err := client.DeclareScope(context.Background(), DeclareScopeOptions{
		AgentID: "agent_1", AllowedTools: []string{"command"}, MaxDurationSeconds: 7200, RenewableSeconds: 86400,
	}); err != nil {
		t.Fatalf("DeclareScope: %v", err)
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
