package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	shrike "github.com/shrike-security/shrike-guard-go"
)

func TestGetScanHeaders(t *testing.T) {
	t.Run("generates headers with API key", func(t *testing.T) {
		headers := GetScanHeaders("test-api-key", "")

		if headers["Authorization"] != "Bearer test-api-key" {
			t.Errorf("Expected Authorization header, got %s", headers["Authorization"])
		}
		if headers["Content-Type"] != "application/json" {
			t.Errorf("Expected Content-Type header, got %s", headers["Content-Type"])
		}
		if headers["X-Shrike-SDK"] != shrike.SDKName {
			t.Errorf("Expected X-Shrike-SDK header, got %s", headers["X-Shrike-SDK"])
		}
		if headers["X-Shrike-SDK-Version"] != shrike.Version {
			t.Errorf("Expected X-Shrike-SDK-Version header, got %s", headers["X-Shrike-SDK-Version"])
		}
		if headers["X-Shrike-Request-ID"] == "" {
			t.Error("Expected X-Shrike-Request-ID header to be generated")
		}
	})

	t.Run("uses provided request ID", func(t *testing.T) {
		headers := GetScanHeaders("test-key", "custom-request-id")

		if headers["X-Shrike-Request-ID"] != "custom-request-id" {
			t.Errorf("Expected custom request ID, got %s", headers["X-Shrike-Request-ID"])
		}
	})

	t.Run("generates unique UUIDs", func(t *testing.T) {
		headers1 := GetScanHeaders("test-key", "")
		headers2 := GetScanHeaders("test-key", "")

		if headers1["X-Shrike-Request-ID"] == headers2["X-Shrike-Request-ID"] {
			t.Error("Expected unique request IDs")
		}
	})
}

func TestNewClient(t *testing.T) {
	t.Run("creates client with defaults", func(t *testing.T) {
		client := NewClient("test-api-key")

		if client == nil {
			t.Fatal("Expected client to be created")
		}
	})

	t.Run("creates client with custom endpoint", func(t *testing.T) {
		client := NewClient("test-key", WithEndpoint("https://custom.endpoint.com/"))

		if client.endpoint != "https://custom.endpoint.com" {
			t.Errorf("Expected custom endpoint, got %s", client.endpoint)
		}
	})

	t.Run("creates client with custom timeout", func(t *testing.T) {
		client := NewClient("test-key", WithTimeout(5*time.Second))

		if client.timeout != 5*time.Second {
			t.Errorf("Expected 5s timeout, got %v", client.timeout)
		}
	})
}

func TestClient_Scan(t *testing.T) {
	t.Run("scans prompt successfully via enforce endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/scan/enforce" {
				t.Errorf("Expected /api/scan/enforce path, got %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("Expected POST method, got %s", r.Method)
			}

			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["prompt"] != "Hello, world!" {
				t.Errorf("Expected prompt, got %v", payload["prompt"])
			}
			// Session context must ride every scan for L9 correlation.
			ctx, _ := payload["context"].(map[string]interface{})
			if ctx == nil || ctx["session_id"] == "" || ctx["source_application"] != "shrike-guard-go" {
				t.Errorf("Expected session context, got %v", payload["context"])
			}

			json.NewEncoder(w).Encode(map[string]interface{}{"safe": true, "action": "allow"})
		}))
		defer server.Close()

		client := NewClient("test-key", WithEndpoint(server.URL))
		result, err := client.Scan(context.Background(), "Hello, world!")

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !result.Safe {
			t.Error("Expected safe result")
		}
		if IsBlocked(result) {
			t.Error("allow verdict must not be blocked")
		}
	})

	t.Run("includes conversation_history when context provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["conversation_history"] != "Previous context" {
				t.Errorf("Expected conversation_history, got %v", payload["conversation_history"])
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"safe": true})
		}))
		defer server.Close()

		client := NewClient("test-key", WithEndpoint(server.URL))
		_, err := client.ScanWithContext(context.Background(), "Test", "Previous context")

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})

	t.Run("handles API errors fail-closed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		client := NewClient("test-key",
			WithEndpoint(server.URL),
			WithFailMode(shrike.FailModeClosed),
		)
		_, err := client.Scan(context.Background(), "Test")

		if err == nil {
			t.Fatal("Expected error in fail-closed mode")
		}
	})

	t.Run("handles API errors fail-open with degraded marker", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()

		client := NewClient("test-key",
			WithEndpoint(server.URL),
			WithFailMode(shrike.FailModeOpen),
		)
		result, err := client.Scan(context.Background(), "Test")

		if err != nil {
			t.Fatalf("Expected no error in fail-open mode, got %v", err)
		}
		if !result.Safe {
			t.Error("Expected safe result in fail-open mode")
		}
		if result.Reason != "scan_unavailable_fail_open" {
			t.Errorf("Expected scan_unavailable_fail_open reason, got %s", result.Reason)
		}
		if !result.Degraded {
			t.Error("fail-open verdict must be marked Degraded so callers can tell it was not scanned")
		}
	})

	t.Run("detects prompt injection and sanitizes to bucketed confidence", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Enforce shape: top-level threat_type null, detail in violations[],
			// plus internal attribution fields that MUST be stripped.
			json.NewEncoder(w).Encode(map[string]interface{}{
				"safe":       false,
				"action":     "block",
				"confidence": 0.95,
				"reason":     "Prompt injection detected",
				"violations": []map[string]interface{}{
					{"threat_type": "instruction_override", "policy_id": "pol_123", "matched_pattern": "ignore previous"},
				},
			})
		}))
		defer server.Close()

		client := NewClient("test-key", WithEndpoint(server.URL))
		result, err := client.Scan(context.Background(), "Ignore previous instructions")

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Safe {
			t.Error("Expected unsafe result")
		}
		if result.ThreatType != "prompt_injection" {
			t.Errorf("Expected normalized prompt_injection threat, got %s", result.ThreatType)
		}
		if result.Confidence != "high" {
			t.Errorf("Expected bucketed confidence 'high', got %q", result.Confidence)
		}
		if !IsBlocked(result) {
			t.Error("block verdict must be blocked")
		}
		// Internal attribution must be stripped from the violation.
		if len(result.Violations) != 1 {
			t.Fatalf("Expected 1 violation, got %d", len(result.Violations))
		}
		if _, leaked := result.Violations[0]["policy_id"]; leaked {
			t.Error("policy_id must be stripped from violations")
		}
		if _, leaked := result.Violations[0]["matched_pattern"]; leaked {
			t.Error("matched_pattern must be stripped from violations")
		}
	})
}

func TestClient_ScanSQL(t *testing.T) {
	t.Run("scans SQL via enforce specialized endpoint", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/scan/enforce/specialized" {
				t.Errorf("Expected /api/scan/enforce/specialized path, got %s", r.URL.Path)
			}

			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["content_type"] != "sql" {
				t.Errorf("Expected sql content type, got %v", payload["content_type"])
			}

			json.NewEncoder(w).Encode(map[string]interface{}{"safe": true})
		}))
		defer server.Close()

		client := NewClient("test-key", WithEndpoint(server.URL))
		result, err := client.ScanSQL(context.Background(), "SELECT * FROM users", "", false)

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !result.Safe {
			t.Error("Expected safe result")
		}
	})

	t.Run("includes database in tool context", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			ctx, _ := payload["context"].(map[string]interface{})
			if ctx == nil || ctx["database"] != "production_db" {
				t.Errorf("Expected database context, got %v", payload["context"])
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"safe": true})
		}))
		defer server.Close()

		client := NewClient("test-key", WithEndpoint(server.URL))
		_, err := client.ScanSQL(context.Background(), "SELECT * FROM users", "production_db", false)

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})
}

func TestClient_ScanFile(t *testing.T) {
	t.Run("scans file paths", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["content_type"] != "file_path" {
				t.Errorf("Expected file_path content type, got %v", payload["content_type"])
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"safe": true})
		}))
		defer server.Close()

		client := NewClient("test-key", WithEndpoint(server.URL))
		result, err := client.ScanFile(context.Background(), "/tmp/data.txt", "")

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !result.Safe {
			t.Error("Expected safe result")
		}
	})

	t.Run("scans file content when provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["content_type"] != "file_content" {
				t.Errorf("Expected file_content content type, got %v", payload["content_type"])
			}
			ctx, _ := payload["context"].(map[string]interface{})
			if ctx == nil || ctx["file_content"] != "secret data" {
				t.Errorf("Expected file content in context, got %v", payload["context"])
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"safe": true})
		}))
		defer server.Close()

		client := NewClient("test-key", WithEndpoint(server.URL))
		_, err := client.ScanFile(context.Background(), "/tmp/config.json", "secret data")

		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})
}
