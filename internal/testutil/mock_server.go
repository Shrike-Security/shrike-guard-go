// Package testutil provides testing utilities for the Shrike SDK.
package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

// MockServer is a mock HTTP server for testing.
type MockServer struct {
	Server *httptest.Server
}

// NewMockServer creates a new mock server with common Shrike API handlers.
func NewMockServer() *MockServer {
	mux := http.NewServeMux()

	// Scan endpoint (enforce). Emits raw backend-shaped responses; the SDK
	// sanitizes them client-side.
	mux.HandleFunc("/api/scan/enforce", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		prompt, _ := payload["prompt"].(string)

		if strings.Contains(strings.ToLower(prompt), "ignore previous") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"safe":       false,
				"action":     "block",
				"confidence": 0.95,
				"reason":     "Prompt injection detected",
				"violations": []map[string]interface{}{{"threat_type": "instruction_override"}},
			})
			return
		}

		if strings.Contains(prompt, "SSN") || strings.Contains(prompt, "-") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"safe":       false,
				"action":     "block",
				"confidence": 0.99,
				"reason":     "PII detected",
				"violations": []map[string]interface{}{{"threat_type": "pii"}},
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"safe": true, "action": "allow"})
	})

	// Specialized scan endpoint (enforce).
	mux.HandleFunc("/api/scan/enforce/specialized", func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		contentType, _ := payload["content_type"].(string)
		content, _ := payload["content"].(string)

		if contentType == "sql" {
			if strings.Contains(content, "'1'='1'") || strings.Contains(content, "DROP TABLE") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"safe":       false,
					"action":     "block",
					"reason":     "SQL injection detected",
					"violations": []map[string]interface{}{{"threat_type": "sql_injection"}},
				})
				return
			}
		}

		if contentType == "file_path" || contentType == "file_content" {
			if strings.Contains(content, "..") || strings.Contains(content, "/etc/passwd") {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"safe":       false,
					"action":     "block",
					"reason":     "Path traversal detected",
					"violations": []map[string]interface{}{{"threat_type": "path_traversal"}},
				})
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"safe": true, "action": "allow"})
	})

	// Auth endpoints
	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if req.Email == "test@example.com" && req.Password == "password123" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "mock-access-token",
				"refresh_token": "mock-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
	})

	mux.HandleFunc("/api/v1/auth/register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "mock-access-token",
			"refresh_token": "mock-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	mux.HandleFunc("/api/v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"customer_id":  "cust_123",
			"email":        "test@example.com",
			"company_name": "Test Company",
			"created_at":   "2024-01-01T00:00:00Z",
		})
	})

	server := httptest.NewServer(mux)
	return &MockServer{Server: server}
}

// URL returns the server URL.
func (m *MockServer) URL() string {
	return m.Server.URL
}

// Close closes the server.
func (m *MockServer) Close() {
	m.Server.Close()
}
