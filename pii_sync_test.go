package shrike

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const goodPayload = `{
  "patterns": [
    {"pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "threat_type": "pii_ssn", "confidence": 0.95, "description": "US SSN"},
    {"pattern": "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}[A-Z0-9]{0,16}\\b", "threat_type": "pii_iban", "confidence": 0.9, "description": "IBAN"}
  ],
  "total": 2,
  "version": "2026-06-30"
}`

func TestSyncPIIPatterns_Success(t *testing.T) {
	defer withDefaultPatterns(t)()

	t.Run("replaces bootstrap with backend patterns", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/pii/patterns" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(goodPayload))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{
			Endpoint: server.URL,
		})
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}

		if got := GetPIIPatternCount(); got != 2 {
			t.Errorf("expected 2 patterns, got %d", got)
		}

		// Wider coverage: IBAN now detected (wasn't in bootstrap).
		r := RedactPII("Transfer to GB29NWBK60161331926819 please")
		if !r.PIIDetected {
			t.Fatal("expected PII detection after sync")
		}
		if r.Redactions[0].Type != "iban" {
			t.Errorf("expected iban, got %s", r.Redactions[0].Type)
		}
	})

	t.Run("sends Authorization header when APIKey provided", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		var capturedAuth string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			w.Write([]byte(goodPayload))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{
			Endpoint: server.URL,
			APIKey:   "shrike_test_key",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedAuth != "Bearer shrike_test_key" {
			t.Errorf("auth header mismatch: %q", capturedAuth)
		}
	})

	t.Run("omits Authorization header when APIKey absent", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		var capturedAuth string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			w.Write([]byte(goodPayload))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{Endpoint: server.URL})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedAuth != "" {
			t.Errorf("expected no auth header, got %q", capturedAuth)
		}
	})

	t.Run("strips trailing slashes from endpoint", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		var capturedPath string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			w.Write([]byte(goodPayload))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{
			Endpoint: server.URL + "///",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedPath != "/api/pii/patterns" {
			t.Errorf("path mismatch: %q", capturedPath)
		}
	})
}

func TestSyncPIIPatterns_FailurePreservesFallback(t *testing.T) {
	defer withDefaultPatterns(t)()
	bootstrap := GetPIIPatternCount()

	t.Run("non-200 keeps bootstrap", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{Endpoint: server.URL})
		if err == nil {
			t.Fatal("expected non-nil informational error")
		}
		if GetPIIPatternCount() != bootstrap {
			t.Errorf("pattern count changed; expected %d, got %d", bootstrap, GetPIIPatternCount())
		}
	})

	t.Run("malformed JSON keeps bootstrap", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{Endpoint: server.URL})
		if err == nil {
			t.Fatal("expected non-nil informational error")
		}
		if GetPIIPatternCount() != bootstrap {
			t.Errorf("pattern count changed; expected %d, got %d", bootstrap, GetPIIPatternCount())
		}
	})

	t.Run("empty pattern array keeps bootstrap", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			payload, _ := json.Marshal(piiPatternsResponse{Patterns: []piiPatternEntry{}, Total: 0, Version: "v"})
			w.Write(payload)
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{Endpoint: server.URL})
		if err == nil {
			t.Fatal("expected non-nil informational error")
		}
		if GetPIIPatternCount() != bootstrap {
			t.Errorf("pattern count changed; expected %d, got %d", bootstrap, GetPIIPatternCount())
		}
	})

	t.Run("all unknown threat types keep bootstrap", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"patterns":[{"pattern":"\\bx\\b","threat_type":"pii_nonsense","confidence":1.0,"description":""}],"total":1,"version":"v"}`))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{Endpoint: server.URL})
		if err == nil {
			t.Fatal("expected non-nil informational error")
		}
		if GetPIIPatternCount() != bootstrap {
			t.Errorf("pattern count changed; expected %d, got %d", bootstrap, GetPIIPatternCount())
		}
	})

	t.Run("case-insensitive: capitalized input matches lowercase backend pattern", func(t *testing.T) {
		// Regression: backend patterns are authored lowercase without a
		// (?i) inline flag. Sync must compile case-insensitively to match
		// MCP TS behavior, or "Phone: 555-..." won't match the backend's
		// lowercase `phone...` pattern.
		defer withDefaultPatterns(t)()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"patterns":[{"pattern":"(?:phone|tel|mobile|cell)[\\s:]*\\+?\\d[\\d\\s().-]{7,}","threat_type":"pii_phone","confidence":0.9,"description":"Phone with context"}],"total":1,"version":"v"}`))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{Endpoint: server.URL})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}

		r := RedactPII("Phone: 555-123-4567")
		if !r.PIIDetected {
			t.Fatal("expected case-insensitive match on 'Phone'")
		}
		if r.Redactions[0].Type != "phone" {
			t.Errorf("expected phone, got %s", r.Redactions[0].Type)
		}
	})

	t.Run("unparseable regex among others does not kill sync", func(t *testing.T) {
		defer withDefaultPatterns(t)()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"patterns":[
				{"pattern":"[invalid","threat_type":"pii_ssn","confidence":0.9,"description":"bad"},
				{"pattern":"\\bok@example\\.com\\b","threat_type":"pii_email","confidence":0.9,"description":"ok"}
			],"total":2,"version":"v"}`))
		}))
		defer server.Close()

		err := SyncPIIPatterns(context.Background(), SyncPIIPatternsOptions{Endpoint: server.URL})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if got := GetPIIPatternCount(); got != 1 {
			t.Errorf("expected 1 surviving pattern, got %d", got)
		}
	})
}
