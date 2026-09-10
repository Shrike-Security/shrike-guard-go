package shrike

import (
	"regexp"
	"testing"
)

// Snapshot + restore the default pattern set so tests that mutate global
// state don't bleed into siblings.
func withDefaultPatterns(t *testing.T) func() {
	t.Helper()
	piiPatternsMu.RLock()
	snapshot := append([]PIIPattern(nil), piiPatterns...)
	piiPatternsMu.RUnlock()
	return func() {
		piiPatternsMu.Lock()
		piiPatterns = snapshot
		piiPatternsMu.Unlock()
	}
}

func TestRedactPII(t *testing.T) {
	defer withDefaultPatterns(t)()

	t.Run("returns unchanged text when no PII is found", func(t *testing.T) {
		r := RedactPII("Hello, this is a normal message.")
		if r.PIIDetected {
			t.Errorf("expected no PII, got %d redactions", r.RedactionCount)
		}
		if r.RedactedText != "Hello, this is a normal message." {
			t.Errorf("text changed unexpectedly: %q", r.RedactedText)
		}
	})

	t.Run("redacts single email", func(t *testing.T) {
		r := RedactPII("Contact john@acme.com for details.")
		if !r.PIIDetected {
			t.Fatal("expected PII detected")
		}
		if r.RedactedText != "Contact [EMAIL_1] for details." {
			t.Errorf("got %q", r.RedactedText)
		}
		if r.Redactions[0].Original != "john@acme.com" || r.Redactions[0].Type != "email" {
			t.Errorf("unexpected entry: %+v", r.Redactions[0])
		}
	})

	t.Run("redacts multiple emails with unique tokens", func(t *testing.T) {
		r := RedactPII("Email john@acme.com and jane@acme.com about the meeting.")
		if r.RedactedText != "Email [EMAIL_1] and [EMAIL_2] about the meeting." {
			t.Errorf("got %q", r.RedactedText)
		}
		if r.RedactionCount != 2 {
			t.Errorf("want 2 redactions, got %d", r.RedactionCount)
		}
	})

	t.Run("redacts phone numbers", func(t *testing.T) {
		r := RedactPII("Call me at 555-123-4567.")
		if r.RedactedText != "Call me at [PHONE_1]." {
			t.Errorf("got %q", r.RedactedText)
		}
		if r.Redactions[0].Type != "phone" {
			t.Errorf("want phone, got %s", r.Redactions[0].Type)
		}
	})

	t.Run("redacts SSN", func(t *testing.T) {
		r := RedactPII("My SSN is 123-45-6789.")
		if r.RedactedText != "My SSN is [SSN_1]." {
			t.Errorf("got %q", r.RedactedText)
		}
	})

	t.Run("redacts credit card (contiguous)", func(t *testing.T) {
		r := RedactPII("Card number: 4111111111111111")
		if r.RedactedText != "Card number: [CARD_1]" {
			t.Errorf("got %q", r.RedactedText)
		}
		if r.Redactions[0].Type != "credit_card" {
			t.Errorf("want credit_card, got %s", r.Redactions[0].Type)
		}
	})

	t.Run("redacts credit card (hyphenated)", func(t *testing.T) {
		r := RedactPII("My card is 4532-8721-0039-4456")
		if r.RedactedText != "My card is [CARD_1]" {
			t.Errorf("got %q", r.RedactedText)
		}
		if r.Redactions[0].Original != "4532-8721-0039-4456" {
			t.Errorf("want hyphenated original, got %q", r.Redactions[0].Original)
		}
	})

	t.Run("redacts AWS key", func(t *testing.T) {
		r := RedactPII("Key: AKIAIOSFODNN7EXAMPLE")
		if r.RedactedText != "Key: [AWSKEY_1]" {
			t.Errorf("got %q", r.RedactedText)
		}
	})

	t.Run("redacts IP address", func(t *testing.T) {
		r := RedactPII("Server at 192.168.1.100")
		if r.RedactedText != "Server at [IP_1]" {
			t.Errorf("got %q", r.RedactedText)
		}
	})

	t.Run("redacts multiple PII types", func(t *testing.T) {
		r := RedactPII("Send to john@acme.com at 555-123-4567. SSN: 123-45-6789")
		if r.RedactionCount != 3 {
			t.Fatalf("want 3 redactions, got %d (%+v)", r.RedactionCount, r.Redactions)
		}
		types := map[string]bool{}
		for _, e := range r.Redactions {
			types[e.Type] = true
		}
		for _, want := range []string{"email", "phone", "ssn"} {
			if !types[want] {
				t.Errorf("missing %s redaction in %v", want, types)
			}
		}
	})

	t.Run("redacts private key markers", func(t *testing.T) {
		r := RedactPII("-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAK...")
		if !r.PIIDetected {
			t.Fatal("expected detection")
		}
		if r.Redactions[0].Type != "private_key" {
			t.Errorf("want private_key, got %s", r.Redactions[0].Type)
		}
	})

	t.Run("redacts DOB", func(t *testing.T) {
		r := RedactPII("DOB: 01/15/1990")
		if !r.PIIDetected || r.Redactions[0].Type != "dob" {
			t.Errorf("expected dob, got %+v", r.Redactions)
		}
	})

	t.Run("redacts street address", func(t *testing.T) {
		r := RedactPII("Lives at 123 Main Street")
		if !r.PIIDetected || r.Redactions[0].Type != "address" {
			t.Errorf("expected address, got %+v", r.Redactions)
		}
	})
}

func TestRehydratePII(t *testing.T) {
	defer withDefaultPatterns(t)()

	t.Run("replaces tokens with original values", func(t *testing.T) {
		redactions := []RedactionEntry{
			{Token: "[EMAIL_1]", Original: "john@acme.com", Type: "email", Position: 8},
		}
		got := RehydratePII("Contact [EMAIL_1] for details.", redactions)
		if got != "Contact john@acme.com for details." {
			t.Errorf("got %q", got)
		}
	})

	t.Run("handles multiple tokens", func(t *testing.T) {
		redactions := []RedactionEntry{
			{Token: "[EMAIL_1]", Original: "john@acme.com", Type: "email", Position: 0},
			{Token: "[EMAIL_2]", Original: "jane@acme.com", Type: "email", Position: 20},
		}
		got := RehydratePII("Email [EMAIL_1] and [EMAIL_2] about the meeting.", redactions)
		want := "Email john@acme.com and jane@acme.com about the meeting."
		if got != want {
			t.Errorf("got %q", got)
		}
	})

	t.Run("handles repeated tokens from LLM output", func(t *testing.T) {
		redactions := []RedactionEntry{
			{Token: "[EMAIL_1]", Original: "john@acme.com", Type: "email", Position: 0},
		}
		got := RehydratePII("I sent to [EMAIL_1]. Confirming [EMAIL_1] received it.", redactions)
		want := "I sent to john@acme.com. Confirming john@acme.com received it."
		if got != want {
			t.Errorf("got %q", got)
		}
	})

	t.Run("returns text unchanged when no redactions", func(t *testing.T) {
		got := RehydratePII("No PII here.", nil)
		if got != "No PII here." {
			t.Errorf("got %q", got)
		}
	})

	t.Run("roundtrips: redact then rehydrate", func(t *testing.T) {
		original := "Email john@acme.com and call 555-123-4567."
		r := RedactPII(original)
		restored := RehydratePII(r.RedactedText, r.Redactions)
		if restored != original {
			t.Errorf("roundtrip diverged.\n  want: %q\n  got:  %q", original, restored)
		}
	})
}

func TestGetRedactionSummary(t *testing.T) {
	redactions := []RedactionEntry{
		{Token: "[EMAIL_1]", Original: "a@b.com", Type: "email", Position: 0},
		{Token: "[EMAIL_2]", Original: "c@d.com", Type: "email", Position: 10},
		{Token: "[PHONE_1]", Original: "555-1234", Type: "phone", Position: 20},
	}
	got := GetRedactionSummary(redactions)
	if got["email"] != 2 || got["phone"] != 1 {
		t.Errorf("unexpected summary: %v", got)
	}

	if len(GetRedactionSummary(nil)) != 0 {
		t.Errorf("nil summary should be empty")
	}
}

func TestUpdatePIIPatterns(t *testing.T) {
	defer withDefaultPatterns(t)()

	if GetPIIPatternCount() == 0 {
		t.Fatal("expected default patterns to be loaded")
	}

	t.Run("replaces patterns with custom set", func(t *testing.T) {
		custom := []PIIPattern{
			{
				Name:   "test_iban",
				Regex:  regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b`),
				Prefix: "IBAN",
			},
		}
		UpdatePIIPatterns(custom)
		if GetPIIPatternCount() != 1 {
			t.Errorf("want 1 pattern, got %d", GetPIIPatternCount())
		}

		r := RedactPII("Transfer to GB29NWBK60161331926819")
		if r.RedactedText != "Transfer to [IBAN_1]" {
			t.Errorf("got %q", r.RedactedText)
		}
		if r.Redactions[0].Type != "test_iban" {
			t.Errorf("want test_iban, got %s", r.Redactions[0].Type)
		}
	})

	t.Run("no longer detects old patterns after replacement", func(t *testing.T) {
		UpdatePIIPatterns(nil)
		r := RedactPII("Email john@acme.com")
		if r.PIIDetected {
			t.Errorf("expected no detection, got %+v", r.Redactions)
		}
	})
}
