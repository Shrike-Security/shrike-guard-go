package pii

import (
	"strings"
	"testing"
)

func TestRedactRehydrateRoundtrip(t *testing.T) {
	text := "Contact john@acme.com or jane@acme.com, SSN 123-45-6789."
	r := Redact(text)
	if !r.PIIDetected {
		t.Fatal("expected PII detected")
	}
	if strings.Contains(r.RedactedText, "john@acme.com") {
		t.Error("email not redacted")
	}
	if strings.Contains(r.RedactedText, "123-45-6789") {
		t.Error("ssn not redacted")
	}
	if !strings.Contains(r.RedactedText, "[EMAIL_1]") || !strings.Contains(r.RedactedText, "[EMAIL_2]") {
		t.Errorf("expected indexed email tokens, got %q", r.RedactedText)
	}
	if got := Rehydrate(r.RedactedText, r.Redactions); got != text {
		t.Errorf("roundtrip mismatch:\n got %q\nwant %q", got, text)
	}
}

func TestRedactionSummary(t *testing.T) {
	r := Redact("a@b.com c@d.com and SSN 111-22-3333")
	sum := RedactionSummary(r.Redactions)
	if sum["email"] != 2 {
		t.Errorf("expected 2 emails, got %d", sum["email"])
	}
	if sum["ssn"] != 1 {
		t.Errorf("expected 1 ssn, got %d", sum["ssn"])
	}
}

func TestNoPII(t *testing.T) {
	const clean = "just a normal sentence with no secrets"
	r := Redact(clean)
	if r.PIIDetected || r.RedactionCount != 0 {
		t.Error("expected no PII")
	}
	if r.RedactedText != clean {
		t.Errorf("text should be unchanged, got %q", r.RedactedText)
	}
}

func TestRehydrateReplacesAllOccurrences(t *testing.T) {
	red := []RedactionEntry{{Token: "[EMAIL_1]", Original: "x@y.com", Type: "email"}}
	got := Rehydrate("send to [EMAIL_1] and cc [EMAIL_1]", red)
	if got != "send to x@y.com and cc x@y.com" {
		t.Errorf("got %q", got)
	}
}

func TestPatternCountAndUpdate(t *testing.T) {
	if PatternCount() == 0 {
		t.Fatal("expected bootstrap patterns to be present")
	}
	// UpdatePatterns swaps the active set; restore afterwards so other tests
	// (and their package-global state) stay deterministic.
	original := defaultPatterns()
	UpdatePatterns(original[:2])
	if PatternCount() != 2 {
		t.Errorf("expected 2 patterns after update, got %d", PatternCount())
	}
	UpdatePatterns(original)
}
