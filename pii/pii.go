// Package pii provides client-side PII redaction and rehydration.
//
// It detects PII in text, replaces each match with an indexed token
// (e.g. [EMAIL_1]), and returns a reversible map for rehydration after LLM
// processing. PII never leaves the caller's process — neither the Shrike
// backend nor the downstream LLM sees raw PII.
//
// Mirrors the TypeScript SDK's piiRedactor.ts and the Python SDK's
// pii_redactor.py (canonical, roundtrip-tested).
package pii

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Pattern is one named PII detector. Prefix drives the token tag
// (e.g. "EMAIL" → [EMAIL_1], [EMAIL_2]).
type Pattern struct {
	Name   string
	Regex  *regexp.Regexp
	Prefix string
}

// RedactionEntry records one redacted span so it can be rehydrated later.
type RedactionEntry struct {
	Token    string // [EMAIL_1]
	Original string // john@acme.com
	Type     string // email
	Position int    // byte offset in the original text
}

// RedactionResult is the output of Redact.
type RedactionResult struct {
	RedactedText   string
	Redactions     []RedactionEntry
	PIIDetected    bool
	RedactionCount int
}

// defaultPatterns are the bootstrap fallback set used until SyncPatterns pulls
// the canonical backend set. Order matters: more specific patterns first.
func defaultPatterns() []Pattern {
	return []Pattern{
		{Name: "aws_key", Prefix: "AWSKEY", Regex: regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
		{Name: "private_key", Prefix: "PRIVKEY", Regex: regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`)},
		{Name: "credit_card", Prefix: "CARD", Regex: regexp.MustCompile(`\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b`)},
		{Name: "ssn", Prefix: "SSN", Regex: regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`)},
		{Name: "email", Prefix: "EMAIL", Regex: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
		{Name: "phone", Prefix: "PHONE", Regex: regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)},
		{Name: "api_key", Prefix: "APIKEY", Regex: regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|access[_-]?token)[:\s=]+[A-Za-z0-9_\-]{20,}\b`)},
		{Name: "medical_record", Prefix: "MRN", Regex: regexp.MustCompile(`(?i)\b(?:MRN|Medical Record)[:\s#]*[A-Z0-9]{6,12}\b`)},
		{Name: "dob", Prefix: "DOB", Regex: regexp.MustCompile(`(?i)\b(?:DOB|D\.O\.B\.|Date of Birth|Birth Date)[:\s]+(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b`)},
		{Name: "bank_account", Prefix: "ACCOUNT", Regex: regexp.MustCompile(`(?i)\b(?:Account|Acct)[:\s#]*\d{8,17}\b`)},
		{Name: "routing_number", Prefix: "ROUTING", Regex: regexp.MustCompile(`(?i)\b(?:Routing|ABA)[:\s#]*\d{9}\b`)},
		{Name: "ip_address", Prefix: "IP", Regex: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
		{Name: "address", Prefix: "ADDR", Regex: regexp.MustCompile(`(?i)\b\d+\s+[A-Za-z0-9\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b`)},
	}
}

var (
	patternsMu     sync.RWMutex
	activePatterns = defaultPatterns()
)

type piiMatch struct {
	start, end   int
	original     string
	name, prefix string
}

// Redact replaces PII in text with indexed tokens and returns a reversible map.
//
//	r := pii.Redact("Email john@acme.com and jane@acme.com")
//	// r.RedactedText == "Email [EMAIL_1] and [EMAIL_2]"
func Redact(text string) RedactionResult {
	patternsMu.RLock()
	patterns := activePatterns
	patternsMu.RUnlock()

	var all []piiMatch
	for _, p := range patterns {
		for _, loc := range p.Regex.FindAllStringIndex(text, -1) {
			all = append(all, piiMatch{start: loc[0], end: loc[1], original: text[loc[0]:loc[1]], name: p.Name, prefix: p.Prefix})
		}
	}

	sort.SliceStable(all, func(i, j int) bool { return all[i].start < all[j].start })

	// Deduplicate overlapping matches (keep the earlier/first match).
	var filtered []piiMatch
	for _, m := range all {
		overlaps := false
		for _, e := range filtered {
			if m.start < e.end && m.end > e.start {
				overlaps = true
				break
			}
		}
		if !overlaps {
			filtered = append(filtered, m)
		}
	}

	// Assign token numbers in document order (ascending).
	counters := map[string]int{}
	tokens := make([]string, len(filtered))
	for i, m := range filtered {
		counters[m.prefix]++
		tokens[i] = fmt.Sprintf("[%s_%d]", m.prefix, counters[m.prefix])
	}

	redactions := make([]RedactionEntry, len(filtered))
	for i, m := range filtered {
		redactions[i] = RedactionEntry{Token: tokens[i], Original: m.original, Type: m.name, Position: m.start}
	}

	// Replace from end to start to preserve earlier byte positions.
	redacted := text
	for i := len(filtered) - 1; i >= 0; i-- {
		m := filtered[i]
		redacted = redacted[:m.start] + tokens[i] + redacted[m.end:]
	}

	return RedactionResult{
		RedactedText:   redacted,
		Redactions:     redactions,
		PIIDetected:    len(redactions) > 0,
		RedactionCount: len(redactions),
	}
}

// Rehydrate replaces indexed tokens with their original PII values. It replaces
// ALL occurrences of each token (an LLM may repeat a token in its output).
func Rehydrate(text string, redactions []RedactionEntry) string {
	result := text
	for _, e := range redactions {
		result = strings.ReplaceAll(result, e.Token, e.Original)
	}
	return result
}

// RedactionSummary counts redactions by type (no raw PII values). Safe for logs.
func RedactionSummary(redactions []RedactionEntry) map[string]int {
	summary := map[string]int{}
	for _, e := range redactions {
		summary[e.Type]++
	}
	return summary
}

// UpdatePatterns replaces the active PII patterns (e.g. with a backend-fetched
// canonical set). Safe for concurrent use.
func UpdatePatterns(patterns []Pattern) {
	patternsMu.Lock()
	activePatterns = patterns
	patternsMu.Unlock()
}

// PatternCount returns the number of active PII patterns.
func PatternCount() int {
	patternsMu.RLock()
	defer patternsMu.RUnlock()
	return len(activePatterns)
}
