package shrike

// PII Redactor — client-side PII redaction and rehydration.
//
// Detects PII in text, replaces with indexed tokens, and provides a reversible
// map for rehydration after LLM processing. PII never leaves the caller's
// process — neither the backend nor the downstream LLM sees raw PII.
//
// Ported from the MCP server's piiRedactor.ts (canonical, roundtrip-tested).

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// PIIPattern is one PII detection rule.
type PIIPattern struct {
	Name   string         // e.g. "email"
	Regex  *regexp.Regexp // compiled detector
	Prefix string         // e.g. "EMAIL" → [EMAIL_1], [EMAIL_2]
}

// RedactionEntry is one redacted span: token in redacted text + original PII value.
type RedactionEntry struct {
	Token    string // [EMAIL_1]
	Original string // john@acme.com
	Type     string // email
	Position int    // char offset in original text
}

// RedactionResult is the outcome of RedactPII.
type RedactionResult struct {
	RedactedText   string
	Redactions     []RedactionEntry
	PIIDetected    bool
	RedactionCount int
}

// Default PII patterns (fallback when backend is unreachable).
// Order matters: more specific patterns first to avoid partial matches.
// Go's RE2 doesn't support look-around or backreferences; all of these use
// the same character classes as the MCP TS source so detection parity holds.
var defaultPIIPatterns = []PIIPattern{
	{
		Name:   "aws_key",
		Regex:  regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
		Prefix: "AWSKEY",
	},
	{
		Name:   "private_key",
		Regex:  regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
		Prefix: "PRIVKEY",
	},
	{
		Name: "credit_card",
		Regex: regexp.MustCompile(
			`\b(?:` +
				`4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|` +
				`5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|` +
				`3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|` +
				`6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}` +
				`)\b`,
		),
		Prefix: "CARD",
	},
	{
		Name:   "ssn",
		Regex:  regexp.MustCompile(`\b\d{3}-?\d{2}-?\d{4}\b`),
		Prefix: "SSN",
	},
	{
		Name:   "email",
		Regex:  regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
		Prefix: "EMAIL",
	},
	{
		Name:   "phone",
		Regex:  regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
		Prefix: "PHONE",
	},
	{
		Name:   "api_key",
		Regex:  regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|access[_-]?token)[:\s=]+[A-Za-z0-9_\-]{20,}\b`),
		Prefix: "APIKEY",
	},
	{
		Name:   "medical_record",
		Regex:  regexp.MustCompile(`(?i)\b(?:MRN|Medical Record)[:\s#]*[A-Z0-9]{6,12}\b`),
		Prefix: "MRN",
	},
	{
		Name:   "dob",
		Regex:  regexp.MustCompile(`(?i)\b(?:DOB|D\.O\.B\.|Date of Birth|Birth Date)[:\s]+(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b`),
		Prefix: "DOB",
	},
	{
		Name:   "bank_account",
		Regex:  regexp.MustCompile(`(?i)\b(?:Account|Acct)[:\s#]*\d{8,17}\b`),
		Prefix: "ACCOUNT",
	},
	{
		Name:   "routing_number",
		Regex:  regexp.MustCompile(`(?i)\b(?:Routing|ABA)[:\s#]*\d{9}\b`),
		Prefix: "ROUTING",
	},
	{
		Name:   "ip_address",
		Regex:  regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		Prefix: "IP",
	},
	{
		Name:   "address",
		Regex:  regexp.MustCompile(`(?i)\b\d+\s+[A-Za-z0-9\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b`),
		Prefix: "ADDR",
	},
}

var (
	piiPatternsMu sync.RWMutex
	piiPatterns   = append([]PIIPattern(nil), defaultPIIPatterns...)
)

// candidate holds one provisional match while collecting + deduplicating.
type candidate struct {
	start    int
	end      int
	original string
	pattern  PIIPattern
}

// RedactPII redacts PII from text, replacing matches with indexed tokens
// ([EMAIL_1], [EMAIL_2], ...) and returning a reversible redaction map.
//
//	r := shrike.RedactPII("Email john@acme.com")
//	// r.RedactedText == "Email [EMAIL_1]"
//	// r.Redactions[0].Original == "john@acme.com"
func RedactPII(text string) RedactionResult {
	piiPatternsMu.RLock()
	patterns := append([]PIIPattern(nil), piiPatterns...)
	piiPatternsMu.RUnlock()

	candidates := make([]candidate, 0, 8)
	for _, p := range patterns {
		for _, idx := range p.Regex.FindAllStringIndex(text, -1) {
			candidates = append(candidates, candidate{
				start:    idx[0],
				end:      idx[1],
				original: text[idx[0]:idx[1]],
				pattern:  p,
			})
		}
	}

	// Sort ascending by start position for dedup + token numbering.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].start < candidates[j].start
	})

	// Deduplicate overlapping matches (keep the earlier/first match).
	filtered := make([]candidate, 0, len(candidates))
	for _, c := range candidates {
		overlaps := false
		for _, existing := range filtered {
			if c.start < existing.end && c.end > existing.start {
				overlaps = true
				break
			}
		}
		if !overlaps {
			filtered = append(filtered, c)
		}
	}

	// Assign token numbers in document order, then build redactions in
	// document order and apply substitutions back-to-front to preserve offsets.
	counters := make(map[string]int, len(filtered))
	tokens := make([]string, len(filtered))
	for i, c := range filtered {
		counters[c.pattern.Prefix]++
		tokens[i] = fmt.Sprintf("[%s_%d]", c.pattern.Prefix, counters[c.pattern.Prefix])
	}

	redactedText := text
	for i := len(filtered) - 1; i >= 0; i-- {
		c := filtered[i]
		redactedText = redactedText[:c.start] + tokens[i] + redactedText[c.end:]
	}

	redactions := make([]RedactionEntry, len(filtered))
	for i, c := range filtered {
		redactions[i] = RedactionEntry{
			Token:    tokens[i],
			Original: c.original,
			Type:     c.pattern.Name,
			Position: c.start,
		}
	}

	return RedactionResult{
		RedactedText:   redactedText,
		Redactions:     redactions,
		PIIDetected:    len(redactions) > 0,
		RedactionCount: len(redactions),
	}
}

// RehydratePII restores indexed tokens in text back to their original PII
// values using the redaction map returned by RedactPII. All occurrences of
// each token are replaced (LLMs may repeat tokens in their output).
//
//	restored := shrike.RehydratePII(llmOutput, redacted.Redactions)
func RehydratePII(text string, redactions []RedactionEntry) string {
	result := text
	for _, entry := range redactions {
		result = strings.ReplaceAll(result, entry.Token, entry.Original)
	}
	return result
}

// GetRedactionSummary returns a count of redactions grouped by PII type
// (no raw PII values). Safe to log.
func GetRedactionSummary(redactions []RedactionEntry) map[string]int {
	summary := make(map[string]int)
	for _, entry := range redactions {
		summary[entry.Type]++
	}
	return summary
}

// UpdatePIIPatterns replaces the active PII pattern list (e.g. with a
// backend-fetched canonical set). Thread-safe.
func UpdatePIIPatterns(patterns []PIIPattern) {
	piiPatternsMu.Lock()
	piiPatterns = append([]PIIPattern(nil), patterns...)
	piiPatternsMu.Unlock()
}

// GetPIIPatternCount returns the current number of active PII patterns.
func GetPIIPatternCount() int {
	piiPatternsMu.RLock()
	defer piiPatternsMu.RUnlock()
	return len(piiPatterns)
}
