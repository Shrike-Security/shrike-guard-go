# Shrike Guard (Go)

[![Go Reference](https://pkg.go.dev/badge/github.com/shrike-security/shrike-guard-go.svg)](https://pkg.go.dev/github.com/shrike-security/shrike-guard-go)
[![Go 1.25+](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://go.dev/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is the Go SDK for the [Shrike](https://shrikesecurity.com) platform — AI governance for every AI interaction. It wraps OpenAI, Anthropic (Claude), and Google Gemini clients to automatically evaluate every prompt against policy before it reaches the LLM. Whether you're governing a customer-facing chatbot, securing developer AI tools, or managing autonomous agent actions — the same 9-layer cognitive pipeline evaluates every interaction.

## Features

- **Drop-in wrappers** for the OpenAI, Anthropic, and Gemini Go clients
- **Automatic prompt scanning** for:
  - Prompt injection attacks
  - PII / sensitive-data leakage
  - Jailbreak attempts
  - SQL injection
  - Path traversal
- **Fail-closed by default** (Zero Trust posture); opt into fail-open explicitly when availability outranks enforcement
- **Per-provider subpackages**: import `.../openai`, `.../anthropic`, or `.../gemini` and only that provider's dependency is pulled in
- **Client-side PII redaction**: redact before the prompt leaves your process, rehydrate the model's response afterward
- **Idiomatic errors**: `errors.As` against `*shrike.BlockedError` and `*shrike.ScanError`

## What Shrike Detects

Shrike's 9-layer cognitive pipeline includes sensitive-data detection aligned to 5 major regulatory frameworks:

| Framework | Coverage |
|-----------|----------|
| **GDPR** | EU personal data — names, addresses, national IDs |
| **HIPAA** | Protected health information (PHI) |
| **ISO 27001** | Information security — passwords, tokens, certificates |
| **SOC 2** | Secrets, credentials, API keys, cloud tokens |
| **NIST** | AI risk management (IR 8596), cybersecurity framework (CSF 2.0) |

Detection coverage is not a certification claim — see [shrikesecurity.com/compliance](https://shrikesecurity.com/compliance) for our current certification status. Plus built-in detection for prompt injection, jailbreaks, social engineering, and dangerous requests.

### Tiers

Detection depth depends on your tier. All tiers get the same SDK wrappers — tiers control which backend layers run.

| | Anonymous | Community | Pro | Enterprise |
|---|---|---|---|---|
| Detection Layers | L1-L5 | L1-L5 | L1-L9 (full) | L1-L9 (full) |
| API Key | Not needed | Free signup | Paid | Paid |
| Rate Limit | — | 10/min | 100/min | 1,000/min |
| Scans/month | — | 1,000 | 25,000 | 1,000,000 |

**Anonymous** (no API key): pattern-based detection (L1-L5). **Community** (free): same L1-L5 detection with a dashboard and higher limits; LLM-powered semantic analysis (L6-L9) is Pro+. Register at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) — instant, no credit card.

## Installation

```bash
go get github.com/shrike-security/shrike-guard-go@v1.0.1
```

Requires Go 1.25+. Provider dependencies are pulled in only when you import the matching subpackage.

## Quick Start

### OpenAI

```go
import (
	"github.com/sashabaranov/go-openai"
	shrikeopenai "github.com/shrike-security/shrike-guard-go/openai"
)

client, err := shrikeopenai.NewClient(shrikeopenai.ClientOptions{
	OpenAIAPIKey: "sk-...",     // your OpenAI API key
	ShrikeAPIKey: "shrike-...", // your Shrike API key
})
if err != nil {
	log.Fatal(err)
}

// Use it like the normal go-openai client — every prompt is scanned first.
resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
	Model: openai.GPT4,
	Messages: []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleUser, Content: "Hello, how are you?"},
	},
})
```

### Anthropic (Claude)

```go
import (
	anthropicsdk "github.com/anthropics/anthropic-sdk-go"
	shrikeanthropic "github.com/shrike-security/shrike-guard-go/anthropic"
)

client, err := shrikeanthropic.NewClient(shrikeanthropic.ClientOptions{
	AnthropicAPIKey: "sk-ant-...",
	ShrikeAPIKey:    "shrike-...",
})
if err != nil {
	log.Fatal(err)
}

// Params are the underlying anthropic-sdk-go MessageNewParams; the user
// content is scanned before Messages.New is called.
msg, err := client.CreateMessage(ctx, anthropicsdk.MessageNewParams{
	Model:     anthropicsdk.ModelClaudeSonnet4_5,
	MaxTokens: 1024,
	Messages: []anthropicsdk.MessageParam{
		anthropicsdk.NewUserMessage(anthropicsdk.NewTextBlock("Hello!")),
	},
})
```

### Google Gemini

```go
import (
	"google.golang.org/genai"
	shrikegemini "github.com/shrike-security/shrike-guard-go/gemini"
)

client, err := shrikegemini.NewClient(ctx, shrikegemini.ClientOptions{
	GeminiAPIKey: "AIza...",
	ShrikeAPIKey: "shrike-...",
})
if err != nil {
	log.Fatal(err)
}

resp, err := client.GenerateContent(ctx, "gemini-2.0-flash",
	[]*genai.Content{genai.NewContentFromText("Hello!", genai.RoleUser)}, nil)
```

Streaming is supported too: `CreateMessageStream` and `GenerateContentStream` scan the user content **before** the first token is produced, returning a `*shrike.BlockedError` if the request is refused.

## Configuration

Every wrapper's `ClientOptions` accepts the same Shrike knobs:

```go
shrikeopenai.ClientOptions{
	OpenAIAPIKey:   "sk-...",
	ShrikeAPIKey:   "shrike-...",
	ShrikeEndpoint: "https://your-shrike-instance.com", // self-hosted / VPC (optional)
	FailMode:       shrike.FailModeClosed,              // default; see below
	ScanTimeout:    5000,                               // milliseconds (default 10000)
}
```

### Fail Modes

Choose how the SDK behaves when the scan itself fails (timeout, network error, backend 5xx):

- **`shrike.FailModeClosed`** (default) — block the request and return a `*shrike.ScanError`. Best for production security workloads: if the Shrike backend is down, traffic does not flow through unguarded.
- **`shrike.FailModeOpen`** — allow the request to proceed. Best for non-production experiments or internal tools where availability must outrank enforcement. Trades the guard's enforcement promise for uptime.

## SQL and File Scanning

Each provider wrapper also exposes standalone scanning:

```go
sqlResult, err := client.ScanSQL(ctx, "SELECT * FROM users WHERE id = 1", "production_db", false)
if !sqlResult.Safe {
	log.Printf("SQL threat: %s", sqlResult.Reason)
}

fileResult, err := client.ScanFile(ctx, "/app/data/report.csv", "") // optional content arg
```

## Client-Side PII Redaction

Redact PII **before** the prompt leaves your process, then rehydrate the model's response. Raw PII is never sent to Shrike or the downstream LLM.

```go
import "github.com/shrike-security/shrike-guard-go/pii"

r := pii.Redact("Email john@acme.com about invoice 12345")
// r.RedactedText == "Email [EMAIL_1] about invoice 12345"

// ... send r.RedactedText to the LLM ...

final := pii.Rehydrate(llmOutput, r.Redactions) // tokens → original values
```

`pii.SyncPatterns` optionally pulls Shrike's canonical server-side pattern set to replace the bootstrap patterns; it never fails your request (returns `(false, err)` on a soft failure and keeps the current patterns).

## Error Handling

```go
import (
	"errors"
	shrike "github.com/shrike-security/shrike-guard-go"
)

resp, err := client.CreateChatCompletion(ctx, req)
if err != nil {
	var blocked *shrike.BlockedError
	if errors.As(err, &blocked) {
		log.Printf("blocked: %s (threat=%s, confidence=%s)",
			blocked.Message, blocked.ThreatType, blocked.Confidence)
		return
	}
	var scanErr *shrike.ScanError
	if errors.As(err, &scanErr) {
		// only returned under FailModeClosed when the scan couldn't complete
		log.Printf("scan error: %s", scanErr.Message)
		return
	}
	log.Fatal(err) // an underlying provider error
}
```

`Confidence` is a bucketed level (`high` / `medium` / `low`), not a raw score — the SDK never surfaces exact detection thresholds.

## Low-Level Scan Client

For direct control, use the scanner client without a provider wrapper:

```go
import "github.com/shrike-security/shrike-guard-go/scanner"

sc := scanner.NewClient("shrike-...")
res, err := sc.Scan(ctx, "Check this prompt for threats")
if scanner.IsBlocked(res) {
	log.Printf("threat detected: %s", res.Reason)
}
```

`scanner.IsBlocked` is the single proceed-vs-refuse decision helper: it honors the server `action` (`allow`/`warn` proceed, `block`/`require_approval` refuse) and fails closed on unknown verdicts. The scanner also provides `DeclareScope`, `ScanA2AMessage`, and `ScanAgentCard` for agent-to-agent governance.

## System Prompt

Inject the canonical "Working with Shrike" guidance into your agent's system prompt — byte-for-byte identical across the Go, TypeScript, and Python SDKs:

```go
prompt := shrike.SystemPrompt() // shrike.SystemPromptVersion identifies the block
```

## Compatibility

- **Go**: 1.25+
- **Provider SDKs**:
  - OpenAI — `github.com/sashabaranov/go-openai`
  - Anthropic — `github.com/anthropics/anthropic-sdk-go` v1
  - Google Gemini — `google.golang.org/genai` v1 (the unified Google GenAI SDK)

## Other Integration Surfaces

Shrike Guard is one of several ways to integrate with the Shrike platform:

- **MCP Server** — `npx shrike-mcp` ([GitHub](https://github.com/Shrike-Security/shrike-mcp))
- **TypeScript SDK** — `npm install shrike-guard` ([GitHub](https://github.com/Shrike-Security/shrike-guard-js))
- **Python SDK** — `pip install shrike-guard` ([GitHub](https://github.com/Shrike-Security/shrike-guard-python))
- **REST API** — `POST https://api.shrikesecurity.com/agent/scan`
- **LLM Gateway** — change one URL, scan everything
- **Dashboard** — [shrikesecurity.com](https://shrikesecurity.com)

## License

Apache 2.0 — see [LICENSE](./LICENSE).

## Support

- [Shrike](https://shrikesecurity.com) — sign up, dashboard, docs
- [Documentation](https://shrikesecurity.com/docs) — quick start, API reference
- [Go Reference](https://pkg.go.dev/github.com/shrike-security/shrike-guard-go) — full API docs
