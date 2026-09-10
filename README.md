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
go get github.com/shrike-security/shrike-guard-go@latest
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

### Local and self-hosted LLMs

Shrike governs the model you point it at — it does not have to be a hosted
frontier API. Local runtimes like [Ollama](https://ollama.com),
[vLLM](https://docs.vllm.ai), and LM Studio expose an OpenAI-compatible
endpoint, so the OpenAI wrapper guards them via a custom `OpenAIConfig`:

```go
cfg := openai.DefaultConfig("ollama")        // local servers ignore the token
cfg.BaseURL = "http://localhost:11434/v1"    // your local/self-hosted endpoint

client, err := shrikeopenai.NewClient(shrikeopenai.ClientOptions{
	OpenAIConfig: &cfg,
	ShrikeAPIKey: "shrike-...",               // governance still runs server-side
})
```

The Anthropic and Gemini wrappers take a `BaseURL` for compatible gateways
(added in v1.1.0):

```go
shrikeanthropic.ClientOptions{AnthropicAPIKey: "…", ShrikeAPIKey: "shrike-...", BaseURL: "https://anthropic-gateway.example"}
shrikegemini.ClientOptions{GeminiAPIKey: "…", ShrikeAPIKey: "shrike-...", BaseURL: "https://gemini-gateway.example"}
```

The prompt still leaves your process to reach the Shrike backend for scanning;
the *model call* stays on your local/self-hosted endpoint.

### Fail Modes

Choose how the SDK behaves when the scan itself fails (timeout, network error, backend 5xx):

- **`shrike.FailModeClosed`** (default) — block the request and return a `*shrike.ScanError`. Best for production security workloads: if the Shrike backend is down, traffic does not flow through unguarded.
- **`shrike.FailModeOpen`** — allow the request to proceed. Best for non-production experiments or internal tools where availability must outrank enforcement. Trades the guard's enforcement promise for uptime.

### Sessions: one per unit of work, not one per process

Shrike correlates risk across a session. After a refusal, later actions in the
same session are held until the session recovers. That is the multi-turn
defence, and it means the session id has to mean one unit of work: one agent
run, one conversation, one user's request.

By default the SDK scans under one id for the whole process. That suits a CLI,
a worker, or a single agent. It does not suit a server that scans on behalf of
many end users, because every user then shares one risk score, and one user's
refusal counts against the next user's action.

Build one client at startup and derive a per-request view from it. The view
shares the HTTP client, circuit breaker and cache, so it costs nothing to make
one per request:

```go
guard := scanner.NewClient(key)                        // once, at startup

func handle(w http.ResponseWriter, r *http.Request) {  // per request
    scoped := guard.ForSession(sessionIDFor(r))
    verdict, err := scoped.ScanCommand(r.Context(), cmd, "")
    if err != nil || verdict.RefuseTier != "allow" {
        ...
    }
}
```

Or pin the identity at construction when one client serves one unit of work:

```go
client := scanner.NewClient(key, scanner.WithSession("job-42"), scanner.WithAgentID("ingest"))
```

`WithAgentID` is separate on purpose: it names *which agent* a scope is
enforced against and who an incident is attributed to. Set it when one process
drives several distinct agents.

The SDK logs once per process when it is scanning under the shared default.
Set `SHRIKE_SUPPRESS_SESSION_WARNING=1` to silence it once you have decided
the default is what you want.

### The content cache and sessions

Content-hash caching is off by default, so every scan reaches the backend and
no verdict is reused. That is the right default for an enforcement point: a
cache key built from content alone carries no session identity, so a cached
verdict can outlive the session state that produced it, and an `allow` stored
before a quarantine would be served after it.

Opt in where a stale allow is acceptable, such as a single-tenant advisory
check or a batch pass over static content:

```go
guard := scanner.NewClient(key, scanner.WithCache(5*time.Minute, 1000))
```

A non-positive TTL or size means "use the default", so `WithCache(0, 0)`
enables a 5-minute cache rather than disabling one. `WithoutCache()` remains
available to undo a `WithCache` passed earlier in the same option list.

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

`scanner.IsBlocked` is the single proceed-vs-refuse decision helper: it honors the server `action` (`allow`/`warn` proceed, `block`/`require_approval` refuse) and fails closed on unknown verdicts.

## Scanning agent actions (shell commands, SQL, web search, RAG, MCP tools)

Scanning the prompt protects the model. It does not protect the shell. An agent
that was never told anything malicious can still be talked into running
`curl … | sh` by a poisoned README, and the prompt scan has no view of that.

`scanner.Client` exposes a method per action channel. Call the one that matches
what the agent is about to do, before it does it:

| Channel | Method | Screens for |
|---|---|---|
| Shell command | `ScanCommand(ctx, cmd, cwd)` | destructive commands, data exfiltration, credential dumps, embedded SQL injection |
| SQL query | `ScanSQL(ctx, query, db, allowDestructive)` | SQL injection, unauthorized destructive statements |
| File path | `ScanFile(ctx, path, "")` | path traversal, writes outside the working tree |
| File content | `ScanFile(ctx, path, content)` | secrets, credentials, PII before they land on disk |
| Web search | `ScanWebSearch(ctx, query)` | searches that acquire attack tooling, credentials, or evasion tradecraft |
| RAG context | `ScanRagContext(ctx, chunks, query)` | indirect prompt injection in retrieved documents |
| Agent message | `ScanA2AMessage(ctx, msg, opts)` | instructions smuggled between agents |
| Agent card | `ScanAgentCard(ctx, card, verifySig)` | capability misrepresentation in A2A discovery |
| MCP tool schema | `ScanMCPSchema(ctx, name, desc, schema)` | tool poisoning in `tools/list` responses |

```go
client := scanner.NewClient(os.Getenv("SHRIKE_API_KEY"))

// Before shelling out
res, err := client.ScanCommand(ctx, `psql -c "SELECT * FROM users"`, "/srv/app")
if err != nil {
	log.Fatal(err) // fail closed
}
if scanner.IsBlocked(res) {
	return fmt.Errorf("refused: %s", res.Reason)
}

// Before searching the web
res, _ = client.ScanWebSearch(ctx, "sql injection prevention owasp")

// Screen an MCP tool before registering it — tool poisoning needs no execution
res, _ = client.ScanMCPSchema(ctx, tool.Name, tool.Description, tool.InputSchema)
```

A shell command is not one thing. `ScanCommand` sends it to a backend that
decomposes it, so SQL passed to `psql -c`, `mysql -e`, or a heredoc is scanned
as SQL rather than as an opaque string of shell text.

`DeclareScope` binds an agent to a declared operating scope, after which every
scan for that `agent_id` is enforced against it server-side.

### Who is answerable: `ContentOrigin`

Every verdict carries `ContentOrigin`, which says where the scanned content came
from. It answers the question a verdict alone cannot: *was that my prompt, or
the agent acting on its own?*

| Value | Meaning |
|---|---|
| `human_prompt` | the operator typed it |
| `agent_output` | the model generated it |
| `agent_action` | the agent is about to do it (every act-plane channel) |
| `third_party` | it arrived from outside: a tool result, a retrieved document, a peer agent |

```go
res, _ := client.ScanRagContext(ctx, chunks, userQuery)

if scanner.IsBlocked(res) {
	if scanner.AttributableToOperator(res.ContentOrigin) {
		showUser("Your request was blocked: " + res.Reason)
	} else {
		// The agent poisoned its own context. Telling the user "your request
		// was blocked" would be both wrong and unhelpful.
		log.Printf("agent-side refusal: %s", res.Reason)
	}
}
```

Unknown content types resolve to `agent_action`, never to `human_prompt`:
attributing an unattributable action to the operator is the one error that is
never safe to make by default.

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
