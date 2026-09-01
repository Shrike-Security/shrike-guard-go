# Changelog

## [v1.1.0] - 2026-08-31

### Added
- **Custom endpoint for the Anthropic and Gemini wrappers (`BaseURL`).** Both
  `anthropic.ClientOptions` and `gemini.ClientOptions` now accept a `BaseURL`
  that routes model calls to a compatible gateway or proxy — wired through
  `option.WithBaseURL` and `genai.HTTPOptions.BaseURL` respectively. This brings
  Anthropic and Gemini to parity with the OpenAI wrapper, which already accepted
  a custom endpoint via `OpenAIConfig.BaseURL`.
- **Documented local / self-hosted LLM governance.** New README section shows
  governing an OpenAI-compatible local runtime (Ollama, vLLM, LM Studio) by
  setting `OpenAIConfig.BaseURL`, plus the Anthropic and Gemini equivalents.

## [v1.0.1] - 2026-07-29

Security patch — bumps transitive dependencies to their fixed versions.

### Security
- Bump transitive dependencies to their fixed versions, clearing all `CRITICAL`/`HIGH` advisories flagged against v1.0.0 (all pulled in via the provider SDKs; the SDK itself does not use `ssh`/`grpc` directly):
  - `golang.org/x/crypto` v0.40.0 → v0.52.0 (`ssh`)
  - `golang.org/x/net` v0.41.0 → v0.55.0 (`net/html`)
  - `golang.org/x/text` v0.27.0 → v0.39.0 (`norm` infinite loop)
  - `google.golang.org/grpc` v1.66.2 → v1.82.1 (CVE-2026-33186)
  - `google.golang.org/protobuf` v1.34.2 → v1.36.11 (+ `x/sync`/`x/sys`)
- All versions match the Shrike backend, which already runs them.

### Changed
- **Minimum Go version is now 1.25** (required by the patched `x/crypto`), matching the Shrike backend toolchain.

## [v1.0.0] - 2026-07-29

First public release of the Go SDK. It ships full feature parity with the Shrike
TypeScript and Python SDKs (the 4.0.x contract line) — the same enforce contract,
response sanitization, and governance surface — as the Go module's initial stable
version.

The version number is intentionally independent of the other SDKs. Go's module
rules tie the major version to the import path (a `v2+` module must import as
`.../vN`), so the SDKs are aligned on the **wire contract** — which is what
claim-consistency verifies — not on the tag string.

### Provider wrappers

Each wrapper lives in its own subpackage, so a provider's dependency is only
pulled in when you import it.

- **`ShrikeOpenAI` (`openai/`)** — wraps `github.com/sashabaranov/go-openai`; scans user content before the request is sent.
- **`ShrikeAnthropic` (`anthropic/`)** — wraps `github.com/anthropics/anthropic-sdk-go`; scans before `Messages.New` and before streaming, refusing unsafe requests with a `*shrike.BlockedError`.
- **`ShrikeGemini` (`gemini/`)** — wraps `google.golang.org/genai` (the unified Google GenAI SDK); scans before `GenerateContent` and `GenerateContentStream`.

### Scanning & governance surface

- **Response sanitizer.** Scan responses strip internal detection attribution (policy IDs, matched patterns, layer/stage details, LLM reasoning) before returning — the SDK never surfaces detection methodology to callers. Confidence is returned as a bucketed level (`high`/`medium`/`low`), not a raw score.
- **Contract symmetry.** `ScanResult` carries the four-state governance fields — `Action` / `RefuseTier` / `Recovery` / `SessionState` — on both safe and refuse verdicts, matching the TypeScript and Python SDKs.
- **`scanner.IsBlocked(*ScanResult)`** — the single proceed-vs-refuse decision helper. Prefers the server `action`; unknown/future tiers fail closed. Every provider wrapper routes through it, so `warn` advises without refusing and `require_approval` refuses.
- Normalized `ThreatType`, derived `Severity`, and threat `Guidance` on block verdicts.
- **`Client.DeclareScope`** — declare an agent's tool scope (`POST /api/v1/agent/scope/declare`); later scans are enforced against it.
- **`shrike.SystemPrompt()`** + `shrike.SystemPromptVersion` — the canonical "Working with Shrike" system-prompt block, byte-for-byte identical to the TypeScript and Python SDKs.
- **`scanner.FormatBlockFeedback(*ScanResult)`** — renders a stable prompt-shape string (block/warn/approval prefix + reason, threat type, session risk, triggered patterns, recovery) to inject as the model's next system message.
- **`scanner.EvaluateRotation`** + `scanner.RotationThreshold` + `scanner.ModuleSessionID()` — pure session-rotation evaluator.
- **`pii` package** — client-side PII redaction: `Redact` / `Rehydrate` / `RedactionSummary` / `UpdatePatterns` / `PatternCount`, plus `SyncPatterns` to pull the backend's canonical (Presidio-derived) pattern set. PII never leaves the caller's process; the redactor ships a bootstrap regex set and syncs the canonical set on demand.
- **`Client.ScanA2AMessage`** and **`Client.ScanAgentCard`** — specialized scans for agent-to-agent messages and A2A AgentCard JSON.
- **`api.SandboxClient`** — quota-free sandbox scans (`POST /api/v1/sandbox/scan`), sanitized through the same path as production scans.

### Defaults

- **Fail-closed by default (`FailModeClosed`).** When the Shrike backend is unreachable, returns 4xx/5xx, or times out, the SDK blocks the request and returns a `*shrike.ScanError`. This matches the Zero Trust contract published on the Shrike platform — if the guard cannot evaluate the action, the action does not proceed. Opt into fail-open (availability over enforcement) with `scanner.WithFailMode(shrike.FailModeOpen)` at construction.

  A security SDK's default determines its trust model. A fail-open default lets traffic through during backend outages — precisely when adversarial pressure is highest — so fail-closed is the standard expectation for security-product SDKs (WAF, IDS, secrets scanners) and matches what the platform's customer-facing materials promise.

### Notes

- Scans POST to the enforce endpoints `/api/scan/enforce` and `/api/scan/enforce/specialized`, which return the governance surface above.
- **Error type names** are `shrike.ScanError` / `shrike.BlockedError` / `shrike.ConfigError` (not `Shrike*Error`). In Go the `shrike` package qualifier already namespaces them; a `Shrike`-prefix would be redundant "stutter" that Go linters flag. These are the idiomatic-Go equivalents of the TypeScript/Python `Shrike*Error` classes.
- **Minimum Go version is 1.24**, required by the Anthropic and Gemini provider SDKs.
