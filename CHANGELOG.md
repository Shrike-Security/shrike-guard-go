# Changelog

## [v1.3.0] - 2026-10-01

### Fixed
- **A locked session is no longer offered a new session id.** `EvaluateRotation`
  returned a rotation record carrying a freshly minted id on a `session_locked`
  verdict. A lock means the session is finished, so it now returns a record with
  both rotation flags false, `Reason` set to `session_locked`, and no new id to
  adopt. Recovery from a lock is self-release under a live declared scope, or an
  operator.

### Added
- `SessionRotation.IsLocked()` reports a lock without parsing `Reason`, and
  `SessionRotation.SessionID()` returns the id to use next, with `ok` false
  under a lock. Go collapses the three wire shapes into one struct, so branch on
  these rather than on the string.

## [v1.2.0] - 2026-09-10

### Added
- **Act-plane scanning: every channel the backend scans is now reachable from
  the SDK.** The backend has scanned eight specialized content types since the
  act plane shipped; this SDK exposed four. `ScanCommand` — the highest-volume
  surface, the one an agent hits before every shell-out — had no method at all,
  so the only way to reach it was to hand-roll an HTTP call. New on `Client`:
  - `ScanCommand(ctx, command, cwd)` — shell commands, screened before `exec`.
    Commands are decomposed server-side, so SQL passed to `psql -c`, `mysql -e`
    or a heredoc is scanned as SQL rather than as opaque shell text.
  - `ScanWebSearch(ctx, query)` — search queries that acquire attack tooling,
    credentials, or evasion tradecraft.
  - `ScanRagContext(ctx, chunks, query)` — retrieved context, the standard
    carrier for indirect prompt injection. Chunks are serialized as a JSON
    array so the backend can split them apart again; joining them would lose
    the boundary an injection usually sits on.
  - `ScanMCPSchema(ctx, name, description, inputSchema)` — a single MCP tool
    definition, for tool poisoning in a `tools/list` response. Its own endpoint
    and detector, screened once at registration rather than per call.
- **`ContentOrigin` on `ScanResult`.** Every verdict now says where the scanned
  content came from: `human_prompt`, `agent_output`, `agent_action` or
  `third_party`. This answers the question a verdict alone cannot — was that my
  prompt, or the agent acting on its own — which decides who a refusal message
  is addressed to. `AttributableToOperator(origin)` is the helper; it is true
  only for `human_prompt`. Unknown content types resolve to `agent_action`,
  never to `human_prompt`.
- **Act-plane parity and wire-shape tests** (`scanner/actplane_test.go`). The
  parity half iterates the canonical channel list and fails when a channel has
  no method. The transport half asserts the endpoint, the `content_type`, the
  optional arguments that must reach the payload, and that the scan auth header
  is `Authorization`/`X-Shrike-API-Key` and never `X-API-Key`. Contract-symmetric
  with the TypeScript and Python suites of the same name.

- **Per-request session identity — `WithSession`, `WithAgentID` and
  `ForSession`.** Session identity is the key the backend accumulates multi-turn
  risk against, so it has to mean one unit of work: one agent run, one
  conversation, one user's request. It defaults to a process-wide id, which
  suits a CLI or a worker but not a server serving many end users, where every
  user would share one risk score and one user's refusal would count against
  the next user's action. `ForSession` returns a view sharing the parent's HTTP client,
  circuit breaker and cache, so deriving one per request is cheap:

  ```go
  guard := scanner.NewClient(key)                        // once, at startup

  func handle(w http.ResponseWriter, r *http.Request) {  // per request
      scoped := guard.ForSession(sessionIDFor(r))
      verdict, err := scoped.ScanCommand(r.Context(), cmd, "")
  }
  ```

  Sharing the breaker is deliberate: breaker state is a property of the backend,
  not of a session, and a per-request breaker would never accumulate enough
  failures to open. The process-wide default is unchanged when nothing is
  supplied, so single-agent callers keep multi-turn correlation; the SDK now
  logs once when it is in force. Silence that with
  `SHRIKE_SUPPRESS_SESSION_WARNING=1`.

### Fixed
- **`content_origin` was computed by the backend and dropped before the caller.**
  `SanitizeScanResponse` is an allow-list, and the field was never added to
  `preservedGovernanceFields` nor assigned, so it was serialized by the server
  and stripped one layer before the application. Same defect as the one fixed
  in the TypeScript and Python SDKs in 4.1.0.
- **Session identity could not be configured.** Every scan in a process used one
  generated session id, so a server scanning on behalf of more than one person
  placed all of them in one session. See `WithSession` / `ForSession` above.

### Changed
- **Content-hash caching is now off by default.** Previously `NewClient`
  enabled a 5-minute cache keyed on the content alone. Because the key carried
  no session identity, a verdict shaped by one session's state could be served
  to another session, or to the same session after its state had changed,
  including an `allow` cached before a quarantine and served after it. A client
  cannot see server-side session state, so it cannot safely cache a verdict
  shaped by it, and the scan is an enforcement point rather than an advisory
  check. Every scan now reaches the backend unless caching is requested.

  Opt back in with `WithCache(ttl, maxSize)` where a stale allow is acceptable,
  such as a single-tenant advisory check or a batch pass over static content.
  `WithoutCache()` still works and is now only needed to undo an earlier
  `WithCache` in the same option list. Note that a non-positive TTL or size
  means "use the default", so `WithCache(0, 0)` enables a 5-minute cache rather
  than disabling one.

  **Upgrading:** callers who relied on the implicit cache will make more backend
  calls. This is the intended direction; add `WithCache` explicitly if the
  trade-off suits your deployment. The TypeScript and Python SDKs have no
  equivalent cache, so this also restores parity across the three.

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
- **`pii` package** — client-side PII redaction: `Redact` / `Rehydrate` / `RedactionSummary` / `UpdatePatterns` / `PatternCount`, plus `SyncPatterns` to pull the backend's canonical pattern set. PII never leaves the caller's process; the redactor ships a bootstrap regex set and syncs the canonical set on demand.
- **`Client.ScanA2AMessage`** and **`Client.ScanAgentCard`** — specialized scans for agent-to-agent messages and A2A AgentCard JSON.
- **`api.SandboxClient`** — quota-free sandbox scans (`POST /api/v1/sandbox/scan`), sanitized through the same path as production scans.

### Defaults

- **Fail-closed by default (`FailModeClosed`).** When the Shrike backend is unreachable, returns 4xx/5xx, or times out, the SDK blocks the request and returns a `*shrike.ScanError`. This matches the Zero Trust contract published on the Shrike platform — if the guard cannot evaluate the action, the action does not proceed. Opt into fail-open (availability over enforcement) with `scanner.WithFailMode(shrike.FailModeOpen)` at construction.

  A security SDK's default determines its trust model. A fail-open default lets traffic through during backend outages — precisely when adversarial pressure is highest — so fail-closed is the standard expectation for security-product SDKs (WAF, IDS, secrets scanners) and matches what the platform's customer-facing materials promise.

### Notes

- Scans POST to the enforce endpoints `/api/scan/enforce` and `/api/scan/enforce/specialized`, which return the governance surface above.
- **Error type names** are `shrike.ScanError` / `shrike.BlockedError` / `shrike.ConfigError` (not `Shrike*Error`). In Go the `shrike` package qualifier already namespaces them; a `Shrike`-prefix would be redundant "stutter" that Go linters flag. These are the idiomatic-Go equivalents of the TypeScript/Python `Shrike*Error` classes.
- **Minimum Go version is 1.24**, required by the Anthropic and Gemini provider SDKs.
