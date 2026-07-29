// Package shrike is the Go SDK for the Shrike platform — AI governance for
// every AI interaction.
//
// Shrike evaluates every prompt against policy before it reaches the model,
// deciding in real time what is allowed, blocked, or escalated. The same
// backend cognitive pipeline that governs a customer-facing chatbot also
// governs autonomous, tool-using agents.
//
// # Drop-in provider wrappers
//
// Wrap your existing LLM client and every prompt is scanned before it is sent.
// Each wrapper lives in its own subpackage so provider dependencies are only
// pulled in when you import the one you use:
//
//   - github.com/shrike-security/shrike-guard-go/openai    (ShrikeOpenAI)
//   - github.com/shrike-security/shrike-guard-go/anthropic (ShrikeAnthropic)
//   - github.com/shrike-security/shrike-guard-go/gemini    (ShrikeGemini)
//
// A minimal OpenAI example:
//
//	client, err := shrikeopenai.NewClient(shrikeopenai.ClientOptions{
//	    OpenAIAPIKey: os.Getenv("OPENAI_API_KEY"),
//	    ShrikeAPIKey: os.Getenv("SHRIKE_API_KEY"),
//	})
//	resp, err := client.CreateChatCompletion(ctx, req) // scanned before send
//
// # Fail-closed by default
//
// When the Shrike backend cannot decide (timeout, network error, backend 5xx),
// the SDK blocks the request and returns a *ScanError — the Zero Trust posture.
// Opt into fail-open only when availability must outrank enforcement, via
// scanner.WithFailMode(shrike.FailModeOpen).
//
// # Other packages
//
//   - scanner — the low-level scan client (Scan, ScanSQL, ScanFile,
//     DeclareScope, ScanA2AMessage, ScanAgentCard) plus IsBlocked, the single
//     proceed-vs-refuse decision helper.
//   - pii — client-side PII redaction and rehydration; PII never leaves the
//     caller's process.
//   - api — the quota-free sandbox scan client.
//
// SystemPrompt returns the canonical "Working with Shrike" system-prompt block,
// byte-for-byte identical across the Go, TypeScript, and Python SDKs.
package shrike
