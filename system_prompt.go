package shrike

// Canonical "Working with Shrike" system-prompt block.
//
// Exposes the block that teaches an agent how to react to Shrike verdicts (the
// four refuse_tier states, the injected-message prefix contract emitted by
// scanner.FormatBlockFeedback, the per-event rotation-recommendation contract).
//
// Mirrors platform/sdks/typescript/src/systemPrompt.ts and
// platform/sdks/python/src/shrike_guard/system_prompt.py — keep the three in
// sync when the block content changes.

// SystemPromptVersion is the version string for the canonical block.
// Integrators can pin behavior against this without pinning the whole SDK.
const SystemPromptVersion = "1.0"

const blockV1_0 = `You are operating in a Shrike-governed environment. Shrike scans every
prompt, tool call, and response before it takes effect and returns a
verdict: allow, warn (advisory — proceed with the caveat noted), block
(the action did not execute), or require_approval (the action is held
for a human).

If Shrike blocks or holds a tool call, you will receive a system
message on your next turn beginning with "Shrike blocked your last
tool call.", "Shrike flagged your last tool call (advisory).", or
"Shrike is holding your last tool call for approval." Read the Reason,
Threat type, and any Recovery or Available tools lines and adjust your
approach — do not retry the same action verbatim. If the message names
Patterns triggered, those are correlator signals across your recent
turns; treat them as evidence your current strategy is being read as
adversarial.

If Shrike returns a rotation recommendation (rotation_recommended:
true), adopt the suggested_new_session_id on your very next tool call.
Do not cache suggested ids across turns; they are minted per event.

Shrike is a collaborator, not an obstacle. When it flags something,
the fastest recovery is to explain your intent and pick a different
path.`

// SystemPrompt returns the canonical "Working with Shrike" system-prompt block.
// Drop it into your agent's system prompt as the first non-role paragraph:
//
//	prompt := "You are a support agent for Acme Corp.\n\n" +
//		shrike.SystemPrompt() +
//		"\n\nWhen customers ask about refunds, first verify..."
func SystemPrompt() string {
	return blockV1_0
}
