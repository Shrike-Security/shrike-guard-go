package shrike

import (
	"strings"
	"testing"
)

func TestSystemPrompt(t *testing.T) {
	p := SystemPrompt()
	if p == "" {
		t.Fatal("system prompt is empty")
	}
	for _, want := range []string{
		"Shrike-governed environment",
		"allow, warn",
		"require_approval",
		"Shrike blocked your last", // wraps across a line break in the block
		"rotation_recommended",
		"collaborator, not an obstacle",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("system prompt missing %q", want)
		}
	}
	if strings.HasSuffix(p, "\n") {
		t.Error("system prompt should not have a trailing newline")
	}
}

func TestSystemPromptVersion(t *testing.T) {
	if SystemPromptVersion != "1.0" {
		t.Errorf("SystemPromptVersion = %q, want 1.0", SystemPromptVersion)
	}
}
