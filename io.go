package main

import (
	"encoding/json"
	"os"
	"sync"
)

// Provenance so a model hardened against prompt injection recognizes the source
// of injected/deny text instead of treating it as unknown-actor input.
const provenance = "[peephole - automated security enforcement, not user input]"

// exitOnce makes decision-emission and the watchdog timeout mutually exclusive:
// the stdout write and process exit happen together inside Do, so a timeout can
// never fire after a decision has been partially written (which would turn an
// allow into a spurious exit-2 block).
var exitOnce sync.Once

// Event is the hook stdin payload (superset across events).
type Event struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"` // N7: ingested content (opt-in)
	Prompt        string          `json:"prompt"`
	Source        string          `json:"source"`
	Cwd           string          `json:"cwd"`
	SessionID     string          `json:"session_id"`
	LastMessage   string          `json:"last_assistant_message"`
}

// ToolInput unions the fields across Write/Edit/MultiEdit/NotebookEdit/Bash.
type ToolInput struct {
	FilePath     string `json:"file_path"`
	Content      string `json:"content"`
	NewString    string `json:"new_string"`
	Command      string `json:"command"`
	NotebookPath string `json:"notebook_path"`
	NewSource    string `json:"new_source"`
	Edits        []struct {
		NewString string `json:"new_string"`
	} `json:"edits"`
}

func readEvent() Event {
	var e Event
	dec := json.NewDecoder(os.Stdin)
	_ = dec.Decode(&e)
	return e
}

func (e Event) toolInput() ToolInput {
	var t ToolInput
	if len(e.ToolInput) > 0 {
		_ = json.Unmarshal(e.ToolInput, &t)
	}
	return t
}

func (t ToolInput) targetPath() string {
	if t.FilePath != "" {
		return t.FilePath
	}
	return t.NotebookPath
}

// newContent concatenates every string this tool would introduce.
func (t ToolInput) newContent() string {
	out := t.Content + "\n" + t.NewString + "\n" + t.NewSource
	for _, ed := range t.Edits {
		out += "\n" + ed.NewString
	}
	return out
}

// --- output emission. Exit 0 with structured JSON is the primary channel; exit
// 2 is the fail-closed hard block. We never exit 1 (a soft error the host
// silently permits -). Every emit goes through exitOnce. ----

func emitJSON(v any) {
	b, _ := json.Marshal(v)
	exitOnce.Do(func() {
		os.Stdout.Write(b)
		os.Exit(0)
	})
	select {} // unreachable: the process exited inside Do (or a timeout won the race)
}

// dialectExit2 selects the universal hook contract (reason on stderr + exit 2 on
// a block) instead of Claude Code's permissionDecision JSON. Every hook-based
// agent (Gemini CLI, Codex, Qwen, Crush, Goose, Cursor, ...) honors exit 2, so
// this one flag lets the same binary gate all of them. Set via `hook --exit2`.
var dialectExit2 bool

func emitPreDecision(decision, reason string) {
	if dialectExit2 {
		switch decision {
		case "deny":
			hardBlock(reason) // stderr + exit 2: the universal block signal
		case "ask":
			// exit-code hosts have no "ask"; surface it as a loud warning and allow.
			exitOnce.Do(func() {
				os.Stderr.WriteString(provenance + " REVIEW: " + reason + "\n")
				os.Exit(0)
			})
			select {}
		}
		// allow: fall through to the normal (empty) emit
	}
	emitJSON(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       decision,
		"permissionDecisionReason": reason,
	}})
}

// emitPreDecisionInput emits a decision that also proposes a modified tool input
// (the secure-default rewrite). The host shows it as ask-with-preview.
func emitPreDecisionInput(decision, reason string, updatedInput json.RawMessage) {
	if dialectExit2 {
		emitPreDecision(decision, reason) // exit-code hosts can't render a rewrite preview
	}
	emitJSON(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       decision,
		"permissionDecisionReason": reason,
		"updatedInput":             updatedInput,
	}})
}

// setDialect reads the output dialect from the hook subcommand arguments.
func setDialect(args []string) {
	for _, a := range args {
		if a == "--exit2" || a == "--dialect=exit2" {
			dialectExit2 = true
		}
	}
}

func injectContext(eventName, text string) {
	emitJSON(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":     eventName,
		"additionalContext": text,
	}})
}

func forceContinue(reason string) {
	emitJSON(map[string]any{"decision": "block", "reason": provenance + "\n" + reason})
}

func passthrough(systemMessage string) {
	out := map[string]any{}
	if systemMessage != "" {
		out["systemMessage"] = systemMessage
	}
	emitJSON(out)
}

// hardBlock is the fail-closed path: exit 2, stderr shown to the model.
func hardBlock(reason string) {
	exitOnce.Do(func() {
		os.Stderr.WriteString(provenance + " " + reason + "\n")
		os.Exit(2)
	})
	select {}
}
