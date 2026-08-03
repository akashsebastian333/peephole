package main

import (
	"encoding/json"
	"os"
	"strings"
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
	// Some hosts (Cursor beforeShellExecution) put the command at the TOP level of
	// the payload with no tool_name/tool_input; captured here to synthesize a Bash tool.
	TopCommand string `json:"command"`
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
	// Fold each non-Claude host's event/tool taxonomy onto Claude's, so the same
	// decision logic gates every hook-based agent. Escalation-only: Claude's own
	// names map to themselves, and an unknown name is left as-is (falls through to
	// passthrough exactly as before) - this can only make the gate handle MORE
	// events, never fewer.
	e.HookEventName = normalizeEvent(e.HookEventName)
	e.ToolName = normalizeTool(e.ToolName)
	// Cursor's beforeShellExecution (and similar) carry the command at the top
	// level with no tool_name/tool_input; synthesize a Bash tool so the write-path
	// gate still inspects it.
	if e.ToolName == "" && e.HookEventName == "PreToolUse" && e.TopCommand != "" && len(e.ToolInput) == 0 {
		e.ToolName = "Bash"
		e.ToolInput, _ = json.Marshal(map[string]string{"command": e.TopCommand})
	}
	return e
}

// canonicalEvents maps host-native pre/post-tool event names onto Claude's.
// Keyed lowercase so casing variants (Cursor's preToolUse) also fold.
var canonicalEvents = map[string]string{
	"pretooluse": "PreToolUse", "beforetool": "PreToolUse", "beforetooluse": "PreToolUse",
	"beforetoolcall": "PreToolUse", "beforeshellexecution": "PreToolUse",
	"posttooluse":    "PostToolUse", "aftertool": "PostToolUse", "aftertooluse": "PostToolUse",
	"sessionstart": "SessionStart", "subagentstart": "SubagentStart",
	"userpromptsubmit": "UserPromptSubmit", "stop": "Stop", "configchange": "ConfigChange",
}

// canonicalTools maps host-native tool names onto Claude's Write/Edit/Bash family
// so the write-path gate fires regardless of host. MCP tools (mcp__*) are left
// untouched for the dedicated MCP path.
var canonicalTools = map[string]string{
	"write": "Write", "write_file": "Write", "writefile": "Write", "create_file": "Write", "createfile": "Write",
	"write_to_file": "Write",
	"edit": "Edit", "replace": "Edit", "str_replace": "Edit", "strreplace": "Edit", "str_replace_editor": "Edit",
	"apply_patch": "Edit", "applypatch": "Edit", "multiedit": "MultiEdit", "notebookedit": "NotebookEdit",
	"replace_in_file": "Edit", "editor": "Edit", "edit_file": "Edit",
	"bash": "Bash", "shell": "Bash", "run_shell_command": "Bash", "runshellcommand": "Bash",
	"execute_command": "Bash", "executecommand": "Bash", "run_command": "Bash", "exec_command": "Bash",
}

func normalizeEvent(name string) string {
	if c, ok := canonicalEvents[strings.ToLower(name)]; ok {
		return c
	}
	return name
}

func normalizeTool(name string) string {
	if strings.HasPrefix(name, "mcp__") {
		return name
	}
	if c, ok := canonicalTools[strings.ToLower(name)]; ok {
		return c
	}
	return name
}

func (e Event) toolInput() ToolInput {
	var t ToolInput
	if len(e.ToolInput) == 0 {
		return t
	}
	_ = json.Unmarshal(e.ToolInput, &t)
	// Non-Claude hosts use camelCase / alternate keys for the same values (Go's
	// json is case-insensitive but does not bridge snake_case <-> camelCase). Fill
	// any empty canonical field from a documented alias so the path and edit text
	// still reach the scanner instead of the write being a silent no-op. (content
	// and command are already the shared key across every listed host.)
	var m map[string]json.RawMessage
	if json.Unmarshal(e.ToolInput, &m) == nil {
		pick := func(keys ...string) string {
			for _, k := range keys {
				if raw, ok := m[k]; ok {
					var s string
					if json.Unmarshal(raw, &s) == nil && s != "" {
						return s
					}
				}
			}
			return ""
		}
		if t.FilePath == "" {
			t.FilePath = pick("filePath", "path", "absolute_path", "file")
		}
		if t.NewString == "" { // edit / patch / diff replacement text across hosts
			t.NewString = pick("newString", "new_str", "after", "file_text", "diff", "patch", "input")
		}
		if t.Content == "" {
			t.Content = pick("contents", "text")
		}
		if t.Command == "" {
			t.Command = pick("cmd")
		}
		// Belt-and-suspenders: if a write-family tool still yielded no scannable
		// content (an unmapped field name), scan every string value in the payload
		// rather than let the write pass uninspected.
		if t.Content == "" && t.NewString == "" && t.NewSource == "" && t.Command == "" && len(t.Edits) == 0 {
			t.Content = stringValues(e.ToolInput)
		}
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
