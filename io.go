package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

const provenance = "[peephole - automated security enforcement, not user input]"

var exitOnce sync.Once

type Event struct {
	HookEventName string          `json:"hook_event_name"`
	Event         string          `json:"event"` // Crush stdin uses "event", not hook_event_name
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
	Prompt        string          `json:"prompt"`
	Source        string          `json:"source"`
	Cwd           string          `json:"cwd"`
	FilePath      string          `json:"file_path"`
	SessionID     string          `json:"session_id"`
	LastMessage   string          `json:"last_assistant_message"`
	TopCommand    string          `json:"command"`
}

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
	if e.HookEventName == "" {
		e.HookEventName = e.Event
	}
	e.HookEventName = normalizeEvent(e.HookEventName)
	e.ToolName = normalizeTool(e.ToolName)
	if e.ToolName == "" && e.HookEventName == "PreToolUse" && e.TopCommand != "" && len(e.ToolInput) == 0 {
		e.ToolName = "Bash"
		e.ToolInput, _ = json.Marshal(map[string]string{"command": e.TopCommand})
	}
	return e
}

var canonicalEvents = map[string]string{
	"pretooluse": "PreToolUse", "beforetool": "PreToolUse", "beforetooluse": "PreToolUse",
	"beforetoolcall": "PreToolUse", "beforeshellexecution": "PreToolUse",
	"posttooluse": "PostToolUse", "aftertool": "PostToolUse", "aftertooluse": "PostToolUse",
	"sessionstart": "SessionStart", "subagentstart": "SubagentStart",
	"userpromptsubmit": "UserPromptSubmit", "stop": "Stop", "configchange": "ConfigChange",
}

var canonicalTools = map[string]string{
	"write": "Write", "write_file": "Write", "writefile": "Write", "create_file": "Write", "createfile": "Write",
	"write_to_file": "Write",
	"edit":          "Edit", "replace": "Edit", "str_replace": "Edit", "strreplace": "Edit", "str_replace_editor": "Edit",
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
		if t.NewString == "" {
			t.NewString = pick("newString", "new_str", "after", "file_text", "diff", "patch", "input")
		}
		if t.Content == "" {
			t.Content = pick("contents", "text")
		}
		if t.Command == "" {
			t.Command = pick("cmd")
		}
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

func (t ToolInput) newContent() string {
	out := t.Content + "\n" + t.NewString + "\n" + t.NewSource
	for _, ed := range t.Edits {
		out += "\n" + ed.NewString
	}
	if strings.TrimSpace(out) == "" && t.Command != "" {
		return t.Command
	}
	return out
}

func emitJSON(v any) {
	b, _ := json.Marshal(v)
	exitOnce.Do(func() {
		os.Stdout.Write(b)
		os.Exit(0)
	})
	select {}
}

var dialectExit2 bool

func emitPreDecision(decision, reason string) {
	if dialectExit2 {
		switch decision {
		case "deny":
			hardBlock(reason)
		case "ask":
			exitOnce.Do(func() {
				os.Stderr.WriteString(provenance + " REVIEW: " + reason + "\n")
				os.Exit(0)
			})
			select {}
		}
	}
	emitJSON(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       decision,
		"permissionDecisionReason": reason,
	}})
}

func emitPreDecisionInput(decision, reason string, updatedInput json.RawMessage) {
	if dialectExit2 {
		emitPreDecision(decision, reason)
	}
	emitJSON(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       decision,
		"permissionDecisionReason": reason,
		"updatedInput":             updatedInput,
	}})
}

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

func hardBlock(reason string) {
	exitOnce.Do(func() {
		os.Stderr.WriteString(provenance + " " + reason + "\n")
		os.Exit(2)
	})
	select {}
}
