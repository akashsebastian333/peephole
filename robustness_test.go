package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Robustness: peephole must never crash, hang, or exit 1 on hostile or malformed
// input, and must always finish well inside the hook budget. A security tool
// that breaks the developer's workflow is worse than no tool.
func TestRobustnessHostileInput(t *testing.T) {
	p := newProject(t, "strict")
	huge := strings.Repeat("a = 1\n", 200000)                    // ~1.2MB
	longLine := strings.Repeat("x", 500000)                      // one 500k line
	redos := "\"" + strings.Repeat("a", 5000) + "!"              // pathological for a backtracking engine (RE2 is linear)
	binary := string([]byte{0x00, 0x01, 0xff, 0xfe, 0x89, 0x50}) // non-UTF8 bytes

	cases := []struct {
		name  string
		stdin string
	}{
		{"empty", ""},
		{"whitespace", "   \n\t "},
		{"not-json", "this is not json at all {{{"},
		{"truncated-json", `{"hook_event_name":"PreToolUse","tool_`},
		{"null-fields", `{"hook_event_name":null,"tool_name":null,"tool_input":null,"cwd":null}`},
		{"missing-all", `{}`},
		{"unknown-event", `{"hook_event_name":"Nonsense","cwd":"` + p + `"}`},
		{"empty-toolinput", `{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"` + p + `","tool_input":{}}`},
		{"huge-content", mustJSON(writeEvent(p, huge))},
		{"long-single-line", mustJSON(writeEvent(p, longLine))},
		{"redos-attempt", mustJSON(writeEvent(p, redos))},
		{"binary-content", mustJSON(writeEvent(p, binary))},
		{"unicode-content", mustJSON(writeEvent(p, "emoji \U0001F512 and ‮ rtl and а cyrillic"))},
		{"deeply-nested", `{"hook_event_name":"PreToolUse","tool_name":"mcp__x","cwd":"` + p + `","tool_input":` + nest(200) + `}`},
		{"array-toolinput", `{"hook_event_name":"PreToolUse","tool_name":"Write","cwd":"` + p + `","tool_input":[1,2,3]}`},
		{"bash-empty-cmd", `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"` + p + `","tool_input":{"command":""}}`},
		{"bash-huge-cmd", mustJSON(bashEvent(p, strings.Repeat("echo hi | ", 50000)))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			cmd := exec.Command(testBin, "hook")
			cmd.Stdin = strings.NewReader(c.stdin)
			out, err := cmd.Output()
			// exit code must be 0 or 2, never 1 (host silently permits 1)
			if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				t.Fatalf("exited 1 on %q input", c.name)
			}
			// must finish fast (well under the 2s watchdog)
			if d := time.Since(start); d > time.Second {
				t.Fatalf("took %v on %q - possible hang", d, c.name)
			}
			// stdout must be empty or valid JSON (never garbage)
			if len(out) > 0 {
				var v any
				if json.Unmarshal(out, &v) != nil {
					t.Fatalf("emitted non-JSON on %q: %q", c.name, out)
				}
			}
		})
	}
}

func writeEvent(p, content string) map[string]any {
	return map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": p,
		"tool_input": map[string]any{"file_path": "a.py", "content": content}}
}
func bashEvent(p, cmd string) map[string]any {
	return map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": p,
		"tool_input": map[string]any{"command": cmd}}
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func nest(n int) string {
	return strings.Repeat(`{"x":`, n) + "1" + strings.Repeat("}", n)
}
