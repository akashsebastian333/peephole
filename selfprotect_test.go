package main

import "testing"

// Self-protection must not be evadable by aliasing the peephole binary through a
// shell variable. `P=peephole; $P mode off` resolves to `peephole mode off` at
// exec, so it must be caught after assignment resolution.
func TestModeLowerBypass(t *testing.T) {
	viol := func(cmd string) bool {
		ok, _ := selfProtectViolation(Event{ToolName: "Bash"}, ToolInput{Command: cmd})
		return ok
	}
	block := []string{
		"peephole mode off",
		"P=peephole; $P mode off",
		"p=peephole && $p mode audit",
		"X=/usr/bin/peephole; ${X} mode strict",
		`eval "peephole mode off"`,
		"B=.peephole; rm -rf $B",
	}
	for _, c := range block {
		if !viol(c) {
			t.Errorf("self-protection should BLOCK but allowed: %q", c)
		}
	}
	allow := []string{"echo hello", "P=1; echo $P", "git status", "npm test"}
	for _, c := range allow {
		if viol(c) {
			t.Errorf("self-protection should ALLOW but blocked: %q", c)
		}
	}
}
