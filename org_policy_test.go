package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Org policy is ESCALATION ONLY: a committed .peephole-policy.json can make the
// gate stricter (mandate a CWE to deny, raise the mode floor) but never weaker,
// so a poisoned repo cannot use it to disable enforcement.

func TestOrgPolicyEnforceEscalates(t *testing.T) {
	p := newProject(t, "strict")
	// document.write is medium-confidence XSS -> strict normally ASKS.
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"enforce":["CWE-79"]}`), 0o644)
	ho, exit, _ := runHookJSON(t, write(p, "Write", "x.js", `document.write(location.hash)`))
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("org enforce must escalate CWE-79 ask->deny, got %q", ho.HookSpecificOutput.PermissionDecision)
	}
}

func TestOrgMandateNotDowngradedByDenyBudget(t *testing.T) {
	// An `enforce` CWE is unwaivable, so the terminating-guardrail budget (which
	// downgrades a repeated deny to ask) must NOT apply to it - else an agent turns
	// a hard org block into a human-clickable prompt by retrying 3x.
	p := newProject(t, "strict")
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"enforce":["CWE-79"]}`), 0o644)
	for i := 0; i < 4; i++ {
		ev := write(p, "Write", "x.js", `document.write(location.hash)`)
		ev["session_id"] = "mandate-sess"
		ho, exit, raw := runHookJSON(t, ev)
		assertNotExit1(t, exit)
		if ho.HookSpecificOutput.PermissionDecision != "deny" {
			t.Fatalf("retry %d: org-mandated CWE-79 must stay deny, got %q (%s)", i+1, ho.HookSpecificOutput.PermissionDecision, raw)
		}
	}
}

func TestOrgPolicyMinModeFloor(t *testing.T) {
	// no local mode set; the org floor of strict must enforce (SQLi denied).
	p := t.TempDir()
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"min_mode":"strict"}`), 0o644)
	ho, exit, _ := runHookJSON(t, write(p, "Write", "a.py", `cur.execute(f"SELECT * FROM t WHERE id={uid}")`))
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("min_mode=strict floor must deny SQLi, got %q", ho.HookSpecificOutput.PermissionDecision)
	}
}

func TestOrgPolicyCannotWeaken(t *testing.T) {
	// A committed policy must not be able to downgrade a strict project: an
	// invalid/weaker min_mode is ignored (the floor only ever raises).
	p := newProject(t, "strict")
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"min_mode":"audit"}`), 0o644)
	ho, exit, _ := runHookJSON(t, write(p, "Write", "a.py", `cur.execute(f"SELECT * FROM t WHERE id={uid}")`))
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("policy must not weaken strict->audit, got %q", ho.HookSpecificOutput.PermissionDecision)
	}
}

// The org policy must reach EVERY write surface, not just the Write tool. These
// pin the Bash write-path and MCP paths, the exact vectors a denied Write retries
// through - the escalation was previously applied only in handleWriteFamily.

func TestOrgEnforceAppliesToBashWritePath(t *testing.T) {
	p := newProject(t, "strict")
	// document.write is medium-confidence XSS -> strict normally ASKS; the org
	// mandate must escalate it to deny even when it arrives via a heredoc write.
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"enforce":["CWE-79"]}`), 0o644)
	cmd := "cat > x.js <<'EOF'\ndocument.write(location.hash)\nEOF"
	ho, exit, raw := runHookJSON(t, bash(p, cmd))
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("org enforce must reach the Bash write-path, got %q (%s)", ho.HookSpecificOutput.PermissionDecision, raw)
	}
}

func TestOrgEnforceAppliesToMCPWrite(t *testing.T) {
	p := newProject(t, "strict")
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"enforce":["CWE-79"]}`), 0o644)
	ev := map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "mcp__fs__write_file", "cwd": p,
		"tool_input": map[string]any{"path": "x.js", "contents": `document.write(location.hash)`},
	}
	ho, exit, raw := runHookJSON(t, ev)
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("org enforce must reach MCP writes, got %q (%s)", ho.HookSpecificOutput.PermissionDecision, raw)
	}
}

func TestMinModeFloorRaisesAuditToStrict(t *testing.T) {
	// Non-vacuous floor test: the local mode is explicitly the weaker "audit", so
	// a deny only happens if floor() actually raises it to strict. (The prior test
	// used a no-mode TempDir whose default is already strict, hiding a floor no-op.)
	p := newProject(t, "audit")
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"min_mode":"strict"}`), 0o644)
	ho, exit, raw := runHookJSON(t, write(p, "Write", "a.py", `cur.execute(f"SELECT * FROM t WHERE id={uid}")`))
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("min_mode=strict must raise audit->strict and deny SQLi, got %q (%s)", ho.HookSpecificOutput.PermissionDecision, raw)
	}
}

func TestMinModeFloorOverridesOff(t *testing.T) {
	// A repo cannot disable the gate under an org floor: local "off" + min_mode
	// strict must still enforce (the floor is applied before the off short-circuit).
	p := newProject(t, "off")
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"min_mode":"strict"}`), 0o644)
	ho, exit, raw := runHookJSON(t, write(p, "Write", "a.py", `cur.execute(f"SELECT * FROM t WHERE id={uid}")`))
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("min_mode floor must override a repo's off, got %q (%s)", ho.HookSpecificOutput.PermissionDecision, raw)
	}
}

func TestHardenedIgnoresSecDebtMarker(t *testing.T) {
	// Markers are non-waivable in hardened (a hook cannot collect typed human
	// confirmation), so a scoped sec-debt marker must NOT downgrade a deny there.
	p := newProject(t, "hardened")
	content := "# sec-debt: CWE-89 internal tool only\ncur.execute(f\"SELECT * FROM t WHERE id={uid}\")"
	ho, exit, raw := runHookJSON(t, write(p, "Write", "a.py", content))
	assertNotExit1(t, exit)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("hardened must not let a sec-debt marker downgrade a deny, got %q (%s)", ho.HookSpecificOutput.PermissionDecision, raw)
	}
}
