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
