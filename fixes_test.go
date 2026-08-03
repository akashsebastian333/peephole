package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression tests for the hardening round: each test pins one fixed blunder or
// one completed blueprint mechanism so it cannot silently regress.

func TestModeLoweringObfuscationDenied(t *testing.T) {
	// Shell no-op quoting/escaping must not slip the enforcement-lowering guard:
	// `mode o''ff` normalizes to `mode off` at exec.
	p := newProject(t, "strict")
	for _, cmd := range []string{
		`sh "$CLAUDE_PLUGIN_ROOT/hooks/peephole.sh" mode o''ff`,
		`sh "$CLAUDE_PLUGIN_ROOT/hooks/peephole.sh" mode aud''it`,
		`sh "$CLAUDE_PLUGIN_ROOT/hooks/peephole.sh" m\ode off`,
		`peephole mode "of"f`,
	} {
		ho, _, _ := runHookJSON(t, bash(p, cmd))
		if ho.HookSpecificOutput.PermissionDecision != "deny" {
			t.Fatalf("obfuscated mode lowering must be denied: %q -> %q", cmd, ho.HookSpecificOutput.PermissionDecision)
		}
	}
	if readMode(t, p) != "strict" {
		t.Fatal("mode must not have been lowered")
	}
}

func TestRewriteRequiresFullClear(t *testing.T) {
	// A secure-default rewrite that fixes only SOME findings must not smuggle the
	// rest through the ask: yaml.load + an AWS key denies (the secret), while
	// yaml.load alone is still offered the rewrite.
	p := newProject(t, "strict")
	ho, _, _ := runHookJSON(t, write(p, "Write", "app.py",
		"cfg = yaml.load(open(p))\nAWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"))
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("partial rewrite must not bypass the remaining finding, got %q", ho.HookSpecificOutput.PermissionDecision)
	}
	ho2, _, raw := runHookJSON(t, write(p, "Write", "app.py", "cfg = yaml.load(open(p))"))
	if ho2.HookSpecificOutput.PermissionDecision != "ask" || !strings.Contains(raw, "safe_load") {
		t.Fatalf("full-clear rewrite should still be offered: %q", ho2.HookSpecificOutput.PermissionDecision)
	}
}

func TestSecDebtScopedToFinding(t *testing.T) {
	// A marker 40 lines away must not waive the finding; one directly above must.
	p := newProject(t, "strict")
	far := "# sec-debt: CWE-798 legacy key, accepted\n" + strings.Repeat("x = 1\n", 40) + "cur.execute(f\"SELECT * FROM t WHERE id={y}\")"
	ho, _, _ := runHookJSON(t, write(p, "Write", "app.py", far))
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("a distant sec-debt marker must not waive the finding, got %q", ho.HookSpecificOutput.PermissionDecision)
	}
	near := "x = 1\n# sec-debt: CWE-89 internal tool, network-isolated\ncur.execute(f\"SELECT * FROM t WHERE id={y}\")"
	ho2, _, _ := runHookJSON(t, write(p, "Write", "app.py", near))
	if ho2.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("a marker on the line above the finding should downgrade deny to ask, got %q", ho2.HookSpecificOutput.PermissionDecision)
	}
}

func TestSecDebtEvasionFlaggedAtStop(t *testing.T) {
	// N4: a marker without matching human approval is flagged at Stop as evasion.
	p := newProject(t, "strict")
	near := "x = 1\n# sec-debt: CWE-89 internal tool\ncur.execute(f\"SELECT * FROM t WHERE id={y}\")"
	runHookJSON(t, map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": p, "session_id": "s-evade",
		"tool_input": map[string]any{"file_path": "app.py", "content": near},
	})
	ho, _, _ := runHookJSON(t, map[string]any{
		"hook_event_name": "Stop", "cwd": p, "session_id": "s-evade", "last_assistant_message": "done"})
	if !strings.Contains(ho.SystemMessage, "sec-debt") {
		t.Fatalf("unapproved marker must be flagged at Stop: %q", ho.SystemMessage)
	}
	// with approval recorded, no flag
	os.WriteFile(filepath.Join(p, ".peephole", "secdebt-approved"), []byte("app.py\n"), 0o600)
	ho2, _, _ := runHookJSON(t, map[string]any{
		"hook_event_name": "Stop", "cwd": p, "session_id": "s-evade", "last_assistant_message": "done"})
	if strings.Contains(ho2.SystemMessage, "evasion") || strings.Contains(ho2.SystemMessage, "sec-debt marker") {
		t.Fatalf("approved marker must not be flagged: %q", ho2.SystemMessage)
	}
}

func TestStopGatesRespectOrgFloor(t *testing.T) {
	// A repo's mode=off must not silently disable the Stop-time gates when an org
	// min_mode floor is committed: the sec-debt evasion check must still fire.
	p := newProject(t, "off")
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"), []byte(`{"min_mode":"strict"}`), 0o644)
	near := "x = 1\n# sec-debt: CWE-89 internal tool\ncur.execute(f\"SELECT * FROM t WHERE id={y}\")"
	runHookJSON(t, map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": p, "session_id": "s-floor",
		"tool_input": map[string]any{"file_path": "app.py", "content": near},
	})
	ho, _, _ := runHookJSON(t, map[string]any{
		"hook_event_name": "Stop", "cwd": p, "session_id": "s-floor", "last_assistant_message": "done"})
	if !strings.Contains(ho.SystemMessage, "sec-debt") {
		t.Fatalf("org floor must keep the Stop evasion check active under mode=off: %q", ho.SystemMessage)
	}
}

func TestSecDebtApprovalExactMatch(t *testing.T) {
	// A whole-file or exact file:line grant approves; a substring must NOT (a
	// line-4 grant used to approve line-42, and "app.py" any *.python file).
	if isApproved(debtMarker{File: "app.py", Line: 42}, []string{"app.py:4"}) {
		t.Error("app.py:4 must not approve app.py:42")
	}
	if isApproved(debtMarker{File: "myapp.python", Line: 1}, []string{"app.py"}) {
		t.Error("app.py must not approve myapp.python")
	}
	if !isApproved(debtMarker{File: "app.py", Line: 42}, []string{"app.py"}) {
		t.Error("a whole-file grant must approve")
	}
	if !isApproved(debtMarker{File: "app.py", Line: 42}, []string{"app.py:42"}) {
		t.Error("an exact file:line grant must approve")
	}
}

func TestSelfReviewTracksClassesNotOneShot(t *testing.T) {
	// A semantic class first introduced DURING the forced continuation must still
	// be reviewed: the reviewed-state is per-class, not a sticky one-shot flag.
	sd, sid := t.TempDir(), "s1"
	pending := func() []string {
		reviewed := map[string]bool{}
		for _, k := range sessionReviewedClasses(sd, sid) {
			reviewed[k] = true
		}
		var out []string
		for _, k := range sessionSemReview(sd, sid) {
			if !reviewed[k] {
				out = append(out, k)
			}
		}
		return out
	}
	markSemReview(sd, sid, []string{"idor"})
	markReviewedClasses(sd, sid, []string{"idor"}) // first Stop reviewed idor
	markSemReview(sd, sid, []string{"race"})       // a new class lands during the continuation
	if p := pending(); len(p) != 1 || p[0] != "race" {
		t.Fatalf("a class introduced after the first review must still be pending, got %v", p)
	}
	markReviewedClasses(sd, sid, []string{"race"})
	if p := pending(); len(p) != 0 {
		t.Fatalf("all classes reviewed, nothing should pend, got %v", p)
	}
}

func TestRuleIDLogged(t *testing.T) {
	// The audit log's rule_id carries the rule identity, never the confidence tier.
	p := newProject(t, "strict")
	runHookJSON(t, write(p, "Write", "app.py", `cur.execute(f"SELECT * FROM t WHERE id={y}")`))
	b, _ := os.ReadFile(filepath.Join(p, ".peephole", "log.jsonl"))
	if !strings.Contains(string(b), `"rule_id":"SQL Injection"`) {
		t.Fatalf("log should carry the rule name in rule_id: %s", b)
	}
	if strings.Contains(string(b), `"rule_id":"high"`) {
		t.Fatalf("confidence tier must not be logged as rule_id: %s", b)
	}
}

func TestCleanBashWriteNoTamperAlarm(t *testing.T) {
	// A Bash-only write session with clean content logs an allow at the gate, so
	// the zero-decision alarm does not false-fire at Stop.
	p := newProject(t, "strict")
	cmd := "cat > notes.txt <<'EOF'\nhello world\nEOF"
	runHookJSON(t, map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": p, "session_id": "s-bw",
		"tool_input": map[string]any{"command": cmd},
	})
	ho, _, _ := runHookJSON(t, map[string]any{
		"hook_event_name": "Stop", "cwd": p, "session_id": "s-bw", "last_assistant_message": "wrote notes"})
	if strings.Contains(ho.SystemMessage, "possible tampering") {
		t.Fatalf("clean Bash write session must not raise the tamper alarm: %q", ho.SystemMessage)
	}
}

func TestPeepholeRulesFileAccessible(t *testing.T) {
	// .peephole-rules.json is a committed, user-editable project file - not
	// peephole state. Reading or writing it must not trip self-protection.
	p := newProject(t, "strict")
	ho, _, _ := runHookJSON(t, bash(p, "cat .peephole-rules.json"))
	if ho.HookSpecificOutput.PermissionDecision == "deny" {
		t.Fatal("reading .peephole-rules.json must not be denied")
	}
	ho2, _, _ := runHookJSON(t, bash(p, `D=.peephole; rm -rf $D`))
	if ho2.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatal("the actual state dir must stay protected")
	}
}

func TestRedirectCarveOut(t *testing.T) {
	// Benign producer -> plain-data target: everyday flow, no gate. Code/config
	// targets and obfuscated producers stay gated.
	p := newProject(t, "strict")
	ho, _, _ := runHookJSON(t, bash(p, "git diff > notes.txt"))
	if ho.HookSpecificOutput.PermissionDecision != "" {
		t.Fatalf("git diff > notes.txt should not be gated, got %q", ho.HookSpecificOutput.PermissionDecision)
	}
	ho2, _, _ := runHookJSON(t, bash(p, "git show :vuln.py > app.py"))
	if ho2.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("a code target must stay gated, got %q", ho2.HookSpecificOutput.PermissionDecision)
	}
	ho3, _, _ := runHookJSON(t, bash(p, "echo aW1wb3J0IG9z | base64 -d > notes.txt"))
	if ho3.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("an obfuscated producer must stay gated, got %q", ho3.HookSpecificOutput.PermissionDecision)
	}
}

func TestRetroScanBeyondHotWindow(t *testing.T) {
	// A finding past the 256KB hot-path window must still surface via the
	// retro-scan (degraded after-landing coverage).
	p := newProject(t, "audit")
	big := strings.Repeat("# padding line\n", 22000) + "cur.execute(f\"SELECT * FROM t WHERE id={y}\")\n"
	os.WriteFile(filepath.Join(p, "big.py"), []byte(big), 0o600)
	if len(big) < maxScanBytes {
		t.Skip("fixture smaller than the scan window")
	}
	runHookJSON(t, map[string]any{
		"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": p, "session_id": "s-big",
		"tool_input": map[string]any{"command": "cat > big.py <<'EOF'\nx\nEOF"},
	})
	b, _ := os.ReadFile(filepath.Join(p, ".peephole", "log.jsonl"))
	if !strings.Contains(string(b), "retro-flag") {
		t.Fatal("retro-scan must flag a finding past the hot-path window")
	}
}

func TestHunkMemo(t *testing.T) {
	// §7.4: once a hunk landed (allowed or ask-approved), the same hunk is not
	// re-gated this session.
	p := newProject(t, "strict")
	ev := write(p, "Write", "app.py", `cur.execute(f"SELECT * FROM t WHERE id={y}")`)
	ho, _, _ := runHookJSON(t, ev)
	if ho.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("first sight of the vuln hunk should deny, got %q", ho.HookSpecificOutput.PermissionDecision)
	}
	// simulate the hunk having landed (e.g. written in audit earlier / approved)
	raw := `cur.execute(f"SELECT * FROM t WHERE id={y}")`
	content := ToolInput{Content: raw}.newContent() // exactly what the hook memoizes
	sd := stateDir(Event{Cwd: p})
	recordHunk(sd, "", hunkKey("app.py", content))
	ho2, _, _ := runHookJSON(t, ev)
	if ho2.HookSpecificOutput.PermissionDecision == "deny" {
		t.Fatal("a hunk that already landed this session must not be re-gated")
	}
	// The memo is language-scoped: the same bytes landing clean as another language
	// (Go: the python-only SQLi rule is skipped) must NOT waive the .py finding.
	p2 := newProject(t, "strict")
	sd2 := stateDir(Event{Cwd: p2})
	recordHunk(sd2, "", hunkKey("stage.go", content)) // same bytes, "landed" clean as Go
	ho3, _, _ := runHookJSON(t, write(p2, "Write", "app.py", raw))
	if ho3.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("a Go-scoped memo must not waive the same bytes in a .py file, got %q", ho3.HookSpecificOutput.PermissionDecision)
	}
}

func TestSubagentStartContext(t *testing.T) {
	p := newProject(t, "strict")
	ho, _, _ := runHookJSON(t, map[string]any{
		"hook_event_name": "SubagentStart", "cwd": p,
		"prompt": "implement the file upload endpoint with a database query"})
	ctx := ho.HookSpecificOutput.AdditionalContext
	if !strings.Contains(ctx, "SECURITY LADDER") || !strings.Contains(ctx, "CWE-") {
		t.Fatalf("SubagentStart should inject ladder + task CWE context: %q", ctx)
	}
	p2 := newProject(t, "off")
	ho2, _, _ := runHookJSON(t, map[string]any{
		"hook_event_name": "SubagentStart", "cwd": p2, "prompt": "database query"})
	if ho2.HookSpecificOutput.AdditionalContext != "" {
		t.Fatal("off mode injects nothing")
	}
}

func TestUserRulePoisoningRejected(t *testing.T) {
	// A project-local rule carrying invisible Unicode in its exemplar is a Rules
	// File Backdoor vector: rejected, loudly, never loaded.
	p := newProject(t, "strict")
	os.WriteFile(filepath.Join(p, ".peephole-rules.json"),
		[]byte(`[{"cwe_id":"CWE-9001","name":"Org","attack_scenario":"x","exemplar":{"noncompliant":"BAD​CALL()","compliant":"ok","explanation":"x"},"patterns":[{"lang":"python","re":"FORBIDDEN_XYZ","confidence":"high"}]}]`), 0o600)
	ho, _, _ := runHookJSON(t, write(p, "Write", "a.py", "x = FORBIDDEN_XYZ(y)"))
	if ho.HookSpecificOutput.PermissionDecision == "deny" {
		t.Fatal("a poisoned user rule must be rejected, not enforced")
	}
	ho2, _, _ := runHookJSON(t, map[string]any{"hook_event_name": "SessionStart", "cwd": p, "source": "startup"})
	if !strings.Contains(ho2.HookSpecificOutput.AdditionalContext, "REJECTED") {
		t.Fatalf("the rejection must be surfaced at SessionStart: %q", ho2.HookSpecificOutput.AdditionalContext)
	}
}

func TestOrgPolicyInjection(t *testing.T) {
	p := newProject(t, "strict")
	os.WriteFile(filepath.Join(p, ".peephole-policy.json"),
		[]byte(`{"global": ["bcrypt cost >= 12"], "CWE-89": ["all queries via the repository layer"]}`), 0o600)
	ho, _, _ := runHookJSON(t, map[string]any{
		"hook_event_name": "UserPromptSubmit", "cwd": p,
		"prompt": "add a login endpoint that runs a database query for the user"})
	ctx := ho.HookSpecificOutput.AdditionalContext
	if !strings.Contains(ctx, "repository layer") || !strings.Contains(ctx, "bcrypt cost >= 12") {
		t.Fatalf("org policy must be injected with the CWE context: %q", ctx)
	}
}

func TestStateVersionMigration(t *testing.T) {
	// A version mismatch resets volatile state and re-stamps (migrate-or-reset).
	p := newProject(t, "strict")
	sd := stateDir(Event{Cwd: p})
	os.Remove(filepath.Join(sd, "state-version"))
	os.MkdirAll(filepath.Join(sd, "session"), 0o700)
	runHookJSON(t, map[string]any{"hook_event_name": "SessionStart", "cwd": p, "source": "startup"})
	b, err := os.ReadFile(filepath.Join(sd, "state-version"))
	if err != nil || strings.TrimSpace(string(b)) != stateSchemaVersion {
		t.Fatalf("state version must be stamped after migration: %q %v", b, err)
	}
}

func TestOWASP2025Mapping(t *testing.T) {
	// Blueprint rollup target is OWASP Top 10:2025 (A03 = supply chain).
	if cweToOWASP["CWE-1104"] != "A03" {
		t.Fatal("CWE-1104 (unpinned dependencies) must roll to A03:2025 supply chain")
	}
	if cweToOWASP["CWE-918"] != "A01" {
		t.Fatal("SSRF merged into A01 Broken Access Control in 2025")
	}
	if cweToOWASP["CWE-89"] != "A05" {
		t.Fatal("injection is A05:2025")
	}
	for _, c := range []string{"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"} {
		if owaspName[c] == "" {
			t.Fatalf("owaspName missing %s", c)
		}
	}
	// owaspOf (the SARIF/audit tag source) must derive from the 2025 CWE table and
	// IGNORE the rule's declared owasp field, which is 2021 - emitting a 2021 number
	// under an "OWASP-2025" label mislabels the finding (Injection A03->A05).
	for cwe, want := range map[string]string{"CWE-78": "A05", "CWE-89": "A05", "CWE-327": "A04", "CWE-829": "A03", "CWE-502": "A08"} {
		if got := owaspOf(&Rule{CWE: cwe, OWASP: []string{"A03"}}); len(got) != 1 || got[0] != want {
			t.Errorf("owaspOf(%s) = %v, want [%s]; the 2021 owasp field must be ignored", cwe, got, want)
		}
	}
}

func TestScan100KBUnderBudget(t *testing.T) {
	// §7.4 performance budget: p99 well under 500ms on a 100KB write. The race
	// detector adds ~20x instrumentation overhead that swamps real latency and
	// varies by machine/CI load, and a single-threaded scan gains no race coverage,
	// so the budget is enforced only in the non-race test run.
	if raceEnabled {
		t.Skip("timing budget is validated without the race detector")
	}
	kb := loadKB()
	content := strings.Repeat("x = compute(value)\n", 8000) // ~160KB of clean code
	start := time.Now()
	for i := 0; i < 5; i++ {
		kb.scan("a.py", content)
	}
	if d := time.Since(start) / 5; d > 500*time.Millisecond {
		t.Fatalf("scan of a 100KB+ file took %v - over the §7.4 p99 budget (500ms)", d)
	}
}

func TestCommitReviewDedupe(t *testing.T) {
	// hooks.json wires both a generic Bash PostToolUse and if-gated asyncRewake
	// entries at us; one commit must only produce one review.
	p := newProject(t, "strict")
	run := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = p
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("git unavailable: %s", out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t")
	run("config", "user.name", "t")
	os.WriteFile(filepath.Join(p, "net.py"), []byte("import os\nos.system(f\"ping {host}\")\n"), 0o600)
	run("add", "-A")
	run("commit", "-qm", "add net")
	ev := map[string]any{
		"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": p,
		"tool_input": map[string]any{"command": "git commit -m x"},
	}
	ho, _, _ := runHookJSON(t, ev)
	if !strings.Contains(ho.SystemMessage, "commit review") {
		t.Fatalf("first review should fire: %q", ho.SystemMessage)
	}
	ho2, _, _ := runHookJSON(t, ev)
	if strings.Contains(ho2.SystemMessage, "commit review") || ho2.HookSpecificOutput.AdditionalContext != "" {
		t.Fatal("the same commit must not be reviewed twice")
	}
}
