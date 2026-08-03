package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every rule must catch its own noncompliant exemplar and pass its compliant
// one. This keeps the KB honest: a regex that doesn't match the bad example it
// ships is broken, and one that matches the good example is a false-positive
// generator.
func TestKBExemplarConsistency(t *testing.T) {
	kb := loadKB()
	if len(kb.Rules) == 0 {
		t.Fatal("no rules loaded")
	}
	for i := range kb.Rules {
		r := &kb.Rules[i]
		if len(r.Patterns) == 0 || r.Exemplar.Noncompliant == "" {
			continue // advisory-only rule
		}
		if !scanHitsCWE(kb, r.CWE, r.Exemplar.Noncompliant) {
			t.Errorf("%s: noncompliant exemplar not caught:\n  %s", r.CWE, r.Exemplar.Noncompliant)
		}
		if r.Exemplar.Compliant != "" && scanHitsCWE(kb, r.CWE, r.Exemplar.Compliant) {
			t.Errorf("%s: compliant exemplar FALSE-POSITIVES:\n  %s", r.CWE, r.Exemplar.Compliant)
		}
	}
}

// scanHitsCWE scans content across python/js/generic extensions and reports
// whether the given CWE appears (exemplar language is not always known).
func scanHitsCWE(kb *KB, cwe, content string) bool {
	for _, path := range []string{"x.py", "x.js", "x.txt"} {
		for _, f := range kb.scan(path, content) {
			if f.Rule.CWE == cwe {
				return true
			}
		}
	}
	return false
}

func TestRequiredLiteralSafety(t *testing.T) {
	// requiredLiteral must return only a literal GUARANTEED present in every match.
	// A wrong literal causes the prefilter to skip a real match (missed vuln).
	cases := []struct{ re, want string }{
		{`os\.system\(`, "system"},
		{`\bxp_cmdshell\b`, "xp_cmdshell"},
		{`(?i)MODE_ECB\b`, "mode_ecb"},
		{`(?:log(?:ger)?)\s*[.(][^)\n]{0,120}\baadhaar\b`, "aadhaar"}, // must not be "120"
		{`a{0,200}bcdef`, "bcdef"},                                    // quantifier body digits are not literals
		{`(?:eval|exec)\(`, ""},                                       // top-level alternation -> no single literal
		{`foo|bar`, ""},                                               // top-level alternation
		{`[A-Z]{3,}`, ""},                                             // only a char class -> no literal
		{`re\.compile\(`, "compile"},                                  // longest run wins
	}
	for _, c := range cases {
		if got := requiredLiteral(c.re); got != c.want {
			t.Errorf("requiredLiteral(%q) = %q, want %q", c.re, got, c.want)
		}
	}
	// The extracted literal set, if any, must have at least one member present in
	// the pattern's own noncompliant exemplar for every shipped rule (else the
	// prefilter would false-skip a true match).
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
	// Every corpus/rule true-positive must survive the prefilter: extract the
	// set, and at least one literal must appear in the matched content. This is
	// the net that catches an unsound requiredLiterals extraction.
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
	// group-alternation extraction sanity
	cases := []struct {
		re   string
		want []string
	}{
		{`MODE_ECB\b|\bmodes\.ECB\(`, []string{"mode_ecb", "modes"}},
		{`(?:eval|exec)\(`, []string{"eval", "exec"}},
		{`(?i)(?:razorpay_signature|payu_hash)\b`, []string{"razorpay_signature", "payu_hash"}},
		{`__\$\{[^}\n]*\}__`, nil},          // no literal -> no prefilter
		{`foo|bar`, []string{"foo", "bar"}}, // top-level alternation -> union set
		{`ab|cd`, nil},                      // alternatives too short to be selective/sound (<3)
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
	// earliest PUBLICATION date wins: with multiple uploads, the oldest determines
	// age (a package first published in 2000 is not fresh even if re-uploaded today).
	if freshlyCreated(`{"urls":[{"upload_time_iso_8601":"` + recent + `T00:00:00"},{"upload_time_iso_8601":"2000-01-01T00:00:00"}]}`) {
		t.Error("earliest upload (2000) should make it not-fresh")
	}
	// A date in an attacker-controlled body field (readme/description) must NOT be
	// treated as the publication date - only created / upload_time_iso_8601 count.
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
	// A generic "I added a test that returns 400" must not satisfy the gate.
	if testExercised("I added a test that returns a 400 error", hint, true) {
		t.Error("generic test mention should not satisfy an armed payload hint")
	}
	// A test that actually includes the payload literal satisfies it.
	if !testExercised(`def test_sqli(): assert query("' OR '1'='1' -- ") raises`, hint, true) {
		t.Error("a test exercising the payload literal should satisfy the gate")
	}
	// With no payload hint, fall back to the generic heuristic.
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

func TestBashCopyMoveWithTrailingSeparator(t *testing.T) {
	// A cp/mv/dd write is uninspectable and must be flagged even when a command
	// separator follows it - a trailing $-anchor let `; echo done` hide the write.
	for _, cmd := range []string{
		"cp /tmp/evil.py routes.py; echo done",
		"mv /tmp/evil.py app.py && true",
		"cp /tmp/evil.py routes.py", // control: still flagged
	} {
		a := analyzeBash(cmd)
		if !a.Uninspectable {
			t.Errorf("copy/move write not flagged uninspectable: %q -> %+v", cmd, a)
		}
	}
}

func TestBashInterpEscapedQuoteNotTruncated(t *testing.T) {
	// An embedded \" must not truncate extraction: the payload after it (here
	// os.system(user)) has to remain visible to the scanner.
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
	// php -r '<code>' is inline execution and must be inspected (was a silent hole).
	a := analyzeBash(`php -r 'system($_GET[x]);'`)
	joined := ""
	for _, p := range a.Payloads {
		joined += p.Content
	}
	if !strings.Contains(joined, "system($_GET") && !a.Uninspectable {
		t.Fatalf("php -r inline code not inspected: payloads=%+v uninspectable=%v", a.Payloads, a.Uninspectable)
	}
	// -r must stay php-only: `node -r module` is a module preload, not inline code.
	if b := analyzeBash(`node -r ./config.js server.js`); len(b.Payloads) > 0 {
		t.Errorf("node -r (module preload) wrongly treated as inline code: %+v", b.Payloads)
	}
}

func TestSemReviewTagsJSIdorCsrf(t *testing.T) {
	// The Stop self-review fires on the classes semReviewKeys tags; the detectors
	// were Python-only, so the whole JS/Node web-IDOR shape went unreviewed.
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

func TestBashWritePrimitiveEvasions(t *testing.T) {
	// Each of these writes runtime-determined or copied content and must be flagged
	// uninspectable (a caught form has an uncaught sibling otherwise).
	for _, cmd := range []string{
		`echo "${CODE}" > /app/x.py`,                         // brace param expansion (was unflagged)
		`install -m 0755 /tmp/evil.py /app/routes.py`,        // coreutils install (cp sibling)
		`echo -e "\x69\x6d\x70\x6f\x72\x74 os" > /app/x.py`,  // runtime hex-escape decode
		`printf "%b" "\x69mport os" > /app/x.py`,             // printf %b decode
	} {
		if a := analyzeBash(cmd); !a.Uninspectable {
			t.Errorf("write primitive not flagged uninspectable: %q", cmd)
		}
	}
	// A benign printf to stdout (no redirect / no %b) must NOT be flagged.
	if a := analyzeBash(`printf "%b\n" "$x"`); a.Uninspectable {
		t.Errorf("benign printf to stdout wrongly flagged uninspectable")
	}
	// A package-manager `install` subcommand must NOT be mistaken for coreutils
	// install (the flag classes collide; install is anchored to command position).
	for _, cmd := range []string{"npm install -g typescript", "pip install -v flask", "apt install -s nginx", "apt-get install -d curl"} {
		if a := analyzeBash(cmd); a.Uninspectable {
			t.Errorf("package-manager install wrongly flagged as coreutils install: %q", cmd)
		}
	}
	// but real coreutils install (leading, or after sudo) stays flagged.
	for _, cmd := range []string{"install -m 0755 /tmp/x /app/y", "sudo install -m 0755 x y"} {
		if a := analyzeBash(cmd); !a.Uninspectable {
			t.Errorf("coreutils install not flagged uninspectable: %q", cmd)
		}
	}
}

func TestAddSessionSetConcurrent(t *testing.T) {
	// Concurrent tool calls spawn concurrent PostToolUse hooks that all union into
	// the same semreview set; an unlocked read-modify-write dropped classes, so the
	// Stop self-review silently skipped them. Every class written must be retained.
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
	// Tamper: rewrite a decision in place.
	corruptLogLine(t, sd)
	if ok, _ := verifyChain(sd); ok {
		t.Fatal("chain verification should FAIL after tampering")
	}
}

func TestLogChainDetectsTailTruncation(t *testing.T) {
	// Truncating entries after the last checkpoint must be detected via the head
	// sidecar, even with fewer than chainEvery entries.
	sd := t.TempDir()
	for i := 0; i < 5; i++ {
		appendLog(sd, logEntry{Decision: "deny", Tool: "Write"})
	}
	if ok, _ := verifyChain(sd); !ok {
		t.Fatal("fresh short log should verify")
	}
	// drop the last line
	p := filepath.Join(sd, "log.jsonl")
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600)
	if ok, _ := verifyChain(sd); ok {
		t.Fatal("tail truncation should be detected as tampering")
	}
}

func TestNoUncompilablePatterns(t *testing.T) {
	// Every shipped KB pattern must compile, a silently-disabled rule is a
	// security hole.
	if bad := loadKB().uncompilable(); len(bad) > 0 {
		t.Fatalf("KB has uncompilable patterns: %v", bad)
	}
}

// corruptLogLine flips a decision on an early (non-checkpoint) line, proving the
// running hash covers every entry, not just checkpoint lines.
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
