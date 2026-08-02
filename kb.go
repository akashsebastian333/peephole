package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"peephole/internal/litset"
)

// Pattern is one presence signature. Go's regexp is RE2, which has no lookaround,
// so the exclusions the knowledge base needs are declared as separate fields
// rather than embedded in the regex. PrevNot rejects a match whose preceding rune
// is in the given class, emulating a negative lookbehind such as excluding
// ast.literal_eval. RejectRe suppresses a match when a second regex also matches
// the same line, emulating a negative lookahead such as a SafeLoader being
// present. RequireRe is the inverse: the match only fires when a second regex
// matches the same line, for two-signal escalation. RejectRe and RequireRe are
// scoped to the matched line so a benign occurrence elsewhere in the hunk cannot
// disable the rule.
type Pattern struct {
	Lang       string `json:"lang"` // "python" | "javascript" | "" (any)
	Re         string `json:"re"`
	Confidence string `json:"confidence"` // "high" | "medium"
	PrevNot    string `json:"prev_not,omitempty"`
	RejectRe   string `json:"reject_re,omitempty"`
	RequireRe  string `json:"require_re,omitempty"`

	re, prevNot, rejectRe, requireRe *regexp.Regexp
	prefilter                        []string // lowercase literals, one of which must be present; nil = no prefilter
}

// requiredLiteral / requiredLiterals are thin wrappers over internal/litset,
// kept so the existing tests read unchanged.

func requiredLiteral(src string) string { return litset.RequiredOne(src) }

// requiredLiterals extracts the prefilter SET: lowercase literals, at least one
// of which is guaranteed present in any string the regex matches (top-level and
// group alternation aware). nil when no guarantee exists. A wrong (unsound)
// extraction would skip a real match, so the corpus TP tests +
// TestPrefilterSoundness are the net.
func requiredLiterals(src string) []string { return litset.Required(src) }

type Rule struct {
	CWE            string    `json:"cwe_id"`
	Name           string    `json:"name"`
	Rank           int       `json:"rank"`
	KEV            bool      `json:"kev"`
	OWASP          []string  `json:"owasp,omitempty"`    // OWASP 2021 categories; derived from CWE when empty
	Severity       string    `json:"severity,omitempty"` // critical|high|medium; derived from confidence when empty
	TaskTriggers   []string  `json:"task_triggers"`
	Patterns       []Pattern `json:"patterns"`
	Absence        []string  `json:"absence_requirements"`
	AttackScenario string    `json:"attack_scenario"`
	NegativeHints  []string  `json:"negative_test_hint"`
	Exemplar       struct {
		Noncompliant string `json:"noncompliant"`
		Compliant    string `json:"compliant"`
		Explanation  string `json:"explanation"`
	} `json:"exemplar"`
}

type KB struct {
	Rules     []Rule
	bad       []string                  // patterns that failed to compile (surfaced at SessionStart)
	userCount int                       // number of loaded project-local (user) rules
	compiled  bool                      // compileAll has run (SessionStart only)
	kwRe      map[string]*regexp.Regexp // precompiled task-trigger matchers (classify hot path)
}

type Finding struct {
	Rule       *Rule
	Confidence string
}

// extToLang maps a file extension to a language bucket. A pattern's `lang` is
// matched against this so language-flavored regexes only run on the right files;
// `lang:""` patterns run everywhere. Files whose extension isn't here are
// "unknown" and get all language-specific patterns (fail-safe against
// write-to-odd-extension-then-rename evasion).
var extToLang = map[string]string{
	".py": "python", ".pyi": "python", ".ipynb": "python",
	".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
	".mjs": "javascript", ".cjs": "javascript", ".mts": "javascript", ".cts": "javascript",
	".vue": "javascript", ".svelte": "javascript",
	".php": "php", ".phtml": "php",
	".go": "go",
	// JVM family shares APIs (readObject, SpEL, Runtime.exec), one bucket so
	// java-lang rules apply to Kotlin and Scala too.
	".java": "java", ".kt": "java", ".kts": "java", ".scala": "java", ".groovy": "java",
	".rb": "ruby", ".erb": "ruby", ".rake": "ruby",
	".cs": "csharp",
	".c":  "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c", ".hpp": "c", ".hh": "c",
	".rs":    "rust",
	".swift": "swift",
	".dart":  "dart",
	".ex":    "elixir", ".exs": "elixir",
	".sh": "shell", ".bash": "shell", ".zsh": "shell",
	".ps1": "powershell", ".psm1": "powershell",
	".lua": "lua",
	".pl":  "perl", ".pm": "perl",
	".r": "r", ".rmd": "r",
	// smart-contract / infrastructure-as-code / CI buckets
	".sol": "solidity",
	".tf":  "terraform", ".tfvars": "terraform",
	".yml": "yaml", ".yaml": "yaml",
	// mobile / db / server-config / niche buckets
	".m": "objc", ".mm": "objc", ".plist": "objc",
	".sql":  "sql",
	".conf": "webserver", ".htaccess": "webserver",
	".nim": "nim", ".nims": "nim",
	".zig": "zig",
	".cr":  "crystal",
	".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure",
	".jl": "julia",
	".hs": "haskell", ".lhs": "haskell",
	".bicep":       "bicep",
	".jenkinsfile": "java",
}

func langOf(path string) string {
	p := strings.ToLower(path)
	base := p
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		base = p[i+1:]
	}
	// Dockerfiles are identified by name, not extension.
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return "dockerfile"
	}
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return extToLang[p[i:]]
	}
	return ""
}

// compile builds the pattern's regexes, returning an error with a locator if any
// fail so loadKB can surface it. A silently-disabled security rule is worse than
// a loud one.
func (p *Pattern) compile() error {
	if p.re != nil {
		return nil
	}
	var err error
	if p.re, err = regexp.Compile(p.Re); err != nil {
		p.re = nil
		return err
	}
	if p.PrevNot != "" {
		if p.prevNot, err = regexp.Compile("[" + p.PrevNot + "]"); err != nil {
			return err
		}
	}
	if p.RejectRe != "" {
		if p.rejectRe, err = regexp.Compile(p.RejectRe); err != nil {
			return err
		}
	}
	if p.RequireRe != "" {
		if p.requireRe, err = regexp.Compile(p.RequireRe); err != nil {
			return err
		}
	}
	return nil
}

// match returns (ok) applying the declarative refinements, scoped to the line of
// each candidate match. Compiles lazily on first use so the hot path only ever
// compiles the file's language subset.
func (p *Pattern) match(content string) bool {
	_ = p.compile() // idempotent: compiles once, no-op thereafter
	if p.re == nil {
		return false
	}
	// Fast path: ~90% of patterns have no line-scoped refinements, so they only
	// need "does it match at all". MatchString finds the first hit without
	// allocating the [][]int of every match - identical result, since the loop
	// below also returns on the first match when there is nothing to refine.
	if p.prevNot == nil && p.rejectRe == nil && p.requireRe == nil {
		return p.re.MatchString(content)
	}
	for _, loc := range p.re.FindAllStringIndex(content, -1) {
		if p.prevNot != nil && loc[0] > 0 && p.prevNot.MatchString(content[loc[0]-1:loc[0]]) {
			continue
		}
		// Scope refinements to the match's own lines (start line through end line),
		// so a multi-line match or an adjacent second signal is still seen, while a
		// benign occurrence elsewhere in the hunk cannot switch the rule off.
		win := spanLines(content, loc[0], loc[1])
		if p.rejectRe != nil && p.rejectRe.MatchString(win) {
			continue
		}
		if p.requireRe != nil && !p.requireRe.MatchString(win) {
			continue
		}
		return true
	}
	return false
}

func spanLines(content string, from, to int) string {
	start := strings.LastIndexByte(content[:from], '\n') + 1
	end := strings.IndexByte(content[to:], '\n')
	if end < 0 {
		return content[start:]
	}
	return content[start : to+end]
}

// maxScanBytes bounds hot-path scan latency. Running ~500 linear regexes over a
// multi-MB write would take seconds and stall the developer; a normal source
// file is well under this. Larger writes scan the first window on the hot path;
// the PostToolUse retro-scan (scanFull, off the hot path) covers the whole file.
const maxScanBytes = 256 * 1024

// retroScanBytes bounds the off-hot-path full scans (retro-scan, commit review).
const retroScanBytes = 4 * 1024 * 1024

// scan returns findings for presence patterns matching this file's language.
// Language-agnostic patterns (Lang=="") always apply. When the file language is
// UNKNOWN, language-specific patterns are all evaluated (so writing vulnerable
// code to an unrecognized extension and renaming later does not evade the gate).
func (kb *KB) scan(path, content string) []Finding {
	return kb.scanBound(path, content, maxScanBytes)
}

// scanFull is scan without the hot-path window, for the PostToolUse retro-scan
// and commit review: a finding past the 256KB gate window must still surface.
func (kb *KB) scanFull(path, content string) []Finding {
	return kb.scanBound(path, content, retroScanBytes)
}

func (kb *KB) scanBound(path, content string, bound int) []Finding {
	if content == "" {
		return nil
	}
	if len(content) > bound {
		content = content[:bound]
	}
	lang := langOf(path)
	lc := strings.ToLower(content)
	var out []Finding
	for i := range kb.Rules {
		r := &kb.Rules[i]
		for j := range r.Patterns {
			pat := &r.Patterns[j]
			if pat.Lang != "" && lang != "" && pat.Lang != lang {
				continue
			}
			if pat.prefilter != nil && prefilterMiss(pat.prefilter, lc) {
				continue // required literal absent, skip compile+scan
			}
			if pat.match(content) {
				out = append(out, Finding{Rule: r, Confidence: pat.Confidence})
				break
			}
		}
	}
	// Framework-level cross-line taint: a variable built from user input or a
	// dynamic string that reaches a sink on another line (additive, dedup by CWE).
	out = append(out, kb.taintScan(lang, content, lc, tlHave(out))...)
	sort.SliceStable(out, func(i, j int) bool { return findingLess(out[i], out[j]) })
	return out
}

// sinkTokens: the relevance heuristic behind N2. A clean hunk counts as
// security-relevant (born-secure numerator) only if it plausibly touches a
// guarded sink - a query/exec/deserialization/render/crypto/auth/dependency
// surface. Heuristic by construction; the /sec-audit report labels it as such.
var sinkTokens = []string{
	"execute(", "executemany(", "query(", "raw(", "select ", "insert ", "update ", "delete ",
	"cursor", ".sql", "orm", "eval(", "exec(", "system(", "popen(", "subprocess", "popen",
	"shell", "command", "innerhtml", "dangerouslysetinnerhtml", "document.write", "outerhtml",
	"yaml.load", "pickle", "unserialize", "marshal.load", "readobject", "deserialize",
	"open(", "readfile", "writefile", "send_file", "sendfile", "filepath.join", "os.path.join",
	"requests.", "http.get", "http.post", "fetch(", "axios", "urllib", "curl", "wget",
	"redirect", "location.href", "set-cookie", "cookie", "session", "jwt", "token",
	"password", "passwd", "secret", "api_key", "apikey", "private_key", "credential",
	"md5", "sha1", "bcrypt", "argon", "cipher", "encrypt", "decrypt", "random", "uuid",
	"render_template", "template", "ssti", "cors", "csrf", "auth", "login", "permission",
	"chmod", "chown", "umask", "tls", "ssl", "x509", "certificate", "verify",
	"require(", "import ", "include(", "pipe(", "fork(", "ptmx", "docker.sock",
}

// securityRelevant reports whether content plausibly touches a guarded sink, so
// /sec-audit can separate "born secure" from "not security-relevant" instead of
// counting every clean write as a security win.
func (kb *KB) securityRelevant(path, content string) bool {
	if content == "" {
		return false
	}
	if len(content) > maxScanBytes {
		content = content[:maxScanBytes]
	}
	lc := strings.ToLower(content)
	for _, t := range sinkTokens {
		if strings.Contains(lc, t) {
			return true
		}
	}
	return false
}

// scanAgnostic runs only language-agnostic patterns (Lang=="") against arbitrary
// text, used to scan a raw Bash command surface (chmod 777, umask 0, --acl
// public-read) without misfiring code-specific python/js patterns on it.
func (kb *KB) scanAgnostic(content string) []Finding {
	if content == "" {
		return nil
	}
	if len(content) > maxScanBytes {
		content = content[:maxScanBytes]
	}
	lc := strings.ToLower(content)
	var out []Finding
	for i := range kb.Rules {
		r := &kb.Rules[i]
		for j := range r.Patterns {
			pat := &r.Patterns[j]
			if pat.Lang != "" {
				continue
			}
			if pat.prefilter != nil && prefilterMiss(pat.prefilter, lc) {
				continue
			}
			if pat.match(content) {
				out = append(out, Finding{Rule: r, Confidence: pat.Confidence})
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return findingLess(out[i], out[j]) })
	return out
}

// classify maps a prompt to candidate rules via task-trigger keywords (N3).
func (kb *KB) classify(prompt string) []*Rule {
	text := strings.ToLower(prompt)
	// Rank matched CWEs by RELEVANCE (how many of the task's trigger keywords the
	// rule matches), then by Top-25 rank. With a large KB many rules match a
	// generic prompt; the downstream injector caps the list, so the most
	// task-relevant class (e.g. SQLi for a "database query") must sort first and
	// not be crowded out by incidentally-matching low-relevance rules.
	type scored struct {
		r *Rule
		n int
	}
	idx := map[string]int{}
	var list []scored
	for i := range kb.Rules {
		r := &kb.Rules[i]
		n := 0
		for _, kw := range r.TaskTriggers {
			if kb.wordIn(text, strings.ToLower(kw)) {
				n++
			}
		}
		if n == 0 {
			continue
		}
		if j, ok := idx[r.CWE]; ok { // one entry per CWE; keep the strongest match
			if n > list[j].n {
				list[j].n = n
			}
			continue
		}
		idx[r.CWE] = len(list)
		list = append(list, scored{r, n})
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		ri, rj := list[i].r.Rank, list[j].r.Rank
		if ri == 0 {
			ri = 99
		}
		if rj == 0 {
			rj = 99
		}
		return ri < rj
	})
	out := make([]*Rule, len(list))
	for i := range list {
		out[i] = list[i].r
	}
	return out
}

// wordIn reports whether kw appears in text, using the KB's precompiled matcher
// cache (a regexp.MustCompile per keyword per prompt was measurable waste on
// every UserPromptSubmit). Multi-word triggers match as substrings; single
// tokens require word boundaries (so "sql" != "mysql").
func (kb *KB) wordIn(text, kw string) bool {
	if kw == "" {
		return false
	}
	if strings.ContainsAny(kw, " ") {
		return strings.Contains(text, kw)
	}
	if kb.kwRe == nil {
		kb.kwRe = map[string]*regexp.Regexp{}
	}
	re, ok := kb.kwRe[kw]
	if !ok {
		re = regexp.MustCompile(`\b` + regexp.QuoteMeta(kw) + `\b`)
		kb.kwRe[kw] = re
	}
	return re.MatchString(text)
}

// compileAll eagerly compiles every pattern to surface broken ones. not on the
// hot path, called only when uncompilable is needed (SessionStart). On
// PreToolUse, patterns compile lazily via match, so only the file's language
// subset is ever compiled.
func (kb *KB) compileAll() {
	if kb.compiled {
		return
	}
	kb.compiled = true
	for i := range kb.Rules {
		r := &kb.Rules[i]
		for j := range r.Patterns {
			if err := r.Patterns[j].compile(); err != nil {
				kb.bad = append(kb.bad, r.CWE+": "+truncate(r.Patterns[j].Re, 40))
			}
		}
	}
}

func (kb *KB) uncompilable() []string {
	kb.compileAll()
	return kb.bad
}

// loadKB returns the knowledge base. The rules ship as generatedRules - Go
// literals produced at build time by cmd/kbgen from rules/*.json, with every
// pattern's prefilter set precomputed. No file reads, no JSON unmarshal, no
// per-event prefilter computation (~2ms saved on every hook event). Rules
// remain data: patterns compile lazily per language, never eval'd. The JSON
// files stay the source of truth; `go run ./cmd/kbgen --check` (CI) fails the
// build if they drift from rules_gen.go.
func loadKB() *KB {
	kb := &KB{Rules: make([]Rule, len(generatedRules))}
	copy(kb.Rules, generatedRules)
	return kb
}

// initPrefilters computes the skip-literal set for patterns that don't already
// carry one (generated built-ins ship theirs precomputed; only user rules need
// the work). Cheap; no regex is compiled.
func (kb *KB) initPrefilters() {
	for i := range kb.Rules {
		for j := range kb.Rules[i].Patterns {
			p := &kb.Rules[i].Patterns[j]
			if p.prefilter != nil {
				continue // precomputed at build time
			}
			p.prefilter = requiredLiterals(p.Re)
		}
	}
}

// prefilterMiss reports whether the content definitely cannot match: none of
// the required literals is present. Only called when the pattern HAS a set.
func prefilterMiss(prefilter []string, lc string) bool {
	for _, lit := range prefilter {
		if strings.Contains(lc, lit) {
			return false
		}
	}
	return true
}

// loadUserRules merges project-local custom rules (org policy / team rules) with
// the built-in KB, the extensibility model borrowed from security-guidance,
// made safe by RE2: user regexes are linear-time by construction so they cannot
// ReDoS. ADDITIVE only: user rules can add findings, never disable a built-in.
// Files live OUTSIDE the self-protected .peephole dir so a team can commit them:
//
//	<project>/.peephole-rules.json (array of rules, committed)
//	<project>/.claude/peephole-rules.json
//
// A committed rules file is still an untrusted input (a poisoned repo or a Rules
// File Backdoor): every rule is schema-checked and its exemplar/scenario text is
// Unicode- and injection-scanned before it can reach model context.
func (kb *KB) loadUserRules(projectDir string) {
	const maxUserRules = 200
	for _, p := range []string{
		filepath.Join(projectDir, ".peephole-rules.json"),
		filepath.Join(projectDir, ".claude", "peephole-rules.json"),
	} {
		b, err := os.ReadFile(p)
		if err != nil || len(b) > 1<<20 {
			continue
		}
		var many []Rule
		if json.Unmarshal(b, &many) != nil {
			var one Rule
			if json.Unmarshal(b, &one) == nil && one.CWE != "" {
				many = []Rule{one}
			}
		}
		for i := range many {
			if kb.userCount >= maxUserRules {
				break
			}
			r := many[i]
			if r.CWE == "" {
				continue
			}
			if !userRuleSafe(&r) {
				kb.bad = append(kb.bad, "user "+r.CWE+": REJECTED (invisible/bidi/injection content or invalid schema)")
				continue
			}
			ok := true
			for j := range r.Patterns {
				if err := r.Patterns[j].compile(); err != nil {
					ok = false
					kb.bad = append(kb.bad, "user "+r.CWE+": "+truncate(r.Patterns[j].Re, 30))
				}
			}
			if ok {
				kb.Rules = append(kb.Rules, r)
				kb.userCount++
			}
		}
	}
	kb.initPrefilters()
}

// userRuleSafe validates a project-local rule before it can add findings or
// reach context: bounded shape, and no invisible/bidi/homoglyph characters or
// instruction-injection phrasing in the text that will be shown to the model
// (exemplars, attack scenario, hints) - the Rules File Backdoor applied to the
// extensibility path.
func userRuleSafe(r *Rule) bool {
	if len(r.Patterns) > 20 || len(r.TaskTriggers) > 40 || len(r.Absence) > 20 || len(r.NegativeHints) > 4 {
		return false
	}
	for _, p := range r.Patterns {
		if p.Re == "" || len(p.Re) > 2000 {
			return false
		}
	}
	text := r.Name + "\n" + r.AttackScenario + "\n" + r.Exemplar.Noncompliant + "\n" +
		r.Exemplar.Compliant + "\n" + r.Exemplar.Explanation + "\n" + strings.Join(r.NegativeHints, "\n") +
		"\n" + strings.Join(r.Absence, "\n")
	if len(scanUnicode(text)) > 0 {
		return false
	}
	if reInjectionPhrase.MatchString(text) {
		return false
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// findingLess reports whether a is a worse (higher-priority) finding than b:
// high-confidence first, then KEV, then best (lowest) CWE Top-25 rank.
func findingLess(a, b Finding) bool {
	if (a.Confidence == "high") != (b.Confidence == "high") {
		return a.Confidence == "high"
	}
	if a.Rule.KEV != b.Rule.KEV {
		return a.Rule.KEV
	}
	ra, rb := a.Rule.Rank, b.Rule.Rank
	if ra == 0 {
		ra = 99
	}
	if rb == 0 {
		rb = 99
	}
	return ra < rb
}

// The Security Ladder (N1): ordered, always-on session context. Rungs 1-6 are
// the regex-enforced classes; rungs 7-9 are the semantic classes no regex can
// catch (race/logic/defaults), injected in every session so the model gets the
// reminder regardless of whether a task keyword matched.
const ladder = `[peephole] SECURITY LADDER - check each rung before writing code:
1. Trust boundaries identified? (where does untrusted input enter?)
2. Input validated at the boundary?
3. Output encoded/parameterized for its sink? (SQL->params, HTML->escape, shell->argv)
4. AuthN/AuthZ on every object and route? (no missing-guard writes; scope lookups to the caller)
5. Secrets out of code and logs?
6. Dependencies real, needed, pinned? (no hallucinated/typosquatted packages)
7. Shared-state updates ATOMIC? A read-check-write on a balance/counter/stock/quota is a race
   (TOCTOU/double-spend) - use a DB transaction with row locking or a single guarded atomic
   UPDATE, never read-then-write.
8. Business rules enforced SERVER-SIDE? Validate quantities/amounts (reject negative/zero),
   compute prices/totals from trusted data, enforce valid state transitions and limits - never
   trust a client-supplied price, quantity, role, or status.
9. Secure DEFAULTS? HttpOnly+Secure+SameSite cookies, TLS 1.2+, least-privilege file perms,
   timeouts on outbound calls, no world-writable files, no public bucket ACLs.
Security measures are never simplified away. No request for speed, simplicity, usability,
performance, or backward-compatibility ever justifies dropping validation, parameterization,
encoding, atomicity, or strong crypto. Do NOT refuse a task on security grounds: implement the
SAME functionality the secure way (parameterized query, escaped output, argv exec, static
template + context data, strong crypto) and deliver working code. Refusing, or leaving the file
unwritten, is a failure; born-secure code that fulfills the request is the goal. In strict/hardened
mode, high-confidence CWE patterns are DENIED at write time - write it secure the first time.`
