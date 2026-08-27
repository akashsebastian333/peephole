package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"peephole/internal/litset"
)

type Pattern struct {
	Lang       string `json:"lang"`
	Re         string `json:"re"`
	Confidence string `json:"confidence"`
	PrevNot    string `json:"prev_not,omitempty"`
	RejectRe   string `json:"reject_re,omitempty"`
	RequireRe  string `json:"require_re,omitempty"`

	re, prevNot, rejectRe, requireRe *regexp.Regexp
	prefilter                        []string
	prevNotSet                       [256]bool
	hasPrevNot                       bool
}

func requiredLiteral(src string) string { return litset.RequiredOne(src) }

func requiredLiterals(src string) []string { return litset.Required(src) }

type Rule struct {
	CWE            string    `json:"cwe_id"`
	Name           string    `json:"name"`
	Rank           int       `json:"rank"`
	KEV            bool      `json:"kev"`
	OWASP          []string  `json:"owasp,omitempty"`
	Severity       string    `json:"severity,omitempty"`
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
	bad       []string
	userCount int
	compiled  bool
}

type Finding struct {
	Rule       *Rule
	Confidence string
}

var extToLang = map[string]string{
	".py": "python", ".pyi": "python", ".ipynb": "python",
	".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
	".mjs": "javascript", ".cjs": "javascript", ".mts": "javascript", ".cts": "javascript",
	".vue": "javascript", ".svelte": "javascript",
	".php": "php", ".phtml": "php",
	".go":   "go",
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
	".sol": "solidity",
	".tf":  "terraform", ".tfvars": "terraform",
	".yml": "yaml", ".yaml": "yaml",
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
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return "dockerfile"
	}
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return extToLang[p[i:]]
	}
	return ""
}

var compileMu sync.Mutex

func (p *Pattern) compile() error {
	if p.re != nil {
		return nil
	}
	compileMu.Lock()
	defer compileMu.Unlock()
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
			p.re = nil
			return err
		}
		p.hasPrevNot = true
		var one [1]byte
		for i := 0; i < 256; i++ {
			one[0] = byte(i)
			p.prevNotSet[i] = p.prevNot.MatchString(string(one[:]))
		}
	}
	if p.RejectRe != "" {
		if p.rejectRe, err = regexp.Compile(p.RejectRe); err != nil {
			p.re = nil
			return err
		}
	}
	if p.RequireRe != "" {
		if p.requireRe, err = regexp.Compile(p.RequireRe); err != nil {
			p.re = nil
			return err
		}
	}
	return nil
}

func (p *Pattern) match(content string) bool {
	_ = p.compile()
	if p.re == nil {
		return false
	}
	if !p.hasPrevNot && p.rejectRe == nil && p.requireRe == nil {
		return p.re.MatchString(content)
	}
	for offset := 0; offset <= len(content); {
		loc := p.re.FindStringIndex(content[offset:])
		if loc == nil {
			return false
		}
		abs0, abs1 := offset+loc[0], offset+loc[1]
		ok := true
		if p.hasPrevNot && abs0 > 0 && p.prevNotSet[content[abs0-1]] {
			ok = false
		}
		if ok {
			win := spanLines(content, abs0, abs1)
			if p.rejectRe != nil && p.rejectRe.MatchString(win) {
				ok = false
			} else if p.requireRe != nil && !p.requireRe.MatchString(win) {
				ok = false
			}
		}
		if ok {
			return true
		}
		offset = abs0 + 1
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

type patIdx struct{ ri, pi int }

var (
	patsAll []patIdx
	patsAny []patIdx
	patsFor map[string][]patIdx
)

func init() {
	patsFor = map[string][]patIdx{}
	langs := map[string]struct{}{}
	for i := range generatedRules {
		for j := range generatedRules[i].Patterns {
			if l := generatedRules[i].Patterns[j].Lang; l != "" {
				langs[l] = struct{}{}
			}
		}
	}
	for i := range generatedRules {
		for j := range generatedRules[i].Patterns {
			ix := patIdx{i, j}
			patsAll = append(patsAll, ix)
			pl := generatedRules[i].Patterns[j].Lang
			if pl == "" {
				patsAny = append(patsAny, ix)
			}
			for L := range langs {
				if pl == "" || pl == L {
					patsFor[L] = append(patsFor[L], ix)
				}
			}
		}
	}
}

func patternList(lang string) []patIdx {
	if lang == "" {
		return patsAll
	}
	if list, ok := patsFor[lang]; ok {
		return list
	}
	return patsAny
}

func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := make([]byte, len(s))
			copy(b, s)
			b[i] = c + 32
			for j := i + 1; j < len(s); j++ {
				if c2 := b[j]; c2 >= 'A' && c2 <= 'Z' {
					b[j] = c2 + 32
				}
			}
			return string(b)
		}
	}
	return s
}

const maxScanBytes = 256 * 1024

const retroScanBytes = 4 * 1024 * 1024

func (kb *KB) scan(path, content string) []Finding {
	return kb.scanBound(path, content, maxScanBytes)
}

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
	prose := proseFile(path)
	lc := asciiLower(content)
	var out []Finding
	lastRi, skipRule := -1, false
	for _, ix := range patternList(lang) {
		if ix.ri != lastRi {
			lastRi, skipRule = ix.ri, false
		}
		if skipRule {
			continue
		}
		r := &kb.Rules[ix.ri]
		if prose && !proseKeepCWE[r.CWE] {
			skipRule = true
			continue
		}
		pat := &r.Patterns[ix.pi]
		if pat.prefilter != nil && prefilterMiss(pat.prefilter, lc) {
			continue
		}
		if pat.match(content) {
			out = append(out, Finding{Rule: r, Confidence: pat.Confidence})
			skipRule = true
		}
	}
	for i := len(generatedRules); i < len(kb.Rules); i++ {
		r := &kb.Rules[i]
		if prose && !proseKeepCWE[r.CWE] {
			continue
		}
		for j := range r.Patterns {
			pat := &r.Patterns[j]
			if pat.Lang != "" && lang != "" && pat.Lang != lang {
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
	if !prose {
		out = append(out, kb.taintScan(lang, content, lc, tlHave(out))...)
	}
	if lowAssurancePath(path) {
		for i := range out {
			if out[i].Confidence == "high" {
				out[i].Confidence = "medium"
			}
		}
	}
	if len(out) > 1 {
		sort.SliceStable(out, func(i, j int) bool { return findingLess(out[i], out[j]) })
	}
	return out
}

var reLowAssurance = regexp.MustCompile(`(?i)(?:^|/)(?:tests?|__tests__|testdata|spec|specs?|__mocks__|fixtures?|examples?|sample|samples|demos?|benchmarks?|bench|perf|vendor|third_party|3rdparty|node_modules|\.storybook)(?:/|$)|(?:^|/)docs?/|[._-](?:test|spec|stories|fixture|bench)\.[a-z0-9]+$|[._/]min\.[a-z]+$`)

func lowAssurancePath(path string) bool { return reLowAssurance.MatchString(path) }

var proseExts = map[string]bool{
	".md": true, ".markdown": true, ".mdx": true, ".rst": true,
	".adoc": true, ".asciidoc": true, ".textile": true, ".pod": true,
}

func proseFile(path string) bool {
	p := strings.ToLower(path)
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.LastIndexByte(p, '.'); i >= 0 {
		return proseExts[p[i:]]
	}
	return false
}

var proseKeepCWE = map[string]bool{
	"CWE-798": true,
	"CWE-321": true,
	"CWE-259": true,
	"CWE-540": true,
}

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
	"spawn(", "create_subprocess", "createdecipher", "fromstring",
	"jsonpickle", "cloudpickle",
}

func (kb *KB) securityRelevant(path, content string) bool {
	if content == "" {
		return false
	}
	if len(content) > maxScanBytes {
		content = content[:maxScanBytes]
	}
	lc := asciiLower(content)
	for _, t := range sinkTokens {
		if strings.Contains(lc, t) {
			return true
		}
	}
	return false
}

func (kb *KB) scanAgnostic(content string) []Finding {
	if content == "" {
		return nil
	}
	if len(content) > maxScanBytes {
		content = content[:maxScanBytes]
	}
	lc := asciiLower(content)
	var out []Finding
	lastRi, skipRule := -1, false
	for _, ix := range patsAny {
		if ix.ri != lastRi {
			lastRi, skipRule = ix.ri, false
		}
		if skipRule {
			continue
		}
		r := &kb.Rules[ix.ri]
		pat := &r.Patterns[ix.pi]
		if pat.prefilter != nil && prefilterMiss(pat.prefilter, lc) {
			continue
		}
		if pat.match(content) {
			out = append(out, Finding{Rule: r, Confidence: pat.Confidence})
			skipRule = true
		}
	}
	for i := len(generatedRules); i < len(kb.Rules); i++ {
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
	if len(out) > 1 {
		sort.SliceStable(out, func(i, j int) bool { return findingLess(out[i], out[j]) })
	}
	return out
}

func (kb *KB) classify(prompt string) []*Rule {
	text := strings.ToLower(prompt)
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
		if j, ok := idx[r.CWE]; ok {
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

func (kb *KB) wordIn(text, kw string) bool {
	if kw == "" {
		return false
	}
	if strings.ContainsAny(kw, " ") {
		return strings.Contains(text, kw)
	}
	for start := 0; start <= len(text); {
		i := strings.Index(text[start:], kw)
		if i < 0 {
			return false
		}
		i += start
		leftOK := i == 0 || !isWordByte(text[i-1])
		r := i + len(kw)
		rightOK := r == len(text) || !isWordByte(text[r])
		if leftOK && rightOK {
			return true
		}
		start = i + 1
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

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

func loadKB() *KB {
	return &KB{Rules: generatedRules}
}

func (kb *KB) initPrefilters() {
	for i := range kb.Rules {
		for j := range kb.Rules[i].Patterns {
			p := &kb.Rules[i].Patterns[j]
			if p.prefilter != nil {
				continue
			}
			p.prefilter = requiredLiterals(p.Re)
		}
	}
}

func prefilterMiss(prefilter []string, lc string) bool {
	for _, lit := range prefilter {
		if strings.Contains(lc, lit) {
			return false
		}
	}
	return true
}

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
				if kb.userCount == 0 {
					nr := make([]Rule, len(kb.Rules), len(kb.Rules)+maxUserRules)
					copy(nr, kb.Rules)
					kb.Rules = nr
				}
				kb.Rules = append(kb.Rules, r)
				kb.userCount++
			}
		}
	}
	if kb.userCount > 0 {
		kb.initPrefilters()
	}
}

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
unwritten, is a failure; born-secure code that fulfills the request is the goal.`

func ladderFor(mode string) string {
	switch mode {
	case "audit":
		return ladder + " Mode is audit: findings are logged and the write is allowed."
	case "guided":
		return ladder + " Mode is guided: high-confidence CWE patterns will ASK before the write."
	default:
		return ladder + " In strict/hardened mode, high-confidence CWE patterns are DENIED at write time - write it secure the first time."
	}
}
