package main

import (
	"regexp"
	"strings"
)

// Intra-file local taint (framework-level cross-line detection).
//
// The single-line presence patterns miss the shape where a dangerous value is
// built into a VARIABLE on one line and passed to a sink on another:
//
//	tmpl = f"Hello {request.args['name']}"     # tainted assignment
//	return render_template_string(tmpl)        # sink, different line
//
// This pass tracks two taint kinds per variable and flags when a tainted
// variable reaches a sink. It generalizes across every injection class (SSTI,
// SQLi, command, code-eval, deserialization, XSS), not one rule. It is strictly
// ADDITIVE: it only appends findings and never changes existing rule behavior.
// Because it checks the ACTUAL variable in the sink (not proximity), an
// unrelated dynamic string near a static-const sink does not misfire.
//
//   user = variable traces to user-controlled input (request/input/argv/env/...).
//   dyn  = variable holds a dynamically-built string (f-string / template-literal
//          interpolation, string concat/format/%).
//
// Propagation follows real code references only: interpolation contents of
// f-strings and template literals, and concatenation — never identifiers that
// merely appear inside a plain string literal (so a static Jinja template
// "Hi {{ name }}" does not taint through the word "name"). Assignments are
// processed in order so a later sanitizer re-assignment (int()/shlex.quote()/
// escape()/...) clears the taint. SQL and deserialization require `user` taint
// (a bound-parameter or int-cast value is safe); the higher-danger sinks
// (SSTI/eval/command/XSS) also fire on `dyn` alone, since those sinks should
// never receive a dynamically-built string.

var (
	tlWord   = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	tlAssign = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_$][\w$]*)\s*(?::=|=)\s*(.+)$`)

	// A quoted string literal with an optional prefix (f/r/b/u...), plus JS
	// template literals. Used to strip literal text before reference extraction.
	tlStrLit = regexp.MustCompile("([fFrRbBuU]*)(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*')|(`(?:[^`\\\\]|\\\\.)*`)")
	tlInterp = regexp.MustCompile(`[{$]\{?([^{}]+)\}`)

	// RHS traces to user-controlled input (evaluated on the de-stringed RHS).
	tlSource = regexp.MustCompile(`request\b|\.args\b|\.form\b|\.values\b|\.get_json\b|\.cookies\b|\.headers\b|\binput\s*\(|sys\.argv|os\.environ|getenv\s*\(|\.read\s*\(|\breq\.(?:query|body|params)\b|process\.argv|process\.env`)
	// RHS builds a dynamic string (evaluated on the RAW RHS: needs the quotes).
	tlDynStr = regexp.MustCompile("f[\"'][^\"'\\n]*\\{[^}\\n]*\\}|`[^`]*\\$\\{|[\"'][^\"'\\n]*[\"']\\s*[+%]|\\+\\s*[frbu]*[\"']|\\.format\\s*\\(|%\\s*[A-Za-z_(]")
	// RHS is sanitized/cast: clears taint.
	tlSanitizer = regexp.MustCompile(`^\s*(?:int|float|bool)\s*\(|shlex\.quote|\bescape\s*\(|markupsafe|bleach\.|re\.escape|secure_filename|\bquote_plus\b|urllib\.parse\.quote|encodeURIComponent`)

	// An identifier that IS a secret/PII by name (whole word or trailing segment,
	// so token_count / secretariat are not swept in). Feeds CWE-532.
	tlSensName = regexp.MustCompile(`(?i)(?:^|_)(?:password|passwd|pwd|secret|apikey|api_?key|access_?token|auth_?token|private_?key|credentials?|creds|cvv|ssn|session_?token|client_?secret|refresh_?token|bearer)(?:_?(?:value|str|plain|raw))?$`)
	// RHS reads a secret/PII from a real source, or dumps the whole environment.
	tlSensSource = regexp.MustCompile(`(?i)getpass|\.headers\.get\(\s*["']authorization|request\.headers\[["']authorization|\.form\[["'](?:password|token|secret)|os\.environ(?:\.get\()?\[?["'][A-Z_]*(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY|CRED)|dict\(\s*os\.environ|\{\s*\*\*\s*os\.environ`)
	// Redaction clears sensitivity (masked / hashed before logging).
	tlRedact = regexp.MustCompile(`(?i)redact|mask|\bsha\d|hashlib|\*{3,}|\[:\d\]|truncate|last4`)
	// Log sinks: the whole argument text is captured for reference scanning.
	tlLogSink = regexp.MustCompile(`(?i)(?:log(?:ger|ging)?)\.(?:info|debug|warning|warn|error|critical|exception|log)\s*\(([^\n]*)|(?:^|[^.\w])print\s*\(([^\n]*)|console\.(?:log|debug|info|warn|error|trace)\s*\(([^\n]*)`)
	// Network sinks (whole arg text captured): a sensitive value in the body is
	// exfiltration (CWE-200).
	tlNetSink = regexp.MustCompile(`(?i)requests\.(?:post|put|patch|get)\s*\(([^\n]*)|httpx\.(?:post|put|patch|get)\s*\(([^\n]*)|urllib\.request\.urlopen\s*\(([^\n]*)|\.post\s*\(([^\n]*)|fetch\s*\(([^\n]*)`)
)

// tlRefs returns the RHS with plain string-literal bodies removed but the
// interpolation contents of f-strings and template literals preserved, so
// reference extraction sees real variable references only.
func tlRefs(rhs string) string {
	return tlStrLit.ReplaceAllStringFunc(rhs, func(s string) string {
		m := tlStrLit.FindStringSubmatch(s)
		prefix, quoted, backtick := m[1], m[2], m[3]
		if backtick != "" || strings.ContainsAny(prefix, "fF") {
			var b strings.Builder
			for _, mm := range tlInterp.FindAllStringSubmatch(quoted+backtick, -1) {
				b.WriteByte(' ')
				b.WriteString(mm[1])
			}
			return b.String()
		}
		return " "
	})
}

// tlSink is a dangerous call/assignment whose argument variable, when tainted,
// is a vulnerability. re captures the argument identifier in group 1.
type tlSink struct {
	cwe  string
	lang string // "python" | "javascript" | "" (any)
	dyn  bool   // also fire when the arg is a dynamically-built string
	user bool   // fire when the arg is user-derived
	re   *regexp.Regexp
}

var tlSinks = []tlSink{
	{"CWE-1336", "python", true, true, regexp.MustCompile(`render_template_string\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	{"CWE-1336", "python", true, true, regexp.MustCompile(`(?:Template|from_string)\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	{"CWE-94", "python", true, true, regexp.MustCompile(`\beval\s*\(\s*([A-Za-z_]\w*)\s*\)`)},
	{"CWE-94", "python", true, true, regexp.MustCompile(`\bexec\s*\(\s*([A-Za-z_]\w*)\s*\)`)},
	{"CWE-78", "python", true, true, regexp.MustCompile(`os\.system\s*\(\s*([A-Za-z_]\w*)\s*\)`)},
	{"CWE-78", "python", true, true, regexp.MustCompile(`os\.popen\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	// SQLi: bound params / int-cast are safe, so require user taint, not dyn.
	{"CWE-89", "python", false, true, regexp.MustCompile(`\.execute(?:many|script)?\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	// Deserialization: the risk is untrusted bytes, not a dynamic string.
	{"CWE-502", "python", false, true, regexp.MustCompile(`yaml\.load\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	{"CWE-502", "python", false, true, regexp.MustCompile(`(?:pickle|cPickle|_pickle)\.loads?\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	{"CWE-502", "python", false, true, regexp.MustCompile(`marshal\.loads?\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},

	// SSRF: the whole request URL is a user-controlled variable.
	{"CWE-918", "python", false, true, regexp.MustCompile(`(?:requests\.(?:get|post|put|patch|delete|head|request)|httpx\.(?:get|post|stream|request)|urllib\.request\.urlopen|urlopen)\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	// Path traversal: a user-controlled path into a file op.
	{"CWE-22", "python", false, true, regexp.MustCompile(`(?:open|send_file|send_from_directory)\s*\(\s*([A-Za-z_]\w*)\s*[,)]`)},
	// Open redirect: a user-controlled redirect target.
	{"CWE-601", "python", false, true, regexp.MustCompile(`\bredirect\s*\(\s*([A-Za-z_]\w*)\s*\)`)},

	{"CWE-94", "javascript", true, true, regexp.MustCompile(`\beval\s*\(\s*([A-Za-z_$][\w$]*)\s*\)`)},
	{"CWE-79", "javascript", true, true, regexp.MustCompile(`\.(?:innerHTML|outerHTML)\s*=\s*([A-Za-z_$][\w$]*)\b`)},
	{"CWE-79", "javascript", true, true, regexp.MustCompile(`document\.write\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]`)},
	{"CWE-78", "javascript", true, true, regexp.MustCompile(`child_process\.exec\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]`)},
	{"CWE-918", "javascript", false, true, regexp.MustCompile(`(?:fetch|axios(?:\.\w+)?)\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]`)},
	{"CWE-601", "javascript", false, true, regexp.MustCompile(`\.redirect\s*\(\s*([A-Za-z_$][\w$]*)\s*\)`)},
}

// tlRules are synthetic Rule descriptors the taint findings attribute to.
var tlRules = map[string]*Rule{
	"CWE-1336": {CWE: "CWE-1336", Name: "Server-Side Template Injection (tainted template variable)", Severity: "critical", OWASP: []string{"A03"}, KEV: true},
	"CWE-94":   {CWE: "CWE-94", Name: "Code Injection (tainted variable into eval/exec)", Severity: "critical", OWASP: []string{"A03"}},
	"CWE-78":   {CWE: "CWE-78", Name: "OS Command Injection (tainted variable into shell sink)", Severity: "critical", OWASP: []string{"A03"}},
	"CWE-89":   {CWE: "CWE-89", Name: "SQL Injection (user-derived query variable)", Severity: "critical", OWASP: []string{"A03"}},
	"CWE-502":  {CWE: "CWE-502", Name: "Unsafe Deserialization (user-controlled input)", Severity: "critical", OWASP: []string{"A08"}},
	"CWE-79":   {CWE: "CWE-79", Name: "Cross-Site Scripting (tainted variable into HTML sink)", Severity: "high", OWASP: []string{"A03"}},
	"CWE-918":  {CWE: "CWE-918", Name: "SSRF (user-controlled URL into a network fetch)", Severity: "high", OWASP: []string{"A10"}},
	"CWE-22":   {CWE: "CWE-22", Name: "Path Traversal (user-controlled path into a file op)", Severity: "high", OWASP: []string{"A01"}},
	"CWE-601":  {CWE: "CWE-601", Name: "Open Redirect (user-controlled redirect target)", Severity: "medium", OWASP: []string{"A01"}},
	"CWE-532":  {CWE: "CWE-532", Name: "Sensitive Data in Logs (secret/PII into a log sink)", Severity: "medium", OWASP: []string{"A09"}},
	"CWE-200":  {CWE: "CWE-200", Name: "Sensitive/Environment Exfiltration (secret into a network sink)", Severity: "critical", OWASP: []string{"A01"}},
}

// tlTaint computes the user/dyn/sens taint sets for a file. user = derived from
// user input; dyn = a dynamically-built string; sens = a secret/PII/environment
// value. A sanitizer (int()/shlex.quote()/escape()) neutralizes user/dyn; a
// redaction (mask/hash/truncate) neutralizes sens.
func tlTaint(content string) (user, dyn, sens map[string]bool) {
	user, dyn, sens = map[string]bool{}, map[string]bool{}, map[string]bool{}
	assigns := tlAssign.FindAllStringSubmatch(content, -1)
	if len(assigns) == 0 {
		return
	}
	set := func(m map[string]bool, k string, v bool, changed *bool) {
		if m[k] != v {
			if v {
				m[k] = true
			} else {
				delete(m, k)
			}
			*changed = true
		}
	}
	for pass := 0; pass < 4; pass++ {
		changed := false
		for _, m := range assigns {
			lhs, rhs := m[1], m[2]
			refs := tlRefs(rhs)
			// An assignment OVERWRITES the variable: its taint is computed FRESH
			// from the RHS, not OR-ed with the variable's prior state. So a
			// constant/validated/sanitized reassignment (target = "/",
			// url = shlex.quote(url), pw = mask(pw)) correctly clears the taint.
			var nu, nd, ns bool
			if !tlSanitizer.MatchString(rhs) { // sanitizer neutralizes injection
				if tlSource.MatchString(refs) {
					nu = true
				}
				if tlDynStr.MatchString(rhs) {
					nd = true
				}
				for _, id := range tlWord.FindAllString(refs, -1) {
					if user[id] {
						nu = true
					}
					if dyn[id] {
						nd = true
					}
				}
			}
			if !tlRedact.MatchString(rhs) { // redaction/hashing de-sensitizes
				// sensitive SOURCE keys live inside string literals
				// (request.form['password']), so match the raw RHS, not refs.
				if tlSensName.MatchString(lhs) || tlSensSource.MatchString(rhs) {
					ns = true
				}
				for _, id := range tlWord.FindAllString(refs, -1) {
					if sens[id] {
						ns = true
					}
				}
			}
			set(user, lhs, nu, &changed)
			set(dyn, lhs, nd, &changed)
			set(sens, lhs, ns, &changed)
		}
		if !changed {
			break
		}
	}
	return
}

// tlArgScan reports whether any sink call (matched by re, whose capture groups
// hold the call's argument text) carries a sensitive reference — a sens-tainted
// variable or an identifier that is a secret by name — and is not redacted.
func tlArgScan(content string, re *regexp.Regexp, sens map[string]bool) bool {
	for _, m := range re.FindAllStringSubmatch(content, -1) {
		args := strings.Join(m[1:], "")
		if args == "" || tlRedact.MatchString(args) {
			continue
		}
		for _, id := range tlWord.FindAllString(tlRefs(args), -1) {
			if sens[id] || tlSensName.MatchString(id) {
				return true
			}
		}
	}
	return false
}

// taintScan returns cross-line taint findings for sinks fed a tainted variable.
// have holds CWEs already reported by the presence patterns, so the same class
// is not double-flagged on one file.
func (kb *KB) taintScan(lang, content string, have map[string]bool) []Finding {
	if content == "" || (lang != "python" && lang != "javascript" && lang != "") {
		return nil
	}
	user, dyn, sens := tlTaint(content)
	var out []Finding
	seen := map[string]bool{}
	add := func(cwe string) {
		if !have[cwe] && !seen[cwe] {
			if r := tlRules[cwe]; r != nil {
				// Provability calibration: a dynamically-built string reaching
				// SSTI/SQLi/eval is unsafe regardless of any guard -> deny. A
				// user value reaching SSRF / redirect / a file path is commonly
				// validated by control flow a pattern engine cannot see, so it
				// asks (defers to the human) rather than hard-denying.
				conf := "high"
				if tlAskSink[cwe] {
					conf = "medium"
				}
				out = append(out, Finding{Rule: r, Confidence: conf})
				seen[cwe] = true
			}
		}
	}
	for i := range tlSinks {
		s := &tlSinks[i]
		if s.lang != "" && lang != "" && s.lang != lang {
			continue
		}
		if have[s.cwe] || seen[s.cwe] {
			continue
		}
		for _, m := range s.re.FindAllStringSubmatch(content, -1) {
			v := m[1]
			if (s.user && user[v]) || (s.dyn && dyn[v]) {
				add(s.cwe)
				break
			}
		}
	}
	// Whole-arglist sinks: a secret/PII into a log sink (CWE-532) or a network
	// sink (CWE-200, exfiltration). tlArgScan also matches secrets by name, so
	// these run even when no assignment produced a sens variable.
	if tlArgScan(content, tlLogSink, sens) {
		add("CWE-532")
	}
	if tlArgScan(content, tlNetSink, sens) {
		add("CWE-200")
	}
	return out
}

// tlAskSink: taint findings whose exploitability depends on a validation guard a
// pattern engine cannot see -> ask (defer to human), not deny.
var tlAskSink = map[string]bool{"CWE-918": true, "CWE-22": true, "CWE-601": true}

// tlHave collects the CWEs present in a finding slice (for dedup).
func tlHave(fs []Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[f.Rule.CWE] = true
	}
	return m
}
