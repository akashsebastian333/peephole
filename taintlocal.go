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
	tlWord = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	// group 1 = variable, group 2 = augmenting op (empty for plain = / :=), group 3
	// = RHS. An optional const/let/var lets JS/TS declarations bind the real
	// variable (const q = ...) instead of the keyword; \s+ after it means a name
	// like `constant` is not mistaken for the keyword. Capturing the op lets an
	// augmented assign (cmd += user, q .= $_GET) accumulate taint instead of the
	// plain-= overwrite that laundered it clean.
	tlAssign = regexp.MustCompile(`(?m)^[ \t]*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?:([-+*/%|&^.]?)=|:=)\s*(.+)$`)

	// A quoted string literal with an optional prefix (f/r/b/u...), plus JS
	// template literals. Used to strip literal text before reference extraction.
	tlStrLit = regexp.MustCompile("([fFrRbBuU]*)(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*')|(`(?:[^`\\\\]|\\\\.)*`)")
	tlInterp = regexp.MustCompile(`[{$]\{?([^{}]+)\}`)

	// RHS traces to user-controlled (request) input, evaluated on the de-stringed
	// RHS. Env vars (os.environ/getenv/process.env) and a bare .read() are NOT
	// request taint - they are operator config and local file/stream reads, and
	// treating them as user input painted ordinary vars (VERSION, cwd, config)
	// tainted, which then tripped every f-string that referenced them. Secret env
	// reads are still covered separately by tlSensSource (CWE-532).
	tlSource = regexp.MustCompile(`request\b|\.args\b|\.form\b|\.get_json\b|\.cookies\b|\binput\s*\(|sys\.argv|\breq\.(?:query|body|params)\b|process\.argv`)
	// RHS builds a dynamic string (evaluated on the RAW RHS: needs the quotes).
	tlDynStr = regexp.MustCompile("f[\"'][^\"'\\n]*\\{[^}\\n]*\\}|`[^`]*\\$\\{|[\"'][^\"'\\n]*[\"']\\s*[+%]|\\+\\s*[frbu]*[\"']|\\.format\\s*\\(|%\\s*[A-Za-z_(]")
	// RHS is sanitized/cast: clears taint.
	tlSanitizer = regexp.MustCompile(`^\s*(?:int|float|bool)\s*\(|shlex\.quote|\bescape\s*\(|markupsafe|bleach\.|re\.escape|secure_filename|\bquote_plus\b|urllib\.parse\.quote|encodeURIComponent`)
	// A sanitizer applied to an argument, so the wrapped (safe) sub-expression can
	// be removed before deciding whether a RAW tainted value still reaches the sink.
	// One level of nested parens is handled (secure_filename(request.args.get('x')));
	// deeper nesting is best-effort. Defuses sanitizer-spoofing, where a decoy
	// sanitizer on one sub-expression cleared the taint of a raw one beside it.
	tlSanitizerCall = regexp.MustCompile(`(?:\bint|\bfloat|\bbool|shlex\.quote|\bescape|\bmarkupsafe\.\w+|\bbleach\.\w+|re\.escape|\bsecure_filename|\bquote_plus|urllib\.parse\.quote|\bencodeURIComponent)\s*\((?:[^()]|\([^()]*\))*\)`)

	// An identifier that IS a secret/PII by name (whole word or trailing segment,
	// so token_count / secretariat are not swept in). Feeds CWE-532.
	tlSensName = regexp.MustCompile(`(?i)(?:^|_)(?:password|passwd|pwd|secret|apikey|api_?key|access_?token|auth_?token|private_?key|credentials?|creds|cvv|ssn|session_?token|client_?secret|refresh_?token|bearer)(?:_?(?:value|str|plain|raw))?$`)
	// RHS reads a secret/PII from a real source, or dumps the whole environment.
	tlSensSource = regexp.MustCompile(`(?i)getpass|\.headers\.get\(\s*["']authorization|request\.headers\[["']authorization|\.form\[["'](?:password|token|secret)|os\.environ(?:\.get\()?\[?["'][A-Z_]*(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY|CRED)|dict\(\s*os\.environ|\{\s*\*\*\s*os\.environ`)
	// Redaction clears sensitivity (masked / hashed before logging).
	tlRedact = regexp.MustCompile(`(?i)redact|mask|\bsha\d|hashlib|\*{3,}|\[:\d\]|truncate|last4`)
	// An f-string field using an !r/!s/!a conversion is a repr/debug rendering
	// (a __repr__ body, a "python -m {mod!r}" message), not raw HTML/response
	// output - so it is not reflected XSS. Applied only to reflected-output specs
	// (see taintSpecHits), never to secret-logging where a repr still leaks.
	tlReprConv = regexp.MustCompile(`![rsa][}:]`)
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

// TaintSpec is one declarative taint rule: which sink patterns, which taint
// kinds trigger them, and how to report. Specs live as data in taint/*.json and
// are compiled into generatedTaintSpecs by cmd/kbgen — adding a class is a JSON
// file plus exemplars, never new engine code.
//
//	mode "arg":  each sink regex captures the argument identifier in group 1;
//	             the finding fires when that variable carries a triggering taint.
//	mode "call": the sink regex captures the whole argument text; the finding
//	             fires when any sensitive reference appears in it (log / exfil).
type taintSinkPat struct {
	Lang      string // "python" | "javascript" | "" (any)
	Re        string
	re        *regexp.Regexp
	prefilter []string // lowercase literals, one of which must be present; nil = always run
}

type TaintSpec struct {
	CWE, Name, Severity string
	OWASP               []string
	KEV                 bool
	Mode                string   // "arg" | "call"
	Triggers            []string // subset of "user","dyn","sens"
	Confidence          string   // "high" (deny) | "medium" (ask)
	Sinks               []taintSinkPat
	Noncompliant        string
	Compliant           string

	rule                     *Rule
	tUser, tDyn, tSens, done bool
}

// prep compiles the spec's sink patterns and derives its trigger flags and Rule
// once, on first use.
func (s *TaintSpec) prep() {
	if s.done {
		return
	}
	s.done = true
	for _, t := range s.Triggers {
		switch t {
		case "user":
			s.tUser = true
		case "dyn":
			s.tDyn = true
		case "sens":
			s.tSens = true
		}
	}
	for i := range s.Sinks {
		if re, err := regexp.Compile(s.Sinks[i].Re); err == nil {
			s.Sinks[i].re = re
		}
		// literal prefilter: skip the whole taint pass on files that cannot
		// contain this sink (keeps large sink-free files off the taint path).
		s.Sinks[i].prefilter = requiredLiterals(s.Sinks[i].Re)
	}
	s.rule = &Rule{CWE: s.CWE, Name: s.Name, Severity: s.Severity, OWASP: s.OWASP, KEV: s.KEV}
}

// taintSpecHits reports whether the spec's sinks are fed a triggering taint.
func taintSpecHits(s *TaintSpec, lang, lc, content string, user, dyn, sens map[string]bool) bool {
	for i := range s.Sinks {
		sp := &s.Sinks[i]
		if sp.re == nil || (sp.Lang != "" && lang != "" && sp.Lang != lang) {
			continue
		}
		if sp.prefilter != nil && prefilterMiss(sp.prefilter, lc) {
			continue // sink's required literal absent
		}
		if s.Mode == "call" {
			// whole-arglist scan: fire when any reference in the captured text is
			// tainted per THIS spec's triggers (sens for log/exfil, user for a
			// reflected value returned to the client, etc.), and not redacted.
			for _, m := range sp.re.FindAllStringSubmatch(content, -1) {
				args := strings.Join(m[1:], "")
				// output-encoding / redaction in the sink clears it (escape() for a
				// returned value, mask()/hash() for a logged secret).
				if args == "" || tlRedact.MatchString(args) || tlSanitizer.MatchString(args) {
					continue
				}
				if s.tUser && !s.tSens && tlReprConv.MatchString(args) {
					continue // repr/debug rendering (!r/!s), not raw response output
				}
				for _, id := range tlWord.FindAllString(tlRefs(args), -1) {
					if (s.tSens && (sens[id] || tlSensName.MatchString(id))) ||
						(s.tUser && user[id]) || (s.tDyn && dyn[id]) {
						return true
					}
				}
			}
			continue
		}
		for _, m := range sp.re.FindAllStringSubmatch(content, -1) {
			v := m[1]
			if (s.tUser && user[v]) || (s.tDyn && dyn[v]) || (s.tSens && sens[v]) {
				return true
			}
		}
	}
	return false
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
			lhs, op, rhs := m[1], m[2], m[3]
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
			// A raw source or a previously-tainted var used OUTSIDE any sanitizer call
			// keeps its taint even when a decoy sanitizer wraps a different
			// sub-expression (cmd = "x " + shlex.quote(a) + user_raw). Only user taint:
			// the value genuinely reaches the sink unsanitized. Removing the
			// sanitizer-wrapped spans first means the legitimate wrapped form
			// (secure_filename(user)) still clears.
			if !nu {
				cleanRefs := tlRefs(tlSanitizerCall.ReplaceAllString(rhs, " "))
				if tlSource.MatchString(cleanRefs) {
					nu = true
				} else {
					for _, id := range tlWord.FindAllString(cleanRefs, -1) {
						if user[id] {
							nu = true
							break
						}
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
			// An augmented assignment (cmd += x, q .= $_GET) ACCUMULATES: unlike a
			// plain =, it keeps the variable's prior taint and only adds the RHS's,
			// so `cmd = "ping "; cmd += user; os.system(cmd)` stays tainted instead
			// of being laundered clean by the second line.
			if op != "" {
				nu = nu || user[lhs]
				nd = nd || dyn[lhs]
				ns = ns || sens[lhs]
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

// taintScan returns cross-line taint findings for sinks fed a tainted variable.
// have holds CWEs already reported by the presence patterns, so the same class
// is not double-flagged on one file.
func (kb *KB) taintScan(lang, content, lc string, have map[string]bool) []Finding {
	if content == "" || (lang != "python" && lang != "javascript" && lang != "") {
		return nil
	}
	// lc is the caller-lowercased content (avoids a second pass)
	// Fast path: if no sink's literal prefilter survives, no taint finding is
	// possible - skip the whole pass (and its O(assignments) taint computation)
	// so large sink-free files stay cheap.
	if !anyTaintSinkPresent(lang, lc) {
		return nil
	}
	user, dyn, sens := tlTaint(content)
	var out []Finding
	seen := map[string]bool{}
	for i := range generatedTaintSpecs {
		s := &generatedTaintSpecs[i]
		s.prep()
		if s.rule == nil || have[s.CWE] || seen[s.CWE] {
			continue
		}
		if taintSpecHits(s, lang, lc, content, user, dyn, sens) {
			out = append(out, Finding{Rule: s.rule, Confidence: s.Confidence})
			seen[s.CWE] = true
		}
	}
	return out
}

// anyTaintSinkPresent reports whether any spec sink's prefilter literal is in the
// (lowercased) content for this language - the cheap gate before tlTaint runs.
func anyTaintSinkPresent(lang, lc string) bool {
	for i := range generatedTaintSpecs {
		s := &generatedTaintSpecs[i]
		s.prep()
		for j := range s.Sinks {
			sp := &s.Sinks[j]
			if sp.re == nil || (sp.Lang != "" && lang != "" && sp.Lang != lang) {
				continue
			}
			if sp.prefilter == nil || !prefilterMiss(sp.prefilter, lc) {
				return true
			}
		}
	}
	return false
}

// tlHave collects the CWEs present in a finding slice (for dedup).
func tlHave(fs []Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[f.Rule.CWE] = true
	}
	return m
}
