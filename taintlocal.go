package main

import (
	"regexp"
	"strings"
)

var (
	tlWord   = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	tlAssign = regexp.MustCompile(`(?m)^[ \t]*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)(?:\s*,\s*[A-Za-z_$][\w$]*)*\s*(?:([-+*/%|&^.]?)=|:=)\s*(.+)$`)
	tlPush   = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_$][\w$]*)\.push_str\(\s*&?(.+?)\s*\)\s*;?\s*$`)

	tlStrLit = regexp.MustCompile("([fFrRbBuU]*)(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*')|(`(?:[^`\\\\]|\\\\.)*`)")
	tlInterp = regexp.MustCompile(`[{$]\{?([^{}]+)\}`)

	tlSource        = regexp.MustCompile(`request\b|\.args\b|\.form\b|\.get_json\b|\.cookies\b|\binput\s*\(|sys\.argv|\breq\.(?:query|body|params)\b|process\.argv|\.FormValue\(|\.PostFormValue\(|\.PathValue\(|\.URL\.Query\(|chi\.URLParam|mux\.Vars|web::(?:Query|Path|Form)|extract::(?:Query|Path|Form)`)
	tlDynStr        = regexp.MustCompile("f[\"'][^\"'\\n]*\\{[^}\\n]*\\}|`[^`]*\\$\\{|[\"'][^\"'\\n]*[\"']\\s*[+%]|\\+\\s*[frbu]*[\"']|\\.format\\s*\\(|%\\s*[A-Za-z_(]|fmt\\.Sprintf|format!\\s*\\(")
	tlSanitizer     = regexp.MustCompile(`^\s*(?:int|float|bool)\s*\(|shlex\.quote|\bescape\s*\(|markupsafe|bleach\.|re\.escape|secure_filename|\bquote_plus\b|urllib\.parse\.quote|encodeURIComponent|strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat)|html\.EscapeString|url\.(?:QueryEscape|PathEscape)|html_escape|\.parse::<(?:i|u)\d+>`)
	tlSanitizerCall = regexp.MustCompile(`(?:\bint|\bfloat|\bbool|shlex\.quote|\bescape|\bmarkupsafe\.\w+|\bbleach\.\w+|re\.escape|\bsecure_filename|\bquote_plus|urllib\.parse\.quote|\bencodeURIComponent|strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat)|html\.EscapeString|url\.(?:QueryEscape|PathEscape))\s*\((?:[^()]|\([^()]*\))*\)`)

	tlSensName   = regexp.MustCompile(`(?i)(?:^|_)(?:password|passwd|pwd|secret|apikey|api_?key|access_?token|auth_?token|private_?key|credentials?|creds|cvv|ssn|session_?token|client_?secret|refresh_?token|bearer)(?:_?(?:value|str|plain|raw))?$`)
	tlSensSource = regexp.MustCompile(`(?i)getpass|\.headers\.get\(\s*["']authorization|request\.headers\[["']authorization|\.form\[["'](?:password|token|secret)|os\.environ(?:\.get\()?\[?["'][A-Z_]*(?:SECRET|TOKEN|PASSWORD|API_?KEY|PRIVATE_?KEY|CRED)|dict\(\s*os\.environ|\{\s*\*\*\s*os\.environ`)
	tlRedact     = regexp.MustCompile(`(?i)redact|mask|\bsha\d|hashlib|\*{3,}|\[:\d\]|truncate|last4`)
	tlReprConv   = regexp.MustCompile(`![rsa][}:]`)
)

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

type taintSinkPat struct {
	Lang      string
	Re        string
	re        *regexp.Regexp
	prefilter []string
}

type TaintSpec struct {
	CWE, Name, Severity string
	OWASP               []string
	KEV                 bool
	Mode                string
	Triggers            []string
	Confidence          string
	Sinks               []taintSinkPat
	Noncompliant        string
	Compliant           string

	rule                     *Rule
	tUser, tDyn, tSens, done bool
}

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
		s.Sinks[i].prefilter = requiredLiterals(s.Sinks[i].Re)
	}
	s.rule = &Rule{CWE: s.CWE, Name: s.Name, Severity: s.Severity, OWASP: s.OWASP, KEV: s.KEV}
}

func taintSpecHits(s *TaintSpec, lang, lc, content string, user, dyn, sens map[string]bool) bool {
	for i := range s.Sinks {
		sp := &s.Sinks[i]
		if sp.re == nil || (sp.Lang != "" && lang != "" && sp.Lang != lang) {
			continue
		}
		if sp.prefilter != nil && prefilterMiss(sp.prefilter, lc) {
			continue
		}
		if s.Mode == "call" {
			if taintCallHits(sp.re, content, s, user, dyn, sens) {
				return true
			}
			continue
		}
		if taintArgHits(sp.re, content, s, user, dyn, sens) {
			return true
		}
	}
	return false
}

func taintArgHits(re *regexp.Regexp, content string, s *TaintSpec, user, dyn, sens map[string]bool) bool {
	start := 0
	for start <= len(content) {
		loc := re.FindStringSubmatchIndex(content[start:])
		if loc == nil {
			return false
		}
		if len(loc) >= 4 && loc[2] >= 0 {
			v := content[start+loc[2] : start+loc[3]]
			if (s.tUser && user[v]) || (s.tDyn && dyn[v]) || (s.tSens && sens[v]) {
				return true
			}
		}
		if loc[1] == 0 {
			start++
			continue
		}
		start += loc[1]
	}
	return false
}

func taintCallHits(re *regexp.Regexp, content string, s *TaintSpec, user, dyn, sens map[string]bool) bool {
	start := 0
	for start <= len(content) {
		loc := re.FindStringSubmatchIndex(content[start:])
		if loc == nil {
			return false
		}
		var b strings.Builder
		for g := 1; g < len(loc)/2; g++ {
			a, z := loc[2*g], loc[2*g+1]
			if a >= 0 && z >= a {
				b.WriteString(content[start+a : start+z])
			}
		}
		args := b.String()
		if args != "" && !tlRedact.MatchString(args) && !tlSanitizer.MatchString(args) {
			if !(s.tUser && !s.tSens && tlReprConv.MatchString(args)) {
				for _, id := range tlWord.FindAllString(tlRefs(args), -1) {
					if (s.tSens && (sens[id] || tlSensName.MatchString(id))) ||
						(s.tUser && user[id]) || (s.tDyn && dyn[id]) {
						return true
					}
				}
			}
		}
		if loc[1] == 0 {
			start++
			continue
		}
		start += loc[1]
	}
	return false
}

func tlTaint(content string) (user, dyn, sens map[string]bool) {
	user, dyn, sens = map[string]bool{}, map[string]bool{}, map[string]bool{}
	assigns := tlAssign.FindAllStringSubmatch(content, -1)
	for _, m := range tlPush.FindAllStringSubmatch(content, -1) {
		assigns = append(assigns, []string{m[0], m[1], "+", m[2]})
	}
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
			var nu, nd, ns bool
			if !tlSanitizer.MatchString(rhs) {
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
			if !tlRedact.MatchString(rhs) {
				if tlSensName.MatchString(lhs) || tlSensSource.MatchString(rhs) {
					ns = true
				}
				for _, id := range tlWord.FindAllString(refs, -1) {
					if sens[id] {
						ns = true
					}
				}
			}
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

func (kb *KB) taintScan(lang, content, lc string, have map[string]bool) []Finding {
	if content == "" || (lang != "python" && lang != "javascript" && lang != "go" && lang != "rust" && lang != "") {
		return nil
	}
	if !anyTaintSinkPresent(lang, lc) {
		return nil
	}
	user, dyn, sens := tlTaint(content)
	noFlow := len(user) == 0 && len(dyn) == 0
	var out []Finding
	seen := map[string]bool{}
	for i := range generatedTaintSpecs {
		s := &generatedTaintSpecs[i]
		s.prep()
		if s.rule == nil || have[s.CWE] || seen[s.CWE] {
			continue
		}
		if noFlow && !s.tSens && (s.tUser || s.tDyn) {
			continue
		}
		if taintSpecHits(s, lang, lc, content, user, dyn, sens) {
			out = append(out, Finding{Rule: s.rule, Confidence: s.Confidence})
			seen[s.CWE] = true
		}
	}
	return out
}

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

func tlHave(fs []Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[f.Rule.CWE] = true
	}
	return m
}
