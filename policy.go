package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

// Org policy loading (N3's policy plane, blueprint §4.1 policy_hooks / §5 N3).
// A team commits policy values that the context compiler injects alongside the
// CWE guidance before generation - e.g. "bcrypt cost >= 12", "all queries via
// the repository layer". Files (first hit wins, array or object form):
//
//	<project>/.peephole-policy.json
//	<project>/.claude/peephole-policy.json
//
// Object form: { "global": ["..."], "CWE-89": ["..."] }. Like user rules, a
// committed file is untrusted input: values are Unicode/injection-scanned and
// length-capped before they can reach model context.
type policy struct {
	global  []string
	byCWE   map[string][]string
	enforce map[string]bool // CWE -> deny in strict/hardened (org mandate). ESCALATION ONLY; audit still measure-only.
	minMode string          // org floor: the effective mode is never weaker than this
}

const (
	maxPolicyEntries = 50
	maxPolicyLen     = 240
)

var reCWEid = regexp.MustCompile(`^CWE-\d{1,4}$`)

var modeRank = map[string]int{"off": 0, "audit": 1, "guided": 2, "strict": 3, "hardened": 4}

// mustDeny reports whether the org policy mandates a hard deny for this CWE,
// regardless of the built-in confidence (an escalation, always safe).
func (p policy) mustDeny(cwe string) bool { return cwe != "" && p.enforce[cwe] }

// floor raises the mode to the org minimum when the local mode is weaker. It only
// ever makes enforcement STRICTER: a committed policy cannot downgrade the mode,
// so a poisoned repo cannot use it to disable the gate.
func (p policy) floor(mode string) string {
	if p.minMode != "" && modeRank[p.minMode] > modeRank[mode] {
		return p.minMode
	}
	return mode
}

func loadPolicy(projectDir string) policy {
	p := policy{byCWE: map[string][]string{}, enforce: map[string]bool{}}
	var b []byte
	var err error
	for _, path := range []string{
		filepath.Join(projectDir, ".peephole-policy.json"),
		filepath.Join(projectDir, ".claude", "peephole-policy.json"),
	} {
		if b, err = os.ReadFile(path); err == nil {
			break
		}
	}
	if err != nil || len(b) > 1<<20 {
		return p
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return p
	}
	// Escalation directives (safe: they can only make peephole stricter, so a
	// poisoned committed file cannot use them to weaken the gate).
	if v, ok := raw["enforce"]; ok {
		var cwes []string
		if json.Unmarshal(v, &cwes) == nil {
			for _, c := range cwes {
				if reCWEid.MatchString(c) {
					p.enforce[c] = true
				}
			}
		}
		delete(raw, "enforce")
	}
	if v, ok := raw["min_mode"]; ok {
		var m string
		if json.Unmarshal(v, &m) == nil && (m == "strict" || m == "hardened") {
			p.minMode = m
		}
		delete(raw, "min_mode")
	}
	total := 0
	add := func(cwe, s string) {
		if total >= maxPolicyEntries || len(s) > maxPolicyLen {
			return
		}
		if len(scanUnicode(s)) > 0 || reInjectionPhrase.MatchString(s) {
			return // untrusted content refused, not sanitized-in-place
		}
		total++
		if cwe == "global" {
			p.global = append(p.global, s)
		} else {
			p.byCWE[cwe] = append(p.byCWE[cwe], s)
		}
	}
	for k, v := range raw {
		var arr []string
		if json.Unmarshal(v, &arr) != nil {
			var one string
			if json.Unmarshal(v, &one) == nil {
				arr = []string{one}
			} else {
				continue
			}
		}
		for _, s := range arr {
			add(k, s)
		}
	}
	return p
}

// forCWE returns the policy entries pinned to one CWE (capped).
func (p policy) forCWE(cwe string) []string {
	out := p.byCWE[cwe]
	if len(out) > 2 {
		out = out[:2]
	}
	return out
}

// globalFor returns global policy entries, but only when the task classified at
// all (a generic prompt gets no policy noise - RESCUE's injection-size caveat).
func (p policy) globalFor(candidates []*Rule) []string {
	if len(candidates) == 0 {
		return nil
	}
	out := p.global
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}
