package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	global []string
	byCWE  map[string][]string
}

const (
	maxPolicyEntries = 50
	maxPolicyLen     = 240
)

func loadPolicy(projectDir string) policy {
	p := policy{byCWE: map[string][]string{}}
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
