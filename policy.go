package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

type policy struct {
	global  []string
	byCWE   map[string][]string
	enforce map[string]bool
	minMode string
}

const (
	maxPolicyEntries = 50
	maxPolicyLen     = 240
)

var reCWEid = regexp.MustCompile(`^CWE-\d{1,4}$`)

var modeRank = map[string]int{"off": 0, "audit": 1, "guided": 2, "strict": 3, "hardened": 4}

func (p policy) mustDeny(cwe string) bool { return cwe != "" && p.enforce[cwe] }

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
			return
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

func (p policy) forCWE(cwe string) []string {
	out := p.byCWE[cwe]
	if len(out) > 2 {
		out = out[:2]
	}
	return out
}

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
