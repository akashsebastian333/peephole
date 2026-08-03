package main

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// TestAllPrefiltersSound is the definitive prefilter soundness guard: for EVERY
// shipped rule pattern and taint sink that carries a prefilter set, it generates
// representative matching strings (each alternation arm, empty repeats — the
// literal-dropping cases) and asserts every real match contains at least one
// prefilter literal. If not, prefilterMiss would skip a genuine match = a
// silently missed vulnerability. Covers the litset AST recovery for nested
// alternations across the real KB.
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
