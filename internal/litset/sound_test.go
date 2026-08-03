package litset

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// SOUNDNESS invariant: the prefilter skips a pattern only when NONE of its
// Required() literals is present, so every string the regex matches must contain
// AT LEAST ONE required literal. (It is a SET / any-of filter, not all-of.) An
// unsound set has a matching string containing none of its literals — the
// prefilter would then skip a real match = a silently missed vulnerability.
//
// assertSound generates representative matching strings (covering each
// alternation arm and empty repeats — the literal-dropping cases) and checks the
// invariant on each.
func assertSound(t *testing.T, src string) {
	t.Helper()
	set := Required(src)
	if len(set) == 0 {
		return // no prefilter = always run = trivially sound
	}
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return
	}
	rx := regexp.MustCompile(src)
	for _, m := range genMatches(re.Simplify(), 400) {
		if !rx.MatchString(m) {
			continue // generator over-approximates; only judge real matches
		}
		low := strings.ToLower(m)
		found := false
		for _, lit := range set {
			if strings.Contains(low, lit) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("UNSOUND %q: match %q contains none of required set %v", src, m, set)
		}
	}
}

// genMatches returns up to `cap` representative strings the regex matches,
// biased toward the fewest literals (each alternation arm covered; every
// star/quest/repeat-min-0 contributes an empty expansion).
func genMatches(re *syntax.Regexp, cap int) []string {
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
		return genMatches(re.Sub[0], cap)
	case syntax.OpStar, syntax.OpQuest:
		out := []string{""} // zero repetitions: the literal-dropping case
		for _, s := range genMatches(re.Sub[0], cap) {
			out = append(out, s)
		}
		return out
	case syntax.OpPlus:
		return genMatches(re.Sub[0], cap)
	case syntax.OpRepeat:
		if re.Min == 0 {
			return []string{""}
		}
		return genMatches(re.Sub[0], cap)
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			out = append(out, genMatches(sub, cap)...)
			if len(out) > cap {
				break
			}
		}
		return out
	case syntax.OpConcat:
		acc := []string{""}
		for _, sub := range re.Sub {
			parts := genMatches(sub, cap)
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

func TestPrefilterSoundnessGenerative(t *testing.T) {
	cases := []string{
		// optional / repeat forms (literals may be absent)
		`(?:abc|def)?x`, `(?:abc|def)*x`, `(?:foo|bar)?baz`, `(?i:aaa|bbb)?q`,
		`(?:get|post)?\w+\(`, `os\.system\(`, `(?:eval|exec)\(`,
		// nested alternations (the recovery path)
		`(?:Handlebars\.compile|_\.template|ejs\.(?:render|compile))\(`,
		`(?:os\.system|subprocess\.(?:run|call|popen)|os\.popen)\(`,
		`(?:fetch|axios\.(?:get|post|put))\(`,
		`(?:requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request\.urlopen|urlopen)\s*\(`,
		`(?:\bredirect|HttpResponseRedirect|HttpResponsePermanentRedirect)\s*\(`,
		`foo(?:nested(?:a|b))bar(?:cccc|dddd)`,
	}
	for _, src := range cases {
		assertSound(t, src)
	}
}
