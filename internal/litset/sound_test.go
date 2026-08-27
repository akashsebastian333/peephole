package litset

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

func assertSound(t *testing.T, src string) {
	t.Helper()
	set := Required(src)
	if len(set) == 0 {
		return
	}
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return
	}
	rx := regexp.MustCompile(src)
	for _, m := range genMatches(re.Simplify(), 400) {
		if !rx.MatchString(m) {
			continue
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
		out := []string{""}
		out = append(out, genMatches(re.Sub[0], cap)...)
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
		`(?:abc|def)?x`, `(?:abc|def)*x`, `(?:foo|bar)?baz`, `(?i:aaa|bbb)?q`,
		`(?:get|post)?\w+\(`, `os\.system\(`, `(?:eval|exec)\(`,
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
