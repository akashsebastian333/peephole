package litset

import (
	"regexp"
	"strings"
	"testing"
)

// A required literal must appear in EVERY string the regex matches; otherwise the
// prefilter would skip a genuine match (a missed vulnerability). The risky case
// is an optional pure-literal group whose absence still matches.
func TestOptionalGroupSoundness(t *testing.T) {
	cases := []string{
		`(?:abc|def)?x`, `(?:abc|def)*x`, `(?:foo|bar)?baz`, `(?i:aaa|bbb)?q`,
		`(?:get|post)?\w+\(`, `os\.system\(`, `(?:eval|exec)\(`,
	}
	probe := "x baz q w( system("
	for _, re := range cases {
		rx := regexp.MustCompile(re)
		for _, lit := range Required(re) {
			if rx.MatchString(probe) && !strings.Contains(strings.ToLower(probe), lit) {
				t.Errorf("%q returned unsound required literal %q (probe matches without it)", re, lit)
			}
		}
	}
}
