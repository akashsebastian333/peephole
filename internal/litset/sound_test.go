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

// A pure-literal alternation NESTED inside one arm of an outer alternation is not
// guaranteed to appear (the outer alternation may pick another arm), so its
// literals must NOT be extracted as required - the bug that silently skipped
// _.template SSTI, os.system(tool_input) agent-shell, and process.env exfil.
func TestNestedAlternationSoundness(t *testing.T) {
	cases := []struct{ re, matchesWithout string }{
		{`(?:Handlebars\.compile|_\.template|ejs\.(?:render|compile))\(`, "_.template("},
		{`(?:os\.system|subprocess\.(?:run|call|popen)|os\.popen)\(`, "os.system("},
		{`(?:fetch|axios\.(?:get|post|put))\(`, "fetch("},
		{`foo(?:nested(?:a|b))bar(?:cccc|dddd)`, "foonestedabarcccc"}, // later depth-0 group still usable
	}
	for _, c := range cases {
		rx := regexp.MustCompile(c.re)
		if !rx.MatchString(c.matchesWithout) {
			t.Fatalf("test bug: %q should match %q", c.re, c.matchesWithout)
		}
		for _, lit := range Required(c.re) {
			if !strings.Contains(strings.ToLower(c.matchesWithout), lit) {
				t.Errorf("%q: unsound required literal %q (matches %q without it)", c.re, lit, c.matchesWithout)
			}
		}
	}
}
