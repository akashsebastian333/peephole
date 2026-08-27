package main

import (
	"regexp"
	"strings"
)

var secureRewrites = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`\byaml\.load\(\s*([A-Za-z_][\w.]*(?:\([^()]*\))?)\s*\)`), "yaml.safe_load(${1})"},
	{regexp.MustCompile(`\bverify(\s*=\s*)False\b`), "verify${1}True"},
	{regexp.MustCompile(`rejectUnauthorized(\s*:\s*)false`), "rejectUnauthorized${1}true"},
}

var reDeclLine = regexp.MustCompile(`^\s*(?:@\w|(?:async\s+)?def\s+\w+\s*\(|(?:export\s+)?(?:async\s+)?function\s*\**\s*\w*\s*\(|(?:public|private|protected|static|func|fn|sub)\s+\w+\s*\()`)

func declSpan(lines []string) []bool {
	out := make([]bool, len(lines))
	depth := 0
	for i, ln := range lines {
		inDecl := depth > 0
		if depth == 0 && reDeclLine.MatchString(ln) {
			inDecl = true
		}
		out[i] = inDecl
		if inDecl {
			depth += strings.Count(ln, "(") - strings.Count(ln, ")")
			if depth < 0 {
				depth = 0
			}
		}
	}
	return out
}

func secureRewrite(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	inDecl := declSpan(lines)
	changed := false
	for i, ln := range lines {
		if inDecl[i] {
			continue
		}
		out := ln
		for _, r := range secureRewrites {
			out = r.re.ReplaceAllString(out, r.repl)
		}
		if out != ln {
			lines[i] = out
			changed = true
		}
	}
	if !changed {
		return content, false
	}
	return strings.Join(lines, "\n"), true
}
