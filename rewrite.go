package main

import (
	"regexp"
	"strings"
)

// Secure-default rewrites (updatedInput only via ask-with-preview,
// syntactic-only, re-scanned). These are pure, unambiguous token substitutions
// that turn an insecure default into its secure form. Anything semantically
// risky (DEBUG flags, crypto mode changes) is deliberately excluded; those get
// a deny/ask with guidance, never an auto-rewrite.
//
// Two classes of corruption are guarded against explicitly, because a rewrite
// that lands broken code is worse than no rewrite at all:
//
//  1. yaml.safe_load takes no Loader= kwarg, so only the genuine single-argument
//     form may be rewritten. `[^),]*` is NOT sufficient for this: it terminates
//     at the inner ")" of a nested call, so yaml.load(open(p), Loader=...) still
//     matched and produced yaml.safe_load(open(p), Loader=...) — a TypeError at
//     runtime. The argument pattern below allows one level of nesting and then
//     requires the closing paren, so any comma-separated form falls through.
//  2. `verify=False` / `rejectUnauthorized: false` in a *function signature* is a
//     declared default, not a call site. Flipping it silently changes the
//     function's public contract for every caller. Signature lines — including
//     the continuation lines of a multi-line signature — are skipped.
var secureRewrites = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`\byaml\.load\(\s*([A-Za-z_][\w.]*(?:\([^()]*\))?)\s*\)`), "yaml.safe_load(${1})"},
	{regexp.MustCompile(`\bverify(\s*=\s*)False\b`), "verify${1}True"},
	{regexp.MustCompile(`rejectUnauthorized(\s*:\s*)false`), "rejectUnauthorized${1}true"},
}

// reDeclLine opens a function/method declaration, whose parameter defaults are a
// public contract rather than a call argument.
var reDeclLine = regexp.MustCompile(`^\s*(?:@\w|(?:async\s+)?def\s+\w+\s*\(|(?:export\s+)?(?:async\s+)?function\s*\**\s*\w*\s*\(|(?:public|private|protected|static|func|fn|sub)\s+\w+\s*\()`)

// declSpan reports, for each line, whether it is part of an open function
// declaration's parameter list. A declaration keeps the flag set until its
// parentheses balance, so continuation lines are covered too.
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

// secureRewrite applies the substitutions line by line, skipping any line that
// belongs to a function declaration's parameter list. Returns the new content
// and whether anything changed.
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
