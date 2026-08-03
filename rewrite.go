package main

import "regexp"

// Secure-default rewrites (updatedInput only via ask-with-preview,
// syntactic-only, re-scanned). These are pure, unambiguous token substitutions
// that turn an insecure default into its secure form. Anything semantically
// risky (DEBUG flags, crypto mode changes) is deliberately excluded; those get
// a deny/ask with guidance, never an auto-rewrite.
var secureRewrites = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Only the single-argument form: safe_load takes no Loader kwarg, so rewriting
	// yaml.load(f, Loader=...) to yaml.safe_load(f, Loader=...) would crash at
	// runtime. The Loader= form falls through to normal deny/guidance instead.
	{regexp.MustCompile(`\byaml\.load\(([^),]*)\)`), "yaml.safe_load(${1})"},
	{regexp.MustCompile(`\bverify(\s*=\s*)False\b`), "verify${1}True"},
	{regexp.MustCompile(`rejectUnauthorized(\s*:\s*)false`), "rejectUnauthorized${1}true"},
}

// secureRewrite applies the substitutions. Returns the new content and whether
// anything changed.
func secureRewrite(content string) (string, bool) {
	out := content
	for _, r := range secureRewrites {
		out = r.re.ReplaceAllString(out, r.repl)
	}
	return out, out != content
}
