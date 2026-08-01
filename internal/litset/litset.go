// Package litset extracts guaranteed literal sets from RE2 patterns, used to
// skip a pattern's compile+scan when none of its required literals is present
// in the content. Shared by the hook binary (kb.go) and the build-time code
// generator (cmd/kbgen).
package litset

import "strings"

// Required extracts the prefilter SET for a regex: lowercase literals, at
// least one of which is guaranteed present in any string the regex matches.
// It handles top-level alternation (each branch must yield a literal; the
// union is the set) and group alternation of pure literals ((?:alpha|beta) ->
// {alpha, beta}). nil when no guarantee exists. Soundness is enforced by the
// corpus true-positive tests plus TestPrefilterSoundness.
func Required(src string) []string {
	var out []string
	for _, branch := range splitTopLevelAlternation(src) {
		set := branchLiteralSet(branch)
		if len(set) == 0 {
			return nil // a branch with no guaranteed literal defeats the filter
		}
		out = append(out, set...)
		if len(out) > 10 {
			return nil // too broad to be selective
		}
	}
	seen := map[string]bool{}
	dedup := out[:0]
	for _, l := range out {
		if !seen[l] {
			seen[l] = true
			dedup = append(dedup, l)
		}
	}
	return dedup
}

// RequiredOne extracts a single lowercase literal guaranteed present in any
// match of src (the longest top-level run), or "" if none exists. It is
// deliberately conservative: it only considers maximal word-char runs at the
// top level (depth 0, outside character classes), drops the last char before a
// ?/*/{ quantifier, and bails to "" on a top-level alternation.
func RequiredOne(src string) string {
	var best, cur []byte
	flush := func() {
		if len(cur) > len(best) {
			best = append(best[:0:0], cur...)
		}
		cur = cur[:0]
	}
	depth, inClass := 0, false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '\\' && i+1 < len(src) {
			i++
			flush() // an escape ends the current literal run (class escape or literal punctuation)
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			continue
		}
		switch c {
		case '[':
			inClass = true
			flush()
		case '(':
			depth++
			flush()
		case ')':
			if depth > 0 {
				depth--
			}
			flush()
		case '|':
			flush()
			if depth == 0 {
				return "" // top-level alternation: no single literal is guaranteed
			}
		case '?', '*':
			if len(cur) > 0 { // preceding char is optional/variable
				cur = cur[:len(cur)-1]
			}
			flush()
		case '{':
			if len(cur) > 0 { // {n,m} makes the preceding char variable
				cur = cur[:len(cur)-1]
			}
			flush()
			for i < len(src) && src[i] != '}' { // skip the quantifier body; its digits are not literals
				i++
			}
		case '+':
			flush()
		default:
			if depth == 0 && (c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				cur = append(cur, c)
			} else {
				flush()
			}
		}
	}
	flush()
	if len(best) < 3 {
		return ""
	}
	return string(best)
}

// splitTopLevelAlternation splits a regex on top-level `|` (outside classes and
// groups, escape-aware). No top-level alternation -> one branch.
func splitTopLevelAlternation(src string) []string {
	var out []string
	depth, inClass, start := 0, false, 0
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '\\' && i+1 < len(src) {
			i++
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			continue
		}
		switch c {
		case '[':
			inClass = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 {
				out = append(out, src[start:i])
				start = i + 1
			}
		}
	}
	return append(out, src[start:])
}

// branchLiteralSet returns the most selective guaranteed literal set for one
// alternation-free branch: a single top-level literal run if one exists, else a
// group alternation of pure literals ((?:alpha|beta) -> {alpha, beta}).
func branchLiteralSet(branch string) []string {
	if lit := RequiredOne(branch); lit != "" {
		return []string{lit}
	}
	// group alternation of pure literals: (?:alpha|beta|gamma), also plain (..)
	for i := 0; i < len(branch); i++ {
		if branch[i] != '(' {
			continue
		}
		j := i + 1
		if j < len(branch) && branch[j] == '?' { // (?:...), (?i:...) etc.
			// skip the flag/option prefix up to ':' or ')'
			for j < len(branch) && branch[j] != ':' && branch[j] != ')' {
				j++
			}
			if j >= len(branch) || branch[j] != ':' {
				continue // a pure flag group like (?i) - not an alternation
			}
			j++
		}
		end := strings.IndexByte(branch[j:], ')')
		if end < 0 {
			continue
		}
		if after := j + end + 1; after < len(branch) && (branch[after] == '?' || branch[after] == '*') {
			continue // optional group: its literals are not guaranteed in a match
		}
		body := branch[j : j+end]
		if strings.ContainsAny(body, "()[]{}") {
			continue // nested group or class content - not pure literals
		}
		alts := strings.Split(body, "|")
		if len(alts) < 2 {
			continue
		}
		set := make([]string, 0, len(alts))
		ok := true
		for _, a := range alts {
			lit, pure := pureLiteral(a)
			if !pure {
				ok = false
				break
			}
			set = append(set, lit)
		}
		if ok {
			return set
		}
	}
	return nil
}

// pureLiteral reports whether a group alternative is a pure literal string (no
// regex metacharacters; only simple backslash escapes like \. \/ \_), returning
// its lowercase form. Anything regex-flavored is rejected: treating a regex dot
// or class as a literal would make the prefilter skip a real match.
func pureLiteral(alt string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(alt); i++ {
		c := alt[i]
		if c == '\\' && i+1 < len(alt) {
			n := alt[i+1]
			if n == '.' || n == '/' || n == '_' || n == '-' || n == ' ' {
				b.WriteByte(n)
				i++
				continue
			}
			return "", false // class escape (\d \w \s ...) or other regex construct
		}
		if c == '_' || c == ' ' || c == '-' || c == '/' ||
			c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			b.WriteByte(c)
			continue
		}
		return "", false
	}
	s := strings.ToLower(b.String())
	if len(s) < 3 {
		return "", false
	}
	return s, true
}
