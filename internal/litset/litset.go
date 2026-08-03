// Package litset extracts guaranteed literal sets from RE2 patterns, used to
// skip a pattern's compile+scan when none of its required literals is present
// in the content. Shared by the hook binary (kb.go) and the build-time code
// generator (cmd/kbgen).
package litset

import (
	"regexp/syntax"
	"strings"
)

const minLit = 3 // a literal shorter than this is not selective enough to prefilter on

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
			// The string scanner can't extract a guaranteed literal from this branch
			// (e.g. a nested alternation like `(?:requests\.(?:get|post)|urlopen)`).
			// Fall back to the regex AST, which computes the required set soundly by
			// recursion - recovery only, so it never changes a branch the scanner
			// already handled, and nil there means "always run" (sound, just slower).
			return dedupCap(requiredSetAST(src))
		}
		out = append(out, set...)
		if len(out) > 10 {
			return nil // too broad to be selective
		}
	}
	return dedupCap(out)
}

func dedupCap(out []string) []string {
	if len(out) == 0 || len(out) > 10 {
		return nil
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

// requiredSetAST computes the guaranteed-literal set from the parsed regex AST: a
// set S such that every string the regex matches contains at least one member of
// S (or nil if no such guarantee). Recursion: a literal run >= minLit is itself;
// an alternation is the UNION of its arms' sets (nil if any arm has none, since
// that arm could match with no literal); a concatenation takes the most-selective
// child's set (all children are present, so any one child's literal suffices); a
// 0-or-more/optional yields nil (may be absent); a 1-or-more/capture recurses.
func requiredSetAST(src string) []string {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	return requiredSet(re.Simplify())
}

func requiredSet(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		s := strings.ToLower(string(re.Rune))
		if len(s) >= minLit {
			return []string{s}
		}
		return nil
	case syntax.OpConcat:
		var best []string
		for _, sub := range re.Sub {
			if s := requiredSet(sub); setScore(s) > setScore(best) {
				best = s
			}
		}
		return best
	case syntax.OpAlternate:
		var union []string
		for _, sub := range re.Sub {
			s := requiredSet(sub)
			if len(s) == 0 {
				return nil // an arm with no required literal defeats the whole alternation
			}
			union = append(union, s...)
		}
		return union
	case syntax.OpCapture:
		return requiredSet(re.Sub[0])
	case syntax.OpPlus:
		return requiredSet(re.Sub[0]) // 1+ -> the sub occurs at least once
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredSet(re.Sub[0])
		}
		return nil
	default:
		return nil // star, quest, char class, any-char, anchors, empty match
	}
}

// setScore ranks a required set's selectivity: a set is only as selective as its
// weakest (shortest) member, and fewer members is better. nil scores 0.
func setScore(s []string) int {
	if len(s) == 0 {
		return 0
	}
	minLen := 1 << 30
	for _, l := range s {
		if len(l) < minLen {
			minLen = len(l)
		}
	}
	return minLen*4 - len(s)
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
	// group alternation of pure literals: (?:alpha|beta|gamma), also plain (..).
	// Only a TOP-LEVEL (depth-0) group is evaluated: a group nested inside another
	// group is one arm of an outer alternation and is NOT guaranteed to appear, so
	// treating its literals as required would skip real matches. We track balanced
	// parens (and skip escapes / char classes) and, when a group is not a usable
	// pure-literal alternation, jump PAST it rather than descending into it.
	for i := 0; i < len(branch); i++ {
		switch branch[i] {
		case '\\':
			i++ // escaped char, never a group open
			continue
		case '[':
			i = skipClass(branch, i)
			continue
		case '(':
		default:
			continue
		}
		close := matchingParen(branch, i)
		if close < 0 {
			break // unbalanced - give up (rest can't be soundly extracted)
		}
		j := i + 1
		if j < len(branch) && branch[j] == '?' { // (?:...), (?i:...) etc.
			for j < len(branch) && branch[j] != ':' && branch[j] != ')' {
				j++
			}
			if j >= len(branch) || branch[j] != ':' {
				i = close // a pure flag group like (?i) - not an alternation
				continue
			}
			j++
		}
		if after := close + 1; after < len(branch) && (branch[after] == '?' || branch[after] == '*' || branch[after] == '{') {
			i = close // optional/repeatable group: literals not guaranteed
			continue
		}
		body := branch[j:close]
		if strings.ContainsAny(body, "()[]{}") {
			i = close // nested group or class content - not pure literals
			continue
		}
		alts := strings.Split(body, "|")
		if len(alts) < 2 {
			i = close
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
		i = close
	}
	return nil
}

// matchingParen returns the index of the ')' that closes the '(' at open,
// skipping escapes and character classes, or -1 if unbalanced.
func matchingParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '[':
			i = skipClass(s, i)
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipClass returns the index of the ']' closing the char class opening at lb,
// or the last index if unterminated.
func skipClass(s string, lb int) int {
	i := lb + 1
	if i < len(s) && s[i] == '^' {
		i++
	}
	if i < len(s) && s[i] == ']' {
		i++ // a ']' right after [ or [^ is a literal member
	}
	for i < len(s) {
		if s[i] == '\\' {
			i++
		} else if s[i] == ']' {
			return i
		}
		i++
	}
	return len(s) - 1
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
