package litset

import (
	"regexp/syntax"
	"strings"
)

const minLit = 3

func Required(src string) []string {
	var out []string
	for _, branch := range splitTopLevelAlternation(src) {
		set := branchLiteralSet(branch)
		if len(set) == 0 {
			return dedupCap(requiredSetAST(src))
		}
		out = append(out, set...)
		if len(out) > 10 {
			return nil
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
		best := expandedPrefix(re.Sub)
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
				return nil
			}
			union = append(union, s...)
		}
		return union
	case syntax.OpCapture:
		return requiredSet(re.Sub[0])
	case syntax.OpPlus:
		return requiredSet(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredSet(re.Sub[0])
		}
		return nil
	default:
		return nil
	}
}

const (
	maxClassExpand = 8
	maxPrefixes    = 12
)

func expandedPrefix(subs []*syntax.Regexp) []string {
	prefixes := []string{""}
	for _, sub := range subs {
		switch sub.Op {
		case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
			syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpEmptyMatch:
			continue
		case syntax.OpLiteral:
			lit := strings.ToLower(string(sub.Rune))
			for i := range prefixes {
				prefixes[i] += lit
			}
		case syntax.OpCharClass:
			var runes []rune
			for i := 0; i+1 < len(sub.Rune); i += 2 {
				lo, hi := sub.Rune[i], sub.Rune[i+1]
				if hi-lo+1 > maxClassExpand || len(runes)+int(hi-lo+1) > maxClassExpand {
					return finishPrefixes(prefixes)
				}
				for r := lo; r <= hi; r++ {
					runes = append(runes, r)
				}
			}
			if len(runes) == 0 || len(prefixes)*len(runes) > maxPrefixes {
				return finishPrefixes(prefixes)
			}
			var np []string
			for _, p := range prefixes {
				for _, r := range runes {
					np = append(np, p+strings.ToLower(string(r)))
				}
			}
			prefixes = np
		default:
			return finishPrefixes(prefixes)
		}
	}
	return finishPrefixes(prefixes)
}

func finishPrefixes(prefixes []string) []string {
	if len(prefixes) == 0 || (len(prefixes) == 1 && prefixes[0] == "") {
		return nil
	}
	for _, p := range prefixes {
		if len(p) < minLit {
			return nil
		}
	}
	return prefixes
}

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
			flush()
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
				return ""
			}
		case '?', '*':
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			flush()
		case '{':
			if len(cur) > 0 {
				cur = cur[:len(cur)-1]
			}
			flush()
			for i < len(src) && src[i] != '}' {
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

func branchLiteralSet(branch string) []string {
	if lit := RequiredOne(branch); lit != "" {
		return []string{lit}
	}
	for i := 0; i < len(branch); i++ {
		switch branch[i] {
		case '\\':
			i++
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
			break
		}
		j := i + 1
		if j < len(branch) && branch[j] == '?' {
			for j < len(branch) && branch[j] != ':' && branch[j] != ')' {
				j++
			}
			if j >= len(branch) || branch[j] != ':' {
				i = close
				continue
			}
			j++
		}
		if after := close + 1; after < len(branch) && (branch[after] == '?' || branch[after] == '*' || branch[after] == '{') {
			i = close
			continue
		}
		body := branch[j:close]
		if strings.ContainsAny(body, "()[]{}") {
			i = close
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

func skipClass(s string, lb int) int {
	i := lb + 1
	if i < len(s) && s[i] == '^' {
		i++
	}
	if i < len(s) && s[i] == ']' {
		i++
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
			return "", false
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
