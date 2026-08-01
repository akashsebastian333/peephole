package main

import (
	"os"
	"path/filepath"
	"regexp"
	"unicode"
)

// Injection/concealment phrases in an instruction file are a Rules File Backdoor
// signature, especially the concealment ones, which try to suppress peephole's
// own logging/reporting. Detected in addition to the Unicode tricks.
var reInjectionPhrase = regexp.MustCompile(`(?i)ignore (?:all |the )?(?:previous|prior|above) (?:instructions|rules)|disregard (?:all|the) (?:previous|prior)|you are now|<important>|do not (?:mention|tell|log|report|warn)|don'?t (?:mention|tell|log|report|warn)|hide this from|without (?:mentioning|telling|logging)|忽略(?:之前|以上|前面)的?(?:所有)?指令`)

// Instruction-file Unicode scan (control #7, Rules File
// Backdoor). Invisible zero-width / bidi-override / homoglyph characters in
// CLAUDE.md or rules files can steer the agent to insert backdoors while looking
// benign to a human reviewer. At SessionStart we scan the instruction files and,
// on a hit, surface a counter-notice and elevate sensitivity.

// hardControls have no legitimate use in a plain-English instruction file and
// are flagged unconditionally, bidi overrides/embeddings/isolates plus the
// invisible spacers most used for backdoors.
var hardControls = map[rune]string{
	0x200B: "zero-width space", 0xFEFF: "zero-width no-break space (BOM)",
	0x2060: "word joiner", 0x00AD: "soft hyphen",
	0x202A: "LTR embedding", 0x202B: "RTL embedding", 0x202C: "pop directional formatting",
	0x202D: "LTR override", 0x202E: "RTL override", 0x2066: "LTR isolate", 0x2067: "RTL isolate",
	0x2068: "first-strong isolate", 0x2069: "pop directional isolate",
}

// softMarks are legitimate in Persian/Indic text and emoji ZWJ sequences, so
// they are flagged only when adjacent to ASCII Latin (the concealment pattern).
var softMarks = map[rune]string{
	0x200C: "zero-width non-joiner", 0x200D: "zero-width joiner",
	0x200E: "LTR mark", 0x200F: "RTL mark", 0x061C: "Arabic letter mark",
}

// latinConfusables: Cyrillic/Greek letters that look like ASCII Latin ones, the
// actual homoglyph set. A lone Greek symbol used as math notation is not here.
var latinConfusables = map[rune]bool{
	'а': true, 'е': true, 'о': true, 'р': true, 'с': true, 'у': true, 'х': true, 'ѕ': true, 'і': true, 'ј': true,
	'А': true, 'В': true, 'Е': true, 'К': true, 'М': true, 'Н': true, 'О': true, 'Р': true, 'С': true, 'Т': true, 'У': true, 'Х': true,
	'ο': true, 'ν': true, 'α': true, 'ρ': true, 'Α': true, 'Β': true, 'Ε': true, 'Ζ': true, 'Η': true, 'Ι': true, 'Κ': true, 'Μ': true, 'Ν': true, 'Ο': true, 'Ρ': true, 'Τ': true, 'Χ': true,
}

func isASCIILatin(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// scanUnicode returns descriptions of dangerous characters. Bounded so a hostile
// file can't flood the context.
func scanUnicode(text string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] && len(out) < 8 {
			seen[s] = true
			out = append(out, s)
		}
	}
	runes := []rune(text)
	for i, r := range runes {
		if name, bad := hardControls[r]; bad {
			add("invisible/bidi control: " + name)
			continue
		}
		if name, soft := softMarks[r]; soft {
			// only suspicious when embedded in ASCII-Latin text
			if (i > 0 && isASCIILatin(runes[i-1])) || (i+1 < len(runes) && isASCIILatin(runes[i+1])) {
				add("invisible mark inside Latin text: " + name)
			}
		}
	}
	// homoglyph: a token mixing ASCII Latin with an actual Latin-confusable.
	var hasLatin, hasConfusable bool
	flush := func() {
		if hasLatin && hasConfusable {
			add("mixed-script word (possible homoglyph substitution)")
		}
		hasLatin, hasConfusable = false, false
	}
	for _, r := range runes {
		switch {
		case isASCIILatin(r):
			hasLatin = true
		case latinConfusables[r]:
			hasConfusable = true
		case unicode.IsLetter(r):
			// other scripts / non-confusable letters
		default:
			flush()
		}
	}
	flush()
	return out
}

// scanInstructionFiles checks the instruction files that steer the agent in this
// project. Returns "file: issue" descriptions. Bounded file size.
func scanInstructionFiles(dir string) []string {
	candidates := []string{
		filepath.Join(dir, "CLAUDE.md"),
		filepath.Join(dir, "AGENTS.md"),
		filepath.Join(dir, ".claude", "CLAUDE.md"),
		filepath.Join(dir, ".cursorrules"),
		filepath.Join(dir, ".mcp.json"),
		filepath.Join(dir, ".github", "copilot-instructions.md"),
	}
	var out []string
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() > 1<<20 {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(b)
		for _, issue := range scanUnicode(text) {
			out = append(out, filepath.Base(p)+": "+issue)
		}
		if reInjectionPhrase.MatchString(text) {
			out = append(out, filepath.Base(p)+": embedded instruction-injection/concealment phrase")
		}
	}
	return out
}
