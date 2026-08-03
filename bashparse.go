package main

import (
	"regexp"
	"strings"
)

// Bash write-path inspection. A model denied a Write for `cat auth/routes.py`
// will retry from Bash: a heredoc, echo/printf redirect, cp/mv/dd, or
// interpreter -c. This extracts the payload a command would write/execute and
// routes it through the same scanner, and flags any write it cannot inspect so
// the Bash path is never a silent hole.
//
// Not a full bash parser. Extractable content (heredoc, echo/printf literal,
// interpreter -c) is scanned; every other write target (redirect, tee, cp, mv,
// dd, git apply, sed -i, obfuscated/remote) is marked Uninspectable ->
// ask (strict) / deny (hardened), never a silent pass.

type WritePayload struct {
	Target  string // best-effort target path ("" if unknown)
	Content string // the code/text being introduced
}

type Install struct {
	Manager string // pip | npm | yarn | pnpm | go | poetry | pipenv | uv
	Pkg     string
}

type BashAnalysis struct {
	Payloads      []WritePayload
	Installs      []Install
	Uninspectable bool
	Reason        string
	Targets       []string // every path the command may write to (self-protection)
	InstallSmells []string // install-hook / index / remote-source smells (ask)
}

var (
	// RE2 has no backreferences, so quotes are matched independently rather than
	// as a balanced pair, fine for delimiter extraction.
	reHeredoc = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	// Handles plain >, >>, fd-prefixed (1>), clobber (>|), both-streams (&>), and
	// tee. A target is always captured so an unpaired write is flagged.
	reRedirect = regexp.MustCompile(`(?:[0-9&]*>>?\|?|\btee\b(?:\s+-a)?)\s*([^\s;&|<>()]+)`)
	// [^|]*? so an intervening decode pipe (echo <b64> | base64 -d > f) does not
	// let the echo literal 'claim' the redirect target, that path stays
	// uninspectable instead.
	reEchoWrite = regexp.MustCompile(`\b(?:echo|printf)\b\s+([^|]*?)\s*>>?\s*[^\s;&|<>]+`)
	// no "install" here, it collides with `pip install` / `npm install`.
	// The target is captured whether the copy ends the line OR is followed by a
	// command separator (`cp evil.py app.py; echo done`) - a trailing $-only anchor
	// let a two-token suffix hide the staged write entirely.
	reCopyMove   = regexp.MustCompile(`\b(?:cp|mv|dd|rsync|ln)\b[^;&|]*\s([^\s;&|<>]+)\s*(?:[;&|]|$)`)
	reGitApply   = regexp.MustCompile(`\bgit\s+apply\b|\bpatch\b\s+-`)
	reSedInplace = regexp.MustCompile(`\bsed\b[^|;&]*\s-i\b`)
	// Allow interpreter flags before -c/-e (e.g. python -B -c "...") and php's -r
	// inline flag. The quoted body spans escaped chars ((?:[^'\\]|\\.)*) so an
	// embedded \" doesn't truncate the extracted code (hiding the rest from scan);
	// it still stops at the first UNescaped closing quote. -r is php-only: for
	// node/ruby -r means "preload a module", not inline code.
	reInterp    = regexp.MustCompile(`\b(?:(?:python3?|node|deno|bun|ruby|perl|bash|sh)(?:\s+-[\w-]+)*\s+(?:-c|-e)|php(?:\s+-[\w-]+)*\s+-r)\s+('((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")`)
	reInstall   = regexp.MustCompile(`\b(pip3?|uv\s+pip|poetry|pipenv|npm|pnpm|yarn|bun|go)\s+(?:install|add|get|i)\b([^\n;&|]*)`)
	reUninspect = regexp.MustCompile(`base64\s+-+d|base64\s+--decode|\|\s*(?:sh|bash|zsh|ed|ex|python3?|node|deno|bun|ruby|perl|php|tclsh|Rscript)\b|\b(?:ed|ex)\s+-|eval\s+"?\$\(|xxd\s+-r|(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh|python3?|node|ruby|perl|php)`)
	// obfuscation/decode primitives inside interpreter -c/-e code
	reObfExec = regexp.MustCompile(`(?i)b64decode|base64|codecs\.decode|marshal\.loads|\bexec\s*\(|\beval\s*\(|__import__|fromhex|bytes\.fromhex|zlib\.decompress`)
	// A redirect/copy target we cannot statically resolve (glob, variable, tilde)
	// could land anywhere, treat as uninspectable rather than assume it's safe.
	reUnresolvableTarget = regexp.MustCompile(`[*?\[\]{}$~]`)
	reInterpDashC        = regexp.MustCompile(`\b(?:(?:python3?|node|deno|bun|ruby|perl|bash|sh)(?:\s+-[\w-]+)*\s+(?:-c|-e)|php(?:\s+-[\w-]+)*\s+-r)\b`)
	reShellNoise         = regexp.MustCompile("[\"'\\\\\\[\\]{}]")
	// $( command sub, backtick, ${...} parameter/brace expansion, and $VAR - all
	// make the written bytes runtime-determined. The brace form ${VAR} was missing,
	// so `echo "${CODE}" > f` slipped the determinability check the unbraced $VAR hit.
	reCmdSubst = regexp.MustCompile(`\$[({]|` + "`" + `|\$[A-Za-z_]`)
	// coreutils `install` is a copy-with-mode (install -m 0755 src dst) - a write
	// primitive like cp/mv/dd. Anchored to command position (line start or after a
	// separator, optional sudo) so `npm install -g` / `pip install -v` / `apt
	// install -s` (install as a package-manager SUBcommand) don't collide with it.
	reInstallBin = regexp.MustCompile(`(?:^|[\n;&|])\s*(?:sudo\s+)?install\s+-[DmogtTsSbpvcd]`)
	// echo -e / printf with \xNN, \0NN, or %b decode escapes at runtime, so the
	// bytes landing in the file are not the literal we see. Scoped to a write (has
	// a redirect) so a benign `printf "%b\n" "$x"` to stdout is not flagged.
	reEscapeDecodeWrite = regexp.MustCompile(`\b(?:echo\s+-e\b|printf\b)[^;&|]*(?:\\x[0-9a-fA-F]|\\0[0-7]{2}|%b)[^;&|]*>`)
	rePkgClean          = regexp.MustCompile(`^[@A-Za-z0-9._/-]+`)
	reFlagValue         = regexp.MustCompile(`^-(?:r|c|f|e|-requirement|-constraint|-find-links|-editable)$`)
	reFilePath          = regexp.MustCompile(`\.(?:txt|whl|tar|gz|tgz|zip|cfg|toml|lock|in|json)$`)
	reIndexURL          = regexp.MustCompile(`--(?:extra-)?index-url\s+(\S+)`)
	reRemoteInstall     = regexp.MustCompile(`\b(?:pip3?|npm|yarn|pnpm|bun)\s+(?:install|add|i)\s+[^\n;&|]*\b(git\+|https?://|git://|ssh://|file:)`)
	rePypiHost          = regexp.MustCompile(`(?i)^https?://(?:[\w.-]+\.)?(?:pypi\.org|pythonhosted\.org|npmjs\.org|npmjs\.com)`)
)

func analyzeBash(cmd string) BashAnalysis {
	var a BashAnalysis

	// 1. Heredoc payloads.
	for _, m := range reHeredoc.FindAllStringSubmatchIndex(cmd, -1) {
		delim := cmd[m[2]:m[3]]
		if body := heredocBody(cmd, m[1], delim); body != "" {
			a.Payloads = append(a.Payloads, WritePayload{Content: body})
		}
	}
	// 2. echo/printf > file, extract the literal being written. If the literal
	// hides content in a variable / command substitution, it is not inspectable.
	for _, m := range reEchoWrite.FindAllStringSubmatch(cmd, -1) {
		raw := strings.TrimSpace(m[1])
		if reCmdSubst.MatchString(raw) {
			a.Uninspectable, a.Reason = true, "echo/printf write contains a variable or command substitution - content not statically determinable"
			continue
		}
		lit := unescapeShell(strings.Trim(raw, `"'`))
		if lit != "" {
			a.Payloads = append(a.Payloads, WritePayload{Content: lit})
		}
	}
	// 3. Redirect / tee targets.
	for _, m := range reRedirect.FindAllStringSubmatch(cmd, -1) {
		t := strings.Trim(m[1], `"'`)
		if t != "" && t != "/dev/null" {
			a.Targets = append(a.Targets, t)
			for i := range a.Payloads {
				if a.Payloads[i].Target == "" {
					a.Payloads[i].Target = t
					break
				}
			}
		}
	}
	// 4. Interpreter inline code.
	for _, m := range reInterp.FindAllStringSubmatch(cmd, -1) {
		code := m[2]
		if code == "" {
			code = m[3]
		}
		switch {
		case reCmdSubst.MatchString(code):
			a.Uninspectable, a.Reason = true, "interpreter code contains command substitution / variables - not statically determinable"
		case reObfExec.MatchString(code):
			a.Uninspectable, a.Reason = true, "interpreter code decodes/executes an obfuscated payload (base64/exec/eval/__import__) - not statically inspectable"
		case code != "":
			a.Payloads = append(a.Payloads, WritePayload{Content: code})
		}
	}
	// An interpreter -c/-e with no cleanly-extractable quoted literal (ANSI-C
	// $'...', concatenation, unquoted) is also uninspectable.
	if reInterpDashC.MatchString(cmd) && !reInterp.MatchString(cmd) {
		a.Uninspectable, a.Reason = true, "interpreter -c/-e code could not be extracted (obfuscated quoting) - not inspectable"
	}
	// 5. Install commands -> package names + supply-chain smells.
	a.Installs = extractInstalls(cmd)
	for _, m := range reIndexURL.FindAllStringSubmatch(cmd, -1) {
		if !rePypiHost.MatchString(m[1]) {
			a.InstallSmells = append(a.InstallSmells, "install uses a non-official package index ("+m[1]+") - packages could be substituted; verify the host.")
		}
	}
	if m := reRemoteInstall.FindStringSubmatch(cmd); m != nil {
		a.InstallSmells = append(a.InstallSmells, "install pulls from a remote/VCS source ("+m[1]+"...) that bypasses registry checks - confirm the source is trusted.")
	}
	// 6. cp/mv/dd/install/ln and git apply write a file with content we can't
	// reconstruct here.
	for _, m := range reCopyMove.FindAllStringSubmatch(cmd, -1) {
		if t := strings.Trim(m[1], `"'`); t != "" {
			a.Targets = append(a.Targets, t)
			a.Uninspectable = true
			if a.Reason == "" {
				a.Reason = "copy/move/dd write - content not statically inspectable"
			}
		}
	}
	if reGitApply.MatchString(cmd) {
		a.Uninspectable = true
		if a.Reason == "" {
			a.Reason = "patch application - content not statically inspectable"
		}
	}
	if reInstallBin.MatchString(cmd) {
		a.Uninspectable = true
		if a.Reason == "" {
			a.Reason = "coreutils install (copy-with-mode) - content not statically inspectable"
		}
	}
	if reEscapeDecodeWrite.MatchString(cmd) {
		a.Uninspectable = true
		if a.Reason == "" {
			a.Reason = "escape-decoded write (echo -e / printf %b) - runtime-decoded, not statically determinable"
		}
	}
	// 7. sed -i in-place edit.
	if reSedInplace.MatchString(cmd) {
		a.Uninspectable = true
		if a.Reason == "" {
			a.Reason = "in-place edit (sed -i) - content not statically reconstructable"
		}
	}
	// 8. Any redirect/copy target with no extracted payload, or one whose path
	// can't be statically resolved (glob/variable/tilde), is an uninspectable
	// write (never a silent pass). Carve-out: a benign read-only producer
	// (git/grep/jq/test-runners...) redirecting program OUTPUT to a plain-data
	// file (.log/.txt/.md/...) is everyday dev flow, not staged code - gating it
	// was the top ask-fatigue source. Code/config/manifest targets stay gated,
	// and the landed file is still covered by the PostToolUse retro-scan.
	for _, t := range a.Targets {
		if reUnresolvableTarget.MatchString(t) {
			a.Uninspectable = true
			if a.Reason == "" {
				a.Reason = "write to an unresolvable path (glob/variable/tilde)"
			}
			break
		}
		if !hasPayloadFor(a.Payloads, t) && !benignOutputRedirect(cmd, t) {
			a.Uninspectable = true
			if a.Reason == "" {
				a.Reason = "redirected write with non-extractable content"
			}
			break
		}
	}
	// 9. Obfuscated / remote-sourced write or exec.
	if reUninspect.MatchString(cmd) {
		a.Uninspectable = true
		if a.Reason == "" {
			a.Reason = "obfuscated or remote-sourced write/exec - payload not statically determinable"
		}
	}
	return a
}

func extractInstalls(cmd string) []Install {
	var out []Install
	for _, m := range reInstall.FindAllStringSubmatch(cmd, -1) {
		mgr := strings.Fields(m[1])[0]
		toks := strings.Fields(m[2])
		for i := 0; i < len(toks); i++ {
			tok := toks[i]
			if strings.HasPrefix(tok, "-") {
				if reFlagValue.MatchString(tok) {
					i++ // skip this flag's value (e.g. -r requirements.txt)
				}
				continue
			}
			// Skip real filesystem paths (./x../x, /x, foo.txt) but KEEP scoped
			// npm names (@scope/name) and dotted pip names (zope.interface), those
			// are packages the slopsquat gate must still check.
			if strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../") || strings.HasPrefix(tok, "/") || reFilePath.MatchString(tok) {
				continue
			}
			pkg := rePkgClean.FindString(tok)
			// strip a version pin without eating a leading scope '@' (@scope/name)
			if i := strings.IndexAny(pkg, "=<>~!"); i >= 0 {
				pkg = pkg[:i]
			}
			if at := strings.LastIndex(pkg, "@"); at > 0 { // '@' not the leading scope char
				pkg = pkg[:at]
			}
			if pkg != "" && pkg != "install" && pkg != "add" {
				out = append(out, Install{Manager: mgr, Pkg: pkg})
			}
		}
	}
	return out
}

func hasPayloadFor(payloads []WritePayload, target string) bool {
	for _, p := range payloads {
		if p.Target == target {
			return true
		}
	}
	return false
}

// reBenignProducer matches commands whose stdout is program output, not staged
// code: read-only inspection tools and common build/test runners. Used with the
// plain-data target check to spare everyday `git diff > notes.txt` flow.
var reBenignProducer = regexp.MustCompile(`^\s*(?:sudo\s+)?(?:git|grep|rg|egrep|fgrep|find|ls|ll|cat|head|tail|sort|uniq|jq|yq|diff|wc|date|env|printenv|ps|whoami|hostname|uname|file|stat|tree|basename|dirname|pwd|seq|tr|cut|column|history|df|du|free|lsof|ss|dig|host|nslookup|make|cmake|go|cargo|npm|npx|yarn|pnpm|pip|pip3|pytest|python3?|node|deno|bun|jest|mocha|vitest|mvn|gradle|rake|rspec|phpunit|dotnet|swift|java|javac|gcc|g\+\+|clang|rustc|kotlinc)\b`)

// plainDataExt: targets that are data, not runnable code or configuration. A
// redirect landing here can't stage code by itself; anything code-shaped still
// gets gated (and the retro-scan covers the landed file regardless).
var plainDataExt = map[string]bool{
	".log": true, ".txt": true, ".md": true, ".markdown": true, ".rst": true,
	".out": true, ".csv": true, ".tsv": true, ".diff": true, ".patch": true,
	".asc": true, ".sig": true, ".summary": true,
}

// benignOutputRedirect reports whether cmd is a benign producer writing program
// output to a plain-data target - the everyday redirect the gate should not
// interrupt. The producer is anchored at the command start so
// `cat x | sh > y` (reUninspect, handled separately) never qualifies.
func benignOutputRedirect(cmd, target string) bool {
	t := strings.ToLower(strings.Trim(target, `"'`))
	ext := ""
	if i := strings.LastIndexByte(t, '.'); i >= 0 {
		ext = t[i:]
	}
	if !plainDataExt[ext] {
		return false
	}
	return reBenignProducer.MatchString(cmd)
}

// stripShellNoise removes shell no-op metacharacters (quotes, brackets,
// backslashes) that obfuscate a literal path but vanish at exec, so a
// normalized comparison sees `.peephole` through `.pee""phole` / `.pee[p]hole`.
func stripShellNoise(s string) string {
	return reShellNoise.ReplaceAllString(s, "")
}

var (
	reShellAssign = regexp.MustCompile(`(?:^|[;&|]|\bexport\s+)\s*([A-Za-z_]\w*)=('[^']*'|"[^"]*"|[^\s;&|)]*)`)
	reShellVar    = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)\}?`)
)

// resolveAssignments substitutes simple `VAR=value` shell assignments into later
// `$VAR`/`${VAR}` uses, so self-protection cannot be evaded by aliasing the
// peephole binary through a variable (e.g. `P=peephole; $P mode off`). Only
// literal, single-token assignments are resolved; this is a detection aid, not a
// shell interpreter.
func resolveAssignments(cmd string) string {
	vals := map[string]string{}
	for _, m := range reShellAssign.FindAllStringSubmatch(cmd, -1) {
		vals[m[1]] = strings.Trim(m[2], `"'`)
	}
	if len(vals) == 0 {
		return cmd
	}
	return reShellVar.ReplaceAllStringFunc(cmd, func(tok string) string {
		name := strings.Trim(strings.TrimPrefix(tok, "$"), "{}")
		if v, ok := vals[name]; ok {
			return v
		}
		return tok
	})
}

// unescapeShell undoes the common backslash escapes bash introduces inside a
// double-quoted echo argument, so the scanner sees `f"` not `f\"`.
func unescapeShell(s string) string {
	return strings.NewReplacer(`\"`, `"`, `\'`, `'`, `\$`, `$`, `\\`, `\`).Replace(s)
}

// heredocBody returns the text between the heredoc opener and its closing
// delimiter line.
func heredocBody(cmd string, from int, delim string) string {
	rest := cmd[from:]
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return ""
	}
	var body []string
	for _, ln := range strings.Split(rest[nl+1:], "\n") {
		if strings.TrimSpace(ln) == delim {
			return strings.Join(body, "\n")
		}
		body = append(body, ln)
	}
	return strings.Join(body, "\n") // unterminated: take what we have
}
