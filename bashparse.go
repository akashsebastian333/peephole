package main

import (
	"regexp"
	"strings"
)

type WritePayload struct {
	Target  string
	Content string
}

type Install struct {
	Manager string
	Pkg     string
}

type BashAnalysis struct {
	Payloads      []WritePayload
	Installs      []Install
	Uninspectable bool
	Reason        string
	Targets       []string
	InstallSmells []string
}

var (
	reHeredoc            = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	reRedirect           = regexp.MustCompile(`(?:[0-9&]*>>?\|?|\btee\b(?:\s+-a)?)\s*([^\s;&|<>()]+)`)
	reEchoWrite          = regexp.MustCompile(`\b(?:echo|printf)\b\s+([^|]*?)\s*>>?\s*[^\s;&|<>]+`)
	reCopyMove           = regexp.MustCompile(`\b(?:cp|mv|dd|rsync|ln)\b[^;&|]*\s([^\s;&|<>]+)\s*(?:[;&|]|$)`)
	reGitApply           = regexp.MustCompile(`\bgit\s+apply\b|\bpatch\b\s+-`)
	reSedInplace         = regexp.MustCompile(`\bsed\b[^|;&]*\s-i\b`)
	reInterp             = regexp.MustCompile(`\b(?:(?:python3?|node|deno|bun|ruby|perl|bash|sh)(?:\s+-[\w-]+)*\s+(?:-c|-e)|php(?:\s+-[\w-]+)*\s+-r)\s+('((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")`)
	reInstall            = regexp.MustCompile(`\b(pip3?|uv\s+pip|poetry|pipenv|npm|pnpm|yarn|bun|go)\s+(?:install|add|get|i)\b([^\n;&|]*)`)
	reUninspect          = regexp.MustCompile(`base64\s+-+d|base64\s+--decode|\|\s*(?:sh|bash|zsh|ed|ex|python3?|node|deno|bun|ruby|perl|php|tclsh|Rscript)\b|\b(?:ed|ex)\s+-|eval\s+"?\$\(|xxd\s+-r|(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh|python3?|node|ruby|perl|php)`)
	reObfExec            = regexp.MustCompile(`(?i)b64decode|base64|codecs\.decode|marshal\.loads|\bexec\s*\(|\beval\s*\(|__import__|fromhex|bytes\.fromhex|zlib\.decompress`)
	reUnresolvableTarget = regexp.MustCompile(`[*?\[\]{}$~]`)
	reInterpDashC        = regexp.MustCompile(`\b(?:(?:python3?|node|deno|bun|ruby|perl|bash|sh)(?:\s+-[\w-]+)*\s+(?:-c|-e)|php(?:\s+-[\w-]+)*\s+-r)\b`)
	reShellNoise         = regexp.MustCompile("[\"'\\\\\\[\\]{}]")
	reCmdSubst           = regexp.MustCompile(`\$[({]|` + "`" + `|\$[A-Za-z_]`)
	reInstallBin         = regexp.MustCompile(`(?:^|[\n;&|])\s*(?:sudo\s+)?install\s+-[DmogtTsSbpvcd]`)
	reEscapeDecodeWrite  = regexp.MustCompile(`\b(?:echo\s+-e\b|printf\b)[^;&|]*(?:\\x[0-9a-fA-F]|\\0[0-7]{2}|%b)[^;&|]*>`)
	rePkgClean           = regexp.MustCompile(`^[@A-Za-z0-9._/-]+`)
	reFlagValue          = regexp.MustCompile(`^-(?:r|c|f|e|i|-requirement|-constraint|-find-links|-editable|-index-url|-extra-index-url)$`)
	reFilePath           = regexp.MustCompile(`\.(?:txt|whl|tar|gz|tgz|zip|cfg|toml|lock|in|json)$`)
	reIndexURLLong       = regexp.MustCompile(`--(?:extra-)?index-url(?:=|\s+)(\S+)`)
	reRemoteInstall      = regexp.MustCompile(`\b(?:pip3?|npm|yarn|pnpm|bun)\s+(?:install|add|i)\s+[^\n;&|]*\b(git\+|https?://|git://|ssh://|file:)`)
	rePypiHost           = regexp.MustCompile(`(?i)^https?://(?:[\w.-]+\.)?(?:pypi\.org|pythonhosted\.org|npmjs\.org|npmjs\.com)`)
	rePipInstallShortI   = regexp.MustCompile(`(?i)((?:^|[\n;&|])\s*(?:sudo\s+)?(?:pip3?|uv\s+pip|poetry|pipenv)\s+(?:install|add|get|i)\b[^\n;&|]*?)\s+-i\s+[^\s;&|]+`)
)

var pipIndexManagers = map[string]bool{
	"pip": true, "pip3": true, "poetry": true, "pipenv": true, "uv": true,
}

func bashLooksLive(cmd string) bool {
	for i := 0; i < len(cmd); i++ {
		switch cmd[i] {
		case '>', '<', '|', '`', ';', '&', '(', ')':
			return true
		}
	}
	lc := asciiLower(cmd)
	for _, k := range bashLiveKw {
		if strings.Contains(lc, k) {
			return true
		}
	}
	return false
}

var bashLiveKw = []string{
	"pip", "npm", "yarn", "pnpm", "bun", "poetry", "pipenv", "uv ",
	"go get", "go install",
	"python", "node", "deno", "ruby", "perl", "php", "lua",
	"chmod", "umask", "curl", "wget", "base64", "eval",
	"install", "tee", "rsync", "sed", "patch", "git apply",
	"cp ", "mv ", "dd ", "ln ",
}

func analyzeBash(cmd string) BashAnalysis {
	if cmd == "" || !bashLooksLive(cmd) {
		return BashAnalysis{}
	}
	var a BashAnalysis

	hd := reHeredoc.FindAllStringSubmatchIndex(cmd, -1)
	if len(hd) > 16 {
		a.Uninspectable, a.Reason = true, "too many heredocs to inspect statically"
		hd = hd[:16]
	}
	for _, m := range hd {
		delim := cmd[m[2]:m[3]]
		if body := heredocBody(cmd, m[1], delim); body != "" {
			a.Payloads = append(a.Payloads, WritePayload{Content: body})
		}
	}
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
	if reInterpDashC.MatchString(cmd) && !reInterp.MatchString(cmd) {
		a.Uninspectable, a.Reason = true, "interpreter -c/-e code could not be extracted (obfuscated quoting) - not inspectable"
	}
	a.Installs = extractInstalls(cmd)
	for _, host := range unofficialIndexHosts(cmd) {
		a.InstallSmells = append(a.InstallSmells, "install uses a non-official package index ("+host+") - packages could be substituted; verify the host.")
	}
	if m := reRemoteInstall.FindStringSubmatch(stripIndexURLFlags(cmd)); m != nil {
		a.InstallSmells = append(a.InstallSmells, "install pulls from a remote/VCS source ("+m[1]+"...) that bypasses registry checks - confirm the source is trusted.")
	}
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
	if reSedInplace.MatchString(cmd) {
		a.Uninspectable = true
		if a.Reason == "" {
			a.Reason = "in-place edit (sed -i) - content not statically reconstructable"
		}
	}
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
	if reUninspect.MatchString(cmd) {
		a.Uninspectable = true
		if a.Reason == "" {
			a.Reason = "obfuscated or remote-sourced write/exec - payload not statically determinable"
		}
	}
	return a
}

func unofficialIndexHosts(cmd string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(host string) {
		host = strings.Trim(host, `"'`)
		if host == "" || rePypiHost.MatchString(host) || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
	}
	for _, m := range reIndexURLLong.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	for _, m := range reInstall.FindAllStringSubmatch(cmd, -1) {
		fields := strings.Fields(m[1])
		if len(fields) == 0 || !pipIndexManagers[fields[0]] {
			continue
		}
		toks := strings.Fields(m[2])
		for i := 0; i < len(toks); i++ {
			tok := toks[i]
			switch {
			case tok == "-i" || tok == "--index-url" || tok == "--extra-index-url":
				if i+1 < len(toks) {
					i++
					add(toks[i])
				}
			case strings.HasPrefix(tok, "--index-url="):
				add(strings.TrimPrefix(tok, "--index-url="))
			case strings.HasPrefix(tok, "--extra-index-url="):
				add(strings.TrimPrefix(tok, "--extra-index-url="))
			}
		}
	}
	return out
}

func stripIndexURLFlags(cmd string) string {
	s := reIndexURLLong.ReplaceAllString(cmd, " ")
	for {
		next := rePipInstallShortI.ReplaceAllString(s, "$1")
		if next == s {
			return s
		}
		s = next
	}
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
					i++
				}
				continue
			}
			if strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../") || strings.HasPrefix(tok, "/") || reFilePath.MatchString(tok) {
				continue
			}
			pkg := rePkgClean.FindString(tok)
			if i := strings.IndexAny(pkg, "=<>~!"); i >= 0 {
				pkg = pkg[:i]
			}
			if at := strings.LastIndex(pkg, "@"); at > 0 {
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

var reBenignProducer = regexp.MustCompile(`^\s*(?:sudo\s+)?(?:git|grep|rg|egrep|fgrep|find|ls|ll|cat|head|tail|sort|uniq|jq|yq|diff|wc|date|env|printenv|ps|whoami|hostname|uname|file|stat|tree|basename|dirname|pwd|seq|tr|cut|column|history|df|du|free|lsof|ss|dig|host|nslookup|make|cmake|go|cargo|npm|npx|yarn|pnpm|pip|pip3|pytest|python3?|node|deno|bun|jest|mocha|vitest|mvn|gradle|rake|rspec|phpunit|dotnet|swift|java|javac|gcc|g\+\+|clang|rustc|kotlinc)\b`)

var plainDataExt = map[string]bool{
	".log": true, ".txt": true, ".md": true, ".markdown": true, ".rst": true,
	".out": true, ".csv": true, ".tsv": true, ".diff": true, ".patch": true,
	".asc": true, ".sig": true, ".summary": true,
}

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

func stripShellNoise(s string) string {
	return reShellNoise.ReplaceAllString(s, "")
}

var (
	reShellAssign = regexp.MustCompile(`(?:^|[;&|]|\bexport\s+)\s*([A-Za-z_]\w*)=('[^']*'|"[^"]*"|[^\s;&|)]*)`)
	reShellVar    = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)\}?`)
)

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

func unescapeShell(s string) string {
	return strings.NewReplacer(`\"`, `"`, `\'`, `'`, `\$`, `$`, `\\`, `\`).Replace(s)
}

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
	return strings.Join(body, "\n")
}
