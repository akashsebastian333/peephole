package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Peephole hook binary. Invoked as:
// peephole hook read a hook event on stdin, decide, emit (default)
// peephole mode <m> set enforcement mode for the project (skills use this)
// peephole selfcheck verify binary integrity (tests + /sec-audit)
// peephole audit print the /sec-audit report for the project
// peephole genmanifest (build) hash bin/* into bin/manifest.sha256

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "mode":
			cliMode(args[1:])
			return
		case "selfcheck":
			cliSelfcheck()
			return
		case "audit":
			cliAudit()
			return
		case "debt":
			cliDebt()
			return
		case "scan":
			cliScan(args[1:])
			return
		case "warmcache":
			cliWarmcache()
			return
		case "sarif":
			cliSarif(args[1:])
			return
		case "mcp":
			cliMCP()
			return
		case "lsp":
			cliLSP()
			return
		case "statusline":
			cliStatusline()
			return
		case "genmanifest":
			if err := genManifest(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("manifest written:", manifestPath())
			return
		case "hook":
			setDialect(args[1:])
			// fall through
		}
	}
	runHook()
}

func runHook() {
	e := readEvent()
	kb := loadKB()
	kb.loadUserRules(projectDir(e)) // additive project-local / org rules
	done := make(chan struct{})
	go func() {
		// A panic (e.g. unexpected event shape) must fail closed for enforcement,
		// not crash the process into an exit-2 with a stack trace on every event.
		defer func() {
			if r := recover(); r != nil {
				timeoutFailClosed(e)
			}
		}()
		dispatch(e, kb) // handlers exit the process on decision
		close(done)
	}()
	// Never-hang watchdog (2s work budget). On expiry the
	// enforcement events fail closed; advisory events fail open.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		timeoutFailClosed(e)
	}
	os.Exit(0)
}

func timeoutFailClosed(e Event) {
	// Best-effort log of the timeout itself (advisory hooks fail open WITH a log
	// entry; the lock waits at most ~200ms so this can't re-hang).
	appendLog(stateDir(e), logEntry{Decision: "internal-timeout", Tool: e.ToolName})
	if e.HookEventName == "PreToolUse" {
		if m := getMode(e); m == "strict" || m == "hardened" {
			hardBlock("timed out - failing closed (enforcement). Retry, or /peephole off to disable.")
		}
	}
	// advisory events and audit mode: fail open, but visibly and logged.
	passthrough("[peephole] internal timeout - advisory path failed open (logged). Retry if a decision was expected.")
}

func cliMode(a []string) {
	if len(a) < 1 {
		fmt.Fprintln(os.Stderr, "usage: peephole mode <audit|strict|hardened|off>")
		os.Exit(1)
	}
	cwd, _ := os.Getwd()
	if err := setMode(Event{Cwd: cwd}, a[0]); err != nil {
		fmt.Fprintln(os.Stderr, "invalid mode:", a[0])
		os.Exit(1)
	}
	fmt.Println("peephole mode set to", a[0])
}

func cliSelfcheck() {
	ok, detail := verifySelf()
	if ok {
		fmt.Println("peephole integrity: OK")
		return
	}
	fmt.Println("peephole integrity: FAIL - ", detail)
	os.Exit(1)
}

func cliAudit() {
	cwd, _ := os.Getwd()
	e := Event{Cwd: cwd}
	sd := stateDir(e)
	root := projectDir(e)
	fmt.Println("peephole /sec-audit - ", root)
	fmt.Println("mode:", getMode(e))
	if ok, detail := verifySelf(); ok {
		fmt.Println("binary integrity: OK")
	} else {
		fmt.Println("binary integrity: ALARM - ", detail)
	}

	f, err := os.Open(filepath.Join(sd, "log.jsonl"))
	if err != nil {
		fmt.Println("no decision log yet.")
		return
	}
	defer f.Close()
	tally := map[string]int{}
	byCWE := map[string]int{}
	var markers, n6Exhausted int
	born, nonSec, landedAudit := 0, 0, 0
	writeDecisions := 0
	total := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		var ent logEntry
		if json.Unmarshal(sc.Bytes(), &ent) != nil {
			continue
		}
		total++
		tally[ent.Decision]++
		if ent.CWE != "" {
			byCWE[ent.CWE]++
		}
		if ent.Marker {
			markers++
		}
		if ent.Decision == "n6-exhausted" {
			n6Exhausted++
		}
		switch {
		case ent.Decision == "allow" && ent.CWE == "" && ent.Rel:
			born++ // security-relevant hunk, clean at first write
		case ent.Decision == "allow" && ent.CWE == "":
			nonSec++ // clean write, not security-relevant
		case ent.Decision == "allow" && ent.CWE != "":
			landedAudit++ // audit-mode warn: the finding LANDED
		}
		switch ent.Tool {
		case "Write", "Edit", "MultiEdit", "NotebookEdit", "Bash", "Bash(write-path)", "Bash(command)":
			writeDecisions++
		default:
			if strings.HasPrefix(ent.Tool, "mcp__") {
				writeDecisions++
			}
		}
	}
	fmt.Printf("decisions logged: %d  (deny=%d ask=%d allow=%d retro-flag=%d rewrite=%d)\n",
		total, tally["deny"], tally["ask"], tally["allow"], tally["retro-flag"], tally["rewrite"])
	// Born-secure decomposition (N2): over SECURITY-RELEVANT hunks only - a clean
	// README edit is not a security win. "born" counts relevant hunks clean at
	// first write; "landed insecure" = retro-flags + audit-mode warns (in audit
	// mode a finding is allowed through, which is a landed vuln, never "born").
	gate := tally["deny"] + tally["ask"]
	landed := tally["retro-flag"] + landedAudit
	fmt.Printf("born-secure (N2, heuristic-tagged): %d born clean / %d prevented at gate / %d offered secure-rewrite / %d landed insecure / %d non-security writes\n",
		born, gate, tally["rewrite"], landed, nonSec)
	if rel := born + gate + landed; rel > 0 {
		fmt.Printf("born-secure rate: %.0f%% of %d security-relevant hunk(s) were clean at first write (instrumentation, not proof)\n",
			100*float64(born)/float64(rel), rel)
	}
	// §7.4 FP-budget instrumentation: unsolicited asks per 20 write decisions.
	if writeDecisions > 0 {
		fmt.Printf("interruption rate: %.1f asks+denies per 20 write-gate decisions (budget: <= 1 unsolicited ask per 20 writes)\n",
			20*float64(tally["deny"]+tally["ask"])/float64(writeDecisions))
	}
	if markers > 0 {
		fmt.Printf("sec-debt waiver requests logged: %d (cross-check against .peephole/secdebt-approved)\n", markers)
	}
	if n6Exhausted > 0 {
		fmt.Printf("negative-test mandate exhausted without compliance: %d (sec-debt events requiring human acknowledgment)\n", n6Exhausted)
	}
	if unapproved := unapprovedMarkers(root, sd); len(unapproved) > 0 {
		fmt.Printf("UNAPPROVED sec-debt markers in the tree (evasion risk, N4): %d\n", len(unapproved))
		for _, m := range unapproved {
			fmt.Printf("  - %s:%d  %s\n", m.File, m.Line, truncate(m.Text, 80))
		}
	}
	if len(byCWE) > 0 {
		fmt.Println("by CWE:")
		for cwe, n := range byCWE {
			fmt.Printf("  %s: %d\n", cwe, n)
		}
		// OWASP 2025 rollup (compliance evidence).
		byOWASP := map[string]int{}
		for cwe, n := range byCWE {
			cat := cweToOWASP[cwe]
			if cat == "" {
				cat = "A00"
			}
			byOWASP[cat] += n
		}
		fmt.Println("by OWASP 2025:")
		for _, cat := range []string{"A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10", "A00"} {
			if n := byOWASP[cat]; n > 0 {
				fmt.Printf("  %s %s: %d\n", cat, owaspName[cat], n)
			}
		}
	}
	if ok, bad := verifyChain(sd); ok {
		fmt.Println("log chain: intact")
	} else {
		fmt.Printf("log chain: BROKEN at line %d - possible tampering/truncation\n", bad+1)
	}
}

// unapprovedMarkers harvests the tree for sec-debt markers lacking a matching
// human approval (blueprint N4: unapproved markers are surfaced in /sec-audit).
func unapprovedMarkers(root, sd string) []debtMarker {
	approvals := loadApprovals(sd)
	var out []debtMarker
	for _, m := range harvestSecDebt(root) {
		if !isApproved(m, approvals) {
			out = append(out, m)
		}
	}
	return out
}

// cliWarmcache refreshes the slopsquat cache for the project's manifest deps in
// the background. Spawned detached by SessionStart (spawnWarmcache), so the
// first install command of a session hits a warm cache instead of eating a
// 1-2s live registry check on the write path. Silent, best-effort, bounded.
func cliWarmcache() {
	cwd, _ := os.Getwd()
	e := Event{Cwd: cwd}
	root := projectDir(e)
	sd := stateDir(e)
	if err := os.MkdirAll(sd, 0o700); err != nil {
		return
	}
	var deps []Install
	for _, m := range []string{"requirements.txt", "pyproject.toml", "Pipfile", "package.json"} {
		if b, err := os.ReadFile(filepath.Join(root, m)); err == nil {
			deps = append(deps, extractManifestDeps(m, string(b))...)
		}
	}
	var live []Install
	for _, in := range deps {
		if checkPackageOffline(sd, in) == pkgUnknown {
			live = append(live, in)
		}
	}
	if len(live) > 0 {
		checkPackagesLive(sd, live) // populates the 7-day disk cache
	}
}

// spawnWarmcache launches `peephole warmcache` detached at SessionStart when the
// project has a dependency manifest. Fire-and-forget: setsid, stdio discarded,
// never waited on - SessionStart latency is unaffected (~1 fork).
func spawnWarmcache(e Event) {
	root := projectDir(e)
	hasManifest := false
	for _, m := range []string{"requirements.txt", "pyproject.toml", "Pipfile", "package.json"} {
		if fi, err := os.Stat(filepath.Join(root, m)); err == nil && fi.Size() > 0 {
			hasManifest = true
			break
		}
	}
	if !hasManifest {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "warmcache")
	cmd.Dir = root
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	detach(cmd)
	if err := cmd.Start(); err != nil {
		_ = os.WriteFile(filepath.Join(stateDir(e), "warmcache.err"), []byte(err.Error()), 0o600)
	}
	// deliberately not waited on
}

// cliScan scans one or more files and prints CWE findings. Exit 0 always (a
// scoring/dogfooding tool, not an enforcement path).
// cliScan scans files and prints CWE findings. Flags:
//
//	--gate     exit 2 if any HIGH-confidence finding (for a git pre-commit hook)
//	--staged   scan the git-staged files (--diff-filter=ACM) instead of args
func cliScan(args []string) {
	gate := false
	var paths []string
	for _, a := range args {
		switch a {
		case "--gate":
			gate = true
		case "--staged":
			paths = append(paths, stagedFiles()...)
		default:
			paths = append(paths, a)
		}
	}
	kb := loadKB()
	total, high := 0, 0
	readErr := false
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			// Never drop a requested path silently: a typo/dir/permission error would
			// otherwise produce a clean-looking report and pass a --gate hook.
			fmt.Fprintf(os.Stderr, "peephole: cannot read %s: %v\n", p, err)
			readErr = true
			continue
		}
		findings := kb.scan(p, string(b))
		if len(findings) == 0 {
			if !gate {
				fmt.Printf("%s: clean\n", p)
			}
			continue
		}
		for _, f := range findings {
			total++
			if f.Confidence == "high" {
				high++
			}
			fmt.Printf("%s: %s %s (%s)\n", p, f.Rule.CWE, f.Rule.Name, f.Confidence)
		}
	}
	fmt.Printf("total findings: %d (%d high-confidence)\n", total, high)
	if gate && (high > 0 || readErr) {
		fmt.Fprintln(os.Stderr, "peephole: blocking - high-confidence security findings or unreadable paths above. Fix them, or commit with --no-verify to override.")
		os.Exit(2)
	}
}

// stagedFiles returns the git-staged (added/copied/modified) file paths.
func stagedFiles() []string {
	out, err := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM").Output()
	if err != nil {
		return nil
	}
	var files []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			if _, e := os.Stat(l); e == nil {
				files = append(files, l)
			}
		}
	}
	return files
}

// cliStatusline prints the peephole badge for the Claude Code status line:
// mode + this project's block/warn tally + rule count. Claude Code passes the
// session JSON on stdin; we read cwd from it (falling back to getwd).
func cliStatusline() {
	cwd, _ := os.Getwd()
	var in struct {
		Cwd       string `json:"cwd"`
		Workspace struct {
			CurrentDir string `json:"current_dir"`
		} `json:"workspace"`
	}
	if raw, err := io.ReadAll(os.Stdin); err == nil && len(raw) > 0 {
		if json.Unmarshal(raw, &in) == nil {
			if in.Workspace.CurrentDir != "" {
				cwd = in.Workspace.CurrentDir
			} else if in.Cwd != "" {
				cwd = in.Cwd
			}
		}
	}
	e := Event{Cwd: cwd}
	mode := getMode(e)
	if mode == "off" {
		fmt.Print("peephole off")
		return
	}
	deny, ask := 0, 0
	if f, err := os.Open(filepath.Join(stateDir(e), "log.jsonl")); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
		for sc.Scan() {
			var ent logEntry
			if json.Unmarshal(sc.Bytes(), &ent) == nil {
				switch ent.Decision {
				case "deny":
					deny++
				case "ask", "rewrite":
					ask++
				}
			}
		}
		f.Close()
	}
	fmt.Printf("peephole %s | %d blocked %d flagged | %d rules", mode, deny, ask, len(loadKB().Rules))
}

func cliDebt() {
	cwd, _ := os.Getwd()
	e := Event{Cwd: cwd}
	root := projectDir(e)
	markers := harvestSecDebt(root)
	approvals := loadApprovals(stateDir(e))
	fmt.Println("peephole /sec-debt - ", root)
	if len(markers) == 0 {
		fmt.Println("no sec-debt markers found.")
		return
	}
	var unapproved int
	for _, m := range markers {
		status := "APPROVED"
		if !isApproved(m, approvals) {
			status = "UNAPPROVED (evasion risk)"
			unapproved++
		}
		fmt.Printf("  %s:%d  [%s]\n    %s\n", m.File, m.Line, status, m.Text)
	}
	fmt.Printf("\n%d marker(s), %d unapproved. Approve by adding the file (or file:line) to .peephole/secdebt-approved.\n",
		len(markers), unapproved)
}
