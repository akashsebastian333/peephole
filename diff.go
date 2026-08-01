package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// sessionDiff returns the session's working-tree diff (bounded), for the
// Stop-time diff-grounded self-review. Covers staged + unstaged changes and
// new untracked source files. Returns "" outside a git repo or on any error -
// the caller falls back to the plain checklist. This runs at Stop, off the hot
// path; it makes the existing forced continuation concrete without adding one.
func sessionDiff(root string) string {
	const maxDiffBytes = 6 * 1024
	var b strings.Builder
	// tracked changes (staged + unstaged vs HEAD; fresh repos have no HEAD yet)
	diff, err := exec.Command("git", "-C", root, "diff", "HEAD", "--", ".").Output()
	if err != nil {
		diff, _ = exec.Command("git", "-C", root, "diff", "--", ".").Output()
	}
	b.Write(diff)
	// untracked files (new files have no diff entry) - repo-relative paths from
	// git status, read with a containment check, capped
	st, err := exec.Command("git", "-C", root, "status", "--porcelain", "--", ".").Output()
	if err != nil {
		return strings.TrimSpace(b.String())
	}
	for _, ln := range strings.Split(string(st), "\n") {
		if !strings.HasPrefix(ln, "?? ") || b.Len() >= maxDiffBytes {
			continue
		}
		f := strings.TrimSpace(ln[3:])
		abs := filepath.Clean(filepath.Join(root, f))
		if !contained(abs, root) {
			continue
		}
		if fi, err := os.Stat(abs); err != nil || fi.Size() > 64*1024 {
			continue
		}
		if c, err := os.ReadFile(abs); err == nil {
			b.WriteString("\n--- /dev/null\n+++ b/" + f + "\n")
			b.Write(c)
		}
	}
	out := b.String()
	if len(out) > maxDiffBytes {
		out = out[:maxDiffBytes] + "\n... (diff truncated)"
	}
	return strings.TrimSpace(out)
}
