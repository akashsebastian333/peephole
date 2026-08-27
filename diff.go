package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func sessionDiff(root string) string {
	const maxDiffBytes = 6 * 1024
	var b strings.Builder
	diff, err := exec.Command("git", "-C", root, "diff", "HEAD", "--", ".").Output()
	if err != nil {
		diff, _ = exec.Command("git", "-C", root, "diff", "--", ".").Output()
	}
	b.Write(diff)
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
