package main

import (
	"testing"
)

// Component benchmarks for the PreToolUse write path. An external timer showed a
// clean 6-line Write costing ~49ms end-to-end on a loaded laptop while
// BenchmarkScanSmallWrite reports the scan itself at ~0.33ms, so ~37ms is spent
// somewhere other than scanning. These isolate each stage the write path actually
// executes so the cost can be attributed instead of guessed at.
//
// Run: go test -run '^$' -bench Hot -benchmem

func benchEvent(t testing.TB) (Event, ToolInput, string) {
	dir := t.TempDir()
	e := Event{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		SessionID:     "bench-session",
		Cwd:           dir,
	}
	ti := ToolInput{FilePath: dir + "/x.py", Content: "def f():\n    return 1\n"}
	return e, ti, ti.Content
}

func BenchmarkHotFileDigest(b *testing.B) {
	_, _, content := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		fileDigest(content)
	}
}

func BenchmarkHotHunkSeen(b *testing.B) {
	e, ti, content := benchEvent(b)
	sd := stateDir(e)
	b.ReportAllocs()
	for b.Loop() {
		hunkSeen(sd, e.SessionID, hunkKey(ti.targetPath(), content))
	}
}

func BenchmarkHotGetMode(b *testing.B) {
	e, _, _ := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		getMode(e)
	}
}

func BenchmarkHotLoadPolicy(b *testing.B) {
	e, _, _ := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		loadPolicy(projectDir(e))
	}
}

// BenchmarkHotAppendLog is the audit-chain append: lockfile, read head, fold the
// SHA-256 chain, append the entry, rewrite the head.
func BenchmarkHotAppendLog(b *testing.B) {
	e, _, _ := benchEvent(b)
	sd := stateDir(e)
	b.ReportAllocs()
	for b.Loop() {
		appendLog(sd, logEntry{Decision: "allow", Tool: "Write", FileHash: "deadbeef"})
	}
}

func BenchmarkHotBumpDecisionCount(b *testing.B) {
	e, _, _ := benchEvent(b)
	sd := stateDir(e)
	b.ReportAllocs()
	for b.Loop() {
		bumpDecisionCount(sd, e.SessionID)
	}
}

func BenchmarkHotSecurityRelevant(b *testing.B) {
	kb := loadKB()
	_, ti, content := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		kb.securityRelevant(ti.targetPath(), content)
	}
}

func BenchmarkHotSemReviewKeys(b *testing.B) {
	_, _, content := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		semReviewKeys(content)
	}
}

// BenchmarkHotSecureRewrite runs on every Write with a finding, and it re-scans
// the rewritten content, so it can double the scan cost.
func BenchmarkHotSecureRewrite(b *testing.B) {
	content := "import yaml\n\n\ndef load(p):\n    return yaml.load(open(p))\n"
	b.ReportAllocs()
	for b.Loop() {
		secureRewrite(content)
	}
}
