package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func sidFile(sd, sid, suffix string) string {
	if sid == "" {
		sid = "nosession"
	}
	sid = strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(sid)
	dir := filepath.Join(sd, "session")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, sid+"."+suffix)
}

func markSessionWrite(sd, sid string) {
	_ = os.WriteFile(sidFile(sd, sid, "wrote"), []byte("1"), 0o600)
}

func sessionSawWrite(sd, sid string) bool {
	_, err := os.Stat(sidFile(sd, sid, "wrote"))
	return err == nil
}

func markSemReview(sd, sid string, keys []string) { addSessionSet(sd, sid, "semreview", keys) }
func sessionSemReview(sd, sid string) []string    { return readSessionSet(sd, sid, "semreview") }

func markReviewedClasses(sd, sid string, keys []string) { addSessionSet(sd, sid, "reviewed", keys) }
func sessionReviewedClasses(sd, sid string) []string    { return readSessionSet(sd, sid, "reviewed") }

// addSessionSet appends keys to a per-session set file. Concurrent tool calls
// spawn concurrent PostToolUse hooks that all write the same set, and a dropped
// key means the Stop self-review silently skips that class.
//
// This is APPEND-ONLY on purpose. The previous version did a read-modify-write
// inside withLock, but withLock deliberately gives up after ~200ms of contention
// and runs the callback anyway ("logging must never block enforcement") — correct
// for the append-only audit chain, fatal here: two unlocked read-modify-writes
// each write a union that omits the other's keys, and last-rename-wins drops one.
// TestAddSessionSetConcurrent failed roughly 1 run in 5 for exactly that reason,
// more often under load, which is precisely when concurrent hooks are likely.
//
// A single O_APPEND write of a short record is atomic on POSIX, so concurrent
// writers interleave records but cannot lose one. Correctness no longer depends
// on the lock, so the lock is gone from this path — one less contended file
// operation per gated event, which also matters on endpoints where every file
// operation is AV-inspected. readSessionSet unions and dedupes on read.
func addSessionSet(sd, sid, name string, keys []string) {
	if len(keys) == 0 {
		return
	}
	if err := os.MkdirAll(sd, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(sidFile(sd, sid, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	// One Write call, one record, newline-terminated: never torn across appends.
	_, _ = f.WriteString(strings.Join(keys, ",") + "\n")
}

// readSessionSet unions every appended record. Tolerates the previous
// single-line comma-joined format, so a set file written by an older binary
// mid-session still reads correctly.
func readSessionSet(sd, sid, name string) []string {
	b, err := os.ReadFile(sidFile(sd, sid, name))
	if err != nil {
		return nil
	}
	m := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		for _, k := range strings.Split(strings.TrimSpace(line), ",") {
			if k = strings.TrimSpace(k); k != "" {
				m[k] = true
			}
		}
	}
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func armNegTest(sd, sid, hint string) {
	if hint == "" {
		hint = "the adversarial input for this vulnerability class"
	}
	_ = os.WriteFile(sidFile(sd, sid, "negtest"), []byte(hint), 0o600)
}

func incDeny(sd, sid string) int {
	p := sidFile(sd, sid, "denies")
	n := 0
	if b, err := os.ReadFile(p); err == nil {
		n, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	n++
	_ = os.WriteFile(p, []byte(strconv.Itoa(n)), 0o600)
	return n
}

func denyStreak(sd, sid, key string) int {
	p := sidFile(sd, sid, "denystreak")
	n := 1
	if b, err := os.ReadFile(p); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			if i := strings.LastIndexByte(s, '\t'); i >= 0 && s[:i] == key {
				if v, e := strconv.Atoi(s[i+1:]); e == nil {
					n = v + 1
				}
			}
		}
	}
	_ = os.WriteFile(p, []byte(key+"\t"+strconv.Itoa(n)), 0o600)
	return n
}

func pendingNegativeTest(sd, sid string) (string, bool) {
	b, err := os.ReadFile(sidFile(sd, sid, "negtest"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func clearNegTest(sd, sid string) {
	_ = os.Remove(sidFile(sd, sid, "negtest"))
}

const maxNegContinuations = 2

func bumpNegCount(sd, sid string) int {
	n := negCount(sd, sid) + 1
	_ = os.WriteFile(sidFile(sd, sid, "negcount"), []byte(strconv.Itoa(n)), 0o600)
	return n
}

func negCount(sd, sid string) int {
	b, err := os.ReadFile(sidFile(sd, sid, "negcount"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func resetNegCount(sd, sid string) {
	_ = os.Remove(sidFile(sd, sid, "negcount"))
}

func recordMarker(sd, sid, path, content string, f Finding) {
	line := firstMatchLine(f.Rule, "", content)
	lines := strings.Split(content, "\n")
	markerLine := line
	for i := line - 1; i >= 0 && i >= line-6 && i < len(lines); i-- {
		if reSecDebt.MatchString(lines[i]) {
			markerLine = i + 1
			break
		}
	}
	if path == "" {
		path = "(bash-write-path)"
	}
	entry := path + ":" + strconv.Itoa(markerLine)
	f2 := sidFile(sd, sid, "markers")
	existing, _ := os.ReadFile(f2)
	for _, l := range strings.Split(string(existing), "\n") {
		if l == entry {
			return
		}
	}
	mf, err := os.OpenFile(f2, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer mf.Close()
	mf.WriteString(entry + "\n")
}

func unapprovedSessionMarkers(sd, sid string) []string {
	b, err := os.ReadFile(sidFile(sd, sid, "markers"))
	if err != nil {
		return nil
	}
	approvals := loadApprovals(sd)
	var bad []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		file, line, _ := strings.Cut(l, ":")
		ln, _ := strconv.Atoi(line)
		if !isApproved(debtMarker{File: file, Line: ln}, approvals) {
			bad = append(bad, l)
		}
	}
	return bad
}

const hunkMemoCap = 500

func recordHunk(sd, sid, digest string) {
	if digest == "" {
		return
	}
	if hunkSeen(sd, sid, digest) {
		return
	}
	f, err := os.OpenFile(sidFile(sd, sid, "hunks"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(digest + "\n")
}

func hunkSeen(sd, sid, digest string) bool {
	if digest == "" {
		return false
	}
	b, err := os.ReadFile(sidFile(sd, sid, "hunks"))
	if err != nil {
		return false
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > hunkMemoCap {
		lines = lines[len(lines)-hunkMemoCap:]
	}
	for _, l := range lines {
		if l == digest {
			return true
		}
	}
	return false
}

func lastReviewedCommit(sd string) string {
	b, _ := os.ReadFile(filepath.Join(sd, "lastcommit"))
	return strings.TrimSpace(string(b))
}

func markReviewedCommit(sd, hash string) {
	_ = os.WriteFile(filepath.Join(sd, "lastcommit"), []byte(hash), 0o600)
}

func mentionsTest(msg string) bool {
	m := strings.ToLower(msg)
	hasTest := strings.Contains(m, "test") || strings.Contains(m, "assert")
	hasReject := strings.Contains(m, "reject") || strings.Contains(m, "raise") ||
		strings.Contains(m, "400") || strings.Contains(m, "error") || strings.Contains(m, "block")
	return hasTest && hasReject
}

func payloadOf(hint string) string {
	best := ""
	for _, q := range []byte{'"', '\'', '`'} {
		a := strings.IndexByte(hint, q)
		if a < 0 {
			continue
		}
		b := strings.IndexByte(hint[a+1:], q)
		if b < 0 {
			continue
		}
		if s := strings.TrimSpace(hint[a+1 : a+1+b]); len(s) >= 5 && len(s) > len(best) {
			best = s
		}
	}
	return best
}

func normWS(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }

func testExercised(msg, hint string, wantTest bool) bool {
	if wantTest {
		if pl := payloadOf(hint); pl != "" {
			return strings.Contains(normWS(msg), normWS(pl))
		}
	}
	return mentionsTest(msg)
}
