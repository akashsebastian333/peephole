package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Per-session state backing the Stop-time gates (N6 negative-test, zero-decision
// alarm). Keyed by session id, not per-project, so one session hitting the
// continuation cap doesn't disarm the gate forever, and a stale write marker
// from a past session doesn't trigger a false tamper alarm in a new one.

func sidFile(sd, sid, suffix string) string {
	if sid == "" {
		sid = "nosession"
	}
	sid = strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(sid)
	dir := filepath.Join(sd, "session")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, sid+"."+suffix)
}

// markSessionWrite records that a write landed (PostToolUse), independent of
// whether a decision was logged, that decoupling lets the zero-decision alarm
// detect a disabled/tampered PreToolUse gate.
func markSessionWrite(sd, sid string) {
	_ = os.WriteFile(sidFile(sd, sid, "wrote"), []byte("1"), 0o600)
}

func sessionSawWrite(sd, sid string) bool {
	_, err := os.Stat(sidFile(sd, sid, "wrote"))
	return err == nil
}

// sec-relevant: security-relevant code was involved this session (a gate
// decision on a finding, or a finding that landed). Gates the Stop self-review.
func markSecRelevant(sd, sid string) {
	_ = os.WriteFile(sidFile(sd, sid, "secrel"), []byte("1"), 0o600)
}

func sessionSecRelevant(sd, sid string) bool {
	_, err := os.Stat(sidFile(sd, sid, "secrel"))
	return err == nil
}

// reviewed: the Stop-time semantic self-review already fired (one-shot).
func markReviewed(sd, sid string) {
	_ = os.WriteFile(sidFile(sd, sid, "reviewed"), []byte("1"), 0o600)
}

func sessionReviewed(sd, sid string) bool {
	_, err := os.Stat(sidFile(sd, sid, "reviewed"))
	return err == nil
}

// armNegTest records the adversarial input a Stop-time test must exercise.
func armNegTest(sd, sid, hint string) {
	if hint == "" {
		hint = "the adversarial input for this vulnerability class"
	}
	_ = os.WriteFile(sidFile(sd, sid, "negtest"), []byte(hint), 0o600)
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

// maxNegContinuations: the blueprint's N6 cap - at most 2 forced continuations,
// then exhaustion is logged as a sec-debt event rather than silently released.
const maxNegContinuations = 2

// bumpNegCount increments the session's forced-continuation count and returns it.
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

// --- N4 sec-debt marker tracking (gate-time -> Stop cross-check) ---

// recordMarker notes that a sec-debt marker downgraded a gate this session, as
// "path:line", so Stop can cross-check it against the human-owned approval file.
func recordMarker(sd, sid, path, content string, f Finding) {
	line := firstMatchLine(f.Rule, "", content)
	// find the marker line itself near the finding (on it or just above)
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
			return // already recorded
		}
	}
	mf, err := os.OpenFile(f2, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer mf.Close()
	mf.WriteString(entry + "\n")
}

// unapprovedSessionMarkers returns the session's recorded markers that have no
// matching human approval in .peephole/secdebt-approved (evasion, blueprint N4).
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

// --- hunk-hash memoization (§7.4: same finding never fires twice per hunk) ---

const hunkMemoCap = 500

// recordHunk notes the digest of content that landed (allowed or ask-approved).
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

// hunkSeen reports whether this exact content digest already landed this session.
func hunkSeen(sd, sid, digest string) bool {
	if digest == "" {
		return false
	}
	b, err := os.ReadFile(sidFile(sd, sid, "hunks"))
	if err != nil {
		return false
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > hunkMemoCap { // bound the scan; oldest fall off (conservative re-gate)
		lines = lines[len(lines)-hunkMemoCap:]
	}
	for _, l := range lines {
		if l == digest {
			return true
		}
	}
	return false
}

// --- commit-review dedupe (per project, not per session) ---

func lastReviewedCommit(sd string) string {
	b, _ := os.ReadFile(filepath.Join(sd, "lastcommit"))
	return strings.TrimSpace(string(b))
}

func markReviewedCommit(sd, hash string) {
	_ = os.WriteFile(filepath.Join(sd, "lastcommit"), []byte(hash), 0o600)
}

// mentionsTest heuristically detects whether the model's last message added a
// test that asserts a rejection, used to stop forcing continuations once one appears.
func mentionsTest(msg string) bool {
	m := strings.ToLower(msg)
	hasTest := strings.Contains(m, "test") || strings.Contains(m, "assert")
	hasReject := strings.Contains(m, "reject") || strings.Contains(m, "raise") ||
		strings.Contains(m, "400") || strings.Contains(m, "error") || strings.Contains(m, "block")
	return hasTest && hasReject
}

// payloadOf extracts the distinctive adversarial literal from a negative-test
// hint (e.g. ' OR '1'='1 from the SQLi hint), so the Stop gate can verify the
// model's test actually exercises that input, not merely that some test exists
// (N6: "existence of a test is not enough"). Returns "" when the
// hint carries no identifiable payload, in which case the caller falls back to
// the generic mentionsTest heuristic.
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

// testExercised reports whether the model's last message satisfies the armed
// negative-test requirement. When the hint carries a concrete payload, it must
// appear (whitespace/case-normalized) in the message, a real adversarial test,
// not a generic one. Otherwise it falls back to the mentionsTest heuristic.
func testExercised(msg, hint string, wantTest bool) bool {
	if wantTest {
		if pl := payloadOf(hint); pl != "" {
			return strings.Contains(normWS(msg), normWS(pl))
		}
	}
	return mentionsTest(msg)
}
