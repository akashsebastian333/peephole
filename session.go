package main

import (
	"os"
	"path/filepath"
	"sort"
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

// n3sec: the UserPromptSubmit classifier matched this task to CWE candidates -
// the blueprint's N6 trigger ("writes touched trust-boundary paths, per N3").
// Fires the Stop self-review even when no presence finding ever landed, which
// is exactly the semantic-class (IDOR/race/business-logic) coverage gap. The
// file stores the top classes so the review is TARGETED, not generic.
func markN3Sec(sd, sid string, cwes []string) {
	_ = os.WriteFile(sidFile(sd, sid, "n3sec"), []byte(strings.Join(cwes, ",")), 0o600)
}

func sessionN3Sec(sd, sid string) (string, bool) {
	b, err := os.ReadFile(sidFile(sd, sid, "n3sec"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// semreview: the union of absence-of-guard classes (idor/race/csrf/bizlogic/
// ratelimit) the LANDED code touched this session, accumulated at PostToolUse.
// The Stop self-review fires only when this is non-empty, scoped to these classes
// - so pattern-tier code that touches none skips the review continuation entirely.
func markSemReview(sd, sid string, keys []string) { addSessionSet(sd, sid, "semreview", keys) }
func sessionSemReview(sd, sid string) []string    { return readSessionSet(sd, sid, "semreview") }

// reviewedClasses: the semantic classes the Stop self-review has already covered.
// Tracked per-class (not a one-shot flag) so a class first introduced DURING the
// forced continuation is still reviewed on the next Stop.
func markReviewedClasses(sd, sid string, keys []string) { addSessionSet(sd, sid, "reviewed", keys) }
func sessionReviewedClasses(sd, sid string) []string    { return readSessionSet(sd, sid, "reviewed") }

// addSessionSet unions keys into a comma-joined per-session set file.
func addSessionSet(sd, sid, name string, keys []string) {
	if len(keys) == 0 {
		return
	}
	m := map[string]bool{}
	for _, k := range readSessionSet(sd, sid, name) {
		m[k] = true
	}
	for _, k := range keys {
		m[k] = true
	}
	all := make([]string, 0, len(m))
	for k := range m {
		all = append(all, k)
	}
	sort.Strings(all)
	_ = os.WriteFile(sidFile(sd, sid, name), []byte(strings.Join(all, ",")), 0o600)
}

func readSessionSet(sd, sid, name string) []string {
	b, err := os.ReadFile(sidFile(sd, sid, name))
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), ",")
}

// armNegTest records the adversarial input a Stop-time test must exercise.
func armNegTest(sd, sid, hint string) {
	if hint == "" {
		hint = "the adversarial input for this vulnerability class"
	}
	_ = os.WriteFile(sidFile(sd, sid, "negtest"), []byte(hint), 0o600)
}

// incDeny records another PreToolUse deny this session and returns the new count.
// A normal session has 0-1 denies; a rising count is the signature of a
// deny -> rewrite -> deny retry loop, which the caller uses to terminate the loop
// (a blocking guardrail that never terminates is a livelock, not security).
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

// denyStreak returns how many times IN A ROW the same rule has denied this
// session (a different rule denying resets it). Keying the loop detector on the
// rule the guardrail itself emitted - not on the payload - makes it invariant to
// the model (or an adaptive attacker) mutating the payload to change its hash
// while pursuing the identical blocked intent: the payload keeps changing but the
// rule keeps firing, so the streak still climbs and the loop still terminates.
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
