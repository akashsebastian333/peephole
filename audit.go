package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Tamper-evident, content-redacted decision log. Blueprint: append-only
// .peephole/log.jsonl. A running SHA-256 hash folds in every entry; every
// chainEvery entries that running hash is committed to a `chain` field. Because
// each entry feeds the running hash, altering ANY line changes the next
// committed chain value, and the log.head sidecar (running hash + count) lets
// verifyChain also catch truncation of the tail after the last checkpoint. We
// log the decision, CWE, rule id, tool, and a short file digest, never code or
// secrets.
//
// Latency: the running hash + line count live in the O(1) sidecar so append
// never re-reads the (up to 10MB) log on the hot path.
const chainEvery = 50

type logEntry struct {
	TS       int64  `json:"ts"`
	Decision string `json:"decision"`
	CWE      string `json:"cwe,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	Tool     string `json:"tool,omitempty"`
	FileHash string `json:"file_hash,omitempty"`
	Marker   bool   `json:"marker,omitempty"` // sec-debt waiver request (N4)
	Rel      bool   `json:"rel,omitempty"`    // security-relevant hunk (N2 born-secure basis)
	Chain    string `json:"chain,omitempty"`
}

func logPath(sd string) string  { return filepath.Join(sd, "log.jsonl") }
func headPath(sd string) string { return filepath.Join(sd, "log.head") }

func readHead(sd string) (string, int) {
	b, err := os.ReadFile(headPath(sd))
	if err != nil {
		return "", 0
	}
	parts := strings.SplitN(strings.TrimSpace(string(b)), " ", 2)
	if len(parts) != 2 {
		return "", 0
	}
	n, _ := strconv.Atoi(parts[1])
	return parts[0], n
}

func writeHead(sd, running string, n int) {
	_ = os.WriteFile(headPath(sd), []byte(running+" "+strconv.Itoa(n)), 0o600)
}

// foldEntry advances the running hash with one entry's canonical (chain-free)
// body. Same function on write and verify so they agree.
func foldEntry(running string, ent logEntry) string {
	ent.Chain = ""
	body, _ := json.Marshal(ent)
	sum := sha256.Sum256(append([]byte(running), body...))
	return hex.EncodeToString(sum[:])
}

// withLock serializes append across concurrent hook processes (parallel
// subagents) via a best-effort lockfile. If it can't acquire within ~200ms it
// proceeds anyway, logging must never block enforcement.
func withLock(sd string, fn func()) {
	lp := filepath.Join(sd, "log.lock")
	for i := 0; i < 200; i++ {
		f, err := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			defer os.Remove(lp)
			fn()
			return
		}
		time.Sleep(time.Millisecond)
	}
	fn()
}

// appendLog writes one redacted entry. Never returns an error (logging must not
// break enforcement).
func appendLog(sd string, ent logEntry) {
	if err := os.MkdirAll(sd, 0o700); err != nil {
		return
	}
	withLock(sd, func() {
		p := logPath(sd)
		if fi, err := os.Stat(p); err == nil && fi.Size() > 10*1024*1024 {
			_ = os.Rename(p, p+".1")
			writeHead(sd, "", 0)
		}
		running, n := readHead(sd)
		ent.TS = time.Now().Unix()
		newN := n + 1
		running = foldEntry(running, ent)
		if newN%chainEvery == 0 {
			ent.Chain = running
		}
		line, _ := json.Marshal(ent)
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		defer f.Close()
		f.Write(append(line, '\n'))
		writeHead(sd, running, newN)
	})
}

// verifyChain recomputes the running hash and checks it at every committed
// checkpoint and against the head sidecar (which detects truncation of entries
// after the last checkpoint). Returns (ok, firstBadLine).
func verifyChain(sd string) (bool, int) {
	f, err := os.Open(logPath(sd))
	if err != nil {
		return true, -1 // no log yet
	}
	defer f.Close()
	running := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	i := -1
	for sc.Scan() {
		i++
		var ent logEntry
		if err := json.Unmarshal(sc.Bytes(), &ent); err != nil {
			return false, i
		}
		stored := ent.Chain
		running = foldEntry(running, ent)
		if stored != "" && stored != running {
			return false, i
		}
	}
	// Truncation check: the head sidecar holds the running hash and count as of
	// the last append. A shorter/altered tail won't reproduce it.
	if hHash, hN := readHead(sd); hN != 0 && (hN != i+1 || hHash != running) {
		return false, i + 1
	}
	return true, -1
}

func fileDigest(content string) string {
	if content == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])[:16]
}

func bumpDecisionCount(sd, sid string) {
	_ = os.WriteFile(sidFile(sd, sid, "decisions"), []byte(strconv.Itoa(decisionCount(sd, sid)+1)), 0o600)
}

func decisionCount(sd, sid string) int {
	b, err := os.ReadFile(sidFile(sd, sid, "decisions"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
