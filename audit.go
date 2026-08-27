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

const (
	chainEvery    = 50
	logMaxBytes   = 10 * 1024 * 1024
	logRetain     = 30 * 24 * time.Hour
	logPruneEvery = 24 * time.Hour
)

type logEntry struct {
	TS       int64  `json:"ts"`
	Decision string `json:"decision"`
	CWE      string `json:"cwe,omitempty"`
	RuleID   string `json:"rule_id,omitempty"`
	Tool     string `json:"tool,omitempty"`
	FileHash string `json:"file_hash,omitempty"`
	Marker   bool   `json:"marker,omitempty"`
	Rel      bool   `json:"rel,omitempty"`
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

func foldEntry(running string, ent logEntry) string {
	ent.Chain = ""
	body, _ := json.Marshal(ent)
	sum := sha256.Sum256(append([]byte(running), body...))
	return hex.EncodeToString(sum[:])
}

func withLock(sd string, fn func()) {
	lp := filepath.Join(sd, "log.lock")
	for i := 0; i < 400; i++ {
		f, err := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			defer os.Remove(lp)
			fn()
			return
		}
		if st, serr := os.Stat(lp); serr == nil && time.Since(st.ModTime()) > 3*time.Second {
			os.Remove(lp)
			continue
		}
		time.Sleep(time.Millisecond)
	}
	fn()
}

func appendLog(sd string, ent logEntry) {
	if err := os.MkdirAll(sd, 0o700); err != nil {
		return
	}
	withLock(sd, func() {
		p := logPath(sd)
		if fi, err := os.Stat(p); err == nil && fi.Size() > logMaxBytes {
			rotated := p + ".1"
			_ = os.Remove(rotated)
			_ = os.Rename(p, rotated)
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

func pruneStampPath(sd string) string { return filepath.Join(sd, "log.pruned") }

func recentlyPruned(sd string) bool {
	st, err := os.Stat(pruneStampPath(sd))
	return err == nil && time.Since(st.ModTime()) < logPruneEvery
}

func maybePruneAuditLog(sd string) {
	if recentlyPruned(sd) {
		return
	}
	pruneAuditLog(sd)
}

func pruneAuditLog(sd string) {
	if _, err := os.Stat(sd); err != nil {
		return
	}
	cutoff := time.Now().Add(-logRetain).Unix()
	withLock(sd, func() {
		recovered := recoverLogTmp(sd)
		dropExpiredArchives(sd, cutoff)
		compactLog(sd, cutoff, recovered)
		_ = os.WriteFile(pruneStampPath(sd), []byte("1\n"), 0o600)
	})
}

func recoverLogTmp(sd string) bool {
	p := logPath(sd)
	tmp := p + ".tmp"
	if _, err := os.Stat(p); err == nil {
		return false
	}
	if _, err := os.Stat(tmp); err != nil {
		return false
	}
	return os.Rename(tmp, p) == nil
}

func dropExpiredArchives(sd string, cutoff int64) {
	ents, err := os.ReadDir(sd)
	if err != nil {
		return
	}
	for _, e := range ents {
		name := e.Name()
		if name == "log.jsonl" || !strings.HasPrefix(name, "log.jsonl") {
			continue
		}
		p := filepath.Join(sd, name)
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.ModTime().Unix() < cutoff {
			_ = os.Remove(p)
		}
	}
}

func compactLog(sd string, cutoff int64, force bool) {
	p := logPath(sd)
	f, err := os.Open(p)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	var keep []logEntry
	dropped := false
	n := 0
	for sc.Scan() {
		n++
		var ent logEntry
		if json.Unmarshal(sc.Bytes(), &ent) != nil {
			dropped = true
			continue
		}
		if ent.TS >= cutoff {
			keep = append(keep, ent)
		} else {
			dropped = true
		}
		if n == 1 && !dropped && !force {
			f.Close()
			_ = os.Remove(p + ".tmp")
			return
		}
	}
	f.Close()
	if !dropped && !force {
		return
	}
	rewriteLog(sd, p, keep)
}

func rewriteLog(sd, p string, keep []logEntry) {
	if len(keep) == 0 {
		_ = os.Remove(p)
		writeHead(sd, "", 0)
		return
	}
	tmp := p + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(out)
	running := ""
	n := 0
	ok := true
	for _, ent := range keep {
		n++
		ent.Chain = ""
		running = foldEntry(running, ent)
		if n%chainEvery == 0 {
			ent.Chain = running
		}
		line, err := json.Marshal(ent)
		if err != nil {
			ok = false
			break
		}
		if _, err := w.Write(line); err != nil {
			ok = false
			break
		}
		if err := w.WriteByte('\n'); err != nil {
			ok = false
			break
		}
	}
	if ok {
		ok = w.Flush() == nil
	}
	out.Close()
	if !ok {
		_ = os.Remove(tmp)
		return
	}
	_ = os.Remove(p)
	if err := os.Rename(tmp, p); err != nil {
		return
	}
	writeHead(sd, running, n)
}

func verifyChain(sd string) (bool, int) {
	f, err := os.Open(logPath(sd))
	if err != nil {
		if _, hN := readHead(sd); hN > 0 {
			return false, 0
		}
		return true, -1
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
