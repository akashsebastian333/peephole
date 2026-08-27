package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

const defaultMode = "guided"

var validMode = map[string]bool{"audit": true, "guided": true, "strict": true, "hardened": true, "off": true}

func projectDir(e Event) string {
	if e.Cwd != "" {
		return e.Cwd
	}
	if d := os.Getenv("CLAUDE_PROJECT_DIR"); d != "" {
		return d
	}
	d, _ := os.Getwd()
	return d
}

func stateDir(e Event) string {
	return filepath.Join(projectDir(e), ".peephole")
}

func modeFile(e Event) string    { return filepath.Join(stateDir(e), "mode") }
func modeSigFile(e Event) string { return filepath.Join(stateDir(e), "mode.sig") }
func modeKeyFile(e Event) string { return filepath.Join(stateDir(e), ".modekey") }

func modeKey(e Event) []byte {
	p := modeKeyFile(e)
	if b, err := os.ReadFile(p); err == nil && len(b) >= 16 {
		return b
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return []byte("peephole-static-fallback-key")
	}
	_ = os.MkdirAll(stateDir(e), 0o700)
	fd, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err == nil {
		fd.Write(key)
		fd.Close()
	}
	return key
}

func modeSig(mode string, key []byte) string {
	sum := sha256.Sum256(append([]byte(mode+"\n"), key...))
	return hex.EncodeToString(sum[:])
}

func getMode(e Event) string {
	b, err := os.ReadFile(modeFile(e))
	if err != nil {
		return defaultMode
	}
	m := strings.TrimSpace(string(b))
	if !validMode[m] {
		return defaultMode
	}
	sig, err := os.ReadFile(modeSigFile(e))
	if err != nil || strings.TrimSpace(string(sig)) != modeSig(m, modeKey(e)) {
		return "strict"
	}
	return m
}

func modeTampered(e Event) bool {
	b, err := os.ReadFile(modeFile(e))
	if err != nil {
		return false
	}
	m := strings.TrimSpace(string(b))
	sig, err := os.ReadFile(modeSigFile(e))
	return err != nil || strings.TrimSpace(string(sig)) != modeSig(m, modeKey(e))
}

const stateSchemaVersion = "2"

func migrateState(e Event) {
	sd := stateDir(e)
	vf := filepath.Join(sd, "state-version")
	b, err := os.ReadFile(vf)
	if err == nil && strings.TrimSpace(string(b)) == stateSchemaVersion {
		return
	}
	if _, serr := os.Stat(sd); serr != nil {
		return
	}
	_ = os.RemoveAll(filepath.Join(sd, "session"))
	_ = os.Remove(filepath.Join(sd, "pkgcache.json"))
	_ = os.Remove(filepath.Join(sd, "lastcommit"))
	_ = os.WriteFile(vf, []byte(stateSchemaVersion+"\n"), 0o600)
}

func setMode(e Event, m string) error {
	if !validMode[m] {
		return os.ErrInvalid
	}
	d := stateDir(e)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(modeFile(e), []byte(m+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(modeSigFile(e), []byte(modeSig(m, modeKey(e))), 0o600); err != nil {
		return err
	}
	vf := filepath.Join(d, "state-version")
	if _, err := os.Stat(vf); err != nil {
		_ = os.WriteFile(vf, []byte(stateSchemaVersion+"\n"), 0o600)
	}
	return nil
}
