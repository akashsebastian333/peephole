package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// Modes. Default is guided: the developer stays in control - every finding is
// surfaced as an ask (the dev decides at the prompt), nothing is hard-blocked
// except self-protection and explicit org mandates. Teams that want blocking
// opt in: strict denies high-confidence findings, hardened denies by default.
// audit is warn-only (never prompts); off disables enforcement.
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

// modeKey returns the per-install signing key, creating it on first use. An
// out-of-band writer that flips the mode file without forging a matching
// signature is detected; a same-user process that reads the key and forges the
// signature is a host-level residual outside this tool's scope.
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

// getMode returns the enforcement mode. It fail-closes to the default (strict)
// if the mode file was changed out-of-band, i.e. its signature is missing or
// invalid, so a raw write to .peephole/mode (however the shell spelled the
// path) cannot silently disable enforcement.
func getMode(e Event) string {
	b, err := os.ReadFile(modeFile(e))
	if err != nil {
		return defaultMode // no mode file -> default
	}
	m := strings.TrimSpace(string(b))
	if !validMode[m] {
		return defaultMode
	}
	sig, err := os.ReadFile(modeSigFile(e))
	if err != nil || strings.TrimSpace(string(sig)) != modeSig(m, modeKey(e)) {
		return "strict" // out-of-band change -> fail closed to the enforcing mode
	}
	return m
}

// modeTampered reports whether the mode file exists but its signature does not
// verify (an out-of-band write), surfaced as an alarm at SessionStart.
func modeTampered(e Event) bool {
	b, err := os.ReadFile(modeFile(e))
	if err != nil {
		return false
	}
	m := strings.TrimSpace(string(b))
	sig, err := os.ReadFile(modeSigFile(e))
	return err != nil || strings.TrimSpace(string(sig)) != modeSig(m, modeKey(e))
}

// stateSchemaVersion versions the .peephole state layout. On mismatch the
// volatile state (session files, package cache, commit dedupe) is reset; the
// audit log and mode survive (migrate-or-reset policy, blueprint §8).
const stateSchemaVersion = "2"

// migrateState enforces the schema-version contract at SessionStart.
func migrateState(e Event) {
	sd := stateDir(e)
	vf := filepath.Join(sd, "state-version")
	b, err := os.ReadFile(vf)
	if err == nil && strings.TrimSpace(string(b)) == stateSchemaVersion {
		return
	}
	if _, serr := os.Stat(sd); serr != nil {
		return // no state yet; nothing to migrate
	}
	_ = os.RemoveAll(filepath.Join(sd, "session"))
	_ = os.Remove(filepath.Join(sd, "pkgcache.json"))
	_ = os.Remove(filepath.Join(sd, "lastcommit"))
	_ = os.WriteFile(vf, []byte(stateSchemaVersion+"\n"), 0o600)
}

// setMode writes the mode and its signature so getMode will honor it. This is
// the only legitimate way to change the mode.
func setMode(e Event, m string) error {
	if !validMode[m] {
		return os.ErrInvalid
	}
	d := stateDir(e)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	// 0600 stops other local users from flipping the mode; the same-user agent is
	// outside this tool's scope.
	if err := os.WriteFile(modeFile(e), []byte(m+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(modeSigFile(e), []byte(modeSig(m, modeKey(e))), 0o600); err != nil {
		return err
	}
	// stamp the state schema version on first real state write
	vf := filepath.Join(d, "state-version")
	if _, err := os.Stat(vf); err != nil {
		_ = os.WriteFile(vf, []byte(stateSchemaVersion+"\n"), 0o600)
	}
	return nil
}
