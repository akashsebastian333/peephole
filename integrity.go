package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// Self-integrity. The binary embeds its own rules, so one
// hash of the executable covers both code and KB. At SessionStart we hash
// ourselves and compare to bin/manifest.sha256 (shipped alongside, generated at
// build). Drift -> loud alarm; enforcement continues degraded rather than
// bricking (fail-closed on detection, fail-degraded on availability).
//
// This is integrity, not authenticity: a same-user attacker who rewrites both
// the binary and the manifest defeats it (host-level tamper, out of scope). It
// catches accidental corruption, partial poisoning, and casual tampering.

func pluginRoot() string {
	if r := os.Getenv("CLAUDE_PLUGIN_ROOT"); r != "" {
		return r
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(filepath.Dir(exe)) // <root>/bin/<exe> -> <root>
	}
	return "."
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func manifestPath() string {
	return filepath.Join(pluginRoot(), "bin", "manifest.sha256")
}

// verifySelf returns (ok, detail). ok=false with a human-readable reason on any
// drift or a missing manifest.
func verifySelf() (bool, string) {
	exe, err := os.Executable()
	if err != nil {
		return true, "" // cannot locate self; do not alarm
	}
	self, err := hashFile(exe)
	if err != nil {
		return true, ""
	}
	b, err := os.ReadFile(manifestPath())
	if err != nil {
		return false, "integrity manifest missing (" + filepath.Base(exe) + ")"
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return false, "integrity manifest unreadable"
	}
	want, ok := m[filepath.Base(exe)]
	if !ok {
		return false, "no manifest entry for " + filepath.Base(exe)
	}
	if want != self {
		return false, "binary hash drift for " + filepath.Base(exe) + " - possible tampering"
	}
	return true, ""
}

// protectedFiles are the non-binary parts of peephole's own runtime whose
// tampering must be detected: the hook wiring, the launcher, the plugin
// manifest, and the skills (loose instruction files that steer the agent - a
// rewritten SKILL.md is as dangerous as a rewritten rule).
var hookFiles = []string{
	"hooks/hooks.json", "hooks/peephole.sh", ".claude-plugin/plugin.json",
	"skills/peephole/SKILL.md", "skills/sec-audit/SKILL.md",
	"skills/sec-debt/SKILL.md", "skills/sec-review/SKILL.md",
}

// genManifest hashes every file in bin/ (keyed by basename) plus the hook files
// (keyed by relpath) into bin/manifest.sha256. Build step, run after compiling.
func genManifest() error {
	root := pluginRoot()
	m := map[string]string{}
	entries, err := os.ReadDir(filepath.Join(root, "bin"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "manifest.sha256" || e.Name() == ".peephole-exe" {
			continue //.peephole-exe is a runtime launcher cache, not shipped
		}
		h, err := hashFile(filepath.Join(root, "bin", e.Name()))
		if err != nil {
			return err
		}
		m[e.Name()] = h
	}
	for _, rel := range hookFiles {
		if h, err := hashFile(filepath.Join(root, rel)); err == nil {
			m[rel] = h
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(manifestPath(), out, 0o644)
}

// verifyHooks checks the hook wiring/launcher against the manifest. Returns
// (ok, drifted-files).: tampering with hooks.json or the launcher is
// detected at SessionStart/ConfigChange.
func verifyHooks() (bool, []string) {
	b, err := os.ReadFile(manifestPath())
	if err != nil {
		return true, nil // no manifest -> verifySelf already alarms
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return true, nil
	}
	var drift []string
	for _, rel := range hookFiles {
		want, ok := m[rel]
		if !ok {
			continue
		}
		got, err := hashFile(filepath.Join(pluginRoot(), rel))
		if err != nil || got != want {
			drift = append(drift, rel)
		}
	}
	return len(drift) == 0, drift
}
