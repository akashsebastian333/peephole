package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func pluginRoot() string {
	if r := os.Getenv("CLAUDE_PLUGIN_ROOT"); r != "" {
		return r
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(filepath.Dir(exe))
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

func manifestCandidates() []string {
	out := []string{manifestPath()}
	if exe, err := os.Executable(); err == nil {
		out = append(out, filepath.Join(filepath.Dir(exe), "manifest.sha256"))
	}
	return out
}

func loadManifest() (map[string]string, string) {
	var last string
	for _, p := range manifestCandidates() {
		b, err := os.ReadFile(p)
		if err != nil {
			last = p
			continue
		}
		var m map[string]string
		if json.Unmarshal(b, &m) != nil || len(m) == 0 {
			return nil, "integrity manifest unreadable"
		}
		return m, ""
	}
	base := "peephole"
	if exe, err := os.Executable(); err == nil {
		base = filepath.Base(exe)
	}
	if last == "" {
		last = manifestPath()
	}
	return nil, "integrity manifest missing (" + base + " at " + last + ")"
}

func verifySelf() (bool, string) {
	exe, err := os.Executable()
	if err != nil {
		return true, ""
	}
	self, err := hashFile(exe)
	if err != nil {
		return true, ""
	}
	m, fail := loadManifest()
	if m == nil {
		return false, fail
	}
	base := filepath.Base(exe)
	if want, ok := m[base]; ok {
		if want != self {
			return false, "binary hash drift for " + base + " - possible tampering"
		}
		return true, ""
	}
	for name, want := range m {
		if strings.HasPrefix(name, "peephole-") && want == self {
			return true, ""
		}
	}
	return false, "no manifest entry for " + base
}

var hookFiles = []string{
	"hooks/hooks.json", "hooks/peephole.sh", ".claude-plugin/plugin.json",
	"skills/peephole/SKILL.md", "skills/sec-audit/SKILL.md",
	"skills/sec-debt/SKILL.md", "skills/sec-review/SKILL.md",
}

func genManifest() error {
	root := pluginRoot()
	m := map[string]string{}
	entries, err := os.ReadDir(filepath.Join(root, "bin"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "manifest.sha256" || e.Name() == ".peephole-exe" {
			continue
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

func verifyHooks() (bool, []string) {
	b, err := os.ReadFile(manifestPath())
	if err != nil {
		return true, nil
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
