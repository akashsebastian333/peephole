package main

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// Manifest-edit slopsquat gating (N5). Installs
// also arrive by editing package.json / requirements.txt / pyproject.toml, not
// only via `pip install`. On a Write/Edit to a manifest we extract dependency
// names and check them. To keep the write path fast (manifests can list many
// deps) this uses the offline allowlist + cache only, no network burst; the
// live registry lookup stays on the narrow install-command path.

var (
	reReqLine   = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]+)`)
	rePyproj    = regexp.MustCompile(`["']([A-Za-z0-9][A-Za-z0-9._-]+)\s*(?:[<>=!~;\[].*)?["']`)
	rePoetryKey = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]+)\s*=\s*["{]`)
	manifestPy  = map[string]bool{"requirements.txt": true, "pyproject.toml": true, "Pipfile": true}
	manifestJs  = map[string]bool{"package.json": true}
	// TOML metadata keys that are not dependencies (avoid false slopsquat flags).
	tomlMetaKeys = map[string]bool{
		"name": true, "version": true, "description": true, "authors": true,
		"license": true, "readme": true, "homepage": true, "repository": true,
		"keywords": true, "documentation": true, "packages": true, "include": true,
		"python": true, "requires-python": true, "classifiers": true,
	}
)

func isManifest(path string) string {
	base := filepath.Base(path)
	if manifestPy[base] {
		return "pip"
	}
	if manifestJs[base] {
		return "npm"
	}
	return ""
}

// extractManifestDeps pulls dependency names out of a manifest's content.
func extractManifestDeps(path, content string) []Install {
	base := filepath.Base(path)
	var out []Install
	switch {
	case base == "package.json":
		var pkg struct {
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		}
		if json.Unmarshal([]byte(content), &pkg) == nil {
			for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
				for name := range m {
					out = append(out, Install{Manager: "npm", Pkg: name})
				}
			}
		}
	case base == "requirements.txt" || base == "Pipfile":
		for _, m := range reReqLine.FindAllStringSubmatch(content, -1) {
			out = append(out, Install{Manager: "pip", Pkg: m[1]})
		}
	case base == "pyproject.toml":
		// PEP 621 quoted deps ("pkg>=1") and Poetry bare keys (pkg = "^1") under
		// [tool.poetry(.group.*).dependencies], skipping the reserved python key.
		for _, m := range rePyproj.FindAllStringSubmatch(content, -1) {
			if n := m[1]; n != "" && n != "python" && !strings.ContainsAny(n, " ") {
				out = append(out, Install{Manager: "pip", Pkg: n})
			}
		}
		if strings.Contains(content, "[tool.poetry") {
			for _, m := range rePoetryKey.FindAllStringSubmatch(content, -1) {
				if n := m[1]; !tomlMetaKeys[n] {
					out = append(out, Install{Manager: "pip", Pkg: n})
				}
			}
		}
	}
	return dedupInstalls(out)
}

func dedupInstalls(in []Install) []Install {
	seen := map[string]bool{}
	var out []Install
	for _, i := range in {
		k := i.Manager + ":" + i.Pkg
		if !seen[k] {
			seen[k] = true
			out = append(out, i)
		}
	}
	return out
}

// gateManifestDeps applies N5 to a manifest edit. Offline signals first
// (allowlist, homoglyph, known-bad, ecosystem mismatch, typosquat, cache);
// anything unverifiable offline gets a bounded live registry check so an
// unknown package is never a silent allow (mode matrix: strict asks, hardened
// denies hallucinated). Findings are appended to cands.
func gateManifestDeps(e Event, mode string, ti ToolInput, content string, cands *[]cand) {
	sd := stateDir(e)
	deps := extractManifestDeps(ti.targetPath(), content)
	if len(deps) == 0 {
		return
	}
	var hall, typo, fresh, unver []string
	var live []Install
	for _, in := range deps {
		switch checkPackageOffline(sd, in) {
		case pkgHallucinated:
			hall = append(hall, in.Pkg)
		case pkgTyposquat:
			typo = append(typo, in.Pkg)
		case pkgFresh: // cached fresh verdict: still inside the freshness window
			fresh = append(fresh, in.Pkg)
		case pkgOK:
		default:
			live = append(live, in)
		}
	}
	if len(live) > 0 {
		verdicts := checkPackagesLive(sd, live)
		for i, in := range live {
			switch verdicts[i] {
			case pkgHallucinated:
				hall = append(hall, in.Pkg)
			case pkgFresh:
				fresh = append(fresh, in.Pkg)
			case pkgOK:
			default:
				unver = append(unver, in.Pkg)
			}
		}
	}
	if len(hall) > 0 {
		*cands = append(*cands, cand{unreachableDecision(mode), "CWE-1104", "slopsquat-manifest", e.ToolName, "",
			provenance + " this manifest adds package(s) not found in the registry - likely hallucinated: " + strings.Join(hall, ", "), false})
	}
	// audit keeps measuring (enforce downgrades to warn+log); strict/hardened ask.
	if len(typo) > 0 {
		*cands = append(*cands, cand{"ask", "CWE-1104", "typosquat-manifest", e.ToolName, "",
			provenance + " this manifest adds package(s) one or two edits from a popular package - likely typosquats; double-check the exact names: " + strings.Join(typo, ", "), false})
	}
	if len(fresh) > 0 {
		*cands = append(*cands, cand{"ask", "CWE-1104", "slopsquat-manifest-fresh", e.ToolName, "",
			provenance + " this manifest adds package(s) published very recently - the pre-registration pattern of a slopsquat; confirm they are the established, intended packages: " + strings.Join(fresh, ", "), false})
	}
	if len(unver) > 0 {
		*cands = append(*cands, cand{"ask", "CWE-1104", "slopsquat-manifest-unverified", e.ToolName, "",
			provenance + " could not verify these dependencies against the registry; confirm they exist and are intended before adding: " + strings.Join(unver, ", "), false})
	}
}
