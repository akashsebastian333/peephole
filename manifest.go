package main

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reReqLine     = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]+)`)
	reJSONDepPair = regexp.MustCompile(`"(@?[A-Za-z0-9][\w.@/-]*)"\s*:\s*"([^"]*)"`)
	reNpmVersion  = regexp.MustCompile(`^(?:[\^~*=<>]|\d|latest$|next$|git|https?:|file:|npm:|link:|workspace:)`)
	npmNonDepKeys = map[string]bool{"name": true, "version": true, "node": true, "npm": true,
		"yarn": true, "pnpm": true, "type": true, "main": true, "module": true, "engines": true}
	rePyproj     = regexp.MustCompile(`["']\s*([A-Za-z0-9][A-Za-z0-9._-]+)\s*(?:[<>=!~;\[].*)?["']`)
	rePoetryKey  = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]+)\s*=\s*["{]`)
	reDepArray   = regexp.MustCompile(`(?i)[\w.-]*dependencies[\w.-]*\s*=\s*\[([\s\S]*?)\]`)
	reDepSection = regexp.MustCompile(`(?i)^\[[^\]]*dependencies[^\]]*\]`)
	manifestPy   = map[string]bool{"requirements.txt": true, "pyproject.toml": true, "Pipfile": true}
	manifestJs   = map[string]bool{"package.json": true}
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
		if len(out) == 0 {
			for _, m := range reJSONDepPair.FindAllStringSubmatch(content, -1) {
				name, ver := m[1], m[2]
				if npmNonDepKeys[name] || strings.ContainsAny(ver, " ") || !reNpmVersion.MatchString(ver) {
					continue
				}
				out = append(out, Install{Manager: "npm", Pkg: name})
			}
		}
	case base == "requirements.txt" || base == "Pipfile":
		for _, m := range reReqLine.FindAllStringSubmatch(content, -1) {
			out = append(out, Install{Manager: "pip", Pkg: m[1]})
		}
	case base == "pyproject.toml":
		dep := pyprojDepText(content)
		for _, m := range rePyproj.FindAllStringSubmatch(dep, -1) {
			if n := m[1]; n != "" && n != "python" && !tomlMetaKeys[n] && !strings.ContainsAny(n, " ") {
				out = append(out, Install{Manager: "pip", Pkg: n})
			}
		}
		for _, m := range rePoetryKey.FindAllStringSubmatch(dep, -1) {
			if n := m[1]; !tomlMetaKeys[n] {
				out = append(out, Install{Manager: "pip", Pkg: n})
			}
		}
	}
	return dedupInstalls(out)
}

func pyprojDepText(content string) string {
	var b strings.Builder
	for _, m := range reDepArray.FindAllStringSubmatch(content, -1) {
		b.WriteString(m[1])
		b.WriteByte('\n')
	}
	inDep := false
	for _, ln := range strings.Split(content, "\n") {
		if t := strings.TrimSpace(ln); strings.HasPrefix(t, "[") {
			inDep = reDepSection.MatchString(t)
		} else if inDep {
			b.WriteString(ln)
			b.WriteByte('\n')
		}
	}
	return b.String()
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
		case pkgFresh:
			fresh = append(fresh, in.Pkg)
		case pkgOK:
		default:
			live = append(live, in)
		}
	}
	if len(live) > 0 {
		if len(live) > 8 {
			for _, in := range live[8:] {
				unver = append(unver, in.Pkg)
			}
			live = live[:8]
		}
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
