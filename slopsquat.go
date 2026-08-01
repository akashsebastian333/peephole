package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// N5 Slopsquat Gate. Every dependency-introducing install is checked against
// registry ground truth: does the package exist? Hallucinated names (registry
// 404) are the slopsquatting attack surface, an attacker pre-registers a name
// the model invents, so the first `pip install <hallucination>` runs their code.
//
// Latency/robustness: a bundled offline allowlist of popular packages short-
// circuits the common case with zero network. Unknown names hit the registry
// with an 800ms cap and a 7-day disk cache. Registry unreachable is never a
// silent allow, it maps to ask (strict) / deny (hardened) per the mode matrix.

// Popular packages, the common path never touches the network. Recompile to
// extend; the KB recompiles on updates anyway.
var popularPy = set(
	"requests", "urllib3", "boto3", "botocore", "setuptools", "certifi", "idna",
	"charset-normalizer", "numpy", "pandas", "python-dateutil", "pyyaml", "six",
	"packaging", "typing-extensions", "flask", "django", "fastapi", "pydantic",
	"sqlalchemy", "pytest", "click", "jinja2", "werkzeug", "scipy", "pillow",
	"cryptography", "aiohttp", "httpx", "bcrypt", "argon2-cffi", "psycopg2",
	"psycopg2-binary", "redis", "celery", "gunicorn", "uvicorn", "starlette",
	"scikit-learn", "matplotlib", "torch", "transformers", "openai", "anthropic",
)

var popularJs = set(
	"react", "react-dom", "lodash", "axios", "express", "chalk", "commander",
	"debug", "next", "vue", "typescript", "webpack", "eslint", "prettier",
	"jest", "vite", "tailwindcss", "zod", "dotenv", "cors", "body-parser",
	"jsonwebtoken", "bcrypt", "bcryptjs", "pg", "mongoose", "sequelize",
	"redis", "socket.io", "moment", "dayjs", "uuid", "nanoid", "classnames",
	"react-router-dom", "@types/node", "@types/react", "rxjs", "graphql",
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

type pkgVerdict int

const (
	pkgOK           pkgVerdict = iota // exists / known-popular
	pkgHallucinated                   // registry 404 / known-bad / homoglyph / ecosystem-mismatch
	pkgUnknown                        // registry unreachable / undetermined
	pkgTyposquat                      // near-neighbor of a popular name; ask, never deny
	pkgFresh                          // exists but created very recently; the slopsquat pre-registration vector
)

// knownHallucinated: names documented as LLM-hallucinated or malicious squats.
// This is a starter set; production would ship the versioned Spracklen
// ~205k-name corpus with its staleness date recorded. A hit is a strong signal
// (the name is both invented and likely already attacker-registered).
var knownHallucinated = set(
	"requests-http-client", "python-sqlite", "async-requests", "pyfiglet-cli",
	"react-router-domm", "discord-api-py", "openai-python-sdk", "huggingface-cli",
	"python3-dateutil", "jeIlyfish", "colourama", "djanga", "beautifulsup4",
)

// damerauLevenshtein returns the optimal-string-alignment distance (includes
// adjacent transposition) between a and b, capped early at >max for speed.
func damerauLevenshtein(a, b string, max int) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	if la-lb > max || lb-la > max {
		return max + 1
	}
	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			v := min(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if t := prev2[j-2] + 1; t < v {
					v = t
				}
			}
			cur[j] = v
			if v < rowMin {
				rowMin = v
			}
		}
		if rowMin > max {
			return max + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[lb]
}

// typosquatOf returns the nearest popular name within edit distance <=1 (<=2 for
// names >=7 chars), or "" if none. The candidate must not itself be popular.
func typosquatOf(name string, popular map[string]bool) string {
	limit := 1
	if len(name) >= 7 {
		limit = 2
	}
	best, bestD := "", limit+1
	for p := range popular {
		if p == name {
			return "" // exact popular -> fine
		}
		if d := damerauLevenshtein(name, p, limit); d <= limit && d < bestD && d > 0 {
			best, bestD = p, d
		}
	}
	return best
}

type cacheRec struct {
	Verdict int   `json:"v"`
	TS      int64 `json:"ts"`
}

func cachePath(sd string) string { return filepath.Join(sd, "pkgcache.json") }

func loadCache(sd string) map[string]cacheRec {
	m := map[string]cacheRec{}
	if b, err := os.ReadFile(cachePath(sd)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func saveCache(sd string, m map[string]cacheRec) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	// atomic write: a concurrent warmcache/gate reader never sees a torn file
	tmp := cachePath(sd) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, cachePath(sd))
	}
}

// checkPackageOffline applies every network-free signal: homoglyph, known-bad,
// the popular allowlist, ecosystem mismatch, typosquat distance, and the 7-day
// disk cache. pkgUnknown means "needs a live registry check".
func checkPackageOffline(sd string, in Install) pkgVerdict {
	name := strings.ToLower(in.Pkg)

	// Offline high-confidence squat signals, no network, checked first.
	// A non-ASCII name is almost certainly a homoglyph squat (real registry
	// names are ASCII).
	for _, r := range name {
		if r > 127 {
			return pkgHallucinated
		}
	}
	if knownHallucinated[name] {
		return pkgHallucinated
	}
	pip := in.Manager == "pip" || in.Manager == "pip3" || in.Manager == "uv" || in.Manager == "poetry" || in.Manager == "pipenv"
	npm := in.Manager == "npm" || in.Manager == "pnpm" || in.Manager == "yarn" || in.Manager == "bun"

	switch {
	case pip && popularPy[name]:
		return pkgOK
	case npm && (popularJs[name] || strings.HasPrefix(name, "@types/")):
		return pkgOK
	case in.Manager == "go":
		return pkgUnknown // module proxy check out of scope for v1; never a silent allow
	}
	// Ecosystem mismatch: a pip install of a name that is a well-known npm
	// package (or vice-versa) is a dependency-confusion smell.
	if (pip && popularJs[name]) || (npm && popularPy[name]) {
		return pkgHallucinated
	}
	// Typosquat: a near-neighbor of a popular name (that isn't itself popular) is
	// the strongest offline squat signal, a REGISTERED typosquat passes the
	// existence check, so distance is the only tell. Asks, never denies (legit
	// near-neighbor names exist).
	if pip && typosquatOf(name, popularPy) != "" {
		return pkgTyposquat
	}
	if npm && typosquatOf(name, popularJs) != "" {
		return pkgTyposquat
	}

	key := in.Manager + ":" + name
	cache := loadCache(sd)
	if rec, ok := cache[key]; ok && time.Now().Unix()-rec.TS < 7*24*3600 {
		return pkgVerdict(rec.Verdict)
	}
	return pkgUnknown
}

// checkPackage returns a verdict for one install. Network only when not popular
// and not freshly cached.
func checkPackage(sd string, in Install) pkgVerdict {
	if v := checkPackageOffline(sd, in); v != pkgUnknown {
		return v
	}
	v := registryExists(in.Manager, strings.ToLower(in.Pkg))
	cache := loadCache(sd)
	cache[in.Manager+":"+strings.ToLower(in.Pkg)] = cacheRec{Verdict: int(v), TS: time.Now().Unix()}
	saveCache(sd, cache)
	return v
}

// checkPackagesLive resolves unverifiable packages against the registry in
// parallel (manifest path, where one edit can add several deps). Bounded: at
// most 8 live lookups, 4 concurrent, each capped at 1s, so the hook stays well
// inside its 2s work budget. Results are cached like any other check.
func checkPackagesLive(sd string, deps []Install) []pkgVerdict {
	if len(deps) > 8 {
		deps = deps[:8]
	}
	out := make([]pkgVerdict, len(deps))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, in := range deps {
		wg.Add(1)
		go func(i int, in Install) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = registryExistsTimeout(in.Manager, strings.ToLower(in.Pkg), 1)
		}(i, in)
	}
	wg.Wait()
	cache := loadCache(sd)
	for i, in := range deps {
		cache[in.Manager+":"+strings.ToLower(in.Pkg)] = cacheRec{Verdict: int(out[i]), TS: time.Now().Unix()}
	}
	saveCache(sd, cache)
	return out
}

// registryExists checks the package registry via a curl subprocess rather than
// net/http. This keeps the heavy net/http + crypto/tls packages out of the
// binary, so every hook invocation skips their startup init, the network check
// only runs on the rare install path anyway. If curl is unavailable the verdict
// is pkgUnknown (the caller maps that to ask/deny, never a silent allow).
func registryExists(manager, name string) pkgVerdict {
	return registryExistsTimeout(manager, name, 2)
}

func registryExistsTimeout(manager, name string, secs int) pkgVerdict {
	var url string
	switch manager {
	case "pip", "pip3", "uv", "poetry", "pipenv":
		url = "https://pypi.org/pypi/" + name + "/json"
	case "npm", "pnpm", "yarn", "bun":
		url = "https://registry.npmjs.org/" + name
	default:
		return pkgUnknown
	}
	// Fetch the body (not just the status) so we can read the package's age: a
	// REGISTERED-but-brand-new package is the slopsquat pre-registration vector,
	// where an existence-only check is the weaker half (N5: freshness is
	// primary, existence secondary). Only non-popular names reach here (the
	// allowlist short-circuits popular ones), so the body stays small.
	out, err := exec.Command("curl", "-s", "-w", "\n%{http_code}", "--max-time", strconv.Itoa(secs), url).Output()
	if err != nil {
		return pkgUnknown
	}
	body := string(out)
	code := ""
	if nl := strings.LastIndexByte(body, '\n'); nl >= 0 {
		code = strings.TrimSpace(body[nl+1:])
		body = body[:nl]
	}
	switch {
	case code == "404":
		return pkgHallucinated
	case strings.HasPrefix(code, "2"):
		if freshlyCreated(body) {
			return pkgFresh
		}
		return pkgOK
	default:
		return pkgUnknown
	}
}

// freshWindow: a package first published within this window is treated as fresh
// and surfaced for confirmation, long enough to catch pre-registered squats,
// short enough that established packages never trip it.
const freshWindow = 45 * 24 * time.Hour

var reISODate = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)

// freshlyCreated reports whether the earliest date in a PyPI/npm registry
// response (PyPI upload_time_iso_8601 / npm time.created) is within freshWindow.
// ISO YYYY-MM-DD strings compare lexicographically in date order, so the min
// string is the earliest publication. No date found -> not flagged (don't guess).
func freshlyCreated(body string) bool {
	dates := reISODate.FindAllString(body, -1)
	if len(dates) == 0 {
		return false
	}
	min := dates[0]
	for _, d := range dates[1:] {
		if d < min {
			min = d
		}
	}
	t, err := time.Parse("2006-01-02", min)
	if err != nil {
		return false
	}
	return time.Since(t) < freshWindow
}
