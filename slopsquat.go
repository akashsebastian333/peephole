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

var popularPy = set(
	"requests", "urllib3", "boto3", "botocore", "setuptools", "certifi", "idna",
	"charset-normalizer", "numpy", "pandas", "python-dateutil", "pyyaml", "six",
	"packaging", "typing-extensions", "flask", "django", "fastapi", "pydantic",
	"sqlalchemy", "pytest", "click", "jinja2", "werkzeug", "scipy", "pillow",
	"cryptography", "aiohttp", "httpx", "bcrypt", "argon2-cffi", "psycopg2",
	"psycopg2-binary", "psycopg", "redis", "celery", "gunicorn", "uvicorn", "starlette",
	"scikit-learn", "matplotlib", "torch", "transformers", "openai", "anthropic",
)

var popularJs = set(
	"react", "react-dom", "preact", "lodash", "axios", "express", "chalk", "commander",
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
	pkgOK pkgVerdict = iota
	pkgHallucinated
	pkgUnknown
	pkgTyposquat
	pkgFresh
)

var knownHallucinated = set(
	"requests-http-client", "python-sqlite", "async-requests", "pyfiglet-cli",
	"react-router-domm", "discord-api-py", "openai-python-sdk", "huggingface-cli",
	"python3-dateutil", "jeIlyfish", "colourama", "djanga", "beautifulsup4",
)

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

func typosquatOf(name string, popular map[string]bool) string {
	limit := 1
	if len(name) >= 7 {
		limit = 2
	}
	best, bestD := "", limit+1
	for p := range popular {
		if p == name {
			return ""
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
	tmp := cachePath(sd) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, cachePath(sd))
	}
}

func checkPackageOffline(sd string, in Install) pkgVerdict {
	name := strings.ToLower(in.Pkg)

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
		if reGoModPath.MatchString(name) {
			return pkgOK
		}
		return pkgUnknown
	}
	if (pip && popularJs[name]) || (npm && popularPy[name]) {
		return pkgHallucinated
	}
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

const freshWindow = 45 * 24 * time.Hour

var reCreatedDate = regexp.MustCompile(`"(?:created|upload_time_iso_8601)"\s*:\s*"(\d{4}-\d{2}-\d{2})`)

var reGoModPath = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}/[\w./~-]+$`)

func freshlyCreated(body string) bool {
	matches := reCreatedDate.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return false
	}
	min := matches[0][1]
	for _, m := range matches[1:] {
		if m[1] < min {
			min = m[1]
		}
	}
	t, err := time.Parse("2006-01-02", min)
	if err != nil {
		return false
	}
	return time.Since(t) < freshWindow
}
