package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reIdent    = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{4,}`)
	reN7Sink   = regexp.MustCompile(`(?i)\b(?:exec|eval|system|popen|subprocess|query|execute|innerHTML|dangerouslySetInnerHTML|redirect|render_template_string|require|import_module)\b`)
	commonWord = set("string", "return", "value", "result", "config", "request", "response",
		"function", "params", "object", "length", "error", "output", "content", "async", "await")
)

func taintEnabled(sd string) bool {
	_, err := os.Stat(filepath.Join(sd, "taint-echo"))
	return err == nil
}

func taintDenyEnabled(sd string) bool {
	_, err := os.Stat(filepath.Join(sd, "taint-deny"))
	return err == nil
}

func recordIngestion(sd, sid, text string) {
	if text == "" {
		return
	}
	seen := loadTaint(sd, sid)
	for _, id := range reIdent.FindAllString(text, 400) {
		l := strings.ToLower(id)
		if !commonWord[l] {
			seen[l] = true
		}
		if len(seen) > 2000 {
			break
		}
	}
	var b strings.Builder
	for id := range seen {
		b.WriteString(id)
		b.WriteByte('\n')
	}
	_ = os.WriteFile(sidFile(sd, sid, "taintset"), []byte(b.String()), 0o600)
}

func loadTaint(sd, sid string) map[string]bool {
	m := map[string]bool{}
	if b, err := os.ReadFile(sidFile(sd, sid, "taintset")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if l != "" {
				m[l] = true
			}
		}
	}
	return m
}

func taintEcho(sd, sid, content string) (string, bool) {
	if !reN7Sink.MatchString(content) {
		return "", false
	}
	taint := loadTaint(sd, sid)
	if len(taint) == 0 {
		return "", false
	}
	overlap := 0
	for _, id := range reIdent.FindAllString(content, 400) {
		if taint[strings.ToLower(id)] {
			overlap++
			if overlap >= 2 {
				return provenance + " N7: this hunk appears derived from external content ingested this session (fetched/README/MCP) and reaches a dangerous sink. Confirm the untrusted data is validated/encoded before it flows into exec/query/HTML/redirect.", true
			}
		}
	}
	return "", false
}
