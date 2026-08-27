package main

import (
	"strings"
	"testing"
)

const smallWrite = `from flask import Flask, request, jsonify
from db import fetch_one

app = Flask(__name__)

@app.route("/user", methods=["GET"])
def get_user():
    uid = request.args.get("id")
    row = fetch_one("SELECT id, email FROM users WHERE id = ? AND owner = ?", (uid, uid))
    return jsonify(dict(row))
`

func BenchmarkLoadKB(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		kb := loadKB()
		if len(kb.Rules) == 0 {
			b.Fatal("no rules")
		}
	}
}

func BenchmarkScanSmallWrite(b *testing.B) {
	kb := loadKB()
	b.ReportAllocs()
	for b.Loop() {
		kb.scan("api.py", smallWrite)
	}
}

func BenchmarkScanCleanNoSink(b *testing.B) {
	kb := loadKB()
	content := strings.Repeat("# a comment line with no sink token\n", 40)
	b.ReportAllocs()
	for b.Loop() {
		kb.scan("notes.py", content)
	}
}

func BenchmarkScanDeny(b *testing.B) {
	kb := loadKB()
	content := "cur.execute(f\"SELECT * FROM users WHERE id={uid}\")\n"
	b.ReportAllocs()
	for b.Loop() {
		if len(kb.scan("db.py", content)) == 0 {
			b.Fatal("expected a finding")
		}
	}
}

func BenchmarkScan256KB(b *testing.B) {
	kb := loadKB()
	content := strings.Repeat("x = compute(a, b)  # padding line\n", 256*1024/34)
	b.ReportAllocs()
	for b.Loop() {
		kb.scan("big.py", content)
	}
}

func benchEvent(t testing.TB) (Event, ToolInput, string) {
	dir := t.TempDir()
	e := Event{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		SessionID:     "bench-session",
		Cwd:           dir,
	}
	ti := ToolInput{FilePath: dir + "/x.py", Content: "def f():\n    return 1\n"}
	return e, ti, ti.Content
}

func BenchmarkHotFileDigest(b *testing.B) {
	_, _, content := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		fileDigest(content)
	}
}

func BenchmarkHotHunkSeen(b *testing.B) {
	e, ti, content := benchEvent(b)
	sd := stateDir(e)
	b.ReportAllocs()
	for b.Loop() {
		hunkSeen(sd, e.SessionID, hunkKey(ti.targetPath(), content))
	}
}

func BenchmarkHotGetMode(b *testing.B) {
	e, _, _ := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		getMode(e)
	}
}

func BenchmarkHotLoadPolicy(b *testing.B) {
	e, _, _ := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		loadPolicy(projectDir(e))
	}
}

func BenchmarkHotAppendLog(b *testing.B) {
	e, _, _ := benchEvent(b)
	sd := stateDir(e)
	b.ReportAllocs()
	for b.Loop() {
		appendLog(sd, logEntry{Decision: "allow", Tool: "Write", FileHash: "deadbeef"})
	}
}

func BenchmarkHotBumpDecisionCount(b *testing.B) {
	e, _, _ := benchEvent(b)
	sd := stateDir(e)
	b.ReportAllocs()
	for b.Loop() {
		bumpDecisionCount(sd, e.SessionID)
	}
}

func BenchmarkHotSecurityRelevant(b *testing.B) {
	kb := loadKB()
	_, ti, content := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		kb.securityRelevant(ti.targetPath(), content)
	}
}

func BenchmarkHotSemReviewKeys(b *testing.B) {
	_, _, content := benchEvent(b)
	b.ReportAllocs()
	for b.Loop() {
		semReviewKeys(content)
	}
}

func BenchmarkHotSecureRewrite(b *testing.B) {
	content := "import yaml\n\n\ndef load(p):\n    return yaml.load(open(p))\n"
	b.ReportAllocs()
	for b.Loop() {
		secureRewrite(content)
	}
}
