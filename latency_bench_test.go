package main

import (
	"strings"
	"testing"
)

// Benchmarks for the hot-path latency figures docs/DESIGN.md publishes. Those
// numbers were previously unverifiable from the repo: there was a pass/fail
// budget test (TestLatencyUnderBudget) but nothing that reported the actual
// component costs, so a claim like "the scan is sub-2ms" could drift silently.
//
// Run: go test -run '^$' -bench 'Latency|LoadKB|Scan' -benchmem
//
// Interpreting these against DESIGN.md: BenchmarkLoadKB is the "~7µs" claim,
// BenchmarkScanSmallWrite is the "scan is sub-2ms" claim, and
// BenchmarkScan256KB is the "a full 256KB hot-path window is ~40ms" claim. The
// "~2.7ms Go process floor" and "~4ms end-to-end" are process-spawn costs and
// cannot be measured in-process — measure those with an external timer against
// the built binary.

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

// BenchmarkScanSmallWrite is the representative "typical write" case: a short
// handler that carries a recognized taint source, so both the presence pass and
// the taint pass do real work.
func BenchmarkScanSmallWrite(b *testing.B) {
	kb := loadKB()
	b.ReportAllocs()
	for b.Loop() {
		kb.scan("api.py", smallWrite)
	}
}

// BenchmarkScanCleanNoSink exercises the prefilter fast path: a file with no sink
// literal at all should skip both the refinement work and the taint pass.
func BenchmarkScanCleanNoSink(b *testing.B) {
	kb := loadKB()
	content := strings.Repeat("# a comment line with no sink token\n", 40)
	b.ReportAllocs()
	for b.Loop() {
		kb.scan("notes.py", content)
	}
}

// BenchmarkScanDeny is the worst realistic small-write case: a finding is present,
// so refinements run and a Finding is allocated.
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

// BenchmarkScan256KB fills the entire hot-path window (maxScanBytes).
func BenchmarkScan256KB(b *testing.B) {
	kb := loadKB()
	content := strings.Repeat("x = compute(a, b)  # padding line\n", 256*1024/34)
	b.ReportAllocs()
	for b.Loop() {
		kb.scan("big.py", content)
	}
}
