package main

import (
	"strings"
	"testing"
)

func TestMCPScanText(t *testing.T) {
	kb := loadKB()
	vuln := mcpScanText(kb, "a.py", `cur.execute(f"SELECT * FROM t WHERE id={x}")`)
	if !strings.Contains(vuln, "HIGH-confidence") || !strings.Contains(vuln, "CWE-89") {
		t.Errorf("expected HIGH CWE-89 finding, got: %q", vuln)
	}
	clean := mcpScanText(kb, "a.py", `cur.execute("SELECT 1")`)
	if !strings.Contains(clean, "no security findings") {
		t.Errorf("expected clean verdict, got: %q", clean)
	}
}
