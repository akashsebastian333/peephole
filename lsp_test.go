package main

import "testing"

func TestLSPDiagnostics(t *testing.T) {
	kb := loadKB()
	d := lspDiagnostics(kb, "file:///a.py", `cur.execute(f"SELECT * FROM t WHERE id={x}")`)
	if len(d) == 0 {
		t.Fatal("expected a diagnostic for SQLi")
	}
	m := d[0].(map[string]any)
	if m["code"] != "CWE-89" || m["severity"] != 1 {
		t.Errorf("expected CWE-89 severity 1 (error), got code=%v sev=%v", m["code"], m["severity"])
	}
	if len(lspDiagnostics(kb, "file:///a.py", "x = 1")) != 0 {
		t.Error("clean code should have no diagnostics")
	}
}
