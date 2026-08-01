package main

import "testing"

// False-positive corpus: everyday, correct code that a developer writes all the
// time. NONE of it may be flagged. This is the productivity guardrail, a tool
// that blocks legitimate work gets uninstalled.
func TestNoFalsePositives(t *testing.T) {
	kb := loadKB()
	legit := []struct{ path, code string }{
		// parameterized / safe DB
		{"a.py", `cur.execute("SELECT * FROM users WHERE id = %s", (uid,))`},
		{"a.py", `cur.execute("INSERT INTO t (a, b) VALUES (%s, %s)", (a, b))`},
		{"a.js", "db.query('SELECT * FROM u WHERE id = ?', [id])"},
		{"a.go", `db.Query("SELECT * FROM u WHERE id = $1", id)`},
		{"a.rs", `sqlx::query("SELECT * FROM u WHERE id = $1").bind(id)`},
		// safe subprocess
		{"a.py", `subprocess.run(["git", "status"], check=True)`},
		{"a.py", `subprocess.run(["ffmpeg", "-i", path, out], timeout=30)`},
		{"a.go", `exec.Command("ping", "-c", "1", host)`},
		// safe crypto / random
		{"a.py", `digest = hashlib.sha256(file_bytes).hexdigest()`},
		{"a.py", `import bcrypt; bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12))`},
		{"a.py", `dice = random.randint(1, 6)`},
		{"a.py", `import secrets; token = secrets.token_urlsafe(32)`},
		{"a.go", `n := rand.Intn(len(shards))`}, // non-secret rand
		// secrets from env
		{"a.py", `DB_PASSWORD = os.environ["DB_PASSWORD"]`},
		{"a.js", `const key = process.env.STRIPE_KEY`},
		{"a.rs", `let api_key = std::env::var("API_KEY")?;`},
		{"a.py", `API_KEY = "<your-api-key-here>"`},                         // placeholder
		{"a.py", `password = "changeme"  # example only, override in prod`}, // this DOES trip 521; excluded below
		// safe file ops / defaults
		{"a.py", `os.chmod(path, 0o600)`},
		{"a.py", `os.chmod(path, 0o644)`},
		{"a.py", `path = os.path.join(BASE_DIR, "static", "app.css")`},
		{"a.py", `requests.get(url, timeout=10)`},
		{"a.py", `requests.get("https://api.github.com/user", timeout=5)`},
		// safe rendering / output
		{"a.jsx", `return <div>{comment.body}</div>`},
		{"a.js", `el.textContent = userInput`},
		{"a.py", `return render_template("profile.html", user=user)`},
		{"a.py", `cfg = yaml.safe_load(open(path))`},
		// eval-adjacent but safe
		{"a.py", `value = ast.literal_eval(expr)`},
		{"a.py", `model.eval()`}, // torch/ML eval, method call
		{"a.js", `arr.filter(x => x > 0)`},
		{"a.py", `result = calc.evaluate(safe_ast)`},
		// normal comments (not security confessions)
		{"a.py", `# compute the discount and return the total`},
		{"a.py", `# TODO: refactor this into a helper`},
		{"a.go", `// retry with exponential backoff`},
		// normal identifiers containing trigger substrings
		{"a.py", `barcode = generate_barcode(product_id)`},
		{"a.py", `zipcode = address.get("zip")`},
		{"a.js", `const password_field = document.getElementById("pw")`},
		// safe C
		{"a.c", "char buf[64];\nsnprintf(buf, sizeof(buf), \"%s\", name);"},
		// safe logging (no secret value)
		{"a.py", `logger.info("user %s logged in", username)`},
		// new domain buckets: legit code that must not trip the IaC/CI/contract rules
		{"a.js", `this._authToken = await fetchToken()`}, // field assignment, not an.npmrc literal
		{"a.sol", `require(msg.sender == owner, "not owner");`},
		{"a.sol", `token.transfer(recipient, amount);`},
		{"main.tf", `associate_public_ip_address = false`},
		{"main.tf", `storage_encrypted = true`},
		{"main.tf", `cidr_blocks = ["10.0.0.0/16"]`},
		{"pod.yaml", "        runAsNonRoot: true\n        privileged: false"},
		{"Dockerfile", `ENV NODE_ENV=production`},
		{"Dockerfile", `USER 10001`},
		{"Dockerfile", `RUN curl -fsSL -o app.sh https://x/app.sh && sha256sum -c sums`},
		{"ci.yml", "      env:\n        TITLE: ${{ github.event.issue.title }}"},
	}
	// a couple of the entries above are intentionally borderline; exclude them
	skip := map[string]bool{
		`password = "changeme"  # example only, override in prod`: true,
	}
	for _, c := range legit {
		if skip[c.code] {
			continue
		}
		if f := kb.scan(c.path, c.code); len(f) > 0 {
			t.Errorf("FALSE POSITIVE %s on %s: %q", f[0].Rule.CWE, c.path, c.code)
		}
	}
}
