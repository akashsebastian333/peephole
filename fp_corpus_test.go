package main

import "testing"

// Framework FP guard: everyday-correct code that must never be HARD-DENIED (a
// high-confidence match blocks the write in strict/hardened). Medium/ask is
// tolerable; only deny hurts developer productivity. Drawn from the KB review's
// confirmed false positives. This is the regression gate for the rule-authoring
// principle: an injection-class rule may only reach `high` when it can see the
// dangerous position/taint, never on the safe-but-dynamic form.
func TestNoHighConfidenceFalsePositives(t *testing.T) {
	kb := loadKB()
	legit := []struct{ path, code string }{
		// SSRF: fixed host, path/segment interpolated (idiomatic, safe)
		{"a.py", `r = requests.get(f"{BASE_URL}/users/{uid}")`},
		{"a.py", `r = requests.get(f"https://api.example.com/{uid}")`},
		{"a.py", `r = requests.get("https://api.example.com/" + path)`},
		{"a.js", "await fetch(`${API_BASE}/users/${id}`)"},
		{"a.js", "await axios.get(`/api/items/${itemId}`)"},
		{"a.go", `resp, _ := http.Get(fmt.Sprintf("%s/health", baseURL))`},
		// NoSQL: scalar value from request (ambiguous -> ask, not deny)
		{"a.js", `User.findOne({ email: req.body.email })`},
		{"a.js", `Post.find({ authorId: req.params.userId })`},
		// weak credential: None/empty default arg and field init
		{"a.py", `def __init__(self, host, password=None):`},
		{"a.py", `self.password = None`},
		{"a.py", `def connect(user, password=None, timeout=30):`},
		// path traversal: server-generated / validated filename
		{"a.py", `path = os.path.join(UPLOAD_DIR, filename)`},
		{"a.py", `full = os.path.join(base_dir, safe_name)`},
		// crypto: sha256/sha512 of a token/secret is fine (not weak)
		{"a.py", `digest = hashlib.sha256(token.encode()).hexdigest()`},
		{"a.py", `key = hashlib.sha256(secret).digest()`},
		{"a.py", `fingerprint = hashlib.sha512(api_key.encode()).hexdigest()`},
		// Rust: decode/decrypt unwrap panics loudly (not silent failure)
		{"a.rs", `let bytes = decoder.decode(input).unwrap();`},
		{"a.rs", `let pt = cipher.decrypt(&nonce, ct).unwrap();`},
		{"a.rs", `let s = std::str::from_utf8(buf).unwrap();`},
		// header/log with non-request dynamic value
		{"a.py", `resp.headers["Content-Type"] = f"{mime}; charset=utf-8"`},
	}
	for _, c := range legit {
		for _, f := range kb.scan(c.path, c.code) {
			if f.Confidence == "high" {
				t.Errorf("HARD-DENY FALSE POSITIVE %s (%s) on %s: %q", f.Rule.CWE, f.Confidence, c.path, c.code)
			}
		}
	}
}

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
