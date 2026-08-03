package main

import "testing"

// Edge-case corpus: each rule against tricky true-positives (must match) and
// false-positives (benign code that must not match). This is where FP/FN bugs
// surface, beyond the one-pair exemplar-consistency check.
func TestRuleCorpus(t *testing.T) {
	kb := loadKB()
	cases := []struct {
		cwe   string
		path  string
		code  string
		match bool
	}{
		// CWE-89 SQLi
		{"CWE-89", "a.py", `cur.execute(f"SELECT * FROM t WHERE id={x}")`, true},
		{"CWE-89", "a.py", `db.query("SELECT * FROM t WHERE id=" + x)`, true},
		{"CWE-89", "a.py", `cur.execute("SELECT * FROM t WHERE id=%s", (x,))`, false}, // parameterized
		{"CWE-89", "a.py", `cur.execute("SELECT 1")`, false},
		{"CWE-89", "a.py", `logger.info(f"about to run a SELECT for {x}")`, false}, // not execute
		{"CWE-89", "a.js", "db.query(`SELECT * FROM t WHERE id=${x}`)", true},
		{"CWE-89", "a.js", "db.query('SELECT * FROM t WHERE id=?', [x])", false}, // parameterized
		// CWE-89 Go SQL built in a variable (round-2 gap)
		{"CWE-89", "a.go", "query := \"SELECT * FROM users WHERE name = '\" + name + \"'\"\nrows, _ := db.Query(query)", true},
		{"CWE-89", "a.go", "query := fmt.Sprintf(\"SELECT * FROM t WHERE id = %d\", id)\nrows, _ := db.Query(query)", true},
		{"CWE-89", "a.go", "query := \"SELECT * FROM t WHERE id = $1\"\nrows, _ := db.Query(query, id)", false}, // parameterized
		// CWE-78 Java sh -c wrapper (round-2 gap)
		{"CWE-78", "a.java", `new ProcessBuilder("bash", "-c", "ping " + host).start();`, true},
		{"CWE-78", "a.java", "Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"ping \"+host});", true},
		{"CWE-78", "a.java", `new ProcessBuilder("ping", "-c1", host).start();`, false}, // argv, safe
		// CWE-732 Terraform publicly-accessible managed DB (round-2 gap)
		{"CWE-732", "main.tf", "resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = true\n}", true},
		{"CWE-732", "main.tf", "resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = false\n}", false},
		// CWE-703 Solidity unchecked .send() (round-2 gap)
		{"CWE-703", "c.sol", `msg.sender.send(amt);`, true},
		{"CWE-703", "c.sol", `require(msg.sender.send(amt));`, false}, // return checked
		{"CWE-703", "c.sol", `bool ok = msg.sender.send(amt);`, false}, // return consumed
		// Round-3: C#/.NET, Android SQLite, PHP eval, Ruby SSTI, Swift SQL
		{"CWE-89", "a.cs", `var q = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);`, true},
		{"CWE-89", "a.cs", `var q = $"SELECT * FROM Users WHERE Id = {userId}";`, true},
		{"CWE-89", "a.cs", `var q = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);`, false},
		{"CWE-89", "a.cs", `log.Info($"Selected {count} rows from the report");`, false}, // "Selected"/"from" prose, not SQL concat
		{"CWE-78", "a.cs", `Process.Start("cmd.exe", "/c ping " + host);`, true},
		{"CWE-78", "a.cs", `Process.Start("ping", host);`, false}, // argv, safe
		{"CWE-327", "a.cs", `var des = new DESCryptoServiceProvider();`, true},
		{"CWE-327", "a.cs", `var h = SHA256.Create();`, false}, // strong
		{"CWE-94", "a.php", `eval($_GET["code"]);`, true},
		{"CWE-94", "a.php", `eval("return 1 + 2;");`, false}, // static
		{"CWE-1336", "a.rb", `render inline: params[:tpl]`, true},
		{"CWE-1336", "a.rb", `render inline: "<%= @user.name %>"`, false}, // static template
		{"CWE-89", "db.kt", `val c = db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)`, true},
		{"CWE-89", "db.kt", `val c = db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))`, false},
		{"CWE-89", "q.swift", "let rs = try db.executeQuery(\"SELECT * FROM u WHERE name = '\\(name)'\", values: nil)", true},
		{"CWE-89", "q.swift", `let rs = try db.executeQuery("SELECT * FROM u WHERE name = ?", values: [name])`, false},
		// Round-4: GHA pwn-request, C format-string, CloudFormation
		{"CWE-829", "wf.yml", "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}", true},
		{"CWE-829", "wf.yml", "on: pull_request\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}", false}, // read-only trigger
		{"CWE-829", "wf.yml", "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4", false}, // base checkout
		{"CWE-134", "a.c", `fprintf(stderr, user_msg);`, true},
		{"CWE-134", "a.c", `printf(buf);`, true},
		{"CWE-134", "a.c", `fprintf(stderr, "%s", user_msg);`, false}, // fixed format
		{"CWE-134", "a.c", `printf("done\n");`, false},
		{"CWE-732", "cfn.yml", "SecurityGroupIngress:\n  - CidrIp: 0.0.0.0/0", true},
		{"CWE-732", "cfn.yml", "CidrIp: 10.0.0.0/16", false}, // scoped
		{"CWE-732", "cfn.yml", "StorageEncrypted: false", true},
		{"CWE-732", "cfn.yml", "StorageEncrypted: true", false},
		// Round-5: cookie-flag disabled in the bracket-subscript config form
		{"CWE-732", "settings.py", `app.config['SESSION_COOKIE_SECURE'] = False`, true},
		{"CWE-732", "settings.py", `app.config['DEBUG'] = False`, false}, // unrelated key stays clean
		// CWE-78 command injection
		{"CWE-78", "a.py", `os.system(f"ping {h}")`, true},
		{"CWE-78", "a.py", `subprocess.run(["ping", h])`, false}, // argv list
		{"CWE-78", "a.py", `os.system("ls -la")`, false},         // static
		// CWE-94 eval
		{"CWE-94", "a.py", `eval(request.args["x"])`, true},
		{"CWE-94", "a.py", `ast.literal_eval(x)`, false}, // prev_not excludes
		{"CWE-94", "a.py", `model.eval()`, false},        // method call
		{"CWE-94", "a.py", `spec.eval(context)`, false},  // method call
		// CWE-502 deserialization (multi-language)
		{"CWE-502", "a.py", `data = pickle.loads(blob)`, true},
		{"CWE-502", "a.py", `cfg = yaml.load(f)`, true},
		{"CWE-502", "a.py", `cfg = yaml.safe_load(f)`, false},
		{"CWE-502", "a.py", `blob = pickle.dumps(obj)`, false}, // dump not load
		{"CWE-502", "a.php", `$o = unserialize($_GET["x"]);`, true},
		{"CWE-502", "a.rb", `Marshal.load(data)`, true},
		{"CWE-502", "a.java", `ois.readObject()`, true},
		// CWE-79 XSS
		{"CWE-79", "a.js", `el.innerHTML = user + data`, true},
		{"CWE-79", "a.jsx", `<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(x)}} />`, false},
		{"CWE-79", "a.jsx", `<div>{comment.body}</div>`, false}, // JSX text escapes
		// CWE-22 path traversal
		{"CWE-22", "a.py", `open(os.path.join(UP, request.args["n"]), "rb")`, true},
		{"CWE-22", "a.py", `send_from_directory(UP, name)`, false}, // validated helper
		{"CWE-22", "a.py", `os.path.join(BASE, "static", "x.css")`, false},
		// CWE-798 secrets
		{"CWE-798", "a.py", `AWS = "AKIAIOSFODNN7EXAMPLE"`, true},
		{"CWE-798", "a.py", `DB_PASSWORD = os.environ["DB_PASSWORD"]`, false},
		{"CWE-798", "a.py", `password = "<your-password-here>"`, false}, // placeholder
		{"CWE-798", "a.js", `const k = process.env.STRIPE_KEY`, false},
		// CWE-327 crypto
		{"CWE-327", "a.py", `pw = hashlib.md5(password.encode()).hexdigest()`, true},
		{"CWE-327", "a.py", `h = hashlib.sha256(file_bytes).hexdigest()`, false}, // non-password sha256
		{"CWE-327", "a.py", `pw = bcrypt.hashpw(p, bcrypt.gensalt())`, false},
		// CWE-918 SSRF
		{"CWE-918", "a.py", `r = requests.get(f"https://{host}/x")`, true},
		{"CWE-918", "a.py", `r = requests.get("https://api.example.com/x")`, false}, // constant
		{"CWE-918", "a.py", `r = requests.get(url, timeout=5)`, false},              // bare var
		// CWE-943 NoSQL
		{"CWE-943", "a.js", `db.users.findOne({ user: req.body.user })`, true},
		{"CWE-943", "a.js", `db.users.findOne({ user: String(req.body.user) })`, false},
		// CWE-1321 prototype pollution
		{"CWE-1321", "a.js", `target["__proto__"] = value`, true},
		{"CWE-1321", "a.js", `obj[key] = value`, false},
		// CWE-470 unsafe reflection
		{"CWE-470", "a.py", `h = getattr(controllers, request.args["a"])`, true},
		{"CWE-470", "a.py", `h = getattr(obj, "static_name")`, false},
		// CWE-113 header injection
		{"CWE-113", "a.py", `resp.headers["X"] = request.args["n"]`, true},
		{"CWE-113", "a.py", `resp.headers["X"] = "static-value"`, false},
		// CWE-732 insecure defaults (agnostic / command / IaC)
		{"CWE-732", "a.py", `os.chmod(p, 0o777)`, true},
		{"CWE-732", "a.py", `os.chmod(p, 0o600)`, false},
		{"CWE-732", "a.py", `os.chmod(p, 0o644)`, false},
		{"CWE-732", "main.tf", `cidr_blocks = ["0.0.0.0/0"]`, true},
		{"CWE-732", "Dockerfile", `USER root`, true},
		// CWE-521 weak/default/empty credentials (incl. .env)
		{"CWE-521", ".env", `DB_PASSWORD=admin123`, true},
		{"CWE-521", "a.py", `ADMIN_PASSWORD = "changeme"`, true},
		{"CWE-521", ".env", `MYSQL_ALLOW_EMPTY_PASSWORD=yes`, true},
		{"CWE-521", "a.py", `DB_PASSWORD = os.environ["DB_PASSWORD"]`, false},
		{"CWE-521", "a.py", `DB_PASSWORD = generate_strong_secret()`, false},
		// CWE-1188 disabled controls
		{"CWE-1188", "a.py", `requests.get(url, verify=False)`, true},
		{"CWE-1188", "settings.py", `ALLOWED_HOSTS = ["*"]`, true},
		{"CWE-1188", "deploy.sh", `ssh -o StrictHostKeyChecking=no host`, true},
		{"CWE-1188", "a.py", `requests.get(url, verify=True)`, false},
		// CWE-400 missing timeout
		{"CWE-400", "a.py", `r = requests.get(url)`, true},
		{"CWE-400", "a.py", `r = requests.get(url, timeout=5)`, false},
		// FP regression cases
		{"CWE-330", "a.py", `barcode = random.randint(1, 100)`, false}, // 'code' no longer FP
		{"CWE-330", "a.py", `reset_token = str(random.randint(0, 9))`, true},
		{"CWE-79", "a.js", `el.innerHTML = userInput`, true}, // bare var assignment
		{"CWE-79", "a.js", `el.innerHTML = DOMPurify.sanitize(x)`, false},
		{"CWE-79", "a.js", `el.innerHTML = "<b>static</b>"`, false},                 // string literal
		{"CWE-798", "a.py", `DSN = "postgres://user:password@localhost/db"`, false}, // doc/placeholder
		{"CWE-798", "a.py", `DSN = "postgres://svc:Xk9$mQ2@db.prod.internal/app"`, true},
		{"CWE-532", "a.py", `logger.info("processing password reset flow")`, false}, // mention only
		{"CWE-532", "a.py", `logger.info(f"login pw={password}")`, true},
		// CWE-676 dangerous C functions (new: C/C++ bucket)
		{"CWE-676", "a.c", "char buf[64];\nstrcpy(buf, argv[1]);", true},
		{"CWE-676", "a.c", `system(cmd);`, true},
		{"CWE-676", "a.c", `snprintf(buf, sizeof(buf), "%s", argv[1]);`, false},
		// CWE-546 AI-confession markers (AI-specific; medium)
		{"CWE-546", "a.py", `app.run(host="0.0.0.0")  # TODO: add authentication before production`, true},
		{"CWE-546", "a.py", `api_key = "sk_x"  # replace with your real key`, true},
		{"CWE-546", "a.py", `# compute the running total`, false},
		// per-language rules (Rust / Go / PowerShell / Elixir)
		{"CWE-89", "a.rs", `sqlx::query(&format!("SELECT * FROM u WHERE e='{}'", email))`, true},
		{"CWE-89", "a.rs", `sqlx::query("SELECT * FROM u WHERE e=$1").bind(email)`, false},
		{"CWE-798", "a.rs", `const API_KEY: &str = "sk_live_abcdef123456";`, true},
		{"CWE-798", "a.rs", `let api_key = std::env::var("API_KEY")?;`, false},
		{"CWE-703", "a.rs", `let claims = token.verify(&key).unwrap();`, true},
		{"CWE-89", "a.go", `db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%d", id))`, true},
		{"CWE-89", "a.go", `db.Query("SELECT * FROM u WHERE id=$1", id)`, false},
		{"CWE-330", "a.go", `token := fmt.Sprintf("%d", rand.Int63())`, true},
		{"CWE-78", "a.rs", `Command::new("sh").arg("-c").arg(format!("ping {}", host))`, true},
		{"CWE-94", "a.ps1", `Invoke-Expression $userInput`, true},
		{"CWE-94", "a.ex", `Code.eval_string(user_code)`, true},
		// Solidity smart-contract footguns (new bucket)
		{"CWE-284", "a.sol", `require(tx.origin == owner, "not owner");`, true},
		{"CWE-284", "a.sol", `require(msg.sender == owner, "not owner");`, false},
		{"CWE-841", "a.sol", `(bool ok,) = msg.sender.call{value: bal}("");`, true},
		{"CWE-841", "a.sol", `token.transfer(msg.sender, amount);`, false},
		{"CWE-829", "a.sol", `impl.delegatecall(data);`, true},
		{"CWE-829", "a.sol", `function kill() external { selfdestruct(payable(msg.sender)); }`, true},
		{"CWE-330", "a.sol", `uint w = uint(keccak256(abi.encodePacked(block.timestamp))) % n;`, true},
		{"CWE-330", "a.sol", `bytes32 h = keccak256(abi.encodePacked(name, id));`, false},
		// Terraform / IaC (new bucket), all fold into CWE-732 defaults
		{"CWE-732", "main.tf", `storage_encrypted = false`, true},
		{"CWE-732", "main.tf", `"Action": "*"`, true},
		{"CWE-732", "main.tf", `associate_public_ip_address = true`, true},
		{"CWE-732", "main.tf", `storage_encrypted = true`, false},
		{"CWE-798", "main.tf", `password = "hunter2secret"`, true},
		{"CWE-798", "main.tf", `password = var.db_password`, false},
		// Kubernetes YAML (new bucket), CWE-732
		{"CWE-732", "pod.yaml", "        privileged: true", true},
		{"CWE-732", "pod.yaml", "      hostNetwork: true", true},
		{"CWE-732", "pod.yaml", "      hostPath:\n        path: /", true},
		{"CWE-732", "pod.yaml", "        runAsUser: 0", true},
		{"CWE-732", "pod.yaml", "            - SYS_ADMIN", true},
		{"CWE-732", "pod.yaml", "        runAsNonRoot: true", false},
		// Dockerfile (new bucket)
		{"CWE-798", "Dockerfile", `ENV DB_PASSWORD=hunter2`, true},
		{"CWE-798", "Dockerfile", `RUN --mount=type=secret,id=db_password ./configure.sh`, false},
		{"CWE-798", "Dockerfile", `ENV API_KEY=${API_KEY}`, false},
		{"CWE-494", "Dockerfile", `RUN curl -fsSL https://x.sh | sh`, true},
		{"CWE-494", "Dockerfile", `ADD https://example.com/app.tar.gz /app`, true},
		{"CWE-732", "Dockerfile", `USER root`, true},
		{"CWE-732", "Dockerfile", `USER 10001`, false},
		// CI / supply-chain (agnostic)
		{"CWE-94", "ci.yml", `      - run: echo "Issue: ${{ github.event.issue.title }}"`, true},
		{"CWE-94", "ci.yml", "      env:\n        TITLE: ${{ github.event.issue.title }}", false},
		{"CWE-532", "ci.yml", `      - run: echo "token=${{ secrets.NPM_TOKEN }}"`, true},
		{"CWE-494", "ci.yml", `      - run: curl -sSL https://get.example.com/i.sh | bash`, true},
		{"CWE-494", "package.json", `"scripts": { "postinstall": "curl https://x.sh | sh" }`, true},
		{"CWE-494", "package.json", `"scripts": { "postinstall": "node ./scripts/build.js" }`, false},
		{"CWE-798", ".npmrc", `//registry.npmjs.org/:_authToken=npm_AbCdEf0123456789Real`, true},
		{"CWE-798", ".npmrc", `//registry.npmjs.org/:_authToken=${NPM_TOKEN}`, false},
		{"CWE-494", "requirements.txt", `-e git+http://example.com/pkg.git#egg=pkg`, true},
		// CWE-703 silent failure (borrowed from pr-review-toolkit)
		{"CWE-703", "a.py", "try:\n    verify_signature(t)\nexcept Exception:\n    pass", true},
		{"CWE-703", "a.py", "try:\n    verify_signature(t)\nexcept SignatureError:\n    abort(401)", false},
		{"CWE-703", "a.js", "try { verify(t) } catch (e) {}", true},
		{"CWE-703", "a.js", "try { verify(t) } catch (e) { reject(e) }", false},
	}
	for _, c := range cases {
		got := false
		for _, f := range kb.scan(c.path, c.code) {
			if f.Rule.CWE == c.cwe {
				got = true
			}
		}
		if got != c.match {
			verb := "should NOT match but did"
			if c.match {
				verb = "should match but did NOT"
			}
			t.Errorf("%s %s: %q\n    (%s)", c.cwe, c.path, c.code, verb)
		}
	}
}
