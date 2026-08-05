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
		// Go log/status strings that merely START with a SQL verb (no from/where/set
		// second keyword) must NOT be flagged - regression guard for the FP fix.
		{"CWE-89", "a.go", `msg := fmt.Sprintf("UPDATE complete: %d rows affected", n)`, false},
		{"CWE-89", "a.go", `status := "DELETE failed for key " + key`, false},
		{"CWE-89", "a.go", `out := fmt.Sprintf("SELECT which option, got %v", choice)`, false},
		// CWE-78 Java sh -c wrapper (round-2 gap)
		{"CWE-78", "a.java", `new ProcessBuilder("bash", "-c", "ping " + host).start();`, true},
		{"CWE-78", "a.java", "Runtime.getRuntime().exec(new String[]{\"sh\",\"-c\",\"ping \"+host});", true},
		{"CWE-78", "a.java", `new ProcessBuilder("ping", "-c1", host).start();`, false}, // argv, safe
		// CWE-732 Terraform publicly-accessible managed DB (round-2 gap)
		{"CWE-732", "main.tf", "resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = true\n}", true},
		{"CWE-732", "main.tf", "resource \"aws_db_instance\" \"d\" {\n  publicly_accessible = false\n}", false},
		// CWE-703 Solidity unchecked .send() (round-2 gap)
		{"CWE-703", "c.sol", `msg.sender.send(amt);`, true},
		{"CWE-703", "c.sol", `require(msg.sender.send(amt));`, false},  // return checked
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
		{"CWE-829", "wf.yml", "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4", false},                                                                   // base checkout
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
		// hardcoded AWS credential VARIABLE assigned any literal (even a placeholder)
		// is the anti-pattern - the SDK reads from env/profile/IAM. (root-cause fix
		// for a benchmark miss where a placeholder value slipped the format rule.)
		{"CWE-798", "a.py", `AWS_SECRET_ACCESS_KEY = "xxxxxxxxxxxxxxxxxxxx"`, true},
		{"CWE-798", "a.py", `AWS_ACCESS_KEY_ID = "AKIAxxxxxxxxxxxxxxxx"`, true},
		{"CWE-798", "a.py", `AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]`, false},                                                      // env, secure
		{"CWE-798", "a.py", `boto3.client("s3", aws_secret_access_key=AWS_SECRET_ACCESS_KEY)`, false},                                                  // variable, not literal
		{"CWE-798", "a.py", `STRIPE_SECRET_KEY = "sk_placeholder_value_here"`, true},                                                                   // provider credential var = literal
		{"CWE-798", "a.py", `slack_token = config["slack_token"]`, false},                                                                              // from config, secure
		{"CWE-798", "a.py", `github_token = "{token}".format(token=lookup())`, false},                                                                  // runtime .format template, not a literal
		{"CWE-798", "a.py", `gitlab_token = "%(gitlab_token)s"`, false},                                                                                // named-% template, not a literal
		{"CWE-798", "a.js", `const c = "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";`, false}, // Azurite public emulator key
		{"CWE-798", "a.py", `DB_PASSWORD = os.environ["DB_PASSWORD"]`, false},
		{"CWE-798", "a.py", `password = "<your-password-here>"`, false}, // placeholder
		{"CWE-798", "a.js", `const k = process.env.STRIPE_KEY`, false},
		// Round-9: FP-audit fixes (safe code that must NOT match; TPs that must still match)
		{"CWE-798", "a.py", `PARTITION_KEY = os.getenv("PARTITION_KEY", "default")`, false},        // non-secret KEY-name + config default
		{"CWE-798", "a.js", `const s = process.env.SHARD_KEY || "shard-default"`, false},           // non-secret KEY-name default
		{"CWE-798", "a.py", `SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-1a2b3c4d")`, true}, // real hardcoded default kept
		{"CWE-798", "a.rs", `let token = "identifier";`, false},                                    // rust lexer token type, not a secret
		{"CWE-798", "a.rs", `let password_column = "hashed_password";`, false},                     // rust db column name
		{"CWE-798", "a.rs", `let api_key = "AKz9fLm2Qx8vPd41XYZ";`, true},                          // real rust secret (mixed-case value)
		{"CWE-90", "a.java", `String f = "(uid=" + LdapEncoder.filterEncode(u) + ")";`, false},     // escaped LDAP filter
		{"CWE-90", "a.py", `filt = "(uid=" + escape_filter_chars(username) + ")"`, false},          // escaped LDAP filter
		{"CWE-916", "a.py", `h = hashlib.pbkdf2_hmac("sha256", pw, salt, 600000, 32)`, false},      // strong iters w/ dklen
		{"CWE-916", "a.py", `h = hashlib.pbkdf2_hmac("sha256", pw, salt, 1000)`, true},             // weak iters kept
		{"CWE-676", "a.c", `realpath(userpath, resolved);`, false},                                 // realpath is the safe canonicalizer
		{"CWE-676", "a.c", `sscanf(line, "%d", &n);`, false},                                       // bounded numeric scanf
		{"CWE-676", "a.c", `sscanf(line, "%s", buf);`, true},                                       // unbounded %s scanf kept
		{"CWE-676", "a.c", `strcpy(dst, src);`, true},                                              // strcpy still flagged
		{"CWE-732", "a.py", `insecure = False`, false},                                             // substring 'secure' must not match
		{"CWE-732", "a.tf", `unencrypted = false`, false},                                          // substring 'encrypted' must not match
		{"CWE-732", "settings.py", `app.config["SESSION_COOKIE_SECURE"] = False`, true},            // real insecure cookie kept
		{"CWE-732", "a.sql", `GRANT SELECT ON *.* TO 'backup'@'localhost';`, false},                // read-only global grant (backups)
		{"CWE-732", "a.sql", `GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';`, true},                    // ALL PRIVILEGES kept
		{"CWE-502", "a.php", `unserialize($data, ["allowed_classes" => false]);`, false},           // safe unserialize form
		{"CWE-502", "a.php", `unserialize($_GET["x"]);`, true},                                     // tainted unserialize kept
		{"CWE-330", "a.py", `secret_santa = random.shuffle(participants)`, false},                  // shuffle is not secret-gen
		{"CWE-330", "a.py", `salt_amount = random.randint(1, 3)`, false},                           // non-security jitter/amount
		{"CWE-330", "a.py", `session_token = random.choice(chars)`, true},                          // insecure token-gen kept
		{"CWE-22", "a.js", "const c = fs.readFileSync(`${__dirname}/pkg.json`)", false},            // trusted __dirname interpolation
		{"CWE-22", "a.py", `open(f"log_{date}.txt", "w")`, false},                                  // local-var f-string path
		{"CWE-22", "a.py", `open(f"/data/{request.args['n']}")`, true},                             // request-derived path kept
		// Round-10: real-world FP fixes (mature-OSS scan) — safe must NOT match, TP must match
		{"CWE-78", "a.rs", `let cmd = Command::new("cmd");`, false},                             // clap builder API, not a shell
		{"CWE-78", "a.rs", `Command::new("sh").arg("-c").arg(format!("ping {}", host))`, true},  // real rust sh -c injection
		{"CWE-78", "a.py", `os.system("cargo build --release")`, false},                         // constant, no interpolation
		{"CWE-78", "a.py", `os.system(f"ping {host}")`, true},                                   // interpolated
		{"CWE-676", "a.rs", `unsafe { libc::sysconf(x) }`, false},                               // unsafe is idiomatic Rust
		{"CWE-502", "a.py", `obj = pickle.loads(pickle.dumps(request))`, false},                 // provable round-trip
		{"CWE-502", "a.py", `obj = pickle.loads(resp.content)`, true},                           // untrusted unpickle kept
		{"CWE-798", "a.md", `## -----BEGIN RSA PRIVATE KEY-----`, false},                        // PEM banner inside a comment
		{"CWE-798", "a.pem", `-----BEGIN RSA PRIVATE KEY-----`, true},                           // real PEM banner kept
		{"CWE-798", "a.tf", `url = "postgresql://postgres:${var.password}@h/db"`, false},        // templated credential
		{"CWE-798", "a.tf", `url = "postgres://admin:S3cretPass@h/db"`, true},                   // literal credential kept
		{"CWE-521", "a.yaml", `password: ""`, false},                                            // empty = auto-generate default
		{"CWE-79", "a.jsx", `<div dangerouslySetInnerHTML={{ __html: "<p>hi</p>" }} />`, false}, // constant HTML literal
		{"CWE-79", "a.jsx", `<div dangerouslySetInnerHTML={{ __html: userInput }} />`, true},    // tainted HTML kept
		// Round-11: reflected-XSS taint precision (source tightening + repr skip)
		{"CWE-79", "a.py", "url = request.args.get('u')\nreturn f\"<Req({url!r})>\"", false},     // __repr__ (!r), not response output
		{"CWE-79", "a.py", "url = request.args.get('u')\nreturn f\"<Req({url})>\"", true},        // raw reflected user input kept
		{"CWE-79", "a.py", "VERSION = os.environ.get('V', '1')\nreturn f\"=={VERSION}\"", false}, // env config, not user input
		{"CWE-79", "a.py", "SRC = fp.read()\nreturn f\"config: {SRC}\"", false},                  // local file read, not user input
		// Round-12: ask-level friction reduction (swallowed-error, timeout, ReDoS)
		{"CWE-703", "a.py", "try:\n    import ujson\nexcept ImportError:\n    pass", false}, // specific except = intentional
		{"CWE-703", "a.py", "try:\n    critical()\nexcept:\n    pass", true},                // bare except swallows everything
		{"CWE-703", "a.js", "try { risky() } catch {} // intentional noop", false},          // self-documented empty catch
		{"CWE-703", "a.js", "try { risky() } catch {}", true},                               // undocumented empty catch kept
		{"CWE-400", "a.py", ">>> requests.get('http://api.x/data')", false},                 // doctest example
		{"CWE-400", "a.py", "r = requests.get('http://api.x/data')", true},                  // real call, no timeout
		{"CWE-1333", "a.ts", "const globs = 'src/**/(*.)+(spec|test).ts'", false},           // glob string, not a regex
		{"CWE-1333", "a.js", "const re = /(a+)+/g", true},                                   // real nested-quantifier regex
		// Round-13: JWT verify-disable across lines (false-negative fix; flag the
		// disable-signal at its declaration, not only inline at jwt.decode)
		{"CWE-347", "a.py", "opts = {\"verify_signature\": False}\njwt.decode(tok, options=opts)", true}, // split across lines
		{"CWE-347", "a.py", "jwt.decode(tok, options={\"verify_signature\": False})", true},              // inline still caught
		{"CWE-347", "a.py", "jwt.decode(tok, key, algorithms=[\"RS256\"])", false},                       // verified, safe
		// Round-14: false-negative language-parity fixes (crypto/random/sqli/cmdi/jwt/deser/path/iac)
		{"CWE-327", "a.java", `Cipher c = Cipher.getInstance("DES");`, true},                            // broken cipher
		{"CWE-327", "a.java", `Cipher c = Cipher.getInstance("AES");`, true},                            // implicit ECB
		{"CWE-327", "a.java", `Cipher c = Cipher.getInstance("AES/GCM/NoPadding");`, false},             // safe AEAD
		{"CWE-327", "a.go", `d, _ := des.NewCipher(key)`, true},                                         // go broken cipher
		{"CWE-327", "a.go", `sum := sha256.Sum256(data)`, false},                                        // go strong hash
		{"CWE-327", "a.php", `$h = md5($password);`, true},                                              // php md5 password
		{"CWE-330", "a.java", `String otp = "" + new Random().nextInt(999999);`, true},                  // java predictable OTP
		{"CWE-330", "a.java", `int idx = new Random().nextInt(list.size());`, false},                    // non-security random
		{"CWE-89", "a.java", `ResultSet rs = st.executeQuery("SELECT * FROM u WHERE id=" + id);`, true}, // java JDBC SQLi
		{"CWE-78", "a.rb", `system("ping #{host}")`, true},                                              // ruby interpolation cmdi
		{"CWE-347", "a.js", `const claims = jwt.decode(token);`, true},                                  // js bare decode (no verify)
		{"CWE-502", "a.py", `obj = jsonpickle.decode(request.data)`, true},                              // jsonpickle RCE
		{"CWE-22", "a.go", `http.ServeFile(w, r, r.URL.Query().Get("f"))`, true},                        // go path traversal
		{"CWE-732", "main.tf", `actions   = ["*"]`, true},                                               // terraform IAM wildcard
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
