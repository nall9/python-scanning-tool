from flask import Flask, request, redirect, url_for, render_template_string, send_file, session, flash
from functools import wraps
import os, requests
import uuid, json

app = Flask(__name__)
app.secret_key = "change-me"
# حسابات تجريبية
USERS = {
    "admin@local": {"password": "admin123", "id": 1, "role": "admin"},
    "user@local":  {"password": "user123",  "id": 2, "role": "user"},
}

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")     # ملفات Word
PDF_DIR    = os.path.join(BASE_DIR, "converted")   # ملفات PDF
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PDF_DIR,    exist_ok=True)

# ---- ملفات المساعدة للّاب ----
COUNTER_FILE = os.path.join(BASE_DIR, ".counter")          # للأرقام المتسلسلة (نسخة ضعيفة)
OWNER_FILE   = os.path.join(BASE_DIR, ".owners.json")      # خريطة UUID -> user_id (نسخة آمنة)

def _load_owner_map():
    if os.path.exists(OWNER_FILE):
        try:
            with open(OWNER_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_owner_map(d):
    with open(OWNER_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f)

def next_id():
    n = 0
    if os.path.exists(COUNTER_FILE):
        with open(COUNTER_FILE, "r", encoding="utf-8") as f:
            n = int(f.read().strip() or "0")
    n += 1
    with open(COUNTER_FILE, "w", encoding="utf-8") as f:
        f.write(str(n))
    return n

def login_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return _wrap

# ---- قوالب ----
TPL_BASE = """
<!doctype html><html><head><meta charset="utf-8"><title>{{title or "Lab"}}</title>
<style>
body{font-family:Arial;max-width:800px;margin:30px auto;padding:0 12px}
.card{border:1px solid #ddd;border-radius:10px;padding:14px;margin:12px 0}
input,button{padding:8px 10px}
.msg{background:#f6f6f6;padding:8px;border-radius:8px;margin:6px 0}
.topbar{background:#eef;padding:8px;border-radius:8px;margin-bottom:10px}
.topbar a{margin-left:8px}
</style></head><body>

<div class="topbar">
  {% if session.get('user_id') %}
    Logged in as <strong>{{ session.get('user_id') }}</strong>
    <a href="{{ url_for('logout') }}">(Logout)</a>
  {% else %}
    Not logged in
    <a href="{{ url_for('login') }}">(Login)</a>
  {% endif %}
</div>

{% for cat,m in get_flashed_messages(with_categories=true) %}
  <div class="msg">[{{cat}}] {{m}}</div>
{% endfor %}
{{ body|safe }}
</body></html>
"""

TPL_INDEX = """
{% set title = "Home" %}
{% set body %}
<h2>Word → PDF (Vulnerable Lab)</h2>
<p>
  <a href="{{ url_for('convert_page') }}">Convert (INSECURE)</a> |
  <a href="{{ url_for('convert_fix_page') }}">Convert (SECURE)</a> |
  <a href="{{ url_for('login') }}">Login</a> |
  <a href="{{ url_for('admin') }}">Admin</a>
</p>
{% endset %}""" + TPL_BASE

TPL_LOGIN = """
{% set title = "Login" %}
{% set body %}
<div class="card">
  <h3>Login</h3>
  <form method="post">
    <input name="email" placeholder="email">
    <input name="password" placeholder="password" type="password">
    <button>Sign in</button>
  </form>
</div>
{% endset %}""" + TPL_BASE

TPL_CONVERT = """
{% set title = "Convert (INSECURE)" %}
{% set body %}
<div class="card">
  <h3>Upload .docx to 'convert' (INSECURE)</h3>
  <form method="post" action="{{ url_for('convert_upload') }}" enctype="multipart/form-data">
    <input type="file" name="file" accept=".doc,.docx">
    <button>Upload & Convert</button>
  </form>
</div>
{% if last_id %}
<div class="card">
  <strong>Latest ID:</strong> {{last_id}} —
  <a href="{{ url_for('get_pdf') }}?id={{last_id}}" target="_blank">Download PDF (insecure)</a>
</div>
{% endif %}
<p><a href="{{ url_for('index') }}">Home</a></p>
{% endset %}""" + TPL_BASE

TPL_CONVERT_FIX = """
{% set title = "Convert (SECURE)" %}
{% set body %}
<div class="card">
  <h3>Upload .docx (SECURE)</h3>
  <p>Requires login. Files are stored with UUID and bound to the owner.</p>
  <form method="post" action="{{ url_for('convert_fix_upload') }}" enctype="multipart/form-data">
    <input type="file" name="file" accept=".doc,.docx">
    <button>Upload & Convert (secure)</button>
  </form>
</div>
{% if last_uuid %}
<div class="card">
  <strong>Last UUID:</strong> {{last_uuid}}
  — <a href="{{ url_for('get_pdf_fix') }}?id={{last_uuid}}" target="_blank">Download PDF (secure)</a>
</div>
{% endif %}
<p><a href="{{ url_for('index') }}">Home</a></p>
{% endset %}""" + TPL_BASE

TPL_ADMIN = """
{% set title = "Admin" %}
{% set body %}
<div class="card">
  <h3>Admin Dashboard</h3>
  <p><a href="{{ url_for('logout') }}">Logout</a></p>

  <h4>Run Scan (IDOR check - INSECURE)</h4>
  <form method="post" action="{{ url_for('run_scan') }}">
    <input name="base" placeholder="http://127.0.0.1:5000" value="{{request.host_url[:-1]}}">
    <input name="max_id" type="number" min="1" value="10">
    <button>Run Scan (insecure)</button>
  </form>
</div>

<div class="card">
  <h4>Run Scan (SECURE check)</h4>
  <form method="post" action="{{ url_for('run_scan_secure') }}">
    <input name="base" placeholder="http://127.0.0.1:5000" value="{{request.host_url[:-1]}}">
    <button>Run Scan (secure)</button>
  </form>
</div>

{% if scan_output %}
<div class="card"><pre>{{scan_output}}</pre></div>
{% endif %}
<p><a href="{{ url_for('index') }}">Home</a></p>
{% endset %}""" + TPL_BASE

# ---- صفحات عامة + جلسات ----
@app.get("/")
def index():
    return render_template_string(TPL_INDEX)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        user = USERS.get(email)
        if user and user["password"] == password:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            # أولوية الرجوع لـ next إن وُجد، وإلا:
            return redirect(request.args.get("next") or (url_for("admin") if user["role"] == "admin" else url_for("index")))
        flash("Invalid credentials", "error")
    return render_template_string(TPL_LOGIN)

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---- النسخة الضعيفة (INSECURE) ----
@app.get("/convert")
def convert_page():
    last_id = request.args.get("last_id")
    return render_template_string(TPL_CONVERT, last_id=last_id)

@app.post("/convert")
def convert_upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("Choose a file", "error")
        return redirect(url_for("convert_page"))

    _id = next_id()
    src_path = os.path.join(UPLOAD_DIR, f"{_id}.docx")
    pdf_path = os.path.join(PDF_DIR,    f"{_id}.pdf")
    f.save(src_path)
    with open(pdf_path, "wb") as out:
        out.write(b"%%PDF-1.4\n%% Vulnerable demo PDF for ID %d\n" % _id)

    flash(f"Converted as ID={_id}", "info")
    return redirect(url_for("convert_page", last_id=_id))

@app.get("/pdf")
def get_pdf():
    _id = (request.args.get("id") or "").strip()
    pdf_path = os.path.join(PDF_DIR, f"{_id}.pdf")
    if not (_id.isdigit() and os.path.exists(pdf_path)):
        return "Not found", 404
    return send_file(pdf_path, as_attachment=True, download_name=f"{_id}.pdf")

# ---- النسخة الآمنة (SECURE) ----
@app.get("/convert_fix")
@login_required
def convert_fix_page():
    last_uuid = request.args.get("last_uuid")
    return render_template_string(TPL_CONVERT_FIX, last_uuid=last_uuid)

@app.post("/convert_fix")
@login_required
def convert_fix_upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        flash("Choose a file", "error")
        return redirect(url_for("convert_fix_page"))

    file_uuid = str(uuid.uuid4())
    src_path = os.path.join(UPLOAD_DIR, f"{file_uuid}.docx")
    pdf_path = os.path.join(PDF_DIR,    f"{file_uuid}.pdf")
    f.save(src_path)
    with open(pdf_path, "wb") as out:
        out.write(("%%PDF-1.4\n%% Secure demo PDF for UUID %s\n" % file_uuid).encode())

    owners = _load_owner_map()
    owners[file_uuid] = int(session["user_id"])
    _save_owner_map(owners)

    flash(f"Converted (secure) UUID={file_uuid}", "info")
    return redirect(url_for("convert_fix_page", last_uuid=file_uuid))

@app.get("/pdf_fix")
def get_pdf_fix():
    file_uuid = (request.args.get("id") or "").strip()
    pdf_path = os.path.join(PDF_DIR, f"{file_uuid}.pdf")
    owners = _load_owner_map()
    owner = owners.get(file_uuid)

    if not owner or not os.path.exists(pdf_path):
        return "Not found", 404
    if session.get("user_id") != owner:
        return "Forbidden", 403
    return send_file(pdf_path, as_attachment=True, download_name=f"{file_uuid}.pdf")

# ---- لوحة الأدمن + السكان ----
@app.route("/admin", methods=["GET"])
@login_required
def admin():
    if session.get("role") != "admin":
        return "Forbidden", 403
    return render_template_string(TPL_ADMIN, scan_output=None)

@login_required
def admin():
    return render_template_string(TPL_ADMIN, scan_output=None)

@app.post("/admin/scan")
@login_required
def run_scan():
    base = (request.form.get("base") or "").rstrip("/")
    max_id = int(request.form.get("max_id") or 10)
    found = []
    for i in range(1, max_id+1):
        try:
            r = requests.get(f"{base}/pdf?id={i}", timeout=3)
            if r.status_code == 200 and r.headers.get("Content-Type","").startswith("application/pdf"):
                found.append(i)
        except requests.RequestException:
            pass
    report = "IDOR FOUND for IDs: " + ", ".join(map(str, found)) if found else "No public PDFs detected."
    return render_template_string(TPL_ADMIN, scan_output=report)

@app.post("/admin/scan_secure")
@login_required
def run_scan_secure():
    base = (request.form.get("base") or "").rstrip("/")
    owners = _load_owner_map()
    uuids = list(owners.keys())
    if not uuids:
        return render_template_string(TPL_ADMIN, scan_output="No UUID files to test yet. Upload via /convert_fix.")
    unsecured = []
    s = requests.Session()  # بدون كوكيز
    for u in uuids:
        try:
            r = s.get(f"{base}/pdf_fix?id={u}", timeout=3, allow_redirects=False)
            if r.status_code == 200:
                unsecured.append(u)
        except requests.RequestException:
            pass
    report = ("SECURE CHECK FAILED — reachable without session:\n" + "\n".join(unsecured)) if unsecured \
             else "SECURE CHECK PASSED — all UUID PDFs require the correct owner session (403 for unauthenticated)."
    return render_template_string(TPL_ADMIN, scan_output=report)

# ---- تحكم كاش ----
@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp

# ---- دِبَغ ----
@app.get("/debug/list")
def list_files():
    ids = []
    for name in os.listdir(PDF_DIR):
        if name.endswith(".pdf"):
            try:
                ids.append(int(name[:-4]))
            except:
                pass
    ids.sort()
    return "<h3>PDF IDs:</h3><pre>" + ", ".join(map(str, ids)) + "</pre>"

# ---- تشغيل السيرفر (آخر شيء) ----

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

