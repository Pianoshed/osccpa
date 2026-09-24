import os
import io
import re
import math
import time
import uuid
import secrets
import threading
import pandas as pd
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, Response, render_template, request, redirect, send_file,
                   send_from_directory, url_for, session, flash, jsonify, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))


# ---------------------------------------------------------------------------
# SECURITY CONFIG
# ---------------------------------------------------------------------------
def load_secret_key():
    """Use the SECRET_KEY env var if set, otherwise create and reuse a random
    key stored in .secret_key (never hard-code it, never commit it)."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    path = os.path.join(basedir, ".secret_key")
    if os.path.exists(path):
        with open(path, "r") as f:
            existing = f.read().strip()
        if existing:
            return existing
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


app.secret_key = load_secret_key()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'complaints.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MAX_UPLOAD_MB = 10
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set COOKIE_SECURE=1 in production (HTTPS) so the cookie is never sent over http
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=(MAX_UPLOAD_MB + 1) * 1024 * 1024,
)

# Behind a reverse proxy (Render, PythonAnywhere, Nginx...)? Set TRUST_PROXY=1
# so the real visitor IP / https scheme are used.
if os.environ.get("TRUST_PROXY") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Evidence is stored OUTSIDE /static so it is never publicly reachable.
UPLOAD_FOLDER = os.path.join(basedir, "private_uploads")
# Files uploaded by the old version live here. They stay readable, but only by a logged-in admin.
LEGACY_UPLOAD_FOLDER = os.path.join(basedir, "static", "uploads")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)


# ---------------------------------------------------------------------------
# MODELS (unchanged)
# ---------------------------------------------------------------------------
class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Contact(db.Model):
    __tablename__ = 'contacts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    subject = db.Column(db.String(255))
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Complaint(db.Model):
    __tablename__ = 'complaints'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    lga = db.Column(db.String(100))
    business_name = db.Column(db.String(150))
    complaint_type = db.Column(db.String(100))
    complaint_details = db.Column(db.Text)
    evidence = db.Column(db.String(255))
    status = db.Column(db.String(50), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def is_xhr():
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"

def client_ip():
    return request.remote_addr or "unknown"

def clean(value, limit):
    """Trim whitespace and cap length so nothing exceeds its column."""
    return (value or "").strip()[:limit]

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session:
            if is_xhr():
                return jsonify(ok=False, error="Session expired. Please log in again."), 401
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function


# ---- CSRF protection for admin actions (delete / status change) -----------
def get_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token}

def csrf_protect(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent.encode(), expected.encode()):
            if is_xhr():
                return jsonify(ok=False, error="Security check failed. Refresh the page and try again."), 400
            flash("Security check failed. Please try again.", "error")
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    return wrapper


# ---- Login brute-force protection (per IP + username) ----------------------
_login_state = {}
_login_lock = threading.Lock()
MAX_LOGIN_FAILS = 5
LOGIN_LOCK_SECONDS = 600
LOGIN_FAIL_WINDOW = 900
DUMMY_HASH = generate_password_hash(secrets.token_hex(8))  # equalises timing for unknown usernames

def login_lock_remaining(key):
    with _login_lock:
        rec = _login_state.get(key)
        if not rec:
            return 0
        now = time.time()
        if rec["locked_until"] > now:
            return int(rec["locked_until"] - now)
        if now - rec["first"] > LOGIN_FAIL_WINDOW:
            _login_state.pop(key, None)
        return 0

def login_fail(key):
    now = time.time()
    with _login_lock:
        if len(_login_state) > 5000:
            for k in [k for k, r in _login_state.items()
                      if r["locked_until"] < now and now - r["first"] > LOGIN_FAIL_WINDOW]:
                _login_state.pop(k, None)
        rec = _login_state.get(key)
        if not rec or now - rec["first"] > LOGIN_FAIL_WINDOW:
            rec = {"count": 0, "first": now, "locked_until": 0}
        rec["count"] += 1
        if rec["count"] >= MAX_LOGIN_FAILS:
            rec["locked_until"] = now + LOGIN_LOCK_SECONDS
            rec["count"] = 0
            rec["first"] = now
        _login_state[key] = rec

def login_clear(key):
    with _login_lock:
        _login_state.pop(key, None)


# ---- Evidence uploads ------------------------------------------------------
ALLOWED_EVIDENCE = {"png", "jpg", "jpeg", "gif", "webp", "pdf", "doc", "docx",
                    "xls", "xlsx", "txt", "mp4"}

EVIDENCE_MIME = {
    "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
    "gif": "image/gif", "webp": "image/webp", "pdf": "application/pdf",
    "mp4": "video/mp4", "txt": "text/plain; charset=utf-8",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
# Shown in the browser; everything else is offered as a download
INLINE_EVIDENCE = {"png", "jpg", "jpeg", "gif", "webp", "pdf", "mp4"}

def _content_matches_extension(ext, head):
    """Cheap magic-byte check so an .html file can't be renamed to .jpg."""
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "png":
        return head.startswith(b"\x89PNG")
    if ext == "gif":
        return head[:4] == b"GIF8"
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if ext == "pdf":
        return head.lstrip()[:4] == b"%PDF"
    if ext in ("docx", "xlsx"):
        return head[:2] == b"PK"
    if ext in ("doc", "xls"):
        return head[:4] == b"\xd0\xcf\x11\xe0"
    if ext == "mp4":
        return head[4:8] == b"ftyp"
    if ext == "txt":
        return b"\x00" not in head
    return False

def save_evidence(file_storage):
    """Validate and store an upload. Returns the stored filename or None.
    Raises ValueError with a user-friendly message if rejected."""
    if not file_storage or not file_storage.filename:
        return None
    raw_name = file_storage.filename
    stem, dot_ext = os.path.splitext(raw_name)
    ext = dot_ext.lower().lstrip(".")
    if ext not in ALLOWED_EVIDENCE:
        raise ValueError("That file type is not allowed. Upload a photo, PDF, Word, Excel, text or MP4 file.")
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if not _content_matches_extension(ext, head):
        raise ValueError("The file looks damaged or does not match its type. Please upload it again.")
    safe_stem = secure_filename(stem)[:60] or "evidence"
    stored = f"{uuid.uuid4().hex[:12]}_{safe_stem}.{ext}"
    file_storage.save(os.path.join(UPLOAD_FOLDER, stored))
    return stored

def remove_evidence_file(name, exclude_complaint_id=None):
    """Delete a stored evidence file, but only inside the upload folders, and
    only if no other complaint still points at it."""
    if not name:
        return
    safe = os.path.basename(name)
    if safe != name:
        return
    q = Complaint.query.filter(Complaint.evidence == name)
    if exclude_complaint_id is not None:
        q = q.filter(Complaint.id != exclude_complaint_id)
    if q.count():
        return
    for folder in (UPLOAD_FOLDER, LEGACY_UPLOAD_FOLDER):
        path = os.path.join(folder, safe)
        if os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                pass

def _respond(ok, message, status=200, endpoint="complaints"):
    if is_xhr():
        return jsonify(ok=ok, error=None if ok else message), status
    flash(message, "success" if ok else "error")
    return redirect(url_for(endpoint))


# ---------------------------------------------------------------------------
# GLOBAL HOOKS
# ---------------------------------------------------------------------------
@app.before_request
def redirect_to_www():
    if request.host == "occpa.on.gov.ng":
        return redirect("https://www.occpa.on.gov.ng" + request.full_path, code=301)

@app.before_request
def protect_legacy_uploads():
    """Old evidence lived in /static/uploads (public). Keep the files working
    for the admin, but hide them from everyone else."""
    if request.path.startswith("/static/uploads/") and "admin_id" not in session:
        abort(404)

@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if (request.path.startswith("/admin") or request.path == "/export_excel") \
            and not request.path.startswith("/admin/evidence/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

@app.errorhandler(413)
def file_too_large(_e):
    msg = f"That file is too large. The limit is {MAX_UPLOAD_MB} MB."
    if is_xhr():
        return jsonify(ok=False, error=msg), 413
    flash(msg, "error")
    return redirect(url_for("complaints"))


# ---------------------------------------------------------------------------
# ADMIN AUTH
# ---------------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = clean(request.form.get("username"), 150)
        password = request.form.get("password") or ""
        key = f"{client_ip()}|{username.lower()}"

        wait = login_lock_remaining(key)
        if wait:
            flash(f"Too many failed attempts. Try again in {math.ceil(wait / 60)} minute(s).")
            return render_template("admin_login.html"), 429

        admin = Admin.query.filter_by(username=username).first()
        password_ok = check_password_hash(admin.password if admin else DUMMY_HASH, password)

        if admin and password_ok:
            login_clear(key)
            session.clear()                      # new session on login (prevents fixation)
            session["admin_id"] = admin.id
            session["admin_user"] = admin.username
            session.permanent = True
            return redirect(url_for("admin_dashboard"))

        login_fail(key)
        flash("Invalid username or password")
    return render_template("admin_login.html")

@app.route("/admin/logout")
@login_required
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""

        admin = db.session.get(Admin, session["admin_id"])
        if admin is None:
            session.clear()
            return redirect(url_for("admin_login"))

        if not check_password_hash(admin.password, current):
            flash("Current password is incorrect")
            return redirect(url_for("change_password"))

        if new != confirm:
            flash("New passwords do not match")
            return redirect(url_for("change_password"))

        if len(new) < 10:
            flash("New password must be at least 10 characters long")
            return redirect(url_for("change_password"))

        admin.password = generate_password_hash(new)
        db.session.commit()

        flash("Password changed successfully")
        return redirect(url_for("admin_dashboard"))

    return render_template("change_password.html")


# ---------------------------------------------------------------------------
# PUBLIC PAGES
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/news")
def news():
    return render_template("news.html")

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        new_contact = Contact(
            name=clean(request.form.get('name'), 150),
            email=clean(request.form.get('email'), 150),
            phone=clean(request.form.get('phone'), 50) or 'N/A',
            subject=clean(request.form.get('subject'), 255),
            message=clean(request.form.get('message'), 5000)
        )
        db.session.add(new_contact)
        db.session.commit()
        flash("Your message has been submitted successfully!")
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route("/complaints", methods=["GET", "POST"])
def complaints():
    if request.method == "POST":
        full_name = clean(request.form.get("full_name"), 150)
        email = clean(request.form.get("email"), 150)
        phone = clean(request.form.get("phone"), 50) or "N/A"
        lga = clean(request.form.get("lga"), 100)
        business_name = clean(request.form.get("business_name"), 150)
        complaint_type = clean(request.form.get("complaint_type"), 100)
        details = clean(request.form.get("complaint_details"), 10000)

        if not (full_name and email and lga and business_name and complaint_type and details):
            return _respond(False, "Please fill in all the required fields.", 400)
        if not EMAIL_RE.match(email):
            return _respond(False, "Please enter a valid email address.", 400)

        try:
            evidence_filename = save_evidence(request.files.get("evidence"))
        except ValueError as e:
            return _respond(False, str(e), 400)

        new_comp = Complaint(
            full_name=full_name,
            email=email,
            phone=phone,
            lga=lga,
            business_name=business_name,
            complaint_type=complaint_type,
            complaint_details=details,
            evidence=evidence_filename
        )
        try:
            db.session.add(new_comp)
            db.session.commit()
        except Exception:
            db.session.rollback()
            if evidence_filename:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, evidence_filename))
                except OSError:
                    pass
            return _respond(False, "We could not save your complaint. Please try again.", 500)

        if is_xhr():
            return jsonify(ok=True)
        flash("Complaint submitted successfully", "success")
        return redirect(url_for("complaints"))
    return render_template("complaints.html")


# ---------------------------------------------------------------------------
# ADMIN DASHBOARD
# ---------------------------------------------------------------------------
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    complaints_data = Complaint.query.order_by(Complaint.created_at.desc()).all()
    contacts_data = Contact.query.order_by(Contact.created_at.desc()).all()
    return render_template("admin_dashboard.html", complaints=complaints_data, contacts=contacts_data)

@app.route("/admin/evidence/<path:filename>")
@login_required
def admin_evidence(filename):
    """Serve an uploaded file to a logged-in admin only. Images, PDFs and video
    open in the browser; everything else downloads. ?download=1 forces a download."""
    name = os.path.basename(filename)
    if not name or name != filename:
        abort(404)
    folder = next((f for f in (UPLOAD_FOLDER, LEGACY_UPLOAD_FOLDER)
                   if os.path.isfile(os.path.join(f, name))), None)
    if folder is None:
        abort(404)

    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    inline = ext in INLINE_EVIDENCE and not request.args.get("download")
    shown_name = re.sub(r"^[0-9a-f]{12}_", "", name)

    resp = send_from_directory(
        folder, name,
        mimetype=EVIDENCE_MIME.get(ext, "application/octet-stream"),
        as_attachment=not inline,
        download_name=shown_name,
        conditional=True,
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "private, max-age=300"
    if ext != "pdf":
        # Uploaded content can never run scripts even if it were opened directly
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; sandbox"
        )
    return resp

@app.route("/admin/complaints/status/<int:id>", methods=["POST"])
@login_required
@csrf_protect
def update_complaint_status(id):
    complaint = Complaint.query.get_or_404(id)
    new_status = request.form.get("status")
    if new_status in ("Pending", "In Progress", "Resolved"):
        complaint.status = new_status
        db.session.commit()
        if is_xhr():
            return jsonify(ok=True, status=new_status)
        flash("Complaint status updated successfully", "success")
    elif is_xhr():
        return jsonify(ok=False, error="Invalid status."), 400
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/complaints/delete/<int:complaint_id>", methods=["POST"])
@login_required
@csrf_protect
def delete_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    evidence_name = complaint.evidence

    db.session.delete(complaint)
    db.session.commit()
    remove_evidence_file(evidence_name)          # only after the row is gone
    flash("Complaint deleted successfully", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/contacts/delete/<int:contact_id>", methods=["POST"])
@login_required
@csrf_protect
def delete_contact(contact_id):
    contact_obj = Contact.query.get_or_404(contact_id)
    db.session.delete(contact_obj)
    db.session.commit()
    flash("Contact deleted successfully", "success")
    return redirect(url_for("admin_dashboard"))

def _excel_safe(value):
    """Stop spreadsheet formula injection: text that starts with = + - @ would
    otherwise run as a formula when the admin opens the export."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value

@app.route('/export_excel')
@login_required
def export_excel():
    df_complaints = pd.read_sql(db.select(Complaint), db.engine)
    df_contacts = pd.read_sql(db.select(Contact), db.engine)

    for df in (df_complaints, df_contacts):
        for col in df.select_dtypes(include="object").columns:
            df[col] = df[col].map(_excel_safe)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_complaints.to_excel(writer, index=False, sheet_name='Complaints')
        df_contacts.to_excel(writer, index=False, sheet_name='Contacts')
    output.seek(0)

    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True,
                     download_name=f"occpa_export_{datetime.now().strftime('%Y-%m-%d')}.xlsx")


@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    """Simple XML sitemap for the public pages"""
    base_url = request.url_root.rstrip('/')
    pages = [
        f"{base_url}/",
        f"{base_url}/about",
        f"{base_url}/services",
        f"{base_url}/news",
        f"{base_url}/complaints",
        f"{base_url}/contact",
    ]

    lastmod = datetime.now().date().isoformat()

    sitemap_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    sitemap_xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'

    for page in pages:
        sitemap_xml += f'''  <url>
    <loc>{page}</loc>
    <lastmod>{lastmod}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>\n'''

    sitemap_xml += '</urlset>'

    return Response(sitemap_xml, mimetype='application/xml')


if __name__ == '__main__':
    app.run()