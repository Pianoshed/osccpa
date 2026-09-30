import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))   # must run before anything reads os.environ

import io
import re
import math
import time
import uuid
import secrets
import threading
import click
import requests
import pandas as pd
from urllib.parse import quote
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, Response, render_template, request, redirect, send_file,
                   url_for, session, flash, jsonify, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import Markup, escape
# Pillow is used to safely re-encode/compress news images (pip install Pillow)
from PIL import Image, ImageOps

app = Flask(__name__)


# ---------------------------------------------------------------------------
# SECURITY CONFIG
# ---------------------------------------------------------------------------
def load_secret_key():
    """Use the SECRET_KEY env var if set, otherwise create and reuse a random
    key stored in .secret_key (never hard-code it, never commit it).
    In production ALWAYS set SECRET_KEY as an env var (disk may be wiped on deploy)."""
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

# ---------------------------------------------------------------------------
# DATABASE: Supabase (Postgres)
# Set DATABASE_URL to the Supabase *Session pooler* URI (Connect -> Session pooler, port 5432):
#   postgresql://postgres.<ref>:<PASSWORD>@aws-0-<region>.pooler.supabase.com:5432/postgres
# ---------------------------------------------------------------------------
db_url = os.environ.get("DATABASE_URL")
if not db_url:
    raise RuntimeError("DATABASE_URL is not set. Add your Supabase connection string to the environment.")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,   # drop dead connections instead of erroring
    "pool_recycle": 300,     # recycle before the pooler closes idle connections
}
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

db = SQLAlchemy(app)
migrate = Migrate(app, db)


# ---------------------------------------------------------------------------
# SUPABASE STORAGE
#   SUPABASE_URL          https://<project-ref>.supabase.co
#   SUPABASE_SERVICE_KEY  the service_role / secret key (SERVER ONLY, never in templates or JS)
# Two buckets (create with `flask init-storage`):
#   evidence     -> PRIVATE. Only reachable through short-lived signed links for a logged-in admin.
#   news-images  -> PUBLIC.  Cover/gallery photos shown on the site.
# ---------------------------------------------------------------------------
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY") or ""
if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in the environment.")

STORAGE_URL = f"{SUPABASE_URL}/storage/v1"
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "evidence")
NEWS_BUCKET = os.environ.get("NEWS_BUCKET", "news-images")
SIGNED_URL_SECONDS = 300
STORAGE_TIMEOUT = 60

if SUPABASE_SERVICE_KEY.startswith("sb_publishable_"):
    raise RuntimeError("SUPABASE_SERVICE_KEY is a *publishable* key. Use the secret key "
                       "(sb_secret_...) or the legacy service_role key instead.")

_sb = requests.Session()
_sb.headers.update({"apikey": SUPABASE_SERVICE_KEY})
# Legacy service_role keys are JWTs and go in Authorization too.
# New sb_secret_ keys are NOT JWTs and must only be sent in the apikey header.
if SUPABASE_SERVICE_KEY.startswith("eyJ"):
    _sb.headers["Authorization"] = f"Bearer {SUPABASE_SERVICE_KEY}"

UPLOAD_ERROR = "We could not store the file right now. Please try again."


def sb_upload(bucket, key, data, content_type, cache_control=None):
    """Upload bytes to Supabase Storage. Raises ValueError (user-friendly) on failure."""
    headers = {"Content-Type": content_type, "x-upsert": "false"}
    if cache_control:
        headers["cache-control"] = cache_control
    try:
        r = _sb.post(f"{STORAGE_URL}/object/{bucket}/{quote(key)}",
                     data=data, headers=headers, timeout=STORAGE_TIMEOUT)
    except requests.RequestException as e:
        app.logger.error("Supabase upload error: %s", e)
        raise ValueError(UPLOAD_ERROR)
    if r.status_code not in (200, 201):
        app.logger.error("Supabase upload failed (%s): %s", r.status_code, r.text[:300])
        raise ValueError(UPLOAD_ERROR)


def sb_delete(bucket, keys):
    """Best-effort delete of one or more objects. Never raises."""
    keys = [k for k in keys if k]
    if not keys:
        return
    try:
        r = _sb.delete(f"{STORAGE_URL}/object/{bucket}",
                       json={"prefixes": keys}, timeout=STORAGE_TIMEOUT)
        if r.status_code not in (200, 201):
            app.logger.warning("Supabase delete failed (%s): %s", r.status_code, r.text[:300])
    except requests.RequestException as e:
        app.logger.warning("Supabase delete error: %s", e)


def sb_signed_url(bucket, key, expires=SIGNED_URL_SECONDS, download_name=None):
    """Create a short-lived link to a private object. Returns None on failure."""
    try:
        r = _sb.post(f"{STORAGE_URL}/object/sign/{bucket}/{quote(key)}",
                     json={"expiresIn": expires}, timeout=STORAGE_TIMEOUT)
        if r.status_code != 200:
            return None
        signed = r.json().get("signedURL")
    except (requests.RequestException, ValueError):
        return None
    if not signed:
        return None
    if signed.startswith("/storage/v1"):
        url = f"{SUPABASE_URL}{signed}"
    elif signed.startswith("/"):
        url = f"{STORAGE_URL}{signed}"
    else:
        url = signed
    if download_name:
        url += f"&download={quote(download_name)}"
    return url


def news_img_url(name):
    """Public URL of a news image (bucket is public)."""
    if not name:
        return ""
    return f"{STORAGE_URL}/object/public/{NEWS_BUCKET}/{quote(name)}"


@app.context_processor
def inject_storage_helpers():
    return {"news_img": news_img_url}


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

class NewsPost(db.Model):
    __tablename__ = 'news_posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    tag = db.Column(db.String(60), default="Update")
    summary = db.Column(db.String(500), nullable=False)   # short preview shown on cards / homepage
    body = db.Column(db.Text)                             # optional longer "read more" text
    image = db.Column(db.String(255))                     # cover photo -- object name in the news-images bucket
    link = db.Column(db.String(500))                      # optional external press/source link
    published = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def gallery(self):
        return [{'id': i.id, 'f': i.filename} for i in self.images]

class NewsImage(db.Model):
    """Extra gallery photos for a news post (a post can have several)."""
    __tablename__ = 'news_images'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('news_posts.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    post = db.relationship('NewsPost', backref=db.backref(
        'images', order_by='NewsImage.position', cascade='all, delete-orphan'))


# ---------------------------------------------------------------------------
# CLI: fresh database setup
#   flask init-db                      -> creates all tables in Supabase
#   flask init-storage                 -> creates the two storage buckets
#   flask create-admin <username>      -> prompts for a password, creates an admin
# ---------------------------------------------------------------------------
@app.cli.command("init-db")
def init_db_command():
    """Create all tables (use this for a fresh Supabase database)."""
    db.create_all()
    click.echo("Tables created.")

@app.cli.command("init-storage")
def init_storage_command():
    """Create the private 'evidence' bucket and the public 'news-images' bucket."""
    buckets = [
        (EVIDENCE_BUCKET, False),
        (NEWS_BUCKET, True),
    ]
    limit = MAX_UPLOAD_MB * 1024 * 1024
    for name, public in buckets:
        r = _sb.post(f"{STORAGE_URL}/bucket",
                     json={"id": name, "name": name, "public": public, "file_size_limit": limit},
                     timeout=STORAGE_TIMEOUT)
        if r.status_code in (200, 201):
            click.echo(f"Created {'public' if public else 'private'} bucket '{name}'.")
        elif "already exists" in r.text.lower() or r.status_code == 409:
            click.echo(f"Bucket '{name}' already exists.")
        else:
            click.echo(f"Could not create '{name}' ({r.status_code}): {r.text[:200]}")

@app.cli.command("create-admin")
@click.argument("username")
@click.password_option()
def create_admin_command(username, password):
    """Create an admin user."""
    if len(password) < 10:
        raise click.ClickException("Password must be at least 10 characters.")
    if Admin.query.filter_by(username=username).first():
        raise click.ClickException("That username already exists.")
    db.session.add(Admin(username=username, password=generate_password_hash(password)))
    db.session.commit()
    click.echo(f"Admin '{username}' created.")


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


# ---- Evidence uploads (private Supabase bucket) ----------------------------
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
    """Validate and upload to the private evidence bucket. Returns the stored
    object name or None. Raises ValueError with a user-friendly message if rejected."""
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
    data = file_storage.stream.read()
    if not data:
        raise ValueError("That file is empty.")
    safe_stem = secure_filename(stem)[:60] or "evidence"
    stored = f"{uuid.uuid4().hex[:12]}_{safe_stem}.{ext}"
    sb_upload(EVIDENCE_BUCKET, stored, data, EVIDENCE_MIME[ext])
    return stored

def remove_evidence_file(name, exclude_complaint_id=None):
    """Delete a stored evidence object, but only if no other complaint still points at it."""
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
    sb_delete(EVIDENCE_BUCKET, [safe])

def _respond(ok, message, status=200, endpoint="complaints"):
    if is_xhr():
        return jsonify(ok=ok, error=None if ok else message), status
    flash(message, "success" if ok else "error")
    return redirect(url_for(endpoint))


# ---- News images: validated, re-encoded, compressed, then uploaded --------
# Everything the admin uploads is fully decoded and re-saved as a fresh JPEG.
# A file that isn't a genuine, decodable image is rejected outright, and
# nothing from the original bytes (EXIF, trailing data, scripts) survives.
ALLOWED_NEWS_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}
NEWS_IMAGE_MAX_DIMENSION = 1600     # longest side, in pixels, after resizing
NEWS_IMAGE_MAX_PIXELS = 40_000_000  # guards against decompression-bomb uploads
NEWS_IMAGE_JPEG_QUALITY = 78

def save_news_image(file_storage):
    """Validate, safely re-encode, compress and upload a news image.
    Returns the stored object name, or None if no file was supplied.
    Raises ValueError with a user-friendly message if the upload is rejected."""
    if not file_storage or not file_storage.filename:
        return None

    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_NEWS_IMAGE_EXT:
        raise ValueError("Images must be PNG, JPG/JPEG or WEBP.")

    old_limit = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = NEWS_IMAGE_MAX_PIXELS
    try:
        file_storage.stream.seek(0)
        try:
            probe = Image.open(file_storage.stream)
            probe.verify()
        except Exception:
            raise ValueError("That file is not a valid image.")

        file_storage.stream.seek(0)
        try:
            img = Image.open(file_storage.stream)
            img.load()
            img = ImageOps.exif_transpose(img)
            if img.mode in ("RGBA", "LA", "P"):
                rgba = img.convert("RGBA")
                flat = Image.new("RGB", rgba.size, (255, 255, 255))
                flat.paste(rgba, mask=rgba.split()[-1])
                img = flat
            else:
                img = img.convert("RGB")
            img.thumbnail((NEWS_IMAGE_MAX_DIMENSION, NEWS_IMAGE_MAX_DIMENSION), Image.LANCZOS)
        except ValueError:
            raise
        except Exception:
            raise ValueError("Could not process that image. Please try a different file.")

        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=NEWS_IMAGE_JPEG_QUALITY, optimize=True)
        stored = f"{uuid.uuid4().hex[:16]}.jpg"
        sb_upload(NEWS_BUCKET, stored, buf.getvalue(), "image/jpeg",
                  cache_control="max-age=31536000")
        return stored
    finally:
        Image.MAX_IMAGE_PIXELS = old_limit

def remove_news_image(name):
    """Delete a news image from the public bucket."""
    if not name:
        return
    safe = os.path.basename(name)
    if safe != name:
        return
    sb_delete(NEWS_BUCKET, [safe])

NEWS_MAX_IMAGES = 10  # comfortably covers "at least 5 photos" per post

def save_news_images(file_storages):
    """Validate + compress + upload a batch of images (see save_news_image).
    Returns the stored names in order. If any file in the batch is rejected,
    every file already uploaded from this same batch is removed before the
    error is raised, so a failed upload never leaves orphans."""
    saved = []
    try:
        for fs in file_storages:
            if not fs or not fs.filename:
                continue
            name = save_news_image(fs)
            if name:
                saved.append(name)
        return saved
    except ValueError:
        for name in saved:
            remove_news_image(name)
        raise


# ---- Template filter: safe line-break rendering for admin-written text ----
@app.template_filter("nl2br")
def nl2br(value):
    """Escape the text (never trust admin-authored HTML into the page), then
    turn blank-line-separated paragraphs into <p> tags."""
    if not value:
        return ""
    paragraphs = re.split(r"\n\s*\n", str(value).strip())
    html = "".join(f"<p>{escape(p).replace(chr(10), Markup('<br>'))}</p>" for p in paragraphs if p.strip())
    return Markup(html)


# ---------------------------------------------------------------------------
# GLOBAL HOOKS
# ---------------------------------------------------------------------------
@app.before_request
def redirect_to_www():
    if request.host == "occpa.on.gov.ng":
        return redirect("https://www.occpa.on.gov.ng" + request.full_path, code=301)

@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.path.startswith("/admin") or request.path == "/export_excel":
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
    latest_news = NewsPost.query.filter_by(published=True) \
                                 .order_by(NewsPost.created_at.desc()).first()
    return render_template("index.html", latest_news=latest_news)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/news")
def news():
    news_posts = NewsPost.query.filter_by(published=True) \
                                .order_by(NewsPost.created_at.desc()).all()
    return render_template("news.html", news_posts=news_posts)

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
            sb_delete(EVIDENCE_BUCKET, [evidence_filename])   # don't leave an orphan upload
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
    news_data = NewsPost.query.order_by(NewsPost.created_at.desc()).all()
    return render_template("admin_dashboard.html", complaints=complaints_data,
                            contacts=contacts_data, news_posts=news_data)

@app.route("/admin/evidence/<path:filename>")
@login_required
def admin_evidence(filename):
    """Logged-in admins only. Redirects to a 5-minute signed Supabase link.
    Images, PDFs and video open in the browser; everything else downloads.
    ?download=1 forces a download. The URL stays the same as before, so the
    dashboard template needs no change."""
    name = os.path.basename(filename)
    if not name or name != filename:
        abort(404)

    # Only serve files that a complaint actually references
    if not Complaint.query.filter(Complaint.evidence == name).first():
        abort(404)

    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    inline = ext in INLINE_EVIDENCE and not request.args.get("download")
    shown_name = re.sub(r"^[0-9a-f]{12}_", "", name)

    url = sb_signed_url(EVIDENCE_BUCKET, name,
                        download_name=None if inline else shown_name)
    if not url:
        abort(404)
    resp = redirect(url)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
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


# ---------------------------------------------------------------------------
# ADMIN: NEWS POSTS  (drives the /news page and the homepage flash update)
# ---------------------------------------------------------------------------
def _news_form_fields():
    return (
        clean(request.form.get("title"), 200),
        clean(request.form.get("tag"), 60) or "Update",
        clean(request.form.get("summary"), 500),
        clean(request.form.get("body"), 8000),
        clean(request.form.get("link"), 500),
        request.form.get("published") == "on",
    )

@app.route("/admin/news/create", methods=["POST"])
@login_required
@csrf_protect
def news_create():
    title, tag, summary, body, link, published = _news_form_fields()

    if not title or not summary:
        flash("Title and summary are required.", "error")
        return redirect(url_for("admin_dashboard"))
    if link and not re.match(r"^https?://", link, re.I):
        flash("The link must start with http:// or https://", "error")
        return redirect(url_for("admin_dashboard"))

    files = [f for f in request.files.getlist("images") if f and f.filename][:NEWS_MAX_IMAGES]
    try:
        image_names = save_news_images(files)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin_dashboard"))

    try:
        post = NewsPost(title=title, tag=tag, summary=summary, body=body,
                         link=link or None, image=(image_names[0] if image_names else None),
                         published=published)
        db.session.add(post)
        db.session.flush()  # assigns post.id, needed for the NewsImage rows below
        for i, name in enumerate(image_names):
            db.session.add(NewsImage(post_id=post.id, filename=name, position=i))
        db.session.commit()
    except Exception:
        db.session.rollback()
        for name in image_names:
            remove_news_image(name)
        flash("Could not save the post. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))

    flash("News post published." if published else "News post saved as a draft.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/news/edit/<int:post_id>", methods=["POST"])
@login_required
@csrf_protect
def news_edit(post_id):
    post = NewsPost.query.get_or_404(post_id)
    title, tag, summary, body, link, published = _news_form_fields()

    if not title or not summary:
        flash("Title and summary are required.", "error")
        return redirect(url_for("admin_dashboard"))
    if link and not re.match(r"^https?://", link, re.I):
        flash("The link must start with http:// or https://", "error")
        return redirect(url_for("admin_dashboard"))

    remove_ids = {int(i) for i in request.form.getlist("remove_image") if i.isdigit()}
    existing = list(post.images)                       # already ordered by position
    keep = [img for img in existing if img.id not in remove_ids]
    to_delete = [img for img in existing if img.id in remove_ids]

    room_left = max(0, NEWS_MAX_IMAGES - len(keep))
    new_files = [f for f in request.files.getlist("images") if f and f.filename][:room_left]
    try:
        new_names = save_news_images(new_files)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin_dashboard"))

    delete_names = [img.filename for img in to_delete]
    try:
        post.title, post.tag, post.summary, post.body = title, tag, summary, body
        post.link = link or None
        post.published = published

        for img in to_delete:
            db.session.delete(img)
        for i, img in enumerate(keep):
            img.position = i
        new_rows = []
        for i, name in enumerate(new_names):
            row = NewsImage(post_id=post.id, filename=name, position=len(keep) + i)
            db.session.add(row)
            new_rows.append(row)

        final_order = keep + new_rows
        post.image = final_order[0].filename if final_order else None

        db.session.commit()
    except Exception:
        db.session.rollback()
        for name in new_names:
            remove_news_image(name)
        flash("Could not update the post. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))

    for name in delete_names:
        remove_news_image(name)   # only after the row deletions are committed

    flash("News post updated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/news/toggle/<int:post_id>", methods=["POST"])
@login_required
@csrf_protect
def news_toggle(post_id):
    post = NewsPost.query.get_or_404(post_id)
    post.published = not post.published
    db.session.commit()
    if is_xhr():
        return jsonify(ok=True, published=post.published)
    flash("Post is now " + ("published" if post.published else "a draft") + ".", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/news/delete/<int:post_id>", methods=["POST"])
@login_required
@csrf_protect
def news_delete(post_id):
    post = NewsPost.query.get_or_404(post_id)
    image_names = [img.filename for img in post.images]
    if post.image and post.image not in image_names:
        image_names.append(post.image)
    db.session.delete(post)               # cascades to NewsImage rows
    db.session.commit()
    sb_delete(NEWS_BUCKET, image_names)   # only after the row is gone
    flash("News post deleted.", "success")
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