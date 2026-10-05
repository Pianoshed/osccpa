import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))   # must run before anything reads os.environ

import io
import re
import math
import time
import uuid
import base64
import unicodedata
import secrets
import threading
import socket
import ipaddress
from html.parser import HTMLParser
import click
import requests
import pandas as pd
from urllib.parse import quote, urlparse, parse_qs, urljoin
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, Response, render_template, request, redirect, send_file,
                   url_for, session, flash, jsonify, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import Markup, escape
# Pillow is used to safely re-encode/compress uploaded images (pip install Pillow)
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
# Three buckets (create with `flask init-storage`):
#   evidence       -> PRIVATE. Only reachable through short-lived signed links for a logged-in admin.
#   news-images    -> PUBLIC.  Cover/gallery photos for news posts.
#   gallery-images -> PUBLIC.  Photos shown in the homepage "Agency in Action" gallery.
# ---------------------------------------------------------------------------
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY") or ""
if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in the environment.")

STORAGE_URL = f"{SUPABASE_URL}/storage/v1"
EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "evidence")
NEWS_BUCKET = os.environ.get("NEWS_BUCKET", "news-images")
GALLERY_BUCKET = os.environ.get("GALLERY_BUCKET", "gallery-images")
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

def gallery_img_url(name):
    """Public URL of a homepage gallery photo (bucket is public)."""
    if not name:
        return ""
    return f"{STORAGE_URL}/object/public/{GALLERY_BUCKET}/{quote(name)}"


@app.context_processor
def inject_storage_helpers():
    return {"news_img": news_img_url, "gallery_img": gallery_img_url}


# ---------------------------------------------------------------------------
# BREVO EMAIL (transactional API) -- sends the registration certificate (PDF)
# plus the verification link to the business's email.
#   BREVO_API_KEY       Brevo API key (xkeysib-...)  SERVER ONLY
#   MAIL_SENDER_EMAIL   a sender/domain you verified in Brevo (e.g. no-reply@occpa.on.gov.ng)
#   MAIL_SENDER_NAME    display name (default "OSCCPA")
#   MAIL_REPLY_TO       optional reply-to address
#   SITE_URL            public base URL used in the verify link / QR (default https://www.occpa.on.gov.ng)
# If BREVO_API_KEY or MAIL_SENDER_EMAIL is missing, emailing is simply switched off
# (registration still works).
# ---------------------------------------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY") or ""
MAIL_SENDER_EMAIL = os.environ.get("MAIL_SENDER_EMAIL") or ""
MAIL_SENDER_NAME = os.environ.get("MAIL_SENDER_NAME", "OSCCPA")
MAIL_REPLY_TO = os.environ.get("MAIL_REPLY_TO") or ""
SITE_URL = (os.environ.get("SITE_URL") or "https://www.occpa.on.gov.ng").rstrip("/")
BREVO_URL = "https://api.brevo.com/v3/smtp/email"
EMAIL_ENABLED = bool(BREVO_API_KEY and MAIL_SENDER_EMAIL)
RESEND_COOLDOWN_SECONDS = 120    # min gap between two certificate emails for the same business
if not EMAIL_ENABLED:
    app.logger.warning("Brevo email is OFF: set BREVO_API_KEY and MAIL_SENDER_EMAIL to enable it.")


def brevo_send(to_email, to_name, subject, html, text=None, attachments=None):
    """Send one transactional email through Brevo. Returns True/False, never raises.
    attachments: list of (filename, bytes)."""
    if not EMAIL_ENABLED or not to_email:
        return False
    payload = {
        "sender": {"name": MAIL_SENDER_NAME, "email": MAIL_SENDER_EMAIL},
        "to": [{"email": to_email, "name": to_name or to_email}],
        "subject": subject,
        "htmlContent": html,
    }
    if text:
        payload["textContent"] = text
    if MAIL_REPLY_TO:
        payload["replyTo"] = {"email": MAIL_REPLY_TO, "name": MAIL_SENDER_NAME}
    if attachments:
        payload["attachment"] = [
            {"name": n, "content": base64.b64encode(b).decode("ascii")} for n, b in attachments
        ]
    try:
        r = requests.post(
            BREVO_URL, json=payload, timeout=30,
            headers={"api-key": BREVO_API_KEY, "accept": "application/json",
                     "content-type": "application/json"},
        )
    except requests.RequestException as e:
        app.logger.error("Brevo send error: %s", e)
        return False
    if r.status_code not in (200, 201, 202):
        app.logger.error("Brevo send failed (%s): %s", r.status_code, r.text[:300])
        return False
    return True


def send_certificate_email(biz, verify_url, pdf_bytes):
    """Email the certificate PDF + verify link to the business. Returns True/False."""
    if not biz.email:
        return False
    biz_name = escape(biz.business_name)
    owner = escape(biz.owner_name)
    rid = escape(biz.reg_id)
    vurl = escape(verify_url)

    html = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:auto;color:#241B33">
      <div style="background:#6D28D9;color:#fff;padding:18px 22px;border-radius:10px 10px 0 0">
        <h2 style="margin:0;font-size:18px">Ondo State Competition &amp; Consumer Protection Agency</h2>
      </div>
      <div style="border:1px solid #e5def5;border-top:0;padding:22px;border-radius:0 0 10px 10px">
        <p>Dear {owner},</p>
        <p>Congratulations! <strong>{biz_name}</strong> has been successfully registered with the
        Ondo State Competition &amp; Consumer Protection Agency (OSCCPA).</p>
        <div style="background:#F1EBFC;border:1.5px solid #6D28D9;border-radius:10px;padding:14px;text-align:center;margin:18px 0">
          <div style="font-size:11px;letter-spacing:1px;color:#665D77;font-weight:bold">REGISTRATION ID</div>
          <div style="font-family:Courier New,monospace;font-size:24px;font-weight:bold;color:#4C1D95">{rid}</div>
        </div>
        <p>Your <strong>Certificate of Registration</strong> is attached to this email as a PDF.
        The certificate carries a QR code that anyone can scan to confirm your registration.</p>
        <p style="text-align:center;margin:22px 0">
          <a href="{vurl}" style="background:#6D28D9;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:bold;display:inline-block">Verify this registration</a>
        </p>
        <p style="font-size:12px;color:#665D77;word-break:break-all">Or copy this link:<br>{vurl}</p>
        <hr style="border:0;border-top:1px solid #eee;margin:20px 0">
        <p style="font-size:11px;color:#665D77">Keep your Registration ID safe. If you did not make this
        registration, please contact the agency immediately.</p>
      </div>
    </div>"""
    text = (f"Dear {biz.owner_name},\n\n"
            f"{biz.business_name} has been successfully registered with the Ondo State Competition & "
            f"Consumer Protection Agency (OSCCPA).\n\n"
            f"Registration ID: {biz.reg_id}\n"
            f"Verify your registration: {verify_url}\n\n"
            "Your Certificate of Registration is attached to this email (PDF). "
            "Scan the QR code on it, or open the link above, to verify.\n")
    return brevo_send(
        biz.email, biz.owner_name,
        f"Your OSCCPA Certificate of Registration - {biz.reg_id}",
        html, text,
        attachments=[(f"OSCCPA-Certificate-{biz.reg_id}.pdf", pdf_bytes)],
    )


def email_certificate_async(biz_id):
    """Build the certificate and email it. Meant to run in a background thread so the
    visitor isn't kept waiting on the PDF / Brevo. Never raises."""
    try:
        with app.app_context():
            biz = db.session.get(Business, biz_id)
            if not biz or biz.status != "Approved" or not biz.reg_id:
                return
            # No request context in a thread, so build the verify URL from SITE_URL
            verify_url = f"{SITE_URL}/verify/{biz.reg_id}"
            try:
                pdf = build_certificate_pdf(biz, verify_url)
            except Exception as e:
                app.logger.error("Certificate PDF failed for %s: %s", biz.reg_id, e)
                return
            if send_certificate_email(biz, verify_url, pdf):
                biz.cert_emailed_at = datetime.utcnow()
                db.session.commit()
    except Exception as e:
        app.logger.error("email_certificate_async crashed: %s", e)

def queue_certificate_email(biz_id):
    """Fire-and-forget background send."""
    threading.Thread(target=email_certificate_async, args=(biz_id,), daemon=True).start()


# ---------------------------------------------------------------------------
# MODELS
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

class HomepageSlide(db.Model):
    """LEGACY: the old admin-managed homepage slider. No longer used by the site
    (the slider is static again). Kept only so the existing table is not dropped
    by a migration. You can delete this class and the table once you're sure
    you don't need the old rows."""
    __tablename__ = 'homepage_slides'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class GalleryItem(db.Model):
    """One entry in the homepage 'Agency in Action' gallery: either an uploaded
    photo (kind='photo', filename in the gallery-images bucket) or a video
    saved as a link (kind='video', video_url)."""
    __tablename__ = 'gallery_items'
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(10), nullable=False, default="photo")   # 'photo' | 'video'
    filename = db.Column(db.String(255))                               # photos only
    video_url = db.Column(db.String(500))                              # videos only
    caption = db.Column(db.String(150))                                # optional title
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Business(db.Model):
    """A business registered with the agency through the public form.
    The reg_id (verifiable ID) is issued INSTANTLY on submission (status 'Approved'),
    so no admin approval is needed. Admins can still Suspend / Reject / delete later."""
    __tablename__ = 'businesses'
    id = db.Column(db.Integer, primary_key=True)
    reg_id = db.Column(db.String(40), unique=True, index=True)       # e.g. OSCCPA-2026-K7M3QX
    owner_name = db.Column(db.String(150), nullable=False)
    business_name = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(300), nullable=False)
    lga = db.Column(db.String(100))
    phone = db.Column(db.String(50))
    email = db.Column(db.String(150))
    cac_number = db.Column(db.String(40))
    nafdac_number = db.Column(db.String(40))                          # optional
    sector = db.Column(db.String(100))                                # optional
    business_type = db.Column(db.String(60))                          # Sole Proprietorship, Partnership, LLC, Cooperative...
    other_info = db.Column(db.Text)                                   # optional
    status = db.Column(db.String(20), default="Pending", nullable=False)  # Pending | Approved | Rejected | Suspended
    issued_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Set by an admin after checking the CAC number on https://search.cac.gov.ng (free manual check)
    cac_verified = db.Column(db.Boolean, default=False, nullable=False, server_default=db.false())
    cac_verified_at = db.Column(db.DateTime)
    cac_verified_by = db.Column(db.String(150))
    # Set when the certificate email was accepted by Brevo (NULL = not emailed yet)
    cert_emailed_at = db.Column(db.DateTime)

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


# Create any table that does not exist yet (never alters or drops existing tables), so a new
# model such as Business can't crash the site with "relation does not exist" after a deploy.
# NOTE: create_all() does NOT add new columns to existing tables. Run once in Supabase (SQL editor):
#   ALTER TABLE businesses ADD COLUMN IF NOT EXISTS business_type VARCHAR(60);
#   ALTER TABLE businesses ADD COLUMN IF NOT EXISTS cert_emailed_at TIMESTAMP;
with app.app_context():
    try:
        db.create_all()
    except Exception as exc:
        app.logger.error("db.create_all() failed: %s", exc)


# ---------------------------------------------------------------------------
# CLI: fresh database setup
#   flask init-db                      -> creates all tables in Supabase
#   flask init-storage                 -> creates the storage buckets (safe to re-run)
#   flask create-admin <username>      -> prompts for a password, creates an admin
# ---------------------------------------------------------------------------
@app.cli.command("init-db")
def init_db_command():
    """Create all tables (use this for a fresh Supabase database)."""
    db.create_all()
    click.echo("Tables created.")

def ensure_buckets(verbose=False):
    """Create the storage buckets that don't exist yet (existing ones are left alone)."""
    buckets = [
        (EVIDENCE_BUCKET, False),
        (NEWS_BUCKET, True),
        (GALLERY_BUCKET, True),
    ]
    limit = MAX_UPLOAD_MB * 1024 * 1024
    for name, public in buckets:
        try:
            r = _sb.post(f"{STORAGE_URL}/bucket",
                         json={"id": name, "name": name, "public": public, "file_size_limit": limit},
                         timeout=STORAGE_TIMEOUT)
        except requests.RequestException as e:
            app.logger.warning("Could not reach Supabase Storage to create '%s': %s", name, e)
            if verbose:
                click.echo(f"Could not create '{name}': {e}")
            continue
        if r.status_code in (200, 201):
            app.logger.info("Created %s storage bucket '%s'.", "public" if public else "private", name)
            if verbose:
                click.echo(f"Created {'public' if public else 'private'} bucket '{name}'.")
        elif "already exists" in r.text.lower() or r.status_code == 409:
            if verbose:
                click.echo(f"Bucket '{name}' already exists.")
        else:
            app.logger.warning("Could not create bucket '%s' (%s): %s", name, r.status_code, r.text[:200])
            if verbose:
                click.echo(f"Could not create '{name}' ({r.status_code}): {r.text[:200]}")

@app.cli.command("init-storage")
def init_storage_command():
    """Create the private 'evidence' bucket and the public 'news-images' and 'gallery-images' buckets."""
    ensure_buckets(verbose=True)

# Also do it automatically at startup (background thread so a slow network never delays boot).
threading.Thread(target=ensure_buckets, daemon=True).start()

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

@app.cli.command("resend-certificates")
def resend_certificates_command():
    """Email the certificate to every approved business that hasn't received it yet."""
    if not EMAIL_ENABLED:
        raise click.ClickException("Set BREVO_API_KEY and MAIL_SENDER_EMAIL first.")
    rows = Business.query.filter(Business.status == "Approved",
                                 Business.reg_id.isnot(None),
                                 Business.cert_emailed_at.is_(None)).all()
    click.echo(f"{len(rows)} business(es) not emailed yet.")
    sent = 0
    for biz in rows:
        verify_url = f"{SITE_URL}/verify/{biz.reg_id}"
        try:
            ok = send_certificate_email(biz, verify_url, build_certificate_pdf(biz, verify_url))
        except Exception as e:
            click.echo(f"  {biz.reg_id}: failed ({e})")
            continue
        if ok:
            biz.cert_emailed_at = datetime.utcnow()
            db.session.commit()
            sent += 1
            click.echo(f"  {biz.reg_id}: sent to {biz.email}")
        else:
            click.echo(f"  {biz.reg_id}: Brevo rejected / failed")
        time.sleep(0.3)
    click.echo(f"Done. Sent {sent}/{len(rows)}.")


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


# ---- Public images (news + gallery): validated, re-encoded, compressed, uploaded
# Everything the admin uploads is fully decoded and re-saved as a fresh JPEG.
# A file that isn't a genuine, decodable image is rejected outright, and
# nothing from the original bytes (EXIF, trailing data, scripts) survives.
ALLOWED_NEWS_IMAGE_EXT = {"png", "jpg", "jpeg", "webp"}
NEWS_IMAGE_MAX_DIMENSION = 1600     # longest side, in pixels, after resizing
NEWS_IMAGE_MAX_PIXELS = 40_000_000  # guards against decompression-bomb uploads
NEWS_IMAGE_JPEG_QUALITY = 78

def _prepare_jpeg(file_storage, label):
    """Validate an uploaded image, re-encode it as a compressed JPEG and return the bytes.
    Raises ValueError with a user-friendly message if the upload is rejected."""
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_NEWS_IMAGE_EXT:
        raise ValueError(f"{label} must be PNG, JPG/JPEG or WEBP.")

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
        return buf.getvalue()
    finally:
        Image.MAX_IMAGE_PIXELS = old_limit

def save_news_image(file_storage):
    """Validate, safely re-encode, compress and upload a news image.
    Returns the stored object name, or None if no file was supplied."""
    if not file_storage or not file_storage.filename:
        return None
    data = _prepare_jpeg(file_storage, "Images")
    stored = f"{uuid.uuid4().hex[:16]}.jpg"
    sb_upload(NEWS_BUCKET, stored, data, "image/jpeg", cache_control="max-age=31536000")
    return stored

def save_gallery_image(file_storage):
    """Validate, resize, compress and upload one homepage gallery photo."""
    if not file_storage or not file_storage.filename:
        return None
    data = _prepare_jpeg(file_storage, "Gallery photos")
    stored = f"{uuid.uuid4().hex[:16]}.jpg"
    sb_upload(GALLERY_BUCKET, stored, data, "image/jpeg", cache_control="max-age=31536000")
    return stored

def remove_gallery_image(name):
    """Delete a gallery photo from the public bucket."""
    if not name:
        return
    safe = os.path.basename(name)
    if safe != name:
        return
    sb_delete(GALLERY_BUCKET, [safe])

def remove_news_image(name):
    """Delete a news image from the public bucket."""
    if not name:
        return
    safe = os.path.basename(name)
    if safe != name:
        return
    sb_delete(NEWS_BUCKET, [safe])

NEWS_MAX_IMAGES = 10  # comfortably covers "at least 5 photos" per post
GALLERY_MAX_UPLOAD = 10  # photos per upload action

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


# ---- Gallery videos saved as links -----------------------------------------
VIDEO_FILE_EXT = (".mp4", ".webm", ".mov", ".m4v", ".ogv")
VIDEO_LINK_ERROR = ("That video link isn't supported. Use a YouTube, Vimeo or Facebook video link, "
                    "or a direct link ending in .mp4 / .webm.")
_YT_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")

def parse_video_url(url):
    """Work out how to show a pasted video link.
    Returns {'provider', 'embed', 'thumb'} or None if the link isn't supported.
    provider: 'youtube' | 'vimeo' | 'facebook' | 'file'
    embed:    the URL to put in an <iframe> (or a <video> tag when provider == 'file')
    thumb:    a preview image URL, or '' when none is available."""
    try:
        u = urlparse((url or "").strip())
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    host = u.hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    path = u.path or ""
    parts = [p for p in path.split("/") if p]

    # YouTube
    vid = None
    if host in ("youtube.com", "m.youtube.com", "music.youtube.com", "youtube-nocookie.com"):
        if path == "/watch":
            vid = (parse_qs(u.query).get("v") or [None])[0]
        elif len(parts) >= 2 and parts[0] in ("shorts", "embed", "live", "v"):
            vid = parts[1]
    elif host == "youtu.be" and parts:
        vid = parts[0]
    if vid is not None:
        if not _YT_ID.match(vid):
            return None
        return {"provider": "youtube",
                "embed": f"https://www.youtube-nocookie.com/embed/{vid}?rel=0",
                "thumb": f"https://i.ytimg.com/vi/{vid}/hqdefault.jpg"}

    # Vimeo
    if host in ("vimeo.com", "player.vimeo.com"):
        ids = re.findall(r"/(\d{5,})", path)
        if ids:
            return {"provider": "vimeo", "embed": f"https://player.vimeo.com/video/{ids[0]}", "thumb": ""}
        return None

    # Facebook
    if host in ("facebook.com", "m.facebook.com", "web.facebook.com", "fb.watch"):
        if not parts:
            return None
        return {"provider": "facebook",
                "embed": "https://www.facebook.com/plugins/video.php?href="
                         + quote(u.geturl(), safe="") + "&show_text=false&width=560",
                "thumb": ""}

    # Direct video file
    if path.lower().endswith(VIDEO_FILE_EXT):
        return {"provider": "file", "embed": u.geturl(), "thumb": ""}

    return None

def gallery_dict(g):
    """Plain dict for one GalleryItem (used by the admin dashboard and the homepage)."""
    base = {"id": g.id, "kind": g.kind, "caption": g.caption or ""}
    if g.kind == "video":
        info = parse_video_url(g.video_url) or {}
        base.update(url=g.video_url or "", image="", provider=info.get("provider", "link"),
                    embed=info.get("embed", ""), thumb=info.get("thumb", ""))
    else:
        base.update(url="", image=gallery_img_url(g.filename), provider="", embed="", thumb="")
    return base

def gallery_rows():
    """All gallery items, newest first."""
    return [gallery_dict(g) for g in GalleryItem.query.order_by(GalleryItem.id.desc()).all()]

def gallery_for_homepage():
    """Items in the shape the homepage gallery script expects."""
    out = []
    for g in gallery_rows():
        if g["kind"] == "video":
            if g["embed"]:
                out.append({"src": g["embed"], "type": "video", "provider": g["provider"],
                            "thumb": g["thumb"], "label": g["caption"], "feat": False})
        elif g["image"]:
            out.append({"src": g["image"], "type": "photo", "provider": "", "thumb": "",
                        "label": g["caption"], "feat": True})
    return out


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
    return render_template("index.html", latest_news=latest_news,
                           gallery_items=gallery_for_homepage())

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

# ---------------------------------------------------------------------------
# NEWS: external link previews (title / description / image of the post's link)
# The /news page calls this once per post that has a link. The server fetches
# the page, reads its Open Graph tags and returns them as JSON. Results are
# cached in memory, and private/internal addresses are never fetched.
# ---------------------------------------------------------------------------
PREVIEW_TTL_OK = 6 * 3600
PREVIEW_TTL_FAIL = 30 * 60
PREVIEW_MAX_BYTES = 400_000
PREVIEW_TIMEOUT = 5
PREVIEW_MAX_REDIRECTS = 3
PREVIEW_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OCCPA-LinkPreview/1.0; +https://www.occpa.on.gov.ng)",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en",
}
_preview_cache = {}          # link -> (expires_at, data_or_None)
_preview_lock = threading.Lock()

def _is_public_host(host):
    try:
        infos = socket.getaddrinfo(host, None)
        return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)
    except (socket.gaierror, ValueError):
        return False

class _MetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta, self.title, self._in_title = {}, "", False
    def handle_starttag(self, tag, attrs):
        if tag == "meta":
            a = dict(attrs)
            key = (a.get("property") or a.get("name") or "").lower()
            val = a.get("content")
            if key and val and key not in self.meta:
                self.meta[key] = val.strip()
        elif tag == "title" and not self.title:
            self._in_title = True
    def handle_data(self, data):
        if self._in_title:
            self.title += data
    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

def _fetch_preview(url):
    """Return {'title','description','image','url'} or None. Redirects are followed by hand
    so every hop is checked against the public-host rule."""
    current = url
    for _ in range(PREVIEW_MAX_REDIRECTS + 1):
        u = urlparse(current)
        if u.scheme not in ("http", "https") or not u.hostname or not _is_public_host(u.hostname):
            return None
        try:
            r = requests.get(current, headers=PREVIEW_HEADERS, timeout=PREVIEW_TIMEOUT,
                             stream=True, allow_redirects=False)
        except requests.RequestException:
            return None
        try:
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location")
                if not loc:
                    return None
                current = urljoin(current, loc)
                continue
            ctype = r.headers.get("Content-Type", "").lower()
            if r.status_code != 200 or "html" not in ctype:
                return None
            raw = b""
            for chunk in r.iter_content(16384):
                raw += chunk
                if len(raw) >= PREVIEW_MAX_BYTES:
                    break
            enc = r.encoding if (r.encoding and "charset" in ctype) else "utf-8"
            text = raw.decode(enc, errors="replace")
        finally:
            r.close()

        p = _MetaParser()
        try:
            p.feed(text)
        except Exception:
            pass
        m = p.meta
        title = m.get("og:title") or m.get("twitter:title") or p.title.strip()
        desc = m.get("og:description") or m.get("twitter:description") or m.get("description") or ""
        img = m.get("og:image") or m.get("twitter:image") or ""
        if img:
            img = urljoin(current, img)
            if img.startswith("http://"):
                img = "https://" + img[7:]          # avoid mixed-content blocking
            if not img.startswith("https://"):
                img = ""
        if not title and not desc:
            return None
        return {"title": title[:200], "description": desc[:300], "image": img, "url": current}
    return None

@app.route("/news/<int:post_id>/link-preview")
def news_link_preview(post_id):
    post = NewsPost.query.filter_by(id=post_id, published=True).first_or_404()
    link = (post.link or "").strip()
    if not link:
        return jsonify(error="no link")
    if rate_limited("preview", 240, 60):
        return jsonify(error="rate limited"), 429

    now = time.time()
    with _preview_lock:
        hit = _preview_cache.get(link)
    if hit and hit[0] > now:
        data = hit[1]
    else:
        data = _fetch_preview(link)
        with _preview_lock:
            if len(_preview_cache) > 500:
                for k in [k for k, v in _preview_cache.items() if v[0] < now]:
                    _preview_cache.pop(k, None)
            _preview_cache[link] = (now + (PREVIEW_TTL_OK if data else PREVIEW_TTL_FAIL), data)

    # Always 200: when a site blocks previews the page just keeps its "Read full story" button
    # (the page script removes the card) and the browser console stays clean.
    resp = jsonify(data or {"error": "Preview unavailable"})
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp

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
# BUSINESS REGISTRY: public registration form + public ID verification
# ---------------------------------------------------------------------------
ONDO_LGAS = ["Akoko North-East", "Akoko North-West", "Akoko South-East", "Akoko South-West",
             "Akure North", "Akure South", "Ese-Odo", "Idanre", "Ifedore", "Ilaje",
             "Ile-Oluji/Okeigbo", "Irele", "Odigbo", "Okitipupa", "Ondo East", "Ondo West",
             "Ose", "Owo"]
BUSINESS_SECTORS = ["Retail / Trading", "Food & Beverage", "Pharmacy / Health", "Manufacturing",
                    "Hospitality", "Fuel / Petroleum", "Electronics / Telecom", "Agriculture",
                    "Professional Services", "Other"]

# Legal structure of the business (required on the form)
BUSINESS_TYPES = [
    "Sole Proprietorship",
    "Partnership",
    "Limited Liability Company (Ltd)",
    "Public Limited Company (PLC)",
    "Limited Liability Partnership (LLP)",
    "Limited Partnership (LP)",
    "Cooperative Society",
    "Incorporated Trustees (NGO / Association)",
    "Other",
]

@app.context_processor
def inject_business_types():
    return {"business_types": BUSINESS_TYPES}

BUSINESS_STATUSES = ("Pending", "Approved", "Rejected", "Suspended")
ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # no 0/O/1/I so IDs are easy to read out
CAC_RE = re.compile(r"^[A-Z]{0,3}-?\d{3,10}$")           # RC123456, BN1234567, IT12345 ...
NAFDAC_RE = re.compile(r"^[A-Z0-9][A-Z0-9/\- ]{3,29}$")

# Names printed on the certificate (override with env vars if the office-holders change)
CHAIRMAN_NAME = os.environ.get("CHAIRMAN_NAME", "Hon. Oluyemi Fasipe")
CHAIRMAN_TITLE = os.environ.get("CHAIRMAN_TITLE", "Executive Chairman")
SECRETARY_NAME = os.environ.get("SECRETARY_NAME", "Hajia Modelelayo Kudirat Ola")
SECRETARY_TITLE = os.environ.get("SECRETARY_TITLE", "Administrative Secretary")
# Optional signature images (transparent PNG). If a file is missing the line is left blank.
CHAIRMAN_SIG = os.path.join(basedir, "static", "signatures", "chairman.png")
SECRETARY_SIG = os.path.join(basedir, "static", "signatures", "secretary.png")

# Many phones share one mobile-network IP (CGNAT), so keep these generous.
REGISTER_LIMIT = (60, 3600)      # submissions per IP per hour
VERIFY_LIMIT = (90, 60)          # lookups per IP per minute
CERT_LIMIT = (60, 60)            # certificate downloads per IP per minute
RESEND_LIMIT = (10, 3600)        # "email me my certificate again" requests per IP per hour

_rate_hits = {}
_rate_lock = threading.Lock()

def rate_limited(bucket, limit, window):
    """True if this IP has made `limit` calls to `bucket` in the last `window` seconds."""
    key = f"{bucket}|{client_ip()}"
    now = time.time()
    with _rate_lock:
        if len(_rate_hits) > 5000:
            for k in [k for k, v in _rate_hits.items() if not v or now - v[-1] > 3600]:
                _rate_hits.pop(k, None)
        hits = [t for t in _rate_hits.get(key, []) if now - t < window]
        if len(hits) >= limit:
            _rate_hits[key] = hits
            return True
        hits.append(now)
        _rate_hits[key] = hits
    return False

def new_business_id():
    """Random, unguessable ID such as OSCCPA-2026-K7M3QX (unique in the database)."""
    for _ in range(20):
        code = "".join(secrets.choice(ID_ALPHABET) for _ in range(6))
        rid = f"OSCCPA-{datetime.utcnow().year}-{code}"
        if not Business.query.filter_by(reg_id=rid).first():
            return rid
    raise RuntimeError("Could not generate a unique business ID")

def _business_form_error(f):
    if not (f["owner_name"] and f["business_name"] and f["address"] and f["lga"]
            and f["phone"] and f["email"] and f["cac_number"] and f["business_type"]):
        return "Please fill in all the required fields."
    if f["business_type"] not in BUSINESS_TYPES:
        return "Please choose a business type from the list."
    if f["lga"] not in ONDO_LGAS:
        return "Please choose a Local Government Area from the list."
    if not EMAIL_RE.match(f["email"]):
        return "Please enter a valid email address."
    if len(re.sub(r"\D", "", f["phone"])) < 7:
        return "Please enter a valid phone number."
    if not CAC_RE.match(f["cac_number"]):
        return "That CAC registration number doesn't look right. Example: RC1234567 or BN1234567."
    if f["nafdac_number"] and not NAFDAC_RE.match(f["nafdac_number"]):
        return "That NAFDAC number doesn't look right. Leave it blank if it doesn't apply to you."
    if not f["consent"]:
        return "Please confirm that the information you gave is true."
    return None

@app.route("/register-business", methods=["GET", "POST"])
def register_business():
    form = {}
    if request.method == "POST":
        if request.form.get("website"):                    # honeypot: real people never fill this
            return redirect(url_for("register_business"))
        form = {
            "owner_name": clean(request.form.get("owner_name"), 150),
            "business_name": clean(request.form.get("business_name"), 200),
            "address": clean(request.form.get("address"), 300),
            "lga": clean(request.form.get("lga"), 100),
            "phone": clean(request.form.get("phone"), 50),
            "email": clean(request.form.get("email"), 150),
            "cac_number": re.sub(r"\s+", "", clean(request.form.get("cac_number"), 40)).upper(),
            "nafdac_number": clean(request.form.get("nafdac_number"), 40).upper(),
            "sector": clean(request.form.get("sector"), 100),
            "business_type": clean(request.form.get("business_type"), 60),
            "other_info": clean(request.form.get("other_info"), 3000),
            "consent": request.form.get("consent") == "on",
        }
        if form["sector"] not in BUSINESS_SECTORS:
            form["sector"] = ""

        if rate_limited("register", *REGISTER_LIMIT):
            flash("Too many submissions from your connection. Please try again later.", "error")
            return render_template("register_business.html", form=form, lgas=ONDO_LGAS,
                                   sectors=BUSINESS_SECTORS), 429
        error = _business_form_error(form)
        if not error:
            dup = Business.query.filter(Business.cac_number == form["cac_number"],
                                        Business.status != "Rejected").first()
            if dup:
                # Same CAC + same email = the owner came back (lost ID / double tap): show the certificate again.
                if (dup.email or "").lower() == form["email"].lower() and dup.status == "Approved" and dup.reg_id:
                    flash("This business is already registered. Here is your certificate.", "success")
                    return redirect(url_for("registered_business", reg_id=dup.reg_id))
                error = ("A business with that CAC number has already been registered. "
                         "If this is a mistake, please contact the agency.")
        if error:
            flash(error, "error")
            return render_template("register_business.html", form=form, lgas=ONDO_LGAS,
                                   sectors=BUSINESS_SECTORS), 400

        biz = Business(owner_name=form["owner_name"], business_name=form["business_name"],
                       address=form["address"], lga=form["lga"], phone=form["phone"],
                       email=form["email"], cac_number=form["cac_number"],
                       nafdac_number=form["nafdac_number"] or None, sector=form["sector"] or None,
                       business_type=form["business_type"],
                       other_info=form["other_info"] or None, status="Approved")
        try:
            biz.reg_id = new_business_id()               # instant: no admin approval needed
            biz.issued_at = datetime.utcnow()
            db.session.add(biz)
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("We could not save your application. Please try again.", "error")
            return render_template("register_business.html", form=form, lgas=ONDO_LGAS,
                                   sectors=BUSINESS_SECTORS), 500

        # Email the certificate (PDF + verify link) in the background: it never slows down
        # or breaks the registration if Brevo is slow or down.
        if EMAIL_ENABLED:
            queue_certificate_email(biz.id)
            flash("Your certificate is also being sent to " + biz.email + ".", "success")
        return redirect(url_for("registered_business", reg_id=biz.reg_id))
    return render_template("register_business.html", form=form, lgas=ONDO_LGAS,
                           sectors=BUSINESS_SECTORS)

def _pdf_text(value):
    """The built-in PDF fonts only cover Latin-1, so drop accents/dots (e.g. Yoruba marks)."""
    return unicodedata.normalize("NFKD", value or "").encode("latin-1", "ignore").decode("latin-1")

def build_certificate_pdf(biz, verify_url):
    """Render the registration certificate and return the PDF bytes."""
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.colors import HexColor
    from reportlab.lib.utils import simpleSplit
    from reportlab.pdfgen import canvas
    from reportlab.graphics.barcode import qr
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics import renderPDF

    W, H = landscape(A4)
    purple, deep, light = HexColor("#6D28D9"), HexColor("#4C1D95"), HexColor("#F1EBFC")
    accent, muted, dark = HexColor("#A855F7"), HexColor("#665D77"), HexColor("#241B33")
    name = _pdf_text(biz.business_name)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(W, H))
    c.setTitle(f"OSCCPA Certificate of Registration - {biz.reg_id}")
    c.setAuthor("Ondo State Competition & Consumer Protection Agency")

    logo = os.path.join(basedir, "static", "logo", "osccpa_logo.png")
    has_logo = os.path.exists(logo)

    # soft background tint
    c.setFillColor(HexColor("#FBF9FE"))
    c.rect(0, 0, W, H, fill=1, stroke=0)

    # faint centred logo watermark
    if has_logo:
        c.saveState()
        try:
            c.setFillAlpha(0.07)
            c.drawImage(logo, W / 2 - 200, H / 2 - 135, 400, 270,
                        preserveAspectRatio=True, mask="auto", anchor="c")
        except Exception:
            pass
        c.restoreState()

    # borders
    c.setStrokeColor(purple); c.setLineWidth(5); c.rect(16, 16, W - 32, H - 32)
    c.setStrokeColor(accent); c.setLineWidth(1); c.rect(26, 26, W - 52, H - 52)

    # header logo + agency
    if has_logo:
        try:
            c.drawImage(logo, W / 2 - 65, H - 122, 130, 72, preserveAspectRatio=True, mask="auto", anchor="c")
        except Exception:
            pass
    c.setFillColor(purple); c.setFont("Helvetica-Bold", 13)
    c.drawCentredString(W / 2, H - 136, "ONDO STATE COMPETITION & CONSUMER PROTECTION AGENCY")

    # title
    c.setFillColor(deep); c.setFont("Times-Bold", 30)
    c.drawCentredString(W / 2, H - 178, "CERTIFICATE OF REGISTRATION")
    c.setStrokeColor(accent); c.setLineWidth(2); c.line(W / 2 - 60, H - 190, W / 2 + 60, H - 190)
    c.setFillColor(muted); c.setFont("Helvetica", 12)
    c.drawCentredString(W / 2, H - 214, "This is to certify that")

    # business name (shrinks / wraps to fit)
    size = 30
    while True:
        lines = simpleSplit(name, "Times-Bold", size, 640)
        if len(lines) <= 2 or size <= 18:
            break
        size -= 2
    lines = lines[:2]
    if len(simpleSplit(name, "Times-Bold", size, 640)) > 2:
        lines[-1] = lines[-1][:-1].rstrip() + "..."
    y = H - 250
    c.setFillColor(dark); c.setFont("Times-Bold", size)
    for ln in lines:
        c.drawCentredString(W / 2, y, ln)
        y -= size + 6

    # short message
    y -= 6
    c.setFillColor(muted); c.setFont("Helvetica", 12)
    msg = ("has been registered in the business registry of the Ondo State Competition & Consumer "
           "Protection Agency (OSCCPA) and is issued the registration ID below.")
    for ln in simpleSplit(msg, "Helvetica", 12, 600):
        c.drawCentredString(W / 2, y, ln)
        y -= 17

    # ID box
    y -= 8
    box_w, box_h = 380, 62
    c.setFillColor(light); c.setStrokeColor(purple); c.setLineWidth(1.5)
    c.roundRect(W / 2 - box_w / 2, y - box_h, box_w, box_h, 10, fill=1, stroke=1)
    c.setFillColor(muted); c.setFont("Helvetica-Bold", 8.5)
    c.drawCentredString(W / 2, y - 18, "REGISTRATION ID")
    c.setFillColor(deep); c.setFont("Courier-Bold", 26)
    c.drawCentredString(W / 2, y - 48, biz.reg_id)
    y -= box_h + 20

    # details line (business type first)
    bits = []
    if biz.business_type:
        bits.append(_pdf_text(biz.business_type))
    if biz.lga:
        bits.append(_pdf_text(biz.lga) + " Local Government Area")
    if biz.sector:
        bits.append(_pdf_text(biz.sector))
    if biz.issued_at:
        bits.append("Issued " + biz.issued_at.strftime("%d %B %Y"))
    detail = "   |   ".join(bits)
    dsize = 11
    while dsize > 8 and c.stringWidth(detail, "Helvetica", dsize) > W - 120:
        dsize -= 0.5
    c.setFillColor(dark); c.setFont("Helvetica", dsize)
    c.drawCentredString(W / 2, y, detail)
    if biz.cac_verified:
        c.setFillColor(HexColor("#D8F0E1")); c.setStrokeColor(HexColor("#1E6B3F")); c.setLineWidth(1)
        c.roundRect(W / 2 - 78, y - 36, 156, 22, 11, fill=1, stroke=1)
        c.setFillColor(HexColor("#1E6B3F")); c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(W / 2, y - 29, "CAC NUMBER VERIFIED")

    # signatures (Executive Chairman + Administrative Secretary)
    def signer(cx, sig_path, person, title):
        line_y = 122
        if os.path.exists(sig_path):
            try:
                c.drawImage(sig_path, cx - 55, line_y + 2, 110, 36, preserveAspectRatio=True, mask="auto", anchor="s")
            except Exception:
                pass
        c.setStrokeColor(muted); c.setLineWidth(0.8); c.line(cx - 90, line_y, cx + 90, line_y)
        c.setFillColor(dark); c.setFont("Helvetica-Bold", 10.5)
        c.drawCentredString(cx, line_y - 14, _pdf_text(person))
        c.setFillColor(muted); c.setFont("Helvetica", 9)
        c.drawCentredString(cx, line_y - 26, _pdf_text(title))
    signer(W / 2 - 150, CHAIRMAN_SIG, CHAIRMAN_NAME, CHAIRMAN_TITLE)
    signer(W / 2 + 150, SECRETARY_SIG, SECRETARY_NAME, SECRETARY_TITLE)

    # QR code + verify text (bottom left)
    widget = qr.QrCodeWidget(verify_url)
    b = widget.getBounds()
    qr_size = 66
    d = Drawing(qr_size, qr_size, transform=[qr_size / (b[2] - b[0]), 0, 0, qr_size / (b[3] - b[1]), 0, 0])
    d.add(widget)
    renderPDF.draw(d, c, 52, 40)
    c.setFillColor(deep); c.setFont("Helvetica-Bold", 8.5)
    c.drawString(124, 90, "Scan to verify")
    c.setFillColor(muted); c.setFont("Helvetica", 6.5)
    yy = 80
    for ln in simpleSplit(verify_url, "Helvetica", 6.5, 150):
        c.drawString(124, yy, ln); yy -= 8.5

    # note (bottom right)
    c.setFillColor(muted); c.setFont("Helvetica", 7)
    note = ("Issued electronically. Details were supplied by the business and are not an endorsement "
            "of its goods or services. Verify this certificate at the address shown or with the ID above.")
    yy = 66
    for ln in simpleSplit(note, "Helvetica", 7, 260):
        c.drawRightString(W - 52, yy, ln); yy -= 9

    c.showPage()
    c.save()
    return buf.getvalue()

@app.route("/registered/<reg_id>")
def registered_business(reg_id):
    """Shown right after registering: the ID, a certificate preview and the PDF download."""
    rid = re.sub(r"\s+", "", clean(reg_id, 40)).upper()
    biz = Business.query.filter_by(reg_id=rid, status="Approved").first_or_404()
    return render_template("registered_business.html", biz=biz,
                           verify_url=url_for("verify_business", reg_id=biz.reg_id, _external=True),
                           chairman=(CHAIRMAN_NAME, CHAIRMAN_TITLE),
                           secretary=(SECRETARY_NAME, SECRETARY_TITLE),
                           email_enabled=EMAIL_ENABLED)

@app.route("/registered/<reg_id>/resend", methods=["POST"])
def resend_certificate(reg_id):
    """Public 'email my certificate again' button. It ALWAYS sends to the email saved on the
    record (never one typed by the visitor), so it can't be used to spam other people."""
    rid = re.sub(r"\s+", "", clean(reg_id, 40)).upper()
    back = redirect(url_for("registered_business", reg_id=rid))
    if not EMAIL_ENABLED:
        flash("Email is not available right now. Please download your certificate instead.", "error")
        return back
    if rate_limited("resend", *RESEND_LIMIT):
        flash("Too many requests. Please try again later.", "error")
        return back
    biz = Business.query.filter_by(reg_id=rid, status="Approved").first_or_404()
    if biz.cert_emailed_at and (datetime.utcnow() - biz.cert_emailed_at).total_seconds() < RESEND_COOLDOWN_SECONDS:
        flash("We just emailed your certificate. Please check your inbox (and spam folder) "
              "and wait a couple of minutes before asking again.", "success")
        return back
    queue_certificate_email(biz.id)
    flash("Certificate re-sent to " + biz.email + ".", "success")
    return back

@app.route("/certificate/<reg_id>.pdf")
def business_certificate(reg_id):
    if rate_limited("certificate", *CERT_LIMIT):
        abort(429)
    rid = re.sub(r"\s+", "", clean(reg_id, 40)).upper()
    biz = Business.query.filter_by(reg_id=rid, status="Approved").first_or_404()
    try:
        pdf = build_certificate_pdf(biz, url_for("verify_business", reg_id=biz.reg_id, _external=True))
    except ImportError:
        app.logger.error("reportlab is not installed (add 'reportlab' to requirements.txt)")
        abort(503)
    resp = send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                     download_name=f"OSCCPA-Certificate-{biz.reg_id}.pdf")
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.route("/verify")
@app.route("/verify/<reg_id>")
def verify_business(reg_id=None):
    q = re.sub(r"\s+", "", clean(reg_id or request.args.get("id"), 40)).upper()
    biz = None
    if q:
        if rate_limited("verify", *VERIFY_LIMIT):
            flash("Too many lookups. Please wait a minute and try again.", "error")
            return render_template("verify_business.html", q=q, searched=False, biz=None), 429
        found = Business.query.filter_by(reg_id=q).first()
        # Pending / rejected applications are never shown publicly
        biz = found if found and found.status in ("Approved", "Suspended") else None
    return render_template("verify_business.html", q=q, searched=bool(q), biz=biz)


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
                            contacts=contacts_data, news_posts=news_data,
                            gallery_items=gallery_rows(),
                            businesses=Business.query.order_by(Business.created_at.desc()).all(),
                            email_enabled=EMAIL_ENABLED)

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
# ADMIN: GALLERY UPDATES (photos + video links for the homepage gallery)
# ---------------------------------------------------------------------------
@app.route("/admin/gallery/upload", methods=["POST"])
@login_required
@csrf_protect
def gallery_upload():
    files = [f for f in request.files.getlist("gallery_images")
             if f and f.filename][:GALLERY_MAX_UPLOAD]
    if not files:
        flash("Choose at least one photo.", "error")
        return redirect(url_for("admin_dashboard"))

    saved = []
    try:
        for file_storage in files:
            name = save_gallery_image(file_storage)
            if name:
                saved.append(name)
        for name in reversed(saved):      # so the first chosen photo ends up first on the site
            db.session.add(GalleryItem(kind="photo", filename=name))
        db.session.commit()
    except ValueError as e:
        db.session.rollback()
        for name in saved:
            remove_gallery_image(name)
        flash(str(e), "error")
        return redirect(url_for("admin_dashboard"))
    except Exception:
        db.session.rollback()
        for name in saved:
            remove_gallery_image(name)
        flash("Could not save the gallery photos. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))

    flash(f"{len(saved)} photo(s) added to the gallery.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/gallery/video", methods=["POST"])
@login_required
@csrf_protect
def gallery_add_video():
    url = clean(request.form.get("video_url"), 500)
    caption = clean(request.form.get("caption"), 150)
    if not url:
        flash("Paste a video link first.", "error")
        return redirect(url_for("admin_dashboard"))
    if not parse_video_url(url):
        flash(VIDEO_LINK_ERROR, "error")
        return redirect(url_for("admin_dashboard"))
    try:
        db.session.add(GalleryItem(kind="video", video_url=url, caption=caption or None))
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash("Could not save the video link. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))
    flash("Video added to the gallery.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/gallery/delete/<int:item_id>", methods=["POST"])
@login_required
@csrf_protect
def gallery_delete(item_id):
    item = GalleryItem.query.get_or_404(item_id)
    name = item.filename if item.kind == "photo" else None
    db.session.delete(item)
    db.session.commit()
    remove_gallery_image(name)            # only after the row is gone
    flash("Gallery item deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------------------------------------------------------------------
# ADMIN: BUSINESS REGISTRY (review applications, issue / suspend IDs)
# ---------------------------------------------------------------------------
@app.route("/admin/businesses/status/<int:biz_id>", methods=["POST"])
@login_required
@csrf_protect
def business_set_status(biz_id):
    biz = Business.query.get_or_404(biz_id)
    new_status = request.form.get("status")
    if new_status not in BUSINESS_STATUSES:
        flash("Invalid status.", "error")
        return redirect(url_for("admin_dashboard"))
    first_issue = False
    try:
        if new_status == "Approved" and not biz.reg_id:      # the ID is issued once and never changes
            biz.reg_id = new_business_id()
            biz.issued_at = datetime.utcnow()
            first_issue = True
        biz.status = new_status
        db.session.commit()
    except Exception:
        db.session.rollback()
        flash("Could not update the business. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))
    if new_status == "Approved":
        flash(f"{biz.business_name} approved. Registration ID: {biz.reg_id}", "success")
        # An ID was just issued by an admin: email the certificate to the owner too
        if first_issue and EMAIL_ENABLED:
            queue_certificate_email(biz.id)
    else:
        flash(f"{biz.business_name} marked {new_status}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/businesses/resend/<int:biz_id>", methods=["POST"])
@login_required
@csrf_protect
def business_resend_cert(biz_id):
    """Admin: (re)send the certificate email to the business."""
    biz = Business.query.get_or_404(biz_id)
    if not EMAIL_ENABLED:
        flash("Email is not configured. Set BREVO_API_KEY and MAIL_SENDER_EMAIL.", "error")
    elif biz.status != "Approved" or not biz.reg_id:
        flash("Only approved businesses have a certificate to send.", "error")
    elif not biz.email:
        flash("This business has no email address on record.", "error")
    else:
        queue_certificate_email(biz.id)
        flash(f"Certificate is being sent to {biz.email}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/businesses/cac/<int:biz_id>", methods=["POST"])
@login_required
@csrf_protect
def business_set_cac(biz_id):
    """Admin ticks (or un-ticks) 'CAC verified' after checking the number on search.cac.gov.ng."""
    biz = Business.query.get_or_404(biz_id)
    verified = request.form.get("verified") == "1"
    biz.cac_verified = verified
    biz.cac_verified_at = datetime.utcnow() if verified else None
    biz.cac_verified_by = session.get("admin_user") if verified else None
    db.session.commit()
    flash(f"{biz.business_name}: CAC number marked " + ("verified." if verified else "not verified."), "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/businesses/delete/<int:biz_id>", methods=["POST"])
@login_required
@csrf_protect
def business_delete(biz_id):
    biz = Business.query.get_or_404(biz_id)
    db.session.delete(biz)
    db.session.commit()
    flash("Business record deleted.", "success")
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
    df_businesses = pd.read_sql(db.select(Business), db.engine)

    for df in (df_complaints, df_contacts, df_businesses):
        for col in df.select_dtypes(include="object").columns:
            df[col] = df[col].map(_excel_safe)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_complaints.to_excel(writer, index=False, sheet_name='Complaints')
        df_contacts.to_excel(writer, index=False, sheet_name='Contacts')
        df_businesses.to_excel(writer, index=False, sheet_name='Businesses')
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
        f"{base_url}/register-business",
        f"{base_url}/verify",
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