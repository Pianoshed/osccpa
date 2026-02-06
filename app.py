import os
import io
import pandas as pd
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, send_file, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super-secret-key"

# --- Database Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'complaints.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -----------------------------
# Database Models (Required for Migrate)
# -----------------------------
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

# -----------------------------
# Login decorator
# -----------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

# -----------------------------
# Admin login/logout/change password
# -----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # FIXED: Using SQLAlchemy query instead of raw sqlite3
        admin = Admin.query.filter_by(username=username).first()

        if admin and check_password_hash(admin.password, password):
            session["admin_id"] = admin.id
            session["admin_user"] = admin.username
            return redirect(url_for("admin_dashboard"))

        flash("Invalid username or password")
    return render_template("admin_login.html")

@app.before_request
def redirect_to_www():
    if request.host == "occpa.on.gov.ng" :
        return redirect("https://www.occpa.on.gov.ng" + request.full_path, code=301)

@app.route("/admin/logout")
@login_required
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirm_password")

        admin = Admin.query.get(session["admin_id"])

        if not check_password_hash(admin.password, current):
            flash("Current password is incorrect")
            return redirect(url_for("change_password"))

        if new != confirm:
            flash("New passwords do not match")
            return redirect(url_for("change_password"))

        admin.password = generate_password_hash(new)
        db.session.commit()

        flash("Password changed successfully")
        return redirect(url_for("admin_dashboard"))

    return render_template("change_password.html")

# -----------------------------
# Public routes
# -----------------------------
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

# -----------------------------
# Forms
# -----------------------------
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        new_contact = Contact(
            name=request.form.get('name'),
            email=request.form.get('email'),
            phone=request.form.get('phone') or 'N/A',
            subject=request.form.get('subject'),
            message=request.form.get('message')
        )
        db.session.add(new_contact)
        db.session.commit()
        flash("Your message has been submitted successfully!")
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route("/complaints", methods=["GET", "POST"])
def complaints():
    if request.method == "POST":
        evidence = request.files.get("evidence")
        evidence_filename = None
        if evidence and evidence.filename:
            evidence_filename = evidence.filename
            evidence.save(os.path.join(app.config['UPLOAD_FOLDER'], evidence_filename))

        new_comp = Complaint(
            full_name=request.form.get("full_name"),
            email=request.form.get("email"),
            phone=request.form.get("phone") or "N/A",
            lga=request.form.get("lga"),
            business_name=request.form.get("business_name"),
            complaint_type=request.form.get("complaint_type"),
            complaint_details=request.form.get("complaint_details"),
            evidence=evidence_filename
        )
        db.session.add(new_comp)
        db.session.commit()

        flash("Complaint submitted successfully", "success")
        return redirect(url_for("complaints"))
    return render_template("complaints.html")

# -----------------------------
# Admin dashboard
# -----------------------------
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    complaints_data = Complaint.query.order_by(Complaint.created_at.desc()).all()
    contacts_data = Contact.query.order_by(Contact.created_at.desc()).all()
    return render_template("admin_dashboard.html", complaints=complaints_data, contacts=contacts_data)

@app.route("/admin/complaints/status/<int:id>", methods=["POST"])
@login_required
def update_complaint_status(id):
    complaint = Complaint.query.get_or_404(id)
    new_status = request.form.get("status")
    if new_status in ("Pending", "In Progress", "Resolved"):
        complaint.status = new_status
        db.session.commit()
        flash("Complaint status updated successfully")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/complaints/delete/<int:complaint_id>", methods=["POST"])
@login_required
def delete_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    if complaint.evidence:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], complaint.evidence)
        if os.path.exists(file_path):
            os.remove(file_path)

    db.session.delete(complaint)
    db.session.commit()
    flash("Complaint deleted successfully")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/contacts/delete/<int:contact_id>", methods=["POST"])
@login_required
def delete_contact(contact_id):
    contact_obj = Contact.query.get_or_404(contact_id)
    db.session.delete(contact_obj)
    db.session.commit()
    flash("Contact deleted successfully")
    return redirect(url_for("admin_dashboard"))

@app.route('/export_excel')
def export_excel():
    # Pandas works with SQLAlchemy engines
    df_complaints = pd.read_sql(db.select(Complaint), db.engine)
    df_contacts = pd.read_sql(db.select(Contact), db.engine)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_complaints.to_excel(writer, index=False, sheet_name='Complaints')
        df_contacts.to_excel(writer, index=False, sheet_name='Contacts')
    output.seek(0)

    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name='full_backup.xlsx')

if __name__ == '__main__':
    app.run()