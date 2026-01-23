import os
import sqlite3
from functools import wraps
import io
import pandas as pd
from database import get_db_connection
from flask import Flask, render_template, request, redirect, send_file, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_mail import Mail, Message  # Not needed if emails are not sent

app = Flask(__name__)
app.secret_key = "super-secret-key"

# Put the upload folder inside static so it's web-accessible
UPLOAD_FOLDER = os.path.join('static', 'uploads')

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# -----------------------------
# Mail setup (Optional)
# -----------------------------
# app.config['MAIL_SERVER'] = 'smtp.example.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USERNAME'] = 'your_email@example.com'
# app.config['MAIL_PASSWORD'] = 'your_email_password'
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
# mail = Mail(app)

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

        conn = get_db_connection()
        admin = conn.execute(
            "SELECT * FROM admins WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if admin and check_password_hash(admin["password"], password):
            session["admin_id"] = admin["id"]
            session["admin_user"] = admin["username"]
            return redirect(url_for("admin_dashboard"))

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
        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirm_password")

        conn = get_db_connection()
        admin = conn.execute(
            "SELECT * FROM admins WHERE id = ?",
            (session["admin_id"],)
        ).fetchone()

        if not check_password_hash(admin["password"], current):
            flash("Current password is incorrect")
            conn.close()
            return redirect(url_for("change_password"))

        if new != confirm:
            flash("New passwords do not match")
            conn.close()
            return redirect(url_for("change_password"))

        conn.execute(
            "UPDATE admins SET password = ? WHERE id = ?",
            (generate_password_hash(new), session["admin_id"])
        )
        conn.commit()
        conn.close()

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
# Contact form (stores messages in contacts table)
# -----------------------------
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone') or 'N/A'
        subject = request.form.get('subject')
        message = request.form.get('message')

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO contacts (name, email, phone, subject, message)
            VALUES (?, ?, ?, ?, ?)
        """, (name, email, phone, subject, message))
        conn.commit()
        conn.close()

        flash("Your message has been submitted successfully!")
        return redirect(url_for('contact'))

    return render_template('contact.html')

# -----------------------------
# Complaints form
# -----------------------------
@app.route("/complaints", methods=["GET", "POST"])
def complaints():
    if request.method == "POST":
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        phone = request.form.get("phone") or "N/A"
        lga = request.form.get("lga")
        business_name = request.form.get("business_name")
        complaint_type = request.form.get("complaint_type")
        complaint_details = request.form.get("complaint_details")

        evidence = request.files.get("evidence")
        evidence_filename = None
        if evidence and evidence.filename:
            evidence_filename = evidence.filename
            evidence.save(os.path.join(app.config['UPLOAD_FOLDER'], evidence_filename))

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO complaints
            (full_name, email, phone, lga, business_name,
             complaint_type, complaint_details, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            full_name, email, phone, lga, business_name,
            complaint_type, complaint_details, evidence_filename
        ))
        conn.commit()
        conn.close()

        flash("Complaint submitted successfully", "success")
        return redirect(url_for("complaints"))

    return render_template("complaints.html")

# -----------------------------
# Admin dashboard (complaints + contacts)
# -----------------------------
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    conn = get_db_connection()
    complaints = conn.execute("SELECT * FROM complaints ORDER BY created_at DESC").fetchall()
    contacts = conn.execute("SELECT * FROM contacts ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("admin_dashboard.html", complaints=complaints, contacts=contacts)

# -----------------------------
# Update complaint status
# -----------------------------
@app.route("/admin/complaints/status/<int:id>", methods=["POST"])
@login_required
def update_complaint_status(id):
    new_status = request.form.get("status")
    if new_status not in ("Pending", "In Progress", "Resolved"):
        flash("Invalid status")
        return redirect(url_for("admin_dashboard"))

    conn = get_db_connection()
    conn.execute(
        "UPDATE complaints SET status = ? WHERE id = ?",
        (new_status, id)
    )
    conn.commit()
    conn.close()

    flash("Complaint status updated successfully")
    return redirect(url_for("admin_dashboard"))

# -----------------------------
# Delete complaint
# -----------------------------
@app.route("/admin/complaints/delete/<int:complaint_id>", methods=["POST"])
@login_required
def delete_complaint(complaint_id):
    conn = get_db_connection()
    complaint = conn.execute(
        "SELECT * FROM complaints WHERE id = ?", (complaint_id,)
    ).fetchone()

    if not complaint:
        conn.close()
        flash("Complaint not found")
        return redirect(url_for("admin_dashboard"))

    # Delete evidence file if exists
    if complaint["evidence"]:
        file_path = os.path.join(app.root_path, "uploads", complaint["evidence"])
        if os.path.exists(file_path):
            os.remove(file_path)

    conn.execute("DELETE FROM complaints WHERE id = ?", (complaint_id,))
    conn.commit()
    conn.close()

    flash("Complaint deleted successfully")
    return redirect(url_for("admin_dashboard"))

# -----------------------------
# Delete complaint
@app.route("/admin/contacts/delete/<int:contact_id>", methods=["POST"])
@login_required
def delete_contact(contact_id):
    # Connect to the complaints database
    conn = sqlite3.connect("complaints.db")
    conn.row_factory = sqlite3.Row

    # Fetch contact
    contact = conn.execute(
        "SELECT * FROM contacts WHERE id = ?", (contact_id,)
    ).fetchone()

    if not contact:
        conn.close()
        flash("Contact not found")
        return redirect(url_for("admin_dashboard"))

    # Delete from contacts table
    conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
    conn.commit()
    conn.close()

    flash("Contact deleted successfully")
    return redirect(url_for("admin_dashboard"))


@app.route('/export_excel')
def export_all_data():
    conn = get_db_connection()
    
    # 1. Fetch both datasets into DataFrames
    df_complaints = pd.read_sql_query("SELECT * FROM complaints", conn)
    df_contacts = pd.read_sql_query("SELECT * FROM contacts", conn)
    conn.close()

    # 2. Setup the memory buffer
    output = io.BytesIO()
    
    # 3. Use ExcelWriter to save to multiple sheets
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_complaints.to_excel(writer, index=False, sheet_name='Complaints')
        df_contacts.to_excel(writer, index=False, sheet_name='Contacts')
    
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='full_backup.xlsx'
    )

# -----------------------------
# Run app
# -----------------------------
if __name__ == '__main__':
    # Only used for local development
    app.run()