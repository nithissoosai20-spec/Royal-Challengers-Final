import os
import random
import threading
import requests
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from markupsafe import escape

# ================= INITIALIZE =================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# ================= EMAIL VIA BREVO HTTP API =================
def send_email(to_email, subject, body):
    def _send():
        try:
            response = requests.post(
                "https://api.brevo.com/v3/smtp/email",
                headers={
                    "api-key": os.getenv("BREVO_SMTP_KEY"),
                    "Content-Type": "application/json"
                },
                json={
                    "sender": {"name": "Royal Challengers", "email": os.getenv("ADMIN_EMAIL")},
                    "to": [{"email": to_email}],
                    "subject": subject,
                    "textContent": body
                }
            )
            print("✅ MAIL SENT:", response.status_code, response.text)
        except Exception as e:
            print("❌ MAIL ERROR:", e)
    threading.Thread(target=_send).start()

# ================= DB HELPER =================
def get_db_collections():
    try:
        uri = os.getenv("MONGO_URI")
        if not uri:
            print("❌ ERROR: MONGO_URI missing!")
            return None
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        db = client["royal_challengers_db"]
        client.admin.command('ping')
        return {
            "users": db["users"],
            "temp": db["temp_users"],
            "pending": db["pending_users"],
            "logs": db["security_logs"],
            "reports": db["user_reports"],
            "ips": db["authorized_ips"]
        }
    except Exception as e:
        print(f"❌ DB ERROR: {e}")
        return None

# ================= LOGGING =================
def log_event(event, severity="Low", email="Anonymous"):
    cols = get_db_collections()
    if not cols:
        return
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        cols["logs"].insert_one({
            "timestamp": datetime.now(timezone.utc),
            "event": event.upper(),
            "severity": severity,
            "email": email,
            "ip": ip
        })
    except:
        pass


# ================= ROUTES =================

@app.before_request
def monitor():
    if not request.path.startswith('/static') and request.endpoint != 'dashboard':
        log_event(f"Visited {request.path}", "Low", session.get("email", "Anonymous"))

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect(url_for("login"))

    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500

    reports = list(cols["reports"].find().sort("timestamp", -1))
    logs = list(cols["logs"].find().sort("timestamp", -1).limit(20))

    role = session.get("role")
    if role == "Super Admin":
        pending = list(cols["pending"].find().sort("createdAt", -1))
    elif role == "Admin":
        pending = list(cols["pending"].find({"role": "Security Analyst"}).sort("createdAt", -1))
    else:
        pending = []

    # Convert for JSON serialization + IST timezone
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    for doc in logs + reports + pending:
        doc["_id"] = str(doc["_id"])
        if "timestamp" in doc and hasattr(doc["timestamp"], "strftime"):
            doc["timestamp"] = doc["timestamp"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")
        if "createdAt" in doc and hasattr(doc["createdAt"], "strftime"):
            doc["createdAt"] = doc["createdAt"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")
    return render_template("dashboard.html", user_reports=reports, logs=logs, pending_users=pending)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            cols = get_db_collections()
            if not cols:
                flash("Database error")
                return redirect(url_for("register"))

            email = escape(request.form.get("email"))
            name = escape(request.form.get("name"))
            password = request.form.get("password")
            role = escape(request.form.get("role", "Employee"))

            if not email or not name or not password or not role:
                flash("All fields are required")
                return redirect(url_for("register"))

            otp = str(random.randint(100000, 999999))

            cols["temp"].update_one(
                {"email": email},
                {"$set": {
                    "name": name,
                    "password": generate_password_hash(password),
                    "role": role,
                    "otp": otp,
                    "createdAt": datetime.now(timezone.utc)
                }},
                upsert=True
            )

            send_email(str(email), "Your OTP", f"Your OTP code is: {otp}")
            session["pending_email"] = str(email)
            return render_template("verify_otp.html")

        except Exception as e:
            print("❌ REGISTER ERROR:", e)
            flash("Something went wrong. Try again.")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    cols = get_db_collections()
    if not cols:
        flash("Database error")
        return redirect(url_for("register"))

    email = session.get("pending_email")
    if not email:
        flash("Session expired")
        return redirect(url_for("register"))

    otp = request.form.get("otp")
    temp_user = cols["temp"].find_one({"email": email})

    if not temp_user or temp_user["otp"] != otp:
        flash("Invalid OTP")
        return render_template("verify_otp.html")

    role = temp_user["role"]
    cols["temp"].delete_one({"email": email})
    session.pop("pending_email", None)

    if role in ["Security Analyst", "Admin", "Super Admin"]:
        cols["pending"].insert_one({
            "email": temp_user["email"],
            "name": temp_user["name"],
            "password": temp_user["password"],
            "role": role,
            "createdAt": datetime.now(timezone.utc)
        })
        send_email(
            os.getenv("ADMIN_EMAIL"),
            "New Approval Request",
            f"New {role} registration from {temp_user['email']} is awaiting your approval. Login to dashboard to approve or reject."
        )
        log_event("PENDING_APPROVAL", "Medium", email)
        flash("OTP verified! Your account is pending admin approval. You will be notified once approved.")
        return redirect(url_for("login"))

    cols["users"].insert_one({
        "email": temp_user["email"],
        "name": temp_user["name"],
        "password": temp_user["password"],
        "role": role,
        "createdAt": datetime.now(timezone.utc)
    })
    log_event("REGISTRATION_SUCCESS", "Low", email)
    flash("Registration successful! Please login.")
    return redirect(url_for("login"))

@app.route("/approve_user/<user_email>", methods=["POST"])
def approve_user(user_email):
    if session.get("role") not in ["Super Admin", "Admin"]:
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500
    pending = cols["pending"].find_one({"email": user_email})
    if pending:
        cols["users"].insert_one({
            "email": pending["email"],
            "name": pending["name"],
            "password": pending["password"],
            "role": pending["role"],
            "createdAt": datetime.now(timezone.utc)
        })
        cols["pending"].delete_one({"email": user_email})
        send_email(pending["email"], "Account Approved", f"Your {pending['role']} account has been approved! You can now login.")
        log_event("USER_APPROVED", "Medium", user_email)
        flash(f"{user_email} approved successfully.")
    return redirect(url_for("dashboard"))

@app.route("/reject_user/<user_email>", methods=["POST"])
def reject_user(user_email):
    if session.get("role") not in ["Super Admin", "Admin"]:
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500
    cols["pending"].delete_one({"email": user_email})
    log_event("USER_REJECTED", "Medium", user_email)
    flash(f"{user_email} rejected.")
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        cols = get_db_collections()
        if not cols:
            flash("Database error")
            return redirect(url_for("login"))

        email = request.form.get("email")
        password = request.form.get("password")

        user = cols["users"].find_one({"email": email})

        if user and check_password_hash(user["password"], password):
            session["email"] = email
            session["role"] = user.get("role", "Employee")
            log_event("LOGIN_SUCCESS", "Low", email)
            return redirect(url_for("dashboard"))

        flash("Invalid credentials")

    return render_template("login.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/careers")
def careers():
    return render_template("careers.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/report-incident", methods=["GET", "POST"])
def report_incident():
    if "email" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        cols = get_db_collections()
        if not cols:
            flash("Database error")
            return redirect(url_for("report_incident"))
        import uuid
        cols["reports"].insert_one({
            "incident_id": str(uuid.uuid4())[:8].upper(),
            "reporter": session["email"],
            "type": escape(request.form.get("type")),
            "severity": escape(request.form.get("severity")),
            "message": escape(request.form.get("message")),
            "timestamp": datetime.now(timezone.utc)
        })
        log_event("INCIDENT_REPORTED", request.form.get("severity", "Low"), session["email"])
        flash("Incident reported successfully.")
        return redirect(url_for("dashboard"))
    return render_template("report_incident.html")

@app.route("/honeytoken-access")
def honeytoken():
    log_event("HONEYTOKEN_TRIGGERED", "High", session.get("email", "Anonymous"))
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
