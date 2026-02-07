import os
import random
import threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
from dotenv import load_dotenv
from markupsafe import escape

# ================= CONFIG =================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# 🐝 HONEYTOKEN EMAIL (DECOY)
HONEYTOKEN_EMAIL = os.getenv(
    "HONEYTOKEN_EMAIL",
    "admin-trap@royalchallengers.com"
)

# ================= DATABASE =================
# Using Atlas connection with srv support
client = MongoClient(os.getenv("MONGO_URI"))
db = client["royal_challengers_db"]

users_col = db["users"]
logs_col = db["security_logs"]
blacklist_col = db["blacklist"]
reports_col = db["user_reports"]

# ================= MAIL =================
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("ADMIN_EMAIL"),
    MAIL_PASSWORD=os.getenv("EMAIL_PASS")
)
mail = Mail(app)

# ================= TWILIO =================
twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))

# ================= ALERTING & LOGGING =================
def trigger_voice_alert(event):
    try:
        twilio_client.calls.create(
            twiml=f"""
<Response>
    <Say voice="alice" language="en-IN">
        Security Alert. {event}.
    </Say>
</Response>
""",
            to=os.getenv("MY_PHONE"),
            from_=os.getenv("TWILIO_PHONE")
        )
    except Exception as e:
        print("⚠️ Twilio alert failed:", e)

def log_incident(event, severity, email="Anonymous"):
    # Get Real IP for logging
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_addr and ',' in ip_addr:
        ip_addr = ip_addr.split(',')[0].strip()

    try:
        logs_col.insert_one({
            "timestamp": datetime.utcnow(),
            "event": event,
            "severity": severity,
            "email": email,
            "ip": ip_addr,
            "user_agent": request.headers.get("User-Agent")
        })
    except Exception as e:
        print("⚠️ Logging failed:", e)

    if severity == "High":
        threading.Thread(
            target=trigger_voice_alert,
            args=(event,),
            daemon=True
        ).start()

# ================= SECURITY MIDDLEWARE =================
@app.before_request
def block_blacklisted_ips():
    # Handle Proxy IPs on Render
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_addr and ',' in ip_addr:
        ip_addr = ip_addr.split(',')[0].strip()

    if blacklist_col.find_one({"ip": ip_addr}):
        abort(403) # Standard 403 Forbidden

@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ================= ROUTES =================

@app.route("/")
def home():
    return render_template("home.html")

# New routes added to fix 404 errors
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

# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = escape(request.form.get("name"))
        email = escape(request.form.get("email"))
        password = request.form.get("password")
        role = request.form.get("role")

        if not all([name, email, password, role]):
            flash("All fields required")
            return redirect(url_for("register"))

        if users_col.find_one({"email": email}):
            flash("Email already registered")
            return redirect(url_for("register"))

        user_data = {
            "name": name,
            "email": email,
            "password": generate_password_hash(password),
            "role": role,
            "status": "Unverified",
            "failed_attempts": 0,
            "created_at": datetime.utcnow()
        }

        otp = str(random.randint(100000, 999999))
        session["otp"] = otp
        session["temp_user"] = user_data

        try:
            msg = Message(
                "Royal Challengers Email Verification",
                sender=os.getenv("ADMIN_EMAIL"),
                recipients=[email]
            )
            msg.body = f"Your OTP is {otp}"
            mail.send(msg)
        except Exception as e:
            print("⚠️ Mail failed:", e)
            flash("OTP service unavailable")
            return redirect(url_for("register"))

        log_incident("OTP SENT (Registration)", "Low", email)
        return render_template("verify_otp.html")

    return render_template("register.html")

# ---------- OTP VERIFY ----------
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    if request.form.get("otp") != session.get("otp"):
        flash("Invalid OTP")
        return render_template("verify_otp.html")

    user = session.get("temp_user")
    user["status"] = "Active" if user["role"] == "Employee" else "Pending"

    users_col.insert_one(user)
    log_incident(f"OTP VERIFIED ({user['role']})", "Medium", user["email"])

    session.pop("otp", None)
    session.pop("temp_user", None)
    flash("Email verified successfully.")
    return redirect(url_for("login"))

# ---------- LOGIN (WITH HONEYTOKEN TRAP) ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # 🐝 HONEYTOKEN EMAIL TRAP
        if email == HONEYTOKEN_EMAIL:
            ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip_addr and ',' in ip_addr:
                ip_addr = ip_addr.split(',')[0].strip()

            blacklist_col.insert_one({
                "ip": ip_addr,
                "reason": "Honeytoken email used",
                "timestamp": datetime.utcnow()
            })
            log_incident("HONEYTOKEN EMAIL HIT", "High", email)
            return "Unauthorized", 401

        user = users_col.find_one({"email": email})
        if not user or user["status"] == "Locked":
            flash("Invalid credentials or account locked")
            return redirect(url_for("login"))

        if check_password_hash(user["password"], password):
            users_col.update_one({"email": email}, {"$set": {"failed_attempts": 0}})
            session["email"] = user["email"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        attempts = user.get("failed_attempts", 0) + 1
        users_col.update_one(
            {"email": email}, 
            {"$set": {"failed_attempts": attempts, "status": "Locked" if attempts >= 3 else user["status"]}}
        )
        if attempts >= 3:
            log_incident("BRUTE FORCE DETECTED", "High", email)
        flash("Invalid credentials")

    return render_template("login.html")

# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect(url_for("login"))

    logs, reports = [], []
    if session["role"] in ["Admin", "Security Analyst"]:
        logs = list(logs_col.find().sort("timestamp", -1))
        reports = list(reports_col.find().sort("timestamp", -1))

    return render_template("dashboard.html", logs=logs, user_reports=reports)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ================= RUN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)