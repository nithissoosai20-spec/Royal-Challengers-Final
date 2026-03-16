import os
import random
import threading
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
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

# Flask-Mail Config
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("ADMIN_EMAIL")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")

# ================= DATABASE =================
try:
    client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=5000)
    db = client["royal_challengers_db"]
    users_col = db["users"]
    temp_users_col = db["temp_users"]
    logs_col = db["security_logs"]
    reports_col = db["user_reports"]
    authorized_ips_col = db["authorized_ips"]
except Exception as e:
    print(f"❌ DB Connection Error: {e}")

# ================= TOOLS =================
mail = Mail(app)
try:
    twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))
except:
    twilio_client = None

# ================= CORE SOC LOGIC =================

def get_client_ip():
    """Extracts real user IP from Render/Proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def log_incident(event, severity, email="Anonymous", category="general"):
    """Saves security events to MongoDB security_logs collection."""
    try:
        ip_addr = get_client_ip()
        log_doc = {
            "timestamp": datetime.now(timezone.utc),
            "event": event.upper(),
            "severity": severity,
            "category": category,
            "email": email,
            "ip": ip_addr
        }
        logs_col.insert_one(log_doc)
        print(f"✅ LOG SAVED: {event} | {severity}")
        
        if severity == "High" and twilio_client:
            threading.Thread(target=trigger_voice_alert, args=(event,), daemon=True).start()
    except Exception as e:
        print(f"❌ Logging Failed: {e}")

def trigger_voice_alert(event):
    try:
        twilio_client.calls.create(
            twiml=f'<Response><Say voice="alice">Alert: {event} detected.</Say></Response>',
            to=os.getenv("MY_PHONE"), from_=os.getenv("TWILIO_PHONE")
        )
    except: pass

# ================= GLOBAL MONITORING =================

@app.before_request
def auto_log_visit():
    """Automatically logs every page visit to show activity in logs."""
    # Skip logging for static files (CSS/Images) and the dashboard itself to avoid loops
    if not request.path.startswith('/static') and request.endpoint != 'dashboard':
        user = session.get("email", "Anonymous")
        log_incident(f"VISIT: {request.path}", "Low", user, "traffic")

# ================= NAVIGATION =================

@app.route("/")
def home(): return render_template("home.html")

@app.route("/about")
def about(): return render_template("about.html")

@app.route("/services")
def services(): return render_template("services.html")

@app.route("/careers")
def careers(): return render_template("careers.html")

@app.route("/contact")
def contact(): return render_template("contact.html")

# ================= INCIDENTS & DASHBOARD =================

@app.route("/report-incident", methods=["GET", "POST"])
def report_incident():
    if "email" not in session: return redirect(url_for("login"))
    if request.method == "POST":
        report_data = {
            "incident_id": f"RC-{random.randint(1000, 9999)}",
            "reporter": session['email'],
            "type": escape(request.form.get("type")),
            "severity": escape(request.form.get("severity")),
            "message": escape(request.form.get("message")),
            "timestamp": datetime.now(timezone.utc)
        }
        reports_col.insert_one(report_data)
        log_incident(f"REPORT FILED: {report_data['type']}", "Medium", session['email'])
        flash("Incident reported successfully.")
        return redirect(url_for("dashboard"))
    return render_template("report_incident.html")

@app.route("/dashboard")
def dashboard():
    if "email" not in session: return redirect(url_for("login"))
    user_reports = list(reports_col.find().sort("timestamp", -1))
    # Fetch last 20 logs for the SOC feed
    logs = list(logs_col.find().sort("timestamp", -1).limit(20))
    return render_template("dashboard.html", user_reports=user_reports, logs=logs)

# ================= AUTHENTICATION =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = escape(request.form.get("email"))
        if users_col.find_one({"email": email}):
            flash("User already exists.")
            return redirect(url_for("register"))
        
        otp = str(random.randint(100000, 999999))
        temp_users_col.update_one({"email": email}, {"$set": {
            "name": escape(request.form.get("name")),
            "password": generate_password_hash(request.form.get("password")),
            "role": escape(request.form.get("role", "Employee")),
            "otp": otp, 
            "createdAt": datetime.now(timezone.utc)
        }}, upsert=True)
        
        try:
            msg = Message("SOC OTP", sender=os.getenv("ADMIN_EMAIL"), recipients=[email])
            msg.body = f"Your OTP: {otp}"
            mail.send(msg)
            session["pending_email"] = email
            return render_template("verify_otp.html")
        except Exception as e:
            flash("Email error. Check configuration.")
    return render_template("register.html")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = session.get("pending_email")
    user_data = temp_users_col.find_one({"email": email})
    if user_data and request.form.get("otp") == user_data["otp"]:
        users_col.insert_one({
            "name": user_data["name"], "email": user_data["email"], 
            "password": user_data["password"], "role": user_data["role"]
        })
        temp_users_col.delete_one({"email": email})
        log_incident("REGISTRATION COMPLETE", "Low", email)
        return redirect(url_for("login"))
    flash("Invalid OTP")
    return render_template("verify_otp.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = users_col.find_one({"email": email})
        ip = get_client_ip()

        if user and check_password_hash(user["password"], password):
            if email == os.getenv("ADMIN_EMAIL"):
                auth = authorized_ips_col.find_one({"email": email, "ip": ip})
                if not auth:
                    log_incident("UNAUTHORIZED ADMIN IP", "High", email)
                    flash("Access denied: IP not whitelisted.")
                    return redirect(url_for("login"))

            session["email"] = email
            session["role"] = user.get("role", "Employee")
            log_incident("LOGIN SUCCESS", "Low", email)
            return redirect(url_for("dashboard"))
            
        log_incident("LOGIN FAILED", "Medium", email)
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/admin/accept-ip")
def accept_current_ip():
    if session.get("email") == os.getenv("ADMIN_EMAIL"):
        ip = get_client_ip()
        authorized_ips_col.update_one({"email": session["email"], "ip": ip}, {"$set": {"status": "Accepted"}}, upsert=True)
        flash(f"IP {ip} authorized.")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    log_incident("LOGOUT", "Low", session.get("email", "Unknown"))
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))