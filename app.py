import os
import random
import threading
import logging
import sys
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, jsonify
)
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
from dotenv import load_dotenv
from markupsafe import escape

# ================= ENV & APP =================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)],
    format="%(asctime)s | %(levelname)s | %(message)s"
)
app.logger.info("🚀 SOC Portal Engine Initializing...")

# ================= MITRE ATT&CK MAP =================
MITRE_MAP = {
    "LOGIN FAILED": {"tactic": "Credential Access", "technique": "Password Guessing", "id": "T1110.001"},
    "BRUTE FORCE DETECTED": {"tactic": "Credential Access", "technique": "Brute Force", "id": "T1110"},
    "HONEYTOKEN HIT": {"tactic": "Credential Access", "technique": "Valid Accounts", "id": "T1078"},
    "BLACKLISTED ACCESS": {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "id": "T1190"}
}

# ================= DATABASE =================
client = MongoClient(os.getenv("MONGO_URI"))
db = client["royal_challengers_db"]
users_col = db["users"]
temp_users_col = db["temp_users"] # NEW: For TTL storage
logs_col = db["security_logs"]
blacklist_col = db["blacklist"]

# ================= TOOLS =================
mail = Mail(app)
twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))

# ================= SOC UTILITIES =================

def trigger_voice_alert(event):
    """Triggers an automated phone call for High severity incidents."""
    try:
        twilio_client.calls.create(
            twiml=f'<Response><Say voice="alice">Security Alert: {event} detected.</Say></Response>',
            to=os.getenv("MY_PHONE"),
            from_=os.getenv("TWILIO_PHONE")
        )
    except Exception as e:
        app.logger.error(f"Twilio failed: {e}")

def log_incident(event, severity, email="Anonymous", category="security"):
    """Core logging logic with automated alerting."""
    # Get request metadata safely
    ip_addr = "N/A"
    path = "N/A"
    method = "N/A"
    ua = "N/A"
    
    if request:
        ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        path = request.path
        method = request.method
        ua = request.headers.get("User-Agent")

    log_doc = {
        "timestamp": datetime.utcnow(),
        "event": event,
        "severity": severity,
        "category": category,
        "email": email,
        "ip": ip_addr,
        "path": path,
        "method": method,
        "user_agent": ua,
        "mitre": MITRE_MAP.get(event, {})
    }
    logs_col.insert_one(log_doc)
    app.logger.info(f"📝 {severity} | {event} | {email}")

    if severity == "High":
        threading.Thread(target=trigger_voice_alert, args=(event,), daemon=True).start()

def is_brute_forcing(ip):
    """Checks if an IP has > 5 failed logins in the last 10 minutes."""
    ten_mins_ago = datetime.utcnow() - timedelta(minutes=10)
    failed_count = logs_col.count_documents({
        "ip": ip,
        "event": "LOGIN FAILED",
        "timestamp": {"$gte": ten_mins_ago}
    })
    return failed_count >= 5

# ================= ROUTES =================

@app.route("/")
def home(): return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = escape(request.form.get("email"))
        if users_col.find_one({"email": email}):
            flash("User already exists.")
            return redirect(url_for("register"))
        
        otp = str(random.randint(100000, 999999))
        # Store in temp_users instead of session for security
        temp_users_col.update_one(
            {"email": email},
            {"$set": {
                "name": escape(request.form.get("name")),
                "password": generate_password_hash(request.form.get("password")),
                "otp": otp,
                "createdAt": datetime.utcnow()
            }},
            upsert=True
        )
        
        msg = Message("SOC Portal OTP", sender=os.getenv("ADMIN_EMAIL"), recipients=[email])
        msg.body = f"Your verification code is: {otp}"
        mail.send(msg)
        
        session["pending_email"] = email
        log_incident("OTP SENT", "Low", email)
        return render_template("verify_otp.html")
    
    return render_template("register.html")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = session.get("pending_email")
    user_data = temp_users_col.find_one({"email": email})
    
    if not user_data or request.form.get("otp") != user_data["otp"]:
        log_incident("OTP FAILED", "Medium", email)
        flash("Invalid or expired OTP")
        return render_template("verify_otp.html")

    # Move to permanent storage
    users_col.insert_one({
        "name": user_data["name"],
        "email": user_data["email"],
        "password": user_data["password"]
    })
    temp_users_col.delete_one({"email": email})
    session.pop("pending_email", None)
    log_incident("OTP VERIFIED", "Low", email)
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    
    if request.method == "POST":
        if is_brute_forcing(ip):
            log_incident("BRUTE FORCE DETECTED", "High", request.form.get("email"))
            flash("Too many failed attempts. Try again later.")
            return redirect(url_for("login"))

        email = request.form.get("email")
        user = users_col.find_one({"email": email})

        if user and check_password_hash(user["password"], request.form.get("password")):
            session["email"] = email
            log_incident("LOGIN SUCCESS", "Low", email)
            return redirect(url_for("dashboard"))
        else:
            log_incident("LOGIN FAILED", "Medium", email)
            flash("Invalid credentials")
            
    return render_template("login.html")

# ================= DASHBOARD DATA API =================

@app.route("/dashboard-data")
def dashboard_data():
    """Returns JSON for Chart.js visualization."""
    if "email" not in session: abort(401)
    
    # Aggregation for Severity Pie Chart
    pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    severity_stats = list(logs_col.aggregate(pipeline))
    
    # Aggregation for Top Events
    event_pipeline = [{"$group": {"_id": "$event", "count": {"$sum": 1}}}, {"$limit": 5}]
    event_stats = list(logs_col.aggregate(event_pipeline))

    return jsonify({
        "severity": {s["_id"]: s["count"] for s in severity_stats},
        "events": {e["_id"]: e["count"] for e in event_stats}
    })

@app.route("/dashboard")
def dashboard():
    if "email" not in session: return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    log_incident("LOGOUT", "Low", session.get("email"))
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))