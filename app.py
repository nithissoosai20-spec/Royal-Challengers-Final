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

# ================= ENV & APP CONFIG =================
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)],
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# ================= MITRE ATT&CK MAP =================
MITRE_MAP = {
    "LOGIN FAILED": {"tactic": "Credential Access", "technique": "Password Guessing", "id": "T1110.001"},
    "BRUTE FORCE DETECTED": {"tactic": "Credential Access", "technique": "Brute Force", "id": "T1110"},
    "HONEYTOKEN HIT": {"tactic": "Credential Access", "technique": "Valid Accounts", "id": "T1078"},
    "UNAUTHORIZED ACCESS": {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application", "id": "T1190"}
}

# ================= DATABASE =================
client = MongoClient(os.getenv("MONGO_URI"))
db = client["royal_challengers_db"]
users_col = db["users"]
temp_users_col = db["temp_users"] 
logs_col = db["security_logs"]
blacklist_col = db["blacklist"]

# ================= TOOLS =================
mail = Mail(app)
twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))

# ================= UNIVERSAL LOGGER =================

def log_incident(event, severity, email="Anonymous", category="general"):
    """
    The heartbeat of the SOC. Records everything to MongoDB Atlas.
    """
    ip_addr = "N/A"
    path = "N/A"
    method = "N/A"
    ua = "N/A"
    
    try:
        if request:
            ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
            path = request.path
            method = request.method
            ua = request.headers.get("User-Agent")
    except Exception:
        pass

    log_doc = {
        "timestamp": datetime.utcnow(),
        "event": event.upper(),
        "severity": severity,
        "category": category,
        "email": email,
        "ip": ip_addr,
        "path": path,
        "method": method,
        "user_agent": ua,
        "mitre": MITRE_MAP.get(event.upper(), {})
    }
    
    try:
        logs_col.insert_one(log_doc)
        app.logger.info(f"📊 LOG: [{severity}] {event} | {email}")
    except Exception as e:
        app.logger.error(f"MongoDB Error: {e}")

    if severity == "High":
        threading.Thread(target=trigger_voice_alert, args=(event,), daemon=True).start()

def trigger_voice_alert(event):
    try:
        twilio_client.calls.create(
            twiml=f'<Response><Say voice="alice">Critical Security Event: {event}</Say></Response>',
            to=os.getenv("MY_PHONE"),
            from_=os.getenv("TWILIO_PHONE")
        )
    except Exception as e:
        app.logger.error(f"Twilio failed: {e}")

# ================= GLOBAL INTERCEPTOR (THE AUTO-LOGGER) =================

@app.before_request
def global_monitor():
    """Captures EVERY interaction before it hits the route."""
    if request.path.startswith("/static"):
        return

    # 1. IP Check
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    if blacklist_col.find_one({"ip": ip_addr}):
        log_incident("BLACKLISTED IP ATTEMPT", "High", "Unknown", "security")
        abort(403)

    # 2. Universal Activity Logging
    user = session.get("email", "Guest")
    event_name = f"{request.method} REQUEST: {request.path}"
    
    # Logic: Mark POST requests as slightly higher interest than simple GETs
    severity = "Info" if request.method == "GET" else "Medium"
    log_incident(event_name, severity, user, "traffic")

# ================= ROUTES =================

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

# ================= AUTH LOGIC =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = escape(request.form.get("email"))
        if users_col.find_one({"email": email}):
            log_incident("REGISTRATION REJECTED: DUPLICATE", "Medium", email, "auth")
            flash("User already exists.")
            return redirect(url_for("register"))
        
        otp = str(random.randint(100000, 999999))
        temp_users_col.update_one({"email": email}, {"$set": {
            "name": escape(request.form.get("name")),
            "password": generate_password_hash(request.form.get("password")),
            "otp": otp, "createdAt": datetime.utcnow()
        }}, upsert=True)
        
        msg = Message("SOC OTP", sender=os.getenv("ADMIN_EMAIL"), recipients=[email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        
        session["pending_email"] = email
        log_incident("OTP GENERATED", "Low", email, "auth")
        return render_template("verify_otp.html")
    return render_template("register.html")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = session.get("pending_email")
    user_data = temp_users_col.find_one({"email": email})
    entered_otp = request.form.get("otp")
    
    if not user_data or entered_otp != user_data["otp"]:
        log_incident("OTP VERIFICATION FAILED", "Medium", email, "auth")
        flash("Invalid OTP")
        return render_template("verify_otp.html")

    users_col.insert_one({
        "name": user_data["name"], "email": user_data["email"], "password": user_data["password"]
    })
    temp_users_col.delete_one({"email": email})
    session.pop("pending_email", None)
    log_incident("NEW USER REGISTERED", "Low", email, "auth")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        user = users_col.find_one({"email": email})

        if user and check_password_hash(user["password"], request.form.get("password")):
            session["email"] = email
            log_incident("LOGIN SUCCESSFUL", "Low", email, "auth")
            return redirect(url_for("dashboard"))
        else:
            log_incident("LOGIN FAILED", "Medium", email, "auth")
            flash("Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "email" not in session: 
        log_incident("UNAUTHORIZED DASHBOARD ACCESS", "Medium", "Guest", "security")
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/dashboard-data")
def dashboard_data():
    if "email" not in session: abort(401)
    # Aggregation for the Frontend Charts
    severity_stats = list(logs_col.aggregate([{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]))
    return jsonify({"severity": {s["_id"]: s["count"] for s in severity_stats}})

@app.route("/logout")
def logout():
    user = session.get("email")
    log_incident("USER LOGOUT", "Low", user, "auth")
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))