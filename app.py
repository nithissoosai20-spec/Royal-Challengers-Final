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

# ================= DATABASE =================
client = MongoClient(os.getenv("MONGO_URI"))
db = client["royal_challengers_db"]
users_col = db["users"]
temp_users_col = db["temp_users"] 
logs_col = db["security_logs"]
blacklist_col = db["blacklist"]
authorized_ips_col = db["authorized_ips"] # Trusted Admin IPs

# ================= TOOLS =================
mail = Mail(app)
twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))

# ================= CORE SOC LOGIC =================

def trigger_voice_alert(event):
    """Voice alert for High severity incidents."""
    try:
        twilio_client.calls.create(
            twiml=f'<Response><Say voice="alice">Security Alert: {event} detected on the portal.</Say></Response>',
            to=os.getenv("MY_PHONE"),
            from_=os.getenv("TWILIO_PHONE")
        )
    except Exception as e:
        app.logger.error(f"Twilio Voice Alert Failed: {e}")

def log_incident(event, severity, email="Anonymous", category="general"):
    """Global logging with automated alerting."""
    ip_addr = "N/A"
    try:
        if request:
            ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    except Exception: pass

    log_doc = {
        "timestamp": datetime.utcnow(),
        "event": event.upper(),
        "severity": severity,
        "category": category,
        "email": email,
        "ip": ip_addr,
        "path": request.path if request else "N/A"
    }
    logs_col.insert_one(log_doc)
    
    if severity == "High":
        threading.Thread(target=trigger_voice_alert, args=(event,), daemon=True).start()

# ================= GLOBAL MONITORING (PROACTIVE) =================

@app.before_request
def security_monitor():
    if request.path.startswith("/static"): return
    
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    
    # 1. Immediate Blacklist Block
    if blacklist_col.find_one({"ip": ip_addr}):
        abort(403)
    
    # 2. Proactive Reconnaissance Detection
    hacker_paths = ["/.env", "/wp-admin", "/config.php", "/admin-hidden"]
    if any(path in request.path for path in hacker_paths):
        log_incident("SUSPICIOUS RECONNAISSANCE", "Medium", "Potential-Attacker", "security")
        return "Resource Not Found", 404

    # 3. Log Every Visit
    log_incident(f"VISIT: {request.path}", "Low", session.get("email", "Guest"), "traffic")

# ================= ROUTES =================

@app.route("/")
def home(): return render_template("home.html")

@app.route("/about")
def about(): return render_template("about.html")

@app.route("/services")
def services(): return render_template("services.html")

@app.route("/contact")
def contact(): return render_template("contact.html")

@app.route("/careers")
def careers(): return render_template("careers.html")

# ================= AUTHENTICATION (SMART ACCEPTANCE) =================

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    
    if request.method == "POST":
        email = request.form.get("email")
        user = users_col.find_one({"email": email})

        if user and check_password_hash(user["password"], request.form.get("password")):
            
            # --- THE "ACCEPT IP" LOGIC ---
            # Define who needs IP Acceptance (e.g., the Admin)
            if email == os.getenv("ADMIN_EMAIL"):
                is_authorized = authorized_ips_col.find_one({"email": email, "ip": ip})
               # if not is_authorized:
                    log_incident("UNAUTHORIZED ADMIN ATTEMPT", "High", email, "security")
                    flash("Blocked: This IP is not 'Accepted' for Admin access. Approval required.")
                    return redirect(url_for("login"))

            # Standard User or Authorized Admin
            session["email"] = email
            log_incident("LOGIN SUCCESS", "Low", email, "auth")
            return redirect(url_for("dashboard"))
        
        else:
            log_incident("LOGIN FAILED", "Medium", email, "auth")
            flash("Invalid email or password.")

    return render_template("login.html")

# ================= DASHBOARD & ADMIN ACTIONS =================

@app.route("/dashboard")
def dashboard():
    if "email" not in session: return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/admin/accept-ip")
def accept_current_ip():
    """Route to manually whitelist the current IP (Use this to get yourself in!)"""
    if "email" not in session or session["email"] != os.getenv("ADMIN_EMAIL"):
        abort(403)
        
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    authorized_ips_col.update_one(
        {"email": session["email"], "ip": ip},
        {"$set": {"status": "Accepted", "date": datetime.utcnow()}},
        upsert=True
    )
    flash(f"IP {ip} has been Accepted successfully.")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    log_incident("LOGOUT", "Low", session.get("email"))
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))