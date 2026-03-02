import os
import random
import threading
from datetime import datetime

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

# ================= DATABASE =================
client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=5000)
db = client["royal_challengers_db"]
users_col = db["users"]
temp_users_col = db["temp_users"]
logs_col = db["security_logs"]
reports_col = db["user_reports"] # Separate collection for user-submitted reports
blacklist_col = db["blacklist"]
authorized_ips_col = db["authorized_ips"]

# ================= TOOLS =================
mail = Mail(app)
twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))

# ================= CORE SOC LOGIC =================

def log_incident(event, severity, email="Anonymous", category="general"):
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip() if request else "N/A"
    log_doc = {
        "timestamp": datetime.utcnow(),
        "event": event.upper(),
        "severity": severity,
        "category": category,
        "email": email,
        "ip": ip_addr
    }
    logs_col.insert_one(log_doc)
    if severity == "High":
        threading.Thread(target=trigger_voice_alert, args=(event,), daemon=True).start()

def trigger_voice_alert(event):
    try:
        twilio_client.calls.create(
            twiml=f'<Response><Say voice="alice">Security Alert: {event} detected.</Say></Response>',
            to=os.getenv("MY_PHONE"), from_=os.getenv("TWILIO_PHONE")
        )
    except: pass

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

# ================= REPORT INCIDENT (SYNCED) =================

@app.route("/report-incident", methods=["GET", "POST"])
def report_incident():
    if "email" not in session: return redirect(url_for("login"))
    
    if request.method == "POST":
        # Synced with your report_incident.html names
        report_data = {
            "incident_id": f"RC-{random.randint(1000, 9999)}",
            "reporter": session['email'],
            "type": escape(request.form.get("type")),
            "severity": escape(request.form.get("severity")),
            "message": escape(request.form.get("message")),
            "timestamp": datetime.utcnow()
        }
        reports_col.insert_one(report_data)
        log_incident(f"NEW REPORT: {report_data['type']}", "Medium", session['email'])
        flash("Incident reported successfully.")
        return redirect(url_for("dashboard"))
        
    return render_template("report_incident.html")

# ================= AUTHENTICATION =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = escape(request.form.get("email"))
        role = escape(request.form.get("role"))
        
        if users_col.find_one({"email": email}):
            flash("User already exists.")
            return redirect(url_for("register"))
        
        otp = str(random.randint(100000, 999999))
        temp_users_col.update_one({"email": email}, {"$set": {
            "name": escape(request.form.get("name")),
            "password": generate_password_hash(request.form.get("password")),
            "role": role,
            "otp": otp, 
            "createdAt": datetime.utcnow()
        }}, upsert=True)
        
        msg = Message("SOC Portal OTP", sender=os.getenv("ADMIN_EMAIL"), recipients=[email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)
        session["pending_email"] = email
        return render_template("verify_otp.html")
    return render_template("register.html")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    email = session.get("pending_email")
    user_data = temp_users_col.find_one({"email": email})
    if user_data and request.form.get("otp") == user_data["otp"]:
        users_col.insert_one({
            "name": user_data["name"], "email": user_data["email"], 
            "password": user_data["password"], "role": user_data.get("role", "Employee")
        })
        temp_users_col.delete_one({"email": email})
        flash("Registration successful!")
        return redirect(url_for("login"))
    flash("Invalid OTP")
    return render_template("verify_otp.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = users_col.find_one({"email": email})
        ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

        if user and check_password_hash(user["password"], password):
            # Admin "Accept IP" Security Check
            if email == os.getenv("ADMIN_EMAIL"):
                # We use 'pass' here so Python doesn't crash while lines are commented
                pass 
                # if not authorized_ips_col.find_one({"email": email, "ip": ip}):
                #     log_incident("UNAUTHORIZED ADMIN ATTEMPT", "High", email)
                #     flash("Blocked: New IP detected. Admin approval required.")
                #     return redirect(url_for("login"))

            session["email"] = email
            session["role"] = user.get("role", "Employee")
            log_incident("LOGIN SUCCESS", "Low", email)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")
# ================= DASHBOARD (SYNCED) =================

@app.route("/dashboard")
def dashboard():
    if "email" not in session: return redirect(url_for("login"))
    
    # Fetching the TWO lists expected by your dashboard.html
    user_reports = list(reports_col.find().sort("timestamp", -1))
    logs = list(logs_col.find().sort("timestamp", -1).limit(10))
    
    return render_template("dashboard.html", user_reports=user_reports, logs=logs)

@app.route("/admin/accept-ip")
def accept_current_ip():
    if "email" in session and session["email"] == os.getenv("ADMIN_EMAIL"):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        authorized_ips_col.update_one({"email": session["email"], "ip": ip}, {"$set": {"status": "Accepted"}}, upsert=True)
        flash(f"IP {ip} accepted.")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))