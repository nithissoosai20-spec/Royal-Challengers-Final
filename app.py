import os
import random
import threading
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from flask_mail import Mail, Message
from pymongo import MongoClient, errors
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
from dotenv import load_dotenv
from markupsafe import escape

# ================= CONFIG =================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# Flask-Mail Config
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.gmail.com"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("ADMIN_EMAIL"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("ADMIN_EMAIL")
)

mail = Mail(app)

# ================= DATABASE CONNECTION (ROBUST) =================
def get_db():
    try:
        # We use a long timeout to prevent "Internal Server Error" on slow cold starts
        client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=10000)
        # Trigger a call to see if the server is actually there
        client.admin.command('ping')
        return client["royal_challengers_db"]
    except Exception as e:
        print(f"❌ DATABASE CONNECTION DEAD: {e}")
        return None

db = get_db()

# ================= TOOLS =================
try:
    twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))
except:
    twilio_client = None

# ================= CORE SOC LOGIC =================

def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def log_incident(event, severity, email="Anonymous", category="general"):
    """Saves logs with a fresh DB check to prevent 500 errors."""
    database = get_db()
    if database is None: return # Don't crash the app if logging fails
    
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
        database["security_logs"].insert_one(log_doc)
        print(f"✅ LOG SAVED: {event}")
        
        if severity == "High" and twilio_client:
            threading.Thread(target=trigger_voice_alert, args=(event,), daemon=True).start()
    except Exception as e:
        print(f"❌ Log Insert Failed: {e}")

def trigger_voice_alert(event):
    try:
        twilio_client.calls.create(
            twiml=f'<Response><Say voice="alice">Security Alert: {event}</Say></Response>',
            to=os.getenv("MY_PHONE"), from_=os.getenv("TWILIO_PHONE")
        )
    except: pass

# ================= GLOBAL MONITORING =================

@app.before_request
def auto_log_visit():
    if not request.path.startswith('/static') and request.endpoint != 'dashboard':
        user = session.get("email", "Anonymous")
        log_incident(f"VISIT: {request.path}", "Low", user, "traffic")

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

@app.route("/register", methods=["GET", "POST"])
def register():
    database = get_db()
    if database is None: return "Database connection error. Try again later.", 500

    if request.method == "POST":
        email = escape(request.form.get("email"))
        if database["users"].find_one({"email": email}):
            flash("User already exists.")
            return redirect(url_for("register"))
        
        otp = str(random.randint(100000, 999999))
        database["temp_users"].update_one({"email": email}, {"$set": {
            "name": escape(request.form.get("name")),
            "password": generate_password_hash(request.form.get("password")),
            "role": escape(request.form.get("role", "Employee")),
            "otp": otp, 
            "createdAt": datetime.now(timezone.utc)
        }}, upsert=True)
        
        try:
            msg = Message("SOC Portal OTP", recipients=[email])
            msg.body = f"Your OTP is: {otp}"
            mail.send(msg)
            session["pending_email"] = email
            return render_template("verify_otp.html")
        except Exception as e:
            print(f"❌ EMAIL ERROR: {e}")
            flash("Could not send OTP. Check your Email Admin settings.")
            return redirect(url_for("register"))
            
    return render_template("register.html")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    database = get_db()
    email = session.get("pending_email")
    user_data = database["temp_users"].find_one({"email": email})
    
    if user_data and request.form.get("otp") == user_data["otp"]:
        database["users"].insert_one({
            "name": user_data["name"], "email": user_data["email"], 
            "password": user_data["password"], "role": user_data["role"]
        })
        database["temp_users"].delete_one({"email": email})
        log_incident("REGISTRATION COMPLETE", "Low", email)
        flash("Success! Please Login.")
        return redirect(url_for("login"))
    flash("Invalid OTP")
    return render_template("verify_otp.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    database = get_db()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = database["users"].find_one({"email": email})
        ip = get_client_ip()

        if user and check_password_hash(user["password"], password):
            if email == os.getenv("ADMIN_EMAIL"):
                auth = database["authorized_ips"].find_one({"email": email, "ip": ip})
                if not auth:
                    log_incident("UNAUTHORIZED ADMIN IP", "High", email)
                    flash("IP Blocked. Contact System Admin.")
                    return redirect(url_for("login"))

            session["email"] = email
            session["role"] = user.get("role", "Employee")
            log_incident("LOGIN SUCCESS", "Low", email)
            return redirect(url_for("dashboard"))
            
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    database = get_db()
    if "email" not in session: return redirect(url_for("login"))
    
    try:
        user_reports = list(database["user_reports"].find().sort("timestamp", -1))
        logs = list(database["security_logs"].find().sort("timestamp", -1).limit(25))
        return render_template("dashboard.html", user_reports=user_reports, logs=logs)
    except Exception as e:
        print(f"❌ Dashboard Fetch Error: {e}")
        return "Error loading dashboard data.", 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))