import os
import random
import threading
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from markupsafe import escape

# ================= INITIALIZE =================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# ================= MAIL CONFIG =================
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.getenv("ADMIN_EMAIL"),
    MAIL_PASSWORD=os.getenv("EMAIL_PASS"),
    MAIL_DEFAULT_SENDER=os.getenv("ADMIN_EMAIL"),
    MAIL_TIMEOUT=10
)

mail = Mail(app)

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
    return render_template("dashboard.html", user_reports=reports, logs=logs)

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

            if not email or not name or not password:
                flash("All fields are required")
                return redirect(url_for("register"))

            otp = str(random.randint(100000, 999999))

            cols["temp"].update_one(
                {"email": email},
                {"$set": {
                    "name": name,
                    "password": generate_password_hash(password),
                    "role": "Employee",
                    "otp": otp,
                    "createdAt": datetime.now(timezone.utc)
                }},
                upsert=True
            )

            msg = Message("Your OTP", recipients=[email])
            msg.body = f"Your code: {otp}"

            def send_async(app, msg):
                with app.app_context():
                    try:
                        mail.send(msg)
                        print("✅ MAIL SENT")
                    except Exception as e:
                        print("❌ MAIL ERROR:", e)

            threading.Thread(target=send_async, args=(app, msg)).start()

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

    cols["users"].insert_one({
        "email": temp_user["email"],
        "name": temp_user["name"],
        "password": temp_user["password"],
        "role": temp_user["role"],
        "createdAt": datetime.now(timezone.utc)
    })
    cols["temp"].delete_one({"email": email})
    session.pop("pending_email", None)
    
    flash("Registration successful! Please login.")
    log_event("REGISTRATION_SUCCESS", "Low", email)
    return redirect(url_for("login"))

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
            log_event("LOGIN_SUCCESS", "Low", email)
            return redirect(url_for("dashboard"))

        flash("Invalid credentials")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))