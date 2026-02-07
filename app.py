import os
import random
import threading
import logging
import sys
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, has_request_context
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

# ================= LOGGING (RENDER SAFE) =================
logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)],
    format="%(asctime)s | %(levelname)s | %(message)s"
)

app.logger.handlers = logging.getLogger().handlers
app.logger.setLevel(logging.INFO)
app.logger.info("🚀 Application started")

# ================= MITRE ATT&CK MAP =================
MITRE_MAP = {
    "LOGIN FAILED": {
        "tactic": "Credential Access",
        "technique": "Password Guessing",
        "id": "T1110.001"
    },
    "BRUTE FORCE DETECTED": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    },
    "HONEYTOKEN HIT": {
        "tactic": "Credential Access",
        "technique": "Valid Accounts",
        "id": "T1078"
    }
}

# ================= DATABASE =================
client = MongoClient(os.getenv("MONGO_URI"))
db = client["royal_challengers_db"]
users_col = db["users"]
logs_col = db["security_logs"]
blacklist_col = db["blacklist"]

app.logger.info("✅ MongoDB Atlas connected")

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
twilio_client = Client(
    os.getenv("TWILIO_SID"),
    os.getenv("TWILIO_TOKEN")
)

# ================= VOICE ALERT =================
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
        app.logger.error(f"Twilio failed: {e}")

# ================= INCIDENT LOGGER =================
def log_incident(event, severity, email="Anonymous", category="security"):
    if has_request_context():
        ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip_addr and "," in ip_addr:
            ip_addr = ip_addr.split(",")[0].strip()
        path = request.path
        method = request.method
        user_agent = request.headers.get("User-Agent")
    else:
        ip_addr = path = method = user_agent = "N/A"

    mitre = MITRE_MAP.get(event, {})

    logs_col.insert_one({
        "timestamp": datetime.utcnow(),
        "event": event,
        "severity": severity,
        "category": category,
        "email": email,
        "ip": ip_addr,
        "path": path,
        "method": method,
        "user_agent": user_agent,
        "mitre": mitre
    })

    app.logger.info(f"📝 {event} | {email} | {ip_addr}")

    if severity == "High":
        threading.Thread(
            target=trigger_voice_alert,
            args=(event,),
            daemon=True
        ).start()

# ================= PAGE VISIT LOGGER =================
@app.before_request
def log_page_visit():
    if request.path.startswith("/static"):
        return
    if request.path in ["/force-log"]:
        return

    email = session.get("email", "Guest")

    log_incident(
        event="PAGE VISIT",
        severity="Info",
        email=email,
        category="access"
    )

# ================= BLACKLIST CHECK =================
@app.before_request
def block_blacklisted_ips():
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip_addr and "," in ip_addr:
        ip_addr = ip_addr.split(",")[0].strip()

    if blacklist_col.find_one({"ip": ip_addr}):
        log_incident(
            "BLACKLISTED IP ACCESS",
            "High",
            "Unknown"
        )
        abort(403)

# ================= ROUTES =================

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = escape(request.form.get("name"))
        email = escape(request.form.get("email"))
        password = request.form.get("password")

        if users_col.find_one({"email": email}):
            flash("Email already exists")
            return redirect(url_for("register"))

        otp = str(random.randint(100000, 999999))
        session["otp"] = otp
        session["temp_user"] = {
            "name": name,
            "email": email,
            "password": generate_password_hash(password),
            "status": "Unverified",
            "failed_attempts": 0
        }

        msg = Message(
            "OTP Verification",
            sender=os.getenv("ADMIN_EMAIL"),
            recipients=[email]
        )
        msg.body = f"Your OTP is {otp}"
        mail.send(msg)

        log_incident("OTP SENT", "Low", email)
        return render_template("verify_otp.html")

    return render_template("register.html")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    if request.form.get("otp") != session.get("otp"):
        log_incident("OTP FAILED", "Medium", session.get("temp_user", {}).get("email"))
        flash("Invalid OTP")
        return render_template("verify_otp.html")

    users_col.insert_one(session["temp_user"])
    log_incident("OTP VERIFIED", "Low", session["temp_user"]["email"])
    session.clear()
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = users_col.find_one({"email": email})
        if not user or not check_password_hash(user["password"], password):
            log_incident("LOGIN FAILED", "Medium", email)
            flash("Invalid credentials")
            return redirect(url_for("login"))

        session["email"] = email
        log_incident("LOGIN SUCCESS", "Low", email)
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    log_incident("LOGOUT", "Low", session.get("email"))
    session.clear()
    return redirect(url_for("home"))

# ================= TEST =================
@app.route("/force-log")
def force_log():
    log_incident("FORCE LOG TEST", "Low", "tester@local")
    return "log inserted"

# ================= RUN =================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
