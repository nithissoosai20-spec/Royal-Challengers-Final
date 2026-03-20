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
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:
    Limiter = None
    get_remote_address = None

# ================= INITIALIZE =================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# ================= RATE LIMITER =================
if Limiter and get_remote_address:
    limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")
else:
    limiter = None

def rate_limit(limit_str):
    """Decorator that applies rate limit only if limiter is available."""
    def decorator(f):
        if limiter:
            return limiter.limit(limit_str)(f)
        return f
    return decorator

# Single persistent MongoDB connection
_mongo_client = None
def get_db_collections():
    global _mongo_client
    try:
        uri = os.getenv("MONGO_URI")
        if not uri:
            return None
        if _mongo_client is None:
            _mongo_client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        db = _mongo_client["royal_challengers_db"]
        return {
            "users": db["users"],
            "temp": db["temp_users"],
            "pending": db["pending_users"],
            "logs": db["security_logs"],
            "reports": db["user_reports"],
            "ips": db["authorized_ips"],
            "blocked": db["blocked_ips"]
        }
    except Exception as e:
        print(f"❌ DB ERROR: {e}")
        _mongo_client = None
        return None

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

def send_alert_emails(subject, body):
    """Send email to all Super Admin, Admin, Security Analyst in DB."""
    def _send():
        try:
            cols = get_db_collections()
            if not cols:
                return
            users = cols["users"].find(
                {"role": {"$in": ["Super Admin", "Admin", "Security Analyst"]}},
                {"email": 1, "_id": 0}
            )
            for u in users:
                send_email(u["email"], subject, body)
        except Exception as e:
            print("❌ ALERT EMAIL ERROR:", e)
    threading.Thread(target=_send).start()

def send_voice_alert(message):
    """Twilio voice call to Super Admin only."""
    def _call():
        try:
            from twilio.rest import Client
            client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))
            client.calls.create(
                to=os.getenv("MY_PHONE"),
                from_=os.getenv("TWILIO_PHONE"),
                twiml=f"<Response><Say voice='alice'>{message}</Say></Response>"
            )
            print("✅ VOICE ALERT SENT")
        except Exception as e:
            print("❌ VOICE ALERT ERROR:", e)
    threading.Thread(target=_call).start()

# ================= IP INTELLIGENCE =================
def get_ip_intel(ip):
    """Get GeoIP location + AbuseIPDB score for an IP. Returns dict."""
    intel = {"country": "", "city": "", "isp": "", "abuse_score": 0, "abuse_reports": 0}
    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,status", timeout=3).json()
        if geo.get("status") == "success":
            intel["country"] = geo.get("country", "")
            intel["city"] = geo.get("city", "")
            intel["isp"] = geo.get("isp", "")
    except:
        pass
    try:
        abuse = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": os.getenv("ABUSEIPDB_KEY"), "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3
        ).json()
        data = abuse.get("data", {})
        intel["abuse_score"] = data.get("abuseConfidenceScore", 0)
        intel["abuse_reports"] = data.get("totalReports", 0)
    except:
        pass
    return intel

# ================= IP BLOCKING =================
def get_request_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def block_ip(ip, reason):
    try:
        cols = get_db_collections()
        if not cols:
            return
        intel = get_ip_intel(ip)
        cols["blocked"].update_one(
            {"ip": ip},
            {"$set": {
                "ip": ip, "reason": reason,
                "blocked_at": datetime.now(timezone.utc),
                "country": intel["country"],
                "city": intel["city"],
                "isp": intel["isp"],
                "abuse_score": intel["abuse_score"],
                "abuse_reports": intel["abuse_reports"]
            }},
            upsert=True
        )
        print(f"🚫 IP BLOCKED: {ip} | {intel['city']}, {intel['country']} | Abuse: {intel['abuse_score']}%")
    except Exception as e:
        print(f"❌ BLOCK IP ERROR: {e}")

def is_ip_blocked(ip):
    try:
        cols = get_db_collections()
        if not cols:
            return False
        return cols["blocked"].find_one({"ip": ip}) is not None
    except:
        return False

# ================= LOGGING =================
def log_event(event, severity="Low", email="Anonymous"):
    cols = get_db_collections()
    if not cols:
        return
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        intel = get_ip_intel(ip) if severity in ("High", "Medium") else {}
        cols["logs"].insert_one({
            "timestamp": datetime.now(timezone.utc),
            "event": event.upper(),
            "severity": severity,
            "email": email,
            "ip": ip,
            "country": intel.get("country", ""),
            "city": intel.get("city", ""),
            "isp": intel.get("isp", ""),
            "abuse_score": intel.get("abuse_score", 0),
            "abuse_reports": intel.get("abuse_reports", 0)
        })
    except:
        pass


# ================= HONEYTOKEN EMAILS =================
HONEYTOKEN_EMAILS = {
    "admin.backup@royalchallengers.com",
    "soc.monitor@royalchallengers.com",
    "security.audit@royalchallengers.com"
}

# ================= BRUTE FORCE PROTECTION =================
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 30

def get_failed_attempts(ip):
    try:
        cols = get_db_collections()
        rec = cols["logs"].count_documents({"ip": ip, "event": "LOGIN_FAILED",
            "timestamp": {"$gte": datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)}})
        return rec
    except:
        return 0

def get_email_failed_attempts(email):
    """Count failed attempts for a specific email in last 30 mins."""
    try:
        cols = get_db_collections()
        from datetime import timedelta
        since = datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)
        return cols["logs"].count_documents({"email": email, "event": "LOGIN_FAILED", "timestamp": {"$gte": since}})
    except:
        return 0

def is_email_locked(email):
    """Check if email is locked out."""
    try:
        cols = get_db_collections()
        from datetime import timedelta
        since = datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)
        return cols["logs"].count_documents({"email": email, "event": "LOGIN_FAILED", "timestamp": {"$gte": since}}) >= 3
    except:
        return False

# ================= AUDIT TRAIL =================
def audit(action, details=""):
    try:
        cols = get_db_collections()
        if not cols:
            return
        ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        cols["audit"] = cols["logs"]._Collection__database["audit_logs"]
        cols["audit"].insert_one({
            "timestamp": datetime.now(timezone.utc),
            "actor": session.get("email", "Anonymous"),
            "role": session.get("role", ""),
            "action": action,
            "details": details,
            "ip": ip
        })
    except:
        pass

# ================= LOGIN HISTORY =================
def record_login(email, ip, success=True):
    try:
        cols = get_db_collections()
        if not cols:
            return
        intel = get_ip_intel(ip)
        cols["users"].update_one(
            {"email": email},
            {"$push": {"login_history": {
                "$each": [{"timestamp": datetime.now(timezone.utc), "ip": ip,
                           "city": intel.get("city",""), "country": intel.get("country",""),
                           "success": success}],
                "$slice": -10
            }}}
        )
        # Suspicious login detection — 2 different countries within 1 hour
        from datetime import timedelta
        user = cols["users"].find_one({"email": email}, {"login_history": 1})
        history = user.get("login_history", []) if user else []
        recent = [h for h in history if h.get("timestamp") and
                  (datetime.now(timezone.utc) - (h["timestamp"].replace(tzinfo=timezone.utc) if h["timestamp"].tzinfo is None else h["timestamp"])).total_seconds() < 3600
                  and h.get("country") and h["country"] != intel.get("country","")]
        if recent and intel.get("country"):
            log_event("SUSPICIOUS_LOGIN_MULTI_COUNTRY", "High", email)
            send_alert_emails(
                "🚨 Suspicious Login Detected!",
                f"User {email} logged in from {intel.get('country')} but recently logged in from {recent[-1]['country']} — within 1 hour.\nIP: {ip}"
            )
            send_email(email, "⚠️ Suspicious Login on Your Account",
                f"Hello,\n\nWe detected a login to your account ({email}) from {intel.get('city','')}, {intel.get('country','')} (IP: {ip}).\n\nA recent login was also detected from {recent[-1]['country']} within the last hour.\n\nIf this was not you, contact your SOC team immediately.")
    except:
        pass

@app.before_request
def monitor():
    # Session timeout — 20 mins inactivity
    if "email" in session:
        last = session.get("last_active")
        if last and (datetime.now(timezone.utc).timestamp() - last) > 1200:
            session.clear()
            flash("Session expired due to inactivity. Please login again.")
            return redirect(url_for("login"))
        session["last_active"] = datetime.now(timezone.utc).timestamp()
    ip = get_request_ip()
    if is_ip_blocked(ip) and request.endpoint not in ("static", "login"):
        return render_template("blocked.html", ip=ip), 403
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
    blocked_ips = []
    if role == "Super Admin":
        raw_blocked = list(cols["blocked"].find().sort("blocked_at", -1))
        from zoneinfo import ZoneInfo as _ZI
        _ist = _ZI("Asia/Kolkata")
        for doc in raw_blocked:
            doc["_id"] = str(doc["_id"])
            if "blocked_at" in doc and hasattr(doc["blocked_at"], "strftime"):
                doc["blocked_at"] = doc["blocked_at"].astimezone(_ist).strftime("%d-%m-%Y %H:%M:%S")
        blocked_ips = raw_blocked
    analysts = list(cols["users"].find({"role": "Security Analyst"}, {"email": 1, "_id": 0}))
    return render_template("dashboard.html", user_reports=reports, logs=logs, pending_users=pending,
                           blocked_ips=blocked_ips, analysts=analysts,
                           current_user_2fa=bool(cols["users"].find_one({"email": session["email"]}, {"totp_secret": 1}).get("totp_secret")))

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
        audit("USER_APPROVED", f"Approved {user_email} as {pending['role']}")
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
@rate_limit("10 per minute")
def login():
    if request.method == "GET":
        # PROACTIVE: AbuseIPDB pre-check before showing login form
        ip = get_request_ip()
        try:
            abuse = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": os.getenv("ABUSEIPDB_KEY"), "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=3
            ).json()
            score = abuse.get("data", {}).get("abuseConfidenceScore", 0)
            if score >= 75:
                block_ip(ip, f"High AbuseIPDB score on login page: {score}%")
                log_event("PROACTIVE_BLOCK_ABUSEIPDB", "High", "Anonymous")
                send_alert_emails(
                    "🚨 Proactive Block: High Risk IP",
                    f"IP {ip} was blocked before login attempt.\nAbuseIPDB Score: {score}%\nBlocked proactively."
                )
                return render_template("blocked.html", ip=ip), 403
        except:
            pass
        return render_template("login.html", site_key=os.getenv("RECAPTCHA_SITE_KEY", ""))

    if request.method == "POST":
        cols = get_db_collections()
        if not cols:
            flash("Database error")
            return redirect(url_for("login"))

        # PROACTIVE: Verify reCAPTCHA
        recaptcha_secret = os.getenv("RECAPTCHA_SECRET_KEY", "")
        if recaptcha_secret:
            token = request.form.get("g-recaptcha-response", "")
            try:
                r = requests.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={"secret": recaptcha_secret, "response": token},
                    timeout=3
                ).json()
                if not r.get("success") or r.get("score", 1) < 0.5:
                    log_event("CAPTCHA_FAILED", "High", "Anonymous")
                    flash("Security check failed. Please try again.")
                    return render_template("login.html", site_key=os.getenv("RECAPTCHA_SITE_KEY", ""))
            except:
                pass

        email = request.form.get("email")
        password = request.form.get("password")
        ip = get_request_ip()
        user = cols["users"].find_one({"email": email})

        if email in HONEYTOKEN_EMAILS:
            log_event("HONEYTOKEN_EMAIL_TRIGGERED", "High", email)
            block_ip(ip, f"Honeytoken email used: {email}")
            send_alert_emails(
                "🚨 Honeytoken Email Used!",
                f"Someone attempted login with honeytoken email: {email}\nIP: {ip}\nIP has been automatically blocked."
            )
            send_voice_alert(
                f"Alert! A honeytoken email {email} was used in a login attempt from IP {ip}. The IP has been blocked."
            )
            flash("Invalid credentials")
            return render_template("login.html", site_key=os.getenv("RECAPTCHA_SITE_KEY", ""))

        attempts = get_failed_attempts(ip)
        if attempts >= MAX_ATTEMPTS:
            block_ip(ip, f"Brute force: {attempts} failed login attempts")
            log_event("BRUTE_FORCE_BLOCKED", "High", email)
            send_alert_emails(
                "🚨 Brute Force Attack Detected!",
                f"IP {ip} has been blocked after {attempts} failed login attempts.\nLast attempted email: {email}"
            )
            # Alert the targeted account owner directly
            if user:
                send_email(
                    user["email"],
                    "⚠️ Security Alert: Someone is trying to access your account",
                    f"Hello,\n\nWe detected {attempts} failed login attempts targeting your account ({email}) from IP {ip}.\n\nThe IP has been automatically blocked.\nIf this was not you, your account is safe. If you are concerned, please contact your SOC team immediately."
                )
            flash("Too many failed attempts. Your IP has been blocked.")
            return render_template("login.html", site_key=os.getenv("RECAPTCHA_SITE_KEY", ""))

        # PROACTIVE: Email-based account lockout (blocks regardless of IP change)
        if is_email_locked(email):
            log_event("ACCOUNT_LOCKED", "High", email)
            flash(f"Account temporarily locked due to multiple failed attempts. Try again in {LOCKOUT_MINUTES} minutes.")
            return render_template("login.html", site_key=os.getenv("RECAPTCHA_SITE_KEY", ""))

        if user and check_password_hash(user["password"], password):
            # Password expiry check — 90 days
            from datetime import timedelta
            pwd_changed = user.get("password_changed_at", user.get("createdAt"))
            if pwd_changed:
                if pwd_changed.tzinfo is None:
                    pwd_changed = pwd_changed.replace(tzinfo=timezone.utc)
                if (datetime.now(timezone.utc) - pwd_changed).days > 90:
                session["pwd_expired_email"] = email
                flash("Your password has expired. Please set a new password.")
                return redirect(url_for("change_password"))
            if user.get("totp_secret"):
                session["2fa_pending_email"] = email
                session["2fa_pending_role"] = user.get("role", "Employee")
                return redirect(url_for("verify_2fa"))
            session["email"] = email
            session["role"] = user.get("role", "Employee")
            session["last_active"] = datetime.now(timezone.utc).timestamp()
            log_event("LOGIN_SUCCESS", "Low", email)
            record_login(email, ip, success=True)
            return redirect(url_for("dashboard"))

        log_event("LOGIN_FAILED", "Medium", email)
        record_login(email, ip, success=False)
        email_fails = get_email_failed_attempts(email)
        if user and email_fails >= 3:
            send_email(
                user["email"],
                "⚠️ Security Alert: Failed login attempts on your account",
                f"Hello,\n\nWe noticed {email_fails} failed login attempts on your account ({email}) from IP {ip}.\n\nIf this was not you, please contact your SOC team immediately. Your account has been temporarily locked for {LOCKOUT_MINUTES} minutes."
            )
        flash("Invalid credentials")

    return render_template("login.html", site_key=os.getenv("RECAPTCHA_SITE_KEY", ""))

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
        severity = request.form.get("severity", "Low")
        log_event("INCIDENT_REPORTED", severity, session["email"])
        if severity == "Critical":
            inc_type = request.form.get("type", "Unknown")
            reporter = session["email"]
            send_alert_emails(
                "🚨 Critical Incident Reported!",
                f"A Critical severity incident has been reported.\nType: {inc_type}\nReporter: {reporter}\nCheck the SOC dashboard immediately."
            )
            send_voice_alert(
                f"Alert! A critical incident of type {inc_type} has been reported by {reporter} on the Royal Challengers system. Please check the dashboard immediately."
            )
        flash("Incident reported successfully.")
        return redirect(url_for("dashboard"))
    return render_template("report_incident.html")

@app.route("/honeytoken-access")
def honeytoken():
    ip = get_request_ip()
    triggered_by = session.get("email", "Anonymous")
    log_event("HONEYTOKEN_TRIGGERED", "High", triggered_by)
    block_ip(ip, "Honeytoken link accessed")
    send_alert_emails(
        "🚨 Honeytoken Triggered!",
        f"Someone accessed the hidden honeytoken link.\nUser: {triggered_by}\nIP: {ip}\nIP has been automatically blocked."
    )
    send_voice_alert(
        f"Alert! Honeytoken was triggered by {triggered_by} from IP {ip}. The IP has been blocked."
    )
    # If a logged-in user triggered it, alert them directly too
    if triggered_by != "Anonymous":
        send_email(
            triggered_by,
            "⚠️ Security Alert: Suspicious activity on your account",
            f"Hello,\n\nYour account ({triggered_by}) triggered a security honeytoken from IP {ip}.\n\nYour IP has been blocked. If this was not you, contact your SOC team immediately."
        )
    return redirect(url_for("login"))

@app.route("/unblock_ip/<path:ip>", methods=["POST"])
def unblock_ip(ip):
    if session.get("role") != "Super Admin":
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500
    cols["blocked"].delete_one({"ip": ip})
    log_event("IP_UNBLOCKED", "Medium", session["email"])
    flash(f"IP {ip} has been unblocked.")
    return redirect(url_for("dashboard"))

@app.route("/export/<fmt>")
def export_soc(fmt):
    if session.get("role") not in ["Super Admin", "Admin", "Security Analyst"]:
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500

    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    logs = list(cols["logs"].find().sort("timestamp", -1).limit(100))
    reports = list(cols["reports"].find().sort("timestamp", -1))
    for doc in logs + reports:
        doc["_id"] = str(doc["_id"])
        if "timestamp" in doc and hasattr(doc["timestamp"], "strftime"):
            doc["timestamp"] = doc["timestamp"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")

    if fmt == "csv":
        import csv, io
        from flask import Response
        output = io.StringIO()
        w = csv.writer(output)
        w.writerow(["=== SECURITY LOGS ==="])
        w.writerow(["Timestamp", "Event", "Severity", "User", "IP"])
        for l in logs:
            w.writerow([l.get("timestamp"), l.get("event"), l.get("severity"), l.get("email"), l.get("ip")])
        w.writerow([])
        w.writerow(["=== INCIDENT REPORTS ==="])
        w.writerow(["ID", "Reporter", "Type", "Severity", "Message", "Timestamp"])
        for r in reports:
            w.writerow([r.get("incident_id"), r.get("reporter"), r.get("type"), r.get("severity"), r.get("message"), r.get("timestamp")])
        output.seek(0)
        return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=soc_report.csv"})

    elif fmt == "pdf":
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        import io
        from flask import Response
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        elems = []
        elems.append(Paragraph("Royal Challengers SOC Report", styles["Title"]))
        elems.append(Paragraph(f"Exported by: {session['email']} | Role: {session['role']}", styles["Normal"]))
        elems.append(Spacer(1, 12))
        elems.append(Paragraph("Security Logs", styles["Heading2"]))
        log_data = [["Timestamp", "Event", "Severity", "User", "IP"]]
        for l in logs:
            log_data.append([l.get("timestamp",""), l.get("event",""), l.get("severity",""), l.get("email",""), l.get("ip","")])
        t = Table(log_data, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a1b")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor("#c6a15b")),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 16))
        elems.append(Paragraph("Incident Reports", styles["Heading2"]))
        rep_data = [["ID", "Reporter", "Type", "Severity", "Message", "Timestamp"]]
        for r in reports:
            rep_data.append([r.get("incident_id",""), r.get("reporter",""), r.get("type",""), r.get("severity",""), r.get("message","")[:40], r.get("timestamp","")])
        t2 = Table(rep_data, repeatRows=1)
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#da251d")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTSIZE", (0,0), (-1,-1), 7),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
        ]))
        elems.append(t2)
        doc.build(elems)
        buf.seek(0)
        return Response(buf, mimetype="application/pdf", headers={"Content-Disposition": "attachment;filename=soc_report.pdf"})

    elif fmt == "word":
        from docx import Document
        from docx.shared import Pt, RGBColor
        import io
        from flask import Response
        document = Document()
        document.add_heading("Royal Challengers SOC Report", 0)
        document.add_paragraph(f"Exported by: {session['email']} | Role: {session['role']}")
        document.add_heading("Security Logs", level=1)
        tbl = document.add_table(rows=1, cols=5)
        tbl.style = "Table Grid"
        hdr = tbl.rows[0].cells
        for i, h in enumerate(["Timestamp", "Event", "Severity", "User", "IP"]):
            hdr[i].text = h
        for l in logs:
            row = tbl.add_row().cells
            row[0].text = str(l.get("timestamp",""))
            row[1].text = str(l.get("event",""))
            row[2].text = str(l.get("severity",""))
            row[3].text = str(l.get("email",""))
            row[4].text = str(l.get("ip",""))
        document.add_heading("Incident Reports", level=1)
        tbl2 = document.add_table(rows=1, cols=6)
        tbl2.style = "Table Grid"
        hdr2 = tbl2.rows[0].cells
        for i, h in enumerate(["ID", "Reporter", "Type", "Severity", "Message", "Timestamp"]):
            hdr2[i].text = h
        for r in reports:
            row = tbl2.add_row().cells
            row[0].text = str(r.get("incident_id",""))
            row[1].text = str(r.get("reporter",""))
            row[2].text = str(r.get("type",""))
            row[3].text = str(r.get("severity",""))
            row[4].text = str(r.get("message",""))
            row[5].text = str(r.get("timestamp",""))
        buf = io.BytesIO()
        document.save(buf)
        buf.seek(0)
        return Response(buf, mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": "attachment;filename=soc_report.docx"})

    return "Invalid format", 400

@app.route("/update_incident/<incident_id>", methods=["POST"])
def update_incident(incident_id):
    if session.get("role") not in ["Super Admin", "Admin", "Security Analyst"]:
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500
    status = request.form.get("status")
    cols["reports"].update_one(
        {"incident_id": incident_id},
        {"$set": {"status": status, "updated_by": session["email"], "updated_at": datetime.now(timezone.utc)}}
    )
    log_event(f"INCIDENT_{status.upper().replace(' ','_')}", "Low", session["email"])
    flash(f"Incident {incident_id} marked as {status}.")
    return redirect(url_for("dashboard"))

@app.route("/user_management")
def user_management():
    if session.get("role") != "Super Admin":
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    users = list(cols["users"].find({}, {"password": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
        if "createdAt" in u and hasattr(u["createdAt"], "strftime"):
            u["createdAt"] = u["createdAt"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")
    return render_template("user_management.html", users=users)

@app.route("/change_role/<user_email>", methods=["POST"])
def change_role(user_email):
    if session.get("role") != "Super Admin":
        return "Unauthorized", 403
    cols = get_db_collections()
    new_role = request.form.get("role")
    cols["users"].update_one({"email": user_email}, {"$set": {"role": new_role}})
    log_event("ROLE_CHANGED", "Medium", session["email"])
    audit("ROLE_CHANGED", f"Changed {user_email} role to {new_role}")
    flash(f"{user_email} role changed to {new_role}.")
    return redirect(url_for("user_management"))

@app.route("/deactivate_user/<user_email>", methods=["POST"])
def deactivate_user(user_email):
    if session.get("role") != "Super Admin":
        flash("Only Super Admin can delete users.")
        return redirect(url_for("dashboard"))
    if user_email == session["email"]:
        flash("You cannot deactivate yourself.")
        return redirect(url_for("user_management"))
    cols = get_db_collections()
    target = cols["users"].find_one({"email": user_email})
    cols["users"].delete_one({"email": user_email})
    log_event("USER_DEACTIVATED", "Medium", session["email"])
    audit("USER_DELETED", f"Deleted user {user_email}")
    # Notify the deleted user
    if target:
        send_email(
            user_email,
            "Your RC Corp Account Has Been Removed",
            f"Hello,\n\nYour account ({user_email}) has been removed from the Royal Challengers system by a Super Admin.\n\nIf you believe this is a mistake, contact your administrator."
        )
    flash(f"{user_email} has been deactivated.")
    return redirect(url_for("user_management"))

@app.route("/api/dashboard_data")
def dashboard_data():
    if "email" not in session:
        return {"error": "unauthorized"}, 401
    cols = get_db_collections()
    if not cols:
        return {"error": "db offline"}, 500
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    logs = list(cols["logs"].find().sort("timestamp", -1).limit(20))
    for doc in logs:
        doc["_id"] = str(doc["_id"])
        if "timestamp" in doc and hasattr(doc["timestamp"], "strftime"):
            doc["timestamp"] = doc["timestamp"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")
    from flask import jsonify
    return jsonify({"log_count": len(logs), "high_count": sum(1 for l in logs if l["severity"] == "High")})

@app.route("/setup_2fa")
def setup_2fa():
    if "email" not in session:
        return redirect(url_for("login"))
    import pyotp, qrcode, io, base64
    cols = get_db_collections()
    user = cols["users"].find_one({"email": session["email"]})
    if user.get("totp_secret"):
        flash("2FA is already enabled on your account.")
        return redirect(url_for("dashboard"))
    secret = pyotp.random_base32()
    session["totp_setup_secret"] = secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=session["email"], issuer_name="RC Corp SOC")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret)

@app.route("/confirm_2fa", methods=["POST"])
def confirm_2fa():
    if "email" not in session:
        return redirect(url_for("login"))
    import pyotp
    secret = session.get("totp_setup_secret")
    code = request.form.get("code", "").strip()
    if not secret or not pyotp.TOTP(secret).verify(code):
        flash("Invalid code. Please scan the QR again and try.")
        return redirect(url_for("setup_2fa"))
    cols = get_db_collections()
    cols["users"].update_one({"email": session["email"]}, {"$set": {"totp_secret": secret}})
    session.pop("totp_setup_secret", None)
    log_event("2FA_ENABLED", "Low", session["email"])
    flash("2FA enabled successfully! You will need your authenticator app on next login.")
    return redirect(url_for("dashboard"))

@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if "2fa_pending_email" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        import pyotp
        code = request.form.get("code", "").strip()
        email = session["2fa_pending_email"]
        cols = get_db_collections()
        user = cols["users"].find_one({"email": email})
        if user and pyotp.TOTP(user["totp_secret"]).verify(code):
            session.pop("2fa_pending_email", None)
            session.pop("2fa_pending_role", None)
            session["email"] = email
            session["role"] = user.get("role", "Employee")
            session["last_active"] = datetime.now(timezone.utc).timestamp()
            log_event("LOGIN_SUCCESS_2FA", "Low", email)
            record_login(email, get_request_ip(), success=True)
            return redirect(url_for("dashboard"))
        log_event("2FA_FAILED", "High", email)
        flash("Invalid 2FA code. Please try again.")
    return render_template("verify_2fa.html")

@app.route("/disable_2fa", methods=["POST"])
def disable_2fa():
    if "email" not in session:
        return redirect(url_for("login"))
    cols = get_db_collections()
    cols["users"].update_one({"email": session["email"]}, {"$unset": {"totp_secret": ""}})
    log_event("2FA_DISABLED", "Medium", session["email"])
    flash("2FA has been disabled on your account.")
    return redirect(url_for("dashboard"))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    expired_email = session.get("pwd_expired_email") or session.get("email")
    if not expired_email:
        return redirect(url_for("login"))
    if request.method == "POST":
        cols = get_db_collections()
        new_pw = request.form.get("password")
        confirm_pw = request.form.get("confirm_password")
        if new_pw != confirm_pw:
            flash("Passwords do not match.")
            return render_template("change_password.html")
        if len(new_pw) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("change_password.html")
        cols["users"].update_one({"email": expired_email}, {"$set": {
            "password": generate_password_hash(new_pw),
            "password_changed_at": datetime.now(timezone.utc)
        }})
        audit("PASSWORD_CHANGED", f"{expired_email} changed their password")
        log_event("PASSWORD_CHANGED", "Low", expired_email)
        session.pop("pwd_expired_email", None)
        flash("Password updated successfully. Please login.")
        return redirect(url_for("login"))
    return render_template("change_password.html")

@app.route("/profile")
def profile():
    if "email" not in session:
        return redirect(url_for("login"))
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    user = cols["users"].find_one({"email": session["email"]}, {"password": 0})
    if not user:
        return redirect(url_for("logout"))
    history = user.get("login_history", [])[-10:][::-1]
    for h in history:
        if "timestamp" in h and hasattr(h["timestamp"], "strftime"):
            h["timestamp"] = h["timestamp"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")
    return render_template("profile.html", user=user, login_history=history)

@app.route("/assign_incident/<incident_id>", methods=["POST"])
def assign_incident(incident_id):
    if session.get("role") not in ["Super Admin", "Admin"]:
        return "Unauthorized", 403
    cols = get_db_collections()
    assignee = request.form.get("assignee")
    cols["reports"].update_one(
        {"incident_id": incident_id},
        {"$set": {"assigned_to": assignee, "assigned_by": session["email"], "assigned_at": datetime.now(timezone.utc)}}
    )
    audit("INCIDENT_ASSIGNED", f"Incident {incident_id} assigned to {assignee}")
    log_event("INCIDENT_ASSIGNED", "Low", session["email"])
    send_email(assignee, "📋 Incident Assigned to You",
        f"Hello,\n\nIncident {incident_id} has been assigned to you by {session['email']}.\n\nPlease login to the SOC dashboard to review and take action.")
    flash(f"Incident {incident_id} assigned to {assignee}.")
    return redirect(url_for("dashboard"))

@app.route("/audit_log")
def audit_log():
    if session.get("role") != "Super Admin":
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "Database Offline", 500
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    db = cols["logs"]._Collection__database
    entries = list(db["audit_logs"].find().sort("timestamp", -1).limit(50))
    for e in entries:
        e["_id"] = str(e["_id"])
        if "timestamp" in e and hasattr(e["timestamp"], "strftime"):
            e["timestamp"] = e["timestamp"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")
    return render_template("audit_log.html", entries=entries)

@app.route("/api/search_logs")
def search_logs():
    if "email" not in session:
        return {"error": "unauthorized"}, 401
    cols = get_db_collections()
    if not cols:
        return {"error": "db offline"}, 500
    q = request.args.get("q", "").strip()
    from zoneinfo import ZoneInfo
    from flask import jsonify
    ist = ZoneInfo("Asia/Kolkata")
    query = {"$or": [{"ip": {"$regex": q, "$options": "i"}},
                     {"email": {"$regex": q, "$options": "i"}},
                     {"event": {"$regex": q, "$options": "i"}}]} if q else {}
    logs = list(cols["logs"].find(query).sort("timestamp", -1).limit(50))
    for doc in logs:
        doc["_id"] = str(doc["_id"])
        if "timestamp" in doc and hasattr(doc["timestamp"], "strftime"):
            doc["timestamp"] = doc["timestamp"].astimezone(ist).strftime("%d-%m-%Y %H:%M:%S")
    return jsonify(logs)

@app.route("/daily_digest")
def daily_digest():
    """Manually trigger daily digest — also called by cron."""
    if session.get("role") != "Super Admin" and request.args.get("key") != os.getenv("SECRET_KEY"):
        return "Unauthorized", 403
    cols = get_db_collections()
    if not cols:
        return "DB Offline", 500
    from datetime import timedelta
    from zoneinfo import ZoneInfo
    ist = ZoneInfo("Asia/Kolkata")
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    total_logs = cols["logs"].count_documents({"timestamp": {"$gte": since}})
    high = cols["logs"].count_documents({"timestamp": {"$gte": since}, "severity": "High"})
    medium = cols["logs"].count_documents({"timestamp": {"$gte": since}, "severity": "Medium"})
    blocked = cols["blocked"].count_documents({"blocked_at": {"$gte": since}})
    incidents = cols["reports"].count_documents({"timestamp": {"$gte": since}})
    body = f"""RC Corp SOC — Daily Security Digest
{'='*40}
Date: {datetime.now(timezone.utc).astimezone(ist).strftime('%d-%m-%Y')}

Last 24 Hours Summary:
  Total Security Events : {total_logs}
  High Severity         : {high}
  Medium Severity       : {medium}
  New Incidents         : {incidents}
  IPs Blocked           : {blocked}

Login to the SOC Dashboard for full details.
"""
    send_alert_emails("📊 RC Corp Daily Security Digest", body)
    return "Digest sent.", 200

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
