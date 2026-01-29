import os
import random
import threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from flask_mail import Mail, Message
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
from dotenv import load_dotenv
from markupsafe import escape # OWASP A03: Injection Protection

# ================= CONFIGURATION =================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "RC_CHAMPIONS_2026")

# MongoDB Setup
client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db = client["royal_challengers_db"]
users_col = db["users"]
logs_col = db["security_logs"]
blacklist_col = db["blacklist"]
reports_col = db["user_reports"]

# Flask-Mail Setup
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("ADMIN_EMAIL"),
    MAIL_PASSWORD=os.getenv("EMAIL_PASS")
)
mail = Mail(app)

# Twilio Setup
twilio_client = Client(os.getenv("TWILIO_SID"), os.getenv("TWILIO_TOKEN"))

# ================= OWASP A05 & A09: HEADERS & LOGGING =================

@app.after_request
def security_and_logging(response):
    # OWASP A05: Security Misconfiguration (Hardening Headers)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Forensic Activity Logger (A09)
    if not request.path.startswith("/static") and request.endpoint not in ['dashboard']:
        log_incident(f"Access: {request.path}", "Low", session.get('email', 'Guest'))
    return response

def trigger_voice_alert(event_name):
    try:
        msg = f"Security Alert! High-risk incident at Royal Challengers: {event_name}."
        twilio_client.calls.create(
            twiml=f'<Response><Say voice="alice" language="en-IN">{msg}</Say></Response>',
            to=os.getenv("MY_PHONE"),
            from_=os.getenv("TWILIO_PHONE")
        )
    except Exception as e:
        print(f"⚠️ Twilio Alert Failed: {e}")

def log_incident(event, severity, email="Anonymous"):
    log_entry = {
        "timestamp": datetime.now(),
        "event": event,
        "severity": severity,
        "email": email,
        "ip": request.remote_addr
    }
    logs_col.insert_one(log_entry)
    if severity == "High":
        threading.Thread(target=trigger_voice_alert, args=(event,)).start()

# ================= MIDDLEWARE =================

@app.before_request
def block_blacklisted_ips():
    if blacklist_col.find_one({"ip": request.remote_addr}):
        return "<h1>403 Forbidden</h1><p>Your IP is blacklisted per OWASP A01 protocols.</p>", 403

# ================= ROUTES =================

@app.route('/')
def home(): return render_template('home.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/services')
def services(): return render_template('services.html')

@app.route('/careers')
def careers(): return render_template('careers.html')

@app.route('/contact')
def contact(): return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name, email, role = request.form.get('name'), request.form.get('email'), request.form.get('role')
        password = request.form.get('password')
        
        if not all([name, email, password, role]):
            flash("All fields required!"); return redirect(url_for('register'))
        
        user_data = {
            "name": escape(name), "email": escape(email), "role": role,
            "password": generate_password_hash(password),
            "status": "Pending", "failed_attempts": 0
        }

        if role == "Employee":
            otp = str(random.randint(100000, 999999))
            session['otp'], session['temp_user'] = otp, user_data
            msg = Message("RC Verification", sender=os.getenv("ADMIN_EMAIL"), recipients=[email])
            msg.body = f"Your OTP is {otp}"; mail.send(msg)
            return render_template('verify_otp.html')
        else:
            users_col.insert_one(user_data)
            log_incident(f"Registration: {role}", "Medium", email)
            flash("Awaiting Admin Approval."); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify-otp', methods=['POST'])
def process_otp_verification():
    if request.form.get('otp') == session.get('otp'):
        user_data = session.get('temp_user')
        user_data['status'] = "Active"
        users_col.insert_one(user_data)
        session.pop('otp', None); session.pop('temp_user', None)
        flash("Verified! Welcome to RC."); return redirect(url_for('login'))
    flash("Invalid OTP!"); return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        if email == "admin-trap@royalchallengers.com":
            blacklist_col.insert_one({"ip": request.remote_addr, "reason": "Honeytoken hit"})
            log_incident("HONEYTOKEN HIT", "High", email)
            return "Unauthorized", 401

        user = users_col.find_one({"email": email})
        if user:
            if user['status'] == "Locked": flash("Account Locked per A07 policy."); return redirect(url_for('login'))
            if user['status'] == "Pending": flash("Approval Required."); return redirect(url_for('login'))

            if check_password_hash(user["password"], password):
                users_col.update_one({"email": email}, {"$set": {"failed_attempts": 0}})
                session['email'], session['role'] = user['email'], user['role']
                return redirect(url_for('dashboard'))
            else:
                attempts = user.get('failed_attempts', 0) + 1
                users_col.update_one({"email": email}, {"$set": {"failed_attempts": attempts, "status": "Locked" if attempts >= 3 else user['status']}})
                if attempts >= 3: log_incident("BRUTE FORCE DETECTED", "Medium", email)
                flash(f"Invalid credentials. Attempt {attempts}/3.");
    return render_template('login.html')

@app.route('/report-incident', methods=['GET', 'POST'])
def report_incident():
    if 'email' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        # OWASP A03: Escaping input to prevent XSS
        report = {
            "incident_id": f"RC-{random.randint(1000, 9999)}",
            "timestamp": datetime.now(),
            "reporter": session['email'],
            "type": request.form.get('type'),
            "severity": request.form.get('severity'),
            "message": escape(request.form.get('message')) 
        }
        reports_col.insert_one(report)
        log_incident(f"Report: {report['type']}", report['severity'], session['email'])
        flash("Report Submitted Successfully."); return redirect(url_for('dashboard'))
    return render_template('report_incident.html')

@app.route('/dashboard')
def dashboard():
    if 'email' not in session: return redirect(url_for('login'))
    logs, reports = [], []
    if session['role'] in ['Admin', 'Security Analysis']:
        logs = list(logs_col.find().sort("timestamp", -1))
        reports = list(reports_col.find().sort("timestamp", -1))
    return render_template('dashboard.html', logs=logs, user_reports=reports)

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)