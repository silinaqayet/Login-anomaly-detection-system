import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, session
from database import init_db, add_user, get_user, hash_password, get_login_history, save_login_event, increment_fail_count, lock_account, get_all_login_events
from rule import calculate_risk
from datetime import datetime
from alert import send_alert_email
from user_agents import parse as parse_user_agent

ACTION_BY_RISK = {"normal": "allow", "suspicious": "alert", "high risk": "block"}

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required.")

init_db()


# ── LOGIN ─────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('loginpage.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = get_user(username)
    if not user:
        return render_template('loginpage.html', error='Username not found')


    hour = datetime.now().hour
    ua = parse_user_agent(request.headers.get('User-Agent', ''))
    current_browser = ua.browser.family
    current_ip = request.remote_addr
    current_type = ua.os.family

    if user['is_locked']:
        return render_template('loginpage.html', error='Account is locked')


    if user['password'] != hash_password(password):
        increment_fail_count(username)
        if user['fail_count'] + 1 == 3:
            send_alert_email(user['email'], username, 'suspicious activity', 0, current_ip)
            return render_template('loginpage.html', error='Wrong password')
        if user['fail_count'] + 1 >= 4:
            lock_account(username)
            return render_template('loginpage.html', error='Account is locked due to too many failed attempts!')
        return render_template('loginpage.html', error='Wrong password')


    # Step 6 — get login history from database
    history = get_login_history(username)
    known_browsers = [row['user_agent'] for row in history]
    known_ips = [row['ip_address'] for row in history]
    known_countries = [row['country'] for row in history]
    known_types = [row['device_type'] for row in history]

    # Step 7 — calculate risk
    risk_level, score, anomalies = calculate_risk(
        hour,
        current_browser, known_browsers,
        current_type, known_types,
        current_ip, known_ips,
        user['fail_count'],
        "Turkey", known_countries
    )

    new_device = 1 if (
        current_browser not in known_browsers
        or current_ip not in known_ips
        or current_type not in known_types
    ) else 0

    save_login_event(
        username,
        current_ip,
        str(request.user_agent),
        current_browser,
        current_type,
        "Turkey",
        1,
        hour,
        score,
        risk_level,
        str(uuid.uuid4()),
        user['fail_count'],
        new_device,
        ACTION_BY_RISK.get(risk_level, "allow"),
        ",".join(anomalies),
    )

    # Step 8 — send alert if high risk
    if risk_level == "high risk":
        send_alert_email(user['email'], username, risk_level, score, current_ip)

    # Step 9 — login successful
    session['user'] = username
    return redirect(url_for('dashboard'))

# ── REGISTER
@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    email = request.form.get('email')


    if not username or not password:
        return render_template('register.html', error='All fields are required')

    if not email:
        return render_template('register.html', error='Email is required')

    if len(password) < 12:
        return render_template('register.html', error='Password must be at least 12 characters')

    success = add_user(username, password, email)

    if not success:
        return render_template('register.html', error='Username already taken')


    return redirect(url_for('home'))


# ── LOGOUT ────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ── DASHBOARD ─────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('home'))

    print("Session user:", session['user'])
    user = get_user(session['user'])
    print("User from DB:", dict(user))

    if not user['is_admin']:
        return redirect(url_for('home'))

    events = get_all_login_events()
    return render_template('dashboard.html', events=events)

if __name__ == '__main__':
    app.run(debug=True)
