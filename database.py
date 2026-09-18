import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'datasave', 'informations.db')

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            created_at TEXT,
            is_locked INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0,
            locked_at TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            timestamp TEXT,
            user_id TEXT,
            ip_address TEXT,
            country TEXT,
            user_agent TEXT,
            browser TEXT,
            device_type TEXT,
            login_success INTEGER,
            hour_of_day INTEGER,
            fail_count INTEGER,
            new_device INTEGER,
            risk_score REAL,
            severity TEXT,
            action TEXT,
            anomaly_types TEXT
        )
    ''')
    try:
        c.execute("ALTER TABLE login_events ADD COLUMN browser TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

def add_user(username, password, email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), email, str(__import__('datetime').datetime.now()))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    user = c.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return user

def save_login_event(username, ip_address, user_agent, browser, device_type, country,
                     login_success, hour, risk_score, severity,
                     event_id, fail_count, new_device, action, anomaly_types):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO login_events (
            event_id, timestamp, user_id, ip_address, country,
            user_agent, browser, device_type, login_success, hour_of_day,
            fail_count, new_device, risk_score, severity, action, anomaly_types
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        event_id, str(__import__('datetime').datetime.now()), username, ip_address, country,
        user_agent, browser, device_type, login_success, hour,
        fail_count, new_device, risk_score, severity, action, anomaly_types
    ))
    conn.commit()
    conn.close()

def get_login_history(username):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    history = c.execute(
        "SELECT ip_address, user_agent, device_type, country FROM login_events WHERE user_id = ? AND login_success = 1",
        (username,)
    ).fetchall()
    conn.close()
    return history

def increment_fail_count(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET fail_count = fail_count + 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()

def lock_account(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET is_locked = 1, locked_at = ? WHERE username = ?",
              (str(__import__('datetime').datetime.now()), username))
    conn.commit()
    conn.close()

def get_all_login_events():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    events = c.execute(
        "SELECT * FROM login_events ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return events

def create_admin(username, password, email):
    if not username or not password or not email:
        raise ValueError("Admin username, password and email are required.")

    add_user(username, password, email)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    print(f"Admin account ready: {username}")

if __name__ == '__main__':
    init_db()

    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    admin_email = os.environ.get("ADMIN_EMAIL")

    if admin_username and admin_password and admin_email:
        create_admin(admin_username, admin_password, admin_email)
    else:
        print("Database initialized. Set ADMIN_USERNAME, ADMIN_PASSWORD and ADMIN_EMAIL to create an admin.")

    print('Database file:', DB_PATH)
