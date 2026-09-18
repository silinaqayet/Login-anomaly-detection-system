# Login Anomaly Detection System

A rule-based login security system built with **Python, Flask, SQLite, and Jinja templates**. The project detects suspicious login behavior by evaluating contextual risk signals such as unusual login times, new browsers, new devices, unfamiliar IP addresses, repeated failed attempts, and country changes.

## Features

- User registration and login
- Password-length validation
- Failed-login tracking
- Suspicious-login email alerts
- Account locking after repeated failed attempts
- Rule-based anomaly scoring
- New browser, device, IP, and country detection
- Off-hours login detection
- Admin dashboard for reviewing login events
- SQLite persistence
- Environment-variable based secret management

## Risk Scoring

The system assigns points for different anomaly signals:

- Login during off-hours
- New browser
- New IP address
- Multiple failed login attempts
- New country
- New device type

The final score is classified as:

- **Normal** → allow
- **Suspicious** → alert
- **High risk** → block

## Tech Stack

- Python
- Flask
- SQLite
- Jinja2
- HTML / CSS
- user-agents
- SMTP email alerts

## Project Structure

```
.
├── app.py
├── alert.py
├── database.py
├── rule.py
├── requirements.txt
├── .env.example
├── .gitignore
└── templates/
    ├── loginpage.html
    ├── register.html
    └── dashboard.html
```

## Setup

1. Clone the repository.

```bash
git clone https://github.com/silinaqayet/Login-anomaly-detection-system.git
cd Login-anomaly-detection-system
```

2. Create a virtual environment and install dependencies.

```bash
python -m venv venv
pip install -r requirements.txt
```

3. Copy the environment template.

```bash
cp .env.example .env
```

4. Configure the required environment variables in your environment or local `.env` workflow.

Required values:

```
FLASK_SECRET_KEY
SENDER_EMAIL
SENDER_PASSWORD
ADMIN_USERNAME
ADMIN_PASSWORD
ADMIN_EMAIL
```

5. Initialize the database and optionally create an admin account.

```bash
python database.py
```

6. Run the application.

```bash
python app.py
```

Then open:

```
http://127.0.0.1:5000
```

## Security Notes

Secrets and local database files are intentionally excluded from the repository. Credentials must be supplied through environment variables and should never be committed to Git.

## Purpose

This project was developed as a software engineering graduation project to demonstrate authentication monitoring, rule-based anomaly detection, security event logging, and administrative review of suspicious login activity.

## Author

**Silina Qayet**
