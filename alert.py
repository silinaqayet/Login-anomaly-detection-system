import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD")


def send_alert_email(receiver_email, username, risk_level, score, ip_address):
    subject = "DETECTION — Suspicious Login Alert"

    body = f"""
Hello {username},

A suspicious login was detected on your account.

Details:
- Risk Level: {risk_level.upper()}
- Risk Score: {score}
- IP Address: {ip_address}

If this was you, you can ignore this email.
If this was NOT you, please change your password immediately.

— DETECTION Security System
    """

    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("Email credentials are not configured.")
        return False

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        print("Alert email sent successfully!")
        return True
    except Exception as e:
        print("Failed to send email:", e)
        return False
