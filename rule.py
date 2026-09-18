from datetime import datetime

def check_time(hour) :
    if hour >= 1 and hour <=6 :
        return 2
    return 0

def check_device(current_browser,known_browsers):
    if current_browser not in known_browsers:
        return 2
    return 0

def check_ip(current_ip,known_ips):
    if current_ip not in known_ips:
        return 2
    return 0

def check_failed_attempts(failed_count):
    if failed_count >=3 :
        return 3
    return 0

def check_country(current_country,known_countries):
    if current_country not in known_countries :
        return 3
    return 0

def check_device_type(current_type, known_types):
    if current_type not in known_types:
        return 1
    return 0

def calculate_risk(hour, current_browser, known_browsers, current_type, known_types, current_ip, known_ips, failed_count, current_country, known_countries):
    score = 0
    anomalies = []

    s = check_time(hour)
    if s: anomalies.append("off_hours")
    score += s

    s = check_device(current_browser, known_browsers)
    if s: anomalies.append("new_browser")
    score += s

    s = check_ip(current_ip, known_ips)
    if s: anomalies.append("new_ip")
    score += s

    s = check_failed_attempts(failed_count)
    if s: anomalies.append("failed_attempts")
    score += s

    s = check_country(current_country, known_countries)
    if s: anomalies.append("new_country")
    score += s

    s = check_device_type(current_type, known_types)
    if s: anomalies.append("new_device_type")
    score += s

    if score >= 6:
        return "high risk", score, anomalies
    elif score >= 3:
        return "suspicious", score, anomalies
    else:
        return "normal", score, anomalies
