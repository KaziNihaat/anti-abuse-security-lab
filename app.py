"""Anti-Abuse Security Lab

A small defensive Flask lab for learning how account quotas, IP rate limits,
device/session correlation, and simple risk scoring can work together.

Run only in a local/authorized environment.
"""

from collections import defaultdict
import os
import secrets
from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

ACCOUNT_LIMIT = 3
IP_LIMIT = 6
HIGH_RISK_THRESHOLD = 70

# In-memory state for this learning lab. Data resets when the app restarts.
account_usage = defaultdict(int)
ip_usage = defaultdict(int)
device_accounts = defaultdict(set)


@app.before_request
def ensure_device_session():
    """Assign a random lab device/session identifier to each browser session."""
    if "device_id" not in session:
        session["device_id"] = secrets.token_hex(8)


def calculate_risk(device_id: str, ip: str):
    """Return a simple demo risk score and human-readable reasons."""
    score = 0
    reasons = []
    accounts_on_device = len(device_accounts[device_id])

    if accounts_on_device >= 2:
        score += 25
        reasons.append("Multiple accounts associated with the same device")

    if accounts_on_device >= 3:
        score += 25
        reasons.append("Three or more accounts associated with the same device")

    if ip_usage[ip] >= 3:
        score += 15
        reasons.append("Elevated request activity from this IP")

    if ip_usage[ip] >= IP_LIMIT:
        score += 15
        reasons.append("IP usage limit reached")

    return score, reasons


@app.route("/")
def home():
    return """
    <h1>Anti-Abuse Security Lab</h1>
    <p>Educational localhost project for defensive web-security learning.</p>
    <h3>Routes</h3>
    <p>/login/kazi</p>
    <p>/feature</p>
    <p>/risk</p>
    <p>/stats</p>
    """


@app.route("/login/<username>")
def login(username):
    username = username.strip()
    if not username:
        return jsonify({"error": "Username cannot be empty."}), 400

    session["username"] = username
    device_id = session["device_id"]
    device_accounts[device_id].add(username)

    return jsonify(
        {
            "message": "Login successful",
            "username": username,
            "device_id": device_id,
            "accounts_seen_on_device": sorted(device_accounts[device_id]),
        }
    )


@app.route("/feature")
def protected_feature():
    username = session.get("username")
    if not username:
        return jsonify({"error": "Please login first."}), 401

    ip = request.remote_addr or "unknown"
    device_id = session["device_id"]
    risk_score, reasons = calculate_risk(device_id, ip)

    # Risk check first: the lab demonstrates multi-signal correlation.
    if risk_score >= HIGH_RISK_THRESHOLD:
        return (
            jsonify(
                {
                    "error": "Request blocked due to high abuse risk.",
                    "risk_score": risk_score,
                    "risk_threshold": HIGH_RISK_THRESHOLD,
                    "reasons": reasons,
                }
            ),
            429,
        )

    if account_usage[username] >= ACCOUNT_LIMIT:
        return jsonify({"error": "Account usage limit reached.", "limit": ACCOUNT_LIMIT}), 429

    if ip_usage[ip] >= IP_LIMIT:
        return jsonify({"error": "Network/IP usage limit reached.", "limit": IP_LIMIT}), 429

    account_usage[username] += 1
    ip_usage[ip] += 1

    return jsonify(
        {
            "status": "ACCESS GRANTED",
            "username": username,
            "account_usage": account_usage[username],
            "account_limit": ACCOUNT_LIMIT,
            "ip_address": ip,
            "ip_usage": ip_usage[ip],
            "ip_limit": IP_LIMIT,
            "device_id": device_id,
            "risk_score": risk_score,
            "risk_reasons": reasons,
        }
    )


@app.route("/risk")
def risk():
    device_id = session["device_id"]
    ip = request.remote_addr or "unknown"
    score, reasons = calculate_risk(device_id, ip)

    return jsonify(
        {
            "accounts": sorted(device_accounts[device_id]),
            "accounts_on_device": len(device_accounts[device_id]),
            "device_id": device_id,
            "ip_address": ip,
            "reasons": reasons,
            "risk_score": score,
            "risk_threshold": HIGH_RISK_THRESHOLD,
        }
    )


@app.route("/stats")
def stats():
    return jsonify(
        {
            "account_usage": dict(account_usage),
            "ip_usage": dict(ip_usage),
            "device_accounts": {
                device: sorted(accounts) for device, accounts in device_accounts.items()
            },
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
