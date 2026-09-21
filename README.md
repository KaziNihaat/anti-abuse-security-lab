# Anti-Abuse Security Lab

> A small Flask-based defensive security lab exploring **account quotas, IP rate limiting, browser-session/device correlation, and risk scoring** on localhost.


## The story

One late night, I became curious about how websites distinguish repeated limited-use activity across accounts, browser sessions, and network context. Rather than probing a real service, I recreated the problem safely on **localhost** and built a small defensive lab to understand what the server can observe and how different controls interact.

The goal was simple: start with an account that can use a feature only three times, then progressively add more defensive signals and observe what changes.

## What I built

The lab implements four small security ideas:

- **Account quota** — each account can use the protected feature up to 3 times.
- **IP rate limit** — the lab tracks cumulative successful usage from the same source IP.
- **Session/device correlation** — one random lab `device_id` is associated with accounts seen in the same browser session.
- **Risk scoring** — multiple signals are combined into a simple score rather than relying on only one identifier.

### High-level flow

```text
Request
  |
  v
Account/session check
  |
  v
Account quota -----> 429 if exhausted
  |
  v
IP usage ----------> 429 if exhausted
  |
  v
Device + account correlation
  |
  v
Risk score --------> 429 if threshold reached
  |
  v
Allow request
```

## What the tests showed

### 1. A normal request is allowed

The first requests from the account are accepted and the server records both account and IP usage.

### 2. The account limit works

After three successful uses, the same account receives `429 Too Many Requests`.


### 3. A new account does not erase network history

A different account starts with a fresh account counter, but the server still sees cumulative activity from the same localhost IP. Once the shared network limit is reached, another account is restricted too.


### 4. Multiple accounts can be correlated inside the lab session

With two accounts on one lab device/session, the demo risk score becomes **25**. With three accounts, it becomes **50**.


The project also adds IP activity to the score. For example, three accounts plus higher IP activity can raise the score further and eventually cross the configured threshold.

## What I learned

- An **account**, **IP address**, and **browser session/device identifier** are different signals.
- A client-side cookie alone should not be the source of truth for a security-sensitive quota.
- Server-side tracking makes it possible to correlate activity across requests.
- IP-only blocking can create false positives because many legitimate users can share one public IP through NAT, Wi-Fi, offices, or universities.
- Combining several weak signals can provide better context than treating any single signal as absolute proof of abuse.
- Risk thresholds need tuning; defensive controls should balance detection with legitimate-user impact.

## Run the lab locally

### Requirements

- Python 3.11+
- Flask 3.1.x

### Windows PowerShell

```powershell
python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Suggested learning sequence:

```text
/login/kazi
/feature
/stats
/login/testuser
/risk
```

## Routes

| Route | Purpose |
|---|---|
| `/` | Lab home page |
| `/login/<username>` | Creates/updates the demo login session |
| `/feature` | Protected limited-use endpoint |
| `/risk` | Shows current demo risk score and reasons |
| `/stats` | Shows in-memory counters and device/account associations |

## Risk model used in this demo

| Signal | Score |
|---|---:|
| 2+ accounts on one lab device/session | +25 |
| 3+ accounts on one lab device/session | +25 |
| IP usage >= 3 | +15 |
| IP usage reaches limit | +15 |
| High-risk threshold | 70 |

This is intentionally a **simple educational model**, not a production fraud-detection system.

## Important limitations

- All counters are kept **in memory** and reset when the Flask process restarts.
- `127.0.0.1` is the loopback address because the experiment runs locally; it is not a public Internet IP.
- The `device_id` is a random identifier stored in the Flask session. It is **not browser fingerprinting**.
- The Flask development server is for local learning only and should not be exposed as a production service.

## Next steps

- SQLite persistence
- Security event logging
- A small monitoring dashboard
- Configurable rate-limit windows
- Better separation of authentication, rate limiting, and risk policy
- Tests using Flask's test client

## Responsible use

This project is for defensive learning in a local or explicitly authorized environment. It is designed to study how anti-abuse protections can be built—not how to evade restrictions on real services. See [SECURITY.md](SECURITY.md).

## Tech

`Python` · `Flask` · `HTTP 429` · `Sessions` · `Rate Limiting` · `Risk Scoring` · `Web Security`

---

Built from curiosity, tested on localhost, and documented as a small cybersecurity learning project.
