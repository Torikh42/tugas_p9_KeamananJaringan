# Campus Event Portal — Security Demo Project

**Course**: Keamanan Jaringan  
**Team**: Fadil · Rafi · Akbar · Torikh  
**Assignment**: Security Plan for Campus Event Portal Web Application

---

## Overview

This project demonstrates application-layer security vulnerabilities and their mitigations for a fictional **Campus Event Portal** — a web system where students can create, register for, and comment on campus events.

The deliverables cover:
- **Threat Analysis** (OWASP Threat Dragon — `threat-model/`)
- **UML Security Diagrams** (Papyrus Desktop — `papyrus-project/`)
- **Runnable Source Code** demonstrating vulnerable vs. secure implementations (`src/`)

---

## Project Structure

```
campus-event-portal-security/
│
├── src/
│   ├── main.py           # Entry point — runs all demos
│   ├── database.py       # SQLite setup + dummy data (Akbar)
│   ├── auth_demo.py      # Broken Access Control demo (Rafi)
│   ├── sqli_demo.py      # SQL Injection demo — event registration (Akbar)
│   ├── xss_demo.py       # XSS demo — comment system (Akbar)
│   └── email_demo.py     # Email security + anti-phishing demo (Torikh)
│
├── docs/
│   ├── dns_records.txt   # SPF, DKIM, DMARC records for events.youruniversity.edu
│   └── diagrams/         # PNG exports from Papyrus (Rafi)
│       ├── auth_flow.png
│       ├── broken_access_control.png
│       └── input_validation_flow.png
│
├── threat-model/
│   └── campus-portal.json  # OWASP Threat Dragon project (Fadil)
│
├── papyrus-project/        # Eclipse Papyrus project files (Rafi)
│
├── README.md               # This file
└── requirements.txt        # Dependencies (stdlib only)
```

---

## Requirements

- **Python 3.8+**
- No external packages required — all demos use Python standard library only

Verify your Python version:
```bash
python --version
```

---

## How to Run

### Run All Demos at Once
```bash
python src/main.py
```

### Run Individual Demos
```bash
# SQL Injection demo (event registration form)
python src/sqli_demo.py

# XSS demo (event comment system)
python src/xss_demo.py

# Authentication & Broken Access Control demo
python src/auth_demo.py

# Email Security & Anti-phishing demo
python src/email_demo.py
```

> **Note**: SMTP calls in `email_demo.py` will fail gracefully (connection refused)  
> since there is no real mail server. The demo focuses on the **code logic**,  
> not actual mail delivery.

---

## File Descriptions

### `src/database.py`
Sets up an in-memory SQLite database with dummy data:
- `users` table (students, admins)
- `events` table (campus events)
- `registrations` table
- `comments` table

### `src/sqli_demo.py` — SQL Injection Prevention
Demonstrates event registration form security:

| | Vulnerable | Secure |
|---|---|---|
| Query | String concatenation | Parameterized query |
| Attack | `' OR '1'='1` dumps all registrations | Attack string treated as literal data |
| OWASP | A03:2021 Injection | — |

### `src/xss_demo.py` — XSS Prevention
Demonstrates comment system security:

| | Vulnerable | Secure |
|---|---|---|
| Output | Raw HTML rendered | HTML-escaped before rendering |
| Attack | `<script>alert(1)</script>` executes | Rendered as literal text |
| OWASP | A03:2021 Injection | — |

### `src/auth_demo.py` — Broken Access Control
Demonstrates authentication and authorization:

| | Vulnerable | Secure |
|---|---|---|
| Access check | Missing or client-side only | Server-side role verification |
| Attack | Student accesses admin endpoint | Request rejected with 403 |
| OWASP | A01:2021 Broken Access Control | — |

### `src/email_demo.py` — Email Security
Demonstrates email notification system:

| Attack | Vulnerable | Secure |
|---|---|---|
| Header Injection | Raw email in `To:` header | Regex + CRLF validation |
| Open Redirect | Unvalidated URL in body | Domain whitelist check |
| No TLS | Port 25, plain SMTP | Port 587 + STARTTLS |
| HTML Injection | Raw event name in HTML | `html.escape()` applied |
| Phishing Links | Display text ≠ href | Display text = href URL |

### `docs/dns_records.txt`
Complete DNS email authentication records for `events.youruniversity.edu`:
- **SPF** — Authorizes legitimate sending servers
- **DKIM** — Cryptographic signature on outgoing email
- **DMARC** — Enforcement policy + reporting

---

## Vulnerability Summary (from Threat Analysis)

| # | Vulnerability | OWASP Category | Priority |
|---|---|---|---|
| 1 | SQL Injection (event registration) | A03:2021 Injection | Critical |
| 2 | Stored XSS (comment system) | A03:2021 Injection | High |
| 3 | Broken Access Control (admin endpoints) | A01:2021 | Critical |
| 4 | Insecure Authentication (weak session) | A07:2021 | High |
| 5 | Email Header Injection / Phishing | A03:2021 + Social Engineering | High |
| 6 | IDOR (view other users' registrations) | A01:2021 | Medium |
| 7 | Security Misconfiguration (debug mode) | A05:2021 | Medium |

> Full threat model with DFD: `threat-model/campus-portal.json` (open with OWASP Threat Dragon)

---

## Diagrams (Papyrus)

Open the Papyrus project in **Eclipse IDE with Papyrus plugin** installed:
1. File → Import → Existing Projects into Workspace
2. Select `papyrus-project/` folder
3. Open `.di` file to view diagrams

PNG exports are available in `docs/diagrams/` for quick reference.

---

## Team Responsibilities

| Member | Deliverable |
|---|---|
| **Fadil** | Threat Dragon JSON (`threat-model/campus-portal.json`) |
| **Rafi** | Papyrus UML diagrams (`papyrus-project/` & `docs/diagrams/`) |
| **Akbar** | `src/database.py`, `src/sqli_demo.py`, `src/xss_demo.py`, `src/main.py` |
| **Torikh** | `src/email_demo.py`, `src/auth_demo.py`, `docs/dns_records.txt`, `README.md`, `requirements.txt` |

---

## Security Concepts Covered

- OWASP Top 10 (2021)
- SQL Injection prevention via parameterized queries
- XSS prevention via output encoding
- Broken Access Control — server-side enforcement
- Email security: SPF, DKIM, DMARC
- Anti-phishing link design
- SMTP Header Injection prevention
- TLS/STARTTLS for email transport security

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/)
- [RFC 7208 — SPF](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 6376 — DKIM](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 7489 — DMARC](https://datatracker.ietf.org/doc/html/rfc7489)
- [OWASP Email Injection](https://owasp.org/www-community/attacks/Command_Injection)
