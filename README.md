# Campus Event Portal - Security Lab (Tugas P9)

A demonstration web application built to fulfill the requirements of the Network Security assignment (Tugas P9). This portal simulates a campus event system allowing students to register for events and post comments, while highlighting critical web vulnerabilities and their secure countermeasures.

## 🚀 How to Run

1. **Requirements**: 
   - Python 3.x installed.
   - Standard Library only (No frameworks like Flask/Django needed).

2. **Execution**:
   ```powershell
   python src/web_server.py
   ```
3. **Access**: Open your browser and go to `http://localhost:8000`

---

## 🛡️ Security Features & Demonstrations

### 1. Event Registration (SQL Injection Prevention)
*   **Vulnerability**: Uses string interpolation (f-strings) directly in SQL queries without sanitization.
*   **Attack Vector**: `' OR '1'='1' -- `
*   **Countermeasure**: Parameterized queries using `?` placeholders and input validation via Regex.
*   **Code Location**: `src/sqli_demo.py`

### 2. Event Comment System (XSS Prevention)
*   **Vulnerability**: Data is stored raw in the database and rendered using `.innerHTML` on the frontend.
*   **Attack Vector**: `<img src=x onerror=alert('XSS_Success')>`
*   **Countermeasure**: 
    - **Server-side**: `html.escape()` before storage.
    - **Client-side**: Using `.textContent` instead of `.innerHTML`.
*   **Code Location**: `src/xss_demo.py` & `src/static/index.html`

### 3. Broken Access Control
*   **Scenario**: Demonstrates how predictable session tokens (e.g., `session_admin_12345`) allow unauthorized users to guess and hijack administrative sessions.
*   **Countermeasure**: Implementing cryptographically secure, random session tokens using Python's `secrets` module.

### 4. Email Security (Anti-Phishing)
The system simulates an email notification setup for `events.youruniversity.edu`.

**Proposed DNS Configuration:**
*   **SPF Record**: `v=spf1 ip4:1.2.3.4 include:_spf.google.com ~all` (Specifies authorized IP addresses for sending mail).
*   **DMARC Policy**: `v=DMARC1; p=quarantine; rua=mailto:admin@youruniversity.edu` (Instructs receivers to quarantine emails that fail SPF/DKIM).
*   **DKIM**: Cryptographic signing of headers to ensure email integrity.

---

## 📁 Project Structure
```text
tugas_p9_KeamananJaringan/
├── src/
│   ├── static/             # Frontend (HTML/CSS)
│   ├── web_server.py       # Main Application Entry
│   ├── database.py         # SQLite Setup
│   ├── sqli_demo.py        # SQLi Logic (Vulnerable vs Secure)
│   └── xss_demo.py         # XSS Logic (Vulnerable vs Secure)
├── campus_event.db         # Local SQLite Database
└── README.md               # This documentation
```

## 📋 Deliverable Checklist
- [x] Threat Identification (In Lab UI)
- [x] Risk Prioritization (In Lab UI)
- [x] Vulnerable vs Secure Code Examples
- [x] Email/DNS Security Drafts
- [x] Runnable Source Code
