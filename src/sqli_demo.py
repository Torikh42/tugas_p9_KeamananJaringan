"""
sqli_demo.py - SQL Injection Demo
Campus Event Portal - Network Security Assignment
Team: Fadil, Rafi, Akbar, Torikh

Demonstrates the full Authentication Flow as per the UML Sequence Diagram:
  Step 1 : User    → Web Server  : POST /login (username, password)
  Step 2 : Web Server            : Validasi format input
  Step 3 : Web Server → Database : execute("SELECT * FROM users WHERE user=? AND pass=?", args)
  Step 4 : Database  → Web Server: Kembalikan Data User (atau None)
  alt [Jika Data Ditemukan (Login Valid)]
    Step 5 : Web Server            : Buat Session Token
    Step 6 : Web Server → User     : 200 OK (Set-Cookie: session_id=<token>)
  else [Jika Data Tidak Ditemukan (Invalid)]
    Step 5 : Web Server → User     : 401 Unauthorized (Login Gagal)

Run:
  python src/sqli_demo.py
"""

import sqlite3
import re
import secrets
import sys
from database import get_db_connection

# Fix Unicode output on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')


# ---------------------------------------------------------------------------
# Session store — in production this would be Redis / DB-backed
# ---------------------------------------------------------------------------
_session_store: dict[str, str] = {}   # {session_token: username}


# ---------------------------------------------------------------------------
# STEP 1 HELPER — Input Format Validation (Validasi format input)
# ---------------------------------------------------------------------------

def _validate_login_input(username: str, password: str) -> tuple[bool, str]:
    """
    Validate format of login credentials BEFORE touching the database.

    Aligns with diagram step: [Web Server] Validasi format input

    Rules:
      - Both fields must be non-empty strings
      - Username: max 50 chars, alphanumeric + underscore only
      - Password: max 128 chars, must be non-empty
      - Reject any CRLF / null bytes (header injection guard)

    Returns:
      (is_valid: bool, reason: str)
    """
    if not username or not isinstance(username, str):
        return False, "Username harus diisi"
    if not password or not isinstance(password, str):
        return False, "Password harus diisi"

    # Reject control characters (CRLF / null bytes)
    for field_name, field_val in [("username", username), ("password", password)]:
        if any(c in field_val for c in ("\n", "\r", "\0")):
            return False, f"{field_name} mengandung karakter tidak valid"

    # Username: only safe chars allowed
    if not re.match(r'^[a-zA-Z0-9_]{1,50}$', username):
        return False, "Format username tidak valid (maks 50 karakter, hanya huruf/angka/underscore)"

    # Password length cap
    if len(password) > 128:
        return False, "Password terlalu panjang (maks 128 karakter)"

    return True, "OK"


# ---------------------------------------------------------------------------
# STEP 5 HELPER — Session Token Creation (Buat Session Token)
# ---------------------------------------------------------------------------

def _create_session_token(username: str) -> str:
    """
    Generate a cryptographically secure session token and store it.

    Aligns with diagram step: [Web Server] Buat Session Token

    Returns:
      session_token (str) — 32-byte hex string, e.g. 'a3f9...'
    """
    token = secrets.token_hex(32)           # 256-bit random token
    _session_store[token] = username         # bind token → user
    return token


# ---------------------------------------------------------------------------
# PART 1 — VULNERABLE LOGIN
# ---------------------------------------------------------------------------

def login_vulnerable(username: str, password: str) -> dict:
    """
    VULNERABLE: Skips input validation, uses raw string concatenation in SQL.

    Attack surface:
      [V1] No input validation  — control characters / empty strings accepted
      [V2] String interpolation — SQL Injection via ' OR 1=1 --
      [V3] Fake session token   — sequential/predictable token (not secure)

    Returns a dict with HTTP-like status + data, mirroring the diagram output.
    """
    print(f"\n[VULNERABLE] POST /login  username='{username}'")

    # [V1] SKIP validation — input goes straight to the query
    print("[VULNERABLE] Validasi format input: DILEWATI (tidak ada validasi)")

    conn = get_db_connection()
    cursor = conn.cursor()

    # [V2] DANGEROUS — raw f-string interpolation allows SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[VULNERABLE QUERY]: {query}")

    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except Exception as e:
        conn.close()
        return {"status_code": 500, "body": f"Internal Server Error: {e}"}
    finally:
        conn.close()

    if user:
        # [V3] Predictable "token" — NOT cryptographically secure
        fake_token = f"session_{user['username']}_12345"
        print(f"[VULNERABLE] Buat Session Token: {fake_token}  (PREDIKTABEL!)")
        return {
            "status_code": 200,
            "headers": {"Set-Cookie": f"session_id={fake_token}"},
            "body": f"200 OK — Selamat datang, {user['username']}!"
        }
    else:
        return {
            "status_code": 401,
            "headers": {},
            "body": "401 Unauthorized — Login Gagal: username atau password salah"
        }


# ---------------------------------------------------------------------------
# PART 2 — SECURE LOGIN
# ---------------------------------------------------------------------------

def login_secure(username: str, password: str) -> dict:
    """
    SECURE: Full flow matching the Authentication Flow UML diagram.

    Security controls:
      [S1] Input validation     — format checked BEFORE DB access
      [S2] Parameterized query  — prevents SQL Injection
      [S3] Secure session token — secrets.token_hex(32) — 256-bit random

    Returns a dict with HTTP-like status + data, mirroring the diagram output.
    """
    print(f"\n[SECURE] POST /login  username='{username}'")

    # ── Step 2 (Diagram): Validasi format input ──────────────────────────────
    is_valid, reason = _validate_login_input(username, password)
    if not is_valid:
        print(f"[SECURE] Validasi format input: GAGAL — {reason}")
        return {
            "status_code": 400,
            "headers": {},
            "body": f"400 Bad Request — Input tidak valid: {reason}"
        }
    print(f"[SECURE] Validasi format input: LULUS — {reason}")

    # ── Step 3 (Diagram): execute(parameterized query) ───────────────────────
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"[SECURE QUERY]: {query}  (params: [{username}, ***])")
    cursor.execute(query, (username, password))

    # ── Step 4 (Diagram): Kembalikan Data User (atau None) ───────────────────
    user = cursor.fetchone()
    conn.close()
    print(f"[SECURE] Database kembalikan: {'Data user ditemukan' if user else 'None (tidak ada data)'}")

    if user:
        # ── Step 5 alt[Login Valid] (Diagram): Buat Session Token ────────────
        token = _create_session_token(user["username"])
        print(f"[SECURE] Buat Session Token: {token[:16]}...  (256-bit, kriptografis aman)")

        # ── Step 6 alt[Login Valid] (Diagram): 200 OK (Set-Cookie: session_id)
        return {
            "status_code": 200,
            "headers": {"Set-Cookie": f"session_id={token}; HttpOnly; Secure; SameSite=Strict"},
            "body": f"200 OK — Selamat datang, {user['username']}!"
        }
    else:
        # ── Step 5 else (Diagram): 401 Unauthorized ──────────────────────────
        return {
            "status_code": 401,
            "headers": {},
            "body": "401 Unauthorized — Login Gagal: username atau password salah"
        }


# ---------------------------------------------------------------------------
# DEMO RUNNER
# ---------------------------------------------------------------------------

def _print_response(label: str, response: dict):
    """Pretty-print an HTTP-like response dict."""
    print(f"\n  +-- {label} Response ---------------")
    print(f"  |  Status : {response['status_code']}")
    if "headers" in response:
        for k, v in response["headers"].items():
            print(f"  |  {k}: {v}")
    print(f"  |  Body   : {response['body']}")
    print(f"  +-----------------------------------")


def run_sqli_demo():
    print("=" * 60)
    print("DEMO 1: SQL INJECTION (SQLi) — Authentication Flow")
    print("Aligns with: AuthenticationFlow.uml (Sequence Diagram)")
    print("=" * 60)

    # --- Scenario 1: Normal Login ---
    print("\n\n--- SKENARIO 1: Login Normal ---")
    print("Input: username='akbar', password='password_akbar'")

    resp = login_vulnerable("akbar", "password_akbar")
    _print_response("VULNERABLE", resp)

    resp = login_secure("akbar", "password_akbar")
    _print_response("SECURE", resp)

    # --- Scenario 2: SQL Injection Attack ---
    print("\n\n--- SKENARIO 2: SQL Injection Attack ---")
    print("Payload: username=\' OR 1=1 --   password=apapun")
    attacker_payload = "' OR 1=1 --"

    resp = login_vulnerable(attacker_payload, "wrong_password")
    _print_response("VULNERABLE (SQLi berhasil)", resp)

    resp = login_secure(attacker_payload, "wrong_password")
    _print_response("SECURE (SQLi diblokir)", resp)

    # --- Scenario 3: Invalid Input Format ---
    print("\n\n--- SKENARIO 3: Format Input Tidak Valid ---")
    print("Payload: username dengan karakter newline (header injection)")
    injected_user = "admin\nX-Injected: evil"

    resp = login_vulnerable(injected_user, "any_pass")
    _print_response("VULNERABLE (tidak divalidasi)", resp)

    resp = login_secure(injected_user, "any_pass")
    _print_response("SECURE (ditolak validasi)", resp)

    # --- Scenario 4: Wrong Password ---
    print("\n\n--- SKENARIO 4: Password Salah ---")
    print("Input: username='admin', password='salah123'")

    resp = login_vulnerable("admin", "salah123")
    _print_response("VULNERABLE", resp)

    resp = login_secure("admin", "salah123")
    _print_response("SECURE", resp)

    print("\n" + "=" * 60)
    print("DEMO SELESAI")
    print("=" * 60)


if __name__ == "__main__":
    run_sqli_demo()
