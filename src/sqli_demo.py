import sqlite3
from database import get_db_connection

def login_vulnerable(username, password):
    """
    VULNERABLE: Uses raw string concatenation.
    Susceptible to SQL Injection.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Dangerous SQL query construction
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"\n[VULNERABLE QUERY]: {query}")
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        return user
    except Exception as e:
        print(f"Error: {e}")
        return None

def login_secure(username, password):
    """
    SECURE: Uses parameterized queries.
    Protects against SQL Injection.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Safe SQL query construction using ? placeholders
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print(f"\n[SECURE QUERY]: {query} (with parameters: {username}, {password})")
    
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def run_sqli_demo():
    print("="*50)
    print("DEMO 1: SQL INJECTION (SQLi)")
    print("="*50)

    # 1. Normal Login
    print("\n--- Normal Login ---")
    user = login_vulnerable("akbar", "password_akbar")
    if user:
        print(f"SUCCESS: Welcome {user['username']}")
    else:
        print("FAILED: Invalid credentials")

    # 2. SQL Injection Attack
    print("\n--- SQL Injection Attack (' OR 1=1 --) ---")
    # Payload: ' OR 1=1 --
    # This will make the query: SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '...'
    # The -- comments out the password check.
    attacker_payload = "' OR 1=1 --"
    user = login_vulnerable(attacker_payload, "wrong_password")
    
    if user:
        print(f"ATTACK SUCCESS: Logged in as {user['username']} without correct password!")
    else:
        print("ATTACK FAILED")

    # 3. Secure Login (Testing same payload)
    print("\n--- Testing Secure Login with Payload ---")
    user = login_secure(attacker_payload, "wrong_password")
    
    if user:
        print(f"ATTACK SUCCESS (Wait, this shouldn't happen!): Welcome {user['username']}")
    else:
        print("ATTACK BLOCKED: Secure login prevented the injection.")

if __name__ == "__main__":
    run_sqli_demo()
