"""
auth_demo.py — Broken Access Control Demo
Campus Event Portal — Network Security Assignment

Demonstrates:
  1. VULNERABLE Access Control: Trusts client-provided data (e.g., a parameter or cookie)
     to determine authorization level without server-side validation.
  2. SECURE Access Control: Enforces authorization on the server-side based on
     a trusted session state.

Run:
  python src/auth_demo.py
"""

import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# --- Mock Database/State ---
MOCK_USERS = {
    "student_01": {"name": "Budi", "role": "student"},
    "admin_01": {"name": "Admin Kampus", "role": "admin"}
}

# --- VULNERABLE IMPLEMENTATION ---

def view_admin_dashboard_VULNERABLE(username: str, client_provided_role: str):
    """
    VULNERABLE: The server relies on a role provided by the client (e.g., from a hidden
    form field, a modified URL parameter ?role=admin, or a manipulated cookie).
    """
    print("\n[VULNERABLE] Attempting to access Admin Dashboard...")
    
    # FATAL FLAW: Trusting user input for authorization
    if client_provided_role == "admin":
        print(f"  [!] SUCCESS: Welcome to Admin Dashboard, {username}.")
        print("  [!] Action allowed: Delete events, kick users.")
    else:
        print(f"  [X] DENIED: Access forbidden for role '{client_provided_role}'.")

# --- SECURE IMPLEMENTATION ---

def get_user_role_from_db(username: str) -> str:
    """Simulates fetching the trusted user role from the database/session."""
    user = MOCK_USERS.get(username)
    if user:
        return user["role"]
    return "guest"

def view_admin_dashboard_SECURE(username: str):
    """
    SECURE: The server ignores client claims and verifies the role against
    the trusted server-side state (database or secure session token).
    """
    print("\n[SECURE] Attempting to access Admin Dashboard...")
    
    # SECURE CHECK: Fetching role from a trusted server-side source
    actual_role = get_user_role_from_db(username)
    
    if actual_role == "admin":
        print(f"  [V] SUCCESS: Welcome to Admin Dashboard, {username}.")
    else:
        print(f"  [X] DENIED: {username} is a '{actual_role}'. Admin access required.")
        logging.warning(f"Unauthorized admin access attempt by {username}")


# --- DEMO RUNNER ---

def run_demo():
    print("="*60)
    print("BROKEN ACCESS CONTROL DEMO")
    print("="*60)

    student_user = "student_01"
    
    print("\n--- SCENARIO 1: The attacker manipulates the request ---")
    print("Attacker (student_01) modifies the HTTP request to include role='admin'")
    
    # Attacker forces the role parameter to 'admin'
    malicious_role_payload = "admin" 
    
    view_admin_dashboard_VULNERABLE(student_user, malicious_role_payload)
    
    print("\n--- SCENARIO 2: The secure system defends the attack ---")
    print("Attacker tries the same trick, but the server verifies via session/DB")
    
    # The secure function doesn't even accept a role parameter from the client
    view_admin_dashboard_SECURE(student_user)

    print("\n" + "="*60)

if __name__ == "__main__":
    run_demo()
