import http.server
import socketserver
import json
import urllib.parse
import sys
import os

# Add src to path if needed
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from sqli_demo import login_vulnerable, login_secure
from xss_demo import add_comment, get_comments
from auth_demo import get_user_role_from_db, MOCK_USERS
from email_demo import get_email_preview_data
import html

PORT = 8000

class SecurityDemoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.serve_file('static/index.html', 'text/html')
        elif self.path == '/style.css':
            self.serve_file('static/style.css', 'text/css')
        elif self.path.startswith('/api/get_comments'):
            self.handle_get_comments()
        elif self.path.startswith('/api/admin_dashboard'):
            self.handle_admin_dashboard()
        elif self.path.startswith('/api/email_preview'):
            self.handle_email_preview()
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = json.loads(post_data)

        if self.path == '/api/login' or self.path == '/api/register':
            self.handle_login(data)
        elif self.path == '/api/add_comment':
            self.handle_add_comment(data)
        else:
            self.send_error(404, "API Not Found")

    def serve_file(self, rel_path, content_type):
        try:
            full_path = os.path.join(os.path.dirname(__file__), rel_path)
            with open(full_path, 'rb') as f:
                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.end_headers()
                self.wfile.write(f.read())
        except Exception as e:
            self.send_error(404, f"File not found: {e}")

    def handle_login(self, data):
        username = data.get('username', '')
        password = data.get('password', '')
        mode = data.get('mode', 'vulnerable')

        if mode == 'secure':
            result = login_secure(username, password)
        else:
            result = login_vulnerable(username, password)
        
        self.send_json_response(result['status_code'], result)


    def handle_get_comments(self):
        # Default event_id = 1 for demo
        comments = get_comments(1)
        # Format comments for JSON
        formatted = []
        for c in comments:
            formatted.append({
                "username": c[2],
                "comment": c[3]
            })
        self.send_json_response(200, formatted)

    def handle_add_comment(self, data):
        username = data.get('username', 'Student_Tester')
        text = data.get('comment', '')
        mode = data.get('mode', 'vulnerable')
        
        # Call the demo logic which now supports backend sanitization (matching UML)
        add_comment(1, username, text, mode)
        self.send_json_response(200, {"message": "Comment added successfully"})

    def handle_admin_dashboard(self):
        """
        DEMO: Broken Access Control
        Vulnerable: Trusts the 'role' header/param from client.
        Secure: Verifies role on server-side.
        """
        # Parse query parameters
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        
        username = params.get('username', ['guest'])[0]
        client_role = params.get('role', ['student'])[0]
        mode = params.get('mode', ['vulnerable'])[0]
        
        if mode == 'secure':
            # [SECURE] Verify role from server-side trusted state
            actual_role = get_user_role_from_db(username)
            if actual_role == 'admin':
                status = 200
                msg = {"status": "success", "message": f"Welcome Admin {username}! Full control granted."}
            else:
                status = 403
                msg = {"status": "error", "message": "Access Denied: Server-side check failed."}
        else:
            # [VULNERABLE] Trust the role parameter from client
            if client_role == 'admin':
                status = 200
                msg = {"status": "success", "message": f"Welcome {username}! (Access granted via client-side 'role' parameter)"}
            else:
                status = 403
                msg = {"status": "error", "message": "Access Denied: Client-side role not 'admin'."}
        
        self.send_json_response(status, msg)

    def handle_email_preview(self):
        """
        DEMO: Email Security (SPF/DKIM/DMARC)
        Calls logic from email_demo.py to generate a dynamic preview.
        """
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        
        mode = params.get('mode', ['vulnerable'])[0]
        user_email = params.get('email', ['student@youruniversity.edu'])[0]
        event_name = params.get('event', ['Tech Symposium 2024'])[0]
        event_url  = params.get('url', ['https://events.youruniversity.edu/e/42'])[0]
        
        # Call the actual python logic in email_demo.py
        data = get_email_preview_data(mode, user_email, event_name, event_url)
        
        self.send_json_response(200, data)

    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

def run_server():
    # Ensure static directory exists
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)

    with socketserver.TCPServer(("", PORT), SecurityDemoHandler) as httpd:
        print(f"Server started at http://localhost:{PORT}")
        print("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.server_close()

if __name__ == "__main__":
    run_server()
