import sys
import os

# Ensure the 'src' directory is in the python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import init_db
from sqli_demo import run_sqli_demo
from xss_demo import run_xss_demo
import auth_demo
import email_demo

def main():
    print("="*60)
    print("      CAMPUS EVENT PORTAL - SECURITY DEMONSTRATION")
    print("="*60)
    
    # Initialize database
    init_db()
    
    while True:
        print("\nSilakan pilih menu demo:")
        print("1. SQL Injection (SQLi) - Register/Login")
        print("2. Cross-Site Scripting (XSS) - Comment System")
        print("3. Broken Access Control (Auth) - Admin Dashboard")
        print("4. Email Security & Anti-Phishing - Notifications")
        print("5. Jalankan Semua Demo")
        print("0. Keluar")
        
        choice = input("\nPilihan Anda: ")
        
        if choice == '1':
            run_sqli_demo()
        elif choice == '2':
            run_xss_demo()
        elif choice == '3':
            auth_demo.run_demo()
        elif choice == '4':
            email_demo.run_demo()
        elif choice == '5':
            run_sqli_demo()
            run_xss_demo()
            auth_demo.run_demo()
            email_demo.run_demo()
        elif choice == '0':
            print("Terima kasih! Tetap jaga keamanan jaringan.")
            break
        else:
            print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
