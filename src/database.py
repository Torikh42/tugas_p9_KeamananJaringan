import sqlite3
import os

DB_NAME = "campus_event.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with tables and dummy data."""
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
        
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')

    # Create Comments Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        comment TEXT NOT NULL
    )
    ''')

    # Add Dummy Data
    users = [
        ('admin', 'admin123'),
        ('akbar', 'password_akbar'),
        ('mahasiswa1', 'mhs1_secret')
    ]
    cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)

    comments = [
        (1, 'akbar', 'Acara seminar keamanan jaringan sangat keren!'),
        (1, 'mahasiswa1', 'Saya ingin mendaftar ke acara ini.')
    ]
    cursor.executemany('INSERT INTO comments (event_id, username, comment) VALUES (?, ?, ?)', comments)

    conn.commit()
    conn.close()
    print(f"Database {DB_NAME} initialized successfully.")

if __name__ == "__main__":
    init_db()
