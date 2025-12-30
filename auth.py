import sqlite3
import hashlib

DB_PATH = "users.db"

def _connect():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    con = _connect()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()

def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def register_user(email: str, password: str) -> tuple[bool, str]:
    email = (email or "").strip().lower()
    if not email or not password:
        return False, "Email and password required."

    con = _connect()
    cur = con.cursor()
    try:
        cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, _hash_password(password)))
        con.commit()
        return True, "Registration successful. Please login."
    except sqlite3.IntegrityError:
        return False, "User already exists. Please login."
    finally:
        con.close()

def verify_login(email: str, password: str) -> tuple[bool, str]:
    email = (email or "").strip().lower()
    if not email or not password:
        return False, "Email and password required."

    con = _connect()
    cur = con.cursor()
    cur.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    con.close()

    if not row:
        return False, "No account found. Please register."
    if row[0] != _hash_password(password):
        return False, "Invalid credentials."
    return True, "Login successful."
