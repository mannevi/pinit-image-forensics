import sqlite3
import hashlib


DB = "users.db"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()


def register_user(username: str, password: str) -> bool:
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def verify_login(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return False

    return row[0] == hash_password(password)
