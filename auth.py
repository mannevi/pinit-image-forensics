import sqlite3
import hashlib
import os

# -------------------------------------------------
# STREAMLIT CLOUD SAFE SQLITE LOCATION
# -------------------------------------------------
DB_PATH = "/tmp/pinit_users.db"


def get_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# -------------------------------------------------
# INIT DB (SAFE TO CALL MULTIPLE TIMES)
# -------------------------------------------------
def init_db():
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def register_user(username, password):
    init_db()  # 🔥 FORCE TABLE EXISTENCE EVERY TIME

    conn = get_connection()
    c = conn.cursor()

    try:
        c.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(password))
        )
        conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        conn.close()


def verify_login(username, password):
    init_db()  # 🔥 ENSURE TABLE EXISTS

    conn = get_connection()
    c = conn.cursor()

    c.execute(
        "SELECT id FROM users WHERE username=? AND password=?",
        (username, hash_password(password))
    )

    result = c.fetchone()
    conn.close()

    return result is not None
