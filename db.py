import sqlite3

DB_PATH = "app.db"


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                password_hash TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                label TEXT NOT NULL,
                permissions TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        """)

def get_user(username):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

def create_user(username, role="user", password_hash=None):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO users (username, role, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, role, password_hash)
        )

def get_username_by_api_key(key_hash):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT username FROM api_keys WHERE key_hash = ?",
            (key_hash,)
        ).fetchone()

    return row["username"] if row else None

def create_api_key(key_id, username, label, permissions, key_hash):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO api_keys (key_id, username, label, permissions, key_hash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (key_id, username, label, ",".join(permissions), key_hash)
        )

def get_api_keys_for_user(username):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT key_id, label, permissions FROM api_keys WHERE username = ?",
            (username,)
        ).fetchall()

    return {
        row["key_id"]: {
            "label": row["label"],
            "permissions": row["permissions"].split(",")
        }
        for row in rows
    }

def delete_api_key(username, key_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM api_keys WHERE username = ? AND key_id = ?",
            (username, key_id)
        )