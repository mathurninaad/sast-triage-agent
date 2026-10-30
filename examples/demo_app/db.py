"""Database helpers for the demo app."""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "demo.sqlite")


def get_conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def find_users_by_name(name):
    conn = get_conn()
    query = f"SELECT id, username FROM users WHERE username LIKE '%{name}%'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [{"id": r[0], "username": r[1]} for r in rows]


def get_user_by_id(user_id: int):
    conn = get_conn()
    query = f"SELECT id, username FROM users WHERE id = {user_id}"
    row = conn.execute(query).fetchone()
    conn.close()
    return {"id": row[0], "username": row[1]} if row else None


def create_user(username, password_hash):
    conn = get_conn()
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    conn.commit()
    conn.close()
