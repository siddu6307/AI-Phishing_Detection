import json
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,          -- 'email' or 'link'
    content    TEXT NOT NULL,
    risk_level TEXT NOT NULL,          -- Low / Medium / High
    reasons    TEXT NOT NULL,
    checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    get_db().executescript(SCHEMA)


def get_user_by_email(email):
    return get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def get_user_by_id(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(email, password_hash):
    db = get_db()
    db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
    db.commit()


# --- check history ---
# The 'reasons' column stores a JSON blob: {"score", "reasons", "links"}
def add_check(user_id, kind, content, level, details):
    db = get_db()
    cur = db.execute(
        "INSERT INTO history (user_id, type, content, risk_level, reasons) VALUES (?, ?, ?, ?, ?)",
        (user_id, kind, content, level, json.dumps(details)),
    )
    db.commit()
    return cur.lastrowid


def get_check(user_id, check_id):
    return get_db().execute(
        "SELECT * FROM history WHERE id = ? AND user_id = ?", (check_id, user_id)
    ).fetchone()


def list_checks(user_id, limit=100):
    return get_db().execute(
        "SELECT * FROM history WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit)
    ).fetchall()


def clear_checks(user_id):
    db = get_db()
    db.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
    db.commit()
