import os.path
import sqlite3
from pathlib import Path

DEFAULT_DB_NAME = "secura.sqlite3"


def _db_path() -> str:
    base = os.getenv("FLET_APP_STORAGE_DATA")
    if not base:
        base = os.path.join(os.getcwd(), "storage")
    Path(base).mkdir(parents=True, exist_ok=True)
    return os.path.join(base, DEFAULT_DB_NAME)


def connect_db():
    path = _db_path()
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")

    conn.executescript(
        """
        BEGIN;
        CREATE TABLE IF NOT EXISTS secura(
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            creation_date DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_aes_keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            bits INTEGER NOT NULL,
            key_material BLOB NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_rsa_keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            bits INTEGER NOT NULL,
            public_pem TEXT NOT NULL,
            private_pem TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_dh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            bits INTEGER NOT NULL,
            public_pem TEXT NOT NULL,
            private_pem TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
        );

        COMMIT;
        """
    )

    conn.execute(
        "INSERT OR IGNORE INTO secura (username, password_hash, salt) VALUES (?, ?, ?)",
        ("aravindaksha", "abcd", "efgh"),
    )
    conn.commit()
    return conn
