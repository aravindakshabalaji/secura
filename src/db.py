import os
import sqlite3

import flet as ft

app_data_path = os.getenv("FLET_APP_STORAGE_DATA")
# db_path = os.path.join(app_data_path, "sqlite3")
db_path = (
    r"C:\Users\panch\Documents\Aravindaksha\CS Project\secura\storage\data\sqlite3"
)


def connect_db():
    conn = sqlite3.connect(db_path)

    table_exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='secura';"
    ).fetchall()

    if not table_exists:
        create_db(conn)
    
    return conn


def create_db(conn: sqlite3.Connection):
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    BEGIN;

    CREATE TABLE secura(
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        creation_date DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE user_aes_keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        key_material BLOB NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
    );
    
    CREATE TABLE user_rsa_keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        bits INTEGER NOT NULL,
        public_pem TEXT NOT NULL,
        private_pem TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
    );
    
    INSERT INTO secura (username, password_hash, salt) VALUES ('aravindaksha', 'abcd', 'efgh');

    COMMIT;
    """)

