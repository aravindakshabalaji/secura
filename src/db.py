# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Aravindaksha Balaji
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


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
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_aes_keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            bits INTEGER NOT NULL,
            key_material BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_rsa_keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            bits INTEGER NOT NULL,
            public_pem BLOB NOT NULL,
            private_pem BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_dh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            bits INTEGER NOT NULL,
            public_pem BLOB NOT NULL,
            private_pem BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
        );

        COMMIT;
        """
    )

    conn.commit()
    return conn
