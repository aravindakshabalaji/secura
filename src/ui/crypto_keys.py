import os
import sqlite3

import flet as ft
from pycrypt.asymmetric import RSAKey


class CryptoKeys:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Key Management | Cryptographic Suite"
        self.page.scroll = ft.ScrollMode.AUTO

        # DB path on the page; set a default if not provided
        if not hasattr(self.page, "db_path"):
            self.page.db_path = "secura.db"

        # ensure tables exist
        self._init_db()

    # ---------- DB helpers ----------

    def _conn(self):
        # New connection per call. Safe with Flet threads.
        return sqlite3.connect(self.page.db_path)

    def _init_db(self):
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_aes_keys(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    key_material BLOB NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_rsa_keys(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    bits INTEGER NOT NULL,
                    public_pem TEXT NOT NULL,
                    private_pem TEXT NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES secura(username) ON DELETE CASCADE
                );
                """
            )
            conn.commit()

    # ---------- UI helpers ----------

    @staticmethod
    def styled_button(text, icon, color, on_click, progress=None):
        ctrls = [ft.Icon(icon), ft.Text(text)]
        if progress:
            ctrls.append(progress)
        return ft.ElevatedButton(
            content=ft.Row(
                ctrls, spacing=8, tight=True, alignment=ft.MainAxisAlignment.CENTER
            ),
            bgcolor=color,
            color=ft.Colors.WHITE,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=12),
                padding=ft.padding.all(15),
            ),
            on_click=on_click,
        )

    # ---------- RSA tab ----------

    def create_rsa_tab(self):
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        sizes = ["1024", "2048", "3072", "4096"]
        size_dd = ft.Dropdown(
            label="RSA Key Size",
            options=[ft.DropdownOption(key=s, text=f"{s} bits") for s in sizes],
            value="2048",
            width=220,
        )

        pub_field = ft.TextField(
            label="Public Key (PEM)",
            multiline=True,
            max_lines=5,
            width=800,
            read_only=True,
            icon=ft.Icons.VPN_KEY,
        )
        priv_field = ft.TextField(
            label="Private Key (PEM)",
            multiline=True,
            max_lines=5,
            width=800,
            read_only=True,
            password=True,
            can_reveal_password=False,  # we will supply our own toggle
            icon=ft.Icons.LOCK,
        )

        # Public field copy suffix
        pub_field.suffix = ft.IconButton(
            icon=ft.Icons.COPY,
            tooltip="Copy public key",
            on_click=lambda _: self.page.set_clipboard(pub_field.value),
        )

        # Private field copy + reveal in a fixed-height container to keep vertical center
        reveal_btn = ft.IconButton(icon=ft.Icons.VISIBILITY_OFF, tooltip="Show / Hide")

        def toggle_visibility(e):
            priv_field.password = not priv_field.password
            reveal_btn.icon = (
                ft.Icons.VISIBILITY
                if not priv_field.password
                else ft.Icons.VISIBILITY_OFF
            )
            self.page.update()

        reveal_btn.on_click = toggle_visibility

        copy_btn = ft.IconButton(
            icon=ft.Icons.COPY,
            tooltip="Copy private key",
            on_click=lambda _: self.page.set_clipboard(priv_field.value),
        )

        priv_field.suffix = ft.Row(
            controls=[copy_btn, reveal_btn],
            spacing=4,
            tight=True,
        )

        # saved keys table
        rsa_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("ID")),
                ft.DataColumn(ft.Text("Bits")),
                ft.DataColumn(ft.Text("Public PEM (preview)")),
                ft.DataColumn(ft.Text("Copy Pub")),
                ft.DataColumn(ft.Text("Copy Priv")),
                ft.DataColumn(ft.Text("Delete")),
            ],
            rows=[],
            column_spacing=18,
            data_row_max_height=52,
        )

        def refresh_rsa():
            with self._conn() as conn:
                cur = conn.execute(
                    "SELECT id, bits, public_pem, private_pem "
                    "FROM user_rsa_keys WHERE username=? ORDER BY id DESC",
                    (self.page.username,),
                )
                rows = []
                for rowid, bits, pub_pem, priv_pem in cur.fetchall():
                    preview = pub_pem.splitlines()[0] if pub_pem else ""
                    rows.append(
                        ft.DataRow(
                            cells=[
                                ft.DataCell(ft.Text(str(rowid))),
                                ft.DataCell(ft.Text(str(bits))),
                                ft.DataCell(
                                    ft.Text(
                                        preview,
                                        max_lines=1,
                                        overflow=ft.TextOverflow.ELLIPSIS,
                                        width=520,
                                    )
                                ),
                                ft.DataCell(
                                    ft.IconButton(
                                        icon=ft.Icons.COPY,
                                        tooltip="Copy public PEM",
                                        on_click=lambda _,
                                        v=pub_pem: self.page.set_clipboard(v),
                                    )
                                ),
                                ft.DataCell(
                                    ft.IconButton(
                                        icon=ft.Icons.COPY_ALL,
                                        tooltip="Copy private PEM",
                                        on_click=lambda _,
                                        v=priv_pem: self.page.set_clipboard(v),
                                    )
                                ),
                                ft.DataCell(
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE,
                                        tooltip="Delete key",
                                        on_click=lambda _, rid=rowid: delete_rsa(rid),
                                    )
                                ),
                            ]
                        )
                    )
                rsa_table.rows = rows
            self.page.update()

        def delete_rsa(row_id: int):
            with self._conn() as conn:
                conn.execute("DELETE FROM user_rsa_keys WHERE id=?", (row_id,))
                conn.commit()
            refresh_rsa()

        def generate_pair(e):
            prog.visible = True
            gen_btn.disabled = True
            self.page.update()

            bits = int(size_dd.value)
            key = RSAKey.generate(bits)
            pub_field.value = key.export_key("public")
            priv_field.value = key.export_key("private")

            prog.visible = False
            gen_btn.disabled = False
            self.page.update()

        def save_pair(e):
            if not pub_field.value or not priv_field.value:
                return
            bits = int(size_dd.value)
            with self._conn() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM user_rsa_keys WHERE username=? AND public_pem=?",
                    (self.page.username, pub_field.value),
                ).fetchone()
                if exists:
                    return
                conn.execute(
                    "INSERT INTO user_rsa_keys(username, bits, public_pem, private_pem) "
                    "VALUES(?, ?, ?, ?)",
                    (self.page.username, bits, pub_field.value, priv_field.value),
                )
                conn.commit()
            refresh_rsa()

        gen_btn = self.styled_button(
            "Generate RSA Pair",
            ft.Icons.GENERATING_TOKENS,
            color=ft.Colors.GREEN_700,
            on_click=generate_pair,
            progress=prog,
        )
        save_btn = self.styled_button(
            "Save",
            ft.Icons.SAVE,
            color=ft.Colors.BLUE_700,
            on_click=save_pair,
        )

        refresh_rsa()

        return ft.Container(
            content=ft.Column(
                controls=[
                    ft.Text("RSA Key Management", size=22, weight=ft.FontWeight.BOLD),
                    size_dd,
                    ft.Row(
                        [gen_btn, save_btn],
                        spacing=12,
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                    pub_field,
                    priv_field,
                    ft.Divider(),
                    ft.Text("Saved RSA keys", size=18, weight=ft.FontWeight.W_600),
                    rsa_table,
                ],
                spacing=18,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
            ),
            padding=ft.padding.all(20),
            alignment=ft.alignment.center,
        )

    # ---------- AES tab ----------

    def create_aes_tab(self):
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        modes = ["128", "192", "256"]

        def get_modes():
            return [ft.DropdownOption(key=mode, text=f"AES-{mode}") for mode in modes]

        mode_dd = ft.Dropdown(
            label="Select AES Key Size", options=get_modes(), value="128"
        )

        key_field = ft.TextField(
            label="Key (hex)",
            read_only=True,
            icon=ft.Icons.KEY,
            width=600,
            autofocus=True,
        )

        keys_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("ID")),
                ft.DataColumn(ft.Text("Key (hex)")),
                ft.DataColumn(ft.Text("Copy")),
                ft.DataColumn(ft.Text("Delete")),
            ],
            rows=[],
            column_spacing=20,
            data_row_max_height=48,
        )

        def refresh_keys():
            with self._conn() as conn:
                cur = conn.execute(
                    "SELECT id, UPPER(hex(key_material)) "
                    "FROM user_aes_keys WHERE username=? ORDER BY id DESC",
                    (self.page.username,),
                )
                rows = []
                for rowid, key_hex in cur.fetchall():
                    rows.append(
                        ft.DataRow(
                            cells=[
                                ft.DataCell(ft.Text(str(rowid))),
                                ft.DataCell(
                                    ft.Text(
                                        key_hex,
                                        selectable=True,
                                        max_lines=1,
                                        overflow=ft.TextOverflow.ELLIPSIS,
                                        width=520,
                                    )
                                ),
                                ft.DataCell(
                                    ft.IconButton(
                                        icon=ft.Icons.COPY,
                                        tooltip="Copy key",
                                        on_click=lambda _,
                                        v=key_hex: self.page.set_clipboard(v),
                                    )
                                ),
                                ft.DataCell(
                                    ft.IconButton(
                                        icon=ft.Icons.DELETE,
                                        tooltip="Delete key",
                                        on_click=lambda _, rid=rowid: delete_aes(rid),
                                    )
                                ),
                            ]
                        )
                    )
                keys_table.rows = rows
            self.page.update()

        def delete_aes(row_id: int):
            with self._conn() as conn:
                conn.execute("DELETE FROM user_aes_keys WHERE id=?", (row_id,))
                conn.commit()
            refresh_keys()

        def save_key(e):
            if not key_field.value:
                return
            try:
                key_bytes = bytes.fromhex(key_field.value)
            except ValueError:
                return
            with self._conn() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM user_aes_keys WHERE username=? AND key_material=?",
                    (self.page.username, key_bytes),
                ).fetchone()
                if exists:
                    return
                conn.execute(
                    "INSERT INTO user_aes_keys (username, key_material) VALUES (?, ?)",
                    (self.page.username, key_bytes),
                )
                conn.commit()
            refresh_keys()

        key_field.suffix = ft.Row(
            [
                ft.IconButton(
                    icon=ft.Icons.COPY,
                    on_click=lambda _: self.page.set_clipboard(key_field.value),
                ),
                ft.IconButton(icon=ft.Icons.SAVE, on_click=save_key),
            ],
            tight=True,
        )

        def generate(e):
            prog.visible = True
            generate_key.disabled = True
            self.page.update()

            key_field.value = os.urandom(int(mode_dd.value) // 8).hex().upper()

            prog.visible = False
            generate_key.disabled = False
            self.page.update()

        generate_key = self.styled_button(
            "Generate",
            ft.Icons.GENERATING_TOKENS,
            color=ft.Colors.GREEN_700,
            on_click=generate,
            progress=prog,
        )

        refresh_keys()

        return ft.Container(
            content=ft.Column(
                controls=[
                    ft.Text(
                        "Advanced Encryption Standard (AES) Keys",
                        size=22,
                        weight=ft.FontWeight.BOLD,
                    ),
                    mode_dd,
                    generate_key,
                    key_field,
                    ft.Divider(),
                    ft.Text("Saved keys", size=18, weight=ft.FontWeight.W_600),
                    keys_table,
                ],
                spacing=20,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                scroll=ft.ScrollMode.AUTO,
            ),
            padding=ft.padding.all(20),
            alignment=ft.alignment.center,
        )

    # ---------- View ----------

    def view(self):
        header = ft.Row(
            [
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    tooltip="Go Back",
                    on_click=lambda _: self.page.go("/crypto"),
                ),
                ft.Text("🔑 Key Management", size=28, weight=ft.FontWeight.BOLD),
            ],
            alignment=ft.MainAxisAlignment.START,
            spacing=15,
        )

        aes_tab = self.create_aes_tab()
        rsa_tab = self.create_rsa_tab()

        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(text="AES", content=aes_tab),
                ft.Tab(text="RSA", content=rsa_tab),
                ft.Tab(text="DH", content=None),
            ],
            expand=1,
            indicator_color=ft.Colors.CYAN_700,
        )

        return ft.View(
            route="/crypto/keys",
            controls=[ft.Column([header, ft.Divider(), tabs], expand=True, spacing=10)],
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )
