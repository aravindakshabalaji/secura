import os
import sqlite3

import flet as ft
from pycrypt.asymmetric import RSAKey

from .components import (
    PrimaryButton,
    TonalButton,
    scrollable_table,
    vertical_scroll,
)
from .theme import GAP_MD, GAP_SM, section_title, subsection_title, surface_card


class CryptoKeys:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Key Management | Cryptographic Suite"
        self.page.scroll = ft.ScrollMode.AUTO
        self.conn = page.conn  # shared

    # ---------- View ----------
    def view(self) -> ft.View:
        header = ft.Row(
            [
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    tooltip="Go Back",
                    on_click=lambda _: self.page.go("/crypto"),
                ),
                ft.Text("🔑 Key Management", size=26, weight=ft.FontWeight.BOLD),
            ],
            alignment=ft.MainAxisAlignment.START,
            spacing=GAP_SM,
        )

        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(text="AES", content=self.aes_tab()),
                ft.Tab(text="RSA", content=self.rsa_tab()),
                ft.Tab(
                    text="DH", content=ft.Container(ft.Text("Coming soon"), padding=20)
                ),
            ],
            expand=1,
        )

        return ft.View(
            route="/crypto/keys",
            controls=[
                ft.Column([header, ft.Divider(), tabs], expand=True, spacing=GAP_MD)
            ],
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )

    # ---------- AES ----------
    def aes_tab(self) -> ft.Control:
        mode_dd = ft.Dropdown(
            label="Select AES Key Size",
            options=[
                ft.DropdownOption(key=s, text=f"AES-{s}") for s in ("128", "192", "256")
            ],
            value="128",
            width=220,
        )
        key_field = ft.TextField(
            label="Key (hex)", read_only=True, width=600, prefix_icon=ft.Icons.KEY
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

        def refresh():
            cur = self.conn.execute(
                "SELECT id, UPPER(hex(key_material)) FROM user_aes_keys WHERE username=? ORDER BY id DESC",
                (self.page.username,),
            )
            rows = []
            for rid, key_hex in cur.fetchall():
                rows.append(
                    ft.DataRow(
                        cells=[
                            ft.DataCell(ft.Text(str(rid))),
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
                                    tooltip="Copy",
                                    on_click=lambda _,
                                    v=key_hex: self.page.set_clipboard(v),
                                )
                            ),
                            ft.DataCell(
                                ft.IconButton(
                                    icon=ft.Icons.DELETE_OUTLINE,
                                    tooltip="Delete",
                                    on_click=lambda _, rr=rid: delete(rr),
                                    icon_color=ft.Colors.RED
                                )
                            ),
                        ]
                    )
                )
            keys_table.rows = rows
            self.page.update()

        def delete(row_id: int):
            self.conn.execute("DELETE FROM user_aes_keys WHERE id=?", (row_id,))
            self.conn.commit()
            refresh()

        def save(_):
            if not key_field.value:
                return
            try:
                kb = bytes.fromhex(key_field.value)
            except ValueError:
                return
            exists = self.conn.execute(
                "SELECT 1 FROM user_aes_keys WHERE username=? AND key_material=?",
                (self.page.username, kb),
            ).fetchone()
            if not exists:
                self.conn.execute(
                    "INSERT INTO user_aes_keys(username, key_material) VALUES (?, ?)",
                    (self.page.username, kb),
                )
                self.conn.commit()
            refresh()

        def generate(_):
            size = int(mode_dd.value) // 8
            key_field.value = os.urandom(size).hex().upper()
            self.page.update()

        key_field.suffix = ft.IconButton(
            icon=ft.Icons.COPY,
            on_click=lambda _: self.page.set_clipboard(key_field.value),
        )

        refresh()

        actions = ft.Row(
            [
                PrimaryButton(
                    self.page,
                    "Generate AES Key",
                    icon=ft.Icons.GENERATING_TOKENS,
                    on_click=generate,
                ),
                TonalButton(self.page, "Save", icon=ft.Icons.SAVE, on_click=save),
            ],
            spacing=GAP_MD,
            alignment=ft.MainAxisAlignment.CENTER,
        )

        content = ft.Column(
            [
                section_title("Advanced Encryption Standard (AES) Keys"),
                mode_dd,
                actions,
                key_field,
                ft.Divider(),
                subsection_title("Saved AES keys"),
                scrollable_table(keys_table),
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )
        return ft.Container(vertical_scroll(surface_card(content)), padding=10)

    # ---------- RSA ----------
    def rsa_tab(self) -> ft.Control:
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
            max_lines=6,
            width=800,
            read_only=True,
            prefix_icon=ft.Icons.VPN_KEY,
        )
        priv_field = ft.TextField(
            label="Private Key (PEM)",
            multiline=True,
            max_lines=6,
            width=800,
            read_only=True,
            password=True,
            can_reveal_password=False,
            prefix_icon=ft.Icons.LOCK,
        )

        copy_pub = ft.IconButton(
            icon=ft.Icons.COPY,
            tooltip="Copy public key",
            on_click=lambda _: self.page.set_clipboard(pub_field.value),
        )
        copy_priv = ft.IconButton(
            icon=ft.Icons.COPY_ALL,
            tooltip="Copy private key",
            on_click=lambda _: self.page.set_clipboard(priv_field.value),
        )
        toggle_btn = ft.IconButton(icon=ft.Icons.VISIBILITY_OFF, tooltip="Show / Hide")

        def toggle(_):
            priv_field.password = not priv_field.password
            toggle_btn.icon = (
                ft.Icons.VISIBILITY
                if not priv_field.password
                else ft.Icons.VISIBILITY_OFF
            )
            self.page.update()

        toggle_btn.on_click = toggle
        priv_field.suffix = ft.Row([copy_priv, toggle_btn], spacing=4, tight=True)
        pub_field.suffix = copy_pub

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

        def refresh():
            cur = self.conn.execute(
                "SELECT id, bits, public_pem, private_pem FROM user_rsa_keys WHERE username=? ORDER BY id DESC",
                (self.page.username,),
            )
            rows = []
            for rid, bits, pub_pem, priv_pem in cur.fetchall():
                preview = pub_pem.splitlines()[0] if pub_pem else ""
                rows.append(
                    ft.DataRow(
                        cells=[
                            ft.DataCell(ft.Text(str(rid))),
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
                                    tooltip="Copy public",
                                    on_click=lambda _,
                                    v=pub_pem: self.page.set_clipboard(v),
                                )
                            ),
                            ft.DataCell(
                                ft.IconButton(
                                    icon=ft.Icons.COPY_ALL,
                                    tooltip="Copy private",
                                    on_click=lambda _,
                                    v=priv_pem: self.page.set_clipboard(v),
                                )
                            ),
                            ft.DataCell(
                                ft.IconButton(
                                    icon=ft.Icons.DELETE_OUTLINE,
                                    tooltip="Delete",
                                    on_click=lambda _, rr=rid: delete(rr),
                                    icon_color=ft.Colors.RED
                                )
                            ),
                        ]
                    )
                )
            rsa_table.rows = rows
            self.page.update()

        def delete(row_id: int):
            self.conn.execute("DELETE FROM user_rsa_keys WHERE id=?", (row_id,))
            self.conn.commit()
            refresh()

        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        def generate(_):
            prog.visible = True
            self.page.update()
            bits = int(size_dd.value)
            key = RSAKey.generate(bits)
            pub_field.value = key.export_key("public")
            priv_field.value = key.export_key("private")
            prog.visible = False
            self.page.update()

        def save(_):
            if not pub_field.value or not priv_field.value:
                return
            bits = int(size_dd.value)
            exists = self.conn.execute(
                "SELECT 1 FROM user_rsa_keys WHERE username=? AND public_pem=?",
                (self.page.username, pub_field.value),
            ).fetchone()
            if not exists:
                self.conn.execute(
                    "INSERT INTO user_rsa_keys(username, bits, public_pem, private_pem) VALUES(?, ?, ?, ?)",
                    (self.page.username, bits, pub_field.value, priv_field.value),
                )
                self.conn.commit()
            refresh()

        refresh()

        actions = ft.Row(
            [
                PrimaryButton(
                    self.page,
                    "Generate RSA Pair",
                    icon=ft.Icons.GENERATING_TOKENS,
                    on_click=generate,
                ),
                TonalButton(self.page, "Save", icon=ft.Icons.SAVE, on_click=save),
                prog,
            ],
            spacing=GAP_MD,
            alignment=ft.MainAxisAlignment.CENTER,
        )

        content = ft.Column(
            [
                section_title("RSA Key Management"),
                size_dd,
                actions,
                pub_field,
                priv_field,
                ft.Divider(),
                subsection_title("Saved RSA keys"),
                scrollable_table(rsa_table),
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )
        return ft.Container(vertical_scroll(surface_card(content)), padding=10)
