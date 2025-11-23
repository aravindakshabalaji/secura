from secrets import token_hex

import flet as ft
from pycrypt.asymmetric import DH, RSAKey

from crypto.base_view import BaseView
from ui.components import (
    IconButton,
    PrimaryButton,
    TonalButton,
    scrollable_table,
    vertical_scroll,
)
from ui.theme import GAP_MD, section_title, subsection_title


class KeyManagement(BaseView):
    def __init__(self, page: ft.Page):
        super().__init__(page)
        self.page.title = "Key Management | Cryptographic Suite"
        self.conn = getattr(page, "conn", None)

        self._save_picker = ft.FilePicker()
        self.page.overlay.append(self._save_picker)

    # --- Public view ---
    def view(self):
        header = self.render_header("🔑 Key Management")

        tabs = self.render_tabs(
            [
                ft.Tab(text="AES", content=self._aes_tab()),
                ft.Tab(text="RSA", content=self._rsa_tab()),
                ft.Tab(text="DH", content=self._dh_tab()),
            ]
        )

        return self.render_view(header, tabs, "/crypto/keys")

    # --- Helpers ---
    @staticmethod
    def _safe_filename_component(s: str) -> str:
        if not s:
            return "key"
        safe = s.replace(" ", "_")
        for ch in [":", "/", "\\", "\t"]:
            safe = safe.replace(ch, "_")
        return safe

    def _save_text_to_file(self, text: str, filename: str, ext: str = "pem"):
        plat = self._platform()
        if plat not in ("windows", "linux", "macos"):
            self._show_not_supported("Downloading files")
            return

        def _on_save(e: ft.FilePickerResultEvent):
            try:
                if e.path:
                    with open(f"{e.path}.{ext}", "w", encoding="utf-8") as fh:
                        fh.write(text)
                    self._snack(f"Saved: {e.path}.{ext}")
            except Exception as err:
                self._snack(f"Save failed: {err}")

        try:
            self._save_picker.on_result = _on_save
            self._save_picker.save_file(
                file_name=filename,
                file_type=ft.FilePickerFileType.CUSTOM,
                allowed_extensions=[ext],
            )
        except Exception as err:
            self._snack(f"Save failed: {err}")

    def _make_copy_cell(self, content: str, label: str = "text", icon=ft.Icons.COPY):
        return ft.DataCell(self._copy_button(content, label, icon))

    # --- AES ---
    def _aes_tab(self):
        mode_dd = ft.Dropdown(
            label="AES Key Size",
            options=[
                ft.DropdownOption(key=s, text=f"{s} bits")
                for s in ("128", "192", "256")
            ],
            value="128",
            width=220,
        )

        key_field = ft.TextField(
            label="Key (hex)",
            read_only=True,
            width=600,
            prefix_icon=ft.Icons.KEY,
            password=True,
        )

        toggle_btn = IconButton(
            self.page, icon=ft.Icons.VISIBILITY_OFF, tooltip="Show / Hide Key"
        )

        def toggle(_):
            key_field.password = not key_field.password
            toggle_btn.icon = (
                ft.Icons.VISIBILITY
                if not key_field.password
                else ft.Icons.VISIBILITY_OFF
            )
            self.page.update()

        toggle_btn.on_click = toggle

        key_field.suffix = ft.Row(
            [self._copy_button(key_field, "key"), toggle_btn], spacing=4, tight=True
        )

        keys_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("ID")),
                ft.DataColumn(ft.Text("Bits")),
                ft.DataColumn(ft.Text("Key (hex)")),
                ft.DataColumn(ft.Text("Copy")),
                ft.DataColumn(ft.Text("Download")),
                ft.DataColumn(ft.Text("Delete")),
            ],
            rows=[],
            column_spacing=20,
            data_row_max_height=48,
        )

        def refresh_aes_table():
            if not self.conn:
                return
            cur = self.conn.execute(
                "SELECT id, bits, UPPER(hex(key_material)), created_at "
                "FROM user_aes_keys WHERE username=? ORDER BY id DESC",
                (self.page.username,),
            )
            rows = []
            for rid, bits, key_hex, created_at in cur.fetchall():
                created_comp = self._safe_filename_component(str(created_at))
                rows.append(
                    ft.DataRow(
                        cells=[
                            ft.DataCell(ft.Text(str(rid))),
                            ft.DataCell(ft.Text(str(bits))),
                            ft.DataCell(
                                ft.Text(
                                    key_hex,
                                    selectable=True,
                                    max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS,
                                    width=520,
                                )
                            ),
                            ft.DataCell(self._copy_button(key_hex, "key")),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.FILE_DOWNLOAD,
                                    tooltip="Download key",
                                    on_click=lambda _,
                                    v=key_hex,
                                    c=created_comp: self._save_text_to_file(
                                        v, f"aes{len(v) * 4}-{c}", ext="key"
                                    ),
                                )
                            ),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.DELETE_OUTLINE,
                                    tooltip="Delete key",
                                    on_click=lambda _, rr=rid: delete_aes(rr),
                                    icon_color=ft.Colors.RED,
                                )
                            ),
                        ]
                    )
                )
            keys_table.rows = rows
            self.page.update()

        def delete_aes(row_id: int):
            if not self.conn:
                return
            self.conn.execute("DELETE FROM user_aes_keys WHERE id=?", (row_id,))
            self.conn.commit()
            refresh_aes_table()

        def save_aes(_):
            if not key_field.value or not self.conn:
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
                    "INSERT INTO user_aes_keys(username, bits, key_material) VALUES (?, ?, ?)",
                    (self.page.username, int(mode_dd.value), kb),
                )
                self.conn.commit()
            refresh_aes_table()

        def generate_aes(_):
            size = int(mode_dd.value) // 8
            key_field.value = token_hex(size).upper()
            self.page.update()

        refresh_aes_table()

        actions = ft.Row(
            [
                PrimaryButton(
                    self.page,
                    "Generate AES Key",
                    icon=ft.Icons.GENERATING_TOKENS,
                    on_click=generate_aes,
                ),
                TonalButton(self.page, "Save", icon=ft.Icons.SAVE, on_click=save_aes),
            ],
            spacing=GAP_MD,
            wrap=True,
            alignment=ft.MainAxisAlignment.CENTER,
        )

        return self.render_tab(
            [
                section_title("AES Key Management"),
                mode_dd,
                actions,
                key_field,
                ft.Divider(),
                subsection_title("Saved AES keys"),
                vertical_scroll(scrollable_table(keys_table)),
            ]
        )

    # --- RSA ---
    def _rsa_tab(self):
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
            width=500,
            read_only=True,
            prefix_icon=ft.Icons.KEY,
        )

        priv_field = ft.TextField(
            label="Private Key (PEM)",
            multiline=True,
            max_lines=6,
            width=500,
            read_only=True,
            password=True,
            can_reveal_password=False,
            prefix_icon=ft.Icons.LOCK,
        )

        copy_pub = self._copy_button(pub_field, "public key")
        copy_priv = self._copy_button(priv_field, "private key", ft.Icons.COPY_ALL)

        toggle_btn = IconButton(
            self.page, icon=ft.Icons.VISIBILITY_OFF, tooltip="Show / Hide Key"
        )

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
                ft.DataColumn(ft.Text("Download Pub")),
                ft.DataColumn(ft.Text("Download Priv")),
                ft.DataColumn(ft.Text("Delete")),
            ],
            rows=[],
            column_spacing=18,
            data_row_max_height=52,
        )

        def refresh_rsa_table():
            if not self.conn:
                return
            cur = self.conn.execute(
                "SELECT id, bits, public_pem, private_pem, created_at "
                "FROM user_rsa_keys WHERE username=? ORDER BY id DESC",
                (self.page.username,),
            )
            rows = []
            for rid, bits, pub_pem, priv_pem, created_at in cur.fetchall():
                preview = pub_pem.splitlines()[1] if pub_pem else ""
                created_comp = self._safe_filename_component(str(created_at))

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
                            self._make_copy_cell(pub_pem, "public key"),
                            self._make_copy_cell(priv_pem, "private key", ft.Icons.COPY_ALL),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.FILE_DOWNLOAD,
                                    tooltip="Download public PEM",
                                    on_click=lambda _,
                                    v=pub_pem,
                                    c=created_comp: self._save_text_to_file(
                                        v, f"rsa{bits}-{c}.pub", ext="pem"
                                    ),
                                )
                            ),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.FILE_DOWNLOAD,
                                    tooltip="Download private PEM",
                                    on_click=lambda _,
                                    v=priv_pem,
                                    c=created_comp: self._save_text_to_file(
                                        v, f"rsa{bits}-{c}.priv", ext="pem"
                                    ),
                                )
                            ),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.DELETE_OUTLINE,
                                    tooltip="Delete keypair",
                                    on_click=lambda _, rr=rid: delete_rsa(rr),
                                    icon_color=ft.Colors.RED,
                                )
                            ),
                        ]
                    )
                )
            rsa_table.rows = rows
            self.page.update()

        def delete_rsa(row_id: int):
            if not self.conn:
                return
            self.conn.execute("DELETE FROM user_rsa_keys WHERE id=?", (row_id,))
            self.conn.commit()
            refresh_rsa_table()

        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        def generate_rsa(_):
            prog.visible = True
            self.page.update()

            bits = int(size_dd.value)
            key = RSAKey.generate(bits)

            pub_field.value = key.export_key("public")
            priv_field.value = key.export_key("private")

            prog.visible = False
            self.page.update()

        def save_rsa(_):
            if not pub_field.value or not priv_field.value or not self.conn:
                return
            bits = int(size_dd.value)
            exists = self.conn.execute(
                "SELECT 1 FROM user_rsa_keys WHERE username=? AND public_pem=?",
                (self.page.username, pub_field.value),
            ).fetchone()
            if not exists:
                self.conn.execute(
                    "INSERT INTO user_rsa_keys(username, bits, public_pem, private_pem) "
                    "VALUES(?, ?, ?, ?)",
                    (self.page.username, bits, pub_field.value, priv_field.value),
                )
                self.conn.commit()
            refresh_rsa_table()

        refresh_rsa_table()

        actions = ft.Row(
            [
                PrimaryButton(
                    self.page,
                    "Generate RSA Keypair",
                    icon=ft.Icons.GENERATING_TOKENS,
                    on_click=generate_rsa,
                ),
                TonalButton(self.page, "Save", icon=ft.Icons.SAVE, on_click=save_rsa),
                prog,
            ],
            spacing=GAP_MD,
            wrap=True,
            alignment=ft.MainAxisAlignment.CENTER,
        )

        return self.render_tab(
            [
                section_title("RSA Key Management"),
                size_dd,
                actions,
                ft.ResponsiveRow(
                    [
                        ft.Container(
                            pub_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                        ft.Container(
                            priv_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    width=1000,
                ),
                ft.Divider(),
                subsection_title("Saved RSA keys"),
                vertical_scroll(scrollable_table(rsa_table)),
            ]
        )

    # --- DH ---
    def _dh_tab(self):
        sizes = ["2048", "3072", "4096", "6144", "8192"]
        size_dd = ft.Dropdown(
            label="DH Parameter Size",
            options=[ft.DropdownOption(key=s, text=f"{s} bits") for s in sizes],
            value=sizes[0],
            width=220,
        )

        pub_field = ft.TextField(
            label="Public Key (PEM)",
            multiline=True,
            max_lines=8,
            width=500,
            read_only=True,
            prefix_icon=ft.Icons.KEY,
        )

        priv_field = ft.TextField(
            label="Private Key (PEM)",
            multiline=True,
            max_lines=8,
            width=500,
            read_only=True,
            password=True,
            can_reveal_password=False,
            prefix_icon=ft.Icons.LOCK,
        )

        copy_pub = self._copy_button(pub_field, "public key")
        copy_priv = self._copy_button(priv_field, "private key", ft.Icons.COPY_ALL)

        toggle_btn = IconButton(
            self.page, icon=ft.Icons.VISIBILITY_OFF, tooltip="Show / Hide Key"
        )

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

        dh_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("ID")),
                ft.DataColumn(ft.Text("Bits")),
                ft.DataColumn(ft.Text("Public PEM (preview)")),
                ft.DataColumn(ft.Text("Copy Pub")),
                ft.DataColumn(ft.Text("Copy Priv")),
                ft.DataColumn(ft.Text("Download Pub")),
                ft.DataColumn(ft.Text("Download Priv")),
                ft.DataColumn(ft.Text("Delete")),
            ],
            rows=[],
            column_spacing=18,
            data_row_max_height=52,
        )

        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        def generate_dh(_):
            prog.visible = True
            self.page.update()

            bits = int(size_dd.value)

            params = DH.generate_parameters(key_size=bits)
            priv = params.generate_private_key()
            pub = priv.public_key()

            pub_pem = pub.export_key()
            priv_pem = priv.export_key()

            pub_field.value = pub_pem
            priv_field.value = priv_pem

            prog.visible = False
            self.page.update()

        def save_dh(_):
            if not pub_field.value or not priv_field.value or not self.conn:
                return
            bits = int(size_dd.value)
            exists = self.conn.execute(
                "SELECT 1 FROM user_dh_keys WHERE username=? AND public_pem=?",
                (self.page.username, pub_field.value),
            ).fetchone()
            if not exists:
                self.conn.execute(
                    "INSERT INTO user_dh_keys(username, bits, public_pem, private_pem) "
                    "VALUES(?, ?, ?, ?)",
                    (self.page.username, bits, pub_field.value, priv_field.value),
                )
                self.conn.commit()
            refresh_dh_table()

        def refresh_dh_table():
            if not self.conn:
                return
            cur = self.conn.execute(
                "SELECT id, bits, public_pem, private_pem, created_at "
                "FROM user_dh_keys WHERE username=? ORDER BY id DESC",
                (self.page.username,),
            )
            rows = []
            for rid, bits, pub_pem, priv_pem, created_at in cur.fetchall():
                preview = pub_pem.splitlines()[1] if pub_pem else ""
                created_comp = self._safe_filename_component(str(created_at))

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
                            self._make_copy_cell(pub_pem, "public key"),
                            self._make_copy_cell(priv_pem, "private key", ft.Icons.COPY_ALL),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.FILE_DOWNLOAD,
                                    tooltip="Download public PEM",
                                    on_click=lambda _,
                                    v=pub_pem,
                                    c=created_comp: self._save_text_to_file(
                                        v, f"dh{bits}-{c}.pub", ext="pem"
                                    ),
                                )
                            ),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.FILE_DOWNLOAD,
                                    tooltip="Download private PEM",
                                    on_click=lambda _,
                                    v=priv_pem,
                                    c=created_comp: self._save_text_to_file(
                                        v, f"dh{bits}-{c}.priv", ext="pem"
                                    ),
                                )
                            ),
                            ft.DataCell(
                                IconButton(
                                    self.page,
                                    icon=ft.Icons.DELETE_OUTLINE,
                                    tooltip="Delete keypair",
                                    on_click=lambda _, rr=rid: delete_dh(rr),
                                    icon_color=ft.Colors.RED,
                                )
                            ),
                        ]
                    )
                )
            dh_table.rows = rows
            self.page.update()

        def delete_dh(row_id: int):
            if not self.conn:
                return
            self.conn.execute("DELETE FROM user_dh_keys WHERE id=?", (row_id,))
            self.conn.commit()
            refresh_dh_table()

        refresh_dh_table()

        actions = ft.Row(
            [
                PrimaryButton(
                    self.page,
                    "Generate DH Keypair",
                    icon=ft.Icons.GENERATING_TOKENS,
                    on_click=generate_dh,
                ),
                TonalButton(self.page, "Save", icon=ft.Icons.SAVE, on_click=save_dh),
                prog,
            ],
            spacing=GAP_MD,
            wrap=True,
            alignment=ft.MainAxisAlignment.CENTER,
        )

        return self.render_tab(
            [
                section_title("DH Key Management"),
                size_dd,
                actions,
                ft.ResponsiveRow(
                    [
                        ft.Container(
                            pub_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                        ft.Container(
                            priv_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    width=1000,
                ),
                ft.Divider(),
                subsection_title("Saved DH keys"),
                vertical_scroll(scrollable_table(dh_table)),
            ]
        )
