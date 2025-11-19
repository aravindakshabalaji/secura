import os.path
from secrets import token_bytes

import flet as ft
from pycrypt.asymmetric import RSAKey
from pycrypt.symmetric import AES_CTR

from .components import IconButton, PrimaryButton, TonalButton, vertical_scroll
from .theme import GAP_MD, GAP_SM, section_title, surface_card


class RSAEncryptDecrypt:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "RSA Encrypt / Decrypt | Cryptographic Suite"
        self.page.scroll = ft.ScrollMode.AUTO

    # -------- View ---------
    def view(self) -> ft.View:
        header = ft.Row(
            [
                IconButton(
                    self.page,
                    icon=ft.Icons.ARROW_BACK,
                    tooltip="Go Back",
                    on_click=lambda _: self.page.go("/crypto"),
                ),
                ft.Text(
                    "🔐 RSA Encrypt / Decrypt",
                    size=26,
                    weight=ft.FontWeight.BOLD,
                ),
            ],
            alignment=ft.MainAxisAlignment.START,
            spacing=GAP_SM,
        )

        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(
                    text="Text Data",
                    icon=ft.Icons.TEXT_FIELDS_OUTLINED,
                    content=self.text_mode(),
                ),
                ft.Tab(
                    text="Files",
                    icon=ft.Icons.ATTACH_FILE_ROUNDED,
                    content=self.file_mode(),
                ),
            ],
            expand=1,
        )

        return ft.View(
            route="/crypto/rsa-enc-dec",
            controls=[
                ft.Column(
                    [ft.SafeArea(content=header, top=True), ft.Divider(), tabs],
                    expand=True,
                    spacing=GAP_MD,
                )
            ],
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )

    # ------------- Text Mode -------------
    def text_mode(self) -> ft.Control:
        op_dd = ft.Dropdown(
            label="Operation",
            options=[
                ft.DropdownOption(key="encrypt", text="Encrypt (public key)"),
                ft.DropdownOption(key="decrypt", text="Decrypt (private key)"),
            ],
            value="encrypt",
            width=300,
        )

        key_field = ft.TextField(
            label="Key (PEM)",
            multiline=True,
            max_lines=8,
            width=820,
            prefix_icon=ft.Icons.KEY,
            hint_text="Public PEM for encrypt / Private PEM for decrypt",
        )

        key_field.suffix = ft.Row(
            [
                IconButton(
                    self.page,
                    icon=ft.Icons.PASTE,
                    tooltip="Paste PEM from clipboard",
                    on_click=lambda _: self._paste(key_field),
                ),
                IconButton(
                    self.page,
                    icon=ft.Icons.FILE_UPLOAD,
                    tooltip="Import PEM file",
                    on_click=lambda _: (
                        self._show_not_supported("Uploading files")
                        if self._platform() == "web"
                        else key_picker.pick_files(allow_multiple=False),
                    ),
                ),
            ],
            spacing=6,
            tight=True,
        )

        key_picker = ft.FilePicker()
        self.page.overlay.append(key_picker)

        def on_key_pick(e: ft.FilePickerResultEvent):
            if e.files:
                f = e.files[0]
                try:
                    path = f.path or f.name
                    with open(path, "r", encoding="utf-8") as fh:
                        key_field.value = fh.read()
                    self.page.update()
                except Exception as err:
                    key_field.error_text = f"Failed to import: {err}"
                    self.page.update()

        key_picker.on_result = on_key_pick

        input_field = ft.TextField(
            prefix_icon=ft.Icons.INPUT,
            label="Input (plaintext for encrypt / ciphertext hex for decrypt)",
            multiline=True,
            max_lines=6,
            width=500,
        )

        input_field.suffix = IconButton(
            self.page,
            icon=ft.Icons.PASTE,
            tooltip="Paste from clipboard",
            on_click=lambda _: self._paste(input_field),
        )

        output_field = ft.TextField(
            prefix_icon=ft.Icons.OUTPUT,
            label="Output",
            multiline=True,
            max_lines=6,
            width=500,
            read_only=True,
        )

        verify_result = ft.Text("", visible=False)

        def clear_errors():
            for f in (key_field, input_field, output_field):
                f.error_text = None
            verify_result.visible = False
            verify_result.value = ""
            self.page.update()

        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        def encrypt_click(_):
            clear_errors()
            output_field.value = ""
            pem = (key_field.value or "").strip()
            msg = (input_field.value or "").encode()
            if not pem:
                key_field.error_text = "Public key PEM required for encryption"
                self.page.update()
                return
            if not msg:
                input_field.error_text = "Message required"
                self.page.update()
                return
            try:
                prog.visible = True
                self.page.update()
                key = RSAKey.import_key(pem)
                ct = key.oaep_encrypt(msg)
                output_field.value = ct.hex().upper()
            except Exception as err:
                output_field.value = f"Error: {err}"
            finally:
                prog.visible = False
                self.page.update()

        def decrypt_click(_):
            clear_errors()
            output_field.value = ""
            pem = (key_field.value or "").strip()
            data_hex = (input_field.value or "").strip()
            if not pem:
                key_field.error_text = "Private key PEM required for decryption"
                self.page.update()
                return
            if not data_hex:
                input_field.error_text = "Ciphertext hex required"
                self.page.update()
                return
            try:
                ct = bytes.fromhex(data_hex)
            except Exception:
                input_field.error_text = "Invalid hex"
                self.page.update()
                return
            try:
                prog.visible = True
                self.page.update()
                key = RSAKey.import_key(pem)
                pt = key.oaep_decrypt(ct)
                output_field.value = pt.decode(errors="replace")
            except Exception as err:
                output_field.value = f"Error: {err}"
            finally:
                prog.visible = False
                self.page.update()

        def update_op(_=None):
            m = op_dd.value
            if m == "encrypt":
                input_field.label = "Input (plaintext to encrypt)"
                output_field.label = "Output (ciphertext hex)"
                output_field.read_only = True
                output_field.suffix = ft.Row(
                    [
                        IconButton(
                            self.page,
                            icon=ft.Icons.COPY,
                            tooltip="Copy output",
                            on_click=lambda _: self.page.set_clipboard(
                                output_field.value
                            ),
                        )
                    ],
                    spacing=4,
                    tight=True,
                )
            else:
                input_field.label = "Input (ciphertext hex to decrypt)"
                output_field.label = "Output (plaintext)"
                output_field.read_only = True
                output_field.suffix = ft.Row(
                    [
                        IconButton(
                            self.page,
                            icon=ft.Icons.COPY,
                            tooltip="Copy output",
                            on_click=lambda _: self.page.set_clipboard(
                                output_field.value
                            ),
                        )
                    ],
                    spacing=4,
                    tight=True,
                )
            self.page.update()

        op_dd.on_change = update_op
        update_op()

        buttons = ft.Row(
            [
                PrimaryButton(
                    self.page, "Encrypt", icon=ft.Icons.LOCK, on_click=encrypt_click
                ),
                TonalButton(
                    self.page,
                    "Decrypt",
                    icon=ft.Icons.LOCK_OPEN,
                    on_click=decrypt_click,
                ),
                prog,
            ],
            spacing=GAP_MD,
            alignment=ft.MainAxisAlignment.CENTER,
            wrap=True,
        )

        content = ft.Column(
            [
                section_title("Text Mode"),
                op_dd,
                buttons,
                key_field,
                ft.ResponsiveRow(
                    [
                        ft.Container(
                            input_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                        ft.Container(
                            output_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    width=1000,
                ),
                ft.Container(verify_result, alignment=ft.alignment.center),
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        return ft.Container(vertical_scroll(surface_card(content)), padding=10)

    # ------------- File Mode -------------
    def file_mode(self) -> ft.Control:
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)

        key_field = ft.TextField(
            label="Key (PEM)",
            multiline=True,
            max_lines=8,
            width=700,
            prefix_icon=ft.Icons.KEY,
            hint_text="Public PEM for encrypt / Private PEM for decrypt",
        )
        key_field.suffix = ft.Row(
            [
                IconButton(
                    self.page,
                    icon=ft.Icons.PASTE,
                    tooltip="Paste PEM from clipboard",
                    on_click=lambda _: self._paste(key_field),
                ),
                IconButton(
                    self.page,
                    icon=ft.Icons.FILE_UPLOAD,
                    tooltip="Import PEM file",
                    on_click=lambda _: (
                        self._show_not_supported("Uploading files")
                        if self._platform() == "web"
                        else key_picker.pick_files(allow_multiple=False),
                    ),
                ),
            ],
            spacing=6,
            tight=True,
        )

        key_picker = ft.FilePicker()
        self.page.overlay.append(key_picker)

        def on_key_pick(e: ft.FilePickerResultEvent):
            if e.files:
                f = e.files[0]
                try:
                    path = f.path or f.name
                    with open(path, "r", encoding="utf-8") as fh:
                        key_field.value = fh.read()
                    self.page.update()
                except Exception as err:
                    key_field.error_text = f"Failed to import: {err}"
                    self.page.update()

        key_picker.on_result = on_key_pick

        file_picker = ft.FilePicker()
        self.page.overlay.append(file_picker)

        selected_path = None

        def on_file_pick(e: ft.FilePickerResultEvent):
            nonlocal selected_path
            if e.files:
                f = e.files[0]
                selected_path = f.path or f.name
                display_name = f.name or os.path.basename(selected_path or "")
                selected_file_info.value = f"📄 {display_name} selected"
                selected_file_info.color = ft.Colors.GREEN_ACCENT_400
            else:
                selected_path = None
                selected_file_info.value = "❌ No file selected."
                selected_file_info.color = ft.Colors.RED_ACCENT_400
            self.page.update()

        file_picker.on_result = on_file_pick

        # File format (binary):
        # [2 bytes: len_enc_session_key][enc_session_key][8 bytes nonce][ciphertext...]
        def handle_file(action: str):
            nonlocal selected_path
            if not selected_path:
                selected_file_info.value = "Select a file first."
                selected_file_info.color = ft.Colors.RED_400
                self.page.update()
                return
            pem = (key_field.value or "").strip()
            if not pem:
                selected_file_info.value = "Enter a PEM key."
                selected_file_info.color = ft.Colors.RED_400
                self.page.update()
                return
            try:
                prog.visible = True
                self.page.update()
                if action == "encrypt":
                    with open(selected_path, "rb") as f:
                        body = f.read()

                    session_key = token_bytes(32)
                    nonce = token_bytes(8)

                    aes = AES_CTR(session_key)
                    ct_body = aes.encrypt(body, nonce=nonce)

                    key = RSAKey.import_key(pem)
                    enc_session = key.oaep_encrypt(session_key)
                    header = len(enc_session).to_bytes(2, "big")
                    out_bytes = header + enc_session + nonce + ct_body

                    out_name = selected_path + ".enc"
                    with open(out_name, "wb") as out:
                        out.write(out_bytes)

                    selected_file_info.value = f"✅ Encrypted. Saved: {out_name}"
                    selected_file_info.color = ft.Colors.BLUE_ACCENT_200
                else:
                    with open(selected_path, "rb") as f:
                        raw = f.read()

                    if len(raw) < 2 + 1 + 8:
                        raise ValueError("File too short / invalid format")

                    enc_len = int.from_bytes(raw[:2], "big")
                    if len(raw) < 2 + enc_len + 8:
                        raise ValueError("File truncated or invalid")

                    enc_session = raw[2 : 2 + enc_len]
                    nonce = raw[2 + enc_len : 2 + enc_len + 8]
                    ct_body = raw[2 + enc_len + 8 :]

                    key = RSAKey.import_key(pem)
                    session_key = key.oaep_decrypt(enc_session)
                    aes = AES_CTR(session_key)
                    body = aes.decrypt(ct_body, nonce=nonce)

                    if selected_path.endswith(".enc"):
                        out_name = selected_path[:-4]
                    else:
                        out_name = selected_path + ".dec"

                    with open(out_name, "wb") as out:
                        out.write(body)

                    selected_file_info.value = f"✅ Decrypted. Saved: {out_name}"
                    selected_file_info.color = ft.Colors.PURPLE_ACCENT_100
            except Exception as err:
                selected_file_info.value = f"❌ Error: {err}"
                selected_file_info.color = ft.Colors.RED_400
            finally:
                prog.visible = False
                self.page.update()

        buttons = ft.Row(
            [
                PrimaryButton(
                    self.page,
                    "Select File",
                    icon=ft.Icons.FOLDER_OPEN,
                    on_click=lambda _: (
                        self._show_not_supported("Uploading files")
                        if self._platform() == "web"
                        else file_picker.pick_files(allow_multiple=False),
                    ),
                ),
                PrimaryButton(
                    self.page,
                    "Encrypt File",
                    icon=ft.Icons.LOCK,
                    on_click=lambda _: handle_file("encrypt"),
                ),
                TonalButton(
                    self.page,
                    "Decrypt File",
                    icon=ft.Icons.LOCK_OPEN,
                    on_click=lambda _: handle_file("decrypt"),
                ),
                prog,
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=GAP_MD,
            wrap=True,
        )

        content = ft.Column(
            [
                section_title("File Mode"),
                key_field,
                buttons,
                ft.Card(
                    content=ft.Container(
                        selected_file_info,
                        padding=10,
                        alignment=ft.alignment.center,
                        border_radius=10,
                        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
                    ),
                    elevation=2,
                    width=700,
                ),
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        return ft.Container(vertical_scroll(surface_card(content)), padding=10)

    # ---------- Utilities ----------
    def _paste(self, field: ft.TextField):
        field.value = self.page.get_clipboard()
        self.page.update()

    def _platform(self):
        try:
            if self.page.web:
                return "web"
            else:
                return self.page.platform.name.lower()
        except Exception:
            return None

    def _show_not_supported(self, action: str):
        plat = self._platform()
        self.page.open(
            ft.SnackBar(
                ft.Text(
                    f"{action} not supported on platform: {plat if plat else 'unknown'}"
                )
            )
        )
