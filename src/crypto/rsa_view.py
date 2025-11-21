import os
from secrets import token_bytes
from typing import Optional

import flet as ft
from pycrypt.asymmetric import RSAKey
from pycrypt.symmetric import AES_CTR

from crypto.base_view import BaseView
from ui.components import IconButton, PrimaryButton, TonalButton
from ui.theme import GAP_MD, section_title


class RSAEncryptDecrypt(BaseView):
    def __init__(self, page: ft.Page):
        super().__init__(page)
        self.page.title = "RSA Encrypt / Decrypt | Cryptographic Suite"

        self.key_picker = ft.FilePicker()
        self.key_picker.on_result = self._on_key_pick
        self._key_field_target = None

        self.file_picker = ft.FilePicker()
        self.page.overlay.extend([self.key_picker, self.file_picker])

    # ---------- Public view ----------
    def view(self) -> ft.View:
        header = self.render_header("🔐 RSA Encrypt / Decrypt")

        tabs = self.render_tabs(
            [
                ft.Tab(
                    text="Text Data",
                    icon=ft.Icons.TEXT_FIELDS_OUTLINED,
                    content=self._text_mode(),
                ),
                ft.Tab(
                    text="Files",
                    icon=ft.Icons.ATTACH_FILE_ROUNDED,
                    content=self._file_mode(),
                ),
            ]
        )

        return self.render_view(header, tabs, "/crypto/rsa-enc-dec")

    # ---------- helpers ----------
    def _pem_type(self, pem):
        s = (pem or "").upper()
        has_private = "PRIVATE KEY" in s or "ENCRYPTED PRIVATE KEY" in s
        has_public = "PUBLIC KEY" in s
        return has_private, has_public

    def _pick_key_for_field(self, field: ft.TextField):
        self._key_field_target = field
        self.key_picker.pick_files(allow_multiple=False)

    def _on_key_pick(self, e: ft.FilePickerResultEvent):
        target = self._key_field_target
        self._key_field_target = None

        if not target:
            return

        if e.files:
            f = e.files[0]
            try:
                path = f.path or f.name
                with open(path, "r", encoding="utf-8") as fh:
                    target.value = fh.read()
                self.page.update()
            except Exception as err:
                target.error_text = f"Failed to import: {err}"
                self.page.update()

    def _key_field(self):
        key_field = ft.TextField(
            label="Key (PEM)",
            multiline=True,
            max_lines=8,
            width=820,
            prefix_icon=ft.Icons.KEY,
            hint_text="Public PEM for encrypt / Private PEM for decrypt",
            password=True
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
            [
                IconButton(
                    self.page,
                    icon=ft.Icons.FILE_UPLOAD,
                    tooltip="Import PEM file",
                    on_click=lambda _: (
                        self._show_not_supported("Uploading files")
                        if self._platform() == "web"
                        else self._pick_key_for_field(key_field)
                    ),
                ),
                toggle_btn,
            ],
            spacing=4,
            tight=True,
        )

        return key_field

    # ---------- Text mode ----------
    def _text_mode(self):
        key_field = self._key_field()

        input_field = ft.TextField(
            prefix_icon=ft.Icons.INPUT,
            label="Input",
            hint_text="Plaintext for encrypt / Ciphertext hex for decrypt",
            multiline=True,
            max_lines=6,
            width=500,
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
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        def _validate_key_for_encrypt(pem: str) -> bool:
            if not pem:
                key_field.error_text = "Public key PEM required for encryption"
                return False
            return True

        def _validate_key_for_decrypt(pem: str) -> bool:
            if not pem:
                key_field.error_text = "Private key PEM required for decryption"
                return False
            has_private, _ = self._pem_type(pem)
            if not has_private:
                key_field.error_text = (
                    "Private key PEM is required for decryption: Public key provided"
                )
                return False
            return True

        def encrypt_click(_):
            self._clear_errors(key_field, input_field, output_field)
            output_field.value = ""
            pem = (key_field.value or "").strip()
            data = input_field.value or ""
            if not _validate_key_for_encrypt(pem):
                self.page.update()
                return
            if not data:
                input_field.error_text = "Plaintext required for encryption"
                self.page.update()
                return

            try:
                bytes.fromhex(data.strip())
                verify_result.value = (
                    "⚠️ Input looks like hex — encrypting raw text that looks like hex."
                )
                verify_result.visible = True
            except Exception:
                pass

            try:
                prog.visible = True
                self.page.update()
                try:
                    key = RSAKey.import_key(pem)
                except Exception as e:
                    key_field.error_text = f"Invalid public key PEM: {e}"
                    return
                try:
                    ct = key.oaep_encrypt(data.encode())
                except Exception as e:
                    output_field.error_text = f"Error encrypting: {e}"
                    return
                output_field.value = ct.hex().upper()
            except Exception as err:
                output_field.error_text = f"Error: {err}"
            finally:
                prog.visible = False
                self.page.update()

        def decrypt_click(_):
            self._clear_errors(key_field, input_field, output_field)
            output_field.value = ""
            pem = (key_field.value or "").strip()
            data_hex = (input_field.value or "").strip()
            if not _validate_key_for_decrypt(pem):
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
                try:
                    key = RSAKey.import_key(pem)
                except Exception as e:
                    key_field.error_text = f"Invalid private key PEM: {e}"
                    return
                try:
                    pt = key.oaep_decrypt(ct)
                except Exception as e:
                    output_field.error_text = f"Decryption failed: {e}"
                    return
                output_field.value = pt.decode(errors="replace")
            except Exception as err:
                output_field.error_text = f"Error: {err}"
            finally:
                prog.visible = False
                self.page.update()

        def fill_input_from_output(_):
            input_field.value = output_field.value or ""
            self.page.update()

        output_field.suffix = ft.Row(
            [
                self._copy_button(output_field, "output"),
                IconButton(
                    self.page,
                    icon=ft.Icons.SYNC_ALT,
                    tooltip="Fill input with output",
                    on_click=fill_input_from_output,
                ),
            ],
            spacing=4,
            tight=True,
        )

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

        return self.render_tab(
            [
                section_title("Text Mode"),
                key_field,
                buttons,
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
            ]
        )

    # ---------- File mode ----------
    def _file_mode(self) -> ft.Control:
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)

        key_field = self._key_field()

        selected_path: Optional[str] = None

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

        self.file_picker.on_result = on_file_pick

        def handle_file(action: str):
            nonlocal selected_path
            key_field.error_text = None
            selected_file_info.color = ft.Colors.AMBER_700

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

            has_private, has_public = self._pem_type(pem)
            if action == "decrypt" and not has_private:
                key_field.error_text = (
                    "Private key PEM required for file decryption: Public key provided"
                )
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

                    try:
                        key = RSAKey.import_key(pem)
                    except Exception as e:
                        key_field.error_text = f"Invalid public key PEM: {e}"
                        self.page.update()
                        return

                    try:
                        enc_session = key.oaep_encrypt(session_key)
                    except Exception as e:
                        selected_file_info.value = (
                            f"❌ RSA session key encryption failed: {e}"
                        )
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return

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

                    try:
                        key = RSAKey.import_key(pem)
                    except Exception as e:
                        key_field.error_text = f"Invalid private key PEM: {e}"
                        self.page.update()
                        return

                    try:
                        session_key = key.oaep_decrypt(enc_session)
                    except Exception as e:
                        selected_file_info.value = (
                            f"❌ RSA session key decryption failed: {e}"
                        )
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return

                    aes = AES_CTR(session_key)
                    try:
                        body = aes.decrypt(ct_body, nonce=nonce)
                    except Exception as e:
                        selected_file_info.value = f"❌ AES decryption failed: {e}"
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return

                    out_name = (
                        selected_path[:-4]
                        if selected_path.endswith(".enc")
                        else selected_path + ".dec"
                    )
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
                        else self.file_picker.pick_files(allow_multiple=False)
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

        return self.render_tab(
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
            ]
        )
