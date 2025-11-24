# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (c) 2025 Aravindaksha Balaji
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


import os
from secrets import token_bytes
from typing import Optional

import flet as ft
from pycrypt.asymmetric import RSAKey
from pycrypt.symmetric import AES_CTR

from crypto.base_view import BaseView
from ui.components import IconButton, PrimaryButton, TonalButton, TextField
from ui.theme import GAP_MD, section_title


class RSAEncryptDecrypt(BaseView):
    PAIRS = ["Encrypt / Decrypt", "Sign / Verify"]

    def __init__(self, page: ft.Page):
        super().__init__(page)
        self.page.title = "RSA Suite | Cryptographic Suite"

        self.file_picker = ft.FilePicker()
        self.page.overlay.append(self.file_picker)

        self._text_pair = self.PAIRS[0]
        self._file_pair = self.PAIRS[0]
        self._selected_file_path: Optional[str] = None

    # ---------- Public view ----------
    def view(self) -> ft.View:
        header = self.render_header("🔐 RSA Suite")

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

        return self.render_view(header, tabs, "/crypto/rsa")

    # ---------- Helpers ----------
    def _fill_from_output(self, input_field: TextField, output_field: TextField):
        input_field.value = output_field.value or ""
        self.page.update()

    def _pem_type(self, pem: Optional[str]):
        s = (pem or "").upper()
        has_private = "PRIVATE KEY" in s or "ENCRYPTED PRIVATE KEY" in s
        has_public = "PUBLIC KEY" in s
        return has_private, has_public

    def _import_key(self, pem: str, expect_private: Optional[bool] = None):
        try:
            key = RSAKey.import_key(pem)
        except Exception as e:
            raise ValueError(f"Invalid PEM: {e}")
        if expect_private is True and getattr(key, "d", None) is None:
            raise ValueError("Private key required for this operation")
        return key

    # ---------- Shared functions ----------
    def _encrypt_bytes_hybrid(self, pub_pem: str, plaintext: bytes) -> bytes:
        key = self._import_key(pub_pem, expect_private=False)
        session_key = token_bytes(32)
        nonce = token_bytes(8)
        aes = AES_CTR(session_key)
        ct_body = aes.encrypt(plaintext, nonce=nonce)
        enc_session = key.oaep_encrypt(session_key)
        return len(enc_session).to_bytes(2, "big") + enc_session + nonce + ct_body

    def _decrypt_bytes_hybrid(self, priv_pem: str, blob: bytes) -> bytes:
        if len(blob) < 2 + 1 + 8:
            raise ValueError("Input too short / invalid format")
        enc_len = int.from_bytes(blob[:2], "big")
        if len(blob) < 2 + enc_len + 8:
            raise ValueError("Input truncated or invalid")
        enc_session = blob[2 : 2 + enc_len]
        nonce = blob[2 + enc_len : 2 + enc_len + 8]
        ct_body = blob[2 + enc_len + 8 :]
        key = self._import_key(priv_pem, expect_private=True)
        session_key = key.oaep_decrypt(enc_session)
        aes = AES_CTR(session_key)
        return aes.decrypt(ct_body, nonce=nonce)

    # ---------- Text mode ----------
    def _text_mode(self) -> ft.Control:
        key_field = self._key_field(
            "Key (PEM)",
            "Public PEM for Encrypt/Verify — Private PEM for Decrypt/Sign",
            "PEM",
            ["pem"],
        )

        pair_dropdown = ft.Dropdown(
            label="Mode",
            width=220,
            value=self._text_pair,
            options=[ft.dropdown.Option(p) for p in self.PAIRS],
        )

        input_field = TextField(
            prefix_icon=ft.Icons.INPUT,
            label="Input",
            multiline=True,
            max_lines=6,
            width=500,
        )
        input_field.suffix = self._paste_button(input_field)

        output_field = TextField(
            prefix_icon=ft.Icons.OUTPUT,
            label="Output",
            multiline=True,
            max_lines=6,
            width=500,
            read_only=True,
        )

        signature_field = TextField(
            prefix_icon=ft.Icons.VERIFIED_OUTLINED,
            label="Signature (hex)",
            multiline=True,
            max_lines=6,
            width=500,
        )
        signature_field.suffix = self._copy_button(signature_field, "signature")

        verify_result = ft.Text("", visible=False)
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        def _update_ui_for_pair(e=None):
            self._text_pair = pair_dropdown.value
            if self._text_pair == "Encrypt / Decrypt":
                input_field.label = "Input"
                input_field.hint_text = "Plaintext / Hex Ciphertext"

                output_field.label = "Output"
                output_field.visible = True

                key_field.hint_text = "Public PEM for encrypt / Private PEM for decrypt"

                signature_field.visible = False
            else:
                input_field.label = "Message (plaintext)"
                input_field.hint_text = ""

                signature_field.label = "Signature (hex)"
                signature_field.visible = True

                key_field.hint_text = "Private PEM for sign / Public PEM for verify"
                output_field.visible = False

            self._clear_errors(input_field, output_field, signature_field, key_field)
            verify_result.visible = False
            self.page.update()

        def _on_primary(_):
            action = pair_dropdown.value.split("/")[0].strip()
            _perform_text_action(action)

        def _on_tonal(_):
            action = pair_dropdown.value.split("/")[1].strip()
            _perform_text_action(action)

        def _perform_text_action(action: str):
            self._clear_errors(key_field, input_field, output_field, signature_field)
            output_field.value = ""
            signature_field.value = signature_field.value or ""
            verify_result.visible = False

            pem = (key_field.value or "").strip()
            if not pem:
                key_field.error_text = "Key PEM required"
                self.page.update()
                return

            raw = (input_field.value or "").strip()

            try:
                prog.visible = True
                self.page.update()

                if action == "Encrypt":
                    if not raw:
                        input_field.error_text = "Plaintext required for encryption"
                        return
                    out = self._encrypt_bytes_hybrid(pem, raw.encode())
                    output_field.value = out.hex().upper()

                elif action == "Decrypt":
                    if not raw:
                        input_field.error_text = (
                            "Ciphertext hex required for decryption"
                        )
                        return
                    try:
                        blob = bytes.fromhex(raw)
                    except Exception:
                        input_field.error_text = "Invalid hex"
                        return
                    pt = self._decrypt_bytes_hybrid(pem, blob)
                    output_field.value = pt.decode(errors="replace")

                elif action == "Sign":
                    if not raw:
                        input_field.error_text = "Message required for signing"
                        return
                    key = self._import_key(pem, expect_private=True)
                    sig = key.pss_sign(raw.encode())
                    signature_field.value = sig.hex().upper()
                    verify_result.visible = True
                    verify_result.value = "✅ Message signed"
                    verify_result.color = ft.Colors.GREEN

                elif action == "Verify":
                    sig_hex = (signature_field.value or "").strip()
                    if not raw:
                        input_field.error_text = "Message required"
                        self.page.update()
                        return
                    if not sig_hex:
                        signature_field.error_text = "Signature hex required"
                        self.page.update()
                        return
                    try:
                        sig = bytes.fromhex(sig_hex)
                    except Exception:
                        signature_field.error_text = "Signature must be valid hex"
                        self.page.update()
                        return

                    key = self._import_key(pem, expect_private=False)
                    ok = key.pss_verify(raw.encode(), sig)
                    verify_result.visible = True
                    verify_result.value = (
                        "✅ Signature valid" if ok else "❌ Signature invalid"
                    )
                    verify_result.color = ft.Colors.GREEN if ok else ft.Colors.RED

            except Exception as err:
                if isinstance(err, ValueError) and "Invalid PEM" in str(err):
                    key_field.error_text = str(err)
                else:
                    output_field.error_text = f"Error: {err}"
            finally:
                prog.visible = False
                self.page.update()

        output_field.suffix = ft.Row(
            [
                self._copy_button(output_field, "output"),
                IconButton(
                    self.page,
                    icon=ft.Icons.SYNC_ALT,
                    tooltip="Fill input with output",
                    on_click=lambda _: self._fill_from_output(
                        input_field, output_field
                    ),
                ),
            ],
            spacing=4,
            tight=True,
        )

        signature_field.suffix = ft.Row(
            [
                self._copy_button(signature_field, "signature"),
            ],
            spacing=4,
            tight=True,
        )

        buttons = ft.Row(
            [
                PrimaryButton(
                    self.page, "Primary", icon=ft.Icons.LOCK, on_click=_on_primary
                ),
                TonalButton(
                    self.page, "Secondary", icon=ft.Icons.LOCK_OPEN, on_click=_on_tonal
                ),
                prog,
            ],
            spacing=GAP_MD,
            alignment=ft.MainAxisAlignment.CENTER,
            wrap=True,
        )

        def _update_button_labels(e=None):
            pair = pair_dropdown.value
            first, second = [p.strip() for p in pair.split("/")]
            if first == "Encrypt":
                buttons.controls[0].text = "Encrypt"
                buttons.controls[0].icon = ft.Icons.LOCK
            else:
                buttons.controls[0].text = "Sign"
                buttons.controls[0].icon = ft.Icons.EDIT

            if second == "Decrypt":
                buttons.controls[1].text = "Decrypt"
                buttons.controls[1].icon = ft.Icons.LOCK_OPEN
            else:
                buttons.controls[1].text = "Verify"
                buttons.controls[1].icon = ft.Icons.CHECK

            self.page.update()

        pair_dropdown.on_change = lambda e=None: (
            _update_ui_for_pair(e),
            _update_button_labels(e),
        )
        _update_button_labels()

        _update_ui_for_pair()

        return self.render_tab(
            [
                section_title("Text Mode"),
                pair_dropdown,
                key_field,
                buttons,
                ft.ResponsiveRow(
                    [
                        ft.Container(
                            input_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                        ft.Container(
                            ft.Column([output_field, signature_field]),
                            alignment=ft.alignment.center,
                            col={"sm": 6},
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

        key_field = self._key_field(
            "Key (PEM)",
            "Public PEM for Encrypt/Verify — Private PEM for Decrypt/Sign",
            "PEM",
            ["pem"],
        )

        pair_dropdown = ft.Dropdown(
            label="Mode",
            width=220,
            value=self._file_pair,
            options=[ft.dropdown.Option(p) for p in self.PAIRS],
        )

        def on_file_pick(e: ft.FilePickerResultEvent):
            if e.files:
                f = e.files[0]
                self._selected_file_path = f.path or f.name
                display_name = f.name or os.path.basename(
                    self._selected_file_path or ""
                )
                selected_file_info.value = f"📄 {display_name} selected"
                selected_file_info.color = ft.Colors.GREEN_ACCENT_400
            else:
                self._selected_file_path = None
                selected_file_info.value = "❌ No file selected."
                selected_file_info.color = ft.Colors.RED_ACCENT_400
            self.page.update()

        self.file_picker.on_result = on_file_pick

        def _update_file_buttons(e=None):
            pair = pair_dropdown.value
            first, second = [p.strip() for p in pair.split("/")]
            try:
                buttons.controls[1].text = first
                buttons.controls[1].icon = (
                    ft.Icons.LOCK if first == "Encrypt" else ft.Icons.EDIT
                )
                buttons.controls[1].on_click = lambda _, k=first: _handle_file_action(k)

                buttons.controls[2].text = second
                buttons.controls[2].icon = (
                    ft.Icons.LOCK_OPEN if second == "Decrypt" else ft.Icons.CHECK
                )
                buttons.controls[2].on_click = lambda _, k=second: _handle_file_action(
                    k
                )

            except Exception:
                pass

            self.page.update()

        def _handle_file_action(kind: str):
            key_field.error_text = None
            selected_file_info.color = ft.Colors.AMBER_700

            if not self._selected_file_path:
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
            if kind == "Decrypt" and not has_private:
                key_field.error_text = (
                    "Private key PEM required for file decryption: Public key provided"
                )
                self.page.update()
                return
            if kind == "Sign" and not has_private:
                key_field.error_text = (
                    "Private key PEM required to sign files (provided PEM looks public)"
                )
                self.page.update()
                return
            if kind == "Verify" and not (has_public or has_private):
                key_field.error_text = (
                    "Public key PEM required to verify files (unrecognized PEM)"
                )
                self.page.update()
                return

            try:
                prog.visible = True
                self.page.update()

                if kind == "Encrypt":
                    with open(self._selected_file_path, "rb") as f:
                        body = f.read()
                    out_bytes = self._encrypt_bytes_hybrid(pem, body)
                    out_name = self._selected_file_path + ".enc"
                    with open(out_name, "wb") as out:
                        out.write(out_bytes)
                    selected_file_info.value = f"✅ Encrypted. Saved: {out_name}"
                    selected_file_info.color = ft.Colors.BLUE_ACCENT_200

                elif kind == "Decrypt":
                    with open(self._selected_file_path, "rb") as f:
                        raw = f.read()
                    body = self._decrypt_bytes_hybrid(pem, raw)
                    out_name = (
                        self._selected_file_path[:-4]
                        if self._selected_file_path.endswith(".enc")
                        else self._selected_file_path + ".dec"
                    )
                    with open(out_name, "wb") as out:
                        out.write(body)
                    selected_file_info.value = f"✅ Decrypted. Saved: {out_name}"
                    selected_file_info.color = ft.Colors.PURPLE_ACCENT_100

                elif kind == "Sign":
                    with open(self._selected_file_path, "rb") as f:
                        data = f.read()
                    key = self._import_key(pem, expect_private=True)
                    sig = key.pss_sign(data)
                    out_name = self._selected_file_path + ".sig"
                    with open(out_name, "wb") as out:
                        out.write(sig)
                    selected_file_info.value = f"✅ Signed. Signature saved: {out_name}"
                    selected_file_info.color = ft.Colors.BLUE_ACCENT_200

                else:
                    with open(self._selected_file_path, "rb") as f:
                        data = f.read()
                    sig_path = self._selected_file_path + ".sig"
                    if not os.path.exists(sig_path):
                        selected_file_info.value = (
                            "Signature file not found (.sig expected)."
                        )
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return
                    with open(sig_path, "rb") as s:
                        sig = s.read()
                    key = self._import_key(pem, expect_private=False)
                    ok = key.pss_verify(data, sig)
                    selected_file_info.value = (
                        "✅ Signature valid" if ok else "❌ Signature invalid"
                    )
                    selected_file_info.color = ft.Colors.GREEN if ok else ft.Colors.RED

            except Exception as err:
                selected_file_info.value = f"❌ Error: {err}"
                selected_file_info.color = ft.Colors.RED_400
            finally:
                prog.visible = False
                self.page.update()

        def _make_file_buttons():
            pair = pair_dropdown.value
            first, second = [p.strip() for p in pair.split("/")]
            primary = PrimaryButton(
                self.page,
                first,
                icon=ft.Icons.LOCK if first == "Encrypt" else ft.Icons.EDIT,
                on_click=lambda _: _handle_file_action(first),
            )
            tonal = TonalButton(
                self.page,
                second,
                icon=ft.Icons.LOCK_OPEN if second == "Decrypt" else ft.Icons.CHECK,
                on_click=lambda _: _handle_file_action(second),
            )
            return primary, tonal

        primary_btn, tonal_btn = _make_file_buttons()

        def _on_pair_change(e=None):
            nonlocal primary_btn, tonal_btn
            primary_btn, tonal_btn = _make_file_buttons()

            first, second = [p.strip() for p in pair_dropdown.value.split("/")]
            key_field.hint_text = (
                "Public PEM for encrypt / Private PEM for decrypt"
                if first == "Encrypt"
                else "Private PEM for sign / Public PEM for verify"
            )

            self.page.update()

        pair_dropdown.on_change = lambda e=None: (
            _on_pair_change(e),
            _update_file_buttons(e),
        )

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
                primary_btn,
                tonal_btn,
                prog,
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=GAP_MD,
            wrap=True,
        )

        return self.render_tab(
            [
                section_title("File Mode"),
                pair_dropdown,
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
