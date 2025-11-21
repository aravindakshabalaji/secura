import os
from typing import Optional

import flet as ft
from pycrypt.asymmetric import RSAKey

from crypto.base_view import BaseView
from ui.components import IconButton, PrimaryButton, TonalButton
from ui.theme import GAP_MD, section_title


class RSASignVerify(BaseView):
    def __init__(self, page: ft.Page):
        super().__init__(page)
        self.page.title = "RSA Sign / Verify | Cryptographic Suite"

        self.key_picker = ft.FilePicker()
        self.key_picker.on_result = self._on_key_pick
        self._key_field_target = None

        self.file_picker = ft.FilePicker()
        self.page.overlay.extend([self.key_picker, self.file_picker])

    # ---------- Public view ----------
    def view(self) -> ft.View:
        header = self.render_header("✍️ RSA Sign / Verify")

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

        return self.render_view(header, tabs, "/crypto/rsa-sign-verify")

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
            prefix_icon=ft.Icons.EMAIL_OUTLINED,
            label="Message (plaintext)",
            multiline=True,
            max_lines=6,
            width=500,
        )

        signature_field = ft.TextField(
            prefix_icon=ft.Icons.VERIFIED_OUTLINED,
            label="Signature (hex)",
            multiline=True,
            max_lines=6,
            width=500,
        )

        verify_result = ft.Text("", visible=False)
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        def sign_click(_):
            self._clear_errors(key_field, input_field, signature_field)

            signature_field.value = ""
            pem = (key_field.value or "").strip()
            msg = (input_field.value or "").encode()

            if not pem:
                key_field.error_text = "Private key PEM required for signing"
                self.page.update()
                return
            if not msg:
                input_field.error_text = "Message required"
                self.page.update()
                return

            has_private, has_public = self._pem_type(pem)
            if has_public and not has_private:
                key_field.error_text = (
                    "Private key PEM required for signing: Public key provided"
                )
                self.page.update()
                return

            try:
                prog.visible = True
                self.page.update()
                try:
                    key = RSAKey.import_key(pem)
                except Exception as err:
                    key_field.error_text = f"Invalid PEM: {err}"
                    return

                if key.d is None:
                    key_field.error_text = "Private key required for signing"
                    return

                try:
                    sig = key.pss_sign(msg)
                    signature_field.value = sig.hex().upper()

                    verify_result.visible = True
                    verify_result.value = "✅ Message signed"
                    verify_result.color = ft.Colors.GREEN
                except Exception as err:
                    signature_field.error_text = f"Error signing: {err}"
            except Exception as err:
                signature_field.error_text = f"Error: {err}"
            finally:
                prog.visible = False
                self.page.update()

        def verify_click(_):
            self._clear_errors(key_field, input_field, signature_field)

            pem = (key_field.value or "").strip()
            msg = (input_field.value or "").encode()
            sig_hex = (signature_field.value or "").strip()

            if not pem:
                key_field.error_text = "Public key PEM required for verification"
                self.page.update()
                return
            if not msg:
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

            has_private, has_public = self._pem_type(pem)
            if not has_public and not has_private:
                key_field.error_text = "Valid Public key PEM required for verification"
                self.page.update()
                return

            try:
                prog.visible = True
                self.page.update()
                try:
                    key = RSAKey.import_key(pem)
                except Exception as err:
                    key_field.error_text = f"Invalid PEM: {err}"
                    return

                try:
                    ok = key.pss_verify(msg, sig)
                    verify_result.visible = True
                    verify_result.value = (
                        "✅ Signature valid" if ok else "❌ Signature invalid"
                    )
                    verify_result.color = ft.Colors.GREEN if ok else ft.Colors.RED
                except Exception as err:
                    verify_result.visible = True
                    verify_result.value = f"❌ Verification error: {err}"
                    verify_result.color = ft.Colors.RED
            except Exception as err:
                verify_result.visible = True
                verify_result.value = f"❌ Error: {err}"
                verify_result.color = ft.Colors.RED
            finally:
                prog.visible = False
                self.page.update()

        buttons = ft.Row(
            [
                PrimaryButton(
                    self.page, "Sign", icon=ft.Icons.EDIT, on_click=sign_click
                ),
                TonalButton(
                    self.page, "Verify", icon=ft.Icons.CHECK, on_click=verify_click
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
                            signature_field,
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
    def _file_mode(self):
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

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
            if action == "sign" and not has_private:
                key_field.error_text = (
                    "Private key PEM required to sign files (provided PEM looks public)"
                )
                self.page.update()
                return
            if action == "verify" and not (has_public or has_private):
                key_field.error_text = (
                    "Public key PEM required to verify files (unrecognized PEM)"
                )
                self.page.update()
                return

            try:
                with open(selected_path, "rb") as f:
                    data = f.read()

                try:
                    key = RSAKey.import_key(pem)
                except Exception as err:
                    key_field.error_text = f"Invalid PEM: {err}"
                    self.page.update()
                    return

                if action == "sign":
                    if key.d is None:
                        selected_file_info.value = "Private key required to sign files."
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return

                    try:
                        prog.visible = True
                        self.page.update()
                        sig = key.pss_sign(data)
                        out_name = selected_path + ".sig"
                        with open(out_name, "wb") as out:
                            out.write(sig)
                        selected_file_info.value = (
                            f"✅ Signed. Signature saved: {out_name}"
                        )
                        selected_file_info.color = ft.Colors.BLUE_ACCENT_200
                    except Exception as err:
                        selected_file_info.value = f"❌ Signing error: {err}"
                        selected_file_info.color = ft.Colors.RED_400
                    finally:
                        prog.visible = False
                        self.page.update()
                else:
                    sig_path = selected_path + ".sig"
                    if not os.path.exists(sig_path):
                        selected_file_info.value = (
                            "Signature file not found (.sig expected)."
                        )
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return

                    try:
                        with open(sig_path, "rb") as s:
                            sig = s.read()
                    except Exception as err:
                        selected_file_info.value = (
                            f"❌ Could not read signature file: {err}"
                        )
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return

                    try:
                        prog.visible = True
                        self.page.update()
                        ok = key.pss_verify(data, sig)
                        selected_file_info.value = (
                            "✅ Signature valid" if ok else "❌ Signature invalid"
                        )
                        selected_file_info.color = (
                            ft.Colors.GREEN if ok else ft.Colors.RED
                        )
                    except Exception as err:
                        selected_file_info.value = f"❌ Verification error: {err}"
                        selected_file_info.color = ft.Colors.RED_400
                    finally:
                        prog.visible = False
                        self.page.update()
            except Exception as err:
                selected_file_info.value = f"❌ Error: {err}"
                selected_file_info.color = ft.Colors.RED_400
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
                    "Sign File",
                    icon=ft.Icons.LOCK,
                    on_click=lambda _: handle_file("sign"),
                ),
                TonalButton(
                    self.page,
                    "Verify File",
                    icon=ft.Icons.CHECK,
                    on_click=lambda _: handle_file("verify"),
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
