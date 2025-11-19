import os.path

import flet as ft
from pycrypt.asymmetric import RSAKey

from .components import (
    IconButton,
    PrimaryButton,
    TonalButton,
    vertical_scroll,
)
from .theme import GAP_MD, GAP_SM, section_title, surface_card


class RSASignVerify:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "RSA Sign / Verify | Cryptographic Suite"
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
                ft.Text("✍️ RSA Sign / Verify", size=26, weight=ft.FontWeight.BOLD),
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
            route="/crypto/rsa-sign-verify",
            controls=[
                ft.Column(
                    [ft.SafeArea(content=header, top=True), ft.Divider(), tabs],
                    expand=True,
                    spacing=GAP_MD,
                )
            ],
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )

    # ---------- Text Mode ----------
    def text_mode(self) -> ft.Control:
        op_dd = ft.Dropdown(
            label="Operation",
            options=[
                ft.DropdownOption(key="sign", text="Sign (private key)"),
                ft.DropdownOption(key="verify", text="Verify (public key)"),
            ],
            value="sign",
            width=300,
        )

        key_field = ft.TextField(
            label="Key (PEM)",
            multiline=True,
            max_lines=8,
            width=820,
            prefix_icon=ft.Icons.KEY,
            hint_text="Private PEM for sign / Public PEM for verify",
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
            prefix_icon=ft.Icons.EMAIL_OUTLINED,
            label="Message (plaintext)",
            multiline=True,
            max_lines=6,
            width=820,
        )

        input_field.suffix = IconButton(
            self.page,
            icon=ft.Icons.PASTE,
            tooltip="Paste signature from clipboard",
            on_click=lambda _: self._paste(input_field),
        )

        signature_field = ft.TextField(
            prefix_icon=ft.Icons.VERIFIED_OUTLINED,
            label="Signature (hex)",
            multiline=True,
            max_lines=6,
            width=820,
            read_only=True,
        )

        verify_result = ft.Text("", visible=False)

        def clear_errors():
            for f in (key_field, input_field, signature_field):
                f.error_text = None
            verify_result.visible = False
            verify_result.value = ""
            self.page.update()

        def sign_click(_):
            clear_errors()

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

            try:
                key = RSAKey.import_key(pem)
            except Exception as err:
                key_field.error_text = f"Invalid PEM: {err}"
                self.page.update()
                return

            if key.d is None:
                key_field.error_text = "Private key required to sign"
                self.page.update()
                return

            try:
                sig = key.pss_sign(msg)
                signature_field.value = sig.hex().upper()
            except Exception as err:
                signature_field.value = f"Error: {err}"
            self.page.update()

        def verify_click(_):
            clear_errors()

            signature_field.error_text = None
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

            try:
                key = RSAKey.import_key(pem)
            except Exception as err:
                key_field.error_text = f"Invalid PEM: {err}"
                self.page.update()
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
            self.page.update()

        def update_op(_=None):
            m = op_dd.value
            if m == "sign":
                signature_field.read_only = True
                signature_field.label = "Signature (hex) — produced by signing"

                def copy_signature(_):
                    if signature_field.value:
                        self.page.set_clipboard(signature_field.value)

                signature_field.suffix = IconButton(
                    self.page,
                    icon=ft.Icons.COPY,
                    tooltip="Copy",
                    on_click=copy_signature,
                )
            else:
                signature_field.read_only = False
                signature_field.label = "Signature (hex) — paste to verify"

                signature_field.suffix = IconButton(
                    self.page,
                    icon=ft.Icons.PASTE,
                    tooltip="Paste signature from clipboard",
                    on_click=lambda _: self._paste(signature_field),
                )
            self.page.update()

        op_dd.on_change = update_op
        update_op()

        buttons = ft.Row(
            [
                PrimaryButton(
                    self.page, "Sign", icon=ft.Icons.EDIT, on_click=sign_click
                ),
                TonalButton(
                    self.page, "Verify", icon=ft.Icons.CHECK, on_click=verify_click
                ),
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
                input_field,
                signature_field,
                ft.Container(verify_result, alignment=ft.alignment.center),
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        return ft.Container(vertical_scroll(surface_card(content)), padding=10)

    # ---------- File Mode ----------
    def file_mode(self) -> ft.Control:
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        key_field = ft.TextField(
            label="Key (PEM)",
            multiline=True,
            max_lines=8,
            width=600,
            prefix_icon=ft.Icons.KEY,
            hint_text="Private PEM for sign / Public PEM for verify",
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

        def handle_file(action: str):
            self.page.update()

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
                with open(selected_path, "rb") as f:
                    data = f.read()

                key = RSAKey.import_key(pem)
                if action == "sign":
                    if key.d is None:
                        selected_file_info.value = "Private key required to sign files."
                        selected_file_info.color = ft.Colors.RED_400
                        self.page.update()
                        return

                    prog.visible = True
                    self.page.update()
                    sig = key.pss_sign(data)
                    out_name = selected_path + ".sig"
                    with open(out_name, "wb") as out:
                        out.write(sig)

                    selected_file_info.value = f"✅ Signed. Signature saved: {out_name}"
                    selected_file_info.color = ft.Colors.BLUE_ACCENT_200
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

                    with open(sig_path, "rb") as s:
                        sig = s.read()

                    ok = key.pss_verify(data, sig)
                    selected_file_info.value = (
                        "✅ Signature valid" if ok else "❌ Signature invalid"
                    )
                    selected_file_info.color = ft.Colors.GREEN if ok else ft.Colors.RED
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
                        else file_picker.pick_files(allow_multiple=False),
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
