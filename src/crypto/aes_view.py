import os
from secrets import token_bytes, token_hex

import flet as ft
from pycrypt.symmetric import AES_CBC, AES_CTR, AES_ECB, AES_GCM

from crypto.base_view import BaseView
from ui.components import IconButton, PrimaryButton, TonalButton
from ui.theme import GAP_MD, section_title


class AESEncryptDecrypt(BaseView):
    def __init__(self, page: ft.Page):
        super().__init__(page)
        self.page.title = "AES Encrypt / Decrypt | Cryptographic Suite"

        self.text_file_picker = ft.FilePicker()
        self.key_picker = ft.FilePicker()
        self.page.overlay.extend([self.text_file_picker, self.key_picker])

        self._key_field_target: ft.TextField | None = None
        self.key_picker.on_result = self._on_key_file_result

    # ---------- Public view ----------
    def view(self):
        header = self.render_header("🔐 AES Encrypt / Decrypt")

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
            ],
        )

        return self.render_view(header, tabs, "/crypto/aes-enc-dec")

    @staticmethod
    def _is_hex(text):
        try:
            bytes.fromhex((text or "").strip())
            return True
        except Exception:
            return False

    def _validate_key(self, key_field):
        raw = (key_field.value or "").strip()
        try:
            key = bytes.fromhex(raw)
        except Exception:
            key_field.error_text = "Key must be valid hex"
            self.page.update()
            return None

        if len(key) not in (16, 24, 32):
            key_field.error_text = "Key must be 32/48/64 hex characters long"
            self.page.update()
            return None
        return key

    # ---------- key file handling ----------
    def _on_key_file_result(self, e: ft.FilePickerResultEvent):
        target = self._key_field_target
        self._key_field_target = None

        if not target:
            return

        if not e.files:
            target.error_text = "No file selected"
            self.page.update()
            return

        f = e.files[0]
        path = f.path or f.name
        try:
            with open(path, "rb") as fh:
                raw = fh.read()

            try:
                txt = raw.decode("utf-8").strip()
            except Exception:
                txt = None

            if txt:
                stripped = txt.strip()
                is_hex = all(
                    ch in "0123456789abcdefABCDEF"
                    for ch in stripped.replace("\n", "")
                    .replace("\r", "")
                    .replace(" ", "")
                )
                if is_hex:
                    target.value = stripped.upper()
                else:
                    target.value = txt
            else:
                target.value = raw.hex().upper()

            target.error_text = None
            self.page.update()
        except Exception as err:
            target.error_text = f"Failed to import: {err}"
            self.page.update()

    def _pick_key_for_field(self, field: ft.TextField):
        self._key_field_target = field
        self.key_picker.pick_files(allow_multiple=False)

    def _key_field(self):
        key_field = ft.TextField(
            label="Key (hex)",
            hint_text="32/48/64 characters",
            password=True,
            prefix_icon=ft.Icons.KEY,
            width=520,
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
                    tooltip="Import key file",
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
        mode_dd = ft.Dropdown(
            label="Mode",
            options=[
                ft.DropdownOption(key="ECB", text="Electronic Code Book (ECB)"),
                ft.DropdownOption(key="CBC", text="Cipher Block Chaining (CBC)"),
                ft.DropdownOption(key="CTR", text="Counter (CTR)"),
                ft.DropdownOption(key="GCM", text="Galois/Counter Mode (GCM)"),
            ],
            value="ECB",
            width=300,
        )

        key_field = self._key_field()

        iv_field = ft.TextField(
            prefix_icon=ft.Icons.TAG,
            label="IV (hex)",
            hint_text="32 characters",
            width=420,
            visible=False,
        )
        nonce_field = ft.TextField(
            prefix_icon=ft.Icons.TAG, label="Nonce (hex)", width=420, visible=False
        )
        aad_field = ft.TextField(
            prefix_icon=ft.Icons.STORAGE,
            label="AAD (hex)",
            hint_text="Optional for GCM",
            width=420,
            visible=False,
        )
        tag_field = ft.TextField(
            prefix_icon=ft.Icons.LOCAL_OFFER,
            label="Tag (hex)",
            hint_text="32 characters - required for GCM decrypt",
            width=420,
            visible=False,
        )

        def gen_iv(_):
            iv_field.value = token_hex(16).upper()
            self.page.update()

        def gen_nonce(_):
            mode = mode_dd.value
            size = 8 if mode == "CTR" else 12
            nonce_field.value = token_hex(size).upper()
            self.page.update()

        iv_field.suffix = IconButton(
            self.page,
            icon=ft.Icons.CACHED,
            tooltip="Generate random IV",
            on_click=gen_iv,
        )
        nonce_field.suffix = IconButton(
            self.page,
            icon=ft.Icons.CACHED,
            tooltip="Generate random nonce",
            on_click=gen_nonce,
        )

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

        warning_msg = ft.Text("", color=ft.Colors.AMBER_700, visible=False)

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

        def update_mode(_=None):
            m = mode_dd.value
            iv_field.visible = m == "CBC"
            nonce_field.visible = m in ("CTR", "GCM")
            aad_field.visible = m == "GCM"
            tag_field.visible = m == "GCM"

            if m == "CBC":
                iv_field.label = "IV (hex)"
                iv_field.hint_text = "32 characters"
            elif m == "CTR":
                nonce_field.label = "Nonce (hex)"
                nonce_field.hint_text = "16 characters"
            elif m == "GCM":
                nonce_field.label = "Nonce (hex)"
                nonce_field.hint_text = "24 characters"
                tag_field.label = "Tag (hex)"
                tag_field.hint_text = "32 characters - generated by encrypt"

            self.page.update()

        mode_dd.on_change = update_mode
        update_mode()

        def error_check_field(field, value_len=None, required=True):
            if not field.value and required:
                field.error_text = "Required field"
                self.page.update()
                return

            try:
                value = bytes.fromhex(field.value.strip())
            except Exception:
                field.error_text = "Field must contain valid hex"
                self.page.update()
                return

            if value_len and len(value) != value_len:
                field.error_text = f"Field value must be {value_len * 2} characters"
                self.page.update()
                return

            return value

        def encrypt_click(_):
            self._clear_errors(
                key_field,
                input_field,
                iv_field,
                nonce_field,
                aad_field,
                tag_field,
                warning=warning_msg,
            )
            output_field.value = ""
            key = self._validate_key(key_field)
            if key is None:
                return

            data = input_field.value or ""
            if not data:
                input_field.error_text = "Plaintext required for encryption"
                self.page.update()
                return

            if self._is_hex(data):
                warning_msg.value = (
                    "⚠️ Input looks like hex: proceeding to encrypt as plaintext."
                )
                warning_msg.visible = True

            mode = mode_dd.value

            try:
                if mode == "ECB":
                    c = AES_ECB(key)
                    ct = c.encrypt(data.encode())
                    output_field.value = ct.hex().upper()

                elif mode == "CBC":
                    iv = error_check_field(iv_field, 16)
                    c = AES_CBC(key)
                    ct = c.encrypt(data.encode(), iv=iv)
                    output_field.value = ct.hex().upper()

                elif mode == "CTR":
                    nonce = error_check_field(nonce_field, 8)
                    c = AES_CTR(key)
                    ct = c.encrypt(data.encode(), nonce=nonce)
                    output_field.value = ct.hex().upper()

                elif mode == "GCM":
                    nonce = error_check_field(nonce_field, 12)
                    aad = error_check_field(aad_field, required=False)
                    c = AES_GCM(key)
                    ct, tag = c.encrypt(data.encode(), nonce=nonce, aad=aad)
                    output_field.value = ct.hex().upper()
                    tag_field.value = tag.hex().upper()
                else:
                    output_field.value = "Unsupported mode"
            except Exception as err:
                output_field.value = f"Error: {err}"

            self.page.update()

        def decrypt_click(_):
            self._clear_errors(
                key_field,
                input_field,
                iv_field,
                nonce_field,
                aad_field,
                tag_field,
                warning=warning_msg,
            )
            output_field.value = ""
            key = self._validate_key(key_field)
            if key is None:
                return

            data_hex = (input_field.value or "").strip()
            if not data_hex:
                input_field.error_text = "Ciphertext hex required for decryption"
                self.page.update()
                return
            if not self._is_hex(data_hex):
                input_field.error_text = "Decrypt expects ciphertext hex"
                self.page.update()
                return

            try:
                ct_bytes = bytes.fromhex(data_hex)
            except Exception:
                input_field.error_text = "Invalid hex"
                self.page.update()
                return

            mode = mode_dd.value

            try:
                if mode == "ECB":
                    c = AES_ECB(key)
                    pt = c.decrypt(ct_bytes)
                    output_field.value = pt.decode(errors="replace")

                elif mode == "CBC":
                    iv = error_check_field(iv_field, 16)
                    c = AES_CBC(key)
                    pt = c.decrypt(ct_bytes, iv=iv)
                    output_field.value = pt.decode(errors="replace")

                elif mode == "CTR":
                    nonce = error_check_field(nonce_field, 8)
                    c = AES_CTR(key)
                    pt = c.decrypt(ct_bytes, nonce=nonce)
                    output_field.value = pt.decode(errors="replace")

                elif mode == "GCM":
                    if not tag_field.value or not self._is_hex(tag_field.value):
                        tag_field.error_text = "Valid tag hex required for GCM decrypt"
                        self.page.update()
                        return

                    nonce = error_check_field(nonce_field, 12)
                    tag = bytes.fromhex(tag_field.value.strip())
                    aad = error_check_field(aad_field, required=False)
                    c = AES_GCM(key)
                    pt = c.decrypt(ct_bytes, nonce=nonce, tag=tag, aad=aad)
                    output_field.value = pt.decode(errors="replace")
                else:
                    output_field.value = "Unsupported mode"
            except Exception as err:
                output_field.value = f"Error: {err}"

            self.page.update()

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
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=GAP_MD,
            wrap=True,
        )

        return self.render_tab(
            [
                section_title("Text Mode"),
                mode_dd,
                key_field,
                iv_field,
                nonce_field,
                ft.ResponsiveRow(
                    [
                        ft.Container(aad_field, col={"sm": 6}),
                        ft.Container(tag_field, col={"sm": 6}),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    width=840,
                ),
                buttons,
                ft.Container(warning_msg, alignment=ft.alignment.center),
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
            ]
        )

    # ---------- File mode ----------
    def _file_mode(self):
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)

        key_field = self._key_field()

        selected_path: str | None = None

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

        self.text_file_picker.on_result = on_file_pick

        def handle_file(action: str):
            nonlocal selected_path
            if not selected_path:
                selected_file_info.value = "Select a file first."
                selected_file_info.color = ft.Colors.RED_400
                self.page.update()
                return
            if not key_field.value:
                selected_file_info.value = "Enter a valid hex key."
                selected_file_info.color = ft.Colors.RED_400
                self.page.update()
                return

            try:
                key = bytes.fromhex(key_field.value.strip())
            except Exception:
                selected_file_info.value = "❌ Key must be valid hex"
                selected_file_info.color = ft.Colors.RED_400
                self.page.update()
                return

            prog.visible = True
            self.page.update()

            try:
                with open(selected_path, "rb") as f:
                    data = f.read()

                cipher = AES_CTR(key)
                if action == "encrypt":
                    nonce = token_bytes(8)
                    result = nonce + cipher.encrypt(data, nonce=nonce)
                    out_name = selected_path + ".enc"
                    message = "Encrypted."
                else:
                    nonce, body = data[:8], data[8:]
                    result = cipher.decrypt(body, nonce=nonce)
                    out_name = (
                        selected_path[:-4]
                        if selected_path.endswith(".enc")
                        else selected_path + ".dec"
                    )
                    message = "Decrypted."
                with open(out_name, "wb") as f:
                    f.write(result)

                selected_file_info.value = f"✅ {message} Saved: {out_name}"
                selected_file_info.color = (
                    ft.Colors.BLUE_ACCENT_200
                    if action == "encrypt"
                    else ft.Colors.PURPLE_ACCENT_100
                )
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
                        else self.text_file_picker.pick_files(allow_multiple=False)
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
                    width=500,
                ),
            ]
        )
