import os.path
from secrets import token_bytes, token_hex

import flet as ft
from pycrypt.symmetric import AES_CBC, AES_CTR, AES_ECB, AES_GCM

from .components import IconButton, PrimaryButton, TonalButton, vertical_scroll
from .theme import GAP_MD, GAP_SM, section_title, surface_card


class AESEncryptDecrypt:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "AES Encrypt / Decrypt | Cryptographic Suite"
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
                ft.Text("🔐 Encrypt / Decrypt", size=26, weight=ft.FontWeight.BOLD),
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
            route="/crypto/aes-enc-dec",
            controls=[
                ft.Column(
                    [ft.SafeArea(content=header, top=True), ft.Divider(), tabs],
                    expand=True,
                    spacing=GAP_MD,
                )
            ],
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )

    # -------- Text mode ---------
    def text_mode(self) -> ft.Control:
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

        key_field = ft.TextField(
            label="Key (hex, 32/48/64 characters)",
            password=True,
            can_reveal_password=True,
            prefix_icon=ft.Icons.KEY,
            width=520,
        )
        key_field.suffix = IconButton(
            self.page,
            icon=ft.Icons.PASTE,
            tooltip="Paste key from clipboard",
            on_click=lambda _: self._paste(key_field),
        )

        iv_field = ft.TextField(
            prefix_icon=ft.Icons.TAG,
            label="IV (hex, 32 characters)",
            width=420,
            visible=False,
        )
        nonce_field = ft.TextField(
            prefix_icon=ft.Icons.TAG, label="Nonce (Hex)", width=420, visible=False
        )
        aad_field = ft.TextField(
            prefix_icon=ft.Icons.STORAGE,
            label="AAD (hex, optional for GCM)",
            width=420,
            visible=False,
        )
        tag_field = ft.TextField(
            prefix_icon=ft.Icons.LOCAL_OFFER,
            label="Tag (hex, 32 characters) — required for GCM Decrypt",
            width=420,
            visible=False,
        )

        def gen_iv(_):
            iv_field.value = token_hex(16).upper()
            self.page.update()

        def gen_nonce(_):
            mode = mode_dd.value
            if mode == "CTR":
                size = 8
            elif mode == "GCM":
                size = 12
            else:
                size = 12
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
            label="Input (plaintext for encrypt, ciphertext for decrypt)",
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

        warning_msg = ft.Text("", color=ft.Colors.AMBER_700, visible=False)

        def copy_output(_):
            if output_field.value:
                self.page.set_clipboard(output_field.value)

        def fill_input_from_output(_):
            input_field.value = output_field.value or ""
            self.page.update()

        output_field.suffix = ft.Row(
            [
                IconButton(
                    self.page,
                    icon=ft.Icons.COPY,
                    tooltip="Copy output",
                    on_click=copy_output,
                ),
                IconButton(
                    self.page,
                    icon=ft.Icons.SYNC_ALT,
                    tooltip="Fill input with output",
                    on_click=fill_input_from_output,
                ),
            ],
            spacing=6,
            tight=True,
        )

        def update_mode(_=None):
            m = mode_dd.value
            iv_field.visible = False
            nonce_field.visible = False
            aad_field.visible = False
            tag_field.visible = False

            if m == "CBC":
                iv_field.visible = True
                iv_field.label = "IV (hex, 32 characters)"
            elif m == "CTR":
                nonce_field.visible = True
                nonce_field.label = "Nonce (hex, 16 characters)"
            elif m == "GCM":
                nonce_field.visible = True
                nonce_field.label = "Nonce (hex, 24 characters)"
                aad_field.visible = True
                tag_field.visible = True
                tag_field.label = "Tag (hex, 32 characters)"

            self.page.update()

        mode_dd.on_change = update_mode
        update_mode()

        def clear_errors_and_warnings():
            for f in (
                key_field,
                input_field,
                iv_field,
                nonce_field,
                aad_field,
                tag_field,
            ):
                f.error_text = None
            warning_msg.visible = False
            warning_msg.value = ""

        def validate_key():
            try:
                key = bytes.fromhex(key_field.value.strip())
                if len(key) not in (16, 24, 32):
                    key_field.error_text = "Key must be 32/48/64 hex characters long"
                    return None

                return key
            except Exception:
                key_field.error_text = "Key must be valid hex"
                self.page.update()
                return None

        def is_hex(s: str) -> bool:
            s2 = (s or "").strip()
            if not s2:
                return False
            try:
                bytes.fromhex(s2)
                return True
            except Exception:
                return False

        def encrypt_click(_):
            clear_errors_and_warnings()
            output_field.value = ""
            key = validate_key()
            if key is None:
                self.page.update()
                return

            data = input_field.value or ""
            if not data:
                input_field.error_text = "Plaintext required for encryption"
                self.page.update()
                return

            if is_hex(data):
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
                    if not iv_field.value:
                        iv_field.error_text = "IV required"
                        self.page.update()
                        return

                    try:
                        iv = bytes.fromhex(iv_field.value.strip())
                    except Exception:
                        iv_field.error_text = "IV must be valid hex"
                        self.page.update()
                        return

                    if len(iv) != 16:
                        iv_field.error_text = "IV must be 32 characters"
                        self.page.update()
                        return

                    c = AES_CBC(key)
                    ct = c.encrypt(data.encode(), iv=iv)
                    output_field.value = ct.hex().upper()
                elif mode == "CTR":
                    if not nonce_field.value:
                        nonce_field.error_text = "Nonce required"
                        self.page.update()
                        return

                    try:
                        nonce = bytes.fromhex(nonce_field.value.strip())
                    except Exception:
                        nonce_field.error_text = "Nonce must be valid hex"
                        self.page.update()
                        return

                    if len(nonce) != 8:
                        nonce_field.error_text = "Nonce must be 16 characters for CTR"
                        self.page.update()
                        return

                    c = AES_CTR(key)
                    ct = c.encrypt(data.encode(), nonce=nonce)
                    output_field.value = ct.hex().upper()
                elif mode == "GCM":
                    if not nonce_field.value:
                        nonce_field.error_text = "Nonce required"
                        self.page.update()
                        return

                    try:
                        nonce = bytes.fromhex(nonce_field.value.strip())
                    except Exception:
                        nonce_field.error_text = "Nonce must be valid hex"
                        self.page.update()
                        return

                    if len(nonce) != 12:
                        nonce_field.error_text = "Nonce must be 24 characters for GCM"
                        self.page.update()
                        return

                    try:
                        aad = bytes.fromhex(aad_field.value.strip())
                    except Exception:
                        aad_field.error_text = "AAD must be valid hex"
                        self.page.update()
                        return

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
            clear_errors_and_warnings()
            output_field.value = ""
            key = validate_key()
            if key is None:
                self.page.update()
                return

            data_hex = (input_field.value or "").strip()
            if not data_hex:
                input_field.error_text = "Ciphertext hex required for decryption"
                self.page.update()
                return

            if not is_hex(data_hex):
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
                    if not iv_field.value:
                        iv_field.error_text = "IV required"
                        self.page.update()
                        return

                    try:
                        iv = bytes.fromhex(iv_field.value.strip())
                    except Exception:
                        iv_field.error_text = "IV must be valid hex"
                        self.page.update()
                        return

                    if len(iv) != 16:
                        iv_field.error_text = "IV must be 32 characters"
                        self.page.update()
                        return

                    c = AES_CBC(key)
                    pt = c.decrypt(ct_bytes, iv=iv)
                    output_field.value = pt.decode(errors="replace")
                elif mode == "CTR":
                    if not nonce_field.value:
                        nonce_field.error_text = "Nonce required"
                        self.page.update()
                        return

                    try:
                        nonce = bytes.fromhex(nonce_field.value.strip())
                    except Exception:
                        nonce_field.error_text = "Nonce must be valid hex"
                        self.page.update()
                        return

                    if len(nonce) != 8:
                        nonce_field.error_text = "Nonce must be 16 characters for CTR"
                        self.page.update()
                        return

                    c = AES_CTR(key)
                    pt = c.decrypt(ct_bytes, nonce=nonce)
                    output_field.value = pt.decode(errors="replace")
                elif mode == "GCM":
                    if not nonce_field.value:
                        nonce_field.error_text = "Nonce required"
                        self.page.update()
                        return

                    try:
                        nonce = bytes.fromhex(nonce_field.value.strip())
                    except Exception:
                        nonce_field.error_text = "Nonce must be valid hex"
                        self.page.update()
                        return

                    if len(nonce) != 12:
                        nonce_field.error_text = "Nonce must be 24 characters for GCM"
                        self.page.update()
                        return
                    if not tag_field.value or not is_hex(tag_field.value):
                        tag_field.error_text = "Valid tag hex required for GCM decrypt"
                        self.page.update()
                        return

                    tag = bytes.fromhex(tag_field.value.strip())
                    aad = bytes.fromhex(aad_field.value) if aad_field.value else b""
                    c = AES_GCM(key)
                    try:
                        pt = c.decrypt(ct_bytes, nonce=nonce, tag=tag, aad=aad)
                        output_field.value = pt.decode(errors="replace")
                    except Exception:
                        tag_field.error_text = (
                            "GCM authentication tag mismatch - invalid tag provided"
                        )
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

        content = ft.Column(
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
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        update_mode()

        return ft.Container(vertical_scroll(surface_card(content)), padding=10)

    # -------- File mode --------
    def file_mode(self) -> ft.Control:
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)

        key_field = ft.TextField(
            label="File Key (Hex)",
            password=True,
            can_reveal_password=True,
            width=420,
            prefix_icon=ft.Icons.KEY,
        )
        key_field.suffix = IconButton(
            self.page,
            icon=ft.Icons.PASTE,
            tooltip="Paste key from clipboard",
            on_click=lambda _: self._paste(key_field),
        )

        file_picker = ft.FilePicker()
        self.page.overlay.append(file_picker)

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

        file_picker.on_result = on_file_pick

        def handle_file(action: str):
            self.page.update()

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

            prog.visible = True
            self.page.update()

            try:
                with open(selected_path, "rb") as f:
                    data = f.read()
                key = bytes.fromhex(key_field.value.strip())
                c = AES_CTR(key)
                if action == "encrypt":
                    prog.visible = True
                    self.page.update()

                    nonce = token_bytes(8)
                    result = nonce + c.encrypt(data, nonce=nonce)
                    out_name = selected_path + ".enc"
                    message = "Encrypted."
                else:
                    nonce, body = data[:8], data[8:]
                    result = c.decrypt(body, nonce=nonce)
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
                    width=500,
                ),
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )
        return ft.Container(vertical_scroll(surface_card(content)), padding=10)

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
