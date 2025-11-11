import os

import flet as ft
from pycrypt.symmetric import AES_CTR, AES_ECB

from .components import PrimaryButton, TonalButton, vertical_scroll
from .theme import GAP_MD, GAP_SM, section_title, surface_card


class CryptoEncryptDecrypt:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Encrypt / Decrypt | Cryptographic Suite"
        self.page.scroll = ft.ScrollMode.AUTO

    def view(self) -> ft.View:
        header = ft.Row(
            [
                ft.IconButton(
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
            route="/crypto/encrypt",
            controls=[
                ft.Column([header, ft.Divider(), tabs], expand=True, spacing=GAP_MD)
            ],
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )

    # -------- Text mode --------
    def text_mode(self) -> ft.Control:
        key_field = ft.TextField(
            label="Key (Hex, 32/48/64 chars)",
            password=True,
            can_reveal_password=True,
            expand=True,
            prefix_icon=ft.Icons.KEY,
        )
        pt_field = ft.TextField(
            label="Plaintext", multiline=True, expand=True, min_lines=5
        )
        ct_field = ft.TextField(
            label="Ciphertext (Hex)", multiline=True, expand=True, min_lines=5
        )
        output_field = ft.TextField(
            label="Output", multiline=True, read_only=True, expand=True, min_lines=5
        )

        def paste_from_clipboard(_):
            key_field.value = self.page.get_clipboard()
            self.page.update()

        key_field.suffix = ft.IconButton(
            icon=ft.Icons.PASTE, tooltip="Paste", on_click=paste_from_clipboard
        )

        def handle_encrypt(_):
            key = key_field.value.strip()
            if not key:
                key_field.error_text = "Key required"
                self.page.update()
                return
            try:
                c = AES_ECB(bytes.fromhex(key))
                output_field.value = c.encrypt(pt_field.value.encode()).hex()
                key_field.error_text = None
                pt_field.error_text = None
            except ValueError:
                key_field.error_text = "Key must be hex"
            except Exception as err:
                pt_field.error_text = f"Error: {err}"
            self.page.update()

        def handle_decrypt(_):
            key = key_field.value.strip()
            if not key:
                key_field.error_text = "Key required"
                self.page.update()
                return
            try:
                c = AES_ECB(bytes.fromhex(key))
                output_field.value = c.decrypt(bytes.fromhex(ct_field.value)).decode()
                ct_field.error_text = None
                key_field.error_text = None
            except ValueError:
                ct_field.error_text = "Invalid hex"
            except Exception as err:
                ct_field.error_text = f"Error: {err}"
            self.page.update()

        actions = ft.Row(
            [
                PrimaryButton(
                    self.page, "Encrypt", icon=ft.Icons.LOCK, on_click=handle_encrypt
                ),
                TonalButton(
                    self.page,
                    "Decrypt",
                    icon=ft.Icons.LOCK_OPEN,
                    on_click=handle_decrypt,
                ),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=GAP_MD,
            wrap=True,
        )

        content = ft.Column(
            [
                section_title("Text Mode"),
                key_field,
                ft.ResponsiveRow(
                    [
                        ft.Container(pt_field, col={"sm": 12, "md": 6}),
                        ft.Container(ct_field, col={"sm": 12, "md": 6}),
                    ],
                    spacing=GAP_MD,
                ),
                actions,
                output_field,
            ],
            spacing=GAP_MD,
        )
        return ft.Container(vertical_scroll(surface_card(content)), padding=10)

    # -------- File mode --------
    def file_mode(self) -> ft.Control:
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)

        key_field = ft.TextField(
            label="File Key (Hex)",
            password=True,
            can_reveal_password=True,
            width=420,
            prefix_icon=ft.Icons.KEY,
        )
        key_field.suffix = ft.IconButton(
            icon=ft.Icons.PASTE,
            tooltip="Paste",
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
                with open(selected_path, "rb") as f:
                    data = f.read()
                key = bytes.fromhex(key_field.value.strip())
                c = AES_CTR(key)
                if action == "encrypt":
                    nonce = os.urandom(8)
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
            self.page.update()

        buttons = ft.Row(
            [
                PrimaryButton(
                    self.page,
                    "Select File",
                    icon=ft.Icons.FOLDER_OPEN,
                    on_click=lambda _: file_picker.pick_files(allow_multiple=False),
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
