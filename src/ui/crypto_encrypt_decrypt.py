import os

import flet as ft
from pycrypt.symmetric import AES_CTR, AES_ECB


class CryptoEncryptDecrypt:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Encrypt / Decrypt | Cryptographic Suite"
        self.page.scroll = ft.ScrollMode.AUTO

    @staticmethod
    def styled_button(text, icon, color, on_click):
        return ft.ElevatedButton(
            text,
            icon=icon,
            bgcolor=color,
            color=ft.Colors.WHITE,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=12),
                padding=ft.padding.all(15),
            ),
            on_click=on_click,
        )

    def create_file_tab(self):
        selected_file_path = None
        selected_file = None
        
        def set_paste_value(_):
            key_field.value = self.page.get_clipboard()
            self.page.update()

        selected_file_display = ft.Text("No file selected.", color=ft.Colors.AMBER_700)
        key_field = ft.TextField(
            label="File Key (Hex String)",
            password=True,
            can_reveal_password=True,
            width=400,
            suffix=ft.IconButton(
                icon=ft.Icons.PASTE,
                on_click=set_paste_value
            ),
        )

        file_picker = ft.FilePicker()
        save_picker = ft.FilePicker()
        self.page.overlay.extend([file_picker, save_picker])

        def on_file_pick(e: ft.FilePickerResultEvent):
            nonlocal selected_file_path
            nonlocal selected_file
            if e.files:
                selected_file = e.files[0]
                selected_file_path = selected_file.path or selected_file.name
                file_name = selected_file.name or os.path.basename(
                    selected_file_path or ""
                )

                selected_file_display.value = f"📄 {file_name} selected"
                selected_file_display.color = ft.Colors.GREEN_ACCENT_400
            else:
                selected_file = None
                selected_file_display.value = "❌ No file selected."
                selected_file_display.color = ft.Colors.RED_ACCENT_400
            self.page.update()

        file_picker.on_result = on_file_pick

        def handle_file_action(action: str):
            nonlocal selected_file
            nonlocal selected_file_path

            if not selected_file_path:
                selected_file_display.value = "⚠️ Please select a file first."
                selected_file_display.color = ft.Colors.RED_400
                self.page.update()
                return

            if not key_field.value:
                selected_file_display.value = "⚠️ Enter a valid key."
                selected_file_display.color = ft.Colors.RED_400
                self.page.update()
                return

            try:
                if selected_file.path:
                    with open(selected_file_path, "rb") as f:
                        data = f.read()

                c = AES_CTR(key_field.value.encode())
                if action == "Encrypt":
                    nonce = os.urandom(8)
                    encrypted = nonce + c.encrypt(data, nonce=nonce)
                    result_name = selected_file_path.name + ".enc"
                    result_data = encrypted
                    message = f"✅ {selected_file_path.name} encrypted."
                else:
                    nonce, data = data[:8], data[8:]
                    decrypted = c.decrypt(data, nonce=nonce)
                    result_name = selected_file_path.name.replace(".enc", "")
                    result_data = decrypted
                    message = f"✅ {selected_file_path.name} decrypted."

                if selected_file_path.path:
                    output_path = os.path.join(
                        os.path.dirname(selected_file_path.path), result_name
                    )
                    with open(output_path, "wb") as f:
                        f.write(result_data)
                    message += f" Saved at: {output_path}"

                selected_file_display.value = message
                selected_file_display.color = (
                    ft.Colors.BLUE_ACCENT_200
                    if action == "Encrypt"
                    else ft.Colors.PURPLE_ACCENT_100
                )

            except Exception as err:
                selected_file_display.value = f"❌ Error: {err}"
                selected_file_display.color = ft.Colors.RED_400

            self.page.update()

        return ft.Container(
            content=ft.Column(
                [
                    ft.Text("File Mode", size=22, weight=ft.FontWeight.BOLD),
                    key_field,
                    ft.ElevatedButton(
                        "Select File",
                        icon=ft.Icons.FOLDER_OPEN_ROUNDED,
                        on_click=lambda _: file_picker.pick_files(
                            allow_multiple=False,
                            dialog_title="Select a file to encrypt/decrypt",
                        ),
                        style=ft.ButtonStyle(
                            bgcolor={ft.ControlState.DEFAULT: ft.Colors.BLUE_GREY_800},
                            color={ft.ControlState.DEFAULT: ft.Colors.WHITE},
                            shape=ft.RoundedRectangleBorder(radius=10),
                            padding=15,
                        ),
                    ),
                    ft.Card(
                        content=ft.Container(
                            selected_file_display,
                            padding=10,
                            alignment=ft.alignment.center,
                        ),
                        elevation=3,
                        width=400,
                    ),
                    ft.Row(
                        [
                            self.styled_button(
                                "Encrypt File",
                                icon=ft.Icons.LOCK_ROUNDED,
                                color=ft.Colors.GREEN_700,
                                on_click=handle_file_action("Encrypt"),
                            ),
                            self.styled_button(
                                "Decrypt File",
                                icon=ft.Icons.LOCK_OPEN_ROUNDED,
                                color=ft.Colors.DEEP_ORANGE_700,
                                on_click=lambda _: self.page.run_task(
                                    lambda: handle_file_action("Decrypt")
                                ),
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                        spacing=20,
                    ),
                ],
                spacing=20,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=ft.padding.all(20),
            alignment=ft.alignment.center,
        )

    def view(self):
        header = ft.Row(
            [
                ft.IconButton(
                    icon=ft.Icons.ARROW_BACK,
                    tooltip="Go Back",
                    on_click=lambda _: self.page.go("/crypto"),
                ),
                ft.Text("🔐 Encrypt / Decrypt", size=28, weight=ft.FontWeight.BOLD),
            ],
            alignment=ft.MainAxisAlignment.START,
            spacing=15,
        )
        
        def set_paste_value(_):
            key_field.value = self.page.get_clipboard()
            self.page.update()

        key_field = ft.TextField(
            label="Key (Hex String, 32/48/64 chars)",
            password=True,
            can_reveal_password=True,
            expand=True,
            suffix=ft.IconButton(
                icon=ft.Icons.PASTE,
                on_click=set_paste_value
            )
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

        def handle_encrypt(e):
            key = key_field.value.strip()
            if not key:
                key_field.error_text = "Key required"
                self.page.update()
                return
            try:
                c = AES_ECB(key.encode())
                output_field.value = c.encrypt(pt_field.value.encode()).hex()
                key_field.error_text = None
                pt_field.error_text = None
            except Exception as err:
                pt_field.error_text = f"Error: {err}"
            self.page.update()

        def handle_decrypt(e):
            key = key_field.value.strip()
            if not key:
                key_field.error_text = "Key required"
                self.page.update()
                return
            try:
                c = AES_ECB(key.encode())
                output_field.value = c.decrypt(bytes.fromhex(ct_field.value)).decode()
                ct_field.error_text = None
                key_field.error_text = None
            except ValueError:
                ct_field.error_text = "❌ Invalid ciphertext (must be valid hex)"
            except Exception as err:
                ct_field.error_text = f"Error: {err}"
            self.page.update()

        data_tab = ft.Container(
            ft.Column(
                [
                    ft.Text("Text Mode", size=22, weight=ft.FontWeight.BOLD),
                    key_field,
                    ft.ResponsiveRow(
                        [
                            ft.Container(pt_field, col={"sm": 12, "md": 6}),
                            ft.Container(ct_field, col={"sm": 12, "md": 6}),
                        ],
                        spacing=20,
                    ),
                    ft.Row(
                        [
                            self.styled_button(
                                "Encrypt",
                                ft.Icons.LOCK_ROUNDED,
                                ft.Colors.GREEN_700,
                                handle_encrypt,
                            ),
                            self.styled_button(
                                "Decrypt",
                                ft.Icons.LOCK_OPEN_ROUNDED,
                                ft.Colors.DEEP_ORANGE_700,
                                handle_decrypt,
                            ),
                        ],
                        alignment=ft.MainAxisAlignment.CENTER,
                        wrap=True,
                    ),
                    output_field,
                ],
                spacing=15,
            ),
            padding=20,
        )

        file_tab = self.create_file_tab()

        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(
                    text="Text Data",
                    icon=ft.Icons.TEXT_FIELDS_OUTLINED,
                    content=data_tab,
                ),
                ft.Tab(
                    text="Files", icon=ft.Icons.ATTACH_FILE_ROUNDED, content=file_tab
                ),
            ],
            expand=1,
            indicator_color=ft.Colors.CYAN_700,
        )

        return ft.View(
            route="/crypto/encrypt",
            controls=[ft.Column([header, ft.Divider(), tabs], expand=True, spacing=10)],
            padding=ft.padding.symmetric(horizontal=20, vertical=10),
        )
