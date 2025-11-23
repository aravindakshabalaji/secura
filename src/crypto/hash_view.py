import os.path
from secrets import token_hex
from typing import Optional

import flet as ft
from pycrypt.hash import SHA1, SHA256, hkdf, hmac

from crypto.base_view import BaseView
from ui.components import IconButton, PrimaryButton
from ui.theme import GAP_MD, section_title


class HashView(BaseView):
    def __init__(self, page: ft.Page):
        super().__init__(page)
        self.page.title = "Hashing | Cryptographic Suite"

        self.file_picker = ft.FilePicker()
        self.page.overlay.append(self.file_picker)

    def view(self) -> ft.View:
        header = self.render_header("#️⃣ Hashing")

        tabs = self.render_tabs(
            [
                ft.Tab(
                    text="Text Data",
                    icon=ft.Icons.TEXT_FIELDS_OUTLINED,
                    content=self._text_tab(),
                ),
                ft.Tab(
                    text="File Data",
                    icon=ft.Icons.ATTACH_FILE_ROUNDED,
                    content=self._file_tab(),
                ),
                ft.Tab(
                    text="Hash-based",
                    icon=ft.Icons.VERIFIED_OUTLINED,
                    content=self._hash_based_tab(),
                ),
            ]
        )

        return self.render_view(header, tabs, "/crypto/hash")

    # ----------------- helpers -----------------
    def _get_hash_constructor(self, alg_key: str):
        if alg_key == "SHA1":
            return SHA1
        return SHA256

    # ----------------- Text tab -----------------
    def _text_tab(self) -> ft.Control:
        algo_dd = ft.Dropdown(
            label="Algorithm",
            options=[
                ft.DropdownOption(key="SHA1", text="SHA-1"),
                ft.DropdownOption(key="SHA256", text="SHA-256"),
            ],
            value="SHA256",
            width=260,
        )

        input_field = ft.TextField(
            prefix_icon=ft.Icons.INPUT,
            label="Input",
            hint_text="Text to hash",
            multiline=True,
            max_lines=6,
            width=600,
        )
        input_field.suffix = self._paste_button(input_field)

        digest_field = ft.TextField(
            prefix_icon=ft.Icons.OUTPUT,
            label="Digest (hex)",
            multiline=True,
            max_lines=6,
            width=600,
            read_only=True,
        )
        digest_field.suffix = self._copy_button(digest_field, "digest")

        def compute_hash(_):
            digest_field.value = ""
            alg = algo_dd.value
            try:
                ctor = self._get_hash_constructor(alg)
                h = ctor()
                data = (input_field.value or "").encode()
                h.update(data)
                digest_field.value = h.hexdigest().upper()
            except Exception as err:
                digest_field.value = f"Error: {err}"
            self.page.update()

        compute_btn = PrimaryButton(
            self.page, "Compute", icon=ft.Icons.NUMBERS, on_click=compute_hash
        )

        return self.render_tab(
            [
                section_title("Text Data"),
                algo_dd,
                compute_btn,
                ft.ResponsiveRow(
                    [
                        ft.Container(
                            input_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                        ft.Container(
                            digest_field, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    width=1000,
                ),
            ]
        )

    def _fill_input_from_digest(self, inp: ft.TextField, digest: ft.TextField):
        inp.value = digest.value or ""
        self.page.update()

    # ----------------- File tab -----------------
    def _file_tab(self) -> ft.Control:
        selected_file_info = ft.Text("No file selected.", color=ft.Colors.AMBER_700)
        prog = ft.ProgressRing(visible=False, width=16, height=16, stroke_width=2)

        algo_dd = ft.Dropdown(
            label="Algorithm",
            options=[
                ft.DropdownOption(key="SHA1", text="SHA-1"),
                ft.DropdownOption(key="SHA256", text="SHA-256"),
            ],
            value="SHA256",
            width=260,
        )

        digest_field = ft.TextField(
            prefix_icon=ft.Icons.OUTPUT,
            label="Digest (hex)",
            multiline=True,
            max_lines=3,
            width=600,
            read_only=True,
        )
        digest_field.suffix = self._copy_button(digest_field, "digest")

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

        def compute_file_hash(_: ft.Control = None):
            nonlocal selected_path
            digest_field.value = ""
            if not selected_path:
                selected_file_info.value = "Select a file first."
                selected_file_info.color = ft.Colors.RED_400
                self.page.update()
                return

            prog.visible = True
            self.page.update()
            try:
                ctor = self._get_hash_constructor(algo_dd.value)
                h = ctor()
                with open(selected_path, "rb") as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        h.update(chunk)
                digest_field.value = h.hexdigest().upper()
            except Exception as err:
                digest_field.value = f"Error: {err}"
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
                    "Compute Hash",
                    icon=ft.Icons.NUMBERS,
                    on_click=compute_file_hash,
                ),
                prog,
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=GAP_MD,
            wrap=True,
        )

        return self.render_tab(
            [
                section_title("File Data"),
                algo_dd,
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
                ft.Container(digest_field, alignment=ft.alignment.center),
            ]
        )

    # ----------------- Hash-based tab (HMAC / HKDF) -----------------
    def _hash_based_tab(self) -> ft.Control:
        mode_dd = ft.Dropdown(
            label="Mode",
            options=[
                ft.DropdownOption(key="HMAC", text="HMAC"),
                ft.DropdownOption(key="HKDF", text="HKDF"),
            ],
            value="HMAC",
            width=200,
        )

        # --- HMAC ---
        hmac_key = self._key_field(
            "Key (hex or text)",
            "Secret key for HMAC",
        )

        hmac_algo = ft.Dropdown(
            label="HMAC Algorithm",
            options=[
                ft.DropdownOption(key="SHA1", text="HMAC-SHA1"),
                ft.DropdownOption(key="SHA256", text="HMAC-SHA256"),
            ],
            value="SHA256",
            width=260,
        )

        hmac_input = ft.TextField(
            prefix_icon=ft.Icons.INPUT,
            label="Input (message)",
            multiline=True,
            max_lines=6,
            width=500,
        )
        hmac_input.suffix = self._paste_button(hmac_input)

        hmac_out = ft.TextField(
            prefix_icon=ft.Icons.OUTPUT,
            label="Tag (hex)",
            hint_text="Generated by hmac",
            read_only=True,
            width=500,
        )
        hmac_out.suffix = self._copy_button(hmac_out, "tag")

        def compute_hmac(_):
            hmac_out.value = ""
            key_val = (hmac_key.value or "").strip()
            if not key_val:
                hmac_key.error_text = "Key required"
                self.page.update()
                return
            try:
                key_bytes = bytes.fromhex(key_val)
            except Exception:
                key_bytes = key_val.encode()

            data = (hmac_input.value or "").encode()
            try:
                h = hmac(
                    key_bytes,
                    data,
                    hash=SHA1 if hmac_algo.value == "SHA1" else SHA256,
                )
                hmac_out.value = h.hex().upper()
            except Exception as err:
                hmac_out.value = f"Error: {err}"
            self.page.update()

        hmac_buttons = ft.Row(
            [
                PrimaryButton(
                    self.page, "Compute HMAC", icon=ft.Icons.LOCK, on_click=compute_hmac
                ),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=GAP_MD,
            wrap=True,
        )

        hmac_column = ft.Column(
            [
                hmac_algo,
                hmac_key,
                hmac_buttons,
                ft.ResponsiveRow(
                    [
                        ft.Container(
                            hmac_input, alignment=ft.alignment.center, col={"sm": 6}
                        ),
                        ft.Container(
                            hmac_out, alignment=ft.alignment.center, col={"sm": 6}
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

        # --- HKDF ---
        hkdf_ikm = self._key_field(
            "IKM (hex or text)",
            "Input keying material",
        )

        def gen_salt(_):
            hkdf_salt.value = token_hex(32).upper()
            self.page.update()

        hkdf_salt = ft.TextField(
            prefix_icon=ft.Icons.STORAGE,
            label="Salt (hex or text, optional)",
            hint_text="Optional salt",
            width=330,
        )
        hkdf_salt.suffix = IconButton(
            self.page,
            icon=ft.Icons.CACHED,
            tooltip="Generate random salt",
            on_click=gen_salt,
        )

        hkdf_info = ft.TextField(
            prefix_icon=ft.Icons.INFO,
            label="Info (hex or text, optional)",
            hint_text="Optional context/info",
            width=330,
        )
        hkdf_info.suffix = self._paste_button(hkdf_info)

        hkdf_len = ft.TextField(
            prefix_icon=ft.Icons.STRAIGHTEN,
            label="Length (bytes)",
            hint_text="Output length in bytes",
            width=330,
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        hkdf_len.suffix = self._paste_button(hkdf_len)

        hkdf_algo = ft.Dropdown(
            label="HKDF Algorithm",
            options=[
                ft.DropdownOption(key="SHA1", text="HKDF-SHA1"),
                ft.DropdownOption(key="SHA256", text="HKDF-SHA256"),
            ],
            value="SHA256",
            width=260,
        )

        hkdf_out = ft.TextField(
            prefix_icon=ft.Icons.OUTPUT,
            label="Derived Key (hex)",
            read_only=True,
            width=600,
        )
        hkdf_out.suffix = self._copy_button(hkdf_out, "key")

        def compute_hkdf(_):
            hkdf_out.value = ""
            ikm_val = (hkdf_ikm.value or "").strip()
            if not ikm_val:
                hkdf_ikm.error_text = "IKM required"
                self.page.update()
                return

            def parse_maybe_hex(s: str) -> bytes:
                try:
                    return bytes.fromhex(s)
                except Exception:
                    return s.encode()

            ikm = parse_maybe_hex(ikm_val)
            salt = parse_maybe_hex((hkdf_salt.value or "").strip())
            info = parse_maybe_hex((hkdf_info.value or "").strip())

            try:
                length = int((hkdf_len.value or "").strip())
            except Exception:
                hkdf_len.error_text = "Enter a valid integer"
                self.page.update()
                return

            try:
                key = hkdf(
                    ikm=ikm,
                    length=length,
                    salt=salt,
                    info=info,
                    hash=(SHA1 if hkdf_algo.value == "SHA1" else SHA256),
                )
                hkdf_out.value = key.hex().upper()
            except Exception as err:
                hkdf_out.value = f"Error: {err}"
            self.page.update()

        hkdf_buttons = ft.Row(
            [
                PrimaryButton(
                    self.page, "Derive", icon=ft.Icons.KEY, on_click=compute_hkdf
                )
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=GAP_MD,
        )

        hkdf_column = ft.Column(
            [
                hkdf_algo,
                hkdf_ikm,
                ft.ResponsiveRow(
                    [
                        ft.Container(
                            hkdf_salt, alignment=ft.alignment.center, col={"sm": 4}
                        ),
                        ft.Container(
                            hkdf_info, alignment=ft.alignment.center, col={"sm": 4}
                        ),
                        ft.Container(
                            hkdf_len, alignment=ft.alignment.center, col={"sm": 4}
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=12,
                    width=1000,
                ),
                hkdf_buttons,
                hkdf_out,
            ],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        def update_mode(_=None):
            mode = mode_dd.value
            hmac_column.visible = mode == "HMAC"
            hkdf_column.visible = mode == "HKDF"
            self.page.update()

        mode_dd.on_change = update_mode
        update_mode()

        return self.render_tab(
            [section_title("HMAC & HKDF"), mode_dd, hmac_column, hkdf_column]
        )
