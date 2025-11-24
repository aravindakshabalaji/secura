from secrets import token_hex

import flet as ft
from pycrypt.asymmetric import DHPublicKey

from crypto.base_view import BaseView
from ui.components import IconButton, PrimaryButton, TextField, vertical_scroll
from ui.theme import GAP_MD, section_title, surface_card


class DHEncryptDecrypt(BaseView):
    def __init__(self, page: ft.Page):
        super().__init__(page)
        self.page.title = "DH Key Exchange | Cryptographic Suite"

    def view(self):
        header = self.render_header("🔁 DH Key Exchange")

        tabs = self._text_mode()

        return self.render_view(header, tabs, "/crypto/dh")

    def _is_hex(self, text: str) -> bool:
        try:
            bytes.fromhex((text or "").strip())
            return True
        except Exception:
            return False

    def _text_mode(self):
        priv_key_field = self._key_field(
            "Private Key (PEM)",
            upload_tooltip="private key",
            exts=["priv.pem"],
            hint_text="",
        )
        pub_key_field = self._key_field(
            "Peer Public Key (PEM)",
            upload_tooltip="peer public key",
            exts=["pub.pem"],
            hint_text="",
        )
        length_field = TextField(
            label="Derived Key Length (bytes)",
            hint_text="Enter number",
            value="32",
            keyboard_type=ft.KeyboardType.NUMBER,
        )
        length_field.suffix = self._paste_button(length_field)

        salt_field = TextField(
            prefix_icon=ft.Icons.STORAGE,
            label="Salt (hex)",
            hint_text="64 characters",
        )

        def gen_salt(_):
            salt_field.value = token_hex(32).upper()
            self.page.update()

        salt_field.suffix = ft.Row(
            [
                self._copy_button(salt_field),
                IconButton(
                    self.page,
                    icon=ft.Icons.CACHED,
                    tooltip="Generate 32-byte salt",
                    on_click=gen_salt,
                ),
            ],
            spacing=4,
            tight=True,
        )

        derived_key_field = TextField(
            prefix_icon=ft.Icons.KEY,
            label="Derived Key (hex)",
            width=700,
            read_only=True,
        )
        derived_key_field.suffix = self._copy_button(derived_key_field, "derived")

        def import_peer_public(raw: str):
            r = (raw or "").strip()
            try:
                peer_pub = DHPublicKey.import_key(r)
                return peer_pub
            except Exception:
                try:
                    b = bytes.fromhex(r)
                    peer_pub = DHPublicKey.from_bytes(b)
                    return peer_pub
                except Exception as e:
                    pub_key_field.error_text = f"Unable to parse peer public key: {e}"

        def exchange_click(_):
            self._clear_errors(priv_key_field, pub_key_field, derived_key_field)
            derived_key_field.value = ""

            if not (priv_key_field.value or "").strip():
                priv_key_field.error_text = "Private key (PEM) required"
                self.page.update()
                return
            if not (pub_key_field.value or "").strip():
                pub_key_field.error_text = "Peer public key required"
                self.page.update()
                return

            try:
                peer_pub = import_peer_public(pub_key_field.value)
            except Exception as e:
                pub_key_field.error_text = str(e)
                self.page.update()
                return

            try:
                priv = None
                from pycrypt.asymmetric import DHPrivateKey

                priv = DHPrivateKey.import_key(priv_key_field.value.strip())
            except Exception as e:
                priv_key_field.error_text = f"Invalid private key: {e}"
                self.page.update()
                return

            try:
                length = int(length_field.value)
                if length <= 0:
                    raise ValueError("length must be positive")
            except Exception as e:
                length_field.error_text = f"Invalid length: {e}"
                self.page.update()
                return

            salt = None
            if salt_field.value:
                if not self._is_hex(salt_field.value):
                    salt_field.error_text = "Invalid salt value"
                    self.page.update()
                    return
                salt = bytes.fromhex(salt_field.value.strip())
            else:
                salt = None

            try:
                derived = priv.exchange(peer_pub, length=length, salt=salt)
            except Exception as e:
                derived_key_field.error_text = f"Exchange error: {e}"
                self.page.update()
                return

            derived_key_field.value = derived.hex().upper()
            self.page.update()

        buttons = PrimaryButton(
            self.page,
            "Exchange",
            icon=ft.Icons.HANDSHAKE,
            on_click=exchange_click,
        )

        return vertical_scroll(
            surface_card(
                ft.Column(
                    [
                        section_title("DH Key Exchange"),
                        ft.ResponsiveRow(
                            [
                                ft.Container(priv_key_field, col={"sm": 6}),
                                ft.Container(pub_key_field, col={"sm": 6}),
                            ],
                            spacing=12,
                            alignment=ft.alignment.center,
                            width=1000,
                        ),
                        ft.ResponsiveRow(
                            [
                                ft.Container(length_field, col={"sm": 3}),
                                ft.Container(salt_field, col={"sm": 9}),
                            ],
                            spacing=12,
                            alignment=ft.alignment.center,
                            width=1000,
                        ),
                        buttons,
                        derived_key_field,
                    ],
                    spacing=GAP_MD,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                )
            )
        )
