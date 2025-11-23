from secrets import token_hex

import flet as ft
from pycrypt.asymmetric import DHPublicKey

from crypto.base_view import BaseView
from ui.components import IconButton, PrimaryButton
from ui.theme import section_title


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
        length_field = ft.TextField(
            label="Derived key length (bytes)",
            hint_text="Enter number",
            value="32",
            width=220,
        )

        salt_field = ft.TextField(
            prefix_icon=ft.Icons.STORAGE,
            label="Salt (hex)",
            hint_text="64 characters",
            width=420,
        )

        def gen_salt(_):
            salt_field.value = token_hex(32).upper()
            self.page.update()

        salt_field.suffix = IconButton(
            self.page,
            icon=ft.Icons.CACHED,
            tooltip="Generate 32-byte salt",
            on_click=gen_salt,
        )

        derived_key_field = ft.TextField(
            prefix_icon=ft.Icons.KEY,
            label="Derived Key (hex)",
            width=700,
            read_only=True,
        )
        derived_key_field.suffix = self._copy_button(derived_key_field, "derived")

        warning_msg = ft.Text("", color=ft.Colors.AMBER_700, visible=False)

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
                    raise ValueError(f"Unable to parse peer public key: {e}")

        def exchange_click(_):
            self._clear_errors(
                priv_key_field, pub_key_field, derived_key_field, warning=warning_msg
            )
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
                shared = priv.exchange(peer_pub)
            except Exception as e:
                derived_key_field.error_text = f"Exchange error: {e}"
                self.page.update()
                return

            try:
                length = int(length_field.value)
                if length <= 0:
                    raise ValueError("length must be positive")
            except Exception as e:
                derived_key_field.error_text = f"Invalid length: {e}"
                self.page.update()
                return

            salt = None
            if salt_field.value and self._is_hex(salt_field.value):
                salt = bytes.fromhex(salt_field.value.strip())
            else:
                salt = None

            try:
                from pycrypt.kdf import HKDF

                info = b"dh-derived-key"
                derived = HKDF(shared, length=length, salt=salt, info=info)
            except Exception:
                import hashlib

                full = hashlib.sha256(shared + (salt or b"")).digest()
                if length <= len(full):
                    derived = full[:length]
                else:
                    out = full
                    prev = full
                    while len(out) < length:
                        prev = hashlib.sha256(prev + shared + (salt or b"")).digest()
                        out += prev
                    derived = out[:length]

            derived_key_field.value = derived.hex().upper()
            self.page.update()

        buttons = PrimaryButton(
            self.page,
            "Exchange",
            icon=ft.Icons.HANDSHAKE,
            on_click=exchange_click,
        )

        return self.render_tab(
            [
                section_title("DH Key Exchange"),
                ft.ResponsiveRow(
                    [
                        ft.Container(priv_key_field, col={"sm": 6}),
                        ft.Container(pub_key_field, col={"sm": 6}),
                    ],
                    spacing=12,
                    alignment=ft.alignment.center,
                ),
                ft.ResponsiveRow(
                    [
                        ft.Container(length_field, col={"sm": 6}),
                        ft.Container(salt_field, col={"sm": 6}),
                    ],
                    spacing=12,
                    alignment=ft.alignment.center,
                ),
                buttons,
                derived_key_field,
            ]
        )
