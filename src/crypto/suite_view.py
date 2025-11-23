import flet as ft

from ui.components import vertical_scroll
from ui.theme import GAP_MD, PADDING_APP


class CryptoSuite:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Cryptographic Suite"

    def _feature_box(self, title, on_click=None):
        return ft.Container(
            content=ft.Text(
                title,
                size=16,
                weight=ft.FontWeight.BOLD,
                text_align=ft.TextAlign.CENTER,
            ),
            expand=True,
            height=120,
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
            alignment=ft.alignment.center,
            border_radius=12,
            ink=True,
            on_click=on_click,
            col={"xs": 12, "sm": 6, "md": 4},
            padding=10,
        )

    def view(self) -> ft.View:
        header = ft.Text(
            "🔐 Cryptographic Suite",
            size=26,
            weight=ft.FontWeight.BOLD,
            expand=1,
            max_lines=None,
            overflow=ft.TextOverflow.VISIBLE,
        )

        grid = ft.ResponsiveRow(
            [
                self._feature_box(
                    "AES Encrypt / Decrypt",
                    on_click=lambda _: self.page.go("/crypto/aes"),
                ),
                self._feature_box(
                    "RSA Suite",
                    on_click=lambda _: self.page.go("/crypto/rsa"),
                ),
                self._feature_box(
                    "Hashing", on_click=lambda _: self.page.go("/crypto/hash")
                ),
                self._feature_box(
                    "DH Key Exchange", on_click=lambda _: self.page.go("/crypto/dh")
                ),
                self._feature_box(
                    "Key Management", on_click=lambda _: self.page.go("/crypto/keys")
                ),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            run_spacing=GAP_MD,
            spacing=GAP_MD,
        )

        content = ft.Container(
            ft.Column(
                [
                    ft.SafeArea(content=header, top=True),
                    ft.Divider(),
                    vertical_scroll(grid),
                ],
                spacing=GAP_MD,
            ),
            expand=True,
            padding=PADDING_APP,
            alignment=ft.alignment.top_center,
        )
        return ft.View(
            "/crypto",
            [content],
            appbar=self.page.appbar,
            floating_action_button=self.page.floating_action_button,
        )
