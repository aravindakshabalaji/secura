import flet as ft


class CryptoSuite:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Cryptographic Suite"

    def view(self):
        title = ft.Text(
            "🔐 Cryptographic Suite",
            size=25,
            weight=ft.FontWeight.BOLD,
            text_align=ft.TextAlign.CENTER,
        )

        header = ft.Row(
            [
                ft.IconButton(
                    ft.Icons.ARROW_BACK, on_click=lambda _: self.page.go("/")
                ),
                ft.Container(title, expand=True, alignment=ft.alignment.center_left),
            ],
            alignment=ft.MainAxisAlignment.START,
        )

        grid = ft.ResponsiveRow(
            [
                self.feature_box(
                    "Encrypt / Decrypt", lambda _: self.page.go("/crypto/encrypt")
                ),
                self.feature_box("Sign / Verify", on_click=lambda _: self.page.go("/crypto/sign")),
                self.feature_box("Key Management", on_click=lambda _: self.page.go("/crypto/keys")),
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            run_spacing=20,
            spacing=20,
        )

        content = ft.Container(
            ft.Column([header, ft.Divider(), grid], spacing=30),
            expand=True,
            padding=20,
            alignment=ft.alignment.top_center,
        )
        return ft.View("/crypto", [content])

    def feature_box(self, title, on_click=None):
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
            col={"xs": 12, "sm": 6, "md": 4, "lg": 3},
            padding=10,
        )
