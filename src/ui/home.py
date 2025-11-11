import flet as ft

from .components import PrimaryButton
from .theme import GAP_MD, PADDING_APP


class HomePage:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Dashboard"

    def view(self) -> ft.View:
        title = ft.Text(
            "Main Dashboard",
            size=40,
            weight=ft.FontWeight.BOLD,
            text_align=ft.TextAlign.CENTER,
        )

        button_area = ft.Container(
            content=ft.ResponsiveRow(
                controls=[
                    ft.Container(
                        PrimaryButton(
                            self.page,
                            "🔐 Cryptographic Suite",
                            on_click=lambda _: self.page.go("/crypto"),
                        ),
                        col={"xs": 12, "sm": 6},
                        alignment=ft.alignment.center,
                        padding=GAP_MD,
                    ),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                run_spacing=GAP_MD,
                spacing=GAP_MD,
            ),
            alignment=ft.alignment.center,
            expand=False,
        )

        content = ft.Column(
            controls=[title, button_area],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=GAP_MD,
        )

        return ft.View(
            route="/",
            controls=[
                ft.Container(
                    content,
                    expand=True,
                    padding=PADDING_APP,
                    alignment=ft.alignment.center,
                )
            ],
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )
