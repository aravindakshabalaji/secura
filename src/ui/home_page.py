import flet as ft


class HomePage:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Dashboard"
        

    def view(self):
        title = ft.Text(
            "Main Dashboard",
            size=45,
            weight=ft.FontWeight.BOLD,
            selectable=True,
            no_wrap=False,
            max_lines=None,
            text_align=ft.TextAlign.CENTER,
        )
        return ft.View(
            "/",
            [
                ft.Column(
                    [
                        ft.Container(
                            title,
                            width=self.page.width * 0.9,
                            alignment=ft.alignment.center,
                        ),
                        ft.ResponsiveRow(
                            controls=[
                                ft.Container(
                                    ft.ElevatedButton(
                                        "🎵 Pyano",
                                        on_click=lambda _: print("Pyano"),
                                        scale=1.4,
                                    ),
                                    col={"xs": 12, "sm": 6},  # stack on mobile
                                    alignment=ft.alignment.center,
                                    padding=10,
                                ),
                                ft.Container(
                                    ft.ElevatedButton(
                                        text="🔐 Cryptographic Suite",
                                        on_click=lambda _: self.page.go("/crypto"),
                                        scale=1.4,
                                    ),
                                    col={"xs": 12, "sm": 6},
                                    alignment=ft.alignment.center,
                                    padding=10,
                                ),
                            ],
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
            ],
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )
