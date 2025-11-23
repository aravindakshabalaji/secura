from secrets import token_bytes

import flet as ft
from pycrypt.hash import SHA256, hkdf

from appbar import build_appbar
from ui.components import PrimaryButton
from ui.theme import CARD_RADIUS, GAP_MD, build_theme, section_title


class HomePage:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Dashboard"

    def toggle_theme(self, e):
        if self.page.theme_mode == ft.ThemeMode.DARK:
            self.page.theme_mode = ft.ThemeMode.LIGHT
            self.page.client_storage.set("secura.light_mode", True)
            e.control.icon = ft.Icons.DARK_MODE_OUTLINED
        else:
            self.page.theme_mode = ft.ThemeMode.DARK
            self.page.client_storage.set("secura.light_mode", False)
            e.control.icon = ft.Icons.LIGHT_MODE_OUTLINED

        self.page.update()

    def color_change(self, e):
        color = e.control.content.color
        self.page.client_storage.set("secura.color_scheme", color)
        self.page.theme = build_theme(color)
        self.page.update()

    def enter_app(self, e):
        e.control.parent.controls[1].error_text = ""
        username: str = e.control.parent.controls[0].value
        password: str = e.control.parent.controls[1].value
        password_bytes = password.encode()

        conn = self.page.conn
        exists = conn.execute(
            "SELECT 1 FROM secura WHERE username=?", (username,)
        ).fetchone()

        if not exists:
            salt = token_bytes(32)
            hash = SHA256(salt + password_bytes).digest()

            conn.execute(
                "INSERT INTO secura (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, hash, salt),
            )
            conn.commit()

            self.page.username = username
            self.page.master_key = hkdf(password_bytes, 32, salt).hex()
        else:
            hash, salt = conn.execute(
                "SELECT password_hash, salt FROM secura WHERE username=?", (username,)
            ).fetchone()
            if SHA256(salt + password_bytes).digest() != hash:
                e.control.parent.controls[1].error_text = "Incorrect password"
                self.page.update()
                return

            self.page.username = username
            self.page.master_key = hkdf(password_bytes, 32, salt).hex()

        self.page.appbar = build_appbar(self.page, self.toggle_theme, self.color_change)
        
        self.page.go("/crypto")

    def view(self) -> ft.View:
        username_field = ft.TextField(label="Username", prefix_icon=ft.Icons.PERSON)
        password_field = ft.TextField(
            label="Password",
            prefix_icon=ft.Icons.PASSWORD,
            password=True,
            can_reveal_password=True,
        )
        enter_btn = PrimaryButton(
            self.page, "Enter", ft.Icons.LOGIN, on_click=self.enter_app
        )
        content = ft.Container(
            ft.Column(
                [username_field, password_field, enter_btn],
                spacing=GAP_MD,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            padding=10,
        )

        col = ft.Column(
            [section_title("Welcome"), ft.Divider(), content],
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.START,
            width=400,
        )

        return ft.View(
            route="/",
            controls=[
                ft.Container(
                    content=col,
                    padding=20,
                    alignment=ft.alignment.center,
                    bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
                    border_radius=CARD_RADIUS,
                    width=400,
                )
            ],
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )
