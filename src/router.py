import flet as ft

from crypto.aes_view import AESEncryptDecrypt
from crypto.keys_view import KeyManagement
from crypto.rsa_view import RSAEncryptDecrypt
from crypto.suite_view import CryptoSuite
from crypto.home import HomePage
from crypto.hash_view import HashView

ROUTES = {
    "/": HomePage,
    "/crypto": CryptoSuite,
    "/crypto/aes": AESEncryptDecrypt,
    "/crypto/keys": KeyManagement,
    "/crypto/rsa": RSAEncryptDecrypt,
    "/crypto/hash": HashView,
}


def resolve_route(page: ft.Page, route: str) -> ft.View:
    cls = ROUTES.get(route)
    if cls:
        return cls(page).view()

    return ft.View(
        route="/404",
        controls=[
            ft.Column(
                [
                    ft.Text("404 • Page not found", size=24, color=ft.Colors.RED),
                    ft.FilledButton("Go Home", on_click=lambda _: page.go("/")),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                tight=True,
                spacing=20,
            )
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        vertical_alignment=ft.MainAxisAlignment.CENTER,
    )
