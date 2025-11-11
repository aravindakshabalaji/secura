import flet as ft

from ui.crypto_encrypt_decrypt import CryptoEncryptDecrypt
from ui.crypto_keys import CryptoKeys
from ui.crypto_suite import CryptoSuite
from ui.home import HomePage

ROUTES = {
    "/": HomePage,
    "/crypto": CryptoSuite,
    "/crypto/encrypt": CryptoEncryptDecrypt,
    "/crypto/sign": CryptoEncryptDecrypt,
    "/crypto/keys": CryptoKeys,
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
