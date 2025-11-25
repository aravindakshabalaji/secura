# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2025 Aravindaksha Balaji
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import flet as ft

from crypto.aes_view import AESEncryptDecrypt
from crypto.dh_view import DHEncryptDecrypt
from crypto.hash_view import HashView
from crypto.home import HomePage
from crypto.keys_view import KeyManagement
from crypto.rsa_view import RSAEncryptDecrypt
from crypto.suite_view import CryptoSuite
from ui.components import PrimaryButton

ROUTES = {
    "/": HomePage,
    "/crypto": CryptoSuite,
    "/crypto/aes": AESEncryptDecrypt,
    "/crypto/keys": KeyManagement,
    "/crypto/rsa": RSAEncryptDecrypt,
    "/crypto/hash": HashView,
    "/crypto/dh": DHEncryptDecrypt,
}


def resolve_route(page: ft.Page, route: str) -> ft.View:
    cls = ROUTES.get(route)
    if cls:
        return cls(page).view()

    return ft.View(
        appbar=page.appbar,
        route="/404",
        controls=[
            ft.Column(
                [
                    ft.Text("404 • Page not found", size=24, color=ft.Colors.RED),
                    PrimaryButton(page, "Go Home", on_click=lambda _: page.go("/")),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                tight=True,
                spacing=20,
            )
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        vertical_alignment=ft.MainAxisAlignment.CENTER,
    )
