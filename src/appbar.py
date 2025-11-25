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

from ui.components import TonalButton, vertical_scroll

APP_NAME = "Secura"
APP_VERSION = "1.0.0"
DEVELOPER = "Aravindaksha Balaji"
GITHUB_URL = "https://github.com/aravindakshabalaji/secura"
PYCRYPT_LIB_URL = "https://pypi.org/project/pycrypt-lib/"
GPL_URL = "https://www.gnu.org/licenses/gpl-3.0.en.html"
COPYRIGHT = (
    "Copyright (C) 2025 Aravindaksha Balaji\n"
    "\n"
    "This program is free software: you can redistribute it and/or modify\n"
    "it under the terms of the GNU General Public License as published by\n"
    "the Free Software Foundation, either version 3 of the License, or\n"
    "(at your option) any later version.\n"
    "\n"
    "This program is distributed in the hope that it will be useful,\n"
    "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
    "GNU General Public License for more details.\n"
    "\n"
    "You should have received a copy of the GNU General Public License\n"
    "along with this program. If not, see <https://www.gnu.org/licenses/>.\n"
)


def build_appbar(page: ft.Page, toggle_theme):
    width = page.window.width
    compact = width < 700

    leading_content = ft.Row(
        [
            ft.Container(
                ft.Icon(ft.Icons.SHIELD),
                padding=8,
                bgcolor=ft.Colors.WHITE12,
                border_radius=8,
                margin=ft.margin.only(left=10),
            ),
            ft.Text(APP_NAME, weight=ft.FontWeight.W_700, size=16),
        ],
        spacing=10,
        alignment=ft.MainAxisAlignment.CENTER,
    )

    actions = []

    def _open_about(_):
        def close_dlg(_):
            dlg.open = False
            page.update()

        content_col = ft.Column(
            [
                ft.Text(APP_NAME, size=18, weight=ft.FontWeight.W_700),
                ft.Text(
                    f"Version: {APP_VERSION}", size=12, color=ft.ColorScheme.secondary
                ),
                ft.Text(
                    f"Developer: {DEVELOPER}", size=12, color=ft.ColorScheme.secondary
                ),
                ft.Divider(),
                ft.Text("Source Code Repository", weight=ft.FontWeight.W_600),
                ft.TextButton(
                    "Open in GitHub", on_click=lambda e: page.launch_url(GITHUB_URL)
                ),
                ft.Divider(),
                ft.Text("Powered By", weight=ft.FontWeight.W_600),
                ft.Row(
                    [
                        ft.Text("pycrypt by Aravindaksha Balaji"),
                        ft.TextButton(
                            "Open in PyPI",
                            on_click=lambda e: page.launch_url(PYCRYPT_LIB_URL),
                        ),
                    ],
                    wrap=True,
                    spacing=8,
                ),
                ft.Divider(),
                ft.Text("License", weight=ft.FontWeight.W_600),
                ft.TextButton(
                    "GPL-3.0-or-later",
                    on_click=lambda e: page.launch_url(GPL_URL),
                ),
                ft.Divider(),
                ft.Text("Copyright & Warranty", weight=ft.FontWeight.W_600),
                ft.Text(COPYRIGHT, size=11),
            ],
            spacing=10,
            tight=True,
            width=800,
        )

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("About the app"),
            content=vertical_scroll(content_col),
            actions=[
                TonalButton(page, "Close", ft.Icons.CLOSE, close_dlg),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        page.open(dlg)
        page.update()

    actions.append(
        ft.IconButton(
            ft.Icons.INFO_OUTLINED,
            tooltip="About the app",
            on_click=_open_about,
        )
    )

    actions.append(
        ft.IconButton(
            ft.Icons.DARK_MODE_OUTLINED
            if page.client_storage.get("secura.light_mode")
            else ft.Icons.LIGHT_MODE_OUTLINED,
            on_click=toggle_theme,
            tooltip="Toggle theme",
        )
    )

    avatar = ft.Container(
        ft.Row(
            [
                ft.CircleAvatar(
                    content=ft.Text(
                        (page.username or "U")[0].upper(), weight=ft.FontWeight.W_700
                    ),
                    foreground_image_src=f"https://github.com/identicons/{page.username}.png"
                    if page.username
                    else None,
                )
            ]
        ),
        padding=ft.padding.all(2),
        border=ft.border.all(1, ft.Colors.WHITE12),
        border_radius=8,
    )

    def _logout(e):
        page.username = None
        page.master_key = None
        page.ecb = None
        page.go("/")

    def _profile(_):
        def close_dlg(_):
            control.open = False
            page.update()

        control = ft.AlertDialog(
            visible=True,
            content=ft.Container(
                ft.Column(
                    [
                        ft.CircleAvatar(
                            content=ft.Text(
                                (page.username or "U")[0].upper(),
                                weight=ft.FontWeight.W_700,
                            ),
                            foreground_image_src=f"https://github.com/identicons/{page.username}.png"
                            if page.username
                            else None,
                            width=100,
                            height=100,
                        ),
                        ft.Divider(),
                        ft.Text(value=f"Welcome, {page.username or 'User'}!"),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                height=250,
            ),
            actions=[TonalButton(page, "Close", ft.Icons.CANCEL, close_dlg)],
        )
        page.open(control)

    profile_menu = ft.PopupMenuButton(
        content=avatar,
        items=[
            ft.PopupMenuItem(
                content=ft.Column(
                    [
                        ft.Text(page.username or "User", weight=ft.FontWeight.W_700),
                        ft.Divider(height=1),
                    ],
                    tight=True,
                    alignment=ft.MainAxisAlignment.CENTER,
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                on_click=lambda e: None,
            ),
            ft.PopupMenuItem(
                content=ft.Row(
                    [ft.Icon(ft.Icons.PERSON), ft.Text("View Profile")], spacing=12
                ),
                on_click=_profile,
            ),
            ft.PopupMenuItem(
                content=ft.Row(
                    [
                        ft.Icon(ft.Icons.LOGOUT, color=ft.Colors.RED),
                        ft.Text("Logout", color=ft.Colors.RED),
                    ],
                    spacing=12,
                ),
                on_click=_logout,
            ),
        ],
    )

    actions.append(profile_menu)

    leading = leading_content

    appbar = ft.AppBar(
        leading=leading,
        leading_width=120 if not compact else 40,
        center_title=False,
        bgcolor=ft.Colors.SURFACE,
        elevation=6,
        actions=[
            ft.Container(ft.Row(actions, spacing=12), margin=ft.margin.only(right=20))
        ],
    )

    return appbar
