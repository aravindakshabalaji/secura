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

from db import connect_db
from router import resolve_route
from ui.theme import APP_TITLE, PADDING_APP, build_theme


def main(page: ft.Page):
    page.title = APP_TITLE
    page.padding = PADDING_APP
    page.scroll = ft.ScrollMode.AUTO
    page.window_min_width = 900
    page.window_min_height = 600

    page.fonts = {
        "Inter": "/fonts/Inter.ttc",
        "JetBrains Mono": "/fonts/JetBrainsMono-Regular.ttf",
    }
    page.theme_mode = (
        ft.ThemeMode.LIGHT
        if page.client_storage.get("secura.light_mode")
        else ft.ThemeMode.DARK
    )
    page.theme = build_theme(page.theme_mode)

    page.conn = connect_db()

    def route_change(e: ft.RouteChangeEvent):
        page.views.clear()
        view = resolve_route(page, page.route)
        page.views.append(view)
        page.update()

    def view_pop(e: ft.ViewPopEvent):
        page.views.pop()
        page.go(page.views[-1].route if page.views else "/")

    page.on_route_change = route_change
    page.on_view_pop = view_pop

    hf = ft.HapticFeedback()
    page.overlay.append(hf)
    page.hf: ft.HapticFeedback = hf

    page.go(page.route or "/")


if __name__ == "__main__":
    ft.app(target=main)
