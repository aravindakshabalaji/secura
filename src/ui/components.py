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

from .theme import BTN_RADIUS


def button_style() -> ft.ButtonStyle:
    return ft.ButtonStyle(
        shape=ft.RoundedRectangleBorder(radius=BTN_RADIUS),
        padding=ft.padding.all(14),
    )


def _generate_click_event(page, on_click, impact="medium"):
    def click_event(e):
        try:
            {
                "light": page.hf.light_impact,
                "medium": page.hf.medium_impact,
                "heavy": page.hf.heavy_impact,
                "vibrate": page.hf.vibrate,
            }[impact]()
        except Exception:
            pass

        if on_click:
            on_click(e)

    return click_event


def PrimaryButton(
    page: ft.Page, text: str, icon=None, on_click=None
) -> ft.FilledButton:
    return ft.FilledButton(
        text,
        icon=icon,
        style=button_style(),
        on_click=_generate_click_event(page, on_click),
    )


def TonalButton(
    page: ft.Page, text: str, icon=None, on_click=None
) -> ft.OutlinedButton:
    return ft.OutlinedButton(
        text,
        icon=icon,
        style=button_style(),
        on_click=_generate_click_event(page, on_click),
    )


def IconButton(page: ft.Page, *args, **kwargs) -> ft.IconButton:
    on_click = kwargs.pop("on_click", None)

    kwargs["on_click"] = _generate_click_event(page, on_click)

    return ft.IconButton(*args, **kwargs)


def TextField(*args, **kwargs) -> ft.TextField:
    return ft.TextField(
        *args, **kwargs, text_style=ft.TextStyle(font_family="JetBrains Mono")
    )


def toolbar_back(page: ft.Page, title: str, route: str) -> ft.Row:
    return ft.Row(
        [
            IconButton(
                page,
                icon=ft.Icons.ARROW_BACK,
                tooltip="Go Back",
                on_click=lambda _: page.go(route),
            ),
            ft.Text(
                title,
                size=26,
                weight=ft.FontWeight.BOLD,
                expand=1,
                max_lines=None,
                overflow=ft.TextOverflow.VISIBLE,
            ),
        ],
        alignment=ft.MainAxisAlignment.START,
    )


def scrollable_table(table: ft.DataTable, min_width: int = 1100) -> ft.Container:
    return ft.Container(
        content=ft.Row(
            controls=[ft.Container(content=table, width=min_width)],
            scroll=ft.ScrollMode.ALWAYS,
        ),
        expand=True,
    )


def vertical_scroll(control: ft.Control) -> ft.Container:
    return ft.Container(
        content=ft.ListView(
            controls=[control],
            expand=True,
            spacing=0,
            padding=0,
        ),
        expand=True,
    )
