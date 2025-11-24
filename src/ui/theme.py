# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (c) 2025 Aravindaksha Balaji
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

APP_TITLE = "Dashboard"
GAP_XS = 6
GAP_SM = 10
GAP_MD = 16
GAP_LG = 20
GAP_XL = 28
PADDING_APP = 24
CARD_RADIUS = 14
BTN_RADIUS = 12

DARK_TOKENS = {
    "primary": "#4D9FFF",
    "on_primary": "#000000",
    "primary_container": "#153B66",
    "on_primary_container": "#D8EEFF",
    "primary_fixed": "#3E8AE6",
    "primary_fixed_dim": "#2E6FB5",
    "on_primary_fixed": "#FFFFFF",
    "on_primary_fixed_variant": "#E6F2FF",
    "secondary": "#B388FF",
    "on_secondary": "#000000",
    "secondary_container": "#39245A",
    "on_secondary_container": "#EBDCFF",
    "secondary_fixed": "#9E6EFF",
    "secondary_fixed_dim": "#7A4BCC",
    "on_secondary_fixed": "#FFFFFF",
    "on_secondary_fixed_variant": "#F1E6FF",
    "tertiary": "#4CF2FF",
    "on_tertiary": "#000000",
    "tertiary_container": "#00363A",
    "on_tertiary_container": "#CFF9FB",
    "tertiary_fixed": "#35D8E6",
    "tertiary_fixed_dim": "#259EAA",
    "on_tertiary_fixed": "#000000",
    "on_tertiary_fixed_variant": "#E6FBFF",
    "background": "#000000",
    "on_background": "#FFFFFF",
    "surface": "#121212",
    "on_surface": "#FFFFFF",
    "surface_variant": "#1C1C1C",
    "on_surface_variant": "#DCDCDC",
    "surface_bright": "#1F1F1F",
    "surface_dim": "#0A0A0A",
    "surface_tint": "#0A84FF",
    "surface_container": "#0E0E0E",
    "surface_container_high": "#1C1C1C",
    "surface_container_low": "#090909",
    "surface_container_lowest": "#050505",
    "outline": "#FFFFFF",
    "outline_variant": "#B5B5B5",
    "shadow": "#000000",
    "scrim": "rgba(0,0,0,0.6)",
    "inverse_surface": "#FFFFFF",
    "on_inverse_surface": "#000000",
    "inverse_primary": "#4D9FFF",
    "error": "#FF5C5C",
    "on_error": "#000000",
    "error_container": "#3A0F0F",
    "on_error_container": "#FFDFDF",
}

LIGHT_TOKENS = {
    "primary": "#0A84FF",
    "on_primary": "#FFFFFF",
    "primary_container": "#D8EEFF",
    "on_primary_container": "#00203A",
    "primary_fixed": "#0C75E6",
    "primary_fixed_dim": "#095FAF",
    "on_primary_fixed": "#FFFFFF",
    "on_primary_fixed_variant": "#DDEEFF",
    "secondary": "#8E5CFF",
    "on_secondary": "#FFFFFF",
    "secondary_container": "#EEE0FF",
    "on_secondary_container": "#2E0046",
    "secondary_fixed": "#7A47FF",
    "secondary_fixed_dim": "#5D36C0",
    "on_secondary_fixed": "#FFFFFF",
    "on_secondary_fixed_variant": "#F4EDFF",
    "tertiary": "#00CBE6",
    "on_tertiary": "#FFFFFF",
    "tertiary_container": "#DFF9FB",
    "on_tertiary_container": "#002022",
    "tertiary_fixed": "#00B9D0",
    "tertiary_fixed_dim": "#008B9A",
    "on_tertiary_fixed": "#FFFFFF",
    "on_tertiary_fixed_variant": "#E6FBFF",
    "background": "#FFFFFF",
    "on_background": "#000000",
    "surface": "#F7F7F7",
    "on_surface": "#000000",
    "surface_variant": "#EFEFEF",
    "on_surface_variant": "#333333",
    "surface_bright": "#FFFFFF",
    "surface_dim": "#F0F0F0",
    "surface_tint": "#0A84FF",
    "surface_container": "#FFFFFF",
    "surface_container_high": "#F1F7FF",
    "surface_container_low": "#FFFFFF",
    "surface_container_lowest": "#FFFFFF",
    "outline": "#D6D6D6",
    "outline_variant": "#E6E6E6",
    "shadow": "#000000",
    "scrim": "rgba(0,0,0,0.16)",
    "inverse_surface": "#121212",
    "on_inverse_surface": "#FFFFFF",
    "inverse_primary": "#0A84FF",
    "error": "#E53935",
    "on_error": "#FFFFFF",
    "error_container": "#FFEBE9",
    "on_error_container": "#610000",
}


def build_theme(mode=ft.ThemeMode.DARK, color_seed=None) -> ft.Theme:
    tokens = DARK_TOKENS if mode == ft.ThemeMode.DARK else LIGHT_TOKENS
    seed = color_seed or tokens["primary"]

    cs = ft.ColorScheme(
        primary=tokens["primary"],
        on_primary=tokens["on_primary"],
        primary_container=tokens.get("primary_container"),
        on_primary_container=tokens.get("on_primary_container"),
        primary_fixed=tokens.get("primary_fixed"),
        primary_fixed_dim=tokens.get("primary_fixed_dim"),
        on_primary_fixed=tokens.get("on_primary_fixed"),
        on_primary_fixed_variant=tokens.get("on_primary_fixed_variant"),
        secondary=tokens["secondary"],
        on_secondary=tokens["on_secondary"],
        secondary_container=tokens.get("secondary_container"),
        on_secondary_container=tokens.get("on_secondary_container"),
        secondary_fixed=tokens.get("secondary_fixed"),
        secondary_fixed_dim=tokens.get("secondary_fixed_dim"),
        on_secondary_fixed=tokens.get("on_secondary_fixed"),
        on_secondary_fixed_variant=tokens.get("on_secondary_fixed_variant"),
        tertiary=tokens.get("tertiary"),
        on_tertiary=tokens.get("on_tertiary"),
        tertiary_container=tokens.get("tertiary_container"),
        on_tertiary_container=tokens.get("on_tertiary_container"),
        tertiary_fixed=tokens.get("tertiary_fixed"),
        tertiary_fixed_dim=tokens.get("tertiary_fixed_dim"),
        on_tertiary_fixed=tokens.get("on_tertiary_fixed"),
        on_tertiary_fixed_variant=tokens.get("on_tertiary_fixed_variant"),
        background=tokens["background"],
        on_background=tokens["on_background"],
        surface=tokens["surface"],
        on_surface=tokens["on_surface"],
        surface_variant=tokens.get("surface_variant"),
        on_surface_variant=tokens.get("on_surface_variant"),
        surface_bright=tokens.get("surface_bright"),
        surface_dim=tokens.get("surface_dim"),
        surface_tint=tokens.get("surface_tint"),
        surface_container=tokens.get("surface_container"),
        surface_container_high=tokens.get("surface_container_high"),
        surface_container_low=tokens.get("surface_container_low"),
        surface_container_lowest=tokens.get("surface_container_lowest"),
        outline=tokens.get("outline"),
        outline_variant=tokens.get("outline_variant"),
        shadow=tokens.get("shadow"),
        scrim=tokens.get("scrim"),
        inverse_surface=tokens.get("inverse_surface"),
        on_inverse_surface=tokens.get("on_inverse_surface"),
        inverse_primary=tokens.get("inverse_primary"),
        error=tokens.get("error"),
        on_error=tokens.get("on_error"),
        error_container=tokens.get("error_container"),
        on_error_container=tokens.get("on_error_container"),
    )

    theme = ft.Theme(
        color_scheme_seed=seed,
        color_scheme=cs,
        use_material3=True,
        visual_density=ft.VisualDensity.COMFORTABLE,
        font_family="Inter",
        canvas_color=tokens.get("background"),
        card_color=tokens.get("surface"),
        divider_color=tokens.get("outline"),
        focus_color=tokens.get("primary"),
        scaffold_bgcolor=tokens.get("background"),
        shadow_color=tokens.get("shadow"),
    )

    return theme


def section_title(text: str) -> ft.Text:
    return ft.Text(text, size=24, weight=ft.FontWeight.BOLD)


def subsection_title(text: str) -> ft.Text:
    return ft.Text(text, size=18, weight=ft.FontWeight.W_600)


def surface_card(content: ft.Control, padding: int = 16) -> ft.Card:
    return ft.Card(
        content=ft.Container(
            content,
            padding=padding,
            bgcolor=ft.Colors.SURFACE,
            border_radius=CARD_RADIUS,
        )
    )
