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


def build_theme() -> ft.Theme:
    return ft.Theme(
        color_scheme_seed=ft.Colors.BLUE,
        use_material3=True,
        visual_density=ft.VisualDensity.COMFORTABLE,
    )


def section_title(text: str) -> ft.Text:
    return ft.Text(text, size=24, weight=ft.FontWeight.BOLD)


def subsection_title(text: str) -> ft.Text:
    return ft.Text(text, size=18, weight=ft.FontWeight.W_600)


def surface_card(content: ft.Control, padding: int = 16) -> ft.Card:
    return ft.Card(
        content=ft.Container(
            content,
            padding=padding,
            bgcolor=ft.ColorScheme.surface_container,
            border_radius=CARD_RADIUS,
        )
    )
