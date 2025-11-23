import flet as ft

from db import connect_db
from router import resolve_route
from ui.theme import APP_TITLE, PADDING_APP, build_theme


def build_appbar(page: ft.Page, toggle_theme, color_change):
    width = page.window.width
    compact = width < 700

    leading_content = ft.Row(
        [
            ft.Container(
                ft.Icon(ft.Icons.SHIELD),
                padding=8,
                bgcolor=ft.Colors.WHITE12,
                border_radius=8,
                margin=ft.margin.only(left=10)
            ),
            ft.Text("Secura", weight=ft.FontWeight.W_700, size=16),
        ],
        spacing=10,
        alignment=ft.MainAxisAlignment.CENTER,
    )

    color_picker = ft.PopupMenuButton(
        icon=ft.Icons.PALETTE_OUTLINED,
        items=[
            ft.PopupMenuItem(
                content=ft.Text("Blue", color=ft.Colors.BLUE), on_click=color_change
            ),
            ft.PopupMenuItem(
                content=ft.Text("Indigo", color=ft.Colors.INDIGO), on_click=color_change
            ),
            ft.PopupMenuItem(
                content=ft.Text("Deep Orange", color=ft.Colors.DEEP_ORANGE),
                on_click=color_change,
            ),
            ft.PopupMenuItem(
                content=ft.Text("Purple", color=ft.Colors.PURPLE), on_click=color_change
            ),
            ft.PopupMenuItem(
                content=ft.Text("Blue Grey", color=ft.Colors.BLUE_GREY),
                on_click=color_change,
            ),
        ],
    )

    actions = []

    actions.append(color_picker)
    actions.append(
        ft.IconButton(
            ft.Icons.LIGHT_MODE_OUTLINED, on_click=toggle_theme, tooltip="Toggle theme"
        )
    )

    avatar = ft.Container(
        ft.Row([ft.CircleAvatar(content=ft.Text("AB", weight=ft.FontWeight.W_700))]),
        padding=ft.padding.all(2),
        border=ft.border.all(1, ft.Colors.WHITE12),
        border_radius=8,
    )

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
                ),
                on_click=lambda e: None,
            ),
            ft.PopupMenuItem(
                content=ft.Row(
                    [ft.Icon(ft.Icons.PERSON), ft.Text("View profile")], spacing=12
                ),
                on_click=lambda e: page.open(
                    ft.AlertDialog(
                        title=ft.Text("Profile"),
                        content=ft.Text("Profile screen not implemented"),
                        actions=[
                            ft.TextButton(
                                "OK", on_click=lambda e: page.close(e.control.parent)
                            )
                        ],
                    )
                ),
            ),
            ft.PopupMenuItem(
                content=ft.Row(
                    [ft.Icon(ft.Icons.LOGOUT), ft.Text("Logout")], spacing=12
                ),
                on_click=lambda e: page.open(
                    ft.AlertDialog(
                        title=ft.Text("Logout"),
                        content=ft.Text("Logout screen not implemented"),
                        actions=[
                            ft.TextButton(
                                "OK", on_click=lambda e: page.close(e.control.parent)
                            )
                        ],
                    )
                ),
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


def main(page: ft.Page):
    page.title = APP_TITLE
    page.padding = PADDING_APP
    page.scroll = ft.ScrollMode.AUTO
    page.window_min_width = 900
    page.window_min_height = 600

    page.theme_mode = ft.ThemeMode.DARK
    page.theme = build_theme()

    page.username = "aravindaksha"
    page.conn = connect_db()

    def toggle_theme(e):
        if page.theme_mode == ft.ThemeMode.DARK:
            page.theme_mode = ft.ThemeMode.LIGHT
            e.control.icon = ft.Icons.DARK_MODE_OUTLINED
        else:
            page.theme_mode = ft.ThemeMode.DARK
            e.control.icon = ft.Icons.LIGHT_MODE_OUTLINED

        page.update()

    def color_change(e):
        page.theme = build_theme(e.control.content.color)
        page.update()

    page.appbar = build_appbar(page, toggle_theme, color_change)

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
