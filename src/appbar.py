import flet as ft

from ui.components import TonalButton


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
                margin=ft.margin.only(left=10),
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
                        page.username[0].upper(), weight=ft.FontWeight.W_700
                    ),
                    foreground_image_src=f"https://github.com/identicons/{page.username}.png",
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
                                page.username[0].upper(), weight=ft.FontWeight.W_700
                            ),
                            foreground_image_src=f"https://github.com/identicons/{page.username}.png",
                            width=100,
                            height=100,
                        ),
                        ft.Divider(),
                        ft.Text(value=f"Welcome, {page.username}!"),
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
                    [ft.Icon(ft.Icons.PERSON), ft.Text("View profile")], spacing=12
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
