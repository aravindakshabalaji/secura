import flet as ft


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
            ft.Icons.LIGHT_MODE_OUTLINED, on_click=toggle_theme, tooltip="Toggle theme"
        )
    )

    avatar = ft.Container(
        ft.Row(
            [
                ft.CircleAvatar(
                    content=ft.Text("AB", weight=ft.FontWeight.W_700),
                    foreground_image_src=f"https://github.com/identicons/{page.username}.png",
                )
            ]
        ),
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
