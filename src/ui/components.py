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


def DangerButton(
    page: ft.Page, text: str, icon=None, on_click=None
) -> ft.ElevatedButton:
    return ft.ElevatedButton(
        text,
        icon=icon,
        style=button_style(),
        bgcolor=ft.Colors.RED_700,
        color=ft.Colors.WHITE,
        on_click=_generate_click_event(page, on_click),
    )


def IconButton(page: ft.Page, *args, **kwargs) -> ft.IconButton:
    on_click = kwargs.pop("on_click", None)

    kwargs["on_click"] = _generate_click_event(page, on_click)

    return ft.IconButton(*args, **kwargs)


def IconTextButton(page: ft.Page, text: str, icon, on_click=None) -> ft.TextButton:
    return ft.TextButton(
        text,
        icon=icon,
        style=button_style(),
        on_click=_generate_click_event(page, on_click),
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
