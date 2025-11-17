import flet as ft

from .theme import BTN_RADIUS, GAP_SM


def button_style() -> ft.ButtonStyle:
    return ft.ButtonStyle(
        shape=ft.RoundedRectangleBorder(radius=BTN_RADIUS),
        padding=ft.padding.all(14),
    )


def PrimaryButton(
    page: ft.Page, text: str, icon=None, on_click=None
) -> ft.FilledButton:
    def click_event(e):
        page.hf.heavy_impact()
        on_click(e)

    return ft.FilledButton(text, icon=icon, style=button_style(), on_click=click_event)


def TonalButton(
    page: ft.Page, text: str, icon=None, on_click=None
) -> ft.FilledTonalButton:
    def click_event(e):
        page.hf.heavy_impact()
        on_click(e)

    return ft.FilledTonalButton(
        text, icon=icon, style=button_style(), on_click=click_event
    )


def DangerButton(
    page: ft.Page, text: str, icon=None, on_click=None
) -> ft.ElevatedButton:
    def click_event(e):
        page.hf.heavy_impact()
        on_click(e)

    return ft.ElevatedButton(
        text,
        icon=icon,
        style=button_style(),
        bgcolor=ft.Colors.RED_700,
        color=ft.Colors.WHITE,
        on_click=click_event,
    )


def IconButton(page: ft.Page, *args, **kwargs) -> ft.IconButton:
    on_click = kwargs.pop("on_click", None)

    def click_event(e):
        page.hf.heavy_impact()
        if on_click:
            on_click(e)

    kwargs["on_click"] = click_event

    return ft.IconButton(*args, **kwargs)


def IconTextButton(page: ft.Page, text: str, icon, on_click=None) -> ft.TextButton:
    def click_event(e):
        page.hf.heavy_impact()
        on_click(e)

    return ft.TextButton(text, icon=icon, style=button_style(), on_click=click_event)


def toolbar_back(page: ft.Page, title: str, route: str) -> ft.Row:
    return ft.Row(
        [
            IconButton(
                page,
                ft.Icons.ARROW_BACK,
                tooltip="Back",
                on_click=lambda _: page.go(route),
            ),
            ft.Text(title, size=28, weight=ft.FontWeight.BOLD),
        ],
        alignment=ft.MainAxisAlignment.START,
        spacing=GAP_SM,
    )


def scrollable_table(table: ft.DataTable, min_width: int = 1100) -> ft.Container:
    return ft.Container(
        content=ft.Row(
            controls=[ft.Container(content=table, width=min_width)],
            scroll=ft.ScrollMode.ALWAYS,  # horizontal scroll
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
