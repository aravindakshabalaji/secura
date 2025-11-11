import flet as ft

from db import connect_db
from router import resolve_route
from ui.theme import APP_TITLE, PADDING_APP, build_theme


def main(page: ft.Page):

    page.title = APP_TITLE
    page.theme_mode = ft.ThemeMode.SYSTEM
    page.theme = build_theme()
    page.padding = PADDING_APP
    page.scroll = ft.ScrollMode.AUTO
    page.window_min_width = 900
    page.window_min_height = 600

    page.username = "aravindaksha"
    page.conn = connect_db()

    def route_change(e: ft.RouteChangeEvent):
        page.views.clear()
        view = resolve_route(page, page.route)
        page.views.append(view)
        page.update()

    def view_pop(e: ft.ViewPopEvent):
        page.views.pop()
        if page.views:
            page.go(page.views[-1].route)
        else:
            page.go("/")

    page.on_route_change = route_change
    page.on_view_pop = view_pop

    hf = ft.HapticFeedback()
    page.overlay.append(hf)
    page.hf: ft.HapticFeedback = hf

    page.go(page.route or "/")


if __name__ == "__main__":
    ft.app(target=main)
