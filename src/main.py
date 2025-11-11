import flet as ft
from router import resolve_route
from db import connect_db


def main(page: ft.Page):
    page.title = "Dashboard"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 40

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
    conn = connect_db()
    page.username = 'aravindaksha'
    page.conn = conn
    page.go(page.route or "/")


ft.app(target=main)
