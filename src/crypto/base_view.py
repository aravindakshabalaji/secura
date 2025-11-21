import flet as ft

from ui.components import IconButton, vertical_scroll
from ui.theme import GAP_MD, surface_card


class BaseView:
    def __init__(self, page: ft.Page):
        self.page = page

    def paste_field(self, field: ft.TextField):
        try:
            field.value = self.page.get_clipboard()
        except Exception:
            field.value = ""
        self.page.update()

    def copy(self, value):
        self.snack("✅ Copied value")
        self.page.set_clipboard(value)

    def copy_field(self, field):
        if field.value:
            self.copy(field.value)

    def copy_button(self, value, valuename="value", icon=ft.Icons.COPY):
        return IconButton(
            self.page,
            icon,
            tooltip=f"Copy {valuename}",
            on_click=lambda _: self.copy_field(value)
            if isinstance(value, ft.TextField)
            else self.copy(value),
        )

    def platform(self):
        try:
            if self.page.web:
                return "web"
            return self.page.platform.name.lower()
        except Exception:
            return None

    def show_not_supported(self, action: str):
        plat = self.platform()
        self.page.open(
            ft.SnackBar(
                ft.Text(
                    f"{action} not supported on platform: {plat.title() or 'unknown'}"
                )
            )
        )
        self.page.update()

    def snack(self, text: str):
        self.page.open(ft.SnackBar(ft.Text(text)))
        self.page.update()

    def clear_errors(self, *fields: ft.TextField, warning: ft.Text | None = None):
        for f in fields:
            f.error_text = None
        if warning is not None:
            warning.visible = False
            warning.value = ""
        self.page.update()

    def render_header(self, title, back_route="/crypto"):
        return ft.Row(
            [
                IconButton(
                    self.page,
                    icon=ft.Icons.ARROW_BACK,
                    tooltip="Go Back",
                    on_click=lambda _: self.page.go(back_route),
                ),
                ft.Text(title, size=26, weight=ft.FontWeight.BOLD),
            ],
            alignment=ft.MainAxisAlignment.START,
        )

    def render_tabs(self, content):
        return ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=content,
            expand=1,
        )

    def render_view(self, header, tabs, route):
        content = ft.Column(
            [ft.SafeArea(content=header, top=True), ft.Divider(), tabs],
            spacing=GAP_MD,
            expand=True,
        )

        return ft.View(
            route,
            controls=[ft.Container(content, padding=20, expand=True)],
        )

    def render_tab(self, content):
        col = ft.Column(
            content,
            spacing=GAP_MD,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        )

        return ft.Container(vertical_scroll(surface_card(col)), padding=10)
