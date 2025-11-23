import flet as ft

from ui.components import IconButton, toolbar_back, vertical_scroll
from ui.theme import GAP_MD, surface_card


class BaseView:
    def __init__(self, page: ft.Page):
        self.page = page

        self.key_picker = ft.FilePicker()
        self.key_picker.on_result = self._on_key_pick
        self._key_field_target = None

        self.page.overlay.append(self.key_picker)

    def _pick_key_for_field(self, field: ft.TextField, exts):
        self._key_field_target = field
        self.key_picker.pick_files(
            allow_multiple=False,
            file_type=ft.FilePickerFileType.CUSTOM,
            allowed_extensions=exts,
        )

    def _on_key_pick(self, e: ft.FilePickerResultEvent):
        target = self._key_field_target
        self._key_field_target = None

        if not target:
            return

        if e.files:
            f = e.files[0]
            try:
                path = f.path or f.name
                with open(path, "r", encoding="utf-8") as fh:
                    target.value = fh.read()
                self.page.update()
            except Exception as err:
                target.error_text = f"Failed to import: {err}"
                self.page.update()

    def _key_field(self, label, hint_text, upload_tooltip, exts=["key"]):
        key_field = ft.TextField(
            label=label,
            multiline=True,
            max_lines=8,
            width=820,
            prefix_icon=ft.Icons.KEY,
            hint_text=hint_text,
            password=True,
        )

        toggle_btn = IconButton(
            self.page, icon=ft.Icons.VISIBILITY_OFF, tooltip="Show / Hide Key"
        )

        def toggle(_):
            key_field.password = not key_field.password
            toggle_btn.icon = (
                ft.Icons.VISIBILITY
                if not key_field.password
                else ft.Icons.VISIBILITY_OFF
            )
            self.page.update()

        toggle_btn.on_click = toggle

        key_field.suffix = ft.Row(
            [
                IconButton(
                    self.page,
                    icon=ft.Icons.FILE_UPLOAD,
                    tooltip=f"Import {upload_tooltip} file",
                    on_click=lambda _: (
                        self._show_not_supported("Uploading files")
                        if self._platform() == "web"
                        else self._pick_key_for_field(key_field, exts)
                    ),
                ),
                toggle_btn,
            ],
            spacing=4,
            tight=True,
        )

        return key_field

    def _paste_field(self, field: ft.TextField):
        try:
            field.value = self.page.get_clipboard()
        except Exception:
            field.value = ""
        self.page.update()

    def _paste_button(self, field):
        return IconButton(
            self.page,
            icon=ft.Icons.PASTE,
            tooltip="Paste value from clipboard",
            on_click=lambda _: self._paste_field(field),
        )

    def _copy(self, value):
        self._snack("Copied value")
        self.page.set_clipboard(value)

    def _copy_field(self, field):
        if field.value:
            self._copy(field.value)

    def _copy_button(self, value, valuename="value", icon=ft.Icons.COPY):
        return IconButton(
            self.page,
            icon,
            tooltip=f"Copy {valuename}",
            on_click=lambda _: self._copy_field(value)
            if isinstance(value, ft.TextField)
            else self._copy(value),
        )

    def _platform(self):
        try:
            if self.page.web:
                return "web"
            return self.page.platform.name.lower()
        except Exception:
            return None

    def _show_not_supported(self, action: str):
        plat = self._platform()
        self.page.open(
            ft.SnackBar(
                ft.Text(
                    f"{action} not supported on platform: {plat.title() or 'unknown'}"
                )
            )
        )
        self.page.update()

    def _snack(self, text: str):
        self.page.open(ft.SnackBar(ft.Text(text)))
        self.page.update()

    def _clear_errors(self, *fields: ft.TextField, warning: ft.Text | None = None):
        for f in fields:
            f.error_text = None
        if warning is not None:
            warning.visible = False
            warning.value = ""
        self.page.update()

    def render_header(self, title, back_route="/crypto"):
        return toolbar_back(self.page, title, back_route)

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
