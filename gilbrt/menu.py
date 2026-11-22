"""Cross-platform terminal checkboxes for the guided audit flow."""

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.input import Input
from prompt_toolkit.key_binding import KeyBindings, KeyPressEvent
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.output import Output
from prompt_toolkit.styles import Style


def select_checks(options: list[str], selected: set[str], *,
                  input: Input | None = None, output: Output | None = None) -> set[str]:
    """Select checks with arrows/Space; Enter submits, A toggles all, Ctrl+C cancels.

    Input/output injection supports keyboard integration tests without a real TTY.
    No selection is committed until Enter is pressed with at least one check.
    """
    if not options or len(set(options)) != len(options):
        raise ValueError("Checkbox options must be nonempty and unique")
    checked = set(options) & selected
    cursor = 0
    error = ""
    keys = KeyBindings()

    def render() -> list[tuple[str, str]]:
        """Draw ASCII boxes consistently in Windows and Unix terminals."""
        fragments = []
        for index, name in enumerate(options):
            style = "class:focused" if index == cursor else ""
            fragments.append((style, f"{'>' if index == cursor else ' '} [{'x' if name in checked else ' '}] {name}"))
            if index < len(options) - 1:
                fragments.append(("", "\n"))
        return fragments

    @keys.add("up")
    @keys.add("k")
    def previous(_event: KeyPressEvent) -> None:
        """Move to the previous option, wrapping at the beginning."""
        nonlocal cursor
        cursor = (cursor - 1) % len(options)

    @keys.add("down")
    @keys.add("j")
    def next_option(_event: KeyPressEvent) -> None:
        """Move to the next option, wrapping at the end."""
        nonlocal cursor
        cursor = (cursor + 1) % len(options)

    @keys.add(" ")
    def toggle(_event: KeyPressEvent) -> None:
        """Toggle the highlighted checkbox."""
        nonlocal error
        checked.symmetric_difference_update({options[cursor]})
        error = ""

    @keys.add("a")
    @keys.add("A")
    def toggle_all(_event: KeyPressEvent) -> None:
        """Select all checks, or clear all if all are already selected."""
        nonlocal error
        if len(checked) == len(options):
            checked.clear()
        else:
            checked.update(options)
        error = ""

    @keys.add("enter")
    def submit(event: KeyPressEvent) -> None:
        """Reject an empty selection before continuing to report preferences."""
        nonlocal error
        if checked:
            event.app.exit(result=set(checked))
        else:
            error = "Select at least one check (Space toggles; A selects all)."

    @keys.add("c-c")
    def cancel(event: KeyPressEvent) -> None:
        """Use the CLI's existing interruption path without making requests."""
        event.app.exit(exception=KeyboardInterrupt())

    @keys.add("c-d")
    def end_input(event: KeyPressEvent) -> None:
        """Treat end-of-input as setup cancellation."""
        event.app.exit(exception=EOFError())

    control = FormattedTextControl(render, focusable=True, show_cursor=False,
                                   get_cursor_position=lambda: Point(x=0, y=cursor))
    layout = Layout(HSplit([
        Window(FormattedTextControl("What should gilbrt search for?"), height=1, style="class:title"),
        Window(FormattedTextControl("Up/Down: move | Space: toggle | A: all/none | Enter: continue | Ctrl+C: cancel"),
               dont_extend_height=True, style="class:help"),
        Window(control, dont_extend_height=True, wrap_lines=False),
        Window(FormattedTextControl(lambda: error or f"{len(checked)} of {len(options)} checks selected"),
               height=1, style="class:status"),
    ]), focused_element=control)
    application: Application[set[str]] = Application(
        layout=layout, key_bindings=keys, full_screen=False,
        style=Style.from_dict({"title": "bold", "focused": "bg:#164e63 #ffffff bold",
                               "help": "#888888", "status": "#d7af00"}),
        input=input, output=output,
    )
    return application.run()
