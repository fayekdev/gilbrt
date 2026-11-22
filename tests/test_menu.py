"""Exercise the actual checkbox key bindings with platform-native pipe input."""

import unittest

from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from gilbrt.menu import select_checks


class CheckboxTests(unittest.TestCase):
    """Check selection, empty validation and cancellation without network access."""

    def choose(self, keys: str, selected: set[str]) -> set[str]:
        """Feed keyboard events into the real menu application."""
        with create_pipe_input() as pipe:
            pipe.send_text(keys)
            return select_checks(["passwords", "tokens", "headers"], selected,
                                 input=pipe, output=DummyOutput())

    def test_enter_preserves_default_selection(self) -> None:
        self.assertEqual(self.choose("\r", {"passwords", "tokens", "headers"}),
                         {"passwords", "tokens", "headers"})

    def test_arrow_and_space_select_multiple_boxes(self) -> None:
        self.assertEqual(self.choose(" \x1b[B \r", set()), {"passwords", "tokens"})

    def test_space_deselects_checked_box(self) -> None:
        self.assertEqual(self.choose(" \r", {"passwords", "tokens"}), {"tokens"})

    def test_toggle_all_and_empty_validation(self) -> None:
        # A clears all, Enter must refuse; Space then selects the first check.
        self.assertEqual(self.choose("a\r \r", {"passwords", "tokens", "headers"}), {"passwords"})
        self.assertEqual(self.choose("a\r", set()), {"passwords", "tokens", "headers"})

    def test_ctrl_c_and_eof_cancel(self) -> None:
        with self.assertRaises(KeyboardInterrupt):
            self.choose("\x03", {"passwords"})
        with self.assertRaises(EOFError):
            self.choose("\x04", {"passwords"})


if __name__ == "__main__":
    unittest.main()
