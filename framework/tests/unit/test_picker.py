"""Unit tests for the curses-based interactive picker."""

from unittest.mock import MagicMock, patch

import pytest

from apatchy.utils.picker import pick_option


def _fake_curses_wrapper(run_func, keys):
    """Simulate curses.wrapper by feeding a sequence of key presses."""
    import curses

    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (40, 80)

    key_iter = iter(keys)
    stdscr.getch.side_effect = key_iter

    # Stub out curses global calls
    with (
        patch("curses.curs_set"),
        patch("curses.use_default_colors"),
        patch("curses.init_pair"),
        patch("curses.color_pair", return_value=0),
        patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
    ):
        return pick_option.__wrapped__(run_func) if hasattr(pick_option, "__wrapped__") else None


class TestPickOption:
    """Tests for pick_option."""

    def test_empty_list_returns_none(self):
        assert pick_option([]) is None

    def test_select_first_item(self):
        import curses

        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [ord("\n")]

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta", "gamma"])
        assert result == 0

    def test_navigate_down_and_select(self):
        import curses

        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [curses.KEY_DOWN, curses.KEY_DOWN, ord("\n")]

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta", "gamma"])
        assert result == 2

    def test_escape_cancels(self):
        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [27]  # Escape

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta"])
        assert result is None

    def test_q_cancels(self):
        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [ord("q")]

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta"])
        assert result is None

    def test_pre_selected_index(self):
        import curses

        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [ord("\n")]

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta", "gamma"], selected=2)
        assert result == 2

    def test_up_does_not_go_below_zero(self):
        import curses

        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [curses.KEY_UP, curses.KEY_UP, ord("\n")]

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta", "gamma"])
        assert result == 0

    def test_down_does_not_exceed_list(self):
        import curses

        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [curses.KEY_DOWN, curses.KEY_DOWN, curses.KEY_DOWN, curses.KEY_DOWN, ord("\n")]

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta", "gamma"])
        assert result == 2

    def test_vim_keys_j_k(self):
        import curses

        stdscr = MagicMock()
        stdscr.getmaxyx.return_value = (40, 80)
        stdscr.getch.side_effect = [ord("j"), ord("j"), ord("k"), ord("\n")]

        with (
            patch("curses.curs_set"),
            patch("curses.use_default_colors"),
            patch("curses.init_pair"),
            patch("curses.color_pair", return_value=0),
            patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)),
        ):
            result = pick_option(["alpha", "beta", "gamma"])
        assert result == 1
