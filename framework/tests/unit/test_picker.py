"""Unit tests for the curses-based interactive picker."""

import contextlib
import curses
from unittest.mock import MagicMock, patch

from apatchy.utils.picker import pick_option


def _mock_pick(items, keys, **kwargs):
    """Run pick_option with a mocked curses environment and predetermined keys."""
    stdscr = MagicMock()
    stdscr.getmaxyx.return_value = (40, 80)
    stdscr.getch.side_effect = list(keys)

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch("curses.curs_set"))
        stack.enter_context(patch("curses.use_default_colors"))
        stack.enter_context(patch("curses.init_pair"))
        stack.enter_context(patch("curses.color_pair", return_value=0))
        stack.enter_context(patch("curses.wrapper", side_effect=lambda fn: fn(stdscr)))
        return pick_option(items, **kwargs)


class TestPickOption:
    """Tests for pick_option."""

    def test_empty_list_returns_none(self):
        """Empty item list returns None without entering curses."""
        assert pick_option([]) is None

    def test_select_first_item(self):
        """Pressing Enter immediately selects the first item."""
        assert _mock_pick(["alpha", "beta", "gamma"], [ord("\n")]) == 0

    def test_navigate_down_and_select(self):
        """Arrow-down twice then Enter selects the third item."""
        keys = [curses.KEY_DOWN, curses.KEY_DOWN, ord("\n")]
        assert _mock_pick(["alpha", "beta", "gamma"], keys) == 2

    def test_escape_cancels(self):
        """Pressing Escape returns None."""
        assert _mock_pick(["alpha", "beta"], [27]) is None

    def test_q_cancels(self):
        """Pressing q returns None."""
        assert _mock_pick(["alpha", "beta"], [ord("q")]) is None

    def test_pre_selected_index(self):
        """Pre-selected index is honoured when Enter is pressed immediately."""
        assert _mock_pick(["alpha", "beta", "gamma"], [ord("\n")], selected=2) == 2

    def test_up_does_not_go_below_zero(self):
        """Arrow-up at index 0 stays at 0."""
        keys = [curses.KEY_UP, curses.KEY_UP, ord("\n")]
        assert _mock_pick(["alpha", "beta", "gamma"], keys) == 0

    def test_down_does_not_exceed_list(self):
        """Arrow-down past the last item clamps to the last index."""
        keys = [curses.KEY_DOWN] * 4 + [ord("\n")]
        assert _mock_pick(["alpha", "beta", "gamma"], keys) == 2

    def test_vim_keys_j_k(self):
        """Vim-style j/k navigation works."""
        keys = [ord("j"), ord("j"), ord("k"), ord("\n")]
        assert _mock_pick(["alpha", "beta", "gamma"], keys) == 1
