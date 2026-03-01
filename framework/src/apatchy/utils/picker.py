"""Curses-based interactive list picker for terminal menus."""

import curses
from typing import List, Optional


def pick_option(
    items: List[str],
    *,
    title: str = "",
    selected: int = 0,
) -> Optional[int]:
    """Show an interactive arrow-key menu and return the chosen index.

    Parameters
    ----------
    items
        Display strings for each option.
    title
        Header line shown above the list.
    selected
        Index to pre-select (0-based).

    Returns
    -------
    int or None
        The chosen index, or ``None`` if the user cancelled (Escape / q).
    """
    if not items:
        return None

    def _run(stdscr: "curses.window") -> Optional[int]:
        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)

        idx = max(0, min(selected, len(items) - 1))

        while True:
            stdscr.erase()
            max_y, max_x = stdscr.getmaxyx()

            # Title row
            row = 0
            if title:
                stdscr.addnstr(row, 0, title, max_x - 1, curses.A_BOLD)
                row += 1
                stdscr.addnstr(row, 0, "Arrow keys to move, Enter to select, q to cancel", max_x - 1, curses.A_DIM)
                row += 2  # blank line after hint

            visible = max_y - row
            if visible < 1:
                visible = 1

            # Scroll offset so the selection stays visible
            offset = 0
            if idx >= offset + visible:
                offset = idx - visible + 1
            if idx < offset:
                offset = idx

            for i in range(offset, min(offset + visible, len(items))):
                y = row + (i - offset)
                if y >= max_y:
                    break
                label = items[i]
                if len(label) > max_x - 3:
                    label = label[: max_x - 6] + "..."
                if i == idx:
                    stdscr.addnstr(y, 0, f" > {label}", max_x - 1, curses.color_pair(1) | curses.A_BOLD)
                else:
                    stdscr.addnstr(y, 0, f"   {label}", max_x - 1)

            stdscr.refresh()

            key = stdscr.getch()
            if key in (curses.KEY_UP, ord("k")):
                idx = max(0, idx - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                idx = min(len(items) - 1, idx + 1)
            elif key in (curses.KEY_PPAGE,):  # Page Up
                idx = max(0, idx - visible)
            elif key in (curses.KEY_NPAGE,):  # Page Down
                idx = min(len(items) - 1, idx + visible)
            elif key in (curses.KEY_HOME,):
                idx = 0
            elif key in (curses.KEY_END,):
                idx = len(items) - 1
            elif key in (curses.KEY_ENTER, ord("\n"), ord("\r")):
                return idx
            elif key in (27, ord("q")):  # Escape or q
                return None
            elif key == curses.KEY_RESIZE:
                pass  # loop will re-read maxyx

    return curses.wrapper(_run)
