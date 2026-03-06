from __future__ import annotations

import tkinter as tk


_OVERLAYS: dict[int, tuple[tk.Toplevel, int]] = {}


def _sync_geometry(parent: tk.Misc, overlay: tk.Toplevel) -> None:
    parent.update_idletasks()
    x = parent.winfo_rootx()
    y = parent.winfo_rooty()
    w = max(parent.winfo_width(), 1)
    h = max(parent.winfo_height(), 1)
    overlay.geometry(f"{w}x{h}+{x}+{y}")


def create_overlay(parent: tk.Misc) -> tk.Toplevel:
    key = int(parent.winfo_id())
    current = _OVERLAYS.get(key)
    if current and current[0].winfo_exists():
        win, ref_count = current
        _OVERLAYS[key] = (win, ref_count + 1)
        _sync_geometry(parent, win)
        win.lift(parent)
        return win

    overlay = tk.Toplevel(parent)
    overlay.overrideredirect(True)
    overlay.configure(bg="black")
    overlay.transient(parent)
    try:
        overlay.attributes("-alpha", 0.32)
    except tk.TclError:
        pass
    _sync_geometry(parent, overlay)
    overlay.lift(parent)
    overlay.bind("<Button>", lambda _e: "break")
    overlay.bind("<Key>", lambda _e: "break")
    _OVERLAYS[key] = (overlay, 1)
    return overlay


def remove_overlay(overlay_window: tk.Toplevel | None) -> None:
    if overlay_window is None:
        return
    for key, (win, ref_count) in list(_OVERLAYS.items()):
        if win is overlay_window:
            if ref_count > 1 and win.winfo_exists():
                _OVERLAYS[key] = (win, ref_count - 1)
                return
            _OVERLAYS.pop(key, None)
            if win.winfo_exists():
                win.destroy()
            return
    if overlay_window.winfo_exists():
        overlay_window.destroy()

