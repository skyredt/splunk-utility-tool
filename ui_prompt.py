from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from overlay import create_overlay, remove_overlay
from ui_theme import SURFACE_BG, style_window


def _center_dialog(parent: tk.Misc, dialog: tk.Toplevel) -> None:
    parent.update_idletasks()
    dialog.update_idletasks()
    pw = parent.winfo_width()
    ph = parent.winfo_height()
    px = parent.winfo_rootx()
    py = parent.winfo_rooty()
    dw = dialog.winfo_reqwidth()
    dh = dialog.winfo_reqheight()
    x = px + max((pw - dw) // 2, 0)
    y = py + max((ph - dh) // 2, 0)
    dialog.geometry(f"{dw}x{dh}+{x}+{y}")


def show_modal_prompt(
    parent: tk.Misc,
    title: str,
    message: str,
    prompt_type: str = "info",
):
    kind = (prompt_type or "info").lower()
    if kind not in {"info", "warning", "error", "confirm"}:
        raise ValueError(f"Unsupported prompt_type: {prompt_type}")

    overlay = create_overlay(parent)
    result = {"value": False if kind == "confirm" else None}
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.resizable(False, False)
    style_window(dialog, surface=SURFACE_BG)
    try:
        dialog.attributes("-topmost", True)
    except tk.TclError:
        pass

    frame = ttk.Frame(dialog, padding=14, style="Dialog.TFrame")
    frame.pack(fill="both", expand=True)

    label = ttk.Label(frame, text=message, justify="left", wraplength=460, style="Dialog.TLabel")
    label.pack(fill="both", expand=True)

    button_row = ttk.Frame(frame, style="Dialog.TFrame")
    button_row.pack(fill="x", pady=(12, 0))

    def _close(value):
        result["value"] = value
        dialog.destroy()

    if kind == "confirm":
        no_btn = ttk.Button(button_row, text="No", command=lambda: _close(False))
        no_btn.pack(side="right")
        yes_btn = ttk.Button(button_row, text="Yes", command=lambda: _close(True))
        yes_btn.pack(side="right", padx=(0, 8))
    else:
        ok_btn = ttk.Button(button_row, text="OK", command=lambda: _close(None))
        ok_btn.pack(side="right")

    dialog.protocol("WM_DELETE_WINDOW", lambda: _close(False if kind == "confirm" else None))
    _center_dialog(parent, dialog)
    dialog.grab_set()
    dialog.focus_force()
    try:
        parent.wait_window(dialog)
    finally:
        remove_overlay(overlay)
    return result["value"] if kind == "confirm" else None

