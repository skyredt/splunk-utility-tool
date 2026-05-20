from __future__ import annotations

import inspect
import logging
import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional

from gab_loader import GABLoader
from overlay import create_overlay, remove_overlay
from ui_prompt import show_modal_prompt
from ui_theme import SURFACE_BG, style_window


logger = logging.getLogger(__name__)


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


def run_with_progress(
    parent: tk.Misc,
    title: str,
    start_message: str,
    task_callable: Callable,
    *,
    on_success: Optional[Callable[[object], None]] = None,
    on_error: Optional[Callable[[Exception], None]] = None,
    on_cancel_request: Optional[Callable[[Callable[[str], None]], None]] = None,
    cancel_button_text: str = "Cancel",
) -> None:
    overlay = create_overlay(parent)
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.transient(parent)
    dialog.resizable(False, False)
    style_window(dialog, surface=SURFACE_BG)
    try:
        dialog.attributes("-topmost", True)
    except tk.TclError:
        pass

    frame = ttk.Frame(dialog, padding=16, style="Dialog.TFrame")
    frame.pack(fill="both", expand=True)
    loader = GABLoader(frame)
    loader.pack(pady=(2, 10))
    status_var = tk.StringVar(value=start_message)
    status_lbl = ttk.Label(
        frame,
        textvariable=status_var,
        justify="center",
        anchor="center",
        wraplength=420,
        style="Dialog.TLabel",
    )
    status_lbl.pack(fill="x", pady=(0, 10))
    bar = ttk.Progressbar(frame, mode="indeterminate", length=320)
    bar.pack(fill="x")
    if on_cancel_request is not None:
        button_row = ttk.Frame(frame, style="Dialog.TFrame")
        button_row.pack(fill="x", pady=(12, 0))
        cancel_btn = ttk.Button(button_row, text=cancel_button_text)
        cancel_btn.pack(side="right")
    else:
        cancel_btn = None

    _center_dialog(parent, dialog)
    dialog.grab_set()
    dialog.protocol("WM_DELETE_WINDOW", lambda: None)
    loader.start()
    bar.start(10)

    event_q: "queue.Queue[tuple[str, object]]" = queue.Queue()

    def _status_update(text: str) -> None:
        event_q.put(("status", str(text)))

    def _worker() -> None:
        try:
            sig = inspect.signature(task_callable)
            if len(sig.parameters) >= 1:
                result = task_callable(_status_update)
            else:
                result = task_callable()
            event_q.put(("done", result))
        except Exception as exc:
            logger.error("Background task failed: %s", type(exc).__name__)
            event_q.put(("error", exc))

    threading.Thread(target=_worker, daemon=True).start()

    def _close_dialog() -> None:
        try:
            bar.stop()
        except Exception:
            pass
        loader.stop()
        try:
            dialog.grab_release()
        except Exception:
            pass
        if dialog.winfo_exists():
            dialog.destroy()
        remove_overlay(overlay)

    def _handle_cancel() -> None:
        if on_cancel_request is None:
            return
        try:
            on_cancel_request(_status_update)
        except Exception as exc:
            logger.error("Cancel handler failed: %s", type(exc).__name__)

    if cancel_btn is not None:
        cancel_btn.configure(command=_handle_cancel)

    def _poll() -> None:
        if not dialog.winfo_exists():
            return
        try:
            while True:
                event, payload = event_q.get_nowait()
                if event == "status":
                    status_var.set(str(payload))
                    status_lbl.update_idletasks()
                    _center_dialog(parent, dialog)
                elif event == "done":
                    _close_dialog()
                    if on_success:
                        on_success(payload)
                    return
                elif event == "error":
                    _close_dialog()
                    err = payload if isinstance(payload, Exception) else RuntimeError("Unknown background error")
                    if on_error:
                        on_error(err)
                    else:
                        show_modal_prompt(
                            parent,
                            "Operation Failed",
                            "The operation failed. Please review logs and try again.",
                            "error",
                        )
                    return
        except queue.Empty:
            pass
        dialog.after(100, _poll)

    dialog.after(100, _poll)
    parent.wait_window(dialog)
