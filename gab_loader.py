from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ui_theme import ACCENT, TEXT_MUTED


class GABLoader(ttk.Frame):
    def __init__(self, parent: tk.Misc):
        super().__init__(parent, style="Dialog.TFrame")
        self._letters = [
            ttk.Label(self, text="G", style="Dialog.TLabel", font=("Segoe UI Semibold", 16)),
            ttk.Label(self, text="A", style="Dialog.TLabel", font=("Segoe UI Semibold", 16)),
            ttk.Label(self, text="B", style="Dialog.TLabel", font=("Segoe UI Semibold", 16)),
        ]
        for lbl in self._letters:
            lbl.configure(foreground=TEXT_MUTED)
            lbl.pack(side="left", padx=4)

        self._running = False
        self._idx = 0
        self._after_id: str | None = None

    def _tick(self) -> None:
        if not self._running:
            return
        for i, lbl in enumerate(self._letters):
            lbl.configure(foreground=ACCENT if i == self._idx else TEXT_MUTED)
        self._idx = (self._idx + 1) % len(self._letters)
        self._after_id = self.after(150, self._tick)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._idx = 0
        self._tick()

    def stop(self) -> None:
        self._running = False
        if self._after_id is not None:
            try:
                self.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        for lbl in self._letters:
            lbl.configure(foreground=TEXT_MUTED)

