from __future__ import annotations

import tkinter as tk
from tkinter import ttk


FONT_FAMILY = "Segoe UI"
FONT_FAMILY_BOLD = "Segoe UI Semibold"
WINDOW_BG = "#EDF4FC"
SURFACE_BG = "#FFFFFF"
SURFACE_ALT_BG = "#F3F8FE"
BORDER = "#7FA6D6"
TEXT = "#0B1F33"
TEXT_MUTED = "#4F6278"
ACCENT = "#0057B8"
ACCENT_HOVER = "#003F87"
ACCENT_SOFT = "#DCEBFF"
DISABLED_BG = "#D8E3EF"
DISABLED_TEXT = "#71869C"
FOCUS = "#006FE6"
LIST_BG = "#FFFFFF"
LOG_BG = "#F6FAFF"
SUCCESS = "#2E7D32"
WARNING = "#B7791F"
ERROR = "#C62828"
OVERLAY_BG = "#0B1F33"
OVERLAY_ALPHA = 0.16


def _font_spec(family: str, size: int, *options: str) -> tuple:
    return (family, int(size), *tuple(str(x) for x in options))


def apply_splunk_light_theme(root: tk.Misc) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=WINDOW_BG)
    root.option_add("*Font", _font_spec(FONT_FAMILY, 10))
    root.option_add("*TCombobox*Listbox.font", _font_spec(FONT_FAMILY, 10))
    root.option_add("*TCombobox*Listbox.background", SURFACE_BG)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    style.configure(".", background=WINDOW_BG, foreground=TEXT, font=_font_spec(FONT_FAMILY, 10))
    style.configure("App.TFrame", background=WINDOW_BG)
    style.configure("TFrame", background=WINDOW_BG)
    style.configure("Card.TFrame", background=SURFACE_BG, borderwidth=1, relief="solid", bordercolor=BORDER)
    style.configure("Dialog.TFrame", background=SURFACE_BG)
    style.configure("CardInset.TFrame", background=SURFACE_ALT_BG)

    style.configure("TLabel", background=WINDOW_BG, foreground=TEXT, font=_font_spec(FONT_FAMILY, 10))
    style.configure("Card.TLabel", background=SURFACE_BG, foreground=TEXT, font=_font_spec(FONT_FAMILY, 10))
    style.configure("Dialog.TLabel", background=SURFACE_BG, foreground=TEXT, font=_font_spec(FONT_FAMILY, 10))
    style.configure("Section.TLabel", background=SURFACE_BG, foreground=TEXT, font=_font_spec(FONT_FAMILY_BOLD, 10))
    style.configure("Subtle.TLabel", background=SURFACE_BG, foreground=TEXT_MUTED, font=_font_spec(FONT_FAMILY, 9))

    style.configure(
        "TButton",
        background=SURFACE_ALT_BG,
        foreground=TEXT,
        bordercolor=BORDER,
        darkcolor=BORDER,
        lightcolor=BORDER,
        relief="flat",
        padding=(12, 7),
        focusthickness=1,
        focuscolor=FOCUS,
    )
    style.map(
        "TButton",
        background=[("active", "#E7F1FC"), ("pressed", ACCENT_SOFT), ("disabled", DISABLED_BG)],
        foreground=[("disabled", DISABLED_TEXT)],
        bordercolor=[("focus", FOCUS)],
    )
    style.configure(
        "Primary.TButton",
        background=ACCENT,
        foreground="#FFFFFF",
        bordercolor=ACCENT,
        darkcolor=ACCENT,
        lightcolor=ACCENT,
        relief="flat",
        padding=(12, 8),
    )
    style.map(
        "Primary.TButton",
        background=[("active", ACCENT_HOVER), ("pressed", "#002F66"), ("disabled", "#9DB2C8")],
        foreground=[("disabled", "#F5F8FC")],
        bordercolor=[("focus", FOCUS)],
    )

    style.configure(
        "TCheckbutton",
        background=SURFACE_BG,
        foreground=TEXT,
        font=_font_spec(FONT_FAMILY, 10),
    )
    style.map(
        "TCheckbutton",
        foreground=[("disabled", DISABLED_TEXT)],
        indicatorcolor=[("selected", ACCENT), ("!selected", SURFACE_BG)],
        background=[("active", ACCENT_SOFT), ("disabled", SURFACE_BG)],
    )

    style.configure(
        "TEntry",
        fieldbackground=SURFACE_BG,
        foreground=TEXT,
        bordercolor=BORDER,
        lightcolor=FOCUS,
        darkcolor=BORDER,
        insertcolor=TEXT,
        padding=(8, 6),
    )
    style.map(
        "TEntry",
        fieldbackground=[("disabled", DISABLED_BG)],
        foreground=[("disabled", DISABLED_TEXT)],
        bordercolor=[("focus", FOCUS), ("disabled", BORDER)],
        lightcolor=[("focus", FOCUS)],
    )

    style.configure(
        "TCombobox",
        fieldbackground=SURFACE_BG,
        background=SURFACE_BG,
        foreground=TEXT,
        bordercolor=BORDER,
        arrowcolor=TEXT_MUTED,
        lightcolor=FOCUS,
        darkcolor=BORDER,
        padding=(8, 5),
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", SURFACE_BG), ("disabled", DISABLED_BG)],
        background=[("active", ACCENT_SOFT), ("readonly", SURFACE_BG), ("disabled", DISABLED_BG)],
        foreground=[("disabled", DISABLED_TEXT)],
        arrowcolor=[("disabled", DISABLED_TEXT), ("active", ACCENT), ("readonly", TEXT_MUTED)],
        bordercolor=[("focus", FOCUS), ("disabled", BORDER)],
        lightcolor=[("focus", FOCUS)],
        selectbackground=[("readonly", ACCENT)],
        selectforeground=[("readonly", "#FFFFFF")],
    )

    style.configure(
        "TScrollbar",
        background=SURFACE_ALT_BG,
        troughcolor=WINDOW_BG,
        bordercolor=BORDER,
        arrowcolor=TEXT_MUTED,
    )
    style.map(
        "TScrollbar",
        background=[("active", "#DCEBFA"), ("pressed", "#C8DBF0")],
    )

    style.configure(
        "TProgressbar",
        troughcolor=ACCENT_SOFT,
        background=ACCENT,
        bordercolor=BORDER,
        lightcolor=ACCENT,
        darkcolor=ACCENT,
    )
    return style


def style_window(window: tk.Misc, *, surface: str = WINDOW_BG) -> None:
    window.configure(bg=surface)


def style_listbox(widget: tk.Listbox) -> None:
    widget.configure(
        bg=LIST_BG,
        fg=TEXT,
        relief="solid",
        borderwidth=1,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=FOCUS,
        selectbackground=ACCENT,
        selectforeground="#FFFFFF",
        activestyle="none",
        font=_font_spec(FONT_FAMILY, 10),
    )


def style_text_widget(widget: tk.Text) -> None:
    widget.configure(
        bg=LOG_BG,
        fg=TEXT,
        relief="solid",
        borderwidth=1,
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=FOCUS,
        insertbackground=TEXT,
        selectbackground=ACCENT,
        selectforeground="#FFFFFF",
        font=_font_spec(FONT_FAMILY, 10),
        padx=10,
        pady=8,
    )
