from __future__ import annotations

import tkinter as tk
from tkinter import ttk


FONT_FAMILY = "Segoe UI"
FONT_FAMILY_BOLD = "Segoe UI Semibold"
WINDOW_BG = "#F3F7F2"
SURFACE_BG = "#FFFFFF"
SURFACE_ALT_BG = "#FAFCF9"
BORDER = "#CDD7D0"
TEXT = "#1E2821"
TEXT_MUTED = "#607065"
ACCENT = "#2E7D4A"
ACCENT_HOVER = "#27653C"
ACCENT_SOFT = "#DDEEE2"
DISABLED_BG = "#E8EEE9"
DISABLED_TEXT = "#95A39A"
FOCUS = "#8DBB9A"
LIST_BG = "#FFFFFF"
LOG_BG = "#FBFDFC"
SUCCESS = "#2E7D4A"
WARNING = "#9A6A0A"
ERROR = "#B44F4F"
OVERLAY_BG = "#243127"
OVERLAY_ALPHA = 0.16


def apply_splunk_light_theme(root: tk.Misc) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=WINDOW_BG)
    root.option_add("*Font", f"{FONT_FAMILY} 10")
    root.option_add("*TCombobox*Listbox.font", f"{FONT_FAMILY} 10")
    root.option_add("*TCombobox*Listbox.background", SURFACE_BG)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")

    style.configure(".", background=WINDOW_BG, foreground=TEXT, font=(FONT_FAMILY, 10))
    style.configure("App.TFrame", background=WINDOW_BG)
    style.configure("TFrame", background=WINDOW_BG)
    style.configure("Card.TFrame", background=SURFACE_BG, borderwidth=1, relief="solid")
    style.configure("Dialog.TFrame", background=SURFACE_BG)
    style.configure("CardInset.TFrame", background=SURFACE_ALT_BG)

    style.configure("TLabel", background=WINDOW_BG, foreground=TEXT, font=(FONT_FAMILY, 10))
    style.configure("Card.TLabel", background=SURFACE_BG, foreground=TEXT, font=(FONT_FAMILY, 10))
    style.configure("Dialog.TLabel", background=SURFACE_BG, foreground=TEXT, font=(FONT_FAMILY, 10))
    style.configure("Section.TLabel", background=SURFACE_BG, foreground=TEXT, font=(FONT_FAMILY_BOLD, 10))
    style.configure("Subtle.TLabel", background=SURFACE_BG, foreground=TEXT_MUTED, font=(FONT_FAMILY, 9))

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
        background=[("active", "#EEF4EF"), ("pressed", "#E4ECE6"), ("disabled", DISABLED_BG)],
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
        background=[("active", ACCENT_HOVER), ("pressed", "#1F5331"), ("disabled", "#A7BAAD")],
        foreground=[("disabled", "#F4F7F2")],
        bordercolor=[("focus", FOCUS)],
    )

    style.configure(
        "TCheckbutton",
        background=SURFACE_BG,
        foreground=TEXT,
        font=(FONT_FAMILY, 10),
    )
    style.map(
        "TCheckbutton",
        foreground=[("disabled", DISABLED_TEXT)],
        indicatorcolor=[("selected", ACCENT), ("!selected", SURFACE_BG)],
        background=[("active", SURFACE_BG)],
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
        bordercolor=[("focus", FOCUS)],
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
        background=[("readonly", SURFACE_BG), ("disabled", DISABLED_BG)],
        foreground=[("disabled", DISABLED_TEXT)],
        bordercolor=[("focus", FOCUS)],
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
        background=[("active", "#E2EAE3"), ("pressed", "#D8E2DA")],
    )

    style.configure(
        "TProgressbar",
        troughcolor="#E3ECE5",
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
        font=(FONT_FAMILY, 10),
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
        font=(FONT_FAMILY, 10),
        padx=10,
        pady=8,
    )
