from __future__ import annotations

import os
import sys
import tkinter as tk


APP_USER_MODEL_ID = "CIO.SplunkUtilityTool.4"
APP_ICON_RELATIVE_PATH = os.path.join("assets", "app_icon.ico")


def resource_path(relative_path: str) -> str:
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def app_icon_path() -> str:
    return resource_path(APP_ICON_RELATIVE_PATH)


def set_windows_app_user_model_id() -> None:
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


def apply_window_icon(window: tk.Misc) -> None:
    icon_path = app_icon_path()
    if not os.path.exists(icon_path):
        return
    try:
        window.iconbitmap(icon_path)
    except Exception:
        pass
