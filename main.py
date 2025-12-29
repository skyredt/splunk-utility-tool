"""Launcher for Splunk Utility Tool (Tkinter).

This launcher calls the Tk-based GUI implemented in `splunk_report_tk.py`.
It intentionally avoids Qt/PySide6 so the tool can run on Windows machines
without Visual Studio or extra GUI dependencies.
"""

from __future__ import annotations

import sys


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]

    if argv and argv[0] in ("-h", "--help"):
        print("Usage: python main.py")
        return

    # Import and run the Tk GUI. Import is deferred so importing this module
    # doesn't require tkinter to be present immediately.
    try:
        from splunk_report_tk import main as tk_main
    except Exception as e:
        print(f"Failed to start Tk GUI: {e}")
        return

    tk_main()


if __name__ == "__main__":
    main()

