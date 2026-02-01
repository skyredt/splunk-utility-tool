from __future__ import annotations

import queue
import sys
import threading
from datetime import datetime, date

import tkinter as tk
from tkinter import ttk, messagebox

try:
    # Optional calendar widget for nicer date selection
    from tkcalendar import DateEntry
    HAS_TKCALENDAR = True
except ImportError:  # fall back to simple Entry if tkcalendar is not installed
    HAS_TKCALENDAR = False

from splunk_engine import (
    SplunkClient,
    SplunkConfig,
    load_config,
    run_dispatch_multi,
)


class ReportsApp(ttk.Frame):
    DISPATCH_STATUS_WAIT_SECONDS = 60
    DISPATCH_STATUS_POLL_SECONDS = 2

    def __init__(self, master: tk.Tk, cfg: SplunkConfig):
        super().__init__(master)
        self.master = master
        self.cfg = cfg

        self.client: SplunkClient | None = None
        self.report_ids: list[str] = []
        self.report_names: list[str] = []
        self.report_email_flags: list[bool] = []
        self.filtered_indices: list[int] = []
        self._dispatch_in_progress = False
        self._dispatch_queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._dispatch_thread: threading.Thread | None = None

        self._build_ui()
        self._set_connected_state(False)

        # Load servers from config
        self._load_servers()

    # --------------- UI construction ---------------

    def _build_ui(self) -> None:
        self.pack(fill="both", expand=True)
        self.master.title("Splunk Utility Tool v3.0 (Tk)")
        self.master.minsize(900, 600)

        # Top row: server/app + controls
        top = ttk.Frame(self)
        top.pack(side="top", fill="x", padx=10, pady=8)

        ttk.Label(top, text="Server:").pack(side="left")
        self.server_var = tk.StringVar()
        self.server_combo = ttk.Combobox(top, textvariable=self.server_var, state="readonly", width=40)
        self.server_combo.bind("<<ComboboxSelected>>", self.on_server_selection_changed)
        self.server_combo.pack(side="left", padx=(4, 12))

        ttk.Label(top, text="App:").pack(side="left")
        self.app_var = tk.StringVar()
        self.app_combo = ttk.Combobox(top, textvariable=self.app_var, state="disabled", width=30)
        self.app_combo.bind("<<ComboboxSelected>>", self.on_app_changed)
        self.app_combo.pack(side="left", padx=(4, 12))

        self.connect_button = ttk.Button(top, text="Connect", command=self.on_connect_clicked)
        self.connect_button.pack(side="left")

        self.reload_button = ttk.Button(top, text="Reload", command=self.on_reload_clicked, state="disabled")
        self.reload_button.pack(side="left", padx=(8, 0))

        # Spacer
        top_spacer = ttk.Label(top)
        top_spacer.pack(side="left", expand=True)

        # Middle row: reports list + options
        middle = ttk.Frame(self)
        middle.pack(side="top", fill="both", expand=True, padx=10, pady=8)

        # Left: reports list
        left = ttk.Frame(middle)
        left.pack(side="left", fill="both", expand=True)

        ttk.Label(left, text="Reports:").pack(anchor="w")
        search_row = ttk.Frame(left)
        search_row.pack(fill="x", pady=(2, 6))

        ttk.Label(search_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_search_changed)
        self.search_entry = ttk.Entry(search_row, textvariable=self.search_var)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(4, 4))
        self.clear_search_button = ttk.Button(search_row, text="Clear", command=self.on_clear_search)
        self.clear_search_button.pack(side="left")

        self.reports_list = tk.Listbox(
            left,
            selectmode="extended",
            exportselection=False,
        )
        self.reports_list.pack(side="left", fill="both", expand=True)

        reports_scroll = ttk.Scrollbar(left, orient="vertical", command=self.reports_list.yview)
        reports_scroll.pack(side="right", fill="y")
        self.reports_list.config(yscrollcommand=reports_scroll.set)

        # Right: options
        right = ttk.Frame(middle)
        right.pack(side="left", fill="y", padx=(12, 0))

        # Frequency
        ttk.Label(right, text="Frequency:").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.frequency_var = tk.StringVar(value="Daily")
        self.frequency_combo = ttk.Combobox(
            right,
            textvariable=self.frequency_var,
            values=["Daily", "Weekly", "Monthly"],
            state="readonly",
            width=15,
        )
        self.frequency_combo.grid(row=0, column=1, sticky="w", pady=(0, 4))

        # Start date
        ttk.Label(right, text="Start date:").grid(row=1, column=0, sticky="w", pady=4)
        self.start_date_widget = self._make_date_widget(right)
        self.start_date_widget.grid(row=1, column=1, sticky="w", pady=4)

        # End date
        ttk.Label(right, text="End date:").grid(row=2, column=0, sticky="w", pady=4)
        self.end_date_widget = self._make_date_widget(right)
        self.end_date_widget.grid(row=2, column=1, sticky="w", pady=4)

        # No change checkbox
        self.no_change_var = tk.BooleanVar(value=False)
        self.no_change_chk = ttk.Checkbutton(
            right,
            text="Use saved search time range (no override)",
            variable=self.no_change_var,
            command=self.on_no_change_toggled,
        )
        self.no_change_chk.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 4))

        # Send button
        self.send_button = ttk.Button(right, text="Send reports", command=self.on_send_clicked, state="disabled")
        self.send_button.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(16, 0))

        for i in range(2):
            right.grid_columnconfigure(i, weight=1)

        # Bottom: log area
        bottom = ttk.Frame(self)
        bottom.pack(side="top", fill="both", expand=True, padx=10, pady=(0, 10))

        ttk.Label(bottom, text="Log:").pack(anchor="w")
        self.log_text = tk.Text(bottom, height=12, wrap="word", state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True)

        log_scroll = ttk.Scrollbar(bottom, orient="vertical", command=self.log_text.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=log_scroll.set)

    def _make_date_widget(self, parent):
        """Create a date picker: DateEntry when tkcalendar is available, otherwise a plain Entry."""
        today = date.today()
        if HAS_TKCALENDAR:
            widget = DateEntry(parent, date_pattern="yyyy-mm-dd")
            widget.set_date(today)
        else:
            widget = ttk.Entry(parent, width=12)
            widget.insert(0, today.strftime("%Y-%m-%d"))
        return widget

    def _get_date_from_widget(self, widget) -> date | None:
        if HAS_TKCALENDAR and isinstance(widget, DateEntry):
            return widget.get_date()
        else:
            text = widget.get().strip()
            if not text:
                return None
            try:
                d = datetime.strptime(text, "%Y-%m-%d").date()
                return d
            except ValueError:
                return None

    # --------------- State helpers ---------------

    def _load_servers(self) -> None:
        self.server_combo["values"] = self.cfg.servers
        if self.cfg.servers:
            self.server_combo.current(0)

    def _set_connected_state(self, connected: bool) -> None:
        if self._dispatch_in_progress:
            return
        self.connect_button.configure(text="Disconnect" if connected else "Connect")
        state_app = "readonly" if connected else "disabled"
        state_btn = "normal" if connected else "disabled"

        self.app_combo.configure(state=state_app)
        self.reload_button.configure(state=state_btn)
        self.send_button.configure(state=state_btn)

        if not connected:
            self.client = None
            self.app_combo.set("")
            self.app_combo["values"] = ()
            self.reports_list.delete(0, "end")
            self.report_ids = []
            self.report_names = []
            self.report_email_flags = []
            self.filtered_indices = []
            self.search_var.set("")

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _selected_server(self) -> str | None:
        value = self.server_var.get().strip()
        if not value:
            return None
        return value

    def _set_dispatch_state(self, in_progress: bool) -> None:
        self._dispatch_in_progress = in_progress
        if in_progress:
            self.connect_button.configure(state="disabled")
            self.server_combo.configure(state="disabled")
            self.app_combo.configure(state="disabled")
            self.reload_button.configure(state="disabled")
            self.send_button.configure(state="disabled")
            self.frequency_combo.configure(state="disabled")
            self.no_change_chk.configure(state="disabled")
            self.start_date_widget.configure(state="disabled")
            self.end_date_widget.configure(state="disabled")
        else:
            self._set_connected_state(self.client is not None)
            self.no_change_chk.configure(state="normal")
            self.on_no_change_toggled()

    def _apply_search_filter(self) -> None:
        term = self.search_var.get().strip().lower()
        self.reports_list.delete(0, "end")
        self.filtered_indices = []
        for idx, name in enumerate(self.report_names):
            if not term or term in name.lower():
                self.reports_list.insert("end", name)
                self.filtered_indices.append(idx)

    # --------------- Event handlers ---------------

    def on_server_selection_changed(self, event=None) -> None:
        if self.client is not None:
            self._append_log("Server changed; disconnecting current session.")
            self._set_connected_state(False)

    def on_connect_clicked(self) -> None:
        if self.client is not None:
            self._append_log("Disconnected from server.")
            self._set_connected_state(False)
            return
        self._connect_current_server()

    def _connect_current_server(self) -> None:
        server_url = self._selected_server()
        if not server_url:
            messagebox.showwarning("No server", "Please select a server first.")
            return

        self._append_log(f"Connecting to {server_url} ...")
        try:
            client = SplunkClient(
                base_url=server_url,
                username=self.cfg.username,
                password=self.cfg.password,
            )
            apps = client.list_apps()
        except Exception as e:
            self._append_log(f"ERROR connecting to {server_url}: {e}")
            messagebox.showerror(
                "Connection error",
                f"Failed to connect to {server_url}:\n{e}",
            )
            self._set_connected_state(False)
            return

        self.client = client
        self.app_combo.configure(state="readonly")
        self.app_combo["values"] = apps
        if apps:
            self.app_combo.current(0)
        self._set_connected_state(True)

        if apps:
            self.on_app_changed()  # load reports for first app

        self._append_log(f"Connected. {len(apps)} app(s) loaded.")

    def on_reload_clicked(self) -> None:
        if self.client is None:
            messagebox.showwarning("Not connected", "Please connect to a server first.")
            return
        self.on_app_changed()

    def on_app_changed(self, event=None) -> None:
        if self.client is None:
            return
        app = self.app_var.get().strip()
        if not app:
            return

        self._append_log(f"Loading reports from app '{app}' ...")
        try:
            ids, names, email_flags = self.client.list_saved_searches(app)
            self.report_ids = ids
            self.report_names = names
            self.report_email_flags = email_flags
            self._apply_search_filter()

            self._append_log(f"Loaded {len(names)} report(s).")
        except Exception as e:
            self._append_log(f"ERROR loading reports for app '{app}': {e}")
            messagebox.showerror(
                "Error",
                f"Failed to load saved searches for app '{app}':\n{e}",
            )
            self.report_ids = []
            self.report_names = []
            self.report_email_flags = []
            self.reports_list.delete(0, "end")
            self.filtered_indices = []

    def on_search_changed(self, *args) -> None:
        if self.report_names:
            self._apply_search_filter()
        else:
            self.reports_list.delete(0, "end")
            self.filtered_indices = []

    def on_clear_search(self) -> None:
        self.search_var.set("")

    def _dispatch_worker(self, params: dict) -> None:
        def log_callback(line: str) -> None:
            self._dispatch_queue.put(("log", line))

        try:
            run_dispatch_multi(log_callback=log_callback, **params)
            self._dispatch_queue.put(("done", None))
        except Exception as e:
            self._dispatch_queue.put(("err", e))

    def _poll_dispatch_queue(self) -> None:
        done = False
        while True:
            try:
                status, payload = self._dispatch_queue.get_nowait()
            except queue.Empty:
                break

            if status == "log":
                self._append_log(str(payload))
            elif status == "err":
                self._append_log(f"ERROR during dispatch: {payload}")
                messagebox.showerror(
                    "Dispatch error",
                    f"Error while dispatching reports:\n{payload}",
                )
                done = True
            elif status == "done":
                done = True

        if done:
            self._set_dispatch_state(False)
        elif self._dispatch_in_progress:
            self.after(150, self._poll_dispatch_queue)

    def on_no_change_toggled(self) -> None:
        if self._dispatch_in_progress:
            return
        # Optional behavior: when "no change" is on, grey out frequency/date,
        # because they won't be used.
        no_change = self.no_change_var.get()
        state = "disabled" if no_change else "normal"
        self.frequency_combo.configure(state="readonly" if not no_change else "disabled")
        if HAS_TKCALENDAR:
            self.start_date_widget.configure(state=state)
            self.end_date_widget.configure(state=state)
        else:
            self.start_date_widget.configure(state=state)
            self.end_date_widget.configure(state=state)

    def on_send_clicked(self) -> None:
        if self.client is None:
            messagebox.showwarning("Not connected", "Please connect to a server first.")
            return
        if self._dispatch_in_progress:
            messagebox.showinfo("Dispatch running", "A dispatch is already in progress.")
            return

        # Selected reports
        selected_display_indices = list(self.reports_list.curselection())
        if not selected_display_indices:
            messagebox.showinfo("No reports selected", "Please select at least one report.")
            return
        selected_indices = [
            self.filtered_indices[i]
            for i in selected_display_indices
            if i < len(self.filtered_indices)
        ]

        # Dates
        if not self.no_change_var.get():
            start_d = self._get_date_from_widget(self.start_date_widget)
            end_d = self._get_date_from_widget(self.end_date_widget)
            if start_d is None or end_d is None:
                messagebox.showwarning(
                    "Invalid dates",
                    "Please enter valid Start and End dates (YYYY-MM-DD).",
                )
                return

            start = datetime(start_d.year, start_d.month, start_d.day)
            end = datetime(end_d.year, end_d.month, end_d.day)
            if end <= start:
                messagebox.showwarning("Invalid date range", "End date must be after start date.")
                return
        else:
            # When using saved search time range, we still need a range for logging;
            # use today's date as a placeholder window.
            today = date.today()
            start = datetime(today.year, today.month, today.day)
            end = start

        frequency = self.frequency_var.get()
        no_change = self.no_change_var.get()

        # Warn for saved searches without email action enabled
        missing_email = [
            self.report_names[i]
            for i in selected_indices
            if i < len(self.report_email_flags) and not self.report_email_flags[i]
        ]
        if missing_email:
            self._append_log(
                "WARNING: Email action disabled for the following saved searches:"
            )
            for name in missing_email:
                self._append_log(f"  - {name}")

        self._append_log("")
        self._append_log(
            f"Sending {len(selected_indices)} report(s) - frequency={frequency}, "
            f"range={start} -> {end}, no_change={no_change}"
        )

        params = {
            "client": self.client,
            "report_ids": self.report_ids,
            "report_names": self.report_names,
            "selected_indices": selected_indices,
            "frequency": frequency,
            "start": start,
            "end": end,
            "no_change": no_change,
            "wait_seconds": self.DISPATCH_STATUS_WAIT_SECONDS,
            "poll_interval": self.DISPATCH_STATUS_POLL_SECONDS,
        }
        while True:
            try:
                self._dispatch_queue.get_nowait()
            except queue.Empty:
                break
        self._set_dispatch_state(True)
        self._dispatch_thread = threading.Thread(
            target=self._dispatch_worker,
            args=(params,),
            daemon=True,
        )
        self._dispatch_thread.start()
        self.after(150, self._poll_dispatch_queue)


def main() -> None:
    root = tk.Tk()
    root.withdraw()  # hide until config is loaded

    try:
        cfg = load_config()
    except Exception as e:
        messagebox.showerror(
            "Configuration error",
            f"Failed to load config.ini:\n{e}",
        )
        root.destroy()
        return

    root.deiconify()
    app = ReportsApp(root, cfg)
    root.mainloop()


if __name__ == "__main__":
    main()
