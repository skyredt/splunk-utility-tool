from __future__ import annotations

import os
import queue
import re
import socket
import sys
from datetime import datetime, date
from typing import Callable, Optional

import tkinter as tk
from tkinter import ttk

try:
    # Optional calendar widget for nicer date selection
    from tkcalendar import DateEntry
    HAS_TKCALENDAR = True
except ImportError:  # fall back to simple Entry if tkcalendar is not installed
    HAS_TKCALENDAR = False

from splunk_engine import (
    TOOL_DISPLAY_NAME,
    SplunkConfig,
    build_slices,
    get_effective_username,
    inspect_unfinished_batch_journals,
    recover_unfinished_batch_journal,
    resolve_merge_report_runtime_settings,
    resolve_primary_slice_mergereport_enabled,
    resolve_broker_request_timeout_seconds,
    resolve_status_check_poll_seconds,
    resolve_status_check_timeout_seconds,
    run_dispatch_multi,
    set_security_audit_logger,
    set_security_policy,
)
from Internal.baseline_guard import build_security_fingerprint, enforce_security_baseline
from Internal.config_manager import ConfigError
from Internal.logging_broker import (
    BrokerAuditLogger,
    PERSISTENT_AUDIT_UNAVAILABLE_WARNING,
    start_local_logging_broker,
)
from Internal.splunk_broker import (
    LocalSplunkBrokerHandle,
    SPLUNK_BROKER_UNAVAILABLE_WARNING,
    SplunkBrokerProxyClient,
    start_local_splunk_broker,
)
from Internal.security_policy import PolicyViolation, load_security_policy, redact_text
from Internal.tool_logging import configure_tool_logging, debug_log as write_debug_log, runtime_log as write_runtime_log
from mergereport_monitor import MergeReportMonitor
from postdispatch_monitor import PostDispatchStatusMonitor
from progress_dialog import run_with_progress
from ui_theme import (
    SURFACE_BG,
    WINDOW_BG,
    apply_splunk_light_theme,
    style_listbox,
    style_text_widget,
    style_window,
)
from ui_prompt import show_choice_prompt, show_modal_prompt


TOOL_VERSION = "v4"
_RUNNING_SLICE_RE = re.compile(r"^Running slice (\d+) of (\d+)\.\.\.$")
_RECOVERY_BATCH_RE = re.compile(r"batch_id=([A-Za-z0-9_.:-]+)")


def _dispatch_final_outcome_from_log_lines(log_lines: list[str]) -> str:
    for raw_line in reversed(list(log_lines or [])):
        text = str(raw_line or "").strip()
        if not text:
            continue
        if text.startswith("Report generation completed successfully."):
            return "success"
        if text.startswith("Report processing completed, but final verification is still pending."):
            return "pending_verification"
        if text.startswith("Reports were generated, but evidence confirmation could not be fully completed."):
            return "evidence_warning"
        if text.startswith("Report completed with issues."):
            return "partial_success"
        if text.startswith("Unable to connect to Splunk services."):
            return "connectivity_prestart"
        if text.startswith("The report could not be started."):
            return "could_not_start"
    return ""


def _should_show_dispatch_terminal_error(final_outcome: str, error_payload: object) -> bool:
    if error_payload is None:
        return False
    normalized = str(final_outcome or "").strip().lower()
    if normalized in {"success", "partial_success", "pending_verification", "evidence_warning"}:
        return False
    return True


def _operator_display_line(raw_text: str) -> str:
    text = str(raw_text or "").strip()
    if not text:
        return ""
    if text.startswith("[Debug]"):
        return ""
    if text.startswith("Reference ID: "):
        return text
    if text in {
        "Starting report generation...",
        "Preparing report...",
        "Finalizing results...",
        "Recovery journal detected.",
        "No unfinished recovery journals detected.",
        "Temporary dispatch uncertainty detected. Verifying status...",
        "Retrying slice in a fresh execution context...",
    }:
        return text
    if text.startswith("Recovery journal detected."):
        return "Recovery journal detected."
    if _RUNNING_SLICE_RE.match(text):
        return text
    if text.startswith("Recovery journal detected for batch_id="):
        match = _RECOVERY_BATCH_RE.search(text)
        if match:
            return f"Recovery journal detected.\nReference ID: {match.group(1)}"
        return "Recovery journal detected."
    if text.startswith("Incomplete batch detected:"):
        match = _RECOVERY_BATCH_RE.search(text)
        if match:
            return f"Recovery journal detected.\nReference ID: {match.group(1)}"
        return "Recovery journal detected."
    if text.startswith("Blocked by overlap lock."):
        return "Blocked by overlap lock."
    if "Local Splunk broker unavailable" in text:
        return "Unable to connect to Splunk services."
    if text.startswith("Connected.") or text.startswith("Loading reports") or text.startswith("Loaded "):
        return text
    if text.startswith("Unable to connect to Splunk services."):
        return text
    if text.startswith("The report could not be started."):
        return text
    if text.startswith("Report generation completed successfully."):
        return text
    if text.startswith("All reports have been sent."):
        return text
    if text.startswith("Report completed with issues."):
        return text
    if text.startswith("Some reports may not have been generated or sent."):
        return text
    if text.startswith("Report processing completed, but final verification is still pending."):
        return text
    if text.startswith("Reports were generated, but evidence confirmation could not be fully completed."):
        return text
    if text.startswith("Please contact the Splunk team and provide:"):
        return text
    if text.startswith("Please verify manually or contact the Splunk team and provide:"):
        return text
    if text.startswith("Recovery action selected:"):
        return text
    if text.startswith("Recovery reconcile requires an active Splunk connection."):
        return text
    return ""


def _resolve_app_icon_path() -> str | None:
    """Resolve app icon path for source and bundled executions."""
    candidates: list[str] = []

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        candidates.append(os.path.join(exe_dir, "assets", "app.ico"))
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            candidates.append(os.path.join(meipass, "assets", "app.ico"))

    module_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(module_dir, "assets", "app.ico"))

    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _resolve_runtime_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _build_cfg_from_runtime_payload(payload: dict[str, object], exe_dir: str) -> SplunkConfig:
    config_path = os.path.join(exe_dir, "config.ini")
    if isinstance(payload.get("config_path"), str) and str(payload.get("config_path")).strip():
        config_path = str(payload.get("config_path")).strip()
    return SplunkConfig(
        servers=[str(x) for x in (payload.get("servers") or [])] if isinstance(payload.get("servers"), list) else [],
        username=str(payload.get("username") or ""),
        password="",
        secret_file="secret.dpapi",
        dpapi_scope="machine",
        auth_mode="password",
        verify_ssl=bool(payload.get("verify_ssl", True)),
        config_path=config_path,
        logging_level=str(payload.get("logging_level") or "INFO"),
        logging_verbose=bool(payload.get("logging_verbose", False)),
        logging_max_bytes=int(payload.get("logging_max_bytes") or 10_485_760),
        logging_backup_count=int(payload.get("logging_backup_count") or 10),
        file_logging_config=dict(payload.get("file_logging_config")) if isinstance(payload.get("file_logging_config"), dict) else None,
        legacy_password_present=bool(payload.get("legacy_password_present", False)),
        merge_report_enabled=bool(payload.get("merge_report_enabled", False)),
        merge_report_log_path=str(payload.get("merge_report_log_path") or ""),
        merge_report_timeout_seconds=int(payload.get("merge_report_timeout_seconds") or 300),
        dispatch_config=dict(payload.get("dispatch_config")) if isinstance(payload.get("dispatch_config"), dict) else None,
        ack_enabled=bool(payload.get("ack_enabled", True)),
        ack_on_pending=bool(payload.get("ack_on_pending", payload.get("ack_on_unknown", False))),
        ack_on_unknown=bool(payload.get("ack_on_unknown", False)),
        ack_recipients=[str(x) for x in (payload.get("ack_recipients") or [])] if isinstance(payload.get("ack_recipients"), list) else [],
        ack_use_savedsearch_recipients=bool(payload.get("ack_use_savedsearch_recipients", False)),
        ack_attach_manifest=bool(payload.get("ack_attach_manifest", False)),
        smtp_host=str(payload.get("smtp_host") or "127.0.0.1"),
        smtp_port=int(payload.get("smtp_port") or 25),
        smtp_user=str(payload.get("smtp_user") or ""),
        smtp_pass=str(payload.get("smtp_pass") or ""),
        smtp_use_tls=bool(payload.get("smtp_use_tls", False)),
        smtp_from=str(payload.get("smtp_from") or "Splunk Notification <splunk-donotreply@localhost>"),
        postdispatch_config=dict(payload.get("postdispatch_config")) if isinstance(payload.get("postdispatch_config"), dict) else None,
        runtime_config=dict(payload.get("runtime_config")) if isinstance(payload.get("runtime_config"), dict) else None,
    )


class ReportsApp(ttk.Frame):
    DISPATCH_STATUS_WAIT_SECONDS = 300
    DISPATCH_STATUS_POLL_SECONDS = 5

    def __init__(
        self,
        master: tk.Tk,
        cfg: SplunkConfig,
        *,
        audit_logger: Optional[BrokerAuditLogger] = None,
        splunk_broker_handle: Optional[LocalSplunkBrokerHandle] = None,
        startup_warning: str = "",
        exe_dir: Optional[str] = None,
    ):
        super().__init__(master)
        self.master = master
        self.cfg = cfg
        self.audit_logger = audit_logger
        self.splunk_broker_handle = splunk_broker_handle
        self.splunk_broker_client = splunk_broker_handle.client if splunk_broker_handle else None
        if self.splunk_broker_client is not None and hasattr(self.splunk_broker_client, "configure_request_timeout"):
            self.splunk_broker_client.configure_request_timeout(
                resolve_broker_request_timeout_seconds(cfg)
            )
        self.exe_dir = exe_dir or _resolve_runtime_exe_dir()

        self.client: SplunkBrokerProxyClient | None = None
        self.report_ids: list[str] = []
        self.report_names: list[str] = []
        self.report_email_flags: list[bool] = []
        self.filtered_indices: list[int] = []
        self._dispatch_in_progress = False
        self._dispatch_queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._merge_report_monitor: MergeReportMonitor | None = None
        self._postdispatch_monitor: PostDispatchStatusMonitor | None = None
        self._recovery_payloads: list[dict[str, object]] = []
        self._startup_recovery_prompted = False
        self._last_display_line = ""
        self._current_reference_id = ""
        self._dispatch_final_outcome = ""
        self._dispatch_pending_error: Exception | None = None
        self._dispatch_pending_error_text = ""

        self._build_ui()
        self._set_connected_state(False)
        audit_warning = ""
        if self.audit_logger is not None and hasattr(self.audit_logger, "unavailable_warning"):
            audit_warning = str(self.audit_logger.unavailable_warning() or "").strip()
        if audit_warning:
            self._append_log(audit_warning)
        elif self.audit_logger:
            self._append_log("[Audit] Security audit logger initialized.")
        else:
            self._append_log(PERSISTENT_AUDIT_UNAVAILABLE_WARNING)
        if self.splunk_broker_handle and (not self.splunk_broker_handle.is_available):
            self._append_log(SPLUNK_BROKER_UNAVAILABLE_WARNING)
        if startup_warning.strip():
            self._append_log(startup_warning.strip())

        # Load servers from config
        self._load_servers()
        self.after(100, self._startup_connectivity_check)

    # --------------- UI construction ---------------

    def _build_ui(self) -> None:
        self.configure(style="App.TFrame")
        self.pack(fill="both", expand=True, padx=18, pady=18)
        self.master.title(TOOL_DISPLAY_NAME)
        self.master.minsize(900, 600)
        style_window(self.master, surface=WINDOW_BG)

        # Top row: server/app + controls
        top = ttk.Frame(self, padding=(16, 14), style="Card.TFrame")
        top.pack(side="top", fill="x", pady=(0, 14))

        ttk.Label(top, text="Server:", style="Card.TLabel").pack(side="left")
        self.server_var = tk.StringVar()
        self.server_combo = ttk.Combobox(top, textvariable=self.server_var, state="readonly", width=40)
        self.server_combo.bind("<<ComboboxSelected>>", self.on_server_selection_changed)
        self.server_combo.pack(side="left", padx=(4, 12))

        ttk.Label(top, text="App:", style="Card.TLabel").pack(side="left")
        self.app_var = tk.StringVar()
        self.app_combo = ttk.Combobox(top, textvariable=self.app_var, state="disabled", width=30)
        self.app_combo.bind("<<ComboboxSelected>>", self.on_app_changed)
        self.app_combo.pack(side="left", padx=(4, 12))

        self.connect_button = ttk.Button(top, text="Connect", command=self.on_connect_clicked)
        self.connect_button.pack(side="left")

        self.reload_button = ttk.Button(top, text="Reload", command=self.on_reload_clicked, state="disabled")
        self.reload_button.pack(side="left", padx=(8, 0))

        self.recover_button = ttk.Button(top, text="Recover", command=self.on_recover_clicked)
        self.recover_button.pack(side="left", padx=(8, 0))

        # Spacer
        top_spacer = ttk.Label(top, style="Card.TLabel")
        top_spacer.pack(side="left", expand=True)

        # Middle row: reports list + options
        middle = ttk.Frame(self, style="App.TFrame")
        middle.pack(side="top", fill="both", expand=True, pady=(0, 14))

        # Left: reports list
        left = ttk.Frame(middle, padding=(16, 14), style="Card.TFrame")
        left.pack(side="left", fill="both", expand=True)

        ttk.Label(left, text="Reports", style="Section.TLabel").pack(anchor="w")
        search_row = ttk.Frame(left, style="Card.TFrame")
        search_row.pack(fill="x", pady=(2, 6))

        ttk.Label(search_row, text="Search:", style="Card.TLabel").pack(side="left")
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
        style_listbox(self.reports_list)

        reports_scroll = ttk.Scrollbar(left, orient="vertical", command=self.reports_list.yview)
        reports_scroll.pack(side="right", fill="y")
        self.reports_list.config(yscrollcommand=reports_scroll.set)

        # Right: options
        right = ttk.Frame(middle, padding=(16, 14), style="Card.TFrame")
        right.pack(side="left", fill="y", padx=(12, 0))

        # Frequency
        ttk.Label(right, text="Dispatch Options", style="Section.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        ttk.Label(right, text="Frequency:", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 4))
        self.frequency_var = tk.StringVar(value="Daily")
        self.frequency_combo = ttk.Combobox(
            right,
            textvariable=self.frequency_var,
            values=["Daily", "Weekly", "Monthly"],
            state="readonly",
            width=15,
        )
        self.frequency_combo.grid(row=1, column=1, sticky="w", pady=(0, 4))

        # Start date
        ttk.Label(right, text="Start date:", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        self.start_date_widget = self._make_date_widget(right)
        self.start_date_widget.grid(row=2, column=1, sticky="w", pady=4)

        # End date
        ttk.Label(right, text="End date:", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=4)
        self.end_date_widget = self._make_date_widget(right)
        self.end_date_widget.grid(row=3, column=1, sticky="w", pady=4)

        # No change checkbox
        self.no_change_var = tk.BooleanVar(value=False)
        self.no_change_chk = ttk.Checkbutton(
            right,
            text="Use saved search time range (no override)",
            variable=self.no_change_var,
            command=self.on_no_change_toggled,
            style="TCheckbutton",
        )
        self.no_change_chk.grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 4))

        # Send button
        self.send_button = ttk.Button(
            right,
            text="Send reports",
            command=self.on_send_clicked,
            state="disabled",
            style="Primary.TButton",
        )
        self.send_button.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(16, 0))

        # User info display (audit info)
        username = get_effective_username()
        hostname = socket.gethostname()
        tool_name = TOOL_DISPLAY_NAME
        user_info_text = f"Hi {username}.\nYou are using {tool_name} on {hostname}."
        self.user_info_label = ttk.Label(right, text=user_info_text, style="Subtle.TLabel", justify="left")
        self.user_info_label.grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))

        for i in range(2):
            right.grid_columnconfigure(i, weight=1)

        # Bottom: log area
        bottom = ttk.Frame(self, padding=(16, 14), style="Card.TFrame")
        bottom.pack(side="top", fill="both", expand=True)

        ttk.Label(bottom, text="Activity Log", style="Section.TLabel").pack(anchor="w")
        self.log_text = tk.Text(bottom, height=12, wrap="word", state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True)
        style_text_widget(self.log_text)

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
        self.recover_button.configure(state="normal")

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
        safe_text = redact_text(text)
        if not safe_text.strip():
            return
        runtime_level = "INFO"
        upper_text = safe_text.upper()
        if upper_text.startswith("ERROR") or " ERROR " in upper_text:
            runtime_level = "ERROR"
        elif "WARNING" in upper_text or upper_text.startswith("WARN"):
            runtime_level = "WARN"
        if safe_text.startswith("[Debug]"):
            write_debug_log(safe_text, category="general")
        else:
            write_runtime_log(safe_text, level=runtime_level)
            write_debug_log(f"RUNTIME_UI {safe_text}", category="general")
        display_text = _operator_display_line(safe_text)
        if not display_text:
            return
        for line in display_text.splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue
            if cleaned == self._last_display_line:
                continue
            if cleaned.startswith("Reference ID: "):
                self._current_reference_id = cleaned.split(":", 1)[1].strip()
            self.log_text.configure(state="normal")
            self.log_text.insert("end", cleaned + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
            self._last_display_line = cleaned

    def _show_prompt(self, title: str, message: str, prompt_type: str = "info"):
        return show_modal_prompt(self.master, title, message, prompt_type)

    def _audit_event(self, event: str, level: str = "INFO", **fields) -> None:
        if self.audit_logger is None:
            return
        self.audit_logger.log_event(event, level=level, **fields)

    def _require_broker_client(self) -> SplunkBrokerProxyClient:
        client = self.splunk_broker_client
        if client is None:
            raise RuntimeError(SPLUNK_BROKER_UNAVAILABLE_WARNING)
        return client

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
            self.recover_button.configure(state="disabled")
            self.send_button.configure(state="disabled")
            self.frequency_combo.configure(state="disabled")
            self.no_change_chk.configure(state="disabled")
            self.start_date_widget.configure(state="disabled")
            self.end_date_widget.configure(state="disabled")
        else:
            self._set_connected_state(self.client is not None)
            self.no_change_chk.configure(state="normal")
            self.on_no_change_toggled()

    def _reset_run_scoped_state(self) -> tuple[int, int]:
        stopped_monitors = 0
        drained_events = 0
        self._dispatch_final_outcome = ""
        self._dispatch_pending_error = None
        self._dispatch_pending_error_text = ""
        if self._merge_report_monitor is not None:
            try:
                self._merge_report_monitor.stop()
            except Exception:
                pass
            self._merge_report_monitor = None
            stopped_monitors += 1
        if self._postdispatch_monitor is not None:
            try:
                self._postdispatch_monitor.stop()
            except Exception:
                pass
            self._postdispatch_monitor = None
            stopped_monitors += 1
        while True:
            try:
                self._dispatch_queue.get_nowait()
                drained_events += 1
            except queue.Empty:
                break
        return stopped_monitors, drained_events

    def _apply_search_filter(self) -> None:
        term = self.search_var.get().strip().lower()
        self.reports_list.delete(0, "end")
        self.filtered_indices = []
        for idx, name in enumerate(self.report_names):
            if not term or term in name.lower():
                self.reports_list.insert("end", name)
                self.filtered_indices.append(idx)

    def _load_recovery_payloads(self, *, announce: bool) -> list[dict[str, object]]:
        payloads, lines = inspect_unfinished_batch_journals()
        self._recovery_payloads = [dict(item) for item in payloads if isinstance(item, dict)]
        if announce:
            for line in lines:
                self._append_log(line)
            if self._recovery_payloads:
                self._append_log(
                    "Recovery journal detected. Use Recover to inspect, reconcile/finalize, or dismiss/archive unfinished work."
                )
        return list(self._recovery_payloads)

    def _recovery_prompt_message(self, payload: dict[str, object]) -> str:
        batch_id = str(payload.get("batch_id") or "unknown-batch").strip()
        batch_state = str(payload.get("batch_state") or "UNKNOWN").strip()
        report_names = payload.get("report_names") or []
        invalid_reason = str(payload.get("invalid_reason") or "").strip()
        if isinstance(report_names, list):
            reports_text = ", ".join(str(name) for name in report_names if str(name).strip()) or "(unknown)"
        else:
            reports_text = "(unknown)"
        action_hint = (
            "Choose Reconcile to run a bounded finalize sweep using the current Splunk connection."
            if self.client is not None
            else "Connect first if you want the tool to reconcile/finalize against Splunk."
        )
        if bool(payload.get("invalid_journal")):
            return (
                "Recovery journal detected.\n\n"
                f"Reference ID: {batch_id}\n"
                f"State: {batch_state}\n"
                f"Recovery journal issue: {invalid_reason or 'invalid or incompatible journal'}\n\n"
                "Use Inspect to review the situation or Dismiss to archive the invalid journal."
            )
        return (
            f"Recovery journal detected.\n\n"
            f"Reference ID: {batch_id}\n"
            f"State: {batch_state}\n"
            f"Reports: {reports_text}\n"
            f"{action_hint}"
        )

    def _run_recovery_action(self, payload: dict[str, object], action: str) -> None:
        action_name = str(action or "").strip().lower()
        if action_name == "later":
            self._append_log("Recovery action deferred by operator.")
            return
        if action_name == "reconcile" and self.client is None:
            self._append_log("Recovery reconcile requires an active Splunk connection. Connect first, then retry Recover.")
            self._show_prompt(
                "Recovery requires connection",
                "Connect to Splunk before using reconcile/finalize on an unfinished journal.",
                "info",
            )
            return

        def _task(set_status: Callable[[str], None]):
            if action_name == "reconcile":
                set_status("Reconciling unfinished batch...")
            elif action_name == "dismiss":
                set_status("Archiving unfinished batch journal...")
            else:
                set_status("Inspecting unfinished batch journal...")
            return recover_unfinished_batch_journal(
                client=self.client if action_name == "reconcile" else None,
                journal_payload=payload,
                action=action_name,
                wait_seconds=resolve_status_check_timeout_seconds(self.cfg),
                poll_interval=resolve_status_check_poll_seconds(self.cfg),
                prefer_merge_report_verification=resolve_primary_slice_mergereport_enabled(self.cfg),
                merge_report_log_path=self.cfg.merge_report_log_path,
                merge_report_settings=resolve_merge_report_runtime_settings(self.cfg),
            )

        def _on_success(result: object) -> None:
            lines = result if isinstance(result, list) else []
            for line in lines:
                self._append_log(str(line))
            self._load_recovery_payloads(announce=False)

        def _on_error(exc: Exception) -> None:
            self._append_log(f"Recovery action failed: {redact_text(str(exc))}")
            self._show_prompt(
                "Recovery error",
                "Recovery action failed. Review the activity log for details.",
                "error",
            )

        if action_name == "inspect":
            _on_success(_task(lambda _text: None))
            return

        run_with_progress(
            self.master,
            "Recovery",
            "Processing recovery action...",
            _task,
            on_success=_on_success,
            on_error=_on_error,
        )

    def _startup_connectivity_check(self) -> None:
        payloads = self._load_recovery_payloads(announce=True)
        if payloads and not self._startup_recovery_prompted:
            self._startup_recovery_prompted = True
            self.after(50, self.on_recover_clicked)

    def on_recover_clicked(self) -> None:
        payloads = self._load_recovery_payloads(announce=False)
        if not payloads:
            self._append_log("No unfinished recovery journals detected.")
            self._show_prompt("Recovery", "No unfinished recovery journals were found.", "info")
            return

        payload = payloads[0]
        choices = [
            ("inspect", "Inspect/report"),
            ("dismiss", "Dismiss/archive"),
        ]
        if self.client is not None:
            choices.insert(0, ("reconcile", "Reconcile/finalize"))
        else:
            choices.append(("later", "Later"))
        action = show_choice_prompt(
            self.master,
            "Recovery journal detected",
            self._recovery_prompt_message(payload),
            choices,
            default_value="later",
        )
        if not action:
            action = "later"
        self._run_recovery_action(payload, action)

    # --------------- Event handlers ---------------

    def on_server_selection_changed(self, event=None) -> None:
        if self.client is not None:
            self._append_log("Server changed; disconnecting current session.")
            try:
                self.client.disconnect()
            except Exception:
                pass
            self._set_connected_state(False)

    def on_connect_clicked(self) -> None:
        if self.client is not None:
            self._append_log("Disconnected from server.")
            try:
                self.client.disconnect()
            except Exception:
                pass
            self._set_connected_state(False)
            return
        self._connect_current_server()

    def _connect_current_server(self) -> None:
        server_url = self._selected_server()
        if not server_url:
            self._show_prompt("No server", "Please select a server first.", "warning")
            return

        self._append_log(f"Connecting to {server_url} ...")

        def _task(set_status: Callable[[str], None]):
            set_status("Connecting to Splunk...")
            broker_client = self._require_broker_client()
            connect_result = broker_client.connect(server_url)
            credential_persisted = True
            if isinstance(connect_result, dict):
                credential_persisted = bool(connect_result.get("credential_persisted", True))
            set_status("Loading applications...")
            apps = broker_client.list_apps() or []
            return broker_client, apps, credential_persisted

        def _on_success(payload: object) -> None:
            client, apps, credential_persisted = payload  # type: ignore[misc]
            self.client = client
            self.app_combo.configure(state="readonly")
            self.app_combo["values"] = apps
            if apps:
                self.app_combo.current(0)
            self._set_connected_state(True)
            if apps:
                self.on_app_changed()
            self._append_log(f"Connected. {len(apps)} app(s) loaded.")
            if not bool(credential_persisted):
                self._append_log(
                    "Credential was not persisted due local ACL policy; "
                    "you will be prompted again on next launch."
                )

        def _on_error(exc: Exception) -> None:
            safe_error = redact_text(str(exc))
            self._append_log(f"ERROR connecting to {server_url}: {safe_error}")
            try:
                broker_client = self._require_broker_client()
                broker_client.disconnect()
            except Exception:
                pass
            self._set_connected_state(False)
            self._show_prompt(
                "Connection error",
                f"Failed to connect to {server_url}.",
                "error",
            )

        run_with_progress(
            self.master,
            "Connecting to Splunk",
            "Connecting...",
            _task,
            on_success=_on_success,
            on_error=_on_error,
        )

    def on_reload_clicked(self) -> None:
        if self.client is None:
            self._show_prompt("Not connected", "Please connect to a server first.", "warning")
            return
        self.on_app_changed()

    def on_app_changed(self, event=None) -> None:
        if self.client is None:
            return
        app = self.app_var.get().strip()
        if not app:
            return

        self._append_log(f"Loading reports from app '{app}' ...")
        def _task(set_status: Callable[[str], None]):
            set_status(f"Loading reports from '{app}'...")
            return self.client.list_saved_searches(app)

        def _on_success(payload: object) -> None:
            ids, names, email_flags = payload  # type: ignore[misc]
            self.report_ids = ids
            self.report_names = names
            self.report_email_flags = email_flags
            self._apply_search_filter()
            self._append_log(f"Loaded {len(names)} report(s).")

        def _on_error(exc: Exception) -> None:
            self._append_log(f"ERROR loading reports for app '{app}': {redact_text(str(exc))}")
            self._show_prompt(
                "Error",
                f"Failed to load saved searches for app '{app}'.",
                "error",
            )
            self.report_ids = []
            self.report_names = []
            self.report_email_flags = []
            self.reports_list.delete(0, "end")
            self.filtered_indices = []

        run_with_progress(
            self.master,
            "Loading Reports",
            f"Loading reports from '{app}'...",
            _task,
            on_success=_on_success,
            on_error=_on_error,
        )

    def on_search_changed(self, *args) -> None:
        if self.report_names:
            self._apply_search_filter()
        else:
            self.reports_list.delete(0, "end")
            self.filtered_indices = []

    def on_clear_search(self) -> None:
        self.search_var.set("")

    def _dispatch_worker(
        self,
        params: dict,
        status_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        def log_callback(line: str) -> None:
            self._dispatch_queue.put(("log", line))
            friendly = _operator_display_line(line)
            if status_callback and friendly:
                status_callback(friendly.splitlines()[0][:120])

        def sid_callback(sid: str, search_name: str) -> None:
            # Register SID with MergeReport monitor if enabled
            if self._merge_report_monitor is not None:
                self._merge_report_monitor.register_sid(sid, search_name)
            # Register SID with post-dispatch monitor if enabled
            if self._postdispatch_monitor is not None:
                self._postdispatch_monitor.register_sid(sid, search_name)

        try:
            logs = run_dispatch_multi(log_callback=log_callback, sid_callback=sid_callback, config=self.cfg, **params)
            self._dispatch_queue.put(
                (
                    "done",
                    {
                        "final_outcome": _dispatch_final_outcome_from_log_lines(logs),
                    },
                )
            )
        except Exception as e:
            self._dispatch_queue.put(("err", e))

    def _finalize_dispatch_ui_result(self) -> None:
        final_outcome = str(self._dispatch_final_outcome or "").strip().lower()
        pending_error = self._dispatch_pending_error
        safe_error = str(self._dispatch_pending_error_text or "").strip()
        show_modal = _should_show_dispatch_terminal_error(final_outcome, pending_error)
        self._append_log(
            f"[Debug] UI_DISPATCH_MODAL_DECISION final_outcome={final_outcome or '-'} "
            f"pending_error={bool(pending_error)} show_modal={show_modal}"
        )
        if pending_error is None:
            return
        if not show_modal:
            self._append_log(
                f"[Debug] UI_DISPATCH_ERROR_SUPPRESSED final_outcome={final_outcome or '-'} "
                f"detail={safe_error or '-'}"
            )
            return
        if "overlapping local batch is still active" in safe_error.lower():
            self._append_log("Blocked by overlap lock. Resolve or dismiss the unfinished batch journal before rerunning the same report/window.")
            self._load_recovery_payloads(announce=True)
        self._append_log(f"[Debug] UI_DISPATCH_ERROR detail={safe_error}")
        if self._current_reference_id and not final_outcome:
            self._append_log("The report could not be started.")
            self._append_log("Please contact the Splunk team and provide:")
            self._append_log(f"Reference ID: {self._current_reference_id}")
        self._show_prompt(
            "Dispatch error",
            (
                "The report could not be completed.\n\n"
                f"Reference ID: {self._current_reference_id}"
                if self._current_reference_id
                else "The report could not be completed. Review the runtime logs for details."
            ),
            "error",
        )

    def _poll_dispatch_queue(self) -> None:
        done = False
        while True:
            try:
                status, payload = self._dispatch_queue.get_nowait()
            except queue.Empty:
                break

            if status == "log":
                self._append_log(str(payload))
            elif status == "mergereport":
                # MergeReport event from the monitor
                self._append_log(str(payload))
            elif status == "mergereport_error":
                # Internal MergeReport error (won't crash the dispatch)
                self._append_log(f"[MergeReport Monitor Error] {payload}")
            elif status == "postdispatch":
                # Post-dispatch verification event from the monitor
                self._append_log(str(payload))
            elif status == "postdispatch_error":
                # Internal post-dispatch error (won't crash the dispatch)
                self._append_log(f"[PostDispatch Monitor Error] {payload}")
            elif status == "err":
                safe_error = redact_text(str(payload))
                self._dispatch_pending_error = payload if isinstance(payload, Exception) else RuntimeError(safe_error)
                self._dispatch_pending_error_text = safe_error
                self._append_log(f"[Debug] UI_DISPATCH_ERROR_CAPTURED detail={safe_error}")
                done = True
            elif status == "done":
                if isinstance(payload, dict):
                    self._dispatch_final_outcome = str(payload.get("final_outcome") or "").strip()
                self._append_log(
                    f"[Debug] UI_DISPATCH_DONE final_outcome={self._dispatch_final_outcome or '-'}"
                )
                done = True

        if done:
            self._finalize_dispatch_ui_result()
            self._set_dispatch_state(False)
            self._reset_run_scoped_state()
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

    def _manual_regen_prompt_text(
        self,
        selected_report_names: list[str],
        range_text: str,
        mode_text: str,
    ) -> str:
        if len(selected_report_names) <= 5:
            report_label = ", ".join(selected_report_names)
        else:
            shown = ", ".join(selected_report_names[:5])
            report_label = f"{shown} (+{len(selected_report_names) - 5} more)"

        return (
            "This will produce a manually regenerated report run "
            "(different from scheduled automation).\n"
            "An acknowledgement email will be sent only when final status is known, or when pending verification emails are explicitly enabled.\n\n"
            f"Report(s): {report_label}\n"
            f"Date range: {range_text}\n"
            f"Slice mode: {mode_text}\n"
        )

    def on_send_clicked(self) -> None:
        if self.client is None:
            self._show_prompt("Not connected", "Please connect to a server first.", "warning")
            return
        if self._dispatch_in_progress:
            self._show_prompt("Dispatch running", "A dispatch is already in progress.", "info")
            return
        if self._load_recovery_payloads(announce=True):
            self._append_log("Recovery journal detected. Resolve unfinished work before starting a new overlapping batch.")
            self.on_recover_clicked()
            return

        # Selected reports
        selected_display_indices = list(self.reports_list.curselection())
        if not selected_display_indices:
            self._show_prompt("No reports selected", "Please select at least one report.", "info")
            return
        selected_indices = [
            self.filtered_indices[i]
            for i in selected_display_indices
            if i < len(self.filtered_indices)
        ]

        selected_report_names = [self.report_names[i] for i in selected_indices]
        frequency = self.frequency_var.get()
        no_change = self.no_change_var.get()

        # Dates
        if not no_change:
            start_d = self._get_date_from_widget(self.start_date_widget)
            end_d = self._get_date_from_widget(self.end_date_widget)
            if start_d is None or end_d is None:
                self._show_prompt(
                    "Invalid dates",
                    "Please enter valid Start and End dates (YYYY-MM-DD).",
                    "warning",
                )
                return

            start = datetime(start_d.year, start_d.month, start_d.day)
            end = datetime(end_d.year, end_d.month, end_d.day)
            if end <= start:
                self._show_prompt("Invalid date range", "End date must be after start date.", "warning")
                return
            starts, _ = build_slices(start, end, frequency)
            if len(starts) == 0:
                self._show_prompt("Invalid range", "Selected date range generates 0 slices.", "warning")
                return
            if len(starts) > 12:
                self._show_prompt(
                    "Invalid range",
                    "Selected date range generates more than 12 slices.",
                    "warning",
                )
                return
            range_text = f"{start_d.isoformat()} to {end_d.isoformat()}"
            total_runs = len(starts) * len(selected_indices)
            mode_text = (
                f"{frequency.lower()} slices: {len(starts)} per report "
                f"({total_runs} total)"
            )
        else:
            start_d = self._get_date_from_widget(self.start_date_widget)
            end_d = self._get_date_from_widget(self.end_date_widget)
            if start_d is not None and end_d is not None:
                start = datetime(start_d.year, start_d.month, start_d.day)
                end = datetime(end_d.year, end_d.month, end_d.day)
                range_text = f"{start_d.isoformat()} to {end_d.isoformat()} (saved search time range in effect)"
            else:
                today = date.today()
                start = datetime(today.year, today.month, today.day)
                end = start
                range_text = "saved search time range (no override)"
            mode_text = f"single run per report ({len(selected_indices)} total)"

        prompt_text = self._manual_regen_prompt_text(
            selected_report_names=selected_report_names,
            range_text=range_text,
            mode_text=mode_text,
        )
        proceed = self._show_prompt(
            "Confirm Manual Regeneration",
            prompt_text,
            "confirm",
        )
        if not proceed:
            self._append_log("Manual regeneration cancelled by user.")
            return

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
        self._last_display_line = ""
        self._current_reference_id = ""
        stopped_monitors, drained_events = self._reset_run_scoped_state()
        if stopped_monitors > 0 or drained_events > 0:
            self._append_log(
                f"[Debug] RUN_UI_STATE_RESET stopped_monitors={stopped_monitors} drained_events={drained_events}"
            )

        merge_report_settings = resolve_merge_report_runtime_settings(self.cfg)

        # Initialize optional local MergeReport file monitor only when this host can read the file.
        if bool(merge_report_settings.get("enabled")) and bool(merge_report_settings.get("local_file_available")):
            try:
                self._merge_report_monitor = MergeReportMonitor(
                    log_path=str(merge_report_settings.get("local_file_path", "") or ""),
                    ui_queue=self._dispatch_queue,
                    timeout_seconds=int(
                        merge_report_settings.get("timeout_seconds", self.cfg.merge_report_timeout_seconds)
                        or self.cfg.merge_report_timeout_seconds
                    ),
                )
                self._merge_report_monitor.start()
                self._append_log("[MergeReport] Monitor started.")
            except Exception as e:
                self._append_log(f"[MergeReport] WARNING: Could not start monitor: {redact_text(str(e))}")
                self._merge_report_monitor = None
        else:
            if bool(merge_report_settings.get("enabled")):
                self._append_log(
                    (
                        f"[Debug] MERGEREPORT_FILE_UNAVAILABLE local_path="
                        f"{str(merge_report_settings.get('requested_log_path', '') or '(blank)')} "
                        f"reason={str(merge_report_settings.get('local_file_reason', '') or 'unknown')} "
                        "falling back to non-file verification"
                    )
                )
                self._append_log("[MergeReport] Local file monitor skipped; non-file verification remains active.")
            self._merge_report_monitor = None

        # Initialize post-dispatch status monitor if enabled (Phase 2)
        # DISABLED: Not needed for simple dispatch summary
        # if self.cfg.postdispatch_config:
        #     try:
        #         self._postdispatch_monitor = PostDispatchStatusMonitor(
        #             client=self.client,
        #             ui_queue=self._dispatch_queue,
        #             config=self.cfg.postdispatch_config,
        #         )
        #         self._postdispatch_monitor.start()
        #     except Exception as e:
        #         pass
        self._postdispatch_monitor = None

        params = {
            "client": self.client,
            "report_ids": self.report_ids,
            "report_names": self.report_names,
            "selected_indices": selected_indices,
            "frequency": frequency,
            "start": start,
            "end": end,
            "no_change": no_change,
            "wait_seconds": resolve_status_check_timeout_seconds(self.cfg),
            "poll_interval": resolve_status_check_poll_seconds(self.cfg),
            "app": self.app_var.get().strip(),
        }
        self._set_dispatch_state(True)
        self.after(150, self._poll_dispatch_queue)

        def _task(set_status: Callable[[str], None]) -> None:
            self._dispatch_worker(params, status_callback=set_status)

        def _on_error(exc: Exception) -> None:
            self._dispatch_queue.put(("err", exc))

        run_with_progress(
            self.master,
            "Dispatching Reports",
            "Starting dispatch...",
            _task,
            on_error=_on_error,
        )


def main() -> None:
    root = tk.Tk()
    apply_splunk_light_theme(root)
    style_window(root, surface=WINDOW_BG)
    exe_dir = _resolve_runtime_exe_dir()

    policy = None
    policy_load_error: Optional[Exception] = None
    try:
        policy = load_security_policy(exe_dir=exe_dir)
    except Exception as exc:
        policy_load_error = exc

    broker_handle = start_local_logging_broker(
        exe_dir=exe_dir,
        tool_version=TOOL_VERSION,
        allow_local_appdata=bool(policy and (not policy.is_production) and policy.insecure_overrides_active),
    )
    audit_logger = broker_handle.audit_logger
    set_security_audit_logger(audit_logger)
    set_security_policy(policy)
    audit_logger.log_event("TOOL_START", level="INFO")
    if audit_logger.log_path:
        audit_logger.log_event("LOG_PATH_SELECTED", level="INFO", log_path=audit_logger.log_path)

    if policy_load_error is not None:
        if isinstance(policy_load_error, ConfigError):
            audit_logger.log_event("CONFIG_LOAD_FAILED", level="ERROR", reason=redact_text(str(policy_load_error)))
            title = "Configuration error"
            message = (
                f"{policy_load_error}\n\n"
                "Review config.ini and config.ini.example. The tool will create config.ini from the template when possible, "
                "and will save config.ini.bak before any automatic repair."
            )
        elif isinstance(policy_load_error, PolicyViolation):
            audit_logger.log_event(
                "POLICY_VIOLATION_BLOCKED",
                level="ERROR",
                control=policy_load_error.control,
                reason=policy_load_error.detail,
            )
            title = "Security policy blocked startup"
            message = (
                f"{policy_load_error.detail}\n\n"
                "Review the hardening settings in config.ini and audit.jsonl for details."
            )
        else:
            audit_logger.log_event("CONFIG_LOAD_FAILED", level="ERROR", reason=redact_text(str(policy_load_error)))
            title = "Startup error"
            message = (
                f"{redact_text(str(policy_load_error))}\n\n"
                "Startup could not continue. Review audit.jsonl for details."
            )
        audit_logger.log_event("TOOL_EXIT", level="INFO")
        show_modal_prompt(
            root,
            title,
            message,
            "error",
        )
        broker_handle.shutdown()
        root.destroy()
        return

    if policy and policy.break_glass_used:
        audit_logger.log_event(
            "POLICY_BREAK_GLASS_USED",
            level="WARN",
            break_glass_token_sha256=policy.break_glass_token_sha256,
        )

    icon_path = _resolve_app_icon_path()
    if icon_path:
        try:
            root.iconbitmap(icon_path)
        except tk.TclError:
            # Continue even if Tk cannot load the icon in this environment.
            pass
    root.withdraw()  # hide until config is loaded

    log_broker_url, log_broker_token = broker_handle.child_auth_config()
    splunk_broker_handle = start_local_splunk_broker(
        exe_dir=exe_dir,
        logging_broker_url=log_broker_url,
        logging_broker_token=log_broker_token,
    )
    runtime_warning = ""
    runtime_payload: dict[str, object] = {}
    runtime_loaded = False
    config_startup_error = ""
    if splunk_broker_handle.is_available and splunk_broker_handle.client is not None:
        try:
            runtime_payload = splunk_broker_handle.client.get_runtime_config()
            runtime_loaded = True
        except Exception as exc:
            try:
                health = splunk_broker_handle.client.health()
                if isinstance(health, dict):
                    config_startup_error = redact_text(str(health.get("config_error") or "")).strip()
            except Exception:
                config_startup_error = ""
            if config_startup_error:
                runtime_warning = config_startup_error
            else:
                runtime_warning = (
                    f"{SPLUNK_BROKER_UNAVAILABLE_WARNING} "
                    f"({redact_text(str(exc))})"
                )
    else:
        runtime_warning = splunk_broker_handle.startup_error or SPLUNK_BROKER_UNAVAILABLE_WARNING

    if not runtime_loaded:
        if config_startup_error:
            audit_logger.log_event("CONFIG_LOAD_FAILED", level="ERROR", reason=config_startup_error)
            title = "Configuration error"
            message = (
                f"{config_startup_error}\n\n"
                "Fix the configuration and retry. If a repair was applied, compare config.ini with config.ini.bak."
            )
        else:
            audit_logger.log_event("CONFIG_LOAD_FAILED", level="ERROR", reason=runtime_warning or SPLUNK_BROKER_UNAVAILABLE_WARNING)
            title = "Local Splunk broker unavailable"
            message = SPLUNK_BROKER_UNAVAILABLE_WARNING
        audit_logger.log_event("TOOL_EXIT", level="INFO")
        show_modal_prompt(
            root,
            title,
            message,
            "error",
        )
        splunk_broker_handle.shutdown()
        broker_handle.shutdown()
        root.destroy()
        return

    cfg = _build_cfg_from_runtime_payload(runtime_payload, exe_dir=exe_dir)
    configure_tool_logging(
        exe_dir=exe_dir,
        config=cfg,
        broker_url=log_broker_url,
        broker_token=log_broker_token,
    )

    audit_logger.configure(
        level=cfg.logging_level,
        verbose=cfg.logging_verbose,
        max_bytes=cfg.logging_max_bytes,
        backup_count=cfg.logging_backup_count,
    )
    config_hash = audit_logger.record_config_loaded(cfg.config_path)
    audit_logger.verify_log_set()
    if cfg.legacy_password_present:
        audit_logger.log_event("CONFIG_LEGACY_PASSWORD_IGNORED", level="WARN")
    if not cfg.verify_ssl:
        audit_logger.log_event(
            "TLS_VERIFY_DISABLED",
            level="WARN",
            reason="config_verify_ssl_false",
        )

    fingerprint = build_security_fingerprint(
        tool_version=TOOL_VERSION,
        policy=policy,
        logging_level=cfg.logging_level,
        logging_max_bytes=cfg.logging_max_bytes,
        logging_backup_count=cfg.logging_backup_count,
    )
    baseline_ok, baseline_reason = enforce_security_baseline(
        exe_dir=exe_dir,
        policy=policy,
        fingerprint=fingerprint,
        config_hash=config_hash,
        confirm_update_fn=lambda msg: bool(show_modal_prompt(root, "Break-glass confirmation", msg, "confirm")),
        audit_event_fn=audit_logger.log_event,
    )
    if not baseline_ok:
        audit_logger.log_event(
            "HARDENING_REVERSAL_BLOCKED",
            level="ERROR",
            reason=baseline_reason,
        )
        audit_logger.log_event("TOOL_EXIT", level="INFO")
        show_modal_prompt(
            root,
            "Security configuration blocked",
            "Security configuration downgrade detected. Tool run blocked. Contact Splunk team.",
            "error",
        )
        splunk_broker_handle.shutdown()
        broker_handle.shutdown()
        root.destroy()
        return

    root.deiconify()
    app = ReportsApp(
        root,
        cfg,
        audit_logger=audit_logger,
        splunk_broker_handle=splunk_broker_handle,
        startup_warning=runtime_warning,
        exe_dir=exe_dir,
    )

    def _on_close() -> None:
        audit_logger.log_event("TOOL_EXIT", level="INFO")
        splunk_broker_handle.shutdown()
        broker_handle.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)
    try:
        root.mainloop()
    finally:
        splunk_broker_handle.shutdown()
        broker_handle.shutdown()


if __name__ == "__main__":
    main()

