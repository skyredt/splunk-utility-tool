"""Post-dispatch status verification via Splunk searches.

Monitors dispatched searches for confirmation of email/alert action completion
by polling Splunk logs via REST API. Supports both MergeReport (strict) and
native email (best-effort) verification modes.
"""

from __future__ import annotations

import queue
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any

from splunk_engine import SplunkClient


@dataclass
class SIDState:
    """Tracks verification state for a single SID."""

    sid: str
    search_name: str
    registered_time: float
    expected_actions: set[str] = field(default_factory=set)  # "mergeReport", "email", etc.
    merge_report_state: Dict[str, Any] = field(default_factory=lambda: {
        "invoked": False,
        "sending": False,
        "smtp_empty": False,
        "success": False,
        "failed": False,
        "error_msg": "",
    })
    native_email_state: Dict[str, Any] = field(default_factory=lambda: {
        "invoked": False,
        "success": False,
        "failed": False,
        "error_msg": "",
    })
    last_search_time: float = 0.0


class PostDispatchStatusMonitor:
    """
    Monitor dispatch status via Splunk searches.

    Polls _internal logs for MergeReport and native email evidence.
    Emits verification lines to UI queue.
    """

    def __init__(
        self,
        client: SplunkClient,
        ui_queue: "queue.Queue[tuple[str, object]]",
        config: Dict[str, Any],
    ):
        """
        Initialize the monitor.

        Args:
            client: SplunkClient instance for running searches
            ui_queue: Queue for posting UI events ("postdispatch", line)
            config: Config dict with merge_report, native_email, poll_seconds, etc.
        """
        self.client = client
        self.ui_queue = ui_queue
        self.config = config

        self.tracked_sids: Dict[str, SIDState] = {}
        self.stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._last_search_time: float = 0.0
        self._event_dedup_cache: Dict[str, float] = {}  # (time, raw) -> timestamp

    def register_sid(
        self,
        sid: str,
        search_name: str,
        expected_actions: Optional[set[str]] = None,
    ) -> None:
        """Register a SID to track."""
        with self._lock:
            if sid not in self.tracked_sids:
                self.tracked_sids[sid] = SIDState(
                    sid=sid,
                    search_name=search_name,
                    registered_time=time.time(),
                    expected_actions=expected_actions or set(),
                )

    def start(self) -> None:
        """Start the monitor thread."""
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            return
        self.stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._run, daemon=True)
        self._monitor_thread.start()

    def stop(self) -> None:
        """Stop the monitor cleanly."""
        self.stop_event.set()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=2.0)

    def _run(self) -> None:
        """Background thread loop."""
        while not self.stop_event.is_set():
            try:
                self._poll_searches()
            except Exception as e:
                self.ui_queue.put(("postdispatch_error", str(e)))

            time.sleep(self.config.get("poll_seconds", 3))

    def _poll_searches(self) -> None:
        """Poll Splunk logs for verification evidence."""
        with self._lock:
            if not self.tracked_sids:
                return
            sids_to_check = list(self.tracked_sids.keys())

        # Build OR clauses for both searches
        sid_or_clause = self._build_sid_or_clause(sids_to_check)

        # Poll MergeReport if enabled
        if self.config.get("merge_report_enabled", True):
            self._poll_merge_report(sids_to_check, sid_or_clause)

        # Poll native email if enabled
        if self.config.get("native_email_enabled", True):
            self._poll_native_email(sids_to_check, sid_or_clause)

        # Check timeouts
        self._check_timeouts()

    def _build_sid_or_clause(self, sids: list[str]) -> str:
        """Build OR clause for SIDs. Handles variations in log format."""
        clauses = []
        for sid in sids:
            # Variants: SID=..., sid=..., sid="..."
            clauses.append(f'("SID={sid}" OR "sid={sid}" OR "sid=\\"{sid}\\"")'.replace('"', '"'))
        return " OR ".join(clauses)

    def _poll_merge_report(self, sids: list[str], sid_or_clause: str) -> None:
        """Poll for MergeReport verification events."""
        config = self.config

        # Build search
        search_parts = [
            f'index={config.get("merge_report_index", "_internal")}',
            f'source="{config.get("merge_report_source_contains", "mergeReport_alert.log")}"',
            f"({sid_or_clause})",
        ]
        if config.get("merge_report_sourcetype"):
            search_parts.append(f'sourcetype="{config["merge_report_sourcetype"]}"')

        search_query = " ".join(search_parts)

        # Determine earliest
        earliest = self._get_earliest("merge_report")

        try:
            results = self.client._get(
                "/services/search/jobs/export",
                params={
                    "search": search_query,
                    "earliest_time": earliest,
                    "output_mode": "json",
                },
            )

            # Process results
            for result in results.get("results", []):
                self._process_merge_report_result(result, sids)

            # Update last search time
            self._last_search_time = time.time()

        except Exception as e:
            self.ui_queue.put(("postdispatch_error", f"MergeReport search failed: {e}"))

    def _poll_native_email(self, sids: list[str], sid_or_clause: str) -> None:
        """Poll for native email verification events."""
        config = self.config

        # Build search
        search_parts = [
            f'index={config.get("native_email_index", "_internal")}',
            f'source="{config.get("native_email_source_contains", "python.log")}"',
            "sendemail",
            f"({sid_or_clause})",
        ]
        if config.get("native_email_sourcetype"):
            search_parts.append(f'sourcetype="{config["native_email_sourcetype"]}"')

        search_query = " ".join(search_parts)

        # Determine earliest
        earliest = self._get_earliest("native_email")

        try:
            results = self.client._get(
                "/services/search/jobs/export",
                params={
                    "search": search_query,
                    "earliest_time": earliest,
                    "output_mode": "json",
                },
            )

            # Process results
            for result in results.get("results", []):
                self._process_native_email_result(result, sids)

            # Update last search time
            self._last_search_time = time.time()

        except Exception as e:
            self.ui_queue.put(("postdispatch_error", f"Native email search failed: {e}"))

    def _get_earliest(self, channel: str) -> str:
        """Get earliest time for search (incremental)."""
        lookback = self.config.get("lookback_seconds", 300)
        # For simplicity, always use fixed lookback; could be incremental with state
        return f"-{lookback}s"

    def _process_merge_report_result(self, result: dict, sids: list[str]) -> None:
        """Process a MergeReport log entry."""
        raw = result.get("_raw", "")
        raw_time = result.get("_time", 0)

        # Check dedup cache
        cache_key = f"mr_{raw_time}_{hash(raw) % 10000}"
        if cache_key in self._event_dedup_cache:
            return
        self._event_dedup_cache[cache_key] = time.time()

        # Extract SID from raw
        sid_match = re.search(r'SID=([^\s,]+)', raw)
        if not sid_match:
            return

        sid = sid_match.group(1).strip()
        if sid not in self.tracked_sids:
            return

        state = self.tracked_sids[sid]

        # Parse Action field
        action_match = re.search(r'Action=([^,]+)', raw)
        action = action_match.group(1).strip() if action_match else ""

        # Check for "Email sent" (strict success)
        if action == "Email sent":
            state.merge_report_state["success"] = True
            self._emit_ui_line(
                f"[PostDispatch] [MergeReport] (sid={sid}) Email sent"
            )
            return

        # Check for "Sending email" (progress only)
        if action.startswith("Sending email"):
            state.merge_report_state["sending"] = True
            # Extract SMTP info if available
            smtp_match = re.search(r'SmtpServer=([^,]+)', raw)
            smtp = smtp_match.group(1).strip() if smtp_match else "?"
            port_match = re.search(r'SmtpPort=(\d+)', raw)
            port = port_match.group(1) if port_match else ""

            if smtp == "" or smtp.strip() == "":
                state.merge_report_state["smtp_empty"] = True
                self._emit_ui_line(
                    f"[PostDispatch] [MergeReport] (sid={sid}) FAILED: SMTP server not configured (SmtpServer empty)"
                )
                state.merge_report_state["failed"] = True
            else:
                self._emit_ui_line(
                    f"[PostDispatch] [MergeReport] (sid={sid}) Sending email (smtp={smtp}:{port})"
                )
            return

        # Check for ERROR
        if "ERROR" in raw or "Traceback" in raw:
            state.merge_report_state["failed"] = True
            error_msg = raw[raw.find("ERROR") : raw.find("ERROR") + 100] if "ERROR" in raw else raw[:100]
            self._emit_ui_line(
                f"[PostDispatch] [MergeReport] (sid={sid}) FAILED: {error_msg}"
            )
            return

        # Progress lines (zip/xlsx)
        if "Action=" in raw and ("zip" in raw.lower() or "xlsx" in raw.lower()):
            size_match = re.search(r'Size=(\d+)', raw)
            size = size_match.group(1) if size_match else ""
            size_str = f" ({size} bytes)" if size else ""
            self._emit_ui_line(
                f"[PostDispatch] [MergeReport] (sid={sid}) {action}{size_str}"
            )

    def _process_native_email_result(self, result: dict, sids: list[str]) -> None:
        """Process a native email (python.log) log entry."""
        raw = result.get("_raw", "")
        raw_time = result.get("_time", 0)

        # Check dedup cache
        cache_key = f"ne_{raw_time}_{hash(raw) % 10000}"
        if cache_key in self._event_dedup_cache:
            return
        self._event_dedup_cache[cache_key] = time.time()

        # Extract sid (lowercase)
        sid_match = re.search(r'\bsid=([^\s,\]]+)', raw, re.IGNORECASE)
        if not sid_match:
            return

        sid = sid_match.group(1).strip(' \\"')
        if sid not in self.tracked_sids:
            return

        state = self.tracked_sids[sid]

        # Check for error keywords
        error_keywords = [
            "ERROR",
            "Exception",
            "Traceback",
            "SMTPException",
            "connection refused",
            "connection timeout",
            "authentication failed",
            "AUTH failed",
        ]
        has_error = any(kw.lower() in raw.lower() for kw in error_keywords)

        if has_error:
            state.native_email_state["failed"] = True
            # Extract error message
            error_msg = ""
            for kw in error_keywords:
                idx = raw.lower().find(kw.lower())
                if idx >= 0:
                    error_msg = raw[idx : idx + 100]
                    break
            self._emit_ui_line(
                f"[PostDispatch] [NativeEmail] (sid={sid}) FAILED: {error_msg or 'See logs'}"
            )
            return

        # Check for "Sending email." (invoked)
        if "Sending email." in raw:
            state.native_email_state["invoked"] = True
            to_match = re.search(r'to="?([^"]+)"?', raw, re.IGNORECASE)
            recipient = to_match.group(1).strip() if (to_match and to_match.group(1).strip()) else "unknown"
            self._emit_ui_line(
                f"[PostDispatch] [NativeEmail] (sid={sid}) sendemail invoked (to={recipient})"
            )
            return

    def _check_timeouts(self) -> None:
        """Check for SIDs that haven't seen success within timeout."""
        current_time = time.time()

        with self._lock:
            sids_to_check = list(self.tracked_sids.items())

        for sid, state in sids_to_check:
            elapsed = current_time - state.registered_time

            # MergeReport timeout
            mr_timeout = self.config.get("merge_report_timeout_seconds", 120)
            if (
                self.config.get("merge_report_enabled", True)
                and not state.merge_report_state["success"]
                and not state.merge_report_state["failed"]
                and elapsed > mr_timeout
            ):
                state.merge_report_state["failed"] = True
                self._emit_ui_line(
                    f"[PostDispatch] [MergeReport] (sid={sid}) FAILED: Timeout (no success marker after {mr_timeout}s)"
                )
                with self._lock:
                    if sid in self.tracked_sids:
                        del self.tracked_sids[sid]

            # Native email timeout
            ne_timeout = self.config.get("native_email_timeout_seconds", 120)
            if (
                self.config.get("native_email_enabled", True)
                and state.native_email_state["invoked"]
                and not state.native_email_state["success"]
                and not state.native_email_state["failed"]
                and elapsed > ne_timeout
            ):
                # Mark as success if invoked and no error (unless strict)
                if not self.config.get("native_email_strict_success", False):
                    state.native_email_state["success"] = True
                    self._emit_ui_line(
                        f"[PostDispatch] [NativeEmail] (sid={sid}) Sent (best-effort: invoked + no errors)"
                    )
                else:
                    self._emit_ui_line(
                        f"[PostDispatch] [NativeEmail] (sid={sid}) UNKNOWN: Invoked but no success marker (strict mode)"
                    )
                with self._lock:
                    if sid in self.tracked_sids:
                        del self.tracked_sids[sid]

    def _emit_ui_line(self, line: str) -> None:
        """Emit a formatted line to the UI queue."""
        self.ui_queue.put(("postdispatch", line))

    def get_final_status(self) -> Dict[str, int]:
        """Get final status counts for summary."""
        with self._lock:
            states = list(self.tracked_sids.values())

        dispatch_ok = len(states)
        verified_sent = sum(
            1 for s in states
            if (s.merge_report_state["success"] or s.native_email_state["success"])
        )
        failed = sum(
            1 for s in states
            if (s.merge_report_state["failed"] or s.native_email_state["failed"])
        )
        unknown = dispatch_ok - verified_sent - failed

        return {
            "dispatch_ok": dispatch_ok,
            "verified_sent": verified_sent,
            "failed": failed,
            "unknown": unknown,
        }
