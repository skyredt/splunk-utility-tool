"""MergeReport log monitor and parser.

Monitors a MergeReport log file, parses lines matching the expected format,
filters by tracked SIDs, and posts formatted events to a UI queue.
"""

from __future__ import annotations

import queue
import re
import threading
import time
from dataclasses import dataclass
from typing import Optional, Callable

from log_tailer import LogTailer


@dataclass
class MergeReportEvent:
    """A parsed MergeReport log event."""

    search_name: str
    sid: str
    level: str
    message: str
    action: Optional[str] = None
    size: Optional[int] = None
    path: Optional[str] = None

    def format_for_ui(self) -> str:
        """Format event as a friendly UI display line."""
        parts = [f"[MergeReport] [{self.search_name}] (sid={self.sid})"]

        if self.level == "ERROR":
            parts.append(f"[ERROR] {self.message}")
        else:
            parts.append(self.message)
            if self.action:
                parts.append(f"(action={self.action}")
                if self.size is not None:
                    parts[-1] += f", {self.size} bytes"
                if self.path:
                    parts[-1] += f", path={self.path}"
                parts[-1] += ")"

        return " ".join(parts)


class MergeReportParser:
    """Parse MergeReport log lines."""

    # Pattern: YYYY-MM-DD HH:MM:SS,mmm LEVEL Search Name=<name>, SID=<sid>, <message...>
    LOG_PATTERN = re.compile(
        r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2},\d{3})\s+"
        r"(\w+)\s+Search\s+Name=([^,]+),\s+SID=([^,]+),\s+(.*)$"
    )

    @staticmethod
    def parse_line(line: str) -> Optional[MergeReportEvent]:
        """
        Parse a MergeReport log line.

        Returns MergeReportEvent if line matches pattern, None otherwise.
        """
        match = MergeReportParser.LOG_PATTERN.match(line)
        if not match:
            return None

        date_part, time_part, level, search_name, sid, message = match.groups()
        search_name = search_name.strip()
        sid = sid.strip()
        message = message.strip()

        # Extract optional fields
        action = None
        size = None
        path = None

        # Look for "Action=..." pattern
        action_match = re.search(r'Action=([^,]+)', message)
        if action_match:
            action = action_match.group(1).strip()

        # Look for "Size=..." pattern (extract numeric value)
        size_match = re.search(r'Size=(\d+)', message)
        if size_match:
            size = int(size_match.group(1))

        # Look for "Path=..." pattern
        path_match = re.search(r'Path=([^\s,]+)', message)
        if path_match:
            path = path_match.group(1).strip()

        return MergeReportEvent(
            search_name=search_name,
            sid=sid,
            level=level,
            message=message,
            action=action,
            size=size,
            path=path,
        )


class MergeReportMonitor:
    """
    Monitor MergeReport log file and emit parsed events for tracked SIDs.

    Usage:
      1. Instantiate with log file path and UI output queue
      2. Call register_sid() for each SID to track
      3. Call start() to begin monitoring
      4. Call stop() to cleanly shutdown
    """

    def __init__(
        self,
        log_path: str,
        ui_queue: "queue.Queue[tuple[str, object]]",
        timeout_seconds: int = 90,
    ):
        """
        Initialize the monitor.

        Args:
            log_path: Absolute path to MergeReport log file
            ui_queue: Queue for posting UI events (expects ("mergereport", event) tuples)
            timeout_seconds: Seconds of inactivity before "no activity" warning
        """
        self.log_path = log_path
        self.ui_queue = ui_queue
        self.timeout_seconds = timeout_seconds
        self.tailer = LogTailer(log_path)
        self.tracked_sids: dict[str, dict] = {}  # sid -> {search_name, last_seen_time}
        self.stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def register_sid(self, sid: str, search_name: str) -> None:
        """Register a SID to track. Called when dispatch returns OK."""
        with self._lock:
            self.tracked_sids[sid] = {
                "search_name": search_name,
                "last_seen_time": time.time(),
            }

    def unregister_sid(self, sid: str) -> None:
        """Stop tracking a SID once terminal MergeReport activity has been observed."""
        with self._lock:
            self.tracked_sids.pop(str(sid or ""), None)

    def start(self) -> None:
        """Start monitoring the log file."""
        if self._monitor_thread is not None and self._monitor_thread.is_alive():
            return
        self.stop_event.clear()
        self.tailer.start()
        self._monitor_thread = threading.Thread(target=self._run, daemon=True)
        self._monitor_thread.start()

    def stop(self) -> None:
        """Stop monitoring cleanly."""
        self.stop_event.set()
        self.tailer.stop()
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=2.0)
        with self._lock:
            self.tracked_sids.clear()

    def _run(self) -> None:
        """Background thread loop: consume tailer lines and emit events."""
        while not self.stop_event.is_set():
            try:
                # Non-blocking get from tailer queue
                try:
                    line = self.tailer.get_queue().get(timeout=0.5)
                except queue.Empty:
                    line = None

                if line:
                    self._process_line(line)

                # Check for timeouts
                self._check_timeouts()

            except Exception as e:
                self.ui_queue.put(("mergereport_error", str(e)))

    def _process_line(self, line: str) -> None:
        """Parse a line and emit event if it matches a tracked SID."""
        event = MergeReportParser.parse_line(line)
        if not event:
            return

        with self._lock:
            if event.sid not in self.tracked_sids:
                # Not tracking this SID
                return
            # Update last seen time
            self.tracked_sids[event.sid]["last_seen_time"] = time.time()

        # Emit to UI queue
        ui_line = event.format_for_ui()
        self.ui_queue.put(("mergereport", ui_line))
        lower_message = str(event.message or "").lower()
        if (
            "app excution completed" in lower_message
            or "app execution completed" in lower_message
            or event.level == "ERROR"
        ):
            self.unregister_sid(event.sid)

    def _check_timeouts(self) -> None:
        """Emit 'no activity' warnings for SIDs that haven't been seen recently."""
        current_time = time.time()
        with self._lock:
            sids_to_check = list(self.tracked_sids.items())

        for sid, info in sids_to_check:
            if current_time - info["last_seen_time"] > self.timeout_seconds:
                # Emit timeout warning once, then remove from tracking
                search_name = info["search_name"]
                with self._lock:
                    if sid in self.tracked_sids:
                        del self.tracked_sids[sid]
                ui_line = (
                    f"[MergeReport] [{search_name}] (sid={sid}) "
                    f"No activity seen yet (still waiting)"
                )
                self.ui_queue.put(("mergereport", ui_line))


def test_parser(sample_log_content: str) -> None:
    """
    Dev helper: test the parser against sample log lines.

    Args:
        sample_log_content: Multi-line string with sample log entries
    """
    print("=== MergeReport Parser Test ===\n")
    lines = sample_log_content.strip().split("\n")
    for line in lines:
        if not line.strip():
            continue
        event = MergeReportParser.parse_line(line)
        if event:
            print(f"✓ Parsed: {line}")
            print(f"  -> {event.format_for_ui()}\n")
        else:
            print(f"✗ No match: {line}\n")


if __name__ == "__main__":
    # Test harness: validate parser against sample lines
    sample_log = """
2025-02-13 14:23:45,123 INFO Search Name=DailyReport, SID=1707835425.42, results.csv.gz
2025-02-13 14:23:46,234 INFO Search Name=DailyReport, SID=1707835425.42, App executed, generating searches...
2025-02-13 14:23:50,567 INFO Search Name=DailyReport, SID=1707835425.42, Report generates result from 2025-02-12 to 2025-02-13
2025-02-13 14:24:00,789 INFO Search Name=DailyReport, SID=1707835425.42, Action=Xlsx file created, Size=19184
2025-02-13 14:24:02,890 INFO Search Name=DailyReport, SID=1707835425.42, Action=Creating zip file, Path=/tmp/report_1707835425.zip
2025-02-13 14:24:03,901 INFO Search Name=DailyReport, SID=1707835425.42, Action=Zip file created, Size=17836
2025-02-13 14:24:05,012 INFO Search Name=DailyReport, SID=1707835425.42, Action=Sending email, SmtpServer=mail.example.com, SmtpPort=25
2025-02-13 14:24:10,123 ERROR Search Name=DailyReport, SID=1707835425.42, Failed to send email: SMTP connection timeout
"""
    test_parser(sample_log)
