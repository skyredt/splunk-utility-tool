"""Reusable file tailer for monitoring log files.

Provides a background thread that reads newly appended lines from a text log file
and emits them to a queue. Handles file rotation/truncation, missing files, and
permission errors gracefully.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from typing import Optional


class LogTailer:
    """
    Tail a log file and emit new lines to a queue.

    Features:
      - Maintains file offset to detect new lines
      - Detects file truncation/rotation (file size < last offset)
      - Thread-safe queue output
      - Graceful handling of missing files and permission errors
      - Clean shutdown via stop event
    """

    def __init__(self, file_path: str, poll_interval: float = 1.0):
        """
        Initialize the tailer.

        Args:
            file_path: Absolute path to the log file
            poll_interval: Seconds between file checks (default 1.0)
        """
        self.file_path = file_path
        self.poll_interval = poll_interval
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._offset = 0
        self._last_size = 0

    def start(self) -> None:
        """Start the tailer thread (background, daemon mode)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self.stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the tailer thread gracefully."""
        self.stop_event.set()
        if self._thread is not None:
            # Give thread a moment to finish
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        """Background thread loop."""
        while not self.stop_event.is_set():
            try:
                self._poll_file()
            except Exception as e:
                # Log internal errors but don't crash the thread
                self.output_queue.put(f"[LogTailer Error] {e}")

            time.sleep(self.poll_interval)

    def _poll_file(self) -> None:
        """Check file for new lines and emit them to queue."""
        if not os.path.exists(self.file_path):
            # File doesn't exist yet; reset offset and wait
            self._offset = 0
            self._last_size = 0
            return

        try:
            current_size = os.path.getsize(self.file_path)
        except OSError:
            # Permission error or other file access issue; don't emit, just return
            return

        # Detect truncation or rotation: file size less than last offset
        if current_size < self._offset:
            # File was rotated or truncated; start from beginning
            self._offset = 0

        if current_size <= self._offset:
            # No new data
            return

        # Read new lines from offset
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                lines = f.readlines()
                new_offset = f.tell()
        except OSError:
            # Can't read file now; just skip this poll
            return

        # Emit complete lines to queue (exclude incomplete final line)
        for line in lines:
            # Remove trailing newline for queue emission
            if line.endswith("\n"):
                self.output_queue.put(line[:-1])

        self._offset = new_offset
        self._last_size = current_size

    def get_queue(self) -> queue.Queue[str]:
        """Return the output queue for receiving lines."""
        return self.output_queue


if __name__ == "__main__":
    # Simple test: tail a file and print lines
    import sys

    if len(sys.argv) < 2:
        print("Usage: python log_tailer.py <file_path>")
        sys.exit(1)

    tailer = LogTailer(sys.argv[1])
    tailer.start()

    print(f"Tailing {sys.argv[1]} (Ctrl+C to stop)...")
    try:
        while True:
            try:
                line = tailer.get_queue().get(timeout=0.5)
                print(f"[TAIL] {line}")
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print("\nStopping...")
        tailer.stop()
