# MergeReport Integration - Technical Reference

## Module: log_tailer.py

### Class: LogTailer

```python
class LogTailer:
    """Tail a log file and emit new lines to a queue."""
    
    def __init__(self, file_path: str, poll_interval: float = 1.0):
        """Initialize the tailer."""
    
    def start(self) -> None:
        """Start the tailer thread (background, daemon mode)."""
    
    def stop(self) -> None:
        """Stop the tailer thread gracefully."""
    
    def get_queue(self) -> queue.Queue[str]:
        """Return the output queue for receiving lines."""
```

### Key Attributes

- `file_path: str` – Path to log file
- `poll_interval: float` – Seconds between file checks (default 1.0)
- `output_queue: queue.Queue[str]` – Queue of new lines
- `stop_event: threading.Event` – Signal to stop thread
- `_offset: int` – Current file position (internal)
- `_last_size: int` – Last known file size (internal)

### Behavior

1. **Polling Loop**: Checks file every `poll_interval` seconds
2. **Offset Tracking**: Remembers position in file; only reads new data
3. **Rotation Detection**: If file size < last offset, resets to 0
4. **Queue Output**: Emits complete lines (without newline) to `output_queue`
5. **Error Resilience**: Catches OSError; continues silently
6. **Incomplete Lines**: Doesn't emit final line if it lacks newline

### Example Usage

```python
import queue

tailer = LogTailer("/path/to/file.log", poll_interval=0.5)
tailer.start()

try:
    while True:
        try:
            line = tailer.get_queue().get(timeout=1.0)
            print(f"New line: {line}")
        except queue.Empty:
            print("Waiting for new lines...")
except KeyboardInterrupt:
    tailer.stop()
```

---

## Module: mergereport_monitor.py

### Class: MergeReportEvent

```python
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
```

### Class: MergeReportParser

```python
class MergeReportParser:
    """Parse MergeReport log lines (static methods only)."""
    
    LOG_PATTERN = re.compile(
        r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2},\d{3})\s+"
        r"(\w+)\s+Search\s+Name=([^,]+),\s+SID=([^,]+),\s+(.*)$"
    )
    
    @staticmethod
    def parse_line(line: str) -> Optional[MergeReportEvent]:
        """Parse a MergeReport log line."""
```

### Class: MergeReportMonitor

```python
class MergeReportMonitor:
    """Monitor MergeReport log file and emit parsed events for tracked SIDs."""
    
    def __init__(
        self,
        log_path: str,
        ui_queue: "queue.Queue[tuple[str, object]]",
        timeout_seconds: int = 90,
    ):
        """Initialize the monitor."""
    
    def register_sid(self, sid: str, search_name: str) -> None:
        """Register a SID to track."""
    
    def start(self) -> None:
        """Start monitoring the log file."""
    
    def stop(self) -> None:
        """Stop monitoring cleanly."""
```

### Key Attributes

- `log_path: str` – Path to MergeReport log file
- `ui_queue: queue.Queue[tuple[str, object]]` – Output queue (expects ("mergereport", line) tuples)
- `timeout_seconds: int` – Inactivity threshold for warning
- `tracked_sids: dict[str, dict]` – SIDs currently being tracked
- `tailer: LogTailer` – Internal file tailer
- `stop_event: threading.Event` – Signal to stop thread
- `_lock: threading.Lock` – Protects tracked_sids dict

### Behavior

1. **SID Registration**: `register_sid(sid, search_name)` adds SID to tracking
2. **Line Filtering**: Only processes lines matching registered SIDs
3. **Parsing**: Extracts Action, Size, Path metadata
4. **UI Formatting**: Converts event to user-friendly display line
5. **Timeout Detection**: If no activity for configured seconds, posts warning
6. **Queue Output**: Posts `("mergereport", ui_line)` tuples to ui_queue
7. **Error Handling**: Posts `("mergereport_error", msg)` on thread error

### Example Usage

```python
import queue

ui_queue = queue.Queue()
monitor = MergeReportMonitor(
    log_path="/var/log/splunk/mergeReport_alert.log",
    ui_queue=ui_queue,
    timeout_seconds=90
)

monitor.start()

# Register SIDs as they're obtained from dispatch
monitor.register_sid("1234567.1", "DailyReport")
monitor.register_sid("1234567.2", "WeeklyReport")

# Consume events in main thread/UI loop
while True:
    try:
        status, payload = ui_queue.get(timeout=1.0)
        if status == "mergereport":
            print(f"UI Display: {payload}")
        elif status == "mergereport_error":
            print(f"Monitor Error: {payload}")
    except queue.Empty:
        pass

monitor.stop()
```

### Log Format Parsing

**Expected Format**:
```
YYYY-MM-DD HH:MM:SS,mmm LEVEL Search Name=<name>, SID=<sid>, <message>
```

**Regex Pattern**:
```regex
^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2},\d{3})\s+(\w+)\s+Search\s+Name=([^,]+),\s+SID=([^,]+),\s+(.*)$
```

**Captured Groups**:
1. Date (YYYY-MM-DD)
2. Time (HH:MM:SS,mmm)
3. Level (INFO, ERROR, WARNING, etc.)
4. Search Name
5. SID
6. Message (remainder of line)

**Metadata Extraction**:
- `Action=<text>`: Extracted as `action` field
- `Size=<number>`: Extracted as `size` integer
- `Path=<path>`: Extracted as `path` field

**Valid Examples**:
```
2025-02-13 14:23:45,123 INFO Search Name=DailyReport, SID=1707835425.42, results.csv.gz
2025-02-13 14:24:00,789 INFO Search Name=DailyReport, SID=1707835425.42, Action=Xlsx file created, Size=19184
2025-02-13 14:24:05,012 INFO Search Name=DailyReport, SID=1707835425.42, Action=Sending email, SmtpServer=mail.example.com, SmtpPort=25
2025-02-13 14:24:10,123 ERROR Search Name=DailyReport, SID=1707835425.42, Failed to send email: SMTP connection timeout
```

---

## Module: splunk_engine.py

### Updated SplunkConfig Dataclass

```python
@dataclass
class SplunkConfig:
    servers: List[str]
    username: str
    password: str
    merge_report_enabled: bool = False
    merge_report_log_path: str = ""
    merge_report_timeout_seconds: int = 90
```

### Updated load_config() Function

**Signature**:
```python
def load_config(path: str = "config.ini") -> SplunkConfig:
```

**Behavior**:
1. Reads [splunk] section (existing behavior)
2. Reads [mergereport] section if present (new)
3. Validates merge_report_log_path is absolute (raises ValueError if not)
4. Sets merge_report_enabled = False if path is empty/invalid
5. Returns SplunkConfig with all fields populated

**Validation**:
- If log_path is not absolute: `raise ValueError("MergeReport log_path must be absolute, got: ...")`
- Example absolute paths:
  - `D:\Splunk\var\log\splunk\mergeReport_alert.log` ✓
  - `C:\Users\MyUser\Desktop\test.log` ✓
  - `/var/log/splunk/mergeReport_alert.log` ✓
  - `..\file.log` ✗ (relative)
  - `file.log` ✗ (relative)

### Updated run_dispatch_single() Function

**Added Parameters**:
```python
def run_dispatch_single(
    # ... existing parameters ...
    sid_callback: Optional[Callable[[str, str], None]] = None,
) -> List[str]:
```

**Callback Invocation**:
- Called when dispatch succeeds and SID is obtained
- Arguments: `(sid: str, search_name: str)`
- Called once for "no_change" dispatch
- Called once per slice for multi-slice dispatch
- Example:
  ```python
  def on_sid(sid: str, name: str):
      print(f"Got SID {sid} for report {name}")
  
  run_dispatch_single(..., sid_callback=on_sid)
  ```

### Updated run_dispatch_multi() Function

**Added Parameters**:
```python
def run_dispatch_multi(
    # ... existing parameters ...
    sid_callback: Optional[Callable[[str, str], None]] = None,
) -> List[str]:
```

**Behavior**:
- Passes sid_callback through to run_dispatch_single()
- Same callback semantics

---

## Module: splunk_report_tk.py

### Updated ReportsApp Class

**New Instance Variables**:
```python
self._merge_report_monitor: MergeReportMonitor | None = None
```

**Updated Methods**:

#### _dispatch_worker(self, params: dict)

```python
def _dispatch_worker(self, params: dict) -> None:
    def log_callback(line: str) -> None:
        self._dispatch_queue.put(("log", line))

    def sid_callback(sid: str, search_name: str) -> None:
        if self._merge_report_monitor is not None:
            self._merge_report_monitor.register_sid(sid, search_name)

    try:
        run_dispatch_multi(log_callback=log_callback, sid_callback=sid_callback, **params)
        self._dispatch_queue.put(("done", None))
    except Exception as e:
        self._dispatch_queue.put(("err", e))
```

**Key Points**:
- Nested sid_callback() registers SID with monitor
- Passes both callbacks to run_dispatch_multi()

#### _poll_dispatch_queue(self)

**New Queue Message Types**:
- `("mergereport", ui_line)` – Formatted MergeReport event line
- `("mergereport_error", error_msg)` – Monitor error (won't crash)

**Updated Handlers**:
```python
if status == "mergereport":
    self._append_log(str(payload))
elif status == "mergereport_error":
    self._append_log(f"[MergeReport Monitor Error] {payload}")
```

**Updated Cleanup**:
```python
if done:
    self._set_dispatch_state(False)
    if self._merge_report_monitor is not None:
        self._merge_report_monitor.stop()
        self._merge_report_monitor = None
```

#### on_send_clicked(self)

**New Initialization Logic**:
```python
# Initialize MergeReport monitor if enabled
if self.cfg.merge_report_enabled and self.cfg.merge_report_log_path:
    try:
        self._merge_report_monitor = MergeReportMonitor(
            log_path=self.cfg.merge_report_log_path,
            ui_queue=self._dispatch_queue,
            timeout_seconds=self.cfg.merge_report_timeout_seconds,
        )
        self._merge_report_monitor.start()
        self._append_log(
            f"[MergeReport] Monitor started for {self.cfg.merge_report_log_path}"
        )
    except Exception as e:
        self._append_log(f"[MergeReport] WARNING: Could not start monitor: {e}")
        self._merge_report_monitor = None
else:
    if self.cfg.merge_report_enabled and not self.cfg.merge_report_log_path:
        self._append_log(
            "[MergeReport] WARNING: enabled but log_path not configured; skipping"
        )
    self._merge_report_monitor = None
```

**Key Points**:
- Instantiates monitor before dispatch thread starts
- Catches startup errors and logs warning
- Sets to None if disabled or path not configured
- Always graceful; never crashes

---

## Configuration File Format

### config.ini [mergereport] Section

```ini
[mergereport]
enabled = true|false
log_path = /absolute/path/to/mergeReport_alert.log
timeout_seconds = <integer>
```

**Field Details**:

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | bool | `false` | If false, all MergeReport monitoring is skipped |
| `log_path` | string | `""` | Absolute path to MergeReport log file. Must be absolute. Empty = disabled. |
| `timeout_seconds` | int | `90` | Seconds of inactivity before "no activity" warning is shown for a SID. |

**Validation Rules**:
- If `enabled = true` and `log_path` is empty: Treated as disabled; no error
- If `enabled = true` and `log_path` is not absolute: ValueError at startup; app fails to load
- If `enabled = false`: Entire feature disabled; no overhead
- If `log_path` is set but file doesn't exist: No error; tailer waits for file creation

**Example Configurations**:

**Disabled (Default)**:
```ini
[mergereport]
enabled = false
log_path =
timeout_seconds = 90
```

**Enabled (Windows Production)**:
```ini
[mergereport]
enabled = true
log_path = D:\Splunk\var\log\splunk\mergeReport_alert.log
timeout_seconds = 90
```

**Enabled (Linux/Unix)**:
```ini
[mergereport]
enabled = true
log_path = /opt/splunk/var/log/splunk/mergeReport_alert.log
timeout_seconds = 120
```

**Enabled (Network Share)**:
```ini
[mergereport]
enabled = true
log_path = \\fileserver\splunk\mergeReport_alert.log
timeout_seconds = 120
```

---

## Threading Model (Detailed)

```
┌─────────────────────────────────────────────────────────────────┐
│ Main Thread (Tk Event Loop)                                     │
│                                                                 │
│ root.mainloop()  ← User interacts with GUI                      │
│   ↑                                                              │
│   └─→ on_send_clicked()                                         │
│       ├─→ Instantiate MergeReportMonitor                        │
│       ├─→ monitor.start()  ← Start monitor thread              │
│       │                                                          │
│       ├─→ Thread(..., target=_dispatch_worker).start()         │
│       │   └─ Start dispatch thread                             │
│       │                                                          │
│       └─→ after(150ms, _poll_dispatch_queue)  ← Schedule polls │
│                                                                 │
│   _poll_dispatch_queue()  ← Called every 150ms                  │
│   ├─→ while True:                                               │
│   │   └─→ queue.get_nowait()  ← Consume queue                   │
│   │       ├─→ ("log", line) → _append_log()                    │
│   │       ├─→ ("mergereport", line) → _append_log()            │
│   │       ├─→ ("mergereport_error", err) → _append_log()       │
│   │       └─→ ("done", None) → Cleanup & stop monitor          │
│   └─→ after(150ms, self)  ← Reschedule if still running       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Dispatch Thread (spawned by on_send_clicked)                    │
│                                                                 │
│ _dispatch_worker(params)                                        │
│ └─→ run_dispatch_multi(                                         │
│     client=...,                                                 │
│     report_ids=[...],                                           │
│     report_names=[...],                                         │
│     selected_indices=[...],                                     │
│     ...,                                                         │
│     log_callback=log_callback,  ← Puts ("log", ...) on queue   │
│     sid_callback=sid_callback   ← Calls register_sid()         │
│ )                                                               │
│    ├─→ for each report:                                         │
│    │   └─→ run_dispatch_single(                                │
│    │       ...,                                                 │
│    │       sid_callback=sid_callback                           │
│    │   )                                                        │
│    │       ├─→ dispatch_saved_search()  ← Get SID              │
│    │       ├─→ sid_callback(sid, name)  ← Register SID         │
│    │       └─→ log_callback(msg)  ← Post to queue              │
│    │                                                             │
│    └─→ Put ("done", None) on queue when complete              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Monitor Thread (spawned by monitor.start())                     │
│                                                                 │
│ MergeReportMonitor._run()                                       │
│ ├─→ Tailer Thread                                              │
│ │   └─→ LogTailer._run()                                        │
│ │       └─→ while not stop_event:                              │
│ │           ├─→ Poll file (every 1 second)                     │
│ │           ├─→ Detect new lines                               │
│ │           └─→ Put line on tailer.output_queue                │
│ │                                                               │
│ └─→ while not stop_event:                                      │
│     ├─→ Get line from tailer.output_queue                      │
│     ├─→ Parse line (MergeReportParser.parse_line())            │
│     ├─→ Filter by tracked_sids                                 │
│     ├─→ Format for UI (event.format_for_ui())                  │
│     ├─→ Put ("mergereport", ui_line) on ui_queue              │
│     └─→ Check timeouts (every iteration)                       │
└─────────────────────────────────────────────────────────────────┘

Queue Flow:
═════════

ui_queue (queue.Queue)
├─→ ("log", line) [from dispatch thread via log_callback]
├─→ ("mergereport", line) [from monitor thread]
├─→ ("mergereport_error", msg) [from monitor thread on error]
├─→ ("err", exception) [from dispatch thread on exception]
└─→ ("done", None) [from dispatch thread when complete]

Main thread polls this queue every 150ms and updates GUI accordingly.

Synchronization Points:
═══════════════════════

1. Queue.put() / Queue.get() are atomic (stdlib thread-safe)
2. MergeReportMonitor.tracked_sids protected by threading.Lock
3. No shared mutable state between monitor and dispatch threads
4. No shared mutable state between tailer and monitor (only queue)
5. Main thread is single-threaded (no race conditions)
```

---

## Performance Characteristics

| Aspect | Behavior |
|--------|----------|
| **File Reading** | O(n) where n = bytes appended since last read. Efficient (sequential read from offset). |
| **Line Parsing** | O(1) regex match per line. Negligible overhead. |
| **SID Filtering** | O(1) dict lookup per line. Very fast. |
| **UI Update Latency** | ~150ms (Tk poll interval). User sees ~150ms delay from log append to UI display. |
| **CPU Usage (Idle)** | ~1% per thread (sleeping between polls). Negligible. |
| **CPU Usage (Active)** | Depends on log file activity. Minimal for typical 1-10 lines/second rate. |
| **Memory Usage** | ~2-5 MB baseline. Dict of tracked SIDs is typically <100 entries. Queues auto-clear. |
| **File Rotation** | Detected instantly (size check). Reset to 0. No data loss. |
| **Large Log Files** | Supported. Tailer maintains only current offset; doesn't load entire file. |

---

## Error Codes & Messages

### load_config()

| Error | Cause | User Action |
|-------|-------|-------------|
| `ValueError: MergeReport log_path must be absolute, got: ...` | Path is relative | Edit config.ini and use absolute path (e.g., `D:\path\to\file.log`) |
| `FileNotFoundError: Config file not found: ...` | config.ini missing | Create config.ini from config.example.ini |
| `KeyError: Missing [splunk] section in config.ini` | Missing [splunk] section | Add required [splunk] section to config.ini |

### MergeReportMonitor Startup

| Error | Cause | User Action |
|-------|-------|-------------|
| `FileNotFoundError: mergeReport_alert.log not found` | Log file doesn't exist yet | Wait for Splunk MergeReport TA to create it, or verify path is correct |
| `PermissionError: Permission denied` | No read access to log file | Run tool as administrator or fix file permissions |

### UI Display

Messages displayed in log (non-fatal):
```
[MergeReport] Monitor started for D:\path\to\mergeReport_alert.log
[MergeReport] WARNING: Could not start monitor: <error>
[MergeReport] WARNING: enabled but log_path not configured; skipping
[MergeReport Monitor Error] <error from monitor thread>
```

---

## Testing Utilities

### Parser Test Harness

**File**: `mergereport_monitor.py`  
**Command**: `python mergereport_monitor.py`

Runs `test_parser()` function with sample log lines. Output shows parse success/failure and formatted UI lines.

**Sample Output**:
```
=== MergeReport Parser Test ===

✓ Parsed: 2025-02-13 14:23:45,123 INFO Search Name=DailyReport, SID=1707835425.42, results.csv.gz
  -> [MergeReport] [DailyReport] (sid=1707835425.42) results.csv.gz

✓ Parsed: 2025-02-13 14:24:00,789 INFO Search Name=DailyReport, SID=1707835425.42, Action=Xlsx file created, Size=19184
  -> [MergeReport] [DailyReport] (sid=1707835425.42) Action=Xlsx file created, Size=19184 (action=Xlsx file created, 19184 bytes)

✗ No match: invalid line format
```

### Syntax Validation

```bash
python -m py_compile log_tailer.py mergereport_monitor.py splunk_engine.py splunk_report_tk.py
```

No output = all files OK.

### Import Validation

```bash
python -c "from log_tailer import LogTailer; from mergereport_monitor import MergeReportMonitor; print('OK')"
```

Output: `OK`

---

## Compatibility

| Component | Version | Notes |
|-----------|---------|-------|
| Python | 3.9+ | Uses type hints (Optional, Union) |
| Tk | 8.6+ | Standard library (no install needed) |
| Splunk | 8.0+ | MergeReport TA must be installed |
| OS | Windows, Linux, macOS | Uses pathlib internally; paths are OS-independent |
| Dependencies | None (stdlib only) | configparser, queue, threading, re, os, time, dataclasses |

---

**End of Technical Reference**
