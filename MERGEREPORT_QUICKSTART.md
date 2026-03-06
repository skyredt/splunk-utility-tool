# MergeReport Integration - Quick Start Guide

## Installation

1. **Copy new files to your workspace**:
   ```
   C:\SplunkTool3.0\SplunkUtilityTool_v3.0_base\
   ├── log_tailer.py              (NEW)
   └── mergereport_monitor.py      (NEW)
   ```

2. **Backup and update config files**:
   ```
   cp config.ini config.ini.bak
   ```

   Then update `config.ini` to include:
   ```ini
   [mergereport]
   enabled = false
   log_path =
   timeout_seconds = 90
   ```

3. **No pip installs needed** – uses only Python stdlib.

---

## Basic Setup

### Option A: Disable MergeReport (Default)
**No configuration needed.** The feature is off by default.

The tool works exactly as before. Leave:
```ini
[mergereport]
enabled = false
log_path =
```

### Option B: Enable MergeReport

1. **Find your MergeReport log path**:
   - On Windows production: `D:\Splunk\var\log\splunk\mergeReport_alert.log`
   - Or check your Splunk installation: `$SPLUNK_HOME\var\log\splunk\mergeReport_alert.log`
   - Must be an **absolute path** (e.g., `C:\...` or `D:\...`)

2. **Update config.ini**:
   ```ini
   [mergereport]
   enabled = true
   log_path = D:\Splunk\var\log\splunk\mergeReport_alert.log
   timeout_seconds = 90
   ```

3. **Save and restart the tool**. No other steps needed.

---

## Usage

### When Dispatching Reports

1. Select reports → Click "Send reports"
2. If MergeReport is enabled:
   - A message appears in the log: `[MergeReport] Monitor started for ...`
   - As reports dispatch, SIDs are obtained
   - The monitor begins tailing the MergeReport log
3. Watch the log display for MergeReport updates:
   ```
   [MergeReport] [DailyReport] (sid=1234567.1) App executed, generating searches...
   [MergeReport] [DailyReport] (sid=1234567.1) Action=Xlsx file created (19184 bytes)
   [MergeReport] [DailyReport] (sid=1234567.1) Action=Sending email (smtp port 25)
   ```

### Expected Output Format

Each MergeReport line in the GUI looks like:
```
[MergeReport] [SearchName] (sid=XXXXXXX.Y) <message>
```

With action details:
```
[MergeReport] [SearchName] (sid=XXXXXXX.Y) message (action=..., size ... bytes, path=...)
```

Error lines highlighted:
```
[MergeReport] [SearchName] (sid=XXXXXXX.Y) [ERROR] Failed to send email
```

No activity warning (after 90 seconds by default):
```
[MergeReport] [SearchName] (sid=XXXXXXX.Y) No activity seen yet (still waiting)
```

---

## Troubleshooting

### Issue: Tool won't start
**Error**: `ValueError: MergeReport log_path must be absolute`

**Solution**: Check config.ini [mergereport] log_path:
- Must start with a drive letter: `D:\path\to\file.log`
- Cannot be relative: `\..\file.log` ❌
- Try: `C:\Splunk\var\log\splunk\mergeReport_alert.log` ✓

Or simply disable it:
```ini
[mergereport]
enabled = false
```

---

### Issue: MergeReport lines don't appear in the log

**Checklist**:
1. Verify `enabled = true` in config.ini
2. Verify `log_path` is set and is an absolute path
3. Verify the log file exists: `Test-Path "D:\path\to\mergeReport_alert.log"`
4. Verify file is readable (permissions)
5. Verify log format matches pattern:
   ```
   YYYY-MM-DD HH:MM:SS,mmm LEVEL Search Name=<name>, SID=<sid>, <message>
   ```
6. Example valid line:
   ```
   2025-02-13 14:24:00,789 INFO Search Name=DailyReport, SID=1707835425.42, Action=Xlsx file created, Size=19184
   ```

If the Splunk MergeReport TA hasn't written to the log yet, no lines will appear (this is normal).

---

### Issue: Permission denied error appears in log

**Solution**:
1. Check file ownership: `Get-Item "D:\path\to\mergeReport_alert.log" | Select-Object Owner`
2. Run tool as administrator if needed
3. Ensure the file exists and is not empty
4. Check if Splunk service has written to it yet

---

### Issue: Log freezes while sending reports

**This should NOT happen.** The tool uses background threading specifically to prevent this.

If the UI freezes:
1. Check if there are permission issues with the log file
2. Try disabling MergeReport temporarily (`enabled = false`)
3. Verify no massive log file (gigabytes) that would slow reading
4. Report as a bug if freezing persists

---

## Advanced Configuration

### Adjust Timeout

Default is 90 seconds. If reports take longer, increase:
```ini
[mergereport]
enabled = true
log_path = D:\Splunk\var\log\splunk\mergeReport_alert.log
timeout_seconds = 300
```

If you see "No activity" warnings too quickly, increase this value.

### Multiple Log Paths (Not Supported Yet)

Current version monitors one log file. To support multiple:
- Would require enhancement to instantiate multiple monitors
- For now, workaround: append all outputs to a single log file

---

## Testing & Validation

### Validate Parser

Test the parser against sample log lines:
```bash
cd C:\SplunkTool3.0\SplunkUtilityTool_v3.0_base
python mergereport_monitor.py
```

Output will show which lines parse correctly and their formatted UI output.

### Validate Syntax

Check all files compile without errors:
```bash
python -m py_compile log_tailer.py mergereport_monitor.py splunk_engine.py splunk_report_tk.py
echo "All files OK"
```

### Create Test Log File

For testing without real Splunk MergeReport TA:
1. Create a test file: `D:\test_mergeReport.log`
2. Add sample lines:
   ```
   2025-02-13 14:23:45,123 INFO Search Name=TestReport, SID=1707835425.1, Starting report generation
   2025-02-13 14:24:00,456 INFO Search Name=TestReport, SID=1707835425.1, Action=Xlsx file created, Size=5000
   2025-02-13 14:24:05,789 INFO Search Name=TestReport, SID=1707835425.1, Action=Sending email, SmtpServer=localhost
   ```
3. Set config.ini:
   ```ini
   [mergereport]
   enabled = true
   log_path = D:\test_mergeReport.log
   ```
4. Launch tool and send a report
5. While dispatch is running, append more lines to the test file
6. Watch them appear in the GUI log

---

## FAQ

**Q: Does MergeReport monitoring slow down the tool?**  
A: No. Monitoring runs in a background thread. The UI remains responsive. If disabled, there's zero overhead.

**Q: What if the log file is huge (gigabytes)?**  
A: The tailer efficiently reads only new appended lines (using file offset). First read might take a moment, but subsequent reads are fast.

**Q: Can I use a relative path?**  
A: No. Must be absolute (e.g., `D:\path\to\file.log`, not `.\file.log`). This prevents ambiguity.

**Q: What if the log file gets rotated?**  
A: The tailer automatically detects this (file size < previous offset) and resets to read the new file from the beginning.

**Q: What if the Splunk MergeReport TA hasn't written anything yet?**  
A: The tool waits patiently. No errors. When the TA writes a line, it will be captured.

**Q: Can I have multiple Splunk instances writing to the same MergeReport log?**  
A: The tailer will capture all lines. The monitor filters by SID, so lines are paired with the correct report.

**Q: What happens if I disable MergeReport mid-dispatch?**  
A: Can't happen (config is read once at startup). But if you restart the tool with it disabled, ongoing dispatch will stop monitoring.

**Q: Is there a UI for configuring MergeReport path?**  
A: Not yet. Configuration is file-based (config.ini). Future enhancement could add a settings dialog.

**Q: Can I use a UNC path (network share)?**  
A: Yes, if it's absolute: `\\server\share\mergeReport_alert.log`. But performance may be slower than local disk.

---

## Examples

### Example 1: Basic Setup (Windows Production)

```ini
[splunk]
servers = https://splunk-prod:8089
username = admin
password = changeme123

[mergereport]
enabled = true
log_path = D:\Splunk\var\log\splunk\mergeReport_alert.log
timeout_seconds = 90
```

Start the tool. When you send reports, MergeReport progress will appear in the log.

---

### Example 2: Testing (Local Test Log)

```ini
[splunk]
servers = https://127.0.0.1:8089
username = admin
password = password

[mergereport]
enabled = true
log_path = C:\Users\YourUser\Desktop\test_mergeReport.log
timeout_seconds = 30
```

Create `C:\Users\YourUser\Desktop\test_mergeReport.log` and manually append lines while testing.

---

### Example 3: Disabled (Default)

```ini
[splunk]
servers = https://splunk.local:8089
username = admin
password = password

[mergereport]
enabled = false
log_path =
timeout_seconds = 90
```

Tool works normally. No MergeReport monitoring. Can be enabled later.

---

## Support & Documentation

- **Implementation Details**: See `MERGEREPORT_IMPLEMENTATION.md`
- **Change Summary**: See `MERGEREPORT_CHANGES.md`
- **Code Documentation**: See docstrings in `log_tailer.py` and `mergereport_monitor.py`

---

## Key Takeaways

✓ **No hardcoded paths** – Supply via config.ini  
✓ **Absolute paths enforced** – Prevents ambiguity and path injection  
✓ **Graceful error handling** – Never crashes the UI  
✓ **Background threading** – UI stays responsive  
✓ **Standard library only** – No new dependencies  
✓ **Fully backward compatible** – Existing features unchanged  
✓ **Configuration-driven** – Disabled by default, opt-in to enable  

**Ready to use. Happy reporting!**
