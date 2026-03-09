# Quick Start: Post-Dispatch Verification (Phase 2)

## What's New

The Splunk Utility Tool now verifies that reports were **actually delivered**, not just dispatched.

**Before**: ✗ "Dispatch OK" assumed "email sent"  
**Now**: ✓ Searches Splunk logs for actual delivery evidence

## Configuration

### 1. Use the pilot config in config.ini

```ini
[dispatch]
per_slice_wait_seconds = 30
continue_on_timeout = true
timeout_result = pending

[email]
ack_enabled = 0
ack_on_pending = 0

[postdispatch]
merge_report_enabled = true
native_email_enabled = true
reconcile_pending = true
reconcile_wait_seconds = 60
poll_seconds = 5
lookback_seconds = 900
```

Pilot intent:
- wait up to 30 seconds per slice for active confirmation
- continue to the next slice if a SID is still unresolved
- run one bounded reconciliation pass after submission
- keep ACK email disabled by default during pilot

### 2. Verify Splunk Logs Exist

MergeReport users: Check for `mergeReport_alert.log`
```
index=_internal source=mergeReport_alert.log Action=*
```

Native email users: Check for sendemail entries
```
index=_internal source=python.log sendemail
```

## What You'll See

### During Report Sending

```
[PostDispatch] [MergeReport] (sid=1699999_ABC123) Sending email (smtp=mail.company.com:587)
[PostDispatch] [MergeReport] (sid=1699999_ABC123) SUCCESS: Email sent
[PostDispatch] [NativeEmail] (sid=1700000_XYZ789) sendemail invoked (to=admin@company.com)
```

### After Dispatch Completes

```
=== Post-Dispatch Verification Summary ===
Dispatch OK: 10
Verified Sent: 8
Failed: 1
Pending: 1
```

## Success Rules

### MergeReport (Strict)
✅ **SUCCESS**: Log contains `Action=Email sent` with valid SMTP server  
❌ **FAILED**: `SmtpServer=""` or ERROR/Traceback in logs  
⏳ **PENDING**: No activity yet confirmed within the active wait window

### Native Email (Best-Effort)
✅ **SUCCESS**: `Sending email.` found in python.log + no errors  
❌ **FAILED**: SMTPException, connection error, authentication failed  
⏳ **PENDING**: No invocation yet confirmed within the active wait window

## Troubleshooting

### No [PostDispatch] lines appear
1. Check config.ini has `[postdispatch]` section
2. Verify Splunk logs contain expected keywords:
   - MergeReport: `index=_internal source=mergeReport_alert.log`
   - Native: `index=_internal source=python.log sendemail`
3. Check Splunk connectivity (connection test should work)

### All reports show "Pending"
1. Increase `lookback_seconds` in config (logs may be delayed)
2. Verify reports actually used MergeReport or sendemail action
3. Check Splunk log format matches expected patterns

### Performance slow
1. Increase `poll_seconds` (search less frequently)
2. Decrease `lookback_seconds` (search smaller window)
3. Disable one channel if not needed

## Configuration Options

| Setting | Default | What It Does |
|---------|---------|--------------|
| `merge_report_enabled` | true | Monitor MergeReport log |
| `native_email_enabled` | true | Monitor sendemail action |
| `poll_seconds` | 5 | Check logs every N seconds |
| `lookback_seconds` | 900 | Search last N seconds of logs |
| `merge_report_timeout_seconds` | 120 | Give up after N seconds |
| `native_email_timeout_seconds` | 120 | Give up after N seconds |
| `native_email_strict_success` | false | Require explicit success marker (rare) |
| `per_slice_wait_seconds` | 30 | Active wait budget before moving to next slice |
| `reconcile_wait_seconds` | 60 | Bounded pending reconciliation window after submission |
| `ack_enabled` | 0 | Pilot default: do not send ACK email |

## Examples

### MergeReport Only
```ini
[postdispatch]
merge_report_enabled = true
native_email_enabled = false
```

### Native Email Only
```ini
[postdispatch]
merge_report_enabled = false
native_email_enabled = true
```

### Both (Recommended)
```ini
[dispatch]
per_slice_wait_seconds = 30
continue_on_timeout = true
timeout_result = pending

[email]
ack_enabled = 0
ack_on_pending = 0

[postdispatch]
merge_report_enabled = true
native_email_enabled = true
native_email_strict_success = false
reconcile_pending = true
reconcile_wait_seconds = 60
poll_seconds = 5
lookback_seconds = 900
```

### Fast Polling (More Load)
```ini
poll_seconds = 1
lookback_seconds = 60
```

### Slow Polling (Less Load)
```ini
poll_seconds = 5
lookback_seconds = 600
```

## Log Examples

### MergeReport SUCCESS
```
Timestamp: 2024-01-15 14:23:45
SID=1699999999_ABC123
Action=Email sent
SmtpServer=mail.company.com
SmtpPort=587
To=admin@company.com
```

→ **Result**: ✅ SUCCESS: Email sent

### MergeReport FAILED (Misconfigured)
```
Timestamp: 2024-01-15 14:24:00
SID=1700000000_XYZ789
Action=Sending email
SmtpServer=""
SmtpPort=""
```

→ **Result**: ❌ FAILED: SmtpServer empty

### Native Email SUCCESS
```
2024-01-15 14:25:30 - sendemail: Sending email. sid=1700001111_DEF456
2024-01-15 14:25:31 - Email sent to: admin@company.com
```

→ **Result**: ✅ SUCCESS: Email action invoked

### Native Email FAILED (SMTP Error)
```
2024-01-15 14:26:00 - sendemail: Sending email. sid=1700002222_GHI789
2024-01-15 14:26:01 - SMTPException: Connection refused (mail.company.com:587)
```

→ **Result**: ❌ FAILED: SMTPException

## FAQ

**Q: Why does my report show "Pending" status?**  
A: The tool received a SID but did not get active confirmation within 30 seconds. Check:
1. Report actually used MergeReport or native email
2. Splunk logs haven't been purged
3. Increase lookback_seconds if logs are delayed
4. Remember the batch continues and Splunk may still complete the job asynchronously

**Q: Does this verify email was actually read?**  
A: No, only that the send action was invoked. Delivery confirmation depends on your mail server.

**Q: Can I use without Splunk logs?**  
A: No, this feature requires Splunk _internal logs with MergeReport or sendemail activity.

**Q: Is this required?**  
A: No, it's optional. Tool works without [postdispatch] section (reverts to Phase 1 behavior).

**Q: Does it block later slices?**  
A: No. After the 30-second active wait budget expires, the tool continues to the next slice and reconciles pending ones once more afterward.

**Q: Can I customize the search?**  
A: Currently searches are fixed. Future versions may support custom search queries.

## Support

For issues:
1. Check config.ini syntax
2. Verify Splunk logs exist with expected keywords
3. Review tool log output for [PostDispatch] error messages
4. Check Splunk server connectivity

See `PHASE_2_DEPLOYMENT.md` for detailed documentation.
