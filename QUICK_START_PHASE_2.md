# Quick Start: Post-Dispatch Verification

## What Changed

- Each slice gets up to 30 seconds of active verification.
- If a slice has a SID but is still unresolved after that budget, the tool marks it `PENDING` and continues to the next slice.
- `FAILED` now means explicit failure, not just timeout.
- A bounded reconciliation pass re-checks pending slices after submission.
- Acknowledgement email is enabled by default.

## Config Recovery

- `config.ini` is loaded from the executable directory only.
- If `config.ini` is missing, the tool recreates it from `config.ini.example` when the template is present.
- If formatting is valid but inconsistent, the tool rewrites it into canonical INI layout and keeps `config.ini.bak`.
- If formatting is malformed, startup stops with a line-aware configuration error.

## Production Values You Must Set Manually

- `config.ini` is environment-specific and must not be committed to source control.
- REQUIRED: `[splunk] host` and `[splunk] servers` (HTTPS management endpoint allowlist).
- REQUIRED: `[Credentials] username`, `secret_file`, and `dpapi_scope`.
- REQUIRED: `[splunk] verify_ssl` decision (keep `true` unless you must trust self-signed certs).
- REQUIRED: `[email] smtp_host` and `from_addr` (plus `smtp_user`/`smtp_pass` if relay requires auth).
- REQUIRED: `[email] ack_recipients` if `ack_use_savedsearch_recipients = 0`.
- OPTIONAL: `[postdispatch] merge_report_log_path` if enabling file-based MergeReport monitoring; must be the full log file path, not just the directory.

## Pilot Config

```ini
[dispatch]
per_slice_wait_seconds = 30
continue_on_timeout = true
timeout_result = pending

[email]
ack_enabled = 1
ack_on_pending = 0

[postdispatch]
merge_report_enabled = true
native_email_enabled = true
reconcile_pending = true
reconcile_wait_seconds = 60
poll_seconds = 5
lookback_seconds = 900
```

## Operator Expectations

- `OK`: Splunk explicitly confirmed success.
- `FAILED`: Splunk explicitly reported failure.
- `PENDING`: The slice has a SID, but verification was not completed within the active wait or reconciliation window.

## Troubleshooting

1. If startup reports a configuration error, review the line number in the message and compare `config.ini` with `config.ini.bak`.
2. If `config.ini` was recreated, verify environment-specific values such as hostnames and usernames before dispatching.
3. If slices remain `PENDING`, check `_internal` logs and increase `lookback_seconds` only when log delay requires it.
4. If no post-dispatch messages appear, confirm `[postdispatch]` exists and that Splunk logs contain the expected MergeReport or sendemail events.
