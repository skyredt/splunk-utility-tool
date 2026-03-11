# Phase 2 Deployment Guide

## Scope

Phase 2 adds bounded post-dispatch verification so the tool no longer treats a slow status path as a hard failure. The deployment also includes deterministic config recovery and canonical INI formatting.

## Recommended Pilot Settings

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

## Config Loader Behavior

- `config.ini` must remain in the executable directory.
- If `config.ini` is missing and `config.ini.example` exists, the tool recreates `config.ini` automatically from the template.
- If `config.ini` is readable but not in canonical layout, the tool rewrites it and saves `config.ini.bak`.
- Hardening checks run only after config parsing succeeds, so formatting recovery is not treated as a policy downgrade.

## Status Model

- `OK`: explicit success confirmed
- `FAILED`: explicit Splunk failure confirmed
- `PENDING`: SID exists but verification is not yet confirmed

Pending slices do not block later slices. One bounded reconciliation pass runs after submission. Unresolved slices remain `PENDING`.

## Acknowledgement Handling

- `ack_enabled = 0` is the pilot default.
- If ACK is enabled later, the tool still skips acknowledgement when pending slices exist unless `ack_on_pending = 1`.
- Pending slices are never counted as failures in the final summary or ACK body.

## Deployment Checks

1. Confirm `config.ini.example` matches the approved pilot settings.
2. Launch the tool once in the target environment and verify `config.ini` is created or repaired cleanly.
3. If `config.ini.bak` appears, compare it with the repaired file and keep only the approved values.
4. Run the focused regression tests:
   - `python -m unittest test_config_runtime_behavior.py`
   - `python -m unittest test_dispatch_timeout_behavior.py`
5. Verify the UI opens with the light theme and that dispatch summary counts separate `Succeeded`, `Failed`, and `Pending`.
