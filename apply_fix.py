from __future__ import annotations

import pathlib
import shutil
import sys

FILE_PATH = pathlib.Path("splunk_engine.py")


def fail(msg: str) -> None:
    print(f"ERROR: {msg}")
    sys.exit(1)


def main() -> None:
    if not FILE_PATH.exists():
        fail("splunk_engine.py not found in current folder.")

    original = FILE_PATH.read_text(encoding="utf-8")
    content = original

    if "def run_dispatch_single(" in content:
        fail("run_dispatch_single() already exists. Refusing to insert a duplicate.")

    required_markers = [
        "def run_dispatch_multi(",
        "report_logs = run_dispatch_single(",
        "def _append_log(",
    ]
    missing = [m for m in required_markers if m not in content]
    if missing:
        fail(f"Expected markers not found in splunk_engine.py: {missing}")

    if "\nimport time\n" not in content and not content.startswith("import time\n"):
        if "from datetime import datetime\n" in content:
            content = content.replace(
                "from datetime import datetime\n",
                "from datetime import datetime\nimport time\n",
                1,
            )
        else:
            content = "import time\n" + content

    new_func = '''

def run_dispatch_single(
    client: "SplunkClient",
    report_id_url: str,
    report_name: str,
    report_type: str = "",
    verification_mode: str = "",
    verification_source: str = "",
    classification_reason: str = "",
    frequency: str = "",
    start: datetime | None = None,
    end: datetime | None = None,
    no_change: bool = False,
    wait_seconds: int = 10,
    poll_interval: int = 2,
    log_callback: Optional[Callable[[str], None]] = None,
    sid_callback: Optional[Callable[[str, str], None]] = None,
    regen_context: Optional["RegenContext"] = None,
    continue_on_timeout: bool = True,
    timeout_status: str = "PENDING",
    max_slice_runtime_seconds: int = 0,
    resolved_window: Optional["ResolvedReportingWindow"] = None,
    batch_controller: Optional["DispatchBatchController"] = None,
    config: Optional["SplunkConfig"] = None,
) -> List[str]:
    logs: List[str] = []

    def _record_slice(
        slice_label: str,
        status: str,
        slice_index: int = 0,
        slice_total: int = 0,
        earliest: str = "",
        latest: str = "",
        sid: str = "",
        outcome_code: str = "DISPATCHED_PENDING",
        error: str = "",
    ) -> None:
        if regen_context is None:
            return
        try:
            regen_context.add_slice(
                report_name=report_name,
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                earliest=earliest,
                latest=latest,
                sid=sid,
                status=status,
                outcome_code=outcome_code,
                error=error,
                report_type=report_type,
                verification_mode=verification_mode,
                verification_source=verification_source,
                classification_reason=classification_reason,
                display_range=(resolved_window.display_range if resolved_window is not None else ""),
                time_source=(resolved_window.time_source if resolved_window is not None else ""),
            )
        except TypeError:
            # Backward-compatible fallback if add_slice does not accept the newer fields
            regen_context.add_slice(
                report_name=report_name,
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                earliest=earliest,
                latest=latest,
                sid=sid,
                status=status,
                outcome_code=outcome_code,
                error=error,
            )

    def _audit_slice_event(event: str, *, level: str = "INFO", **fields) -> None:
        if regen_context is None:
            return
        try:
            _audit_event(
                event,
                level=level,
                run_id=regen_context.run_id,
                report_name=report_name,
                report_type=report_type,
                verification_mode=verification_mode,
                verification_source=verification_source,
                classification_reason=classification_reason,
                **fields,
            )
        except Exception:
            pass

    if no_change:
        slice_label = "single run"
        _append_log(
            logs,
            f"Dispatching '{report_name}' with saved search time range...",
            log_callback,
        )
        _dispatch_slice_and_wait(
            logs,
            client=client,
            report_id_url=report_id_url,
            report_name=report_name,
            slice_label=slice_label,
            slice_index=1,
            slice_total=1,
            earliest_display=str(start),
            latest_display=str(end),
            dispatch_earliest=None,
            dispatch_latest=None,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            max_slice_runtime_seconds=max_slice_runtime_seconds,
            log_prefix="",
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=_record_slice,
            audit_slice_event=_audit_slice_event,
            report_type=report_type,
            verification_mode=verification_mode,
            verification_source=verification_source,
            classification_reason=classification_reason,
            resolved_window=resolved_window,
            config=config,
        )
        return logs

    starts, ends = build_slices(start, end, frequency)
    if len(starts) == 0:
        raise ValueError("Selected date range generates 0 slices/emails.")
    if len(starts) > 12:
        raise ValueError("Selected date range generates more than 12 slices/emails.")

    _append_log(
        logs,
        f"Dispatching '{report_name}' with {len(starts)} slice(s) ({frequency}) from {start} to {end}.",
        log_callback,
    )

    previous_sid = None
    slice_cooldown_seconds = 15
    previous_sid_poll_seconds = 5
    previous_sid_max_wait_loops = 60

    for i, (s, e) in enumerate(zip(starts, ends), start=1):
        if batch_controller and batch_controller.wait_if_paused():
            _append_log(logs, "Batch cancelled while paused.", log_callback)
            break

        if batch_controller and batch_controller.is_cancel_requested():
            _append_log(logs, "Batch cancellation requested.", log_callback)
            break

        if previous_sid:
            _append_log(
                logs,
                f"  Verifying previous job {previous_sid} is DONE before dispatching next slice...",
                log_callback,
            )

            for _ in range(previous_sid_max_wait_loops):
                if batch_controller and batch_controller.is_cancel_requested():
                    break
                try:
                    state, sys_content = client.get_job_status_snapshot(
                        previous_sid,
                        request_timeout_seconds=5,
                    )
                    dispatch_state = str(sys_content.get("dispatchState", "") or "").upper()
                    if dispatch_state == "DONE":
                        _append_log(
                            logs,
                            f"  Job {previous_sid} dispatchState is DONE.",
                            log_callback,
                        )
                        break
                    if sys_content.get("isFailed", False) or dispatch_state == "FAILED":
                        _append_log(
                            logs,
                            f"  Job {previous_sid} failed. Proceeding.",
                            log_callback,
                        )
                        break
                except Exception:
                    pass
                time.sleep(previous_sid_poll_seconds)

            if slice_cooldown_seconds > 0:
                _append_log(
                    logs,
                    f"  Cooling down for {slice_cooldown_seconds} seconds before next slice...",
                    log_callback,
                )
                time.sleep(slice_cooldown_seconds)

        slice_label = f"[{i}/{len(starts)}]"
        earliest = to_epoch(s)
        latest = to_epoch(e)

        _append_log(
            logs,
            f"  [{i}/{len(starts)}] Earliest: {s}, Latest: {e} - sending...",
            log_callback,
        )

        status, sid = _dispatch_slice_and_wait(
            logs,
            client=client,
            report_id_url=report_id_url,
            report_name=report_name,
            slice_label=slice_label,
            slice_index=i,
            slice_total=len(starts),
            earliest_display=str(s),
            latest_display=str(e),
            dispatch_earliest=earliest,
            dispatch_latest=latest,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            max_slice_runtime_seconds=max_slice_runtime_seconds,
            log_prefix=f"[{i}/{len(starts)}] ",
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=_record_slice,
            audit_slice_event=_audit_slice_event,
            report_type=report_type,
            verification_mode=verification_mode,
            verification_source=verification_source,
            classification_reason=classification_reason,
            resolved_window=resolved_window,
            config=config,
        )

        if sid:
            previous_sid = sid

        if _is_pending_status(status) and i < len(starts):
            if continue_on_timeout:
                _append_log(
                    logs,
                    (
                        f"  [{i}/{len(starts)}] Status not confirmed within {wait_seconds} seconds. "
                        "Continuing to next slice."
                    ),
                    log_callback,
                )
                _audit_slice_event(
                    "REPORT_BATCH_CONTINUE_AFTER_PENDING",
                    level="INFO",
                    slice_label=slice_label,
                    slice_index=i,
                    slice_total=len(starts),
                    sid=sid,
                    remaining_slices=len(starts) - i,
                )
                continue

            _append_log(
                logs,
                f"  [{i}/{len(starts)}] Halting remaining slices because continue_on_timeout=false.",
                log_callback,
            )
            _audit_slice_event(
                "REPORT_BATCH_STOPPED_AFTER_PENDING",
                level="WARN",
                slice_label=slice_label,
                slice_index=i,
                slice_total=len(starts),
                sid=sid,
                remaining_slices=len(starts) - i,
            )
            break

    return logs
'''

    anchor = "\ndef _append_log("
    if anchor not in content:
        fail("Could not find insertion anchor 'def _append_log('")

    content = content.replace(anchor, new_func + anchor, 1)

    backup_path = FILE_PATH.with_suffix(FILE_PATH.suffix + ".bak")
    shutil.copy2(FILE_PATH, backup_path)
    FILE_PATH.write_text(content, encoding="utf-8")

    print("SUCCESS: inserted run_dispatch_single() into splunk_engine.py")
    print(f"Backup created: {backup_path}")
    print("Next step: run 'python -m py_compile splunk_engine.py'")


if __name__ == "__main__":
    main()