from __future__ import annotations
from typing import List, Optional, Callable, Any
from datetime import datetime
import time

DEFAULT_BACKEND_HEALTH_TIMEOUT_SECONDS = 15

def run_dispatch_multi(
    client: "SplunkClient",
    report_ids: List[str],
    report_names: List[str],
    selected_indices: List[int],
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
    wait_seconds: int = 10,
    poll_interval: int = 2,
    log_callback: Optional[Callable[[str], None]] = None,
    sid_callback: Optional[Callable[[str, str], None]] = None,
    config: Optional["SplunkConfig"] = None,
    app: str = "",
    report_namespace_meta: Optional[List[dict[str, str]]] = None,
    resolved_windows: Optional[dict[str, ResolvedReportingWindow]] = None,
    batch_controller: Optional[DispatchBatchController] = None,
) -> List[str]:
    try:
        logs: List[str] = []
        if not selected_indices:
            raise ValueError("No reports selected.")
        selected_report_names = [report_names[i] for i in selected_indices]
        start_time_sgt = get_sgt_now()
        range_display = f"{start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%Y-%m-%d %H:%M:%S')}"
        time_source = "manual"
        if no_change:
            slices_per_report = 1
            mode_description = "single run"
            time_source = "savedsearch"
            range_display = "Per-report saved-search-defined range (resolved lazily at dispatch time)"
        else:
            starts, _ = build_slices(start, end, frequency)
            slices_per_report = len(starts)
            mode_description = f"{frequency.lower()} slices: {slices_per_report}"
        regen_context = RegenContext(
            run_id=f"regen-{start_time_sgt.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}",
            report_names=selected_report_names,
            app=app,
            operator=get_effective_username(),
            hostname=socket.gethostname(),
            tool_name=TOOL_DISPLAY_NAME,
            start_time_sgt=start_time_sgt,
            end_time_sgt=None,
            slicing_enabled=not no_change,
            slice_count=max(0, slices_per_report * len(selected_indices)),
            frequency=frequency,
            earliest_configured=start.strftime("%Y-%m-%d %H:%M:%S"),
            latest_configured=end.strftime("%Y-%m-%d %H:%M:%S"),
            mode_description=mode_description,
            range_display=range_display,
            time_source=time_source,
            ack_attach_manifest=(config.ack_attach_manifest if config else False),
        )

        def _emit_batch_lifecycle_event(event: str, *, level: str = "INFO", **fields: Any) -> None:
            ok_count, fail_count, pending_count = regen_context.summary_counts()
            cancelled_count = regen_context.cancelled_count()
            payload = {
                "run_id": regen_context.run_id,
                "report_name": ",".join(regen_context.report_names),
                "batch_total_slices": len(regen_context.slices),
                "slice_succeeded": ok_count,
                "slice_failed": fail_count,
                "slice_pending": pending_count,
                "slice_cancelled": cancelled_count,
            }
            payload.update(fields)
            try:
                tool_runtime_log(_structured_log_line(event, **payload), level=level)
            except Exception:
                pass
            if tool_debug_category_enabled("dispatch"):
                tool_debug_event(event, category="dispatch", level=level, **payload)

        def _emit_classification_event(event: str, *, level: str = "INFO", **fields: Any) -> None:
            payload = {"run_id": regen_context.run_id}
            payload.update(fields)
            try:
                tool_runtime_log(_structured_log_line(event, **payload), level=level)
            except Exception:
                pass
            if tool_debug_category_enabled("dispatch"):
                tool_debug_event(event, category="dispatch", level=level, **payload)

        splunk_username = str(getattr(client, "username", "") or "").strip()

        report_meta: dict[str, Optional[dict]] = {}
        report_entries: dict[str, Optional[dict]] = {}
        report_metadata_paths: dict[str, str] = {}
        report_resolved_namespace: dict[str, dict[str, str]] = {}
        report_classification: dict[str, ReportClassificationDecision] = {}
        report_classification_errors: dict[str, str] = {}
        report_windows: dict[str, ResolvedReportingWindow] = dict(resolved_windows or {})
        collected: List[str] = []
        dispatch_anchor_epoch = int(datetime.now(timezone.utc).timestamp())
        for i in selected_indices:
            report_id_url = report_ids[i]
            report_name = report_names[i]
            namespace_meta = {}
            if isinstance(report_namespace_meta, list) and i < len(report_namespace_meta):
                candidate_meta = report_namespace_meta[i]
                if isinstance(candidate_meta, dict):
                    namespace_meta = dict(candidate_meta)
            normalized_namespace = _normalize_saved_search_namespace(
                report_id_url=report_id_url,
                report_name=report_name,
                app=app,
                username=splunk_username,
                namespace_meta=namespace_meta,
            )
            try:
                content, path, entry, namespace_used = _fetch_saved_search_entry(
                    client=client,
                    report_id_url=report_id_url,
                    report_name=report_name,
                    app=app,
                    username=splunk_username,
                    namespace_meta=namespace_meta,
                    raise_last_error=True,
                )
                resolved_namespace = dict(namespace_used or normalized_namespace)
                report_meta[report_name] = content
                report_entries[report_name] = entry if isinstance(entry, dict) else None
                report_metadata_paths[report_name] = str(path or "")
                report_resolved_namespace[report_name] = resolved_namespace
                if content:
                    collected.extend(_extract_recipients_from_content(content))
                decision = _resolve_report_classification(
                    report_name=report_name,
                    content=content,
                    entry=entry if isinstance(entry, dict) else None,
                    metadata_path=str(path or ""),
                    namespace_used=resolved_namespace,
                    config=config,
                )
                report_classification[report_name] = decision
                _emit_classification_event(
                    "REPORT_CLASSIFICATION_EVALUATED",
                    level="INFO",
                    report_name=report_name,
                    app=str(resolved_namespace.get("app", "") or app or ""),
                    owner=str(resolved_namespace.get("owner", "") or ""),
                    sharing=str(resolved_namespace.get("sharing", "") or ""),
                    namespace_used=resolved_namespace,
                    metadata_path=decision.metadata_path,
                    content_present=decision.content_present,
                    action_inputs_used=decision.action_inputs,
                    merge_markers_found=decision.action_inputs.get("merge_markers_found", []),
                    native_markers_found=decision.action_inputs.get("native_markers_found", []),
                    final_classification=decision.report_type,
                    verification_mode=decision.verification_mode,
                    verification_source=decision.verification_source,
                    classification_reason=decision.classification_reason,
                    rejected_alternatives=decision.rejected_alternatives,
                )
            except Exception as exc:
                error_text = redact_text(str(exc))
                report_meta[report_name] = None
                report_entries[report_name] = None
                report_metadata_paths[report_name] = ""
                report_resolved_namespace[report_name] = dict(normalized_namespace)
                report_classification_errors[report_name] = error_text
                _emit_classification_event(
                    "REPORT_CLASSIFICATION_FAILED",
                    level="WARN",
                    report_name=report_name,
                    app=str(normalized_namespace.get("app", "") or app or ""),
                    owner=str(normalized_namespace.get("owner", "") or ""),
                    sharing=str(normalized_namespace.get("sharing", "") or ""),
                    namespace_used=normalized_namespace,
                    metadata_path="",
                    failure_stage="post_namespace_resolution",
                    error=error_text,
                )
            if (not no_change) and report_name not in report_windows:
                report_windows[report_name] = build_manual_reporting_window(report_name, start, end)
        regen_context.savedsearch_recipients = _dedupe_keep_order(collected)
        if no_change:
            _refresh_savedsearch_regen_context(
                regen_context,
                report_windows,
                selected_report_count=len(selected_indices),
            )
        _audit_event(
            "REPORT_DISPATCH_REQUESTED",
            level="INFO",
            run_id=regen_context.run_id,
            app=app,
            report_names=selected_report_names,
            slicing_mode=mode_description,
            earliest=regen_context.earliest_configured,
            latest=regen_context.latest_configured,
            range_display=regen_context.range_display,
            time_source=regen_context.time_source,
            report_count=len(selected_indices),
        )
        if regen_context.savedsearch_recipients:
            _append_log(
                logs,
                (
                    "[ACK] Saved-search recipients discovered via REST: "
                    f"{len(regen_context.savedsearch_recipients)} recipient(s)."
                ),
                log_callback,
            )
        else:
            _append_log(
                logs,
                "[ACK] No saved-search recipients discovered via REST.",
                log_callback,
            )
        _append_log(
            logs,
            (
                f"Starting dispatch for {len(selected_indices)} report(s) - "
                f"frequency={frequency}, range={regen_context.range_display or (str(start) + ' -> ' + str(end))}, no_change={no_change}"
            ),
            log_callback,
        )
        for idx_num, i in enumerate(selected_indices, start=1):
            if batch_controller and batch_controller.wait_if_paused():
                regen_context.batch_cancelled = True
                regen_context.cancellation_reason = "User cancelled the batch."
                break
            if batch_controller and batch_controller.is_cancel_requested():
                regen_context.batch_cancelled = True
                regen_context.cancellation_reason = "User cancelled the batch."
                break
            report_id_url = report_ids[i]
            report_name = report_names[i]
            namespace_meta = {}
            if isinstance(report_namespace_meta, list) and i < len(report_namespace_meta):
                candidate_meta = report_namespace_meta[i]
                if isinstance(candidate_meta, dict):
                    namespace_meta = dict(candidate_meta)
            content = report_meta.get(report_name)
            entry = report_entries.get(report_name)
            classification_error = str(report_classification_errors.get(report_name, "") or "").strip()
            classification_decision = report_classification.get(report_name)
            resolved_window = report_windows.get(report_name)
            if classification_error or classification_decision is None:
                error_message = (
                    f"Report classification failed for '{report_name}': "
                    f"{classification_error or 'deterministic classification could not be resolved.'}"
                )
                _append_log(logs, error_message, log_callback)
                regen_context.add_slice(
                    report_name=report_name,
                    slice_label="single run" if no_change else "",
                    slice_index=1 if no_change else 0,
                    slice_total=1 if no_change else 0,
                    status="FAILED",
                    outcome_code="REPORT_CLASSIFICATION_FAILED",
                    error=error_message,
                    report_type=REPORT_TYPE_UNKNOWN,
                    verification_mode=VERIFICATION_MODE_FALLBACK,
                    verification_source=VERIFICATION_SOURCE_FALLBACK,
                    classification_reason=classification_error or "deterministic_classification_unresolved",
                    display_range=resolved_window.display_range if resolved_window is not None else "",
                    time_source=resolved_window.time_source if resolved_window is not None else time_source,
                )
                continue
            if no_change and resolved_window is None:
                _append_log(
                    logs,
                    f"Lazy saved-search time-range resolution for '{report_name}'...",
                    log_callback,
                )
                try:
                    resolved_window = resolve_saved_search_reporting_window(
                        client,
                        report_id_url=report_id_url,
                        report_name=report_name,
                        app=app,
                        username=splunk_username,
                        dispatch_anchor_epoch=dispatch_anchor_epoch,
                        namespace_meta=namespace_meta,
                        config=config,
                        log_callback=log_callback,
                    )
                    report_windows[report_name] = resolved_window
                    _refresh_savedsearch_regen_context(
                        regen_context,
                        report_windows,
                        selected_report_count=len(selected_indices),
                    )
                except Exception as exc:
                    reason = redact_text(str(exc))
                    error_message = (
                        f"Saved-search time-range resolution failed for '{report_name}': {reason}"
                    )
                    _append_log(logs, error_message, log_callback)
                    _audit_event(
                        "SAVED_SEARCH_WINDOW_RESOLUTION_FAILED",
                        level="WARN",
                        run_id=regen_context.run_id,
                        report_name=report_name,
                        reason=reason,
                    )
                    regen_context.add_slice(
                        report_name=report_name,
                        slice_label="single run",
                        slice_index=1,
                        slice_total=1,
                        status="FAILED",
                        outcome_code="TIME_RANGE_RESOLUTION_FAILED",
                        error=error_message,
                        display_range="",
                        time_source="savedsearch",
                    )
                    continue
            report_type = classification_decision.report_type
            classification_reason = classification_decision.classification_reason
            verification_mode = classification_decision.verification_mode
            verification_source = classification_decision.verification_source
            verification_label = _verification_mode_label(report_type, verification_mode, config)
            _append_log(logs, "", log_callback)
            _append_log(
                logs,
                f"=== [{idx_num}/{len(selected_indices)}] {report_name} ===",
                log_callback,
            )
            if debug_logging_enabled(config) and log_callback:
                namespace_used = classification_decision.namespace_used or report_resolved_namespace.get(report_name, {})
                _append_log(
                    logs,
                    "[Debug] Classification inputs: "
                    f"app='{namespace_used.get('app') or app or '-'}', "
                    f"owner='{namespace_used.get('owner') or '-'}', "
                    f"sharing='{namespace_used.get('sharing') or '-'}', "
                    f"metadata_path='{classification_decision.metadata_path or report_metadata_paths.get(report_name, '') or '-'}', "
                    f"merge_markers={classification_decision.action_inputs.get('merge_markers_found', [])}, "
                    f"native_markers={classification_decision.action_inputs.get('native_markers_found', [])}, "
                    f"rejected={classification_decision.rejected_alternatives}",
                    log_callback,
                )
            _append_log(
                logs,
                f"Verification mode: {verification_label}",
                log_callback,
            )
            _append_log(
                logs,
                f"Report classification: {report_type}",
                log_callback,
            )
            if resolved_window is not None:
                _append_log(
                    logs,
                    f"Resolved reporting window: {resolved_window.display_range}",
                    log_callback,
                )
            if verification_mode == VERIFICATION_MODE_MERGEREPORT:
                _append_log(
                    logs,
                    "Verification source: mergeReport_alert.log",
                    log_callback,
                )
            elif verification_mode == VERIFICATION_MODE_NATIVE:
                _append_log(
                    logs,
                    "Verification source: python.log",
                    log_callback,
                )
            else:
                _append_log(
                    logs,
                    "Verification source: fallback (status-only)",
                    log_callback,
                )
            if _should_warn_missing_addinfo(report_type, content):
                _append_log(
                    logs,
                    (
                        "WARNING: MergeReport searches typically require '| addinfo'. "
                        "Verify the saved search includes it."
                    ),
                    log_callback,
                )
                _audit_event(
                    "REPORT_MERGEREPORT_ADDINFO_MISSING",
                    level="WARN",
                    run_id=regen_context.run_id,
                    report_name=report_name,
                    report_type=report_type,
                )
            _audit_event(
                "REPORT_CLASSIFIED",
                level="INFO",
                run_id=regen_context.run_id,
                report_name=report_name,
                report_type=report_type,
                verification_mode=verification_mode,
                verification_source=verification_source,
                classification_reason=classification_reason,
            )
            report_logs = run_dispatch_single(
                client,
                report_id_url=report_id_url,
                report_name=report_name,
                report_type=report_type,
                verification_mode=verification_mode,
                verification_source=verification_source,
                classification_reason=classification_reason,
                frequency=frequency,
                start=start,
                end=end,
                no_change=no_change,
                wait_seconds=wait_seconds,
                poll_interval=poll_interval,
                log_callback=log_callback,
                sid_callback=sid_callback,
                regen_context=regen_context,
                continue_on_timeout=resolve_continue_on_timeout(config),
                timeout_status=resolve_timeout_result(config),
                max_slice_runtime_seconds=resolve_max_slice_runtime_seconds(config),
                resolved_window=resolved_window,
                batch_controller=batch_controller,
                config=config,
            )
            logs.extend(report_logs)
            if batch_controller and batch_controller.is_cancel_requested():
                regen_context.batch_cancelled = True
                regen_context.cancellation_reason = "User cancelled the batch."
                break
                
        if (
            (not regen_context.batch_cancelled)
            and _pending_slice_records(regen_context)
            and resolve_reconcile_pending(config)
        ):
            reconcile_logs = _reconcile_pending_slices(
                client,
                regen_context,
                wait_seconds=resolve_reconcile_wait_seconds(config),
                poll_interval=resolve_status_check_poll_seconds(config),
                config=config,
                log_callback=log_callback,
                batch_controller=batch_controller,
            )
            logs.extend(reconcile_logs)
        if (not regen_context.batch_cancelled) and _pending_slice_records(regen_context):
            postdispatch_logs = _verify_postdispatch_slices(
                client,
                regen_context,
                config=config,
                log_callback=log_callback,
                batch_controller=batch_controller,
            )
            logs.extend(postdispatch_logs)
    finally:
        _emit_batch_lifecycle_event("BATCH_COMPLETED", batch_cancelled=regen_context.batch_cancelled, cancellation_reason=regen_context.cancellation_reason)
        _send_ack_if_needed(config, regen_context, log_callback, logs)

    return logs


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

def _append_log(
    logs: List[str],
    line: str,
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    logs.append(line)
    if log_callback:
        log_callback(line)