from __future__ import annotations

import json
import os
import queue
import tempfile
import threading
import unittest
from datetime import datetime
from unittest.mock import patch

import splunk_engine
import splunk_report_tk
from Internal import splunk_broker as splunk_broker_module
from Internal.tool_logging import configure_tool_logging, shutdown_tool_logging
from splunk_engine import (
    RegenContext,
    ReportClassificationResolutionError,
    SplunkConfig,
    REPORT_TYPE_MERGEREPORT,
    REPORT_TYPE_NATIVE,
    VERIFICATION_MODE_FALLBACK,
    VERIFICATION_MODE_MERGEREPORT,
    VERIFICATION_MODE_NATIVE,
    VERIFICATION_SOURCE_FALLBACK,
    VERIFICATION_SOURCE_MERGEREPORT,
    VERIFICATION_SOURCE_NATIVE,
    build_manual_reporting_window,
    _build_run_summary_lines,
    _classify_report_type,
    _classify_report_type_with_fallback,
    _resolve_report_classification,
    _verify_postdispatch_slices,
    _reconcile_pending_slices,
    _resolve_verification_mode,
    _parse_postdispatch_results,
    _update_merge_report_evidence,
    _merge_report_evidence_state,
    _should_warn_missing_addinfo,
    resolve_saved_search_reporting_window,
    resolve_broker_request_timeout_seconds,
    resolve_max_slice_runtime_seconds,
    resolve_status_check_poll_seconds,
    resolve_status_check_timeout_seconds,
    run_dispatch_single,
    send_ack_summary_email,
    _MergeReportEvidence,
)


class _NullSignal:
    def emit(self, *args, **kwargs) -> None:
        return


class FakeClient:
    def __init__(self, dispatch_results, status_results=None, snapshot_results=None):
        self.dispatch_results = list(dispatch_results)
        self.status_results = list(status_results or [])
        self.snapshot_results = list(snapshot_results or [])
        self.dispatch_log = _NullSignal()
        self.error = _NullSignal()
        self.finished = _NullSignal()
        self.username = "splunk_service"

    def dispatch_saved_search(self, *args, **kwargs):
        return self.dispatch_results.pop(0)

    def check_job_status(self, *args, **kwargs):
        result = self.status_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def get_job_status_snapshot(self, *args, **kwargs):
        result = self.snapshot_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def _get(self, path: str):
        del path
        return {}


class DummySMTP:
    instances = []

    def __init__(self, host: str, port: int, timeout: int):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sent_messages = []
        self.tls_started = False
        self.login_args = None
        DummySMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def starttls(self) -> None:
        self.tls_started = True

    def login(self, user: str, password: str) -> None:
        self.login_args = (user, password)

    def send_message(self, message) -> None:
        self.sent_messages.append(message)


class FakePolicy:
    def __init__(self, config_path: str):
        self.config_path = config_path

    def config_in_exe_dir(self, requested_path: str) -> bool:
        return os.path.abspath(requested_path) == os.path.abspath(self.config_path)

    def enforce_https_url(self, server: str) -> str:
        return server

    def validate_secret_filename(self, secret_file: str) -> str:
        return secret_file

    def enforce_audit_settings(self, level: str, max_bytes: int, backup_count: int):
        return level, max_bytes, backup_count

    def env_overrides_allowed(self) -> bool:
        return False


class DummyAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def log_event(self, event: str, level: str = "INFO", **fields) -> None:
        self.events.append(
            {
                "event": event,
                "level": level,
                "fields": fields,
            }
        )


def _start_test_broker(
    fake_client,
    *,
    username: str = "splunk_service",
) -> tuple[
    splunk_broker_module.SplunkBrokerProxyClient,
    DummyAudit,
    splunk_broker_module._SplunkBrokerHTTPServer,
    threading.Thread,
]:
    audit = DummyAudit()
    state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
    state.audit = audit
    state.client_lifecycle_lock = threading.Lock()
    state.client = fake_client
    state.cfg = None
    state.connected_server = "https://127.0.0.1:8089"
    state.config_error = ""
    state.last_successful_heartbeat_utc = ""
    state.last_health_error = ""
    token = "unit-test-token"
    server = splunk_broker_module._SplunkBrokerHTTPServer(state=state, auth_token=token)
    thread = threading.Thread(target=server.serve_forever, name="TestSplunkBrokerServer", daemon=True)
    thread.start()
    proxy = splunk_broker_module.SplunkBrokerProxyClient(
        host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
        port=server.server_port,
        auth_token=token,
        username=username,
    )
    return proxy, audit, server, thread


class DispatchTimeoutBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        DummySMTP.instances.clear()

    def _make_context(self) -> RegenContext:
        return RegenContext(
            run_id="regen-test-001",
            report_names=["Daily KPI"],
            app="search",
            operator="tester",
            hostname="host1",
            start_time_sgt=datetime(2026, 3, 10, 9, 0, 0),
            end_time_sgt=datetime(2026, 3, 10, 9, 5, 0),
            slicing_enabled=True,
            earliest_configured="2026-03-01 00:00:00",
            latest_configured="2026-03-05 00:00:00",
            mode_description="daily slices: 5",
        )

    def _resolved_window(self) -> object:
        return build_manual_reporting_window(
            "Daily KPI",
            datetime(2026, 3, 1, 0, 0, 0),
            datetime(2026, 3, 2, 0, 0, 0),
        )

    def _make_config(self, **overrides) -> SplunkConfig:
        config = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            dispatch_config={
                "per_slice_wait_seconds": 30,
                "continue_on_timeout": True,
                "timeout_result": "pending",
            },
            ack_enabled=True,
            ack_on_pending=False,
            ack_on_unknown=False,
            ack_recipients=["ops@example.com"],
            postdispatch_config={
                "poll_seconds": 5,
                "broker_request_timeout_seconds": 300,
                "status_check_timeout_seconds": 300,
                "reconcile_pending": True,
                "reconcile_wait_seconds": 60,
            },
            diagnostics_config={
                "snapshot_probe_enabled": False,
            },
        )
        for key, value in overrides.items():
            setattr(config, key, value)
        return config

    def _write_merge_report_log(self, sid: str, *, include_success: bool = True) -> str:
        fd, path = tempfile.mkstemp(prefix="merge_report_", suffix=".log")
        os.close(fd)
        lines = [
            f"2026-03-14 03:07:28,041 INFO Search Name=[Splunk10] TestReport, SID={sid}, C:\\dispatch\\{sid}\\results.csv.gz",
            f"2026-03-14 03:07:28,049 INFO Search Name=[Splunk10] TestReport, SID={sid}, Report generates result from 2026-03-06 00:00:00 to 2026-03-11 00:00:00",
            f"2026-03-14 03:07:28,383 INFO Search Name=[Splunk10] TestReport, SID={sid}, Action=Xlsx file created, Size=7008",
            f"2026-03-14 03:07:28,412 INFO Search Name=[Splunk10] TestReport, SID={sid}, Action=Sending email, SmtpServer=127.0.0.1, SmtpPort=25",
        ]
        if include_success:
            lines.extend(
                [
                    f"2026-03-14 03:07:28,550 INFO Search Name=[Splunk10] TestReport, SID={sid}, Action=Email sent, Subject=Splunk Report",
                    f"2026-03-14 03:07:28,551 INFO Search Name=[Splunk10] TestReport, SID={sid}, App excution completed",
                ]
            )
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def _write_multi_slice_merge_report_log(self, entries: list[tuple[str, str, str]]) -> str:
        fd, path = tempfile.mkstemp(prefix="merge_report_multi_", suffix=".log")
        os.close(fd)
        lines: list[str] = []
        for sid, earliest, latest in entries:
            end_date = latest.split(" ", 1)[0]
            start_date = earliest.split(" ", 1)[0]
            lines.extend(
                [
                    f"2026-03-14 13:06:52,535 INFO Search Name=[Splunk10] TestReport, SID={sid}, C:\\dispatch\\{sid}\\results.csv.gz",
                    f"2026-03-14 13:06:52,547 INFO Search Name=[Splunk10] TestReport, SID={sid}, Report generates result from {earliest} to {latest}",
                    f"2026-03-14 13:06:53,038 INFO Search Name=[Splunk10] TestReport, SID={sid}, Action=Xlsx file created, Size=6984",
                    f"2026-03-14 13:06:53,073 INFO Search Name=[Splunk10] TestReport, SID={sid}, Action=Sending email, SmtpServer=127.0.0.1, SmtpPort=25",
                    f"2026-03-14 13:06:53,219 INFO Search Name=[Splunk10] TestReport, SID={sid}, Action=Email sent, Subject=Splunk Report: [Splunk10] TestReport {start_date} - {end_date}",
                    f"2026-03-14 13:06:53,221 INFO Search Name=[Splunk10] TestReport, SID={sid}, App excution completed",
                ]
            )
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_dispatch_with_sid_and_status_timeout_becomes_pending_after_budget_exhausted(self) -> None:
        context = self._make_context()
        class AlwaysTimeoutClient(FakeClient):
            def __init__(self):
                super().__init__(dispatch_results=[(True, "1700000_ABC123", "")])
                self.snapshot_calls = 0

            def get_job_status_snapshot(self, *args, **kwargs):
                self.snapshot_calls += 1
                raise RuntimeError(
                    "Local Splunk broker timed out while processing the request (op=get_job_status_snapshot, timeout=10s)."
                )

        client = AlwaysTimeoutClient()
        monotonic_tick = {"t": 0.0}

        def _slow_monotonic() -> float:
            monotonic_tick["t"] += 2.0
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slow_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                logs = run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 2, 0, 0, 0),
                    no_change=True,
                    wait_seconds=30,
                    poll_interval=5,
                    regen_context=context,
                    resolved_window=self._resolved_window(),
                )

        self.assertEqual(len(context.slices), 1)
        record = context.slices[0]
        self.assertEqual(record.status, "PENDING")
        self.assertEqual(record.outcome_code, "DISPATCHED_PENDING")
        self.assertEqual(record.sid, "1700000_ABC123")
        self.assertGreaterEqual(client.snapshot_calls, 2)
        self.assertIn("30 seconds", record.error)
        self.assertIn("timeout=10s", record.error)
        self.assertIn("PENDING (sid=1700000_ABC123)", "\n".join(logs))

    def test_dispatch_retries_transient_snapshot_timeout_then_returns_ok(self) -> None:
        context = self._make_context()

        class TransientTimeoutClient(FakeClient):
            def __init__(self):
                super().__init__(dispatch_results=[(True, "1700000_RETRY01", "")])
                self.snapshot_calls = 0

            def get_job_status_snapshot(self, *args, **kwargs):
                self.snapshot_calls += 1
                if self.snapshot_calls == 1:
                    raise RuntimeError(
                        "Local Splunk broker timed out while processing the request (op=get_job_status_snapshot, timeout=7s)."
                    )
                return ("SUCCESS", {"dispatchState": "DONE", "isDone": True})

        client = TransientTimeoutClient()
        monotonic_tick = {"t": 0.0}

        def _slow_monotonic() -> float:
            monotonic_tick["t"] += 0.4
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slow_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                logs = run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 2, 0, 0, 0),
                    no_change=True,
                    wait_seconds=30,
                    poll_interval=5,
                    regen_context=context,
                    resolved_window=self._resolved_window(),
                )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "SUCCESS")
        self.assertGreaterEqual(client.snapshot_calls, 2)
        joined = "\n".join(logs)
        self.assertIn("OK (sid=1700000_RETRY01)", joined)
        self.assertNotIn("PENDING (sid=1700000_RETRY01)", joined)

    def test_mergereport_prefers_file_evidence_before_snapshot_success(self) -> None:
        context = self._make_context()
        sid = "1700000_MRFILE01"
        log_path = self._write_merge_report_log(sid)

        class MergeReportClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[(True, sid, "")],
                    snapshot_results=[("RUNNING", {"dispatchState": "RUNNING", "isDone": False})],
                )
                self.export_calls = 0

            def export_search_json(self, *args, **kwargs):
                self.export_calls += 1
                raise AssertionError("mergeReport _internal fallback should not be used when file evidence is available")

        client = MergeReportClient()
        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 5,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )

        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            report_name="[Splunk10] TestReport",
            frequency="Daily",
            start=datetime(2026, 3, 6, 0, 0, 0),
            end=datetime(2026, 3, 11, 0, 0, 0),
            no_change=True,
            wait_seconds=30,
            poll_interval=5,
            regen_context=context,
            report_type=REPORT_TYPE_MERGEREPORT,
            verification_mode=VERIFICATION_MODE_MERGEREPORT,
            verification_source=VERIFICATION_SOURCE_MERGEREPORT,
            resolved_window=self._resolved_window(),
            config=config,
        )

        record = context.slices[0]
        self.assertEqual(record.status, "OK")
        self.assertEqual(record.outcome_code, "SUCCESS")
        self.assertEqual(record.sid, sid)
        self.assertEqual(record.verification_timeline.get("final_status_source"), "stage1_mergereport_file")
        self.assertTrue(str(record.verification_timeline.get("first_mergereport_evidence_time", "")).strip())
        self.assertEqual(client.export_calls, 0)
        joined = "\n".join(logs)
        self.assertIn("MergeReport confirmation found in mergeReport_alert.log", joined)
        self.assertNotIn("PENDING", joined)

    def test_mergereport_keeps_waiting_when_file_evidence_is_active_but_incomplete(self) -> None:
        context = self._make_context()
        sid = "1700000_MRFALLBACK"
        log_path = self._write_merge_report_log(sid, include_success=False)

        class MergeReportFallbackClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[(True, sid, "")],
                    snapshot_results=[
                        ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                        ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
                    ],
                )
                self.export_calls = 0

            def export_search_json(self, *args, **kwargs):
                self.export_calls += 1
                raise AssertionError("mergeReport _internal fallback should not be used when file path is configured")

        client = MergeReportFallbackClient()
        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )
        monotonic_tick = {"t": 0.0}

        def _fast_monotonic() -> float:
            monotonic_tick["t"] += 0.4
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _fast_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                logs = run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                    report_name="[Splunk10] TestReport",
                    frequency="Daily",
                    start=datetime(2026, 3, 6, 0, 0, 0),
                    end=datetime(2026, 3, 11, 0, 0, 0),
                    no_change=True,
                    wait_seconds=10,
                    poll_interval=2,
                    regen_context=context,
                    report_type=REPORT_TYPE_MERGEREPORT,
                    verification_mode=VERIFICATION_MODE_MERGEREPORT,
                    verification_source=VERIFICATION_SOURCE_MERGEREPORT,
                    resolved_window=self._resolved_window(),
                    config=config,
                )

        record = context.slices[0]
        self.assertEqual(record.status, "PENDING")
        self.assertEqual(client.export_calls, 0)
        self.assertIn(f"PENDING (sid={sid})", "\n".join(logs))

    def test_mergereport_explicit_snapshot_failure_still_fails_without_evidence(self) -> None:
        context = self._make_context()
        sid = "1700000_MRFAIL01"
        log_path = self._write_merge_report_log(sid, include_success=False)

        client = FakeClient(
            dispatch_results=[(True, sid, "")],
            snapshot_results=[("FAILED", {"dispatchState": "FAILED"})],
        )
        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )

        run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            report_name="[Splunk10] TestReport",
            frequency="Daily",
            start=datetime(2026, 3, 6, 0, 0, 0),
            end=datetime(2026, 3, 11, 0, 0, 0),
            no_change=True,
            wait_seconds=10,
            poll_interval=2,
            regen_context=context,
            report_type=REPORT_TYPE_MERGEREPORT,
            verification_mode=VERIFICATION_MODE_MERGEREPORT,
            verification_source=VERIFICATION_SOURCE_MERGEREPORT,
            resolved_window=self._resolved_window(),
            config=config,
        )

        record = context.slices[0]
        self.assertEqual(record.status, "FAILED")
        self.assertEqual(record.outcome_code, "VERIFIED_FAILED")
        self.assertEqual(record.verification_timeline.get("final_status_source"), "stage1_snapshot_failed")

    def test_mergereport_preferred_flow_emits_diagnostic_events(self) -> None:
        context = self._make_context()
        sid = "1700000_MRDIAG01"
        log_path = self._write_merge_report_log(sid)
        debug_events: list[tuple[str, dict[str, object]]] = []

        class MergeReportClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[(True, sid, "")],
                    snapshot_results=[("RUNNING", {"dispatchState": "RUNNING", "isDone": False})],
                )

        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 5,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )

        with patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, fields)) or True,
        ):
            run_dispatch_single(
                client=MergeReportClient(),
                report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                report_name="[Splunk10] TestReport",
                frequency="Daily",
                start=datetime(2026, 3, 6, 0, 0, 0),
                end=datetime(2026, 3, 11, 0, 0, 0),
                no_change=True,
                wait_seconds=30,
                poll_interval=5,
                regen_context=context,
                report_type=REPORT_TYPE_MERGEREPORT,
                verification_mode=VERIFICATION_MODE_MERGEREPORT,
                verification_source=VERIFICATION_SOURCE_MERGEREPORT,
                resolved_window=self._resolved_window(),
                config=config,
            )

        event_names = [name for name, _fields in debug_events]
        self.assertIn("MERGEREPORT_VERIFICATION_STARTED", event_names)
        self.assertIn("VERIFICATION_SOURCE_SELECTED", event_names)
        self.assertIn("MERGEREPORT_EVIDENCE_CHECK_REQUESTED", event_names)
        self.assertIn("MERGEREPORT_EVIDENCE_CHECK_COMPLETED", event_names)
        self.assertIn("MERGEREPORT_PREFERRED_SUCCESS", event_names)
        preferred_success = next(fields for name, fields in debug_events if name == "MERGEREPORT_PREFERRED_SUCCESS")
        self.assertEqual(preferred_success["evidence_source"], "merge_report_file")
        self.assertEqual(preferred_success["snapshot_role"], "health_check_only")
        self.assertFalse(preferred_success["sid_snapshot_final_confirmation"])

    def test_non_mergereport_reports_keep_snapshot_verification_behavior(self) -> None:
        context = self._make_context()
        sid = "1700000_NONMERGE"
        log_path = self._write_merge_report_log(sid)
        debug_events: list[tuple[str, dict[str, object]]] = []
        client = FakeClient(
            dispatch_results=[(True, sid, "")],
            snapshot_results=[("SUCCESS", {"dispatchState": "DONE", "isDone": True})],
        )
        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 5,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )

        with patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, fields)) or True,
        ):
            logs = run_dispatch_single(
                client=client,
                report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                report_name="Daily KPI",
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 2, 0, 0, 0),
                no_change=True,
                wait_seconds=10,
                poll_interval=2,
                regen_context=context,
                report_type=REPORT_TYPE_NATIVE,
                verification_mode=VERIFICATION_MODE_NATIVE,
                verification_source=VERIFICATION_SOURCE_NATIVE,
                resolved_window=self._resolved_window(),
                config=config,
            )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].verification_timeline.get("final_status_source"), "stage1_snapshot_active_wait")
        self.assertNotIn("MergeReport confirmation found", "\n".join(logs))
        self.assertNotIn("MERGEREPORT_VERIFICATION_STARTED", [name for name, _fields in debug_events])

    def test_dispatch_without_sid_is_failed(self) -> None:
        context = self._make_context()
        client = FakeClient(
            dispatch_results=[(True, None, "")],
        )

        run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            regen_context=context,
            resolved_window=self._resolved_window(),
        )

        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[0].outcome_code, "DISPATCH_FAILED")

    def test_explicit_failed_state_is_failed(self) -> None:
        context = self._make_context()
        client = FakeClient(
            dispatch_results=[(True, "1700000_DEF456", "")],
            snapshot_results=[("FAILED", {"dispatchState": "FAILED"})],
        )

        run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            regen_context=context,
            resolved_window=self._resolved_window(),
        )

        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[0].outcome_code, "VERIFIED_FAILED")
        self.assertEqual(context.slices[0].sid, "1700000_DEF456")

    def test_one_pending_slice_does_not_block_next_slice(self) -> None:
        context = self._make_context()
        client = FakeClient(
            dispatch_results=[
                (True, "1700000_PEND01", ""),
                (True, "1700000_OK002", ""),
            ],
            snapshot_results=[
                ("RUNNING", {"dispatchState": "RUNNING"}),
                ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
            ],
        )

        monotonic_tick = {"t": 0.0}

        def _fast_monotonic() -> float:
            monotonic_tick["t"] += 0.6
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _fast_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                logs = run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 3, 0, 0, 0),
                    no_change=False,
                    wait_seconds=5,
                    regen_context=context,
                )

        self.assertEqual(len(context.slices), 2)
        self.assertEqual(context.slices[0].status, "PENDING")
        self.assertEqual(context.slices[1].status, "OK")
        self.assertEqual(context.slices[1].sid, "1700000_OK002")
        self.assertIn("Continuing to next slice.", "\n".join(logs))

    def test_status_check_uses_bounded_snapshot_polls(self) -> None:
        context = self._make_context()

        class RecordingClient(FakeClient):
            def __init__(self):
                super().__init__(dispatch_results=[(True, "1700000_RUN01", "")])
                self.snapshot_calls = []

            def get_job_status_snapshot(self, *args, **kwargs):
                self.snapshot_calls.append(
                    (
                        kwargs.get("request_timeout_seconds"),
                        kwargs.get("max_total_timeout_seconds"),
                    )
                )
                return ("RUNNING", {"dispatchState": "RUNNING"})

        client = RecordingClient()
        monotonic_tick = {"t": 0.0}

        def _slow_monotonic() -> float:
            monotonic_tick["t"] += 0.2
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slow_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 2, 0, 0, 0),
                    no_change=True,
                    wait_seconds=5,
                    poll_interval=2,
                    regen_context=context,
                    resolved_window=self._resolved_window(),
                )

        self.assertGreaterEqual(len(client.snapshot_calls), 2)
        for request_timeout, max_total_timeout in client.snapshot_calls:
            self.assertLessEqual(float(request_timeout), 2.0)
            self.assertLessEqual(float(max_total_timeout), 5.0)

    def test_status_check_fallback_uses_short_check_job_status_calls(self) -> None:
        context = self._make_context()

        class FallbackClient:
            def __init__(self):
                self.dispatch_results = [(True, "1700000_RUN01", "")]
                self.check_calls = []
                self.dispatch_log = _NullSignal()
                self.error = _NullSignal()
                self.finished = _NullSignal()
                self.username = "splunk_service"

            def dispatch_saved_search(self, *args, **kwargs):
                return self.dispatch_results.pop(0)

            def check_job_status(self, *args, **kwargs):
                self.check_calls.append(
                    (kwargs.get("wait_seconds"), kwargs.get("poll_interval"))
                )
                return ("TIMEOUT", {"dispatchState": "RUNNING"})

            def _get(self, path: str):
                del path
                return {}

        client = FallbackClient()
        monotonic_tick = {"t": 0.0}

        def _slow_monotonic() -> float:
            monotonic_tick["t"] += 0.2
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slow_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 2, 0, 0, 0),
                    no_change=True,
                    wait_seconds=5,
                    poll_interval=2,
                    regen_context=context,
                    resolved_window=self._resolved_window(),
                )

        self.assertGreaterEqual(len(client.check_calls), 2)
        for wait_seconds, poll_interval in client.check_calls:
            self.assertLessEqual(int(wait_seconds or 0), 2)
            self.assertLessEqual(int(poll_interval or 0), 2)

    def test_slice_runtime_exceeded_cancels_job(self) -> None:
        context = self._make_context()

        class CancelClient(FakeClient):
            def __init__(self):
                super().__init__(
                    dispatch_results=[(True, "1700000_TIMEOUT", "")],
                    snapshot_results=[("RUNNING", {"dispatchState": "RUNNING"})],
                )
                self.cancel_calls = []

            def cancel_search_job(self, sid: str) -> bool:
                self.cancel_calls.append(sid)
                return True

        client = CancelClient()
        monotonic_tick = {"t": 0.0}

        def _fast_monotonic() -> float:
            monotonic_tick["t"] += 2.0
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _fast_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 2, 0, 0, 0),
                    no_change=True,
                    wait_seconds=5,
                    poll_interval=1,
                    max_slice_runtime_seconds=1,
                    regen_context=context,
                    resolved_window=self._resolved_window(),
                )

        self.assertEqual(client.cancel_calls, ["1700000_TIMEOUT"])
        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[0].outcome_code, "RUNTIME_EXCEEDED")
        self.assertIn("slice runtime exceeded", context.slices[0].error.lower())

    def test_slice_completes_before_timeout_no_cancel(self) -> None:
        context = self._make_context()

        class CancelClient(FakeClient):
            def __init__(self):
                super().__init__(
                    dispatch_results=[(True, "1700000_OK", "")],
                    snapshot_results=[("SUCCESS", {"dispatchState": "DONE", "isDone": True})],
                )
                self.cancel_calls = []

            def cancel_search_job(self, sid: str) -> bool:
                self.cancel_calls.append(sid)
                return True

        client = CancelClient()
        monotonic_tick = {"t": 0.0}

        def _slow_monotonic() -> float:
            monotonic_tick["t"] += 0.2
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slow_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 2, 0, 0, 0),
                    no_change=True,
                    wait_seconds=5,
                    poll_interval=1,
                    max_slice_runtime_seconds=10,
                    regen_context=context,
                    resolved_window=self._resolved_window(),
                )

        self.assertEqual(client.cancel_calls, [])
        self.assertEqual(context.slices[0].status, "OK")

    def test_multi_slice_timeout_affects_only_one_slice(self) -> None:
        context = self._make_context()

        class MultiSliceClient(FakeClient):
            def __init__(self):
                super().__init__(
                    dispatch_results=[
                        (True, "1700000_SID1", ""),
                        (True, "1700000_SID2", ""),
                    ],
                    snapshot_results=[
                        ("RUNNING", {"dispatchState": "RUNNING"}),
                        ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
                    ],
                )
                self.cancel_calls = []
                self.slice_counter = 0

            def dispatch_saved_search(self, *args, **kwargs):
                self.slice_counter += 1
                return super().dispatch_saved_search(*args, **kwargs)

            def cancel_search_job(self, sid: str) -> bool:
                self.cancel_calls.append(sid)
                return True

        client = MultiSliceClient()
        monotonic_tick = {"t": 0.0}

        def _slice_sensitive_monotonic() -> float:
            if client.slice_counter == 1:
                monotonic_tick["t"] += 2.0
            else:
                monotonic_tick["t"] += 0.2
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slice_sensitive_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 3, 0, 0, 0),
                    no_change=False,
                    wait_seconds=5,
                    poll_interval=1,
                    max_slice_runtime_seconds=1,
                    regen_context=context,
                )

        self.assertEqual(client.cancel_calls, ["1700000_SID1"])
        self.assertEqual(len(context.slices), 2)
        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[1].status, "OK")

    def test_multi_slice_mergereport_run_advances_to_second_slice_and_emits_summary(self) -> None:
        sid1 = "1700000_MS01"
        sid2 = "1700000_MS02"
        log_path = self._write_multi_slice_merge_report_log(
            [
                (sid1, "2026-03-12 00:00:00", "2026-03-13 00:00:00"),
                (sid2, "2026-03-13 00:00:00", "2026-03-14 00:00:00"),
            ]
        )
        client = FakeClient(
            dispatch_results=[
                (True, sid1, ""),
                (True, sid2, ""),
            ],
            snapshot_results=[
                ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
            ],
        )
        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
                "enabled": False,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )
        runtime_events: list[str] = []
        debug_events: list[tuple[str, dict[str, object]]] = []
        saved_search_entry = {
            "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
            "content": {
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
        }

        with patch.object(
            splunk_engine,
            "tool_runtime_log",
            lambda message, level="INFO": runtime_events.append(f"{level}:{message}") or True,
        ), patch.object(
            splunk_engine,
            "tool_debug_category_enabled",
            lambda category: str(category).strip().lower() == "dispatch",
        ), patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, dict(fields))) or True,
        ), patch.object(
            splunk_engine,
            "_fetch_saved_search_entry",
            lambda *args, **kwargs: (
                dict(saved_search_entry["content"]),
                "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                dict(saved_search_entry),
                {"app": "search", "owner": "skyred5", "sharing": "user"},
            ),
        ):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport"],
                report_names=["[Splunk10] TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 12, 0, 0, 0),
                end=datetime(2026, 3, 14, 0, 0, 0),
                no_change=False,
                wait_seconds=10,
                poll_interval=1,
                config=config,
                app="search",
            )

        joined = "\n".join(logs)
        self.assertIn("[1/2] OK", joined)
        self.assertIn("[2/2] DISPATCHED", joined)
        self.assertIn("[2/2] OK", joined)
        self.assertIn("Summary:", joined)
        event_names = [name for name, _fields in debug_events]
        self.assertIn("SLICE_STARTED", event_names)
        self.assertIn("SLICE_DISPATCH_REQUESTED", event_names)
        self.assertIn("SLICE_DISPATCHED", event_names)
        self.assertIn("SLICE_COMPLETED", event_names)
        self.assertIn("BATCH_SLICE_ADVANCE", event_names)
        self.assertIn("BATCH_COMPLETED", event_names)
        self.assertIn("REPORT_CLASSIFICATION_EVALUATED", event_names)
        classification_fields = next(
            fields for name, fields in debug_events if name == "REPORT_CLASSIFICATION_EVALUATED"
        )
        self.assertEqual(classification_fields["final_classification"], REPORT_TYPE_MERGEREPORT)
        self.assertEqual(classification_fields["verification_mode"], VERIFICATION_MODE_MERGEREPORT)
        self.assertEqual(classification_fields["verification_source"], VERIFICATION_SOURCE_MERGEREPORT)
        self.assertTrue(classification_fields["merge_markers_found"])
        runtime_joined = "\n".join(runtime_events)
        self.assertIn("SLICE_STARTED", runtime_joined)
        self.assertIn("BATCH_COMPLETED", runtime_joined)
        self.assertIn("REPORT_CLASSIFICATION_EVALUATED", runtime_joined)

    def test_multi_slice_waits_for_app_completion_before_second_dispatch(self) -> None:
        sid1 = "1700000_MSWAIT1"
        sid2 = "1700000_MSWAIT2"
        fd, log_path = tempfile.mkstemp(prefix="merge_report_wait_", suffix=".log")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(log_path) and os.remove(log_path))

        app_completion_visible = {"value": False}
        tail_call_count = {"count": 0}

        def _tail_reader(_path: str, *, max_bytes: int = 262_144) -> str:
            del _path, max_bytes
            tail_call_count["count"] += 1
            lines = [
                f"2026-03-14 13:06:52,535 INFO Search Name=[Splunk10] TestReport, SID={sid1}, C:\\dispatch\\{sid1}\\results.csv.gz",
                f"2026-03-14 13:06:52,547 INFO Search Name=[Splunk10] TestReport, SID={sid1}, Report generates result from 2026-03-12 00:00:00 to 2026-03-13 00:00:00",
                f"2026-03-14 13:06:53,038 INFO Search Name=[Splunk10] TestReport, SID={sid1}, Action=Xlsx file created, Size=6984",
                f"2026-03-14 13:06:53,073 INFO Search Name=[Splunk10] TestReport, SID={sid1}, Action=Sending email, SmtpServer=127.0.0.1, SmtpPort=25",
                f"2026-03-14 13:06:53,219 INFO Search Name=[Splunk10] TestReport, SID={sid1}, Action=Email sent, Subject=Splunk Report: [Splunk10] TestReport 2026-03-12 - 2026-03-13",
            ]
            if tail_call_count["count"] >= 2:
                app_completion_visible["value"] = True
                lines.append(
                    f"2026-03-14 13:06:53,221 INFO Search Name=[Splunk10] TestReport, SID={sid1}, App excution completed"
                )
            if tail_call_count["count"] >= 4:
                lines.extend(
                    [
                        f"2026-03-14 13:07:08,964 INFO Search Name=[Splunk10] TestReport, SID={sid2}, C:\\dispatch\\{sid2}\\results.csv.gz",
                        f"2026-03-14 13:07:08,977 INFO Search Name=[Splunk10] TestReport, SID={sid2}, Report generates result from 2026-03-13 00:00:00 to 2026-03-14 00:00:00",
                        f"2026-03-14 13:07:09,267 INFO Search Name=[Splunk10] TestReport, SID={sid2}, Action=Email sent, Subject=Splunk Report: [Splunk10] TestReport 2026-03-13 - 2026-03-14",
                        f"2026-03-14 13:07:09,431 INFO Search Name=[Splunk10] TestReport, SID={sid2}, App excution completed",
                    ]
                )
            return "\n".join(lines) + "\n"

        class GuardedSecondSliceClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[
                        (True, sid1, ""),
                        (True, sid2, ""),
                    ],
                )
                self.dispatch_calls = 0

            def dispatch_saved_search(self, *args, **kwargs):
                del args, kwargs
                self.dispatch_calls += 1
                if self.dispatch_calls == 2 and not app_completion_visible["value"]:
                    raise RuntimeError("second slice dispatched before app completion")
                return self.dispatch_results.pop(0)

            def get_job_status_snapshot(self, *args, **kwargs):
                del args, kwargs
                return ("SUCCESS", {"dispatchState": "DONE", "isDone": True})

        client = GuardedSecondSliceClient()
        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
                "enabled": False,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )
        monotonic_tick = {"t": 0.0}

        def _monotonic() -> float:
            monotonic_tick["t"] += 0.4
            return monotonic_tick["t"]

        saved_search_entry = {
            "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
            "content": {
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
        }

        with patch.object(
            splunk_engine,
            "_read_text_file_tail",
            _tail_reader,
        ), patch.object(
            splunk_engine.time,
            "monotonic",
            _monotonic,
        ), patch.object(
            splunk_engine.time,
            "sleep",
            lambda _seconds: None,
        ), patch.object(
            splunk_engine,
            "_fetch_saved_search_entry",
            lambda *args, **kwargs: (
                dict(saved_search_entry["content"]),
                "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                dict(saved_search_entry),
                {"app": "search", "owner": "skyred5", "sharing": "user"},
            ),
        ):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport"],
                report_names=["[Splunk10] TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 12, 0, 0, 0),
                end=datetime(2026, 3, 14, 0, 0, 0),
                no_change=False,
                wait_seconds=10,
                poll_interval=1,
                config=config,
                app="search",
            )

        joined = "\n".join(logs)
        self.assertEqual(client.dispatch_calls, 2)
        self.assertTrue(app_completion_visible["value"])
        self.assertIn("[1/2] OK", joined)
        self.assertIn("[2/2] DISPATCHED", joined)
        self.assertIn("[2/2] OK", joined)
        self.assertIn("Summary:", joined)

    def test_multi_slice_unexpected_second_slice_exception_still_emits_summary(self) -> None:
        sid1 = "1700000_MSFAIL1"
        log_path = self._write_multi_slice_merge_report_log(
            [(sid1, "2026-03-12 00:00:00", "2026-03-13 00:00:00")]
        )

        class ExplodingSecondSliceClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[(True, sid1, "")],
                    snapshot_results=[("RUNNING", {"dispatchState": "RUNNING", "isDone": False})],
                )
                self.dispatch_calls = 0

            def dispatch_saved_search(self, *args, **kwargs):
                del args, kwargs
                self.dispatch_calls += 1
                if self.dispatch_calls == 1:
                    return True, sid1, ""
                raise RuntimeError("slice2 dispatch exploded")

        client = ExplodingSecondSliceClient()
        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
                "enabled": False,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )
        saved_search_entry = {
            "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
            "content": {
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
        }

        with patch.object(
            splunk_engine,
            "_fetch_saved_search_entry",
            lambda *args, **kwargs: (
                dict(saved_search_entry["content"]),
                "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                dict(saved_search_entry),
                {"app": "search", "owner": "skyred5", "sharing": "user"},
            ),
        ):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport"],
                report_names=["[Splunk10] TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 12, 0, 0, 0),
                end=datetime(2026, 3, 14, 0, 0, 0),
                no_change=False,
                wait_seconds=10,
                poll_interval=1,
                config=config,
                app="search",
            )

        joined = "\n".join(logs)
        self.assertIn("[1/2] OK", joined)
        self.assertIn("[2/2] FAILED: slice2 dispatch exploded", joined)
        self.assertIn("Summary:", joined)

    def test_five_slice_mergereport_batch_uses_file_primary_path_and_sends_ack(self) -> None:
        sids = [f"1700000_MR5_{index}" for index in range(1, 6)]
        log_entries = [
            (sids[0], "2026-03-09 00:00:00", "2026-03-10 00:00:00"),
            (sids[1], "2026-03-10 00:00:00", "2026-03-11 00:00:00"),
            (sids[2], "2026-03-11 00:00:00", "2026-03-12 00:00:00"),
            (sids[3], "2026-03-12 00:00:00", "2026-03-13 00:00:00"),
            (sids[4], "2026-03-13 00:00:00", "2026-03-14 00:00:00"),
        ]
        log_path = self._write_multi_slice_merge_report_log(log_entries)
        runtime_events: list[str] = []
        debug_events: list[tuple[str, dict[str, object]]] = []
        saved_search_entry = {
            "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
            "content": {
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
        }

        class FiveSliceClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[(True, sid, "") for sid in sids],
                    snapshot_results=[
                        RuntimeError(
                            "Local Splunk broker timed out while processing the request (op=get_job_status_snapshot, timeout=7s)."
                        ),
                        ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                        ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                        ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                        ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                    ],
                )
                self.snapshot_calls = 0

            def get_job_status_snapshot(self, *args, **kwargs):
                self.snapshot_calls += 1
                return super().get_job_status_snapshot(*args, **kwargs)

        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
                "enabled": False,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )

        client = FiveSliceClient()

        with patch.object(
            splunk_engine,
            "tool_runtime_log",
            lambda message, level="INFO": runtime_events.append(f"{level}:{message}") or True,
        ), patch.object(
            splunk_engine,
            "tool_debug_category_enabled",
            lambda category: str(category).strip().lower() == "dispatch",
        ), patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, dict(fields))) or True,
        ), patch.object(
            splunk_engine,
            "_fetch_saved_search_entry",
            lambda *args, **kwargs: (
                dict(saved_search_entry["content"]),
                "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                dict(saved_search_entry),
                {"app": "search", "owner": "skyred5", "sharing": "user"},
            ),
        ), patch.object(
            splunk_engine.time,
            "sleep",
            lambda _seconds: None,
        ), patch.object(
            splunk_engine.smtplib,
            "SMTP",
            DummySMTP,
        ):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport"],
                report_names=["[Splunk10] TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 9, 0, 0, 0),
                end=datetime(2026, 3, 14, 0, 0, 0),
                no_change=False,
                wait_seconds=10,
                poll_interval=1,
                config=config,
                app="search",
            )

        joined = "\n".join(logs)
        self.assertIn("[1/5] OK", joined)
        self.assertIn("[5/5] OK", joined)
        self.assertIn("Summary:", joined)
        self.assertEqual(len(DummySMTP.instances), 1)
        self.assertEqual(client.snapshot_calls, 0)
        event_names = [name for name, _fields in debug_events]
        self.assertIn("SLICE_RESOURCES_RESET", event_names)
        self.assertIn("BATCH_PROGRESS_STATE", event_names)
        runtime_joined = "\n".join(runtime_events)
        self.assertIn("BATCH_COMPLETED", runtime_joined)

    def test_repeated_four_slice_batches_clear_tracked_sids_before_later_dispatch(self) -> None:
        saved_search_entry = {
            "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
            "content": {
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
        }

        for run_index in range(1, 4):
            sids = [f"1700000_MR4_RUN{run_index}_{idx}" for idx in range(1, 5)]
            log_path = self._write_multi_slice_merge_report_log(
                [
                    (sids[0], "2026-03-11 00:00:00", "2026-03-12 00:00:00"),
                    (sids[1], "2026-03-12 00:00:00", "2026-03-13 00:00:00"),
                    (sids[2], "2026-03-13 00:00:00", "2026-03-14 00:00:00"),
                    (sids[3], "2026-03-14 00:00:00", "2026-03-15 00:00:00"),
                ]
            )
            runtime_events: list[str] = []
            debug_events: list[tuple[str, dict[str, object]]] = []

            class StaleSensitiveClient(FakeClient):
                def __init__(self) -> None:
                    super().__init__(dispatch_results=[])
                    self.dispatch_contexts: list[dict[str, object]] = []
                    self._last_dispatch_meta = {}

                def dispatch_saved_search(self, *args, **kwargs):
                    del args, kwargs
                    context = dict(getattr(self, "_dispatch_context", {}) or {})
                    self.dispatch_contexts.append(context)
                    if int(context.get("tracked_sid_count", 0) or 0) > 0:
                        raise AssertionError("later dispatch inherited stale tracked_sid_count")
                    sid = sids[len(self.dispatch_contexts) - 1]
                    self._last_dispatch_meta = {
                        "sid": sid,
                        "sid_source": "location_header",
                        "response_status_code": 201,
                        "response_headers_elapsed_ms": 110,
                        "response_body_read_elapsed_ms": 0,
                        "json_parse_elapsed_ms": 0,
                        "post_sid_return_work_ms": 0,
                        "transport_mode": "oneshot_request",
                    }
                    return True, sid, ""

            config = self._make_config(
                postdispatch_config={
                    "poll_seconds": 1,
                    "merge_report_enabled": True,
                    "merge_report_log_path": log_path,
                    "enabled": False,
                },
                diagnostics_config={"snapshot_probe_enabled": True},
            )
            batch_controller = splunk_engine.DispatchBatchController()
            client = StaleSensitiveClient()

            with patch.object(
                splunk_engine,
                "tool_runtime_log",
                lambda message, level="INFO": runtime_events.append(f"{level}:{message}") or True,
            ), patch.object(
                splunk_engine,
                "tool_debug_category_enabled",
                lambda category: str(category).strip().lower() == "dispatch",
            ), patch.object(
                splunk_engine,
                "tool_debug_event",
                lambda event, **fields: debug_events.append((event, dict(fields))) or True,
            ), patch.object(
                splunk_engine,
                "_fetch_saved_search_entry",
                lambda *args, **kwargs: (
                    dict(saved_search_entry["content"]),
                    "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                    dict(saved_search_entry),
                    {"app": "search", "owner": "skyred5", "sharing": "user"},
                ),
            ), patch.object(
                splunk_engine.time,
                "sleep",
                lambda _seconds: None,
            ), patch.object(
                splunk_engine.smtplib,
                "SMTP",
                DummySMTP,
            ):
                logs = splunk_engine.run_dispatch_multi(
                    client=client,
                    report_ids=["/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport"],
                    report_names=["[Splunk10] TestReport"],
                    selected_indices=[0],
                    frequency="Daily",
                    start=datetime(2026, 3, 11, 0, 0, 0),
                    end=datetime(2026, 3, 15, 0, 0, 0),
                    no_change=False,
                    wait_seconds=10,
                    poll_interval=1,
                    config=config,
                    app="search",
                    batch_controller=batch_controller,
                )

            joined = "\n".join(logs)
            self.assertIn("[1/4] OK", joined)
            self.assertIn("[4/4] OK", joined)
            self.assertIn("Summary:", joined)
            self.assertEqual(batch_controller.tracked_sid_count(), 0)
            self.assertEqual([ctx.get("tracked_sid_count") for ctx in client.dispatch_contexts], [0, 0, 0, 0])
            event_names = [name for name, _fields in debug_events]
            self.assertIn("PREVIOUS_SLICE_CLEANUP_COMPLETED", event_names)
            self.assertIn("ACTIVE_BATCH_TRANSPORT_RESET", event_names)
            self.assertIn("LATER_SLICE_DISPATCH_CONTEXT", event_names)
            tracked_count_lines = [line for line in runtime_events if "tracked_sid_count=" in line]
            self.assertTrue(tracked_count_lines)
            self.assertTrue(all("tracked_sid_count=0" in line for line in tracked_count_lines))

    def test_mergereport_file_activity_suppresses_later_snapshot_retries(self) -> None:
        context = self._make_context()
        sid = "1700000_MRSUPPRESS"
        log_path = self._write_merge_report_log(sid)
        debug_events: list[tuple[str, dict[str, object]]] = []

        class SuppressedSnapshotClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[(True, sid, "")],
                    snapshot_results=[("RUNNING", {"dispatchState": "RUNNING", "isDone": False})],
                )
                self.snapshot_calls = 0

            def get_job_status_snapshot(self, *args, **kwargs):
                self.snapshot_calls += 1
                return super().get_job_status_snapshot(*args, **kwargs)

        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": log_path,
                "enabled": False,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )
        client = SuppressedSnapshotClient()

        with patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, dict(fields))) or True,
        ):
            run_dispatch_single(
                client=client,
                report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                report_name="[Splunk10] TestReport",
                frequency="Daily",
                start=datetime(2026, 3, 6, 0, 0, 0),
                end=datetime(2026, 3, 11, 0, 0, 0),
                no_change=True,
                wait_seconds=10,
                poll_interval=2,
                regen_context=context,
                report_type=REPORT_TYPE_MERGEREPORT,
                verification_mode=VERIFICATION_MODE_MERGEREPORT,
                verification_source=VERIFICATION_SOURCE_MERGEREPORT,
                resolved_window=self._resolved_window(),
                config=config,
            )

        record = context.slices[0]
        self.assertEqual(record.status, "OK")
        self.assertEqual(client.snapshot_calls, 0)
        self.assertFalse(record.verification_timeline.get("initial_health_checked"))
        self.assertTrue(record.verification_timeline.get("file_activity_seen"))
        self.assertTrue(record.verification_timeline.get("snapshot_suppressed"))
        preferred_success = next(fields for name, fields in debug_events if name == "MERGEREPORT_PREFERRED_SUCCESS")
        self.assertEqual(preferred_success["stage1_strategy"], "file_primary")

    def test_mergereport_falls_back_to_snapshot_when_file_evidence_is_absent(self) -> None:
        context = self._make_context()
        sid = "1700000_MRFALLBACK"
        class SnapshotFallbackClient(FakeClient):
            def __init__(self) -> None:
                super().__init__(
                    dispatch_results=[(True, sid, "")],
                    snapshot_results=[
                        ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                        ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
                    ],
                )

        clock = {"t": 0.0}

        def _monotonic() -> float:
            return clock["t"]

        def _sleep(seconds: float) -> None:
            clock["t"] += max(0.0, float(seconds))

        config = self._make_config(
            postdispatch_config={
                "poll_seconds": 1,
                "merge_report_enabled": True,
                "merge_report_log_path": r"C:\Program Files\Splunk\var\log\splunk\mergeReport_alert.log",
                "enabled": False,
            },
            diagnostics_config={"snapshot_probe_enabled": True},
        )

        with patch.object(splunk_engine.time, "monotonic", _monotonic), patch.object(
            splunk_engine.time,
            "sleep",
            _sleep,
        ), patch.object(
            splunk_engine,
            "_check_merge_report_preferred_evidence",
            lambda *args, **kwargs: (
                "PENDING",
                {
                    "evidence_source": "merge_report_file",
                    "matched_line_count": 0,
                },
            ),
        ):
            logs = run_dispatch_single(
                client=SnapshotFallbackClient(),
                report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                report_name="[Splunk10] TestReport",
                frequency="Daily",
                start=datetime(2026, 3, 6, 0, 0, 0),
                end=datetime(2026, 3, 11, 0, 0, 0),
                no_change=True,
                wait_seconds=12,
                poll_interval=1,
                regen_context=context,
                report_type=REPORT_TYPE_MERGEREPORT,
                verification_mode=VERIFICATION_MODE_MERGEREPORT,
                verification_source=VERIFICATION_SOURCE_MERGEREPORT,
                resolved_window=self._resolved_window(),
                config=config,
            )

        self.assertIn("OK", "\n".join(logs))
        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].verification_timeline.get("final_status_source"), "stage1_snapshot_fallback")
        self.assertFalse(context.slices[0].verification_timeline.get("file_activity_seen"))

    def test_reconciliation_converts_pending_to_ok_when_later_completed(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/1]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_WAIT01",
            status="PENDING",
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds.",
        )
        client = FakeClient(
            dispatch_results=[],
            snapshot_results=[
                ("RUNNING", {"dispatchState": "RUNNING"}),
                ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
            ],
        )

        with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
            logs = _reconcile_pending_slices(
                client,
                context,
                wait_seconds=2,
                poll_interval=1,
            )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "RECONCILED_OK")
        self.assertEqual(context.slices[0].error, "")
        self.assertIn("Stage 1 result: Success", "\n".join(logs))

    def test_reconciliation_retries_after_snapshot_exception_then_succeeds(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/1]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_WAIT02",
            status="PENDING",
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds.",
        )

        class RetryClient(FakeClient):
            def __init__(self):
                super().__init__(dispatch_results=[])
                self.snapshot_calls = 0

            def get_job_status_snapshot(self, *args, **kwargs):
                self.snapshot_calls += 1
                if self.snapshot_calls == 1:
                    raise RuntimeError(
                        "Local Splunk broker timed out while processing the request (op=get_job_status_snapshot, timeout=7s)."
                    )
                return ("SUCCESS", {"dispatchState": "DONE", "isDone": True})

        client = RetryClient()
        with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
            logs = _reconcile_pending_slices(
                client,
                context,
                wait_seconds=3,
                poll_interval=1,
            )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "RECONCILED_OK")
        self.assertGreaterEqual(client.snapshot_calls, 2)
        self.assertIn("Stage 1 result: Success", "\n".join(logs))

    def test_reconciliation_uses_bounded_snapshot_polls(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/1]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_WAIT01",
            status="PENDING",
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds.",
        )

        class RecordingClient(FakeClient):
            def __init__(self):
                super().__init__(dispatch_results=[])
                self.snapshot_calls = []

            def get_job_status_snapshot(self, *args, **kwargs):
                self.snapshot_calls.append(
                    (
                        kwargs.get("request_timeout_seconds"),
                        kwargs.get("max_total_timeout_seconds"),
                    )
                )
                return ("RUNNING", {"dispatchState": "RUNNING"})

        client = RecordingClient()
        monotonic_tick = {"t": 0.0}

        def _slow_monotonic() -> float:
            monotonic_tick["t"] += 0.3
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slow_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                _reconcile_pending_slices(
                    client,
                    context,
                    wait_seconds=3,
                    poll_interval=2,
                )

        self.assertGreaterEqual(len(client.snapshot_calls), 1)
        for request_timeout, max_total_timeout in client.snapshot_calls:
            self.assertLessEqual(float(request_timeout), 2.0)
            self.assertLessEqual(float(max_total_timeout), 3.0)

    def test_summary_counts_and_per_slice_lines_include_pending(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/2]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_OK123",
            status="OK",
            outcome_code="SUCCESS",
        )
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[2/2]",
            earliest="2026-03-02 00:00:00",
            latest="2026-03-03 00:00:00",
            sid="1700000_PEND1",
            status="PENDING",
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds. Splunk may still complete pending jobs asynchronously.",
        )

        self.assertEqual(context.summary_counts(), (1, 0, 1))
        lines = _build_run_summary_lines(context)
        joined = "\n".join(lines)
        self.assertIn("Total slices: 2", joined)
        self.assertIn("Succeeded: 1", joined)
        self.assertIn("Failed: 0", joined)
        self.assertIn("Pending: 1", joined)
        self.assertIn("[OK] Daily KPI [1/2]", joined)
        self.assertIn("[PENDING] Daily KPI [2/2]", joined)
        self.assertIn("sid=1700000_PEND1", joined)

    def test_ack_skipped_when_pending_and_ack_on_pending_disabled(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/1]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_PEND1",
            status="PENDING",
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds. Splunk may still complete pending jobs asynchronously.",
        )

        with patch.object(splunk_engine.smtplib, "SMTP", DummySMTP):
            result = send_ack_summary_email(context, config=self._make_config())

        self.assertFalse(result.attempted)
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "pending_slices_present")
        self.assertEqual(len(DummySMTP.instances), 0)

    def test_ack_sent_with_pending_verification_when_enabled(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/2]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_OK123",
            status="OK",
            outcome_code="SUCCESS",
        )
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[2/2]",
            earliest="2026-03-02 00:00:00",
            latest="2026-03-03 00:00:00",
            sid="1700000_PEND1",
            status="PENDING",
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds. Splunk may still complete pending jobs asynchronously.",
        )

        with patch.object(splunk_engine.smtplib, "SMTP", DummySMTP):
            result = send_ack_summary_email(
                context,
                config=self._make_config(ack_on_pending=True, ack_on_unknown=True),
            )

        self.assertTrue(result.attempted)
        self.assertTrue(result.success)
        self.assertEqual(result.reason, "pending_verification")
        self.assertEqual(len(DummySMTP.instances), 1)
        message = DummySMTP.instances[0].sent_messages[0]
        body = message.get_content()
        self.assertIn("PARTIAL / PENDING VERIFICATION", message["Subject"])
        self.assertIn("Overall status: PARTIAL / PENDING VERIFICATION", body)
        self.assertIn("Pending: 1", body)
        self.assertIn("[PENDING]", body)
        self.assertIn("1700000_PEND1", body)
        self.assertNotIn("Failed: 1", body)

    def test_ack_sent_for_single_successful_report(self) -> None:
        context = self._make_context()
        context.report_names = ["[Splunk10] TestReport"]
        context.add_slice(
            report_name="[Splunk10] TestReport",
            slice_label="single run",
            earliest="2026-03-06 00:00:00",
            latest="2026-03-11 00:00:00",
            sid="1700000_ACKOK",
            status="OK",
            outcome_code="SUCCESS",
        )

        with patch.object(splunk_engine.smtplib, "SMTP", DummySMTP):
            result = send_ack_summary_email(context, config=self._make_config())

        self.assertTrue(result.attempted)
        self.assertTrue(result.success)
        self.assertEqual(result.reason, "all_slices_ok")
        self.assertEqual(result.overall_status, "OK")
        self.assertEqual(result.ok_count, 1)
        self.assertEqual(result.fail_count, 0)
        self.assertEqual(result.pending_count, 0)
        self.assertEqual(result.cancelled_count, 0)
        self.assertEqual(result.recipient_source, "config")
        self.assertEqual(result.smtp_host, "127.0.0.1")
        self.assertEqual(result.smtp_port, 25)
        self.assertEqual(len(DummySMTP.instances), 1)
        message = DummySMTP.instances[0].sent_messages[0]
        self.assertIn("*** MANUALLY REGENERATED ***", message["Subject"])
        self.assertIn("overall_status=OK", result.body_summary)

    def test_ack_skipped_when_failed_slices_present(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/1]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_FAIL1",
            status="FAILED",
            outcome_code="VERIFIED_FAILED",
            error="dispatch failed",
        )

        with patch.object(splunk_engine.smtplib, "SMTP", DummySMTP):
            result = send_ack_summary_email(context, config=self._make_config())

        self.assertFalse(result.attempted)
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "failed_slices_present")
        self.assertEqual(len(DummySMTP.instances), 0)

    def test_ack_skipped_when_cancelled_slices_present(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/1]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_CANCEL1",
            status="CANCELLED",
            outcome_code="BATCH_CANCELLED",
            error="cancelled",
        )

        with patch.object(splunk_engine.smtplib, "SMTP", DummySMTP):
            result = send_ack_summary_email(context, config=self._make_config())

        self.assertFalse(result.attempted)
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "cancelled_slices_present")
        self.assertEqual(len(DummySMTP.instances), 0)

    def test_ack_uses_current_slice_status_after_pending_is_resolved(self) -> None:
        context = self._make_context()
        item = context.add_slice(
            report_name="Daily KPI",
            slice_label="[1/1]",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid="1700000_STALE1",
            status="PENDING",
            outcome_code="DISPATCHED_PENDING",
            error="pending",
        )
        item.status = "OK"
        item.outcome_code = "SUCCESS"
        item.error = ""

        with patch.object(splunk_engine.smtplib, "SMTP", DummySMTP):
            result = send_ack_summary_email(context, config=self._make_config())

        self.assertTrue(result.attempted)
        self.assertTrue(result.success)
        self.assertEqual(result.reason, "all_slices_ok")
        self.assertEqual(result.pending_count, 0)
        self.assertEqual(len(DummySMTP.instances), 1)

    def test_ack_diagnostics_events_are_emitted(self) -> None:
        context = self._make_context()
        context.add_slice(
            report_name="[Splunk10] TestReport",
            slice_label="single run",
            earliest="2026-03-06 00:00:00",
            latest="2026-03-11 00:00:00",
            sid="1700000_ACKDIAG",
            status="OK",
            outcome_code="SUCCESS",
        )
        debug_events: list[tuple[str, dict[str, object]]] = []
        config = self._make_config(
            file_logging_config={"debug_log_enabled": True},
        )

        with patch.object(splunk_engine.smtplib, "SMTP", DummySMTP):
            with patch.object(
                splunk_engine,
                "tool_debug_event",
                lambda event, **fields: debug_events.append((event, fields)) or True,
            ):
                result = send_ack_summary_email(context, config=config)

        self.assertTrue(result.success)
        event_names = [name for name, _fields in debug_events]
        self.assertIn("ACK_EVALUATION_STARTED", event_names)
        self.assertIn("ACK_EMAIL_REQUESTED", event_names)
        self.assertIn("ACK_EMAIL_SENT", event_names)
        self.assertIn("ACK_EVALUATION_COMPLETED", event_names)
        requested_fields = next(fields for name, fields in debug_events if name == "ACK_EMAIL_REQUESTED")
        self.assertEqual(requested_fields["recipient_count"], 1)
        self.assertIn("*** MANUALLY REGENERATED ***", requested_fields["subject"])

    def test_timeout_config_values_are_loaded_and_resolved(self) -> None:
        config_text = """
[splunk]
servers = https://splunk.example:8089
auth_mode = password
verify_ssl = false

[Credentials]
username = splunk_service
secret_file = secret.dpapi
dpapi_scope = machine

[mergereport]
enabled = false
timeout_seconds = 333

[dispatch]
per_slice_wait_seconds = 42
continue_on_timeout = true
timeout_result = pending
max_slice_runtime_seconds = 123

[email]
ack_enabled = 1
ack_on_pending = 1

[postdispatch]
merge_report_timeout_seconds = 444
native_email_timeout_seconds = 555
poll_seconds = 7
lookback_seconds = 888
broker_request_timeout_seconds = 654
status_check_timeout_seconds = 321
reconcile_pending = true
reconcile_wait_seconds = 66
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.ini")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(config_text.strip())

            cfg = splunk_engine.load_config(
                path=config_path,
                policy=FakePolicy(config_path),
            )

        self.assertEqual(cfg.merge_report_timeout_seconds, 444)
        self.assertTrue(cfg.ack_enabled)
        self.assertTrue(cfg.ack_on_pending)
        self.assertTrue(cfg.ack_on_unknown)
        self.assertIsNotNone(cfg.dispatch_config)
        self.assertEqual(cfg.dispatch_config["per_slice_wait_seconds"], 42)
        self.assertTrue(cfg.dispatch_config["continue_on_timeout"])
        self.assertEqual(cfg.dispatch_config["timeout_result"], "pending")
        self.assertEqual(cfg.dispatch_config["max_slice_runtime_seconds"], 123)
        self.assertIsNotNone(cfg.postdispatch_config)
        self.assertEqual(cfg.postdispatch_config["merge_report_timeout_seconds"], 444)
        self.assertEqual(cfg.postdispatch_config["native_email_timeout_seconds"], 555)
        self.assertEqual(cfg.postdispatch_config["poll_seconds"], 7)
        self.assertEqual(cfg.postdispatch_config["lookback_seconds"], 888)
        self.assertEqual(cfg.postdispatch_config["broker_request_timeout_seconds"], 654)
        self.assertEqual(cfg.postdispatch_config["status_check_timeout_seconds"], 321)
        self.assertTrue(cfg.postdispatch_config["reconcile_pending"])
        self.assertEqual(cfg.postdispatch_config["reconcile_wait_seconds"], 66)
        self.assertEqual(resolve_status_check_timeout_seconds(cfg), 42)
        self.assertEqual(resolve_status_check_poll_seconds(cfg), 7)
        self.assertEqual(resolve_broker_request_timeout_seconds(cfg), 654)
        self.assertEqual(resolve_max_slice_runtime_seconds(cfg), 123)

    def test_legacy_status_timeout_still_applies_without_dispatch_section(self) -> None:
        config_text = """
[splunk]
servers = https://splunk.example:8089
auth_mode = password
verify_ssl = false

[Credentials]
username = splunk_service
secret_file = secret.dpapi
dpapi_scope = machine

[postdispatch]
status_check_timeout_seconds = 123
"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = os.path.join(temp_dir, "config.ini")
            with open(config_path, "w", encoding="utf-8") as handle:
                handle.write(config_text.strip())

            cfg = splunk_engine.load_config(
                path=config_path,
                policy=FakePolicy(config_path),
            )

        self.assertEqual(resolve_status_check_timeout_seconds(cfg), 123)


class ReportsAppDispatchTests(unittest.TestCase):
    class _Value:
        def __init__(self, value):
            self._value = value

        def get(self):
            return self._value

    class _Listbox:
        def curselection(self):
            return (0,)

    def test_engine_driven_dispatch_does_not_start_legacy_merge_report_monitor(self) -> None:
        app = splunk_report_tk.ReportsApp.__new__(splunk_report_tk.ReportsApp)
        app.client = object()
        app.cfg = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            merge_report_enabled=True,
            merge_report_log_path=r"C:\Program Files\Splunk\var\log\splunk\mergeReport_alert.log",
            merge_report_timeout_seconds=300,
            dispatch_config={
                "per_slice_wait_seconds": 30,
                "continue_on_timeout": True,
                "timeout_result": "pending",
            },
            postdispatch_config={
                "poll_seconds": 5,
                "broker_request_timeout_seconds": 300,
                "status_check_timeout_seconds": 300,
            },
            runtime_config={},
        )
        app._dispatch_in_progress = False
        app._dispatch_queue = queue.Queue()
        app._merge_report_monitor = None
        app._postdispatch_monitor = None
        app._batch_controller = None
        app._return_to_menu_after_dispatch = False
        app._cancel_result_message = ""
        app.report_ids = ["saved-search-id"]
        app.report_names = ["[Splunk10] TestReport"]
        app.report_email_flags = [True]
        app.report_namespace_meta = []
        app.filtered_indices = [0]
        app.reports_list = self._Listbox()
        app.frequency_var = self._Value("Daily")
        app.no_change_var = self._Value(False)
        app.app_var = self._Value("search")
        app.start_date_widget = object()
        app.end_date_widget = object()
        app.master = object()
        app._ensure_backend_ready = lambda _label: True
        app._show_prompt = lambda *args, **kwargs: True
        app._append_log = lambda *args, **kwargs: None
        app._debug_log = lambda *args, **kwargs: None
        app._set_dispatch_state = lambda _state: None
        app._poll_dispatch_queue = lambda: None
        app.after = lambda _delay, _callback: None
        app._on_cancel_requested = lambda: None
        app._get_date_from_widget = (
            lambda widget: datetime(2026, 3, 9).date()
            if widget is app.start_date_widget
            else datetime(2026, 3, 10).date()
        )
        app._resolve_selected_windows = lambda **kwargs: {"windows": {}}

        merge_monitor_ctor_calls: list[tuple[tuple, dict]] = []

        with patch.object(
            splunk_report_tk,
            "MergeReportMonitor",
            lambda *args, **kwargs: merge_monitor_ctor_calls.append((args, kwargs)) or object(),
        ), patch.object(
            splunk_report_tk,
            "run_with_progress",
            lambda *args, **kwargs: None,
        ):
            app.on_send_clicked()

        self.assertEqual(merge_monitor_ctor_calls, [])
        self.assertIsNone(app._merge_report_monitor)


class MergeReportMonitorTests(unittest.TestCase):
    def test_stop_clears_tracked_sids_and_terminal_line_unregisters_sid(self) -> None:
        ui_queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        monitor = splunk_report_tk.MergeReportMonitor(
            log_path=__file__,
            ui_queue=ui_queue,
            timeout_seconds=1,
        )
        sid = "1700000_MONITOR"
        monitor.register_sid(sid, "[Splunk10] TestReport")
        monitor._process_line(
            f"2026-03-14 19:55:34,922 INFO Search Name=[Splunk10] TestReport, SID={sid}, App excution completed"
        )
        self.assertNotIn(sid, monitor.tracked_sids)
        monitor.register_sid(sid, "[Splunk10] TestReport")
        monitor.stop()
        self.assertEqual(monitor.tracked_sids, {})


class ReportClassificationTests(unittest.TestCase):
    def _make_config(self, *, merge_enabled: bool = True, native_enabled: bool = True) -> SplunkConfig:
        return SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            postdispatch_config={
                "merge_report_enabled": merge_enabled,
                "native_email_enabled": native_enabled,
            },
        )

    def test_merge_report_classification_and_mode(self) -> None:
        content = {"action.mergeReport": "1", "search": "index=main | addinfo"}
        report_type, reason = _classify_report_type(content)
        self.assertEqual(report_type, REPORT_TYPE_MERGEREPORT)
        self.assertIn("MergeReport", reason)
        mode, source = _resolve_verification_mode(report_type, self._make_config())
        self.assertEqual(mode, VERIFICATION_MODE_MERGEREPORT)
        self.assertEqual(source, VERIFICATION_SOURCE_MERGEREPORT)

    def test_native_classification_and_mode(self) -> None:
        content = {"action.email": "1", "search": "index=main"}
        report_type, _ = _classify_report_type(content)
        self.assertEqual(report_type, REPORT_TYPE_NATIVE)
        mode, source = _resolve_verification_mode(report_type, self._make_config())
        self.assertEqual(mode, VERIFICATION_MODE_NATIVE)
        self.assertEqual(source, VERIFICATION_SOURCE_NATIVE)

    def test_unknown_classification_no_longer_defaults_native(self) -> None:
        content = {"search": "index=main"}
        report_type, reason = _classify_report_type_with_fallback(
            object(),  # type: ignore[arg-type]
            "Report A",
            content,
            self._make_config(),
        )
        self.assertEqual(report_type, splunk_engine.REPORT_TYPE_UNKNOWN)
        self.assertIn("metadata_incomplete", reason)

    def test_resolved_classification_prefers_merge_report_over_native(self) -> None:
        decision = _resolve_report_classification(
            report_name="[Splunk10] TestReport",
            content={
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
            entry={
                "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
                "content": {
                    "action.mergeReport": "1",
                    "action.email.to": "alerts@example.com",
                },
            },
            metadata_path="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            namespace_used={"app": "search", "owner": "skyred5", "sharing": "user"},
            config=self._make_config(),
        )
        self.assertEqual(decision.report_type, REPORT_TYPE_MERGEREPORT)
        self.assertEqual(decision.verification_mode, VERIFICATION_MODE_MERGEREPORT)
        self.assertEqual(decision.verification_source, VERIFICATION_SOURCE_MERGEREPORT)
        self.assertIn("MergeReport markers", decision.classification_reason)
        self.assertIn(
            "native rejected because MergeReport markers take precedence",
            decision.rejected_alternatives,
        )
        self.assertTrue(decision.action_inputs["merge_markers_found"])
        self.assertTrue(decision.action_inputs["native_markers_found"])

    def test_resolved_classification_missing_metadata_fails_closed(self) -> None:
        with self.assertRaises(ReportClassificationResolutionError):
            _resolve_report_classification(
                report_name="Report B",
                content=None,
                entry=None,
                metadata_path="",
                namespace_used={"app": "search", "owner": "skyred5", "sharing": "user"},
                config=self._make_config(),
            )

    def test_resolved_classification_is_stable_across_repeated_runs(self) -> None:
        kwargs = {
            "report_name": "[Splunk10] TestReport",
            "content": {
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
            "entry": {
                "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
                "content": {
                    "action.mergeReport": "1",
                    "action.email.to": "alerts@example.com",
                    "search": "index=main | addinfo",
                },
            },
            "metadata_path": "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            "namespace_used": {"app": "search", "owner": "skyred5", "sharing": "user"},
            "config": self._make_config(),
        }
        first = _resolve_report_classification(**kwargs)
        second = _resolve_report_classification(**kwargs)
        self.assertEqual(first.report_type, second.report_type)
        self.assertEqual(first.verification_mode, second.verification_mode)
        self.assertEqual(first.verification_source, second.verification_source)
        self.assertEqual(first.classification_reason, second.classification_reason)
        self.assertEqual(first.action_inputs, second.action_inputs)

    def test_namespace_changes_do_not_change_classification_when_actions_match(self) -> None:
        content = {
            "action.mergeReport": "1",
            "action.email.to": "alerts@example.com",
            "search": "index=main | addinfo",
        }
        first = _resolve_report_classification(
            report_name="[Splunk10] TestReport",
            content=content,
            entry={"acl": {"app": "search", "owner": "skyred5", "sharing": "user"}, "content": dict(content)},
            metadata_path="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            namespace_used={"app": "search", "owner": "skyred5", "sharing": "user"},
            config=self._make_config(),
        )
        second = _resolve_report_classification(
            report_name="[Splunk10] TestReport",
            content=content,
            entry={"acl": {"app": "search", "owner": "nobody", "sharing": "app"}, "content": dict(content)},
            metadata_path="/servicesNS/nobody/search/saved/searches/%5BSplunk10%5D%20TestReport",
            namespace_used={"app": "search", "owner": "nobody", "sharing": "app"},
            config=self._make_config(),
        )
        self.assertEqual(first.report_type, REPORT_TYPE_MERGEREPORT)
        self.assertEqual(second.report_type, REPORT_TYPE_MERGEREPORT)
        self.assertEqual(first.verification_mode, second.verification_mode)

    def test_detailed_metadata_overrides_lightweight_list_shape_for_classification(self) -> None:
        lightweight_content = {"action.email.to": "alerts@example.com"}
        report_type, _reason = _classify_report_type(lightweight_content)
        self.assertEqual(report_type, REPORT_TYPE_NATIVE)

        decision = _resolve_report_classification(
            report_name="[Splunk10] TestReport",
            content={
                "action.mergeReport": "1",
                "action.email.to": "alerts@example.com",
                "search": "index=main | addinfo",
            },
            entry={
                "acl": {"app": "search", "owner": "skyred5", "sharing": "user"},
                "content": {
                    "action.mergeReport": "1",
                    "action.email.to": "alerts@example.com",
                    "search": "index=main | addinfo",
                },
            },
            metadata_path="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            namespace_used={"app": "search", "owner": "skyred5", "sharing": "user"},
            config=self._make_config(),
        )
        self.assertEqual(decision.report_type, REPORT_TYPE_MERGEREPORT)

    def test_merge_report_missing_addinfo_warns(self) -> None:
        content = {"action.mergeReport": "1", "search": "index=main"}
        report_type, _ = _classify_report_type(content)
        self.assertEqual(report_type, REPORT_TYPE_MERGEREPORT)
        self.assertTrue(_should_warn_missing_addinfo(report_type, content))

    def test_native_missing_addinfo_not_warned(self) -> None:
        content = {"action.email": "1", "search": "index=main"}
        report_type, _ = _classify_report_type(content)
        self.assertEqual(report_type, REPORT_TYPE_NATIVE)
        self.assertFalse(_should_warn_missing_addinfo(report_type, content))


class MergeReportParsingTests(unittest.TestCase):
    def test_email_sent_is_not_final_success_without_completion(self) -> None:
        sid = "1700000_EMAIL"
        evidence = {sid: _MergeReportEvidence()}
        results = {
            "results": [
                {
                    "_raw": (
                        "2026-03-12 12:00:00,000 INFO Search Name=Daily, "
                        f"SID={sid}, Action=Email sent"
                    )
                }
            ]
        }
        _update_merge_report_evidence(results, evidence)
        self.assertFalse(evidence[sid].success)
        self.assertTrue(evidence[sid].email_sent)
        self.assertEqual(_merge_report_evidence_state(evidence[sid]), "RUNNING")

    def test_success_via_app_excution_completed(self) -> None:
        sid = "1700000_EXEC"
        evidence = {sid: _MergeReportEvidence()}
        results = {
            "results": [
                {
                    "_raw": (
                        "2026-03-12 12:00:01,000 INFO Search Name=Daily, "
                        f"SID={sid}, App excution completed"
                    )
                }
            ]
        }
        _update_merge_report_evidence(results, evidence)
        self.assertTrue(evidence[sid].success)

    def test_success_via_app_execution_completed(self) -> None:
        sid = "1700000_EXEC2"
        evidence = {sid: _MergeReportEvidence()}
        results = {
            "results": [
                {
                    "_raw": (
                        "2026-03-12 12:00:02,000 INFO Search Name=Daily, "
                        f"SID={sid}, App execution completed"
                    )
                }
            ]
        }
        _update_merge_report_evidence(results, evidence)
        self.assertTrue(evidence[sid].success)

    def test_no_false_success_on_sid_mismatch(self) -> None:
        sid = "1700000_MATCH"
        evidence = {sid: _MergeReportEvidence()}
        results = {
            "results": [
                {
                    "_raw": (
                        "2026-03-12 12:00:03,000 INFO Search Name=Daily, "
                        "SID=1700000_OTHER, Action=Email sent"
                    )
                }
            ]
        }
        _update_merge_report_evidence(results, evidence)
        self.assertFalse(evidence[sid].success)

    def test_failure_marker_remains_failed(self) -> None:
        sid = "1700000_FAIL"
        evidence = {sid: _MergeReportEvidence()}
        results = {
            "results": [
                {
                    "_raw": (
                        "2026-03-12 12:00:04,000 ERROR Search Name=Daily, "
                        f"SID={sid}, ERROR KeyError: 'info_min_time'"
                    )
                }
            ]
        }
        _update_merge_report_evidence(results, evidence)
        self.assertTrue(evidence[sid].failed)

    def test_multi_sid_stream_parsing_resolves_both(self) -> None:
        sid1 = "1700000_SID22"
        sid2 = "1700000_SID23"
        raw_lines = [
            json.dumps(
                {
                    "result": {
                        "_raw": (
                            "2026-03-12 12:01:00,000 INFO Search Name=Daily, "
                            f"SID={sid1}, Action=Email sent"
                        )
                    }
                }
            ),
            json.dumps(
                {
                    "result": {
                        "_raw": (
                            "2026-03-12 12:01:01,000 INFO Search Name=Daily, "
                            f"SID={sid1}, App excution completed"
                        )
                    }
                }
            ),
            json.dumps(
                {
                    "result": {
                        "_raw": (
                            "2026-03-12 12:01:02,000 INFO Search Name=Daily, "
                            f"SID={sid2}, Action=Email sent"
                        )
                    }
                }
            ),
            json.dumps(
                {
                    "result": {
                        "_raw": (
                            "2026-03-12 12:01:03,000 INFO Search Name=Daily, "
                            f"SID={sid2}, App excution completed"
                        )
                    }
                }
            ),
        ]
        parsed = _parse_postdispatch_results("\n".join(raw_lines))
        evidence = {sid1: _MergeReportEvidence(), sid2: _MergeReportEvidence()}
        _update_merge_report_evidence(parsed, evidence)
        self.assertTrue(evidence[sid1].success)
        self.assertTrue(evidence[sid2].success)

    def test_merge_report_evidence_records_timeline_and_artifact_events(self) -> None:
        sid = "1700000_TIMELINE"
        evidence = {sid: _MergeReportEvidence()}
        timeline = splunk_engine._new_verification_timeline(
            sid=sid,
            verification_mode=VERIFICATION_MODE_MERGEREPORT,
        )
        debug_events: list[tuple[str, dict[str, object]]] = []
        results = {
            "results": [
                {
                    "_raw": (
                        "2026-03-12 12:00:00,000 INFO Search Name=Daily, "
                        f"SID={sid}, Action=Xlsx file created"
                    )
                },
                {
                    "_raw": (
                        "2026-03-12 12:00:01,000 INFO Search Name=Daily, "
                        f"SID={sid}, Action=Zip file created"
                    )
                },
                {
                    "_raw": (
                        "2026-03-12 12:00:02,000 INFO Search Name=Daily, "
                        f"SID={sid}, Action=Email sent"
                    )
                },
                {
                    "_raw": (
                        "2026-03-12 12:00:03,000 INFO Search Name=Daily, "
                        f"SID={sid}, App excution completed"
                    )
                },
            ]
        }

        with patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, fields)) or True,
        ):
            _update_merge_report_evidence(
                results,
                evidence,
                timeline_map={sid: timeline},
                diagnostics_enabled=True,
                report_name_map={sid: "Merge Report"},
                slice_label_map={sid: "single run"},
            )

        self.assertTrue(evidence[sid].success)
        self.assertEqual(evidence[sid].success_marker, "App excution completed")
        self.assertTrue(timeline["first_mergereport_evidence_time"])
        self.assertEqual(timeline["first_mergereport_evidence_log_time"], "2026-03-12 12:00:00,000")
        self.assertTrue(timeline["first_mergereport_artifact_time"])
        self.assertEqual(timeline["first_mergereport_artifact_log_time"], "2026-03-12 12:00:00,000")
        self.assertIn("MERGEREPORT_EVIDENCE_DETECTED", [event for event, _fields in debug_events])
        self.assertIn("MERGEREPORT_ARTIFACT_DETECTED", [event for event, _fields in debug_events])

    def test_saved_search_time_range_resolution_uses_saved_search_dispatch_config(self) -> None:
        class RangeClient(FakeClient):
            def _get(self, path: str):
                self.last_path = path
                return {
                    "entry": [
                        {
                            "acl": {"owner": "nobody", "app": "search"},
                            "content": {
                                "dispatch.earliest_time": "-1w@w",
                                "dispatch.latest_time": "@w",
                                "dispatch.time_format": "%Y-%m-%d %H:%M:%S",
                                "cron_schedule": "0 6 * * 1",
                            },
                        }
                    ]
                }

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.last_search_query = search_query
                self.last_earliest_time = earliest_time
                self.last_timeout = timeout_seconds
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1740873600",
                            "report_latest_epoch": "1741478400",
                            "report_earliest": "2026-03-02 00:00:00 +0800",
                            "report_latest": "2026-03-09 00:00:00 +0800",
                        }
                    ]
                }

        client = RangeClient(dispatch_results=[])
        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Weekly%20KPI",
            report_name="Weekly KPI",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
        )

        self.assertEqual(window.time_source, "savedsearch")
        self.assertEqual(window.dispatch_earliest, "1740873600")
        self.assertEqual(window.dispatch_latest, "1741478400")
        self.assertEqual(window.display_range, "2026-03-02 00:00:00 +0800 to 2026-03-09 00:00:00 +0800")
        self.assertEqual(window.cron_schedule, "0 6 * * 1")
        self.assertIn('relative_time(1741824000, "-1w@w")', client.last_search_query)
        self.assertEqual(client.last_earliest_time, "-1s")

    def test_saved_search_time_range_resolution_honors_dispatch_values_with_now(self) -> None:
        class RangeClient(FakeClient):
            def _get(self, path: str):
                self.last_path = path
                return {
                    "entry": [
                        {
                            "acl": {"owner": "gabriel", "app": "search", "sharing": "user"},
                            "content": {
                                "dispatch.earliest_time": "-7d@h",
                                "dispatch.latest_time": "now",
                                "cron_schedule": "0 6 * * 1",
                                "search": "search index=main | addinfo",
                            },
                        }
                    ]
                }

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.last_search_query = search_query
                self.last_earliest_time = earliest_time
                self.last_timeout = timeout_seconds
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1741219200",
                            "report_latest_epoch": "1741824000",
                            "report_earliest": "2026-03-06 00:00:00 +0800",
                            "report_latest": "2026-03-13 00:00:00 +0800",
                        }
                    ]
                }

        client = RangeClient(dispatch_results=[])
        logs: list[str] = []
        cfg = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            logging_verbose=True,
        )
        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/gabriel/search/saved/searches/%5BSplunk10%5D%20TestReport",
            report_name="[Splunk10] TestReport",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
            config=cfg,
            log_callback=logs.append,
        )

        self.assertEqual(window.resolution_path, "dispatch")
        self.assertEqual(window.display_range, "2026-03-06 00:00:00 +0800 to 2026-03-13 00:00:00 +0800")
        self.assertIn('relative_time(1741824000, "-7d@h")', client.last_search_query)
        self.assertIn("report_latest_epoch=1741824000", client.last_search_query)
        self.assertNotIn('relative_time(1741824000, "now")', client.last_search_query)
        self.assertIn("[Debug] Saved search retrieved successfully", logs)
        self.assertIn("[Debug] Saved search dispatch.earliest_time: -7d@h", logs)
        self.assertIn("[Debug] Saved search dispatch.latest_time: now", logs)
        self.assertIn(
            "[Debug] Saved search dispatch.earliest_time source: content (key=dispatch.earliest_time)",
            logs,
        )
        self.assertIn(
            "[Debug] Saved search dispatch.latest_time source: content (key=dispatch.latest_time)",
            logs,
        )
        self.assertIn("[Debug] dispatch.earliest_time resolver classification: relative (accepted=true)", logs)
        self.assertIn("[Debug] dispatch.latest_time resolver classification: now (accepted=true)", logs)
        self.assertIn("[Debug] Time range resolution path: dispatch.earliest_time/dispatch.latest_time", logs)
        self.assertIn("[Debug] Fallback skipped because dispatch.* succeeded", logs)
        self.assertIn(
            "[Debug] Final display range: 2026-03-06 00:00:00 +0800 to 2026-03-13 00:00:00 +0800",
            logs,
        )

    def test_saved_search_time_range_resolution_passes_namespace_context_to_broker_lookup(self) -> None:
        class BrokerBackedClient(FakeClient):
            def get_saved_search_metadata(
                self,
                *,
                path: str,
                report_name: str = "",
                app: str = "",
                owner: str = "",
                sharing: str = "",
                namespace_meta=None,
                candidate_label: str = "",
            ) -> dict:
                self.lookup_args = {
                    "path": path,
                    "report_name": report_name,
                    "app": app,
                    "owner": owner,
                    "sharing": sharing,
                    "namespace_meta": dict(namespace_meta or {}),
                    "candidate_label": candidate_label,
                }
                return {
                    "entry": [
                        {
                            "acl": {"owner": "gabriel", "app": "search", "sharing": "user"},
                            "content": {
                                "dispatch.earliest_time": "-7d@h",
                                "dispatch.latest_time": "now",
                                "cron_schedule": "0 6 * * 1",
                            },
                        }
                    ]
                }

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.last_search_query = search_query
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1741219200",
                            "report_latest_epoch": "1741824000",
                            "report_earliest": "2026-03-06 00:00:00 +0800",
                            "report_latest": "2026-03-13 00:00:00 +0800",
                        }
                    ]
                }

        client = BrokerBackedClient(dispatch_results=[])
        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
            report_name="[Splunk10] TestReport",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
            namespace_meta={
                "app": "search",
                "owner": "gabriel",
                "sharing": "user",
                "rest_path": "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
            },
        )

        self.assertEqual(window.resolution_path, "dispatch")
        self.assertEqual(client.lookup_args["report_name"], "[Splunk10] TestReport")
        self.assertEqual(client.lookup_args["app"], "search")
        self.assertEqual(client.lookup_args["owner"], "gabriel")
        self.assertEqual(client.lookup_args["sharing"], "user")
        self.assertEqual(client.lookup_args["candidate_label"], "exact_namespace_metadata")
        self.assertEqual(
            client.lookup_args["namespace_meta"]["rest_path"],
            "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
        )

    def test_broker_saved_search_metadata_lookup_returns_specific_not_found_for_bracketed_report(self) -> None:
        class BrokerClient:
            def __init__(self) -> None:
                self.paths: list[str] = []

            def _get(self, path: str) -> dict:
                self.paths.append(path)
                raise RuntimeError("HTTP 404 returned by Splunk REST API.")

        audit = DummyAudit()
        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = audit
        state.client = BrokerClient()

        with self.assertRaises(splunk_broker_module._BrokerError) as ctx:
            state.op_get_saved_search_metadata(
                {
                    "path": "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
                    "report_name": "[Splunk10] TestReport",
                    "app": "search",
                    "owner": "gabriel",
                    "sharing": "user",
                    "candidate_label": "exact_namespace_metadata",
                    "namespace_meta": {
                        "app": "search",
                        "owner": "gabriel",
                        "sharing": "user",
                        "rest_path": "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
                    },
                }
            )

        self.assertEqual(ctx.exception.error_code, "saved_search_not_found")
        self.assertEqual(
            str(ctx.exception),
            "saved_search_not_found at /servicesNS/gabriel/search/saved/searches/%5BSplunk10%5D%20TestReport",
        )
        self.assertEqual(
            state.client.paths,
            ["/servicesNS/gabriel/search/saved/searches/%5BSplunk10%5D%20TestReport"],
        )
        self.assertEqual(audit.events[0]["event"], "SAVED_SEARCH_METADATA_REQUESTED")
        self.assertEqual(
            audit.events[0]["fields"]["requested_path"],
            "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
        )
        self.assertEqual(audit.events[1]["event"], "SAVED_SEARCH_METADATA_FAILED")
        self.assertEqual(
            audit.events[1]["fields"]["rest_path"],
            "/servicesNS/gabriel/search/saved/searches/%5BSplunk10%5D%20TestReport",
        )
        self.assertEqual(audit.events[1]["fields"]["error_code"], "saved_search_not_found")

    def test_broker_saved_search_metadata_lookup_resolves_bracketed_report_with_quoted_path(self) -> None:
        class BrokerClient:
            def __init__(self) -> None:
                self.paths: list[str] = []

            def _get(self, path: str) -> dict:
                self.paths.append(path)
                return {
                    "entry": [
                        {
                            "acl": {"owner": "gabriel", "app": "search", "sharing": "user"},
                            "content": {
                                "dispatch.earliest_time": "-7d@h",
                                "dispatch.latest_time": "now",
                            },
                        }
                    ]
                }

        audit = DummyAudit()
        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = audit
        state.client = BrokerClient()

        result = state.op_get_saved_search_metadata(
            {
                "path": "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
                "report_name": "[Splunk10] TestReport",
                "app": "search",
                "owner": "gabriel",
                "sharing": "user",
                "candidate_label": "exact_namespace_metadata",
                "namespace_meta": {
                    "app": "search",
                    "owner": "gabriel",
                    "sharing": "user",
                    "rest_path": "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
                },
            }
        )

        self.assertIn("meta", result)
        self.assertEqual(
            state.client.paths,
            ["/servicesNS/gabriel/search/saved/searches/%5BSplunk10%5D%20TestReport"],
        )
        self.assertEqual(audit.events[0]["event"], "SAVED_SEARCH_METADATA_REQUESTED")
        self.assertEqual(audit.events[1]["event"], "SAVED_SEARCH_METADATA_RESOLVED")
        self.assertEqual(
            audit.events[1]["fields"]["rest_path"],
            "/servicesNS/gabriel/search/saved/searches/%5BSplunk10%5D%20TestReport",
        )
        self.assertEqual(audit.events[1]["fields"]["response_status_code"], 200)

    def test_broker_snapshot_timeout_is_classified_and_logs_debug_fields(self) -> None:
        debug_events: list[tuple[str, dict[str, object]]] = []

        class SnapshotClient:
            def __init__(self) -> None:
                self._last_snapshot_meta = {
                    "rest_endpoint": "/services/search/jobs/1700000_TIMEOUT",
                    "rest_method": "GET",
                    "response_status_code": 0,
                    "response_shape": {
                        "entry_present": False,
                        "content_present": False,
                        "content_keys": "",
                    },
                    "last_error": "Network error while calling Splunk REST API: read timed out",
                }

            def get_job_status_snapshot(self, *args, **kwargs):
                del args, kwargs
                raise RuntimeError("Network error while calling Splunk REST API: read timed out")

        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = DummyAudit()
        state.client = SnapshotClient()

        with patch.object(splunk_broker_module, "debug_category_enabled", lambda category: category == "broker"):
            with patch.object(
                splunk_broker_module,
                "debug_event",
                lambda event, **fields: debug_events.append((event, fields)) or True,
            ):
                with self.assertRaises(splunk_broker_module._BrokerError) as ctx:
                    state.op_get_job_status_snapshot(
                        {
                            "sid": "1700000_TIMEOUT",
                            "request_timeout_seconds": 5,
                            "retry_count": 2,
                            "stage_name": "active_wait",
                        }
                    )

        self.assertEqual(ctx.exception.error_code, "job_status_snapshot_timeout")
        self.assertGreaterEqual(len(debug_events), 2)
        event_names = [name for name, _fields in debug_events]
        self.assertIn("GET_JOB_STATUS_SNAPSHOT_REQUESTED", event_names)
        self.assertIn("GET_JOB_STATUS_SNAPSHOT_FAILED", event_names)
        failed_fields = next(fields for name, fields in debug_events if name == "GET_JOB_STATUS_SNAPSHOT_FAILED")
        self.assertEqual(failed_fields["sid"], "1700000_TIMEOUT")
        self.assertEqual(failed_fields["retry_count"], 2)
        self.assertEqual(failed_fields["stage_name"], "active_wait")
        self.assertEqual(failed_fields["rest_method"], "GET")

    def test_broker_proxy_snapshot_passes_retry_context(self) -> None:
        class SnapshotClient:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []
                self._last_snapshot_meta = {}

            def get_job_status_snapshot(self, *args, **kwargs):
                self.calls.append(dict(kwargs))
                self._last_snapshot_meta = {
                    "rest_endpoint": "/services/search/jobs/1700000_PROXY",
                    "rest_method": "GET",
                    "response_status_code": 200,
                    "response_shape": {
                        "entry_present": True,
                        "content_present": True,
                        "content_keys": "dispatchState,isDone,isFailed",
                    },
                }
                return ("RUNNING", {"dispatchState": "RUNNING", "isDone": False, "isFailed": False})

        fake_client = SnapshotClient()
        proxy, audit, server, thread = _start_test_broker(fake_client)
        try:
            state, content = proxy.get_job_status_snapshot(
                "1700000_PROXY",
                request_timeout_seconds=5,
                retry_count=3,
                stage_name="active_wait",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

        self.assertEqual(state, "RUNNING")
        self.assertEqual(content["dispatchState"], "RUNNING")
        self.assertEqual(fake_client.calls[0]["retry_count"], 3)
        self.assertEqual(fake_client.calls[0]["stage_name"], "active_wait")
        self.assertEqual(audit.events, [])

    def test_broker_export_search_classifies_invalid_time_spec(self) -> None:
        class ExportClient:
            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                del search_query, earliest_time, timeout_seconds
                raise RuntimeError("HTTP 400 returned by Splunk REST API. Error in 'EvalCommand': malformed expression.")

        audit = DummyAudit()
        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = audit
        state.client = ExportClient()

        with self.assertRaises(splunk_broker_module._BrokerError) as ctx:
            state.op_export_search(
                {
                    "search_query": '| makeresults | eval report_earliest_epoch=relative_time(1741824000, "-7d@h")',
                    "earliest_time": "-1s",
                    "timeout_seconds": 15,
                }
            )

        self.assertEqual(ctx.exception.error_code, "invalid_time_spec")
        self.assertNotIn("unexpected_exception", str(ctx.exception))
        self.assertEqual(audit.events[0]["event"], "EXPORT_SEARCH_REQUESTED")
        self.assertEqual(audit.events[1]["event"], "EXPORT_SEARCH_FAILED")
        self.assertEqual(audit.events[1]["fields"]["error_code"] if "error_code" in audit.events[1]["fields"] else "invalid_time_spec", "invalid_time_spec")
        self.assertEqual(audit.events[1]["fields"]["response_status_code"], 400)

    def test_broker_export_search_rejects_malformed_payload(self) -> None:
        class ExportClient:
            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                del search_query, earliest_time, timeout_seconds
                return {"results": "not-a-list"}

        audit = DummyAudit()
        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = audit
        state.client = ExportClient()

        with self.assertRaises(splunk_broker_module._BrokerError) as ctx:
            state.op_export_search(
                {
                    "search_query": '| makeresults | eval report_latest_epoch=1741824000',
                    "earliest_time": "-1s",
                    "timeout_seconds": 15,
                }
            )

        self.assertEqual(ctx.exception.error_code, "malformed_rest_response")
        self.assertEqual(audit.events[0]["event"], "EXPORT_SEARCH_REQUESTED")
        self.assertEqual(audit.events[1]["event"], "EXPORT_SEARCH_FAILED")

    def test_broker_export_search_405_includes_post_request_details(self) -> None:
        class ExportClient:
            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                del search_query, earliest_time, timeout_seconds
                raise RuntimeError(
                    "HTTP 405 returned by Splunk REST API for POST /services/search/jobs/export. "
                    "Response snippet: Method Not Allowed"
                )

        audit = DummyAudit()
        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = audit
        state.client = ExportClient()

        with self.assertRaises(splunk_broker_module._BrokerError) as ctx:
            state.op_export_search(
                {
                    "search_query": '| makeresults | eval report_latest_epoch=1741824000',
                    "earliest_time": "-1s",
                    "timeout_seconds": 15,
                }
            )

        self.assertEqual(ctx.exception.error_code, "export_search_failed")
        self.assertIn("method=POST", str(ctx.exception))
        self.assertIn("endpoint=/services/search/jobs/export", str(ctx.exception))
        self.assertIn("request_format=form_body", str(ctx.exception))
        self.assertIn("status=405", str(ctx.exception))
        self.assertEqual(audit.events[0]["fields"]["rest_method"], "POST")
        self.assertEqual(audit.events[0]["fields"]["request_format"], "form_body")
        self.assertEqual(audit.events[1]["fields"]["response_status_code"], 405)
        self.assertEqual(audit.events[1]["fields"]["response_body_snippet"], "Method Not Allowed")

    def test_broker_export_search_parses_fallback_rest_response(self) -> None:
        class Response:
            status_code = 200
            text = json.dumps(
                {
                    "result": {
                        "report_earliest_epoch": "1741219200",
                        "report_latest_epoch": "1741824000",
                        "report_earliest": "2026-03-06 00:00:00 +0800",
                        "report_latest": "2026-03-13 00:00:00 +0800",
                    }
                }
            )

        class ExportClient:
            def _request(self, method: str, path: str, params=None, data=None, timeout: int = 60):
                self.method = method
                self.path = path
                self.params = dict(params or {})
                self.data = dict(data or {})
                self.timeout = timeout
                return Response()

        audit = DummyAudit()
        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = audit
        state.client = ExportClient()

        result = state.op_export_search(
            {
                "search_query": '| makeresults | eval report_earliest_epoch=relative_time(1741824000, "-7d@h"), report_latest_epoch=1741824000',
                "earliest_time": "-1s",
                "timeout_seconds": 15,
            }
        )

        self.assertEqual(result["results"]["results"][0]["report_latest_epoch"], "1741824000")
        self.assertEqual(audit.events[0]["event"], "EXPORT_SEARCH_REQUESTED")
        self.assertEqual(audit.events[1]["event"], "EXPORT_SEARCH_COMPLETED")
        self.assertTrue(audit.events[1]["fields"]["expected_fields_present"])
        self.assertEqual(state.client.method, "POST")
        self.assertEqual(state.client.path, "/services/search/jobs/export")
        self.assertEqual(state.client.data["earliest_time"], "-1s")
        self.assertEqual(state.client.data["output_mode"], "json")

    def test_broker_proxy_export_search_surfaces_specific_error_without_unexpected_exception(self) -> None:
        class ExportClient:
            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                del search_query, earliest_time, timeout_seconds
                raise RuntimeError("HTTP 400 returned by Splunk REST API. Error in 'EvalCommand': malformed expression.")

        proxy, audit, server, thread = _start_test_broker(ExportClient())
        try:
            with self.assertRaises(splunk_broker_module.LocalSplunkBrokerOperationError) as ctx:
                proxy.export_search_json(
                    '| makeresults | eval report_earliest_epoch=relative_time(1741824000, "-7d@h")',
                    earliest_time="-1s",
                    timeout_seconds=15,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

        self.assertEqual(ctx.exception.error_code, "invalid_time_spec")
        self.assertNotIn("unexpected_exception inside local Splunk broker", str(ctx.exception))
        self.assertNotIn("internal_error", str(ctx.exception))
        self.assertEqual(audit.events[1]["event"], "EXPORT_SEARCH_FAILED")

    def test_saved_search_resolution_succeeds_end_to_end_via_broker_proxy(self) -> None:
        class BrokerClient:
            def __init__(self) -> None:
                self.paths: list[str] = []
                self.queries: list[dict[str, object]] = []

            def _get(self, path: str) -> dict:
                self.paths.append(path)
                return {
                    "entry": [
                        {
                            "name": "[Splunk10] TestReport",
                            "acl": {"owner": "gabriel", "app": "search", "sharing": "user"},
                            "content": {
                                "dispatch.earliest_time": "-7d@h",
                                "dispatch.latest_time": "now",
                                "cron_schedule": "0 6 * * 1",
                                "search": "search index=main | addinfo",
                            },
                        }
                    ]
                }

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.queries.append(
                    {
                        "search_query": search_query,
                        "earliest_time": earliest_time,
                        "timeout_seconds": timeout_seconds,
                    }
                )
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1741219200",
                            "report_latest_epoch": "1741824000",
                            "report_earliest": "2026-03-06 00:00:00 +0800",
                            "report_latest": "2026-03-13 00:00:00 +0800",
                        }
                    ]
                }

        proxy, audit, server, thread = _start_test_broker(BrokerClient())
        cfg = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            logging_verbose=True,
        )
        logs: list[str] = []
        try:
            window = resolve_saved_search_reporting_window(
                proxy,
                report_id_url="/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
                report_name="[Splunk10] TestReport",
                app="search",
                username="splunk_service",
                dispatch_anchor_epoch=1741824000,
                namespace_meta={
                    "app": "search",
                    "owner": "gabriel",
                    "sharing": "user",
                    "rest_path": "/servicesNS/gabriel/search/saved/searches/[Splunk10] TestReport",
                },
                config=cfg,
                log_callback=logs.append,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

        self.assertEqual(window.resolution_path, "dispatch")
        self.assertEqual(window.dispatch_latest, "1741824000")
        self.assertEqual(window.display_range, "2026-03-06 00:00:00 +0800 to 2026-03-13 00:00:00 +0800")
        joined_logs = "\n".join(logs)
        self.assertIn("Saved search dispatch.earliest_time: -7d@h", joined_logs)
        self.assertIn("Saved search dispatch.latest_time: now", joined_logs)
        self.assertIn("Time range resolution path: dispatch.earliest_time/dispatch.latest_time", joined_logs)
        self.assertIn("Resolved earliest: 2026-03-06 00:00:00 +0800", joined_logs)
        self.assertIn("Resolved latest: 2026-03-13 00:00:00 +0800", joined_logs)
        self.assertIn("Final display range: 2026-03-06 00:00:00 +0800 to 2026-03-13 00:00:00 +0800", joined_logs)
        self.assertNotIn("unexpected_exception", joined_logs)
        self.assertNotIn("internal_error", joined_logs)
        self.assertEqual(audit.events[0]["event"], "SAVED_SEARCH_METADATA_REQUESTED")
        self.assertEqual(audit.events[1]["event"], "SAVED_SEARCH_METADATA_RESOLVED")
        self.assertEqual(audit.events[2]["event"], "EXPORT_SEARCH_REQUESTED")
        self.assertEqual(audit.events[3]["event"], "EXPORT_SEARCH_COMPLETED")
        self.assertEqual(
            audit.events[1]["fields"]["rest_path"],
            "/servicesNS/gabriel/search/saved/searches/%5BSplunk10%5D%20TestReport",
        )
        self.assertEqual(audit.events[3]["fields"]["response_status_code"], 200)
        self.assertTrue(audit.events[3]["fields"]["expected_fields_present"])

    def test_saved_search_time_range_resolution_falls_back_to_earliest_latest_fields(self) -> None:
        class RangeClient(FakeClient):
            def _get(self, path: str):
                self.last_path = path
                return {
                    "entry": [
                        {
                            "acl": {"owner": "nobody", "app": "search"},
                            "content": {
                                "earliest_time": "-1d@d",
                                "latest_time": "@d",
                                "cron_schedule": "0 6 * * *",
                            },
                        }
                    ]
                }

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.last_search_query = search_query
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1741737600",
                            "report_latest_epoch": "1741824000",
                            "report_earliest": "2026-03-12 00:00:00 +0800",
                            "report_latest": "2026-03-13 00:00:00 +0800",
                        }
                    ]
                }

        client = RangeClient(dispatch_results=[])
        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
        )

        self.assertEqual(window.resolution_path, "savedsearch_fields")
        self.assertIn('relative_time(1741824000, "-1d@d")', client.last_search_query)
        self.assertEqual(window.display_range, "2026-03-12 00:00:00 +0800 to 2026-03-13 00:00:00 +0800")

    def test_saved_search_time_range_resolution_falls_back_to_spl_tokens(self) -> None:
        class RangeClient(FakeClient):
            def _get(self, path: str):
                self.last_path = path
                return {
                    "entry": [
                        {
                            "acl": {"owner": "nobody", "app": "search"},
                            "content": {
                                "search": 'search index=main earliest="-30d@d" latest="@d" | stats count',
                                "cron_schedule": "0 6 * * *",
                            },
                        }
                    ]
                }

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.last_search_query = search_query
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1739232000",
                            "report_latest_epoch": "1741824000",
                            "report_earliest": "2026-02-11 00:00:00 +0800",
                            "report_latest": "2026-03-13 00:00:00 +0800",
                        }
                    ]
                }

        client = RangeClient(dispatch_results=[])
        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Token%20KPI",
            report_name="Token KPI",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
        )

        self.assertEqual(window.resolution_path, "spl_tokens")
        self.assertIn('relative_time(1741824000, "-30d@d")', client.last_search_query)
        self.assertEqual(window.display_range, "2026-02-11 00:00:00 +0800 to 2026-03-13 00:00:00 +0800")

    def test_saved_search_time_range_resolution_falls_back_to_cron_schedule(self) -> None:
        class RangeClient(FakeClient):
            def _get(self, path: str):
                self.last_path = path
                return {
                    "entry": [
                        {
                            "acl": {"owner": "nobody", "app": "search"},
                            "content": {
                                "cron_schedule": "0 6 * * 1",
                            },
                        }
                    ]
                }

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.last_search_query = search_query
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1740873600",
                            "report_latest_epoch": "1741478400",
                            "report_earliest": "2026-03-02 00:00:00 +0800",
                            "report_latest": "2026-03-09 00:00:00 +0800",
                        }
                    ]
                }

        client = RangeClient(dispatch_results=[])
        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Weekly%20Cron",
            report_name="Weekly Cron",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
        )

        self.assertEqual(window.resolution_path, "cron_schedule_weekly")
        self.assertIn('relative_time(1741824000, "-1w@w")', client.last_search_query)
        self.assertEqual(window.display_range, "2026-03-02 00:00:00 +0800 to 2026-03-09 00:00:00 +0800")

    def test_list_saved_searches_uses_lightweight_metadata_request(self) -> None:
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.searches_loaded = _NullSignal()
        client.error = _NullSignal()
        client.finished = _NullSignal()
        client._last_saved_search_list_meta = {}
        client._last_saved_search_namespace_meta = []
        captured: dict[str, object] = {}

        def fake_get(path: str, params=None):
            captured["path"] = path
            captured["params"] = params
            return {
                "entry": [
                    {
                        "id": "https://splunk.example:8089/servicesNS/gabriel/search/saved/searches/Scheduled%20Report",
                        "name": "Scheduled Report",
                        "acl": {"owner": "gabriel", "app": "search", "sharing": "user"},
                        "content": {
                            "is_scheduled": "1",
                            "disabled": "0",
                            "action.email": "1",
                        },
                    },
                    {
                        "id": "id://disabled",
                        "name": "Disabled Report",
                        "content": {
                            "is_scheduled": "1",
                            "disabled": "1",
                        },
                    },
                ]
            }

        client._get = fake_get  # type: ignore[method-assign]

        ids, names, flags = splunk_engine.SplunkClient.list_saved_searches(client, "search")

        params = dict(captured.get("params") or {})
        self.assertEqual(captured.get("path"), "/servicesNS/-/search/saved/searches")
        self.assertEqual(params.get("search"), "is_scheduled=1 disabled=0")
        self.assertIn("is_scheduled", list(params.get("f") or []))
        self.assertEqual(ids, ["https://splunk.example:8089/servicesNS/gabriel/search/saved/searches/Scheduled%20Report"])
        self.assertEqual(names, ["Scheduled Report"])
        self.assertEqual(flags, [True])
        self.assertEqual(
            client._last_saved_search_namespace_meta,
            [
                {
                    "app": "search",
                    "owner": "gabriel",
                    "sharing": "user",
                    "rest_path": "/servicesNS/gabriel/search/saved/searches/Scheduled%20Report",
                    "scope": "user-scoped",
                }
            ],
        )

    def test_splunk_client_export_search_uses_post_form_body(self) -> None:
        class Response:
            status_code = 200
            text = json.dumps(
                {
                    "result": {
                        "report_earliest_epoch": "1772726400",
                        "report_latest_epoch": "1773158400",
                        "report_earliest": "2026-03-06 00:00:00 +0800",
                        "report_latest": "2026-03-11 00:00:00 +0800",
                    }
                }
            )

        class Session:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                return Response()

        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://127.0.0.1:8089"
        client._auth_header = "Splunk test-session"
        client.session = Session()

        result = splunk_engine.SplunkClient.export_search_json(
            client,
            '| makeresults | eval report_latest_epoch=1773158400',
            earliest_time="-1s",
            timeout_seconds=15,
        )

        call = client.session.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["url"], "https://127.0.0.1:8089/services/search/jobs/export")
        self.assertEqual(call["data"]["earliest_time"], "-1s")
        self.assertEqual(call["data"]["output_mode"], "json")
        self.assertEqual(call["headers"]["Authorization"], "Splunk test-session")
        self.assertEqual(result["results"][0]["report_latest_epoch"], "1773158400")

    def test_splunk_client_snapshot_uses_field_filtered_get(self) -> None:
        class Response:
            status_code = 200
            text = json.dumps(
                {
                    "entry": [
                        {
                            "content": {
                                "dispatchState": "RUNNING",
                                "isDone": False,
                                "isFailed": False,
                            }
                        }
                    ]
                }
            )

            @staticmethod
            def json():
                return {
                    "entry": [
                        {
                            "content": {
                                "dispatchState": "RUNNING",
                                "isDone": False,
                                "isFailed": False,
                            }
                        }
                    ]
                }

        class SnapshotHarness:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []
                self._last_snapshot_meta: dict[str, object] = {}

            def _request(self, method: str, path: str, params=None, data=None, timeout: int = 60):
                del data
                self.calls.append(
                    {
                        "method": method,
                        "path": path,
                        "params": params,
                        "timeout": timeout,
                    }
                )
                return Response()

        client = SnapshotHarness()
        state, content = splunk_engine.SplunkClient.get_job_status_snapshot(
            client,
            "1700000_STATUS",
            request_timeout_seconds=5,
            retry_count=2,
            stage_name="active_wait",
        )

        self.assertEqual(state, "RUNNING")
        self.assertEqual(content["dispatchState"], "RUNNING")
        self.assertEqual(client.calls[0]["method"], "GET")
        self.assertEqual(client.calls[0]["path"], "/services/search/jobs/1700000_STATUS")
        self.assertEqual(client.calls[0]["params"]["output_mode"], "json")
        self.assertEqual(client.calls[0]["params"]["count"], 0)
        self.assertEqual(
            client.calls[0]["params"]["f"],
            ["dispatchState", "isDone", "isFailed"],
        )
        self.assertEqual(client._last_snapshot_meta["rest_method"], "GET")
        self.assertEqual(client._last_snapshot_meta["response_status_code"], 200)
        self.assertTrue(client._last_snapshot_meta["response_shape"]["content_present"])

    def test_splunk_client_snapshot_probe_emits_diagnostics_and_timing_breakdown(self) -> None:
        class Response:
            status_code = 200
            text = json.dumps(
                {
                    "entry": [
                        {
                            "content": {
                                "dispatchState": "DONE",
                                "isDone": True,
                                "isFailed": False,
                            }
                        }
                    ]
                }
            )

            @staticmethod
            def json():
                return {
                    "entry": [
                        {
                            "content": {
                                "dispatchState": "DONE",
                                "isDone": True,
                                "isFailed": False,
                            }
                        }
                    ]
                }

        class SnapshotHarness:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []
                self._last_snapshot_meta: dict[str, object] = {}
                self._snapshot_probe_enabled = True

            def _request(self, method: str, path: str, params=None, data=None, timeout: int = 60):
                del data
                self.calls.append(
                    {
                        "method": method,
                        "path": path,
                        "params": params,
                        "timeout": timeout,
                    }
                )
                return Response()

        debug_events: list[tuple[str, dict[str, object]]] = []
        client = SnapshotHarness()
        with patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, fields)) or True,
        ):
            state, content = splunk_engine.SplunkClient.get_job_status_snapshot(
                client,
                "1700000_STATUS_OK",
                request_timeout_seconds=5,
                retry_count=2,
                stage_name="active_wait",
            )

        self.assertEqual(state, "SUCCESS")
        self.assertEqual(content["dispatchState"], "DONE")
        self.assertEqual(
            [event for event, _fields in debug_events],
            [
                "SNAPSHOT_PROBE_REQUESTED",
                "SNAPSHOT_PROBE_REST_STARTED",
                "SNAPSHOT_PROBE_REST_COMPLETED",
                "SNAPSHOT_PROBE_PARSE_COMPLETED",
                "SNAPSHOT_PROBE_FINAL",
            ],
        )
        meta = client._last_snapshot_meta
        self.assertIn("time_before_rest_call_ms", meta)
        self.assertIn("splunk_rest_elapsed_ms", meta)
        self.assertIn("parse_elapsed_ms", meta)
        self.assertIn("return_to_engine_ms", meta)
        self.assertIn("total_elapsed_ms", meta)
        self.assertEqual(meta["final_classified_state"], "SUCCESS")
        self.assertEqual(client.calls[0]["params"]["f"], ["dispatchState", "isDone", "isFailed"])

    def test_splunk_client_snapshot_probe_classifies_sid_not_found(self) -> None:
        class SnapshotHarness:
            def __init__(self) -> None:
                self._last_snapshot_meta: dict[str, object] = {}
                self._snapshot_probe_enabled = True

            def _request(self, method: str, path: str, params=None, data=None, timeout: int = 60):
                del method, path, params, data, timeout
                raise RuntimeError("HTTP 404 returned by Splunk REST API.")

        debug_events: list[tuple[str, dict[str, object]]] = []
        client = SnapshotHarness()
        with patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, fields)) or True,
        ):
            with self.assertRaises(RuntimeError):
                splunk_engine.SplunkClient.get_job_status_snapshot(
                    client,
                    "1700000_STATUS_404",
                    request_timeout_seconds=5,
                    retry_count=1,
                    stage_name="active_wait",
                )

        self.assertEqual(client._last_snapshot_meta["failure_classification"], "sid_not_found")
        self.assertEqual(debug_events[-1][0], "SNAPSHOT_PROBE_FINAL")
        self.assertEqual(debug_events[-1][1]["final_classified_state"], "ERROR")
        self.assertEqual(debug_events[-1][1]["failure_classification"], "sid_not_found")

    def test_splunk_client_dispatch_saved_search_uses_one_shot_request_and_returns_sid_from_location(self) -> None:
        class SharedSession:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                raise AssertionError("dispatch_saved_search should not reuse the shared client session")

        class Response:
            status_code = 201

            def __init__(self) -> None:
                self.headers = {
                    "Location": "/services/search/jobs/1700000_dispatch_sid",
                }
                self.closed = False
                self.elapsed = type("_Elapsed", (), {"total_seconds": staticmethod(lambda: 0.123)})()

            @property
            def text(self):
                raise AssertionError("response body should not be read when Location header already provides the SID")

            def close(self) -> None:
                self.closed = True

        request_calls: list[dict[str, object]] = []

        def _request(**kwargs):
            request_calls.append(dict(kwargs))
            return Response()

        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://127.0.0.1:8089"
        client._auth_header = "Splunk test-session"
        client.verify_ssl = False
        client.session = SharedSession()
        client._last_dispatch_meta = {}

        with patch.object(splunk_engine.requests, "request", _request):
            ok, sid, error = splunk_engine.SplunkClient.dispatch_saved_search(
                client,
                "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                earliest="1772726400",
                latest="1773158400",
                trigger_actions=True,
            )

        self.assertTrue(ok)
        self.assertEqual(sid, "1700000_dispatch_sid")
        self.assertEqual(error, "")
        self.assertEqual(client.session.calls, [])
        self.assertEqual(len(request_calls), 1)
        call = request_calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["timeout"], (10, 30))
        self.assertEqual(call["headers"]["Authorization"], "Splunk test-session")
        self.assertEqual(call["headers"]["Connection"], "close")
        self.assertFalse(call["allow_redirects"])
        self.assertFalse(call["verify"])
        self.assertEqual(call["data"]["output_mode"], "json")
        self.assertEqual(call["data"]["trigger_actions"], 1)
        self.assertEqual(call["data"]["dispatch.earliest_time"], "1772726400")
        self.assertEqual(call["data"]["dispatch.latest_time"], "1773158400")
        self.assertEqual(client._last_dispatch_meta["sid_source"], "location_header")
        self.assertEqual(client._last_dispatch_meta["sid"], "1700000_dispatch_sid")
        self.assertEqual(client._last_dispatch_meta["transport_mode"], "oneshot_request")

    def test_splunk_client_dispatch_saved_search_falls_back_to_json_body_when_location_missing(self) -> None:
        class Response:
            status_code = 201

            def __init__(self) -> None:
                self.headers = {}
                self.closed = False
                self.elapsed = type("_Elapsed", (), {"total_seconds": staticmethod(lambda: 0.111)})()
                self.text = '{"sid":"1700000_dispatch_sid_json"}'

            def close(self) -> None:
                self.closed = True

        def _request(**kwargs):
            del kwargs
            return Response()

        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://127.0.0.1:8089"
        client._auth_header = "Splunk test-session"
        client.verify_ssl = False
        client.session = object()
        client._last_dispatch_meta = {}

        with patch.object(splunk_engine.requests, "request", _request):
            ok, sid, error = splunk_engine.SplunkClient.dispatch_saved_search(
                client,
                "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                earliest="1772726400",
                latest="1773158400",
                trigger_actions=True,
            )

        self.assertTrue(ok)
        self.assertEqual(sid, "1700000_dispatch_sid_json")
        self.assertEqual(error, "")
        self.assertEqual(client._last_dispatch_meta["sid_source"], "json_body")

    def test_broker_dispatch_saved_search_writes_debug_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                configure_tool_logging(
                    exe_dir=tmpdir,
                    config={
                        "runtime_log_enabled": True,
                        "runtime_log_path": os.path.join("Internal", "logs", "runtime.log"),
                        "debug_log_enabled": True,
                        "debug_log_path": os.path.join("Internal", "logs", "debug.log"),
                        "debug_broker_enabled": True,
                        "debug_dispatch_enabled": True,
                        "debug_rest_enabled": False,
                        "debug_tracebacks_enabled": True,
                    },
                )

                class DispatchClient:
                    def __init__(self) -> None:
                        self._last_dispatch_meta = {}

                    def dispatch_saved_search(self, *args, **kwargs):
                        del args, kwargs
                        self._last_dispatch_meta = {
                            "request_body_summary": "{\"dispatch.latest_time\":\"1773158400\",\"output_mode\":\"json\"}",
                            "request_start_time": "2026-03-14T00:00:00Z",
                            "connect_timeout_seconds": 10,
                            "read_timeout_seconds": 30,
                            "response_status_code": 201,
                            "response_headers_elapsed_ms": 95,
                            "response_body_read_elapsed_ms": 0,
                            "json_parse_elapsed_ms": 0,
                            "post_sid_return_work_ms": 0,
                            "sid": "sid-unit-001",
                            "sid_source": "location_header",
                            "response_location": "/services/search/jobs/sid-unit-001",
                        }
                        return True, "sid-unit-001", ""

                audit = DummyAudit()
                state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
                state.audit = audit
                state.client = DispatchClient()

                result = state.op_dispatch_saved_search(
                    {
                        "report_id_url": "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                        "earliest": "1772726400",
                        "latest": "1773158400",
                        "trigger_actions": True,
                    }
                )

                self.assertTrue(result["ok"])
                self.assertEqual(result["sid"], "sid-unit-001")
                debug_path = os.path.join(tmpdir, "Internal", "logs", "debug.log")
                with open(debug_path, "r", encoding="utf-8") as f:
                    debug_text = f.read()
                self.assertIn("DISPATCH_SAVED_SEARCH_REQUESTED", debug_text)
                self.assertIn("DISPATCH_SAVED_SEARCH_RESPONSE_HEADERS", debug_text)
                self.assertIn("DISPATCH_SAVED_SEARCH_SID_PARSED", debug_text)
                self.assertIn("DISPATCH_SAVED_SEARCH_COMPLETED", debug_text)
                self.assertIn("sid_source=location_header", debug_text)
                self.assertIn("rest_endpoint=/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport/dispatch", debug_text)
            finally:
                shutdown_tool_logging()

    def test_run_postdispatch_search_fallback_uses_post_form_body(self) -> None:
        class Response:
            text = json.dumps(
                {
                    "result": {
                        "report_earliest_epoch": "1772726400",
                        "report_latest_epoch": "1773158400",
                        "report_earliest": "2026-03-06 00:00:00 +0800",
                        "report_latest": "2026-03-11 00:00:00 +0800",
                    }
                }
            )

        class FallbackClient:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def _request(self, method: str, path: str, params=None, data=None, timeout: int = 60):
                self.calls.append(
                    {
                        "method": method,
                        "path": path,
                        "params": dict(params or {}),
                        "data": dict(data or {}),
                        "timeout": timeout,
                    }
                )
                return Response()

        client = FallbackClient()
        result = splunk_engine._run_postdispatch_search(
            client,
            '| makeresults | eval report_latest_epoch=1773158400',
            earliest_time="-1s",
            timeout_seconds=15,
        )

        call = client.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["path"], "/services/search/jobs/export")
        self.assertEqual(call["data"]["earliest_time"], "-1s")
        self.assertEqual(call["data"]["output_mode"], "json")
        self.assertEqual(result["results"][0]["report_latest_epoch"], "1773158400")

    def test_run_postdispatch_search_prefixes_search_for_internal_queries(self) -> None:
        class RecordingClient:
            def __init__(self) -> None:
                self.query = ""

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                self.query = search_query
                return {"results": []}

        client = RecordingClient()
        splunk_engine._run_postdispatch_search(
            client,
            'index=_internal source="mergeReport_alert.log" sid=1700000_TEST',
            earliest_time="-900s",
            timeout_seconds=15,
        )

        self.assertEqual(
            client.query,
            'search index=_internal source="mergeReport_alert.log" sid=1700000_TEST',
        )

    def test_saved_search_namespace_resolver_uses_user_scope_metadata(self) -> None:
        class NamespaceClient(FakeClient):
            def _get(self, path: str):
                self.paths.append(path)
                if path == "/servicesNS/gabriel/search/saved/searches/TestReport":
                    return {
                        "entry": [
                            {
                                "acl": {"owner": "gabriel", "app": "search", "sharing": "user"},
                                "content": {
                                    "earliest_time": "-1d@d",
                                    "latest_time": "@d",
                                },
                            }
                        ]
                    }
                return {"entry": []}

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1741737600",
                            "report_latest_epoch": "1741824000",
                            "report_earliest": "2026-03-12 00:00:00 +0800",
                            "report_latest": "2026-03-13 00:00:00 +0800",
                        }
                    ]
                }

        client = NamespaceClient(dispatch_results=[])
        client.paths = []
        cfg = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            logging_verbose=True,
        )
        logs: list[str] = []

        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/nobody/search/saved/searches/TestReport",
            report_name="TestReport",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
            namespace_meta={
                "app": "search",
                "owner": "gabriel",
                "sharing": "user",
                "rest_path": "/servicesNS/gabriel/search/saved/searches/TestReport",
            },
            config=cfg,
            log_callback=logs.append,
        )

        self.assertEqual(window.owner, "gabriel")
        self.assertEqual(client.paths[0], "/servicesNS/gabriel/search/saved/searches/TestReport")
        self.assertIn("[Debug] Saved search resolved from user-scoped namespace", logs)
        self.assertIn("[Debug] Time range resolution path: earliest_time/latest_time", logs)

    def test_saved_search_namespace_resolver_uses_app_scope_metadata(self) -> None:
        class NamespaceClient(FakeClient):
            def _get(self, path: str):
                self.paths.append(path)
                if path == "/servicesNS/nobody/prod_app/saved/searches/ProdReport":
                    return {
                        "entry": [
                            {
                                "acl": {"owner": "nobody", "app": "prod_app", "sharing": "app"},
                                "content": {
                                    "earliest_time": "-1w@w",
                                    "latest_time": "@w",
                                },
                            }
                        ]
                    }
                return {"entry": []}

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1740873600",
                            "report_latest_epoch": "1741478400",
                            "report_earliest": "2026-03-02 00:00:00 +0800",
                            "report_latest": "2026-03-09 00:00:00 +0800",
                        }
                    ]
                }

        client = NamespaceClient(dispatch_results=[])
        client.paths = []
        cfg = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            logging_verbose=True,
        )
        logs: list[str] = []

        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="/servicesNS/gabriel/search/saved/searches/ProdReport",
            report_name="ProdReport",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
            namespace_meta={
                "app": "prod_app",
                "owner": "nobody",
                "sharing": "app",
                "rest_path": "/servicesNS/nobody/prod_app/saved/searches/ProdReport",
            },
            config=cfg,
            log_callback=logs.append,
        )

        self.assertEqual(window.app, "prod_app")
        self.assertEqual(client.paths[0], "/servicesNS/nobody/prod_app/saved/searches/ProdReport")
        self.assertIn("[Debug] Saved search resolved from app-scoped namespace", logs)

    def test_saved_search_namespace_resolver_falls_back_when_metadata_incomplete(self) -> None:
        class NamespaceClient(FakeClient):
            def _get(self, path: str):
                self.paths.append(path)
                if path == "/servicesNS/gabriel/search/saved/searches/Fallback%20Report":
                    return {
                        "entry": [
                            {
                                "acl": {"owner": "gabriel", "app": "search", "sharing": "user"},
                                "content": {
                                    "search": 'search index=main earliest="-30d@d" latest="@d" | stats count',
                                },
                            }
                        ]
                    }
                return {"entry": []}

            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                return {
                    "results": [
                        {
                            "report_earliest_epoch": "1739232000",
                            "report_latest_epoch": "1741824000",
                            "report_earliest": "2026-02-11 00:00:00 +0800",
                            "report_latest": "2026-03-13 00:00:00 +0800",
                        }
                    ]
                }

        client = NamespaceClient(dispatch_results=[])
        client.paths = []

        window = resolve_saved_search_reporting_window(
            client,
            report_id_url="",
            report_name="Fallback Report",
            app="search",
            username="splunk_service",
            dispatch_anchor_epoch=1741824000,
            namespace_meta={
                "app": "search",
                "owner": "gabriel",
            },
        )

        self.assertEqual(window.resolution_path, "spl_tokens")
        self.assertIn("/servicesNS/gabriel/search/saved/searches/Fallback%20Report", client.paths)

    def test_run_dispatch_multi_isolates_saved_search_resolution_failure(self) -> None:
        class LazyClient(FakeClient):
            def __init__(self):
                super().__init__(dispatch_results=[])
                self.dispatch_log = _NullSignal()
                self.error = _NullSignal()
                self.finished = _NullSignal()

            def _get(self, path: str):
                return {
                    "entry": [
                        {
                            "acl": {"owner": "nobody", "app": "search"},
                            "content": {
                                "search": "search index=main",
                                "action.email": "1",
                            },
                        }
                    ]
                }

        client = LazyClient()
        successful_window = build_manual_reporting_window(
            "Healthy Report",
            datetime(2026, 3, 2, 0, 0, 0),
            datetime(2026, 3, 9, 0, 0, 0),
        )
        dispatched_reports: list[str] = []

        def fake_run_dispatch_single(*args, **kwargs):
            report_name = str(kwargs.get("report_name") or "")
            regen_context = kwargs.get("regen_context")
            resolved_window = kwargs.get("resolved_window")
            dispatched_reports.append(report_name)
            if regen_context is not None:
                regen_context.add_slice(
                    report_name=report_name,
                    slice_label="single run",
                    slice_index=1,
                    slice_total=1,
                    earliest=str(getattr(resolved_window, "report_earliest", "") or ""),
                    latest=str(getattr(resolved_window, "report_latest", "") or ""),
                    sid=f"SID_{report_name.replace(' ', '_')}",
                    status="OK",
                    outcome_code="VERIFIED_SUCCESS",
                    display_range=str(getattr(resolved_window, "display_range", "") or ""),
                    time_source="savedsearch",
                )
            return [f"Dispatched {report_name}"]

        config = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            ack_enabled=False,
            postdispatch_config={"enabled": False},
        )

        with patch.object(
            splunk_engine,
            "resolve_saved_search_reporting_window",
            side_effect=[RuntimeError("bad range"), successful_window],
        ), patch.object(splunk_engine, "run_dispatch_single", side_effect=fake_run_dispatch_single):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=[
                    "/servicesNS/nobody/search/saved/searches/Broken%20Report",
                    "/servicesNS/nobody/search/saved/searches/Healthy%20Report",
                ],
                report_names=["Broken Report", "Healthy Report"],
                selected_indices=[0, 1],
                frequency="Daily",
                start=datetime(2026, 3, 13, 0, 0, 0),
                end=datetime(2026, 3, 13, 0, 0, 0),
                no_change=True,
                config=config,
                app="search",
            )

        joined = "\n".join(logs)
        self.assertIn("Saved-search time-range resolution failed for 'Broken Report': bad range", joined)
        self.assertIn("Dispatched Healthy Report", joined)
        self.assertEqual(dispatched_reports, ["Healthy Report"])

    def test_run_dispatch_multi_fails_closed_when_classification_metadata_unavailable(self) -> None:
        client = FakeClient(dispatch_results=[(True, "1700000_SHOULD_NOT_DISPATCH", "")])
        config = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            ack_enabled=False,
            postdispatch_config={"enabled": False},
        )
        runtime_events: list[str] = []
        debug_events: list[tuple[str, dict[str, object]]] = []

        with patch.object(
            splunk_engine,
            "tool_runtime_log",
            lambda message, level="INFO": runtime_events.append(f"{level}:{message}") or True,
        ), patch.object(
            splunk_engine,
            "tool_debug_category_enabled",
            lambda category: str(category).strip().lower() == "dispatch",
        ), patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, dict(fields))) or True,
        ), patch.object(
            splunk_engine,
            "_fetch_saved_search_entry",
            side_effect=ReportClassificationResolutionError("metadata unavailable for classification"),
        ):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport"],
                report_names=["[Splunk10] TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 9, 0, 0, 0),
                end=datetime(2026, 3, 14, 0, 0, 0),
                no_change=False,
                config=config,
                app="search",
                report_namespace_meta=[{"app": "search", "owner": "skyred5", "sharing": "user"}],
            )

        joined = "\n".join(logs)
        self.assertIn("Report classification failed for '[Splunk10] TestReport': metadata unavailable for classification", joined)
        self.assertEqual(len(client.dispatch_results), 1)
        event_names = [name for name, _fields in debug_events]
        self.assertIn("REPORT_CLASSIFICATION_FAILED", event_names)
        runtime_joined = "\n".join(runtime_events)
        self.assertIn("REPORT_CLASSIFICATION_FAILED", runtime_joined)

    def test_postdispatch_stage2_classifies_success_failure_and_pending(self) -> None:
        context = RegenContext(
            run_id="regen-test-stage2",
            report_names=["Merge Report", "Native Report", "Pending Report"],
            app="search",
            operator="tester",
            hostname="host1",
            start_time_sgt=datetime(2026, 3, 10, 9, 0, 0),
            end_time_sgt=datetime(2026, 3, 10, 9, 5, 0),
        )
        context.add_slice(
            report_name="Merge Report",
            slice_label="single run",
            sid="1700000_MERGEOK",
            status="PENDING",
            verification_mode=VERIFICATION_MODE_MERGEREPORT,
            verification_source=VERIFICATION_SOURCE_MERGEREPORT,
        )
        context.add_slice(
            report_name="Native Report",
            slice_label="single run",
            sid="1700000_NATIVEFAIL",
            status="PENDING",
            verification_mode=VERIFICATION_MODE_NATIVE,
            verification_source=VERIFICATION_SOURCE_NATIVE,
        )
        context.add_slice(
            report_name="Pending Report",
            slice_label="single run",
            sid="1700000_PENDING",
            status="PENDING",
            verification_mode=VERIFICATION_MODE_NATIVE,
            verification_source=VERIFICATION_SOURCE_NATIVE,
        )

        class Stage2Client(FakeClient):
            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                if "mergeReport_alert.log" in search_query:
                    return {
                        "results": [
                            {
                                "_raw": (
                                    "2026-03-12 12:00:00,000 INFO Search Name=Daily, "
                                    "SID=1700000_MERGEOK, Action=Email sent"
                                )
                            },
                            {
                                "_raw": (
                                    "2026-03-12 12:00:01,000 INFO Search Name=Daily, "
                                    "SID=1700000_MERGEOK, App excution completed"
                                )
                            }
                        ]
                    }
                if 'source="splunkd.log"' in search_query:
                    return {"results": []}
                if "python.log" in search_query:
                    return {
                        "results": [
                            {
                                "_raw": (
                                    "2026-03-12 12:00:01,000 ERROR sid=1700000_NATIVEFAIL "
                                    "SMTPException connection timeout"
                                )
                            }
                        ]
                    }
                return {"results": []}

        config = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            postdispatch_config={
                "enabled": True,
                "merge_report_enabled": True,
                "native_email_enabled": True,
                "stage2_enabled": True,
                "poll_seconds": 1,
                "lookback_seconds": 900,
                "merge_report_timeout_seconds": 1,
                "native_email_timeout_seconds": 1,
                "max_verification_duration_seconds": 1,
                "pending_on_inconclusive": True,
                "native_email_strict_success": False,
            },
        )
        client = Stage2Client(dispatch_results=[])
        logs = _verify_postdispatch_slices(client, context, config=config)

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[1].status, "FAILED")
        self.assertEqual(context.slices[2].status, "PENDING")
        joined = "\n".join(logs)
        self.assertIn("Stage 2 result: Merge Report single run -> OK", joined)
        self.assertIn("Stage 2 result: Native Report single run -> FAILED", joined)
        self.assertIn("Post-dispatch verification timeout reached", joined)

    def test_postdispatch_stage2_emits_verification_timeline_summary_when_diagnostics_enabled(self) -> None:
        context = RegenContext(
            run_id="regen-test-stage2-diag",
            report_names=["Merge Report"],
            app="search",
            operator="tester",
            hostname="host1",
            start_time_sgt=datetime(2026, 3, 10, 9, 0, 0),
            end_time_sgt=datetime(2026, 3, 10, 9, 5, 0),
        )
        timeline = splunk_engine._new_verification_timeline(
            sid="1700000_MERGEDIAG",
            verification_mode=VERIFICATION_MODE_MERGEREPORT,
        )
        context.add_slice(
            report_name="Merge Report",
            slice_label="single run",
            sid="1700000_MERGEDIAG",
            status="PENDING",
            verification_mode=VERIFICATION_MODE_MERGEREPORT,
            verification_source=VERIFICATION_SOURCE_MERGEREPORT,
            verification_timeline=timeline,
        )

        class Stage2Client(FakeClient):
            def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
                del earliest_time, timeout_seconds
                if "mergeReport_alert.log" in search_query:
                    return {
                        "results": [
                            {
                                "_raw": (
                                    "2026-03-12 12:00:00,000 INFO Search Name=Daily, "
                                    "SID=1700000_MERGEDIAG, Action=Xlsx file created"
                                )
                            },
                            {
                                "_raw": (
                                    "2026-03-12 12:00:02,000 INFO Search Name=Daily, "
                                    "SID=1700000_MERGEDIAG, Action=Email sent"
                                )
                            },
                            {
                                "_raw": (
                                    "2026-03-12 12:00:03,000 INFO Search Name=Daily, "
                                    "SID=1700000_MERGEDIAG, App excution completed"
                                )
                            },
                        ]
                    }
                if 'source="splunkd.log"' in search_query:
                    return {"results": []}
                return {"results": []}

        config = SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            postdispatch_config={
                "enabled": True,
                "merge_report_enabled": True,
                "native_email_enabled": False,
                "stage2_enabled": True,
                "poll_seconds": 1,
                "lookback_seconds": 900,
                "merge_report_timeout_seconds": 1,
                "native_email_timeout_seconds": 1,
                "max_verification_duration_seconds": 1,
                "pending_on_inconclusive": True,
                "native_email_strict_success": False,
            },
            diagnostics_config={
                "snapshot_probe_enabled": True,
            },
        )
        client = Stage2Client(dispatch_results=[])
        debug_events: list[tuple[str, dict[str, object]]] = []
        with patch.object(
            splunk_engine,
            "tool_debug_event",
            lambda event, **fields: debug_events.append((event, fields)) or True,
        ):
            logs = _verify_postdispatch_slices(client, context, config=config)

        self.assertEqual(context.slices[0].status, "OK")
        event_names = [event for event, _fields in debug_events]
        self.assertIn("MERGEREPORT_EVIDENCE_DETECTED", event_names)
        self.assertIn("MERGEREPORT_ARTIFACT_DETECTED", event_names)
        self.assertIn("VERIFICATION_TIMELINE_SUMMARY", event_names)
        summary_fields = next(fields for event, fields in debug_events if event == "VERIFICATION_TIMELINE_SUMMARY")
        self.assertEqual(summary_fields["sid"], "1700000_MERGEDIAG")
        self.assertEqual(summary_fields["final_status"], "OK")
        self.assertEqual(summary_fields["final_status_source"], "stage2_mergereport")
        self.assertTrue(summary_fields["first_mergereport_evidence_time"])
        self.assertIn("Stage 2 result: Merge Report single run -> OK", "\n".join(logs))

    def test_batch_controller_cancel_marks_current_slice_cancelled(self) -> None:
        context = RegenContext(
            run_id="regen-test-cancel",
            report_names=["Daily KPI"],
            app="search",
            operator="tester",
            hostname="host1",
            start_time_sgt=datetime(2026, 3, 10, 9, 0, 0),
            end_time_sgt=datetime(2026, 3, 10, 9, 5, 0),
        )
        controller = splunk_engine.DispatchBatchController()

        class CancelDuringPollClient(FakeClient):
            def __init__(self):
                super().__init__(
                    dispatch_results=[(True, "1700000_CANCELME", "")],
                    snapshot_results=[("RUNNING", {"dispatchState": "RUNNING"})],
                )
                self.cancel_calls = []

            def get_job_status_snapshot(self, *args, **kwargs):
                controller.request_cancel()
                return super().get_job_status_snapshot(*args, **kwargs)

            def cancel_search_job(self, sid: str) -> bool:
                self.cancel_calls.append(sid)
                return True

        client = CancelDuringPollClient()
        monotonic_tick = {"t": 0.0}

        def _slow_monotonic() -> float:
            monotonic_tick["t"] += 0.4
            return monotonic_tick["t"]

        with patch.object(splunk_engine.time, "monotonic", _slow_monotonic):
            with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
                run_dispatch_single(
                    client=client,
                    report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                    report_name="Daily KPI",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 2, 0, 0, 0),
                    no_change=True,
                    wait_seconds=5,
                    poll_interval=1,
                    regen_context=context,
                    resolved_window=build_manual_reporting_window(
                        "Daily KPI",
                        datetime(2026, 3, 1, 0, 0, 0),
                        datetime(2026, 3, 2, 0, 0, 0),
                    ),
                    batch_controller=controller,
                )

        self.assertEqual(context.slices[0].status, "CANCELLED")
        self.assertEqual(context.slices[0].outcome_code, "BATCH_CANCELLED")


if __name__ == "__main__":
    unittest.main()
