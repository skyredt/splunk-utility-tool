from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

import splunk_engine
from splunk_engine import (
    RegenContext,
    SplunkConfig,
    _build_run_summary_lines,
    _reconcile_pending_slices,
    resolve_broker_request_timeout_seconds,
    resolve_status_check_poll_seconds,
    resolve_status_check_timeout_seconds,
    run_dispatch_single,
    send_ack_summary_email,
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
        )
        for key, value in overrides.items():
            setattr(config, key, value)
        return config

    def test_dispatch_with_sid_and_status_timeout_becomes_pending(self) -> None:
        context = self._make_context()
        client = FakeClient(
            dispatch_results=[(True, "1700000_ABC123", "")],
            status_results=[RuntimeError("Local Splunk broker timed out while processing the request.")],
        )

        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            wait_seconds=30,
            regen_context=context,
        )

        self.assertEqual(len(context.slices), 1)
        record = context.slices[0]
        self.assertEqual(record.status, "PENDING")
        self.assertEqual(record.outcome_code, "DISPATCHED_PENDING")
        self.assertEqual(record.sid, "1700000_ABC123")
        self.assertIn("30 seconds", record.error)
        self.assertIn("PENDING (sid=1700000_ABC123)", "\n".join(logs))

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
        )

        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[0].outcome_code, "DISPATCH_FAILED")

    def test_explicit_failed_state_is_failed(self) -> None:
        context = self._make_context()
        client = FakeClient(
            dispatch_results=[(True, "1700000_DEF456", "")],
            status_results=[("FAILED", {"dispatchState": "FAILED"})],
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
            status_results=[
                ("TIMEOUT", {"dispatchState": "RUNNING"}),
                ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
            ],
        )

        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 3, 0, 0, 0),
            no_change=False,
            wait_seconds=30,
            regen_context=context,
        )

        self.assertEqual(len(context.slices), 2)
        self.assertEqual(context.slices[0].status, "PENDING")
        self.assertEqual(context.slices[1].status, "OK")
        self.assertEqual(context.slices[1].sid, "1700000_OK002")
        self.assertIn("Continuing to next slice.", "\n".join(logs))

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
        self.assertIn("Pending slice resolved to OK", "\n".join(logs))

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

        self.assertEqual(cfg.merge_report_timeout_seconds, 333)
        self.assertTrue(cfg.ack_enabled)
        self.assertTrue(cfg.ack_on_pending)
        self.assertTrue(cfg.ack_on_unknown)
        self.assertIsNotNone(cfg.dispatch_config)
        self.assertEqual(cfg.dispatch_config["per_slice_wait_seconds"], 42)
        self.assertTrue(cfg.dispatch_config["continue_on_timeout"])
        self.assertEqual(cfg.dispatch_config["timeout_result"], "pending")
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


if __name__ == "__main__":
    unittest.main()
