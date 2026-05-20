from __future__ import annotations

import threading
import unittest
from datetime import datetime
from unittest.mock import patch

import splunk_engine
from splunk_engine import (
    RegenContext,
    SplunkConfig,
    _finalize_pending_no_sid_dispatches,
    _format_slice_user_summary_line,
    _reconcile_pending_slices,
    run_dispatch_single,
    send_ack_summary_email,
)


class _NullSignal:
    def emit(self, *args, **kwargs) -> None:
        return


class SequencedSliceClient:
    def __init__(self) -> None:
        self.dispatch_results = [
            (True, "SID_SLICE_1", ""),
            (True, "SID_SLICE_2", ""),
        ]
        self.snapshot_results = {
            "SID_SLICE_1": [
                RuntimeError("Local Splunk broker timed out while processing the request (op=get_job_status_snapshot, timeout=7s)."),
                ("RUNNING", {"dispatchState": "RUNNING", "isDone": False}),
                ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
            ],
            "SID_SLICE_2": [
                ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
            ],
        }
        self.snapshot_calls: list[dict[str, object]] = []
        self.reset_transport_calls = 0
        self.close_transport_calls = 0
        self.dispatch_log = _NullSignal()
        self.error = _NullSignal()
        self.finished = _NullSignal()
        self.username = "splunk_service"

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        return self.dispatch_results.pop(0)

    def get_job_status_snapshot(self, sid: str, *args, **kwargs):
        del args
        self.snapshot_calls.append({"sid": sid, **dict(kwargs)})
        result = self.snapshot_results[str(sid)].pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def reset_transport(self) -> None:
        self.reset_transport_calls += 1

    def close_transport(self) -> None:
        self.close_transport_calls += 1


class TimedDispatchClient:
    def __init__(
        self,
        dispatch_plan: list[dict[str, object]],
        *,
        snapshot_results: dict[str, list[object]] | None = None,
    ) -> None:
        self.dispatch_plan = list(dispatch_plan)
        self.snapshot_results = {key: list(value) for key, value in (snapshot_results or {}).items()}
        self.snapshot_calls: list[dict[str, object]] = []
        self.dispatch_calls: list[dict[str, object]] = []
        self.reset_transport_calls = 0
        self.close_transport_calls = 0
        self.dispatch_log = _NullSignal()
        self.error = _NullSignal()
        self.finished = _NullSignal()
        self.username = "splunk_service"

    def dispatch_saved_search(self, *args, **kwargs):
        self.dispatch_calls.append({"args": args, "kwargs": dict(kwargs)})
        plan = self.dispatch_plan.pop(0)
        wait_seconds = float(plan.get("wait_seconds", 0.0) or 0.0)
        if wait_seconds > 0:
            threading.Event().wait(wait_seconds)
        result = plan.get("result", (True, None, ""))
        signal_event = plan.get("signal_event")
        if isinstance(signal_event, threading.Event):
            signal_event.set()
        if isinstance(result, BaseException):
            raise result
        return result

    def get_job_status_snapshot(self, sid: str, *args, **kwargs):
        del args
        self.snapshot_calls.append({"sid": sid, **dict(kwargs)})
        result_queue = self.snapshot_results.get(str(sid), [])
        if not result_queue:
            raise AssertionError(f"Unexpected snapshot request for SID {sid}")
        result = result_queue.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def reset_transport(self) -> None:
        self.reset_transport_calls += 1

    def close_transport(self) -> None:
        self.close_transport_calls += 1


class AlwaysFailDispatchClient:
    def __init__(self) -> None:
        self.dispatch_log = _NullSignal()
        self.error = _NullSignal()
        self.finished = _NullSignal()
        self.username = "splunk_service"

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        return False, None, "Local Splunk broker request failed (dispatch_saved_search_failed)."


class MultiSliceVerificationRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        with splunk_engine._PENDING_DISPATCH_REGISTRY_LOCK:
            splunk_engine._PENDING_DISPATCH_REGISTRY.clear()

    def tearDown(self) -> None:
        with splunk_engine._PENDING_DISPATCH_REGISTRY_LOCK:
            splunk_engine._PENDING_DISPATCH_REGISTRY.clear()

    def _context(self, *, mode_description: str = "daily slices: 2") -> RegenContext:
        return RegenContext(
            run_id="regen-regression-001",
            report_names=["[Splunk10] TestReport"],
            app="search",
            operator="tester",
            hostname="host1",
            start_time_sgt=datetime(2026, 3, 24, 9, 0, 0),
            end_time_sgt=datetime(2026, 3, 24, 9, 5, 0),
            slicing_enabled=True,
            earliest_configured="2026-03-01 00:00:00",
            latest_configured="2026-03-03 00:00:00",
            mode_description=mode_description,
        )

    def _config(self) -> SplunkConfig:
        return SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            ack_enabled=True,
            ack_on_pending=False,
            ack_on_unknown=False,
            ack_recipients=["ops@example.com"],
            dispatch_config={
                "per_slice_wait_seconds": 30,
                "continue_on_timeout": True,
                "timeout_result": "pending",
            },
            postdispatch_config={
                "enabled": True,
                "poll_seconds": 1,
                "reconcile_pending": True,
                "reconcile_wait_seconds": 3,
            },
        )

    def test_foreground_timeout_keeps_sid_preserves_transport_and_reconciles_later(self) -> None:
        client = SequencedSliceClient()
        context = self._context()
        clock = {"t": 0.0}

        def _monotonic() -> float:
            clock["t"] += 0.8
            return clock["t"]

        with patch.object(splunk_engine.time, "monotonic", _monotonic), patch.object(
            splunk_engine.time,
            "sleep",
            lambda _seconds: None,
        ):
            logs = run_dispatch_single(
                client=client,
                report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                report_name="[Splunk10] TestReport",
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 3, 0, 0, 0),
                no_change=False,
                wait_seconds=3,
                poll_interval=1,
                regen_context=context,
            )

        self.assertEqual(len(context.slices), 2)
        self.assertEqual(context.slices[0].status, "PENDING")
        self.assertEqual(context.slices[0].sid, "SID_SLICE_1")
        self.assertEqual(context.slices[0].outcome_code, "DISPATCHED_PENDING")
        self.assertEqual(context.slices[1].status, "OK")
        self.assertEqual(context.slices[1].sid, "SID_SLICE_2")
        self.assertEqual(client.reset_transport_calls, 0)
        self.assertEqual(client.close_transport_calls, 0)
        self.assertIn("Continuing to next slice.", "\n".join(logs))

        with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
            reconcile_logs = _reconcile_pending_slices(
                client,
                context,
                wait_seconds=2,
                poll_interval=1,
            )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "RECONCILED_OK")
        self.assertIn("Email report sent successfully.", "\n".join(reconcile_logs))

    def test_active_wait_retries_one_transient_snapshot_timeout(self) -> None:
        client = SequencedSliceClient()
        context = self._context(mode_description="single run")
        clock = {"t": 0.0}

        def _monotonic() -> float:
            clock["t"] += 0.4
            return clock["t"]

        with patch.object(splunk_engine.time, "monotonic", _monotonic), patch.object(
            splunk_engine.time,
            "sleep",
            lambda _seconds: None,
        ):
            run_dispatch_single(
                client=client,
                report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                report_name="[Splunk10] TestReport",
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 2, 0, 0, 0),
                no_change=True,
                wait_seconds=3,
                poll_interval=1,
                regen_context=context,
            )

        first_slice_calls = [call for call in client.snapshot_calls if call["sid"] == "SID_SLICE_1"]
        self.assertGreaterEqual(len(first_slice_calls), 2)

    def test_late_sid_success_is_harvested_without_duplicate_dispatch(self) -> None:
        completion_event = threading.Event()
        client = TimedDispatchClient(
            [
                {
                    "wait_seconds": 1.2,
                    "result": (True, "SID_LATE_1", ""),
                    "signal_event": completion_event,
                },
                {
                    "result": (True, "SID_SLICE_2", ""),
                },
            ],
            snapshot_results={
                "SID_LATE_1": [("SUCCESS", {"dispatchState": "DONE", "isDone": True})],
                "SID_SLICE_2": [("SUCCESS", {"dispatchState": "DONE", "isDone": True})],
            },
        )
        context = self._context()
        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            report_name="[Splunk10] TestReport",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 3, 0, 0, 0),
            no_change=False,
            wait_seconds=2,
            poll_interval=1,
            regen_context=context,
            dispatch_call_timeout_seconds=1,
        )

        self.assertEqual(len(client.dispatch_calls), 2)
        self.assertEqual(len(context.slices), 2)
        self.assertEqual(context.slices[0].status, "PENDING")
        self.assertEqual(context.slices[0].sid, "")
        self.assertEqual(context.slices[0].outcome_code, "PENDING_NO_SID")
        self.assertTrue(context.slices[0].dispatch_correlation_id)
        self.assertEqual(context.slices[1].status, "OK")
        self.assertEqual(context.slices[1].sid, "SID_SLICE_2")
        self.assertEqual(client.reset_transport_calls, 0)
        self.assertEqual(client.close_transport_calls, 0)
        self.assertIn("Dispatch not yet confirmed; awaiting SID from Splunk.", "\n".join(logs))

        self.assertTrue(completion_event.wait(2.0))
        with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
            reconcile_logs = _reconcile_pending_slices(
                client,
                context,
                wait_seconds=2,
                poll_interval=1,
            )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].sid, "SID_LATE_1")
        self.assertEqual(context.slices[0].outcome_code, "RECONCILED_OK")
        self.assertEqual(len(client.dispatch_calls), 2)
        self.assertIn("Late SID attached", "\n".join(reconcile_logs))

    def test_late_dispatch_failure_marks_slice_failed(self) -> None:
        completion_event = threading.Event()
        client = TimedDispatchClient(
            [
                {
                    "wait_seconds": 1.2,
                    "result": (False, None, "Late dispatch failure from broker."),
                    "signal_event": completion_event,
                },
            ],
        )
        context = self._context(mode_description="single run")
        run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            report_name="[Splunk10] TestReport",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            wait_seconds=2,
            poll_interval=1,
            regen_context=context,
            dispatch_call_timeout_seconds=1,
        )

        self.assertEqual(context.slices[0].status, "PENDING")
        self.assertEqual(context.slices[0].sid, "")
        self.assertTrue(completion_event.wait(2.0))
        with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
            reconcile_logs = _reconcile_pending_slices(
                client,
                context,
                wait_seconds=1,
                poll_interval=1,
            )

        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[0].outcome_code, "DISPATCH_FAILED")
        self.assertIn("Late dispatch failed", "\n".join(reconcile_logs))

    def test_unresolved_no_sid_pending_survives_final_harvest_and_skips_ack(self) -> None:
        client = TimedDispatchClient(
            [
                {
                    "wait_seconds": 2.0,
                    "result": (True, "SID_TOO_LATE", ""),
                },
            ],
        )
        context = self._context(mode_description="single run")
        run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            report_name="[Splunk10] TestReport",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            wait_seconds=2,
            poll_interval=1,
            regen_context=context,
            dispatch_call_timeout_seconds=1,
        )

        with patch.object(splunk_engine.time, "sleep", lambda _seconds: None):
            reconcile_logs = _reconcile_pending_slices(
                client,
                context,
                wait_seconds=1,
                poll_interval=1,
            )
        final_logs = _finalize_pending_no_sid_dispatches(context)

        self.assertEqual(context.slices[0].status, "PENDING")
        self.assertEqual(context.slices[0].sid, "")
        self.assertTrue(context.slices[0].dispatch_correlation_id)
        self.assertIn("awaiting SID from Splunk", _format_slice_user_summary_line(context.slices[0]))
        self.assertIn("Dispatch not yet confirmed; awaiting SID from Splunk.", "\n".join(reconcile_logs + final_logs))

        result = send_ack_summary_email(context, config=self._config())
        self.assertFalse(result.attempted)
        self.assertFalse(result.success)
        self.assertEqual(result.reason, "pending_slices_present")

    def test_true_dispatch_failure_stays_failed_not_pending(self) -> None:
        client = AlwaysFailDispatchClient()
        context = self._context(mode_description="single run")
        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
            report_name="[Splunk10] TestReport",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            wait_seconds=3,
            poll_interval=1,
            regen_context=context,
        )

        self.assertEqual(len(context.slices), 1)
        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[0].outcome_code, "DISPATCH_FAILED")
        self.assertNotIn("PENDING", "\n".join(logs))


if __name__ == "__main__":
    unittest.main()
