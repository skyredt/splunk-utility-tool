from __future__ import annotations

import queue
import threading
import unittest

import splunk_engine
from splunk_report_tk import ReportsApp


class _FakeMonitor:
    def __init__(self) -> None:
        self.stop_calls = 0

    def stop(self) -> None:
        self.stop_calls += 1


class RunScopedCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        splunk_engine._clear_pending_dispatch_attempts_for_run(clear_all=True)

    def tearDown(self) -> None:
        splunk_engine._clear_pending_dispatch_attempts_for_run(clear_all=True)

    def test_clear_pending_dispatch_attempts_for_run_removes_matching_entries(self) -> None:
        q1: "queue.Queue[tuple[str, bool, str, str]]" = queue.Queue()
        q2: "queue.Queue[tuple[str, bool, str, str]]" = queue.Queue()
        splunk_engine._register_pending_dispatch_attempt(
            "corr-run-a",
            result_queue=q1,
            worker_thread_name="worker-a",
            worker_thread_ident=1,
            report_name="ReportA",
            slice_label="[1/2]",
            slice_index=1,
            slice_total=2,
            earliest="2026-03-10 00:00:00",
            latest="2026-03-11 00:00:00",
            report_id_url="/servicesNS/skyred5/search/saved/searches/TestA",
            started_monotonic=1.0,
            started_utc="2026-03-24T04:05:31Z",
            timeout_seconds=30,
            run_id="run-a",
        )
        splunk_engine._register_pending_dispatch_attempt(
            "corr-run-b",
            result_queue=q2,
            worker_thread_name="worker-b",
            worker_thread_ident=2,
            report_name="ReportB",
            slice_label="[1/1]",
            slice_index=1,
            slice_total=1,
            earliest="2026-03-12 00:00:00",
            latest="2026-03-13 00:00:00",
            report_id_url="/servicesNS/skyred5/search/saved/searches/TestB",
            started_monotonic=2.0,
            started_utc="2026-03-24T04:06:01Z",
            timeout_seconds=30,
            run_id="run-b",
        )

        cleared = splunk_engine._clear_pending_dispatch_attempts_for_run("run-a")

        self.assertEqual(cleared, 1)
        self.assertEqual(
            splunk_engine._harvest_pending_dispatch_result("corr-run-a").state,
            "MISSING",
        )
        self.assertEqual(
            splunk_engine._harvest_pending_dispatch_result("corr-run-b").state,
            "PENDING",
        )

    def test_reports_app_reset_run_scoped_state_stops_monitors_and_drains_queue(self) -> None:
        app = ReportsApp.__new__(ReportsApp)
        app._merge_report_monitor = _FakeMonitor()
        app._postdispatch_monitor = _FakeMonitor()
        app._dispatch_queue = queue.Queue()
        app._dispatch_queue.put(("log", "line-1"))
        app._dispatch_queue.put(("done", None))
        app._dispatch_in_progress = False

        stopped_monitors, drained_events = app._reset_run_scoped_state()

        self.assertEqual(stopped_monitors, 2)
        self.assertEqual(drained_events, 2)
        self.assertIsNone(app._merge_report_monitor)
        self.assertIsNone(app._postdispatch_monitor)
        with self.assertRaises(queue.Empty):
            app._dispatch_queue.get_nowait()


if __name__ == "__main__":
    unittest.main()
