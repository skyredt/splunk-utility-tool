import unittest
from datetime import datetime
from unittest.mock import patch

import splunk_engine


class _FakeDispatchLog:
    def emit(self, logs=None):
        self.logs = list(logs or [])


class _FakeClient:
    username = "test-user"

    def __init__(self, events):
        self.events = events
        self.dispatch_log = _FakeDispatchLog()
        self.finished = _FakeDispatchLog()
        self._sid_counter = 0

    def dispatch_saved_search(self, report_id_url, **kwargs):
        self._sid_counter += 1
        sid = f"sid_{self._sid_counter}"
        self.events.append(("dispatch", sid))
        return True, sid, ""


def _fake_verify_factory(events):
    def _fake_verify(logs, *, execution_context, sid, record_slice, **kwargs):
        events.append(("verify", sid))
        record_slice(
            batch_id=execution_context.batch_id,
            slice_id=execution_context.slice_id,
            attempt_id=execution_context.attempt_id,
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            status="OK",
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            sid=sid,
            outcome_code="SUCCESS",
            dispatch_earliest=execution_context.dispatch_earliest or "",
            dispatch_latest=execution_context.dispatch_latest or "",
            lifecycle_state=splunk_engine.SLICE_STATE_SUCCESS,
            execution_context_id=execution_context.execution_context_id,
        )
        return "OK", sid, ""

    return _fake_verify


def _context():
    return splunk_engine.RegenContext(
        run_id="run-test",
        batch_id="batch-test",
        report_names=["saved_search_example"],
        app="search",
        operator="tester",
        hostname="test-host",
    )


class BusPlaneExecutionModelTests(unittest.TestCase):
    def test_execution_model_thresholds(self):
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(0), "plane")
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(1), "plane")
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(7), "plane")
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(8), "bus")
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(30), "bus")

    def test_post_slicing_execution_unit_count_drives_mode(self):
        start = datetime(2026, 1, 1)
        end = datetime(2026, 1, 31)
        starts, _ = splunk_engine.build_slices(start, end, "Daily")

        self.assertEqual(len(starts), 30)
        self.assertEqual(splunk_engine.calculate_execution_unit_count(1, len(starts)), 30)
        self.assertEqual(
            splunk_engine.choose_dispatch_execution_model(
                splunk_engine.calculate_execution_unit_count(1, len(starts))
            ),
            "bus",
        )
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(7), "plane")
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(8), "bus")

    def test_plane_verifies_each_unit_before_next_dispatch(self):
        events = []
        client = _FakeClient(events)
        context = _context()

        with patch.object(splunk_engine, "_audit_event", lambda *args, **kwargs: None), patch.object(
            splunk_engine, "_verify_dispatched_slice", _fake_verify_factory(events)
        ):
            splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/nobody/search/saved/searches/saved_search_example",
                report_name="saved_search_example",
                frequency="Daily",
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 3),
                no_change=False,
                regen_context=context,
                wait_seconds=1,
                poll_interval=1,
                verify_after_dispatch=True,
            )

        self.assertEqual(
            events,
            [
                ("dispatch", "sid_1"),
                ("verify", "sid_1"),
                ("dispatch", "sid_2"),
                ("verify", "sid_2"),
            ],
        )

    def test_bus_dispatches_all_units_before_verification_phase(self):
        events = []
        client = _FakeClient(events)
        context = _context()

        with patch.object(splunk_engine, "_audit_event", lambda *args, **kwargs: None), patch.object(
            splunk_engine, "_verify_dispatched_slice", _fake_verify_factory(events)
        ):
            splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/nobody/search/saved/searches/saved_search_example",
                report_name="saved_search_example",
                frequency="Daily",
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 3),
                no_change=False,
                regen_context=context,
                wait_seconds=1,
                poll_interval=1,
                verify_after_dispatch=False,
            )
            self.assertEqual(events, [("dispatch", "sid_1"), ("dispatch", "sid_2")])

            for item in list(context.slices):
                splunk_engine._verify_recorded_batch_slice(
                    [],
                    client=client,
                    regen_context=context,
                    item=item,
                    wait_seconds=1,
                    poll_interval=1,
                    timeout_status="PENDING",
                    prefer_merge_report_verification=False,
                    merge_report_log_path="",
                    merge_report_timeout_seconds=1,
                    merge_report_settings={},
                    log_callback=None,
                )

        self.assertEqual(
            events,
            [
                ("dispatch", "sid_1"),
                ("dispatch", "sid_2"),
                ("verify", "sid_1"),
                ("verify", "sid_2"),
            ],
        )

    def test_one_report_with_thirty_daily_slices_can_use_bus_dispatch_phase(self):
        events = []
        client = _FakeClient(events)
        context = _context()

        with patch.object(splunk_engine, "_audit_event", lambda *args, **kwargs: None), patch.object(
            splunk_engine, "_verify_dispatched_slice", _fake_verify_factory(events)
        ):
            splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/nobody/search/saved/searches/saved_search_example",
                report_name="saved_search_example",
                frequency="Daily",
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 31),
                no_change=False,
                regen_context=context,
                wait_seconds=1,
                poll_interval=1,
                verify_after_dispatch=False,
            )

        self.assertEqual(len(context.slices), 30)
        self.assertEqual(len([event for event in events if event[0] == "dispatch"]), 30)
        self.assertEqual(len([event for event in events if event[0] == "verify"]), 0)
        self.assertEqual(splunk_engine.choose_dispatch_execution_model(len(context.slices)), "bus")

    def test_run_dispatch_multi_uses_plane_for_seven_execution_units(self):
        events = []
        client = _FakeClient(events)
        report_ids = [
            f"/servicesNS/nobody/search/saved/searches/saved_search_example_{index}"
            for index in range(7)
        ]
        report_names = [f"saved_search_example_{index}" for index in range(7)]

        with self._patched_runtime(events):
            logs = splunk_engine.run_dispatch_multi(
                client,
                report_ids=report_ids,
                report_names=report_names,
                selected_indices=list(range(7)),
                frequency="Daily",
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 1),
                no_change=True,
                wait_seconds=1,
                poll_interval=1,
                config=None,
                app="search",
            )

        self.assertIn("Execution model: plane (7 post-slicing execution unit(s)).", logs)
        self.assertEqual(
            events,
            [
                ("dispatch", "sid_1"),
                ("verify", "sid_1"),
                ("dispatch", "sid_2"),
                ("verify", "sid_2"),
                ("dispatch", "sid_3"),
                ("verify", "sid_3"),
                ("dispatch", "sid_4"),
                ("verify", "sid_4"),
                ("dispatch", "sid_5"),
                ("verify", "sid_5"),
                ("dispatch", "sid_6"),
                ("verify", "sid_6"),
                ("dispatch", "sid_7"),
                ("verify", "sid_7"),
            ],
        )

    def test_run_dispatch_multi_uses_bus_for_eight_execution_units(self):
        events = []
        client = _FakeClient(events)
        report_ids = [
            f"/servicesNS/nobody/search/saved/searches/saved_search_example_{index}"
            for index in range(8)
        ]
        report_names = [f"saved_search_example_{index}" for index in range(8)]

        with self._patched_runtime(events):
            logs = splunk_engine.run_dispatch_multi(
                client,
                report_ids=report_ids,
                report_names=report_names,
                selected_indices=list(range(8)),
                frequency="Daily",
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 1),
                no_change=True,
                wait_seconds=1,
                poll_interval=1,
                config=None,
                app="search",
            )

        self.assertIn("Execution model: bus (8 post-slicing execution unit(s)).", logs)
        self.assertEqual(
            events,
            [(f"dispatch", f"sid_{index}") for index in range(1, 9)]
            + [(f"verify", f"sid_{index}") for index in range(1, 9)],
        )

    def _patched_runtime(self, events):
        return _RuntimePatch(events)


class _RuntimePatch:
    def __init__(self, events):
        self._events = events
        self._patches = [
            patch.object(splunk_engine, "_audit_event", lambda *args, **kwargs: None),
            patch.object(splunk_engine, "_verify_dispatched_slice", _fake_verify_factory(events)),
            patch.object(splunk_engine, "list_unfinished_journals", lambda: []),
            patch.object(splunk_engine, "batch_journal_path", lambda batch_id: ""),
            patch.object(splunk_engine, "acquire_overlap_lock", lambda lock_key, batch_id, metadata: (True, {}, "")),
            patch.object(splunk_engine, "release_overlap_lock", lambda lock_key, batch_id: None),
            patch.object(splunk_engine, "_collect_saved_search_recipients", lambda **kwargs: []),
            patch.object(
                splunk_engine,
                "send_ack_summary_email",
                lambda context, config=None: splunk_engine.AckEmailResult(
                    attempted=False,
                    success=False,
                    recipients=[],
                    reason="ack_disabled",
                ),
            ),
        ]

    def __enter__(self):
        for patcher in self._patches:
            patcher.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        for patcher in reversed(self._patches):
            patcher.stop()
        return False


if __name__ == "__main__":
    unittest.main()
