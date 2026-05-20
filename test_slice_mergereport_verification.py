from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime

from splunk_engine import (
    RegenContext,
    _reconcile_pending_slices,
    run_dispatch_single,
)


class _NoStatusClient:
    def __init__(self, sid: str) -> None:
        self.sid = sid
        self.username = "splunk_service"

    def dispatch_saved_search(self, *args, **kwargs):
        return (True, self.sid, "")

    def get_job_status_snapshot(self, *args, **kwargs):
        raise AssertionError("status snapshot path should not be primary in this test")


class _StatusClient(_NoStatusClient):
    def __init__(self, sid: str, snapshot_results) -> None:
        super().__init__(sid)
        self.snapshot_results = list(snapshot_results)

    def get_job_status_snapshot(self, *args, **kwargs):
        if self.snapshot_results:
            return self.snapshot_results.pop(0)
        return ("RUNNING", {})


class _RaisingStatusClient(_NoStatusClient):
    def get_job_status_snapshot(self, *args, **kwargs):
        raise RuntimeError("status snapshot timeout")


class _RestMergeReportClient(_NoStatusClient):
    def __init__(self, sid: str, raw_lines: list[str], *, snapshot_results=None, raise_search: bool = False) -> None:
        super().__init__(sid)
        self.raw_lines = list(raw_lines)
        self.raise_search = raise_search
        self.snapshot_results = list(snapshot_results or [])
        self.search_calls = 0

    def _get(self, path: str, params: dict | None = None, **kwargs):
        del kwargs
        if path == "/services/search/jobs/export" and params and params.get("search"):
            self.search_calls += 1
            if self.raise_search:
                raise RuntimeError("Network error while calling Splunk REST API: simulated merge report search failure")
            return {"results": [{"_raw": raw} for raw in self.raw_lines]}
        return {"entry": []}

    def get_job_status_snapshot(self, *args, **kwargs):
        if self.snapshot_results:
            return self.snapshot_results.pop(0)
        raise AssertionError("status snapshot path should not be primary in this test")


def _make_context() -> RegenContext:
    return RegenContext(
        run_id="regen-mergereport-001",
        batch_id="batch-mergereport-001",
        report_names=["Daily KPI"],
        app="search",
        operator="tester",
        hostname="host1",
        start_time_sgt=datetime(2026, 3, 16, 10, 0, 0),
    )


class SliceMergeReportVerificationTests(unittest.TestCase):
    def _write_log(self, text: str) -> str:
        fd, path = tempfile.mkstemp(prefix="merge_report_", suffix=".log")
        os.close(fd)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_mergereport_email_sent_marks_slice_ok_without_status_snapshot(self) -> None:
        sid = "1700000_OK123"
        log_path = self._write_log(
            "\n".join(
                [
                    f"2026-03-16 10:00:01,000 INFO Search Name=Daily KPI, SID={sid}, Action=Sending email, SmtpServer=127.0.0.1, SmtpPort=25",
                    f"2026-03-16 10:00:02,000 INFO Search Name=Daily KPI, SID={sid}, Action=Email sent, Subject=Daily KPI",
                ]
            )
            + "\n"
        )
        context = _make_context()

        run_dispatch_single(
            client=_NoStatusClient(sid),
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            regen_context=context,
            prefer_merge_report_verification=True,
            merge_report_log_path=log_path,
            merge_report_timeout_seconds=1,
            poll_interval=1,
        )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "SUCCESS_MERGEREPORT")

    def test_mergereport_rest_verification_succeeds_without_local_file_access(self) -> None:
        sid = "1700000_RESTOK123"
        context = _make_context()
        client = _RestMergeReportClient(
            sid,
            [
                f"2026-03-16 10:00:02,000 INFO Search Name=Daily KPI, SID={sid}, Action=Email sent, Subject=Daily KPI",
            ],
        )

        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            regen_context=context,
            prefer_merge_report_verification=True,
            merge_report_log_path="",
            merge_report_timeout_seconds=1,
            merge_report_settings={
                "enabled": True,
                "requested_log_path": "",
                "local_file_path": "",
                "local_file_available": False,
                "local_file_reason": "blank_path",
                "rest_enabled": True,
                "index": "_internal",
                "source_contains": "mergeReport_alert.log",
                "sourcetype": "",
                "lookback_seconds": 900,
                "timeout_seconds": 1,
            },
            poll_interval=1,
        )

        self.assertEqual(client.search_calls, 1)
        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "SUCCESS_MERGEREPORT")
        self.assertTrue(any("MERGEREPORT_VERIFICATION_SOURCE_SELECTED source=rest" in line for line in logs))

    def test_mergereport_rest_verification_logs_user_scoped_bracketed_namespace(self) -> None:
        sid = "1700000_RESTBRACKET"
        context = _make_context()
        client = _RestMergeReportClient(
            sid,
            [
                f"2026-03-16 10:00:02,000 INFO Search Name=Daily KPI [Weekly], SID={sid}, Action=Email sent, Subject=Daily KPI [Weekly]",
            ],
        )

        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/report.user/search/saved/searches/Daily%20KPI%20%5BWeekly%5D",
            report_name="Daily KPI [Weekly]",
            frequency="Weekly",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 8, 0, 0, 0),
            no_change=True,
            regen_context=context,
            prefer_merge_report_verification=True,
            merge_report_log_path="",
            merge_report_timeout_seconds=1,
            merge_report_settings={
                "enabled": True,
                "requested_log_path": "",
                "local_file_path": "",
                "local_file_available": False,
                "local_file_reason": "blank_path",
                "rest_enabled": True,
                "index": "_internal",
                "source_contains": "mergeReport_alert.log",
                "sourcetype": "",
                "lookback_seconds": 900,
                "timeout_seconds": 1,
            },
            poll_interval=1,
        )

        joined = "\n".join(logs)
        self.assertIn("MERGEREPORT_NAMESPACE_RESOLVED", joined)
        self.assertIn("owner=report.user", joined)
        self.assertIn("app=search", joined)
        self.assertIn("report_name=Daily KPI [Weekly]", joined)
        self.assertIn(
            "saved_search_path=/servicesNS/report.user/search/saved/searches/Daily%20KPI%20%5BWeekly%5D",
            joined,
        )
        self.assertIn("resolution_source=exact_namespace_path", joined)

    def test_mergereport_nonexistent_local_file_is_nonfatal_when_rest_succeeds(self) -> None:
        sid = "1700000_RDSOK123"
        context = _make_context()
        client = _RestMergeReportClient(
            sid,
            [
                f"2026-03-16 10:00:02,000 INFO Search Name=Daily KPI, SID={sid}, Action=Email sent, Subject=Daily KPI",
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            missing_log_path = os.path.join(tmpdir, "search-head-only", "mergeReport_alert.log")
            logs = run_dispatch_single(
                client=client,
                report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
                report_name="Daily KPI",
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 2, 0, 0, 0),
                no_change=True,
                regen_context=context,
                prefer_merge_report_verification=True,
                merge_report_log_path=missing_log_path,
                merge_report_timeout_seconds=1,
                merge_report_settings={
                    "enabled": True,
                    "requested_log_path": missing_log_path,
                    "rest_enabled": True,
                    "index": "_internal",
                    "source_contains": "mergeReport_alert.log",
                    "sourcetype": "",
                    "lookback_seconds": 900,
                    "timeout_seconds": 1,
                },
                poll_interval=1,
            )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertTrue(any("MERGEREPORT_FILE_UNAVAILABLE" in line for line in logs))

    def test_mergereport_source_unavailable_falls_back_to_snapshot_nonfatally(self) -> None:
        sid = "1700000_RESTFALLBACK"
        context = _make_context()
        client = _RestMergeReportClient(
            sid,
            [],
            snapshot_results=[("SUCCESS", {"dispatchState": "DONE", "isDone": True})],
            raise_search=True,
        )

        logs = run_dispatch_single(
            client=client,
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            regen_context=context,
            prefer_merge_report_verification=True,
            merge_report_log_path="",
            merge_report_timeout_seconds=1,
            merge_report_settings={
                "enabled": True,
                "requested_log_path": "",
                "rest_enabled": True,
                "index": "_internal",
                "source_contains": "mergeReport_alert.log",
                "sourcetype": "",
                "lookback_seconds": 900,
                "timeout_seconds": 1,
            },
            poll_interval=1,
            wait_seconds=2,
        )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertTrue(
            any("MERGEREPORT_VERIFICATION_NONFATAL_SOURCE_UNAVAILABLE" in line for line in logs)
        )
        self.assertTrue(any("falling back to native Splunk status verification" in line for line in logs))

    def test_mergereport_missing_terminal_marker_leaves_slice_pending(self) -> None:
        sid = "1700000_PENDING123"
        log_path = self._write_log(
            f"2026-03-16 10:00:01,000 INFO Search Name=Daily KPI, SID={sid}, Action=Sending email, SmtpServer=127.0.0.1, SmtpPort=25\n"
        )
        context = _make_context()

        run_dispatch_single(
            client=_StatusClient(sid, [("SUCCESS", {"dispatchState": "DONE"})]),
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            regen_context=context,
            prefer_merge_report_verification=True,
            merge_report_log_path=log_path,
            merge_report_timeout_seconds=1,
            poll_interval=1,
            wait_seconds=2,
        )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "SUCCESS")

    def test_both_mergereport_and_native_fallback_inconclusive_leave_slice_pending(self) -> None:
        sid = "1700000_PENDING999"
        log_path = self._write_log(
            f"2026-03-16 10:00:01,000 INFO Search Name=Daily KPI, SID={sid}, Action=Sending email, SmtpServer=127.0.0.1, SmtpPort=25\n"
        )
        context = _make_context()

        run_dispatch_single(
            client=_StatusClient(sid, [("RUNNING", {}), ("RUNNING", {})]),
            report_id_url="/servicesNS/nobody/search/saved/searches/Daily%20KPI",
            report_name="Daily KPI",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            regen_context=context,
            prefer_merge_report_verification=True,
            merge_report_log_path=log_path,
            merge_report_timeout_seconds=1,
            poll_interval=1,
            wait_seconds=2,
        )

        self.assertEqual(context.slices[0].status, "PENDING")
        self.assertEqual(context.slices[0].outcome_code, "PENDING_RECONCILE")

    def test_pending_reconciliation_uses_mergereport_success_before_status_snapshot(self) -> None:
        sid = "1700000_RECONOK123"
        log_path = self._write_log(
            f"2026-03-16 10:00:02,000 INFO Search Name=Daily KPI, SID={sid}, Action=Email sent, Subject=Daily KPI\n"
        )
        context = _make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="No Change",
            slice_index=1,
            slice_total=1,
            status="PENDING",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid=sid,
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds.",
        )

        logs = _reconcile_pending_slices(
            _RaisingStatusClient(sid),
            context,
            wait_seconds=1,
            poll_interval=1,
            prefer_merge_report_verification=True,
            merge_report_log_path=log_path,
        )

        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].outcome_code, "RECONCILED_OK_MERGEREPORT")
        self.assertTrue(
            any("MERGEREPORT_RECONCILIATION_RESULT" in line and "state=SUCCESS" in line for line in logs)
        )

    def test_pending_reconciliation_uses_mergereport_failure_before_status_snapshot(self) -> None:
        sid = "1700000_RECONFAIL123"
        log_path = self._write_log(
            f"2026-03-16 10:00:02,000 ERROR Search Name=Daily KPI, SID={sid}, SMTP error while sending email\n"
        )
        context = _make_context()
        context.add_slice(
            report_name="Daily KPI",
            slice_label="No Change",
            slice_index=1,
            slice_total=1,
            status="PENDING",
            earliest="2026-03-01 00:00:00",
            latest="2026-03-02 00:00:00",
            sid=sid,
            outcome_code="DISPATCHED_PENDING",
            error="Status not confirmed within 30 seconds.",
        )

        logs = _reconcile_pending_slices(
            _RaisingStatusClient(sid),
            context,
            wait_seconds=1,
            poll_interval=1,
            prefer_merge_report_verification=True,
            merge_report_log_path=log_path,
        )

        self.assertEqual(context.slices[0].status, "FAILED")
        self.assertEqual(context.slices[0].outcome_code, "RECONCILED_FAILED_MERGEREPORT")
        self.assertTrue(
            any("MERGEREPORT_RECONCILIATION_RESULT" in line and "state=FAILED" in line for line in logs)
        )


if __name__ == "__main__":
    unittest.main()
