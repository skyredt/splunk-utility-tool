from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime

from splunk_engine import RegenContext, run_dispatch_single


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


def _make_context() -> RegenContext:
    return RegenContext(
        run_id="regen-mergereport-001",
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
        self.assertEqual(context.slices[0].outcome_code, "DISPATCHED_PENDING")


if __name__ == "__main__":
    unittest.main()
