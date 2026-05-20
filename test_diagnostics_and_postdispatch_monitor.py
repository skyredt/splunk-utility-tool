from __future__ import annotations

import queue
import unittest
from datetime import datetime

import postdispatch_monitor
import splunk_engine


class _NullSignal:
    def emit(self, *args, **kwargs) -> None:
        return


class _DispatchClient:
    def __init__(self) -> None:
        self.dispatch_log = _NullSignal()
        self.error = _NullSignal()
        self.finished = _NullSignal()
        self.username = "splunk_service"
        self.metadata_calls: list[tuple[str, dict | None]] = []

    def dispatch_saved_search(self, *args, **kwargs):
        return (True, "1700000_DIAG", "")

    def get_job_status_snapshot(self, *args, **kwargs):
        return ("SUCCESS", {"dispatchState": "DONE", "isDone": True})

    def _get(self, path: str, params: dict | None = None):
        self.metadata_calls.append((path, dict(params or {})))
        if params and params.get("search"):
            return {"results": []}
        return {
            "entry": [
                {
                    "content": {
                        "action.email.to": "ops@example.com",
                    }
                }
            ]
        }


class _MalformedSearchClient:
    def _get(self, path: str, params: dict | None = None):
        del path, params
        raise RuntimeError(
            "HTTP 400 returned by Splunk REST API. "
            "{\"type\":\"FATAL\",\"text\":\"Unknown search command 'index'.\"}"
        )


class DiagnosticsAndPostDispatchMonitorTests(unittest.TestCase):
    def test_postdispatch_monitor_prefixes_export_search_with_search_command(self) -> None:
        client = _DispatchClient()
        monitor = postdispatch_monitor.PostDispatchStatusMonitor(
            client=client,
            ui_queue=queue.Queue(),
            config={"merge_report_enabled": True},
        )

        monitor._poll_merge_report(["1700000_TEST"], '("SID=1700000_TEST")')

        self.assertEqual(client.metadata_calls[0][0], "/services/search/jobs/export")
        self.assertEqual(
            client.metadata_calls[0][1]["search"],
            'search index=_internal source="mergeReport_alert.log" (("SID=1700000_TEST"))',
        )

    def test_postdispatch_monitor_labels_malformed_spl_errors_clearly(self) -> None:
        ui_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        monitor = postdispatch_monitor.PostDispatchStatusMonitor(
            client=_MalformedSearchClient(),
            ui_queue=ui_queue,
            config={"merge_report_enabled": True},
        )

        monitor._poll_merge_report(["1700000_TEST"], '("SID=1700000_TEST")')

        event_name, message = ui_queue.get_nowait()
        self.assertEqual(event_name, "postdispatch_error")
        self.assertIn("malformed_spl", message)
        self.assertNotIn("invalid_time_spec", message)

    def test_run_dispatch_single_emits_broker_call_logs_for_dispatch_and_snapshot(self) -> None:
        client = _DispatchClient()

        logs = splunk_engine.run_dispatch_single(
            client,
            report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
            report_name="TestReport",
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=False,
            wait_seconds=5,
            poll_interval=1,
        )

        joined = "\n".join(logs)
        self.assertIn("BROKER_CALL_ENTER op=dispatch_saved_search", joined)
        self.assertIn("BROKER_CALL_EXIT op=dispatch_saved_search", joined)
        self.assertIn("BROKER_CALL_ENTER op=get_job_status_snapshot", joined)
        self.assertIn("BROKER_CALL_EXIT op=get_job_status_snapshot", joined)

    def test_run_dispatch_multi_logs_recipient_discovery_timestamps(self) -> None:
        client = _DispatchClient()
        config = splunk_engine.SplunkConfig(
            servers=["https://splunk.example:8089"],
            username="splunk_service",
            password="",
            verify_ssl=False,
            ack_enabled=False,
            dispatch_config={"continue_on_timeout": True, "timeout_result": "pending"},
        )

        logs = splunk_engine.run_dispatch_multi(
            client=client,
            report_ids=["/servicesNS/splunk_service/search/saved/searches/TestReport"],
            report_names=["TestReport"],
            selected_indices=[0],
            frequency="Daily",
            start=datetime(2026, 3, 1, 0, 0, 0),
            end=datetime(2026, 3, 2, 0, 0, 0),
            no_change=True,
            wait_seconds=5,
            poll_interval=1,
            config=config,
            app="search",
        )

        joined = "\n".join(logs)
        self.assertIn("RECIPIENT_DISCOVERY_START report_name=TestReport started_utc=", joined)
        self.assertIn("RECIPIENT_DISCOVERY_DONE report_name=TestReport ended_utc=", joined)
        self.assertIn("recipient_count=1 outcome=completed", joined)


if __name__ == "__main__":
    unittest.main()
