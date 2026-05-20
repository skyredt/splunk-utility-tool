from __future__ import annotations

import threading
import time
import unittest
from unittest.mock import patch

from Internal import splunk_broker as splunk_broker_module


class DummyAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def log_event(self, event: str, level: str = "INFO", **fields) -> None:
        self.events.append({"event": event, "level": level, "fields": fields})


def _make_state(client):
    state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
    state.audit = DummyAudit()
    state.client_lifecycle_lock = threading.Lock()
    state.client = client
    state.cfg = None
    state.connected_server = "https://127.0.0.1:8089"
    state.config_error = ""
    state.last_successful_heartbeat_utc = ""
    state.last_health_error = ""
    return state


class DispatchTransportClient:
    def __init__(self, sid: str = "xyz123") -> None:
        self.sid = sid
        self.dispatch_calls: list[dict[str, object]] = []
        self.snapshot_calls = 0
        self.export_calls = 0
        self.metadata_calls = 0
        self._last_dispatch_meta: dict[str, object] = {}

    def dispatch_saved_search(self, *args, **kwargs):
        del args
        self.dispatch_calls.append(dict(kwargs))
        self._last_dispatch_meta = {
            "request_body_summary": "{\"dispatch.latest_time\":\"1773158400\",\"output_mode\":\"json\"}",
            "request_start_time": "2026-03-14T06:10:04Z",
            "connect_timeout_seconds": 10,
            "read_timeout_seconds": 30,
            "response_status_code": 201,
            "response_headers_elapsed_ms": 15,
            "response_body_read_elapsed_ms": 0,
            "json_parse_elapsed_ms": 0,
            "post_sid_return_work_ms": 0,
            "sid": self.sid,
            "sid_source": "location_header",
            "response_location": f"/services/search/jobs/{self.sid}",
        }
        return True, self.sid, ""

    def get_job_status_snapshot(self, *args, **kwargs):
        del args, kwargs
        self.snapshot_calls += 1
        raise AssertionError("dispatch transport contract must not call snapshot verification")

    def export_search_json(self, *args, **kwargs):
        del args, kwargs
        self.export_calls += 1
        raise AssertionError("dispatch transport contract must not call export_search")

    def _get(self, *args, **kwargs):
        del args, kwargs
        self.metadata_calls += 1
        raise AssertionError("dispatch transport contract must not call metadata retrieval")


class RaisingDispatchTransportClient(DispatchTransportClient):
    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self._last_dispatch_meta = {
            "connect_timeout_seconds": 10,
            "read_timeout_seconds": 30,
        }
        raise RuntimeError("socket timeout while dispatching saved search")


class SnapshotTransportClient:
    def __init__(self, state: str, content: dict[str, object]) -> None:
        self.state = state
        self.content = dict(content)
        self.snapshot_calls = 0
        self.dispatch_calls = 0
        self._last_snapshot_meta: dict[str, object] = {}

    def get_job_status_snapshot(self, *args, **kwargs):
        del args
        self.snapshot_calls += 1
        self._last_snapshot_meta = {
            "rest_endpoint": f"/services/search/jobs/{kwargs['sid']}",
            "rest_method": "GET",
            "response_status_code": 200,
            "response_shape": {
                "dispatch_state": str(self.content.get("dispatchState", "")),
                "is_done": bool(self.content.get("isDone", False)),
                "is_failed": bool(self.content.get("isFailed", False)),
            },
            "request_timeout_seconds": int(kwargs.get("request_timeout_seconds", 5)),
        }
        return self.state, dict(self.content)

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self.dispatch_calls += 1
        raise AssertionError("snapshot transport contract must not dispatch jobs")


class ExportTransportClient:
    def __init__(self) -> None:
        self.export_calls: list[dict[str, object]] = []
        self.dispatch_calls = 0
        self.snapshot_calls = 0

    def export_search_json(self, search_query: str, *, earliest_time: str, timeout_seconds: int = 60):
        self.export_calls.append(
            {
                "search_query": search_query,
                "earliest_time": earliest_time,
                "timeout_seconds": timeout_seconds,
            }
        )
        return {"results": [{"report_earliest_epoch": "1", "report_latest_epoch": "2"}]}

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self.dispatch_calls += 1
        raise AssertionError("export transport contract must not dispatch jobs")

    def get_job_status_snapshot(self, *args, **kwargs):
        del args, kwargs
        self.snapshot_calls += 1
        raise AssertionError("export transport contract must not poll job status")


class MetadataTransportClient:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.dispatch_calls = 0

    def _get(self, path: str):
        self.paths.append(path)
        return {
            "entry": [
                {
                    "name": "[Splunk10] TestReport",
                    "content": {
                        "dispatch.earliest_time": "1772726400",
                        "dispatch.latest_time": "1773158400",
                    },
                }
            ]
        }

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self.dispatch_calls += 1
        raise AssertionError("metadata transport contract must not dispatch jobs")


class BrokerContractBehaviorTests(unittest.TestCase):
    def _capture_events(self):
        events: list[tuple[str, dict[str, object]]] = []
        patches = (
            patch.object(
                splunk_broker_module,
                "debug_category_enabled",
                lambda category: str(category).strip().lower() == "broker",
            ),
            patch.object(
                splunk_broker_module,
                "debug_event",
                lambda event, **fields: events.append((event, dict(fields))) or True,
            ),
        )
        return events, patches

    def test_dispatch_returns_sid_immediately_without_workflow_calls(self) -> None:
        client = DispatchTransportClient(sid="xyz123")
        state = _make_state(client)
        events, patches = self._capture_events()
        with patches[0], patches[1]:
            result = state.op_dispatch_saved_search(
                {
                    "report_id_url": "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                    "earliest": "1772726400",
                    "latest": "1773158400",
                    "trigger_actions": True,
                }
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["sid"], "xyz123")
        self.assertEqual(client.snapshot_calls, 0)
        self.assertEqual(client.export_calls, 0)
        self.assertEqual(client.metadata_calls, 0)
        self.assertEqual(len(client.dispatch_calls), 1)
        event_names = [name for name, _ in events]
        self.assertIn("BROKER_REQUEST_STARTED", event_names)
        self.assertIn("BROKER_RESPONSE_HEADERS", event_names)
        self.assertIn("BROKER_RESPONSE_BODY", event_names)
        self.assertIn("BROKER_OPERATION_COMPLETED", event_names)
        completed = next(fields for name, fields in events if name == "BROKER_OPERATION_COMPLETED")
        self.assertEqual(completed["operation"], "dispatch_saved_search")
        self.assertEqual(completed["sid"], "xyz123")
        self.assertEqual(completed["method"], "POST")

    def test_dispatch_timing_boundary_events_show_no_post_sid_wait(self) -> None:
        client = DispatchTransportClient(sid="timing123")
        state = _make_state(client)
        events, patches = self._capture_events()
        with patches[0], patches[1]:
            state.op_dispatch_saved_search(
                {
                    "report_id_url": "https://127.0.0.1:8089/servicesNS/nobody/search/saved/searches/TestReport",
                    "earliest": "1772726400",
                    "latest": "1773158400",
                    "trigger_actions": True,
                }
            )

        event_names = [name for name, _ in events]
        self.assertLess(event_names.index("DISPATCH_SAVED_SEARCH_RESPONSE_HEADERS"), event_names.index("DISPATCH_SAVED_SEARCH_SID_PARSED"))
        self.assertLess(event_names.index("DISPATCH_SAVED_SEARCH_SID_PARSED"), event_names.index("DISPATCH_SAVED_SEARCH_COMPLETED"))
        completed = next(fields for name, fields in events if name == "DISPATCH_SAVED_SEARCH_COMPLETED")
        self.assertEqual(completed["post_sid_return_work_ms"], 0)
        self.assertEqual(completed["sid_source"], "location_header")
        self.assertEqual(completed["response_headers_elapsed_ms"], 15)

    def test_snapshot_status_call_returns_parsed_state_without_retry_loops(self) -> None:
        cases = [
            ("RUNNING", {"dispatchState": "RUNNING", "isDone": False, "isFailed": False}),
            ("SUCCESS", {"dispatchState": "DONE", "isDone": True, "isFailed": False}),
            ("FAILED", {"dispatchState": "FAILED", "isDone": True, "isFailed": True}),
        ]
        for expected_state, content in cases:
            with self.subTest(expected_state=expected_state):
                client = SnapshotTransportClient(expected_state, content)
                state = _make_state(client)
                events, patches = self._capture_events()
                with patches[0], patches[1]:
                    result = state.op_get_job_status_snapshot(
                        {
                            "sid": "snapshot_sid_001",
                            "request_timeout_seconds": 5,
                            "retry_count": 0,
                            "stage_name": "active_wait",
                        }
                    )

                self.assertEqual(result["state"], expected_state)
                self.assertEqual(client.snapshot_calls, 1)
                event_names = [name for name, _ in events]
                self.assertIn("BROKER_REQUEST_STARTED", event_names)
                self.assertIn("BROKER_RESPONSE_HEADERS", event_names)
                self.assertIn("BROKER_RESPONSE_BODY", event_names)
                self.assertIn("BROKER_OPERATION_COMPLETED", event_names)
                completed = next(fields for name, fields in events if name == "BROKER_OPERATION_COMPLETED")
                self.assertEqual(completed["operation"], "get_job_status_snapshot")
                self.assertEqual(completed["state"], expected_state)

    def test_export_search_transport_uses_post_and_returns_results_without_workflow_logic(self) -> None:
        client = ExportTransportClient()
        state = _make_state(client)
        events, patches = self._capture_events()
        with patches[0], patches[1]:
            result = state.op_export_search(
                {
                    "search_query": "search index=_internal | head 1",
                    "earliest_time": "-15m",
                    "timeout_seconds": 30,
                }
            )

        self.assertEqual(result["results"]["results"][0]["report_earliest_epoch"], "1")
        self.assertEqual(len(client.export_calls), 1)
        self.assertEqual(client.dispatch_calls, 0)
        self.assertEqual(client.snapshot_calls, 0)
        self.assertEqual(client.export_calls[0]["search_query"], "search index=_internal | head 1")
        self.assertEqual(client.export_calls[0]["earliest_time"], "-15m")
        event_names = [name for name, _ in events]
        self.assertIn("BROKER_REQUEST_STARTED", event_names)
        self.assertIn("BROKER_RESPONSE_BODY", event_names)
        completed = next(fields for name, fields in events if name == "BROKER_OPERATION_COMPLETED")
        self.assertEqual(completed["operation"], "export_search")
        self.assertEqual(completed["endpoint"], "/services/search/jobs/export")
        self.assertEqual(completed["method"], "POST")

    def test_saved_search_metadata_retrieval_returns_config_only(self) -> None:
        client = MetadataTransportClient()
        state = _make_state(client)
        events, patches = self._capture_events()
        with patches[0], patches[1]:
            result = state.op_get_saved_search_metadata(
                {
                    "path": "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                    "report_name": "[Splunk10] TestReport",
                    "app": "search",
                    "owner": "skyred5",
                    "sharing": "user",
                    "candidate_label": "exact_namespace_metadata",
                    "namespace_meta": {
                        "app": "search",
                        "owner": "skyred5",
                        "sharing": "user",
                    },
                }
            )

        self.assertEqual(result["details"]["owner"], "skyred5")
        self.assertEqual(result["details"]["app"], "search")
        self.assertEqual(len(client.paths), 1)
        event_names = [name for name, _ in events]
        self.assertIn("BROKER_REQUEST_STARTED", event_names)
        self.assertIn("BROKER_OPERATION_COMPLETED", event_names)
        self.assertIn("SAVED_SEARCH_METADATA_RESOLVED", event_names)

    def test_dispatch_namespace_behavior_is_identical_for_owner_and_shared_paths(self) -> None:
        client = DispatchTransportClient(sid="same_sid")
        state = _make_state(client)

        owner_result = state.op_dispatch_saved_search(
            {
                "report_id_url": "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/TestReport",
                "earliest": "1",
                "latest": "2",
                "trigger_actions": True,
            }
        )
        shared_result = state.op_dispatch_saved_search(
            {
                "report_id_url": "https://127.0.0.1:8089/servicesNS/nobody/search/saved/searches/TestReport",
                "earliest": "1",
                "latest": "2",
                "trigger_actions": True,
            }
        )

        self.assertTrue(owner_result["ok"])
        self.assertTrue(shared_result["ok"])
        self.assertEqual(owner_result["sid"], "same_sid")
        self.assertEqual(shared_result["sid"], "same_sid")
        self.assertEqual(len(client.dispatch_calls), 2)
        self.assertEqual(
            client.dispatch_calls[0]["report_id_url"],
            "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/TestReport",
        )
        self.assertEqual(
            client.dispatch_calls[1]["report_id_url"],
            "https://127.0.0.1:8089/servicesNS/nobody/search/saved/searches/TestReport",
        )

    def test_dispatch_transport_exception_surfaces_as_specific_broker_failure(self) -> None:
        client = RaisingDispatchTransportClient()
        state = _make_state(client)
        events, patches = self._capture_events()
        with patches[0], patches[1]:
            with self.assertRaises(splunk_broker_module._BrokerError) as raised:
                state.op_dispatch_saved_search(
                    {
                        "report_id_url": "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/TestReport",
                        "earliest": "1",
                        "latest": "2",
                        "trigger_actions": True,
                    }
                )

        self.assertEqual(raised.exception.error_code, "dispatch_saved_search_failed")
        failed = next(fields for name, fields in events if name == "BROKER_OPERATION_FAILED")
        self.assertEqual(failed["operation"], "dispatch_saved_search")
        self.assertEqual(failed["exception_type"], "RuntimeError")
        self.assertIn("socket timeout", failed["exception_message"])

    def test_broker_allows_dispatch_while_prior_snapshot_op_is_still_running(self) -> None:
        class SlowSnapshotClient(DispatchTransportClient):
            def __init__(self) -> None:
                super().__init__(sid="dispatch_after_snapshot")
                self.snapshot_started = threading.Event()
                self.release_snapshot = threading.Event()
                self._last_snapshot_meta = {}

            def get_job_status_snapshot(self, *args, **kwargs):
                sid = kwargs.get("sid", "")
                timeout_seconds = int(kwargs.get("request_timeout_seconds", 1) or 1)
                self._last_snapshot_meta = {
                    "rest_endpoint": f"/services/search/jobs/{sid}",
                    "rest_method": "GET",
                    "request_timeout_seconds": timeout_seconds,
                    "response_shape": {"entry_present": False, "content_present": False},
                }
                self.snapshot_started.set()
                self.release_snapshot.wait(timeout=5.0)
                return "RUNNING", {"dispatchState": "RUNNING", "isDone": False, "isFailed": False}

        client = SlowSnapshotClient()
        state = _make_state(client)
        token = "contract-test-token"
        server = splunk_broker_module._SplunkBrokerHTTPServer(state=state, auth_token=token)
        thread = threading.Thread(target=server.serve_forever, name="BrokerContractServer", daemon=True)
        thread.start()
        proxy = splunk_broker_module.SplunkBrokerProxyClient(
            host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
            port=server.server_port,
            auth_token=token,
            username="splunk_service",
        )

        snapshot_error: list[Exception] = []

        def _snapshot_call() -> None:
            try:
                proxy.get_job_status_snapshot("snapshot_sid_001", request_timeout_seconds=1, stage_name="active_wait")
            except Exception as exc:
                snapshot_error.append(exc)

        snapshot_thread = threading.Thread(target=_snapshot_call, name="SnapshotProxyThread", daemon=True)
        snapshot_thread.start()
        self.assertTrue(client.snapshot_started.wait(timeout=1.0))

        try:
            dispatch_start = time.monotonic()
            ok, sid, err = proxy.dispatch_saved_search(
                "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/TestReport",
                earliest="1",
                latest="2",
                trigger_actions=True,
            )
            dispatch_elapsed_ms = int((time.monotonic() - dispatch_start) * 1000)
            time.sleep(3.2)
        finally:
            client.release_snapshot.set()
            snapshot_thread.join(timeout=2.0)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

        self.assertTrue(ok)
        self.assertEqual(sid, "dispatch_after_snapshot")
        self.assertEqual(err, "")
        self.assertLess(dispatch_elapsed_ms, 2000)
        self.assertTrue(snapshot_error)
        self.assertIsInstance(snapshot_error[0], Exception)
        self.assertEqual(len(client.dispatch_calls), 1)

    def test_broker_emits_active_operation_diagnostics_for_overlapping_snapshot_and_dispatch(self) -> None:
        class SlowSnapshotClient(DispatchTransportClient):
            def __init__(self) -> None:
                super().__init__(sid="dispatch_with_diag")
                self.snapshot_started = threading.Event()
                self.release_snapshot = threading.Event()
                self._last_snapshot_meta = {}

            def get_job_status_snapshot(self, *args, **kwargs):
                sid = kwargs.get("sid", "")
                self._last_snapshot_meta = {
                    "rest_endpoint": f"/services/search/jobs/{sid}",
                    "rest_method": "GET",
                    "response_status_code": 200,
                    "request_timeout_seconds": int(kwargs.get("request_timeout_seconds", 1) or 1),
                }
                self.snapshot_started.set()
                self.release_snapshot.wait(timeout=5.0)
                return "RUNNING", {"dispatchState": "RUNNING", "isDone": False, "isFailed": False}

        client = SlowSnapshotClient()
        state = _make_state(client)
        events, patches = self._capture_events()
        token = "contract-test-token-diag"
        with patches[0], patches[1]:
            server = splunk_broker_module._SplunkBrokerHTTPServer(state=state, auth_token=token)
            thread = threading.Thread(target=server.serve_forever, name="BrokerContractDiagServer", daemon=True)
            thread.start()
            proxy = splunk_broker_module.SplunkBrokerProxyClient(
                host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
                port=server.server_port,
                auth_token=token,
                username="splunk_service",
            )

            snapshot_error: list[Exception] = []

            def _snapshot_call() -> None:
                try:
                    proxy.get_job_status_snapshot("snapshot_sid_diag", request_timeout_seconds=1, stage_name="active_wait")
                except Exception as exc:
                    snapshot_error.append(exc)

            snapshot_thread = threading.Thread(target=_snapshot_call, name="SnapshotDiagThread", daemon=True)
            snapshot_thread.start()
            self.assertTrue(client.snapshot_started.wait(timeout=1.0))

            try:
                ok, sid, err = proxy.dispatch_saved_search(
                    "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/TestReport",
                    earliest="1",
                    latest="2",
                    trigger_actions=True,
                )
                time.sleep(3.2)
            finally:
                client.release_snapshot.set()
                snapshot_thread.join(timeout=2.0)
                server.shutdown()
                server.server_close()
                thread.join(timeout=2.0)

        self.assertTrue(ok)
        self.assertEqual(sid, "dispatch_with_diag")
        self.assertEqual(err, "")
        self.assertTrue(snapshot_error)
        event_names = [name for name, _fields in events]
        self.assertIn("BROKER_OP_STILL_RUNNING", event_names)
        self.assertIn("BROKER_OP_COMPLETED", event_names)
        running = next(fields for name, fields in events if name == "BROKER_OP_STILL_RUNNING")
        self.assertEqual(running["operation"], "dispatch_saved_search")
        self.assertGreaterEqual(int(running["active_op_count"]), 2)


if __name__ == "__main__":
    unittest.main()
