from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

import splunk_engine
from Internal import splunk_broker as splunk_broker_module
from Internal.tool_logging import configure_tool_logging, shutdown_tool_logging


class TransportLoggingRecoveryTests(unittest.TestCase):
    def tearDown(self) -> None:
        shutdown_tool_logging()

    def test_dispatch_saved_search_uses_one_shot_session_without_env_proxy(self) -> None:
        class SharedSession:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                raise AssertionError("dispatch_saved_search should not reuse the shared client session")

        class Response:
            status_code = 201

            def __init__(self) -> None:
                self.headers = {"Location": "/services/search/jobs/1700000_dispatch_sid"}
                self.closed = False
                self.elapsed = type("_Elapsed", (), {"total_seconds": staticmethod(lambda: 0.123)})()

            @property
            def text(self):
                raise AssertionError("response body should not be read when Location already provides the SID")

            def close(self) -> None:
                self.closed = True

        class OneShotSession:
            def __init__(self) -> None:
                self.trust_env = True
                self.calls: list[dict[str, object]] = []
                self.closed = False

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                return Response()

            def close(self) -> None:
                self.closed = True

        shared_session = SharedSession()
        oneshot_session = OneShotSession()
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://127.0.0.1:8089"
        client._auth_header = "Splunk test-session"
        client.verify_ssl = False
        client.session = shared_session
        client._last_dispatch_meta = {}

        with patch.object(splunk_engine.requests, "Session", return_value=oneshot_session):
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
        self.assertEqual(shared_session.calls, [])
        self.assertFalse(oneshot_session.trust_env)
        self.assertTrue(oneshot_session.closed)
        self.assertEqual(len(oneshot_session.calls), 1)
        call = oneshot_session.calls[0]
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["timeout"], (splunk_engine.DEFAULT_HTTP_CONNECT_TIMEOUT_SECONDS, 30))
        self.assertFalse(call["verify"])
        self.assertFalse(call["allow_redirects"])
        self.assertEqual(call["headers"]["Authorization"], "Splunk test-session")
        self.assertEqual(call["headers"]["Connection"], "close")
        self.assertEqual(call["data"]["output_mode"], "json")
        self.assertEqual(call["data"]["trigger_actions"], 1)
        self.assertEqual(client._last_dispatch_meta["transport_mode"], "oneshot_request")
        self.assertEqual(client._last_dispatch_meta["sid_source"], "location_header")

    def test_dispatch_saved_search_falls_back_to_json_body_without_location(self) -> None:
        class Response:
            status_code = 201

            def __init__(self) -> None:
                self.headers = {}
                self.closed = False
                self.elapsed = type("_Elapsed", (), {"total_seconds": staticmethod(lambda: 0.111)})()
                self.text = '{"sid":"1700000_dispatch_sid_json"}'

            def close(self) -> None:
                self.closed = True

        class OneShotSession:
            def __init__(self) -> None:
                self.trust_env = True

            def request(self, **kwargs):
                del kwargs
                return Response()

            def close(self) -> None:
                return

        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://127.0.0.1:8089"
        client._auth_header = "Splunk test-session"
        client.verify_ssl = False
        client.session = object()
        client._last_dispatch_meta = {}

        with patch.object(splunk_engine.requests, "Session", return_value=OneShotSession()):
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

    def test_broker_dispatch_saved_search_writes_debug_log_with_transport_mode(self) -> None:
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
                            "transport_mode": "oneshot_request",
                            "sid": "sid-unit-001",
                            "sid_source": "location_header",
                            "response_location": "/services/search/jobs/sid-unit-001",
                        }
                        return True, "sid-unit-001", ""

                state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
                state.audit = type(
                    "_Audit",
                    (),
                    {"log_event": staticmethod(lambda *args, **kwargs: None)},
                )()
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
                with open(debug_path, "r", encoding="utf-8") as handle:
                    debug_text = handle.read()
                self.assertIn("DISPATCH_SAVED_SEARCH_REQUESTED", debug_text)
                self.assertIn("DISPATCH_SAVED_SEARCH_RESPONSE_HEADERS", debug_text)
                self.assertIn("DISPATCH_SAVED_SEARCH_SID_PARSED", debug_text)
                self.assertIn("DISPATCH_SAVED_SEARCH_COMPLETED", debug_text)
                self.assertIn("transport_mode=oneshot_request", debug_text)
                self.assertIn(
                    "rest_endpoint=/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport/dispatch",
                    debug_text,
                )
            finally:
                shutdown_tool_logging()

    def test_runtime_payload_preserves_file_logging_config(self) -> None:
        cfg = splunk_engine.SplunkConfig(
            servers=["https://127.0.0.1:8089"],
            username="tester",
            password="",
            file_logging_config={
                "runtime_log_enabled": True,
                "debug_log_enabled": True,
                "debug_broker_enabled": True,
            },
            runtime_config={"test_mode": False},
        )
        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.cfg = cfg

        payload = state._runtime_config_payload()

        self.assertTrue(payload["file_logging_config"]["runtime_log_enabled"])
        self.assertTrue(payload["file_logging_config"]["debug_log_enabled"])
        self.assertTrue(payload["file_logging_config"]["debug_broker_enabled"])
        self.assertFalse(payload["runtime_config"]["test_mode"])


if __name__ == "__main__":
    unittest.main()
