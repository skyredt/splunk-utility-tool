from __future__ import annotations

import threading
import time
import unittest
from unittest.mock import patch

from Internal import splunk_broker as splunk_broker_module


class DummyAudit:
    def log_event(self, event: str, level: str = "INFO", **fields) -> None:
        del event, level, fields


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


class DispatchClient:
    def __init__(self, sid: str = "sid-unit-001") -> None:
        self.sid = sid
        self._last_dispatch_meta: dict[str, object] = {}

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self._last_dispatch_meta = {
            "request_body_summary": "{\"dispatch.latest_time\":\"1773158400\",\"output_mode\":\"json\"}",
            "request_start_time": "2026-03-24T03:28:58Z",
            "connect_timeout_seconds": 10,
            "read_timeout_seconds": 30,
            "response_status_code": 201,
            "response_headers_elapsed_ms": 95,
            "response_body_read_elapsed_ms": 0,
            "json_parse_elapsed_ms": 0,
            "post_sid_return_work_ms": 0,
            "sid": self.sid,
            "sid_source": "location_header",
            "response_location": f"/services/search/jobs/{self.sid}",
        }
        return True, self.sid, ""


class SlowDispatchClient(DispatchClient):
    def dispatch_saved_search(self, *args, **kwargs):
        time.sleep(0.03)
        return super().dispatch_saved_search(*args, **kwargs)


class MetadataClient:
    def _get(self, path: str):
        del path
        time.sleep(0.03)
        return {
            "entry": [
                {
                    "name": "[Splunk10] TestReport",
                    "content": {"action.email.to": "user@example.com"},
                }
            ]
        }


class BrokerDispatchRuntimeTraceTests(unittest.TestCase):
    def test_dispatch_runtime_trace_lines_emit_without_broker_debug_logging(self) -> None:
        state = _make_state(DispatchClient(sid="trace123"))
        runtime_lines: list[tuple[str, str]] = []

        with patch.object(splunk_broker_module, "debug_category_enabled", lambda category: False), patch.object(
            splunk_broker_module,
            "runtime_log",
            lambda message, level="INFO": runtime_lines.append((level, str(message))) or True,
        ):
            result = state.op_dispatch_saved_search(
                {
                    "report_id_url": "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                    "earliest": "1772726400",
                    "latest": "1773158400",
                    "trigger_actions": True,
                    "trace_context": {
                        "correlation_id": "corr-trace-001",
                        "slice_label": "[4/4]",
                    },
                }
            )

        self.assertTrue(result["ok"])
        trace_messages = [message for _, message in runtime_lines]
        self.assertTrue(any("BROKER_DISPATCH_REQUEST_RECEIVED" in message for message in trace_messages))
        self.assertTrue(any("BROKER_DISPATCH_BACKEND_START" in message for message in trace_messages))
        self.assertTrue(any("BROKER_DISPATCH_BACKEND_RETURN" in message for message in trace_messages))
        self.assertTrue(any("correlation_id=corr-trace-001" in message for message in trace_messages))

    def test_dispatch_runtime_trace_watchdog_logs_long_backend_wait(self) -> None:
        state = _make_state(SlowDispatchClient(sid="slow123"))
        runtime_lines: list[tuple[str, str]] = []

        with patch.object(
            splunk_broker_module,
            "_BROKER_DISPATCH_WATCHDOG_SECONDS",
            (0.01, 0.02),
        ), patch.object(
            splunk_broker_module,
            "runtime_log",
            lambda message, level="INFO": runtime_lines.append((level, str(message))) or True,
        ):
            result = state.op_dispatch_saved_search(
                {
                    "report_id_url": "https://127.0.0.1:8089/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                    "earliest": "1772726400",
                    "latest": "1773158400",
                    "trigger_actions": True,
                }
            )

        self.assertTrue(result["ok"])
        still_waiting = [message for level, message in runtime_lines if "BROKER_DISPATCH_BACKEND_STILL_WAITING" in message]
        self.assertTrue(still_waiting)
        self.assertTrue(any(level == "WARN" for level, message in runtime_lines if "BROKER_DISPATCH_BACKEND_STILL_WAITING" in message))

    def test_metadata_runtime_trace_logs_request_start_wait_and_return(self) -> None:
        state = _make_state(MetadataClient())
        runtime_lines: list[tuple[str, str]] = []

        with patch.object(
            splunk_broker_module,
            "_BROKER_METADATA_WATCHDOG_SECONDS",
            (0.01, 0.02),
        ), patch.object(
            splunk_broker_module,
            "runtime_log",
            lambda message, level="INFO": runtime_lines.append((level, str(message))) or True,
        ):
            result = state.op_get_saved_search_metadata(
                {
                    "path": "/servicesNS/skyred5/search/saved/searches/%5BSplunk10%5D%20TestReport",
                }
            )

        self.assertIn("meta", result)
        messages = [message for _, message in runtime_lines]
        self.assertTrue(any("BROKER_METADATA_REQUEST_RECEIVED" in message for message in messages))
        self.assertTrue(any("BROKER_METADATA_BACKEND_START" in message for message in messages))
        self.assertTrue(any("BROKER_METADATA_BACKEND_STILL_WAITING" in message for message in messages))
        self.assertTrue(any("BROKER_METADATA_BACKEND_RETURN" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
