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
    state.lock = threading.Lock()
    state.client = client
    state.cfg = None
    state.connected_server = "https://127.0.0.1:8089"
    state.config_error = ""
    state.exe_dir = ""
    state._ensure_runtime_initialized()
    return state


class _LaneClient:
    def __init__(self) -> None:
        self._last_dispatch_meta: dict[str, object] = {}
        self.evidence_started = threading.Event()
        self.evidence_release = threading.Event()
        self.metadata_started = threading.Event()
        self.metadata_release = threading.Event()
        self.dispatch_calls = 0
        self.snapshot_calls = 0
        self.close_calls = 0
        self.fail_metadata = False
        self.block_saved_search_metadata = False

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self.dispatch_calls += 1
        self._last_dispatch_meta = {"sid": "dispatch_lane_sid"}
        return True, "dispatch_lane_sid", ""

    def get_job_status_snapshot(self, *args, **kwargs):
        del args, kwargs
        self.snapshot_calls += 1
        return "SUCCESS", {"dispatchState": "DONE", "isDone": True}

    def find_job_candidates(self, *args, **kwargs):
        del args, kwargs
        self.evidence_started.set()
        self.evidence_release.wait(timeout=5.0)
        return []

    def list_apps(self):
        if self.fail_metadata:
            raise RuntimeError("metadata backend unavailable")
        return ["search"]

    def _get(self, path: str, **kwargs):
        del kwargs
        if self.fail_metadata:
            raise RuntimeError("metadata backend unavailable")
        if self.block_saved_search_metadata:
            self.metadata_started.set()
            self.metadata_release.wait(timeout=5.0)
        return {"entry": [{"content": {"action.email.to": "ops@example.com"}}], "path": path}

    def close_transport(self) -> None:
        self.close_calls += 1
        self.evidence_release.set()
        self.metadata_release.set()


class _TimeoutCleanupClient:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.close_calls = 0

    def find_job_candidates(self, *args, **kwargs):
        del args, kwargs
        self.started.set()
        self.release.wait(timeout=5.0)
        return []

    def close_transport(self) -> None:
        self.close_calls += 1
        self.release.set()


class _RuntimeDefectClient:
    def list_apps(self):
        raise TypeError("programming defect in metadata handling")


class BrokerLaneHardeningTests(unittest.TestCase):
    def test_dispatch_lane_isolated_from_evidence_lane(self) -> None:
        client = _LaneClient()
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)
        evidence_result: dict[str, object] = {}

        def _run_evidence() -> None:
            evidence_result["value"] = state.submit_lane_request(
                "find_job_candidates",
                {"label": "TestReport", "owner": "svc", "app": "search", "limit": 5, "page_size": 5},
            )

        worker = threading.Thread(target=_run_evidence, daemon=True)
        worker.start()
        self.assertTrue(client.evidence_started.wait(timeout=1.0))

        started = time.monotonic()
        result = state.submit_lane_request(
            "dispatch_saved_search",
            {
                "report_id_url": "https://127.0.0.1:8089/servicesNS/svc/search/saved/searches/TestReport",
                "earliest": "1",
                "latest": "2",
                "trigger_actions": True,
            },
        )
        elapsed = time.monotonic() - started
        client.evidence_release.set()
        worker.join(timeout=2.0)

        self.assertLess(elapsed, 1.0)
        self.assertTrue(result["ok"])
        self.assertEqual(result["sid"], "dispatch_lane_sid")
        self.assertEqual(client.dispatch_calls, 1)
        self.assertIn("value", evidence_result)

    def test_verification_lane_isolated_from_evidence_lane(self) -> None:
        client = _LaneClient()
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)

        worker = threading.Thread(
            target=lambda: state.submit_lane_request(
                "find_job_candidates",
                {"label": "TestReport", "owner": "svc", "app": "search", "limit": 5, "page_size": 5},
            ),
            daemon=True,
        )
        worker.start()
        self.assertTrue(client.evidence_started.wait(timeout=1.0))

        started = time.monotonic()
        result = state.submit_lane_request(
            "get_job_status_snapshot",
            {"sid": "verification_sid", "request_timeout_seconds": 5},
        )
        elapsed = time.monotonic() - started
        client.evidence_release.set()
        worker.join(timeout=2.0)

        self.assertLess(elapsed, 1.0)
        self.assertEqual(result["state"], "SUCCESS")
        self.assertEqual(client.snapshot_calls, 1)

    def test_metadata_lane_failure_does_not_poison_dispatch_lane(self) -> None:
        client = _LaneClient()
        client.fail_metadata = True
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)

        for _ in range(splunk_broker_module.BROKER_BREAKER_FAILURE_THRESHOLD):
            with self.assertRaises(splunk_broker_module._BrokerError) as cm:
                state.submit_lane_request("list_apps", {})
            self.assertEqual(cm.exception.error_code, "failed_metadata_fetch")

        with self.assertRaises(splunk_broker_module._BrokerError) as cm:
            state.submit_lane_request("list_apps", {})
        self.assertEqual(cm.exception.error_code, "broker_overloaded")

        result = state.submit_lane_request(
            "dispatch_saved_search",
            {
                "report_id_url": "https://127.0.0.1:8089/servicesNS/svc/search/saved/searches/TestReport",
                "earliest": "1",
                "latest": "2",
                "trigger_actions": True,
            },
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["sid"], "dispatch_lane_sid")

    def test_saved_search_metadata_lane_isolated_from_dispatch_lane(self) -> None:
        client = _LaneClient()
        client.block_saved_search_metadata = True
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)
        metadata_result: dict[str, object] = {}

        def _run_metadata() -> None:
            metadata_result["value"] = state.submit_lane_request(
                "get_saved_search_metadata",
                {"path": "/servicesNS/svc/search/saved/searches/TestReport"},
            )

        worker = threading.Thread(target=_run_metadata, daemon=True)
        worker.start()
        self.assertTrue(client.metadata_started.wait(timeout=1.0))

        started = time.monotonic()
        result = state.submit_lane_request(
            "dispatch_saved_search",
            {
                "report_id_url": "https://127.0.0.1:8089/servicesNS/svc/search/saved/searches/TestReport",
                "earliest": "1",
                "latest": "2",
                "trigger_actions": True,
            },
        )
        elapsed = time.monotonic() - started
        client.metadata_release.set()
        worker.join(timeout=2.0)

        self.assertLess(elapsed, 1.0)
        self.assertTrue(result["ok"])
        self.assertEqual(result["sid"], "dispatch_lane_sid")
        self.assertIn("value", metadata_result)

    def test_broker_timeout_triggers_session_cleanup(self) -> None:
        client = _TimeoutCleanupClient()
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)
        original_spec = splunk_broker_module._BROKER_LANE_SPECS[splunk_broker_module.BROKER_REQUEST_CLASS_EVIDENCE]
        fast_timeout_spec = splunk_broker_module._BrokerLaneSpec(
            request_class=original_spec.request_class,
            lane_name=original_spec.lane_name,
            max_workers=original_spec.max_workers,
            connect_timeout_seconds=original_spec.connect_timeout_seconds,
            read_timeout_seconds=1.0,
            total_budget_seconds=1.0,
        )

        with patch.dict(
            splunk_broker_module._BROKER_LANE_SPECS,
            {splunk_broker_module.BROKER_REQUEST_CLASS_EVIDENCE: fast_timeout_spec},
            clear=False,
        ):
            with self.assertRaises(splunk_broker_module._BrokerError) as cm:
                state.submit_lane_request(
                    "find_job_candidates",
                    {"label": "TestReport", "owner": "svc", "app": "search", "limit": 5, "page_size": 5},
                )
        self.assertEqual(cm.exception.error_code, "timeout_evidence_delay")
        self.assertGreaterEqual(client.close_calls, 1)

    def test_proxy_timeout_budgets_align_to_lane_specs(self) -> None:
        proxy = splunk_broker_module.SplunkBrokerProxyClient(
            host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
            port=8089,
            auth_token="token",
            username="svc",
        )
        captured: list[tuple[str, float]] = []

        def _fake_op(op: str, args=None, *, timeout: float = 30.0, allow_reconnect: bool = True):
            del args, allow_reconnect
            captured.append((op, timeout))
            if op == "dispatch_saved_search":
                return {"ok": True, "sid": "sid-budget", "error": "", "meta": {}}
            if op == "get_job_status_snapshot":
                return {"state": "SUCCESS", "content": {}, "meta": {}}
            if op == "find_job_candidates":
                return {"jobs": []}
            if op == "export_search_json":
                return {"data": {"results": []}}
            if op == "list_apps":
                return {"apps": []}
            if op == "get_saved_search_metadata":
                return {"meta": {}}
            return {}

        proxy._op = _fake_op  # type: ignore[method-assign]

        proxy.dispatch_saved_search(
            "https://127.0.0.1:8089/servicesNS/svc/search/saved/searches/TestReport",
            request_timeout_seconds=300,
        )
        proxy.get_job_status_snapshot("sid-budget", request_timeout_seconds=30)
        proxy.find_job_candidates(label="TestReport", owner="svc", app="search")
        proxy.list_apps()
        proxy._get("/servicesNS/svc/search/saved/searches/TestReport")
        proxy._get("/services/search/jobs/export", params={"search": "search index=_internal"})

        captured_map = {op: timeout for op, timeout in captured}
        self.assertLessEqual(captured_map["dispatch_saved_search"], 35.0)
        self.assertLessEqual(captured_map["get_job_status_snapshot"], 12.0)
        self.assertLessEqual(captured_map["find_job_candidates"], 10.0)
        self.assertLessEqual(captured_map["list_apps"], 12.0)
        self.assertLessEqual(captured_map["get_saved_search_metadata"], 12.0)
        self.assertLessEqual(captured_map["export_search_json"], 10.0)

    def test_proxy_get_routes_export_search_away_from_saved_search_metadata(self) -> None:
        proxy = splunk_broker_module.SplunkBrokerProxyClient(
            host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
            port=8089,
            auth_token="token",
            username="svc",
        )
        captured_ops: list[str] = []

        def _fake_op(op: str, args=None, *, timeout: float = 30.0, allow_reconnect: bool = True):
            del args, timeout, allow_reconnect
            captured_ops.append(op)
            if op == "export_search_json":
                return {"data": {"results": []}}
            if op == "get_saved_search_metadata":
                return {"meta": {"entry": []}}
            return {}

        proxy._op = _fake_op  # type: ignore[method-assign]

        proxy._get("/services/search/jobs/export", params={"search": "search index=_internal"})
        proxy._get("/servicesNS/svc/search/saved/searches/Test%20Report")

        self.assertEqual(captured_ops, ["export_search_json", "get_saved_search_metadata"])

    def test_proxy_dispatch_preflight_recycles_when_dispatch_lane_is_busy(self) -> None:
        proxy = splunk_broker_module.SplunkBrokerProxyClient(
            host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
            port=8089,
            auth_token="token",
            username="svc",
        )
        recycle_calls: list[str] = []

        def _fake_health():
            return {
                "connected": True,
                "broker_runtime": {
                    "active_requests_by_class": {
                        splunk_broker_module.BROKER_REQUEST_CLASS_DISPATCH: 1,
                    },
                    "recent_timeout_count_by_class": {
                        splunk_broker_module.BROKER_REQUEST_CLASS_DISPATCH: 2,
                        splunk_broker_module.BROKER_REQUEST_CLASS_METADATA: 1,
                    },
                },
            }

        def _fake_ensure(op: str) -> None:
            recycle_calls.append(op)

        def _fake_op(op: str, args=None, *, timeout: float = 30.0, allow_reconnect: bool = True):
            del args, timeout, allow_reconnect
            if op == "dispatch_saved_search":
                return {"ok": True, "sid": "preflight_sid", "error": "", "meta": {}}
            raise AssertionError(f"unexpected op {op}")

        proxy.health = _fake_health  # type: ignore[method-assign]
        proxy._ensure_healthy_broker = _fake_ensure  # type: ignore[method-assign]
        proxy._mark_broker_tainted = lambda op, reason: None  # type: ignore[method-assign]
        proxy._op = _fake_op  # type: ignore[method-assign]
        proxy._recent_metadata_activity = {"outcome": "timeout_metadata_fetch", "age_ms": 1500}

        ok, sid, err = proxy.dispatch_saved_search(
            "https://127.0.0.1:8089/servicesNS/svc/search/saved/searches/TestReport",
            request_timeout_seconds=30,
        )

        self.assertTrue(ok)
        self.assertEqual(sid, "preflight_sid")
        self.assertEqual(err, "")
        self.assertEqual(recycle_calls, ["dispatch_saved_search"])
        self.assertTrue(proxy._last_dispatch_meta["preflight_recycle_triggered"])
        self.assertEqual(proxy._last_dispatch_meta["preflight_dispatch_lane_active"], 1)

    def test_half_open_probe_success_closes_degraded_mode(self) -> None:
        client = _LaneClient()
        client.fail_metadata = True
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)

        for _ in range(splunk_broker_module.BROKER_BREAKER_FAILURE_THRESHOLD):
            with self.assertRaises(splunk_broker_module._BrokerError):
                state.submit_lane_request("list_apps", {})

        with self.assertRaises(splunk_broker_module._BrokerError):
            state.submit_lane_request("list_apps", {})

        with state._breaker_lock:
            breaker = state._breaker_state_for_class(splunk_broker_module.BROKER_REQUEST_CLASS_METADATA)
            breaker.open_until = time.monotonic() - 1.0
            breaker.half_open_probe_inflight = False

        client.fail_metadata = False
        result = state.submit_lane_request("list_apps", {})
        health = state._health_counters_payload()

        self.assertEqual(result["apps"], ["search"])
        self.assertFalse(health["degraded_mode"][splunk_broker_module.BROKER_REQUEST_CLASS_METADATA]["open"])

    def test_half_open_probe_failure_reopens_degraded_mode(self) -> None:
        client = _LaneClient()
        client.fail_metadata = True
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)

        for _ in range(splunk_broker_module.BROKER_BREAKER_FAILURE_THRESHOLD):
            with self.assertRaises(splunk_broker_module._BrokerError):
                state.submit_lane_request("list_apps", {})

        with state._breaker_lock:
            breaker = state._breaker_state_for_class(splunk_broker_module.BROKER_REQUEST_CLASS_METADATA)
            breaker.open_until = time.monotonic() - 1.0
            breaker.half_open_probe_inflight = False

        with self.assertRaises(splunk_broker_module._BrokerError) as cm:
            state.submit_lane_request("list_apps", {})
        self.assertEqual(cm.exception.error_code, "failed_metadata_fetch")

        with self.assertRaises(splunk_broker_module._BrokerError) as cm:
            state.submit_lane_request("list_apps", {})
        self.assertEqual(cm.exception.error_code, "broker_overloaded")

    def test_internal_runtime_errors_do_not_open_breaker(self) -> None:
        client = _RuntimeDefectClient()
        state = _make_state(client)
        self.addCleanup(state.shutdown_runtime)

        for _ in range(splunk_broker_module.BROKER_BREAKER_FAILURE_THRESHOLD + 1):
            with self.assertRaises(splunk_broker_module._BrokerError) as cm:
                state.submit_lane_request("list_apps", {})
            self.assertEqual(cm.exception.error_code, "internal_runtime_error")

        health = state._health_counters_payload()
        self.assertEqual(
            health["recent_timeout_count_by_class"][splunk_broker_module.BROKER_REQUEST_CLASS_METADATA],
            0,
        )
        self.assertFalse(
            health["degraded_mode"][splunk_broker_module.BROKER_REQUEST_CLASS_METADATA]["open"]
        )


if __name__ == "__main__":
    unittest.main()
