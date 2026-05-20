from __future__ import annotations

import threading
import time
import unittest
from datetime import datetime
from unittest.mock import patch

import splunk_engine
from Internal import splunk_broker as splunk_broker_module


class DummyAudit:
    def log_event(self, event: str, level: str = "INFO", **fields) -> None:
        del event, level, fields
        return


def _make_state(client):
    state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
    state.audit = DummyAudit()
    state.lock = threading.Lock()
    state.client = client
    state.cfg = None
    state.connected_server = "https://127.0.0.1:8089"
    state.config_error = ""
    return state


def _start_server(client, token: str):
    state = _make_state(client)
    server = splunk_broker_module._SplunkBrokerHTTPServer(state=state, auth_token=token)
    thread = threading.Thread(target=server.serve_forever, name=f"BrokerServer-{token}", daemon=True)
    thread.start()
    return server, thread


def _shutdown_server(server, thread) -> None:
    try:
        server.shutdown()
    except Exception:
        pass
    try:
        server.server_close()
    except Exception:
        pass
    thread.join(timeout=2.0)


class _BlockingDispatchClient:
    def __init__(self, release_event: threading.Event) -> None:
        self.release_event = release_event
        self.dispatch_calls = 0

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self.dispatch_calls += 1
        self.release_event.wait(timeout=5.0)
        return True, "slow_dispatch_sid", ""


class _FastDispatchClient:
    def __init__(self, sid: str) -> None:
        self.sid = sid
        self.dispatch_calls = 0

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self.dispatch_calls += 1
        return True, self.sid, ""

    def get_job_status_snapshot(self, *args, **kwargs):
        del args, kwargs
        return "SUCCESS", {"dispatchState": "DONE", "isDone": True}


class _BlockingSnapshotClient:
    def __init__(self, release_event: threading.Event) -> None:
        self.release_event = release_event
        self.dispatch_calls = 0
        self.snapshot_calls = 0

    def dispatch_saved_search(self, *args, **kwargs):
        del args, kwargs
        self.dispatch_calls += 1
        return True, "snapshot_block_sid", ""

    def get_job_status_snapshot(self, *args, **kwargs):
        del args, kwargs
        self.snapshot_calls += 1
        self.release_event.wait(timeout=6.0)
        return "SUCCESS", {"dispatchState": "DONE", "isDone": True}


class BrokerRecycleBehaviorTests(unittest.TestCase):
    def _proxy_with_recycler(self, initial_server, initial_thread, initial_token, recycle_factory, release_event=None):
        proxy = splunk_broker_module.SplunkBrokerProxyClient(
            host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
            port=initial_server.server_port,
            auth_token=initial_token,
            username="splunk_service",
        )
        recycle_state: dict[str, object] = {
            "server": initial_server,
            "thread": initial_thread,
            "count": 0,
            "replacement_server": None,
            "replacement_thread": None,
        }
        recycle_lock = threading.Lock()

        def _recycler(*, reason: str = "") -> None:
            del reason
            with recycle_lock:
                recycle_state["count"] = int(recycle_state["count"]) + 1
                replacement_client, replacement_token = recycle_factory()
                replacement_server, replacement_thread = _start_server(replacement_client, replacement_token)
                proxy._host = splunk_broker_module.SPLUNK_BROKER_BIND_HOST
                proxy._port = replacement_server.server_port
                proxy._auth_token = replacement_token
                recycle_state["replacement_server"] = replacement_server
                recycle_state["replacement_thread"] = replacement_thread
                if release_event is not None:
                    release_event.set()
                _shutdown_server(recycle_state["server"], recycle_state["thread"])  # type: ignore[arg-type]
                recycle_state["server"] = replacement_server
                recycle_state["thread"] = replacement_thread

        proxy.install_broker_recycler(_recycler)
        return proxy, recycle_state

    def test_proxy_dispatch_timeout_recycles_before_following_request(self) -> None:
        release_event = threading.Event()
        slow_client = _BlockingDispatchClient(release_event)
        server1, thread1 = _start_server(slow_client, "dispatch-timeout-token-1")

        fast_client = _FastDispatchClient("fresh_dispatch_sid")
        proxy, recycle_state = self._proxy_with_recycler(
            server1,
            thread1,
            "dispatch-timeout-token-1",
            lambda: (fast_client, "dispatch-timeout-token-2"),
            release_event=release_event,
        )

        try:
            ok, sid, err = proxy.dispatch_saved_search(
                "https://127.0.0.1:8089/servicesNS/test/search/saved/searches/TestReport",
                request_timeout_seconds=1,
            )
            self.assertFalse(ok)
            self.assertIsNone(sid)
            self.assertIn("timed out", err.lower())
            self.assertTrue(proxy.needs_transport_reset())

            proxy.reset_transport()

            ok, sid, err = proxy.dispatch_saved_search(
                "https://127.0.0.1:8089/servicesNS/test/search/saved/searches/TestReport",
                request_timeout_seconds=1,
            )
            self.assertTrue(ok)
            self.assertEqual(sid, "fresh_dispatch_sid")
            self.assertEqual(err, "")
            self.assertEqual(int(recycle_state["count"]), 1)
            self.assertEqual(fast_client.dispatch_calls, 1)
        finally:
            if not release_event.is_set():
                release_event.set()
            server = recycle_state["server"]
            thread = recycle_state["thread"]
            if server is not None and thread is not None:
                _shutdown_server(server, thread)

    def test_proxy_snapshot_timeout_recycles_before_following_request(self) -> None:
        release_event = threading.Event()
        blocking_client = _BlockingSnapshotClient(release_event)
        server1, thread1 = _start_server(blocking_client, "snapshot-timeout-token-1")

        fast_client = _FastDispatchClient("unused_dispatch_sid")
        proxy, recycle_state = self._proxy_with_recycler(
            server1,
            thread1,
            "snapshot-timeout-token-1",
            lambda: (fast_client, "snapshot-timeout-token-2"),
            release_event=release_event,
        )

        try:
            with self.assertRaises(splunk_broker_module.LocalSplunkBrokerTimeout):
                proxy.get_job_status_snapshot("sid-timeout", request_timeout_seconds=1)
            self.assertTrue(proxy.needs_transport_reset())

            proxy.reset_transport()

            state, content = proxy.get_job_status_snapshot("sid-fresh", request_timeout_seconds=1)
            self.assertEqual(state, "SUCCESS")
            self.assertEqual(content["dispatchState"], "DONE")
            self.assertEqual(int(recycle_state["count"]), 1)
        finally:
            if not release_event.is_set():
                release_event.set()
            server = recycle_state["server"]
            thread = recycle_state["thread"]
            if server is not None and thread is not None:
                _shutdown_server(server, thread)

    def test_proxy_reconnects_once_after_broker_reports_not_connected(self) -> None:
        proxy = splunk_broker_module.SplunkBrokerProxyClient(
            host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
            port=8089,
            auth_token="proxy-token",
            username="splunk_service",
        )
        proxy._connected_server_url = "https://127.0.0.1:8089"
        calls: list[tuple[str, dict, float]] = []

        def _fake_send(op: str, args: dict | None = None, *, timeout: float = 30.0):
            calls.append((op, dict(args or {}), timeout))
            if op == "get_job_status_snapshot" and len([entry for entry in calls if entry[0] == "get_job_status_snapshot"]) == 1:
                return 409, {"ok": False, "error": "not_connected", "message": "Not connected to Splunk."}
            if op == "connect":
                return 200, {"ok": True, "result": {"connected": True}}
            return 200, {"ok": True, "result": {"state": "SUCCESS", "content": {"dispatchState": "DONE", "isDone": True}}}

        proxy._send_op_request = _fake_send  # type: ignore[method-assign]

        state, content = proxy.get_job_status_snapshot("sid-reconnect", request_timeout_seconds=1)
        self.assertEqual(state, "SUCCESS")
        self.assertEqual(content["dispatchState"], "DONE")
        self.assertEqual([entry[0] for entry in calls], ["get_job_status_snapshot", "connect", "get_job_status_snapshot"])

    def test_proxy_reconnects_once_after_broker_reports_auth_expiry(self) -> None:
        proxy = splunk_broker_module.SplunkBrokerProxyClient(
            host=splunk_broker_module.SPLUNK_BROKER_BIND_HOST,
            port=8089,
            auth_token="proxy-token",
            username="splunk_service",
        )
        proxy._connected_server_url = "https://127.0.0.1:8089"
        calls: list[str] = []

        def _fake_send(op: str, args: dict | None = None, *, timeout: float = 30.0):
            del args, timeout
            calls.append(op)
            if op == "find_job_candidates" and calls.count("find_job_candidates") == 1:
                return 401, {"ok": False, "error": "splunk_auth_failed", "message": "Authentication failed (401/403)."}
            if op == "connect":
                return 200, {"ok": True, "result": {"connected": True}}
            return 200, {"ok": True, "result": {"jobs": []}}

        proxy._send_op_request = _fake_send  # type: ignore[method-assign]

        jobs = proxy.find_job_candidates(label="TestReport", owner="splunk_service", app="search")
        self.assertEqual(jobs, [])
        self.assertEqual(calls, ["find_job_candidates", "connect", "find_job_candidates"])

    def test_run_dispatch_single_recycles_broker_after_dispatch_timeout_before_next_slice(self) -> None:
        release_event = threading.Event()
        slow_client = _BlockingDispatchClient(release_event)
        server1, thread1 = _start_server(slow_client, "slice-dispatch-token-1")
        fast_client = _FastDispatchClient("fresh_slice_sid")
        proxy, recycle_state = self._proxy_with_recycler(
            server1,
            thread1,
            "slice-dispatch-token-1",
            lambda: (fast_client, "slice-dispatch-token-2"),
            release_event=release_event,
        )

        try:
            logs = splunk_engine.run_dispatch_single(
                proxy,
                report_id_url="/servicesNS/test/search/saved/searches/TestReport",
                report_name="TestReport",
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 3, 0, 0, 0),
                no_change=False,
                wait_seconds=2,
                poll_interval=1,
                continue_on_timeout=True,
                dispatch_call_timeout_seconds=1,
            )
            joined = "\n".join(logs)
            self.assertIn("[1/2] Email report sent successfully.", joined)
            self.assertIn("[2/2] Email report sent successfully.", joined)
            self.assertEqual(int(recycle_state["count"]), 1)
            self.assertEqual(fast_client.dispatch_calls, 1)
            self.assertIn("The original timed-out dispatch later returned a SID", joined)
        finally:
            if not release_event.is_set():
                release_event.set()
            server = recycle_state["server"]
            thread = recycle_state["thread"]
            if server is not None and thread is not None:
                _shutdown_server(server, thread)

    def test_run_dispatch_single_recycles_broker_after_snapshot_timeout_before_next_slice(self) -> None:
        release_event = threading.Event()
        blocking_client = _BlockingSnapshotClient(release_event)
        server1, thread1 = _start_server(blocking_client, "slice-snapshot-token-1")
        fast_client = _FastDispatchClient("fresh_snapshot_slice_sid")
        proxy, recycle_state = self._proxy_with_recycler(
            server1,
            thread1,
            "slice-snapshot-token-1",
            lambda: (fast_client, "slice-snapshot-token-2"),
            release_event=release_event,
        )

        try:
            with patch.object(splunk_engine, "DEFAULT_STATUS_SNAPSHOT_TIMEOUT_RETRIES", 0):
                logs = splunk_engine.run_dispatch_single(
                    proxy,
                    report_id_url="/servicesNS/test/search/saved/searches/TestReport",
                    report_name="TestReport",
                    frequency="Daily",
                    start=datetime(2026, 3, 1, 0, 0, 0),
                    end=datetime(2026, 3, 3, 0, 0, 0),
                    no_change=False,
                    wait_seconds=2,
                    poll_interval=1,
                    continue_on_timeout=True,
                    dispatch_call_timeout_seconds=2,
                )
            joined = "\n".join(logs)
            self.assertIn("[1/2] PENDING (sid=snapshot_block_sid)", joined)
            self.assertIn("[2/2] Email report sent successfully.", joined)
            self.assertEqual(int(recycle_state["count"]), 1)
            self.assertEqual(fast_client.dispatch_calls, 1)
        finally:
            if not release_event.is_set():
                release_event.set()
            server = recycle_state["server"]
            thread = recycle_state["thread"]
            if server is not None and thread is not None:
                _shutdown_server(server, thread)


if __name__ == "__main__":
    unittest.main()
