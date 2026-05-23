from __future__ import annotations

import unittest

import splunk_engine
from Internal import splunk_broker as splunk_broker_module


class BrokerIsolatedOperationTests(unittest.TestCase):
    def test_create_isolated_rest_client_reuses_existing_auth_header(self) -> None:
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://127.0.0.1:8089"
        client.username = "tester"
        client._password = "secret"
        client.auth_mode = "password"
        client.verify_ssl = False
        client.session = splunk_engine.requests.Session()
        client.session.trust_env = False
        client.session.verify = False
        client._auth_header = "Splunk existing-session-key"
        client._last_snapshot_meta = {}

        isolated = client.create_isolated_rest_client()

        self.assertIsNot(isolated, client)
        self.assertEqual(isolated.base_url, client.base_url)
        self.assertEqual(isolated.username, client.username)
        self.assertEqual(isolated._auth_header, "Splunk existing-session-key")
        self.assertIsNot(isolated.session, client.session)
        self.assertFalse(isolated.session.trust_env)
        self.assertFalse(isolated.session.verify)
        isolated.close_transport()
        client.close_transport()

    def test_snapshot_uses_isolated_backend_client(self) -> None:
        class Audit:
            def log_event(self, *args, **kwargs):
                del args, kwargs

        class IsolatedClient:
            def __init__(self) -> None:
                self.closed = False
                self.snapshot_calls: list[tuple[str, int]] = []

            def get_job_status_snapshot(
                self,
                *,
                sid: str,
                request_timeout_seconds: int,
                retry_count: int = 0,
                stage_name: str = "",
            ):
                del retry_count, stage_name
                self.snapshot_calls.append((sid, request_timeout_seconds))
                return "SUCCESS", {"dispatchState": "DONE"}

            def close_transport(self) -> None:
                self.closed = True

        class BaseClient:
            def __init__(self) -> None:
                self.isolated_client = IsolatedClient()
                self.base_snapshot_called = False

            def create_isolated_rest_client(self):
                return self.isolated_client

            def get_job_status_snapshot(self, **kwargs):
                del kwargs
                self.base_snapshot_called = True
                raise AssertionError("shared client should not be used for snapshot operations")

        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = Audit()
        state.client = BaseClient()

        result = state.op_get_job_status_snapshot({"sid": "sid-unit-001", "request_timeout_seconds": 7})

        self.assertEqual(result["state"], "SUCCESS")
        self.assertEqual(result["content"]["dispatchState"], "DONE")
        self.assertFalse(state.client.base_snapshot_called)
        self.assertEqual(state.client.isolated_client.snapshot_calls, [("sid-unit-001", 7)])
        self.assertTrue(state.client.isolated_client.closed)

    def test_list_saved_searches_uses_isolated_backend_client(self) -> None:
        class Audit:
            def log_event(self, *args, **kwargs):
                del args, kwargs

        class IsolatedClient:
            def __init__(self) -> None:
                self.closed = False
                self.apps: list[str] = []

            def list_saved_searches(self, app: str):
                self.apps.append(app)
                return (
                    ["id-1"],
                    ["[Splunk10] TestReport"],
                    [True],
                )

            def close_transport(self) -> None:
                self.closed = True

        class BaseClient:
            def __init__(self) -> None:
                self.isolated_client = IsolatedClient()
                self.base_list_called = False

            def create_isolated_rest_client(self):
                return self.isolated_client

            def list_saved_searches(self, app: str):
                del app
                self.base_list_called = True
                raise AssertionError("shared client should not be used for list_saved_searches")

        state = splunk_broker_module._SplunkBrokerState.__new__(splunk_broker_module._SplunkBrokerState)
        state.audit = Audit()
        state.client = BaseClient()

        result = state.op_list_saved_searches({"app": "search"})

        self.assertEqual(result["ids"], ["id-1"])
        self.assertEqual(result["names"], ["[Splunk10] TestReport"])
        self.assertEqual(result["email_flags"], [True])
        self.assertFalse(state.client.base_list_called)
        self.assertEqual(state.client.isolated_client.apps, ["search"])
        self.assertTrue(state.client.isolated_client.closed)


if __name__ == "__main__":
    unittest.main()
