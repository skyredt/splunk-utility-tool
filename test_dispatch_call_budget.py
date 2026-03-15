from __future__ import annotations

import threading
import time
import unittest

import splunk_engine


class DispatchCallBudgetTests(unittest.TestCase):
    def test_dispatch_saved_search_with_budget_returns_sid(self) -> None:
        class Client:
            def dispatch_saved_search(self, report_id_url, *, earliest=None, latest=None):
                self.call = {
                    "report_id_url": report_id_url,
                    "earliest": earliest,
                    "latest": latest,
                }
                return True, "sid-123", ""

        client = Client()

        state, ok, sid, err, elapsed_ms = splunk_engine._dispatch_saved_search_with_budget(
            client,
            report_id_url="/servicesNS/test/search/saved/searches/example",
            earliest="100",
            latest="200",
            timeout_seconds=1,
        )

        self.assertEqual(state, "RETURNED")
        self.assertTrue(ok)
        self.assertEqual(sid, "sid-123")
        self.assertEqual(err, "")
        self.assertGreaterEqual(elapsed_ms, 0)
        self.assertEqual(client.call["earliest"], "100")
        self.assertEqual(client.call["latest"], "200")

    def test_dispatch_saved_search_with_budget_times_out_before_return(self) -> None:
        release = threading.Event()

        class Client:
            def dispatch_saved_search(self, report_id_url, *, earliest=None, latest=None):
                del report_id_url, earliest, latest
                release.wait(timeout=0.3)
                return True, "sid-late", ""

        client = Client()
        try:
            state, ok, sid, err, elapsed_ms = splunk_engine._dispatch_saved_search_with_budget(
                client,
                report_id_url="/servicesNS/test/search/saved/searches/example",
                earliest="100",
                latest="200",
                timeout_seconds=0.05,
            )
        finally:
            release.set()

        self.assertEqual(state, "TIMEOUT_NO_SID")
        self.assertFalse(ok)
        self.assertEqual(sid, "")
        self.assertEqual(err, "")
        self.assertGreaterEqual(elapsed_ms, 40)

    def test_dispatch_saved_search_with_budget_captures_exception(self) -> None:
        class Client:
            def dispatch_saved_search(self, report_id_url, *, earliest=None, latest=None):
                del report_id_url, earliest, latest
                raise RuntimeError("dispatch exploded")

        state, ok, sid, err, elapsed_ms = splunk_engine._dispatch_saved_search_with_budget(
            Client(),
            report_id_url="/servicesNS/test/search/saved/searches/example",
            earliest="100",
            latest="200",
            timeout_seconds=1,
        )

        self.assertEqual(state, "EXCEPTION")
        self.assertFalse(ok)
        self.assertEqual(sid, "")
        self.assertIn("dispatch exploded", err)
        self.assertGreaterEqual(elapsed_ms, 0)

    def test_dispatch_saved_search_with_budget_allows_no_sid_return(self) -> None:
        class Client:
            def dispatch_saved_search(self, report_id_url, *, earliest=None, latest=None):
                del report_id_url, earliest, latest
                return True, "", ""

        state, ok, sid, err, elapsed_ms = splunk_engine._dispatch_saved_search_with_budget(
            Client(),
            report_id_url="/servicesNS/test/search/saved/searches/example",
            earliest="100",
            latest="200",
            timeout_seconds=1,
        )

        self.assertEqual(state, "RETURNED")
        self.assertTrue(ok)
        self.assertEqual(sid, "")
        self.assertEqual(err, "")
        self.assertGreaterEqual(elapsed_ms, 0)


if __name__ == "__main__":
    unittest.main()
