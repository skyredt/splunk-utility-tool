from __future__ import annotations

import json
import os
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
from unittest.mock import patch

from Internal import batch_state


class BatchStateHardeningTests(unittest.TestCase):
    def test_write_batch_journal_is_atomic_and_fsyncs(self) -> None:
        with TemporaryDirectory() as temp_root:
            with patch("Internal.batch_state.tempfile.gettempdir", return_value=temp_root):
                journal_path = batch_state.batch_journal_path("batch-atomic")
                payload = {
                    "schema_version": batch_state.STATE_SCHEMA_VERSION,
                    "batch_id": "batch-atomic",
                    "batch_state": "PENDING_RECONCILE",
                    "slices": [],
                }
                with patch("Internal.batch_state.os.fsync", wraps=os.fsync) as fsync_mock:
                    batch_state.write_batch_journal(journal_path, payload)
                self.assertTrue(os.path.exists(journal_path))
                with open(journal_path, "r", encoding="utf-8") as handle:
                    self.assertEqual(json.load(handle)["batch_id"], "batch-atomic")
                self.assertGreaterEqual(fsync_mock.call_count, 1)
                leftovers = [name for name in os.listdir(os.path.dirname(journal_path)) if name.endswith(".tmp")]
                self.assertEqual(leftovers, [])

    def test_invalid_journal_schema_is_detected_cleanly(self) -> None:
        with TemporaryDirectory() as temp_root:
            with patch("Internal.batch_state.tempfile.gettempdir", return_value=temp_root):
                journal_path = batch_state.batch_journal_path("batch-invalid")
                with open(journal_path, "w", encoding="utf-8") as handle:
                    json.dump(
                        {
                            "schema_version": 999,
                            "batch_id": "batch-invalid",
                            "batch_state": "PENDING_RECONCILE",
                            "slices": [],
                        },
                        handle,
                    )
                payloads = batch_state.list_unfinished_journals()
                self.assertEqual(len(payloads), 1)
                self.assertTrue(payloads[0]["invalid_journal"])
                self.assertIn("unsupported_schema_version", payloads[0]["invalid_reason"])

    def test_overlap_lock_acquisition_is_race_safe(self) -> None:
        with TemporaryDirectory() as temp_root:
            with patch("Internal.batch_state.tempfile.gettempdir", return_value=temp_root):
                results: list[tuple[bool, str]] = []
                barrier = threading.Barrier(2)

                def _attempt(batch_id: str) -> None:
                    barrier.wait(timeout=2.0)
                    ok, payload, _ = batch_state.acquire_overlap_lock(
                        "overlap-race",
                        batch_id,
                        {"report_names": ["TestReport"]},
                    )
                    results.append((ok, str(payload.get("batch_id", "") or "")))

                threads = [
                    threading.Thread(target=_attempt, args=("batch-a",), daemon=True),
                    threading.Thread(target=_attempt, args=("batch-b",), daemon=True),
                ]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=3.0)

                self.assertEqual(sum(1 for ok, _ in results if ok), 1)
                self.assertEqual(sum(1 for ok, _ in results if not ok), 1)

    def test_stale_lock_is_recovered_explicitly(self) -> None:
        with TemporaryDirectory() as temp_root:
            with patch("Internal.batch_state.tempfile.gettempdir", return_value=temp_root):
                lock_path = batch_state.overlap_lock_path("overlap-stale")
                stale_payload = {
                    "schema_version": batch_state.STATE_SCHEMA_VERSION,
                    "lock_key": "overlap-stale",
                    "batch_id": "old-batch",
                    "active": True,
                    "started_utc": (
                        datetime.now(timezone.utc) - timedelta(seconds=batch_state.LOCK_STALE_SECONDS + 60)
                    ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                }
                with open(lock_path, "w", encoding="utf-8") as handle:
                    json.dump(stale_payload, handle)
                ok, payload, _ = batch_state.acquire_overlap_lock(
                    "overlap-stale",
                    "new-batch",
                    {"report_names": ["TestReport"]},
                )
                self.assertTrue(ok)
                self.assertTrue(payload.get("_stale_lock_recovered"))
                self.assertTrue(str(payload.get("_stale_lock_reason", "")).strip())


if __name__ == "__main__":
    unittest.main()
