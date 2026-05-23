from __future__ import annotations

import json
import os
import time
import unittest
from datetime import datetime, timedelta, timezone
from tempfile import TemporaryDirectory
from unittest.mock import patch

import splunk_engine
from Internal import batch_state


class _NullSignal:
    def emit(self, *args, **kwargs) -> None:
        del args, kwargs


class TransactionFlowClient:
    def __init__(self) -> None:
        self.username = "splunk_service"
        self.finished = _NullSignal()
        self.error = _NullSignal()
        self.dispatch_log = _NullSignal()
        self.dispatch_calls = 0
        self.dispatch_trace_ids: list[str] = []
        self.dispatch_windows: list[tuple[str, str]] = []
        self.reset_calls = 0
        self.find_calls = 0
        self.snapshot_calls = 0
        self._dispatch_plan: list[dict] = []
        self._last_dispatch_meta: dict[str, object] = {}
        self._job_candidates: list[list[dict]] = []
        self._snapshot_plan: dict[str, object] = {}
        self._snapshot_sequences: dict[str, list[object]] = {}
        self.last_find_kwargs: dict[str, object] = {}

    def queue_dispatch_timeout(self, *, meta: dict | None = None) -> None:
        self._dispatch_plan.append({"kind": "timeout", "meta": dict(meta or {})})

    def queue_dispatch_success(self, sid: str, *, meta: dict | None = None) -> None:
        self._dispatch_plan.append({"kind": "success", "sid": sid, "meta": dict(meta or {})})

    def queue_job_candidates(self, candidates: list[dict]) -> None:
        self._job_candidates.append(candidates)

    def set_snapshot_success(self, sid: str) -> None:
        self._snapshot_plan[sid] = ("SUCCESS", {"dispatchState": "DONE", "isDone": True})

    def set_snapshot_timeout(self, sid: str) -> None:
        self._snapshot_plan[sid] = RuntimeError(
            "Local Splunk broker timed out while processing the request (op=get_job_status_snapshot, timeout=7s)"
        )

    def set_snapshot_sequence(self, sid: str, sequence: list[object]) -> None:
        self._snapshot_sequences[sid] = list(sequence)

    def dispatch_saved_search(
        self,
        report_id_url: str,
        earliest: str | None = None,
        latest: str | None = None,
        trigger_actions: bool = True,
        request_timeout_seconds: float | None = None,
    ):
        del report_id_url, trigger_actions
        self.dispatch_calls += 1
        trace_context = getattr(self, "_dispatch_trace_context", {})
        self.dispatch_trace_ids.append(str(trace_context.get("correlation_id", "")))
        self.dispatch_windows.append((str(earliest or ""), str(latest or "")))
        plan = self._dispatch_plan.pop(0)
        self._last_dispatch_meta = dict(plan.get("meta", {}) or {})
        if plan["kind"] == "timeout":
            time.sleep(max(1.2, float(request_timeout_seconds or 1.0) + 0.2))
            return True, "late_sid_after_timeout", ""
        return True, str(plan["sid"]), ""

    def get_job_status_snapshot(
        self,
        sid: str,
        request_timeout_seconds: float = 7.0,
        max_total_timeout_seconds: float | None = None,
    ):
        del request_timeout_seconds, max_total_timeout_seconds
        self.snapshot_calls += 1
        if sid in self._snapshot_sequences and self._snapshot_sequences[sid]:
            outcome = self._snapshot_sequences[sid].pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        outcome = self._snapshot_plan.get(sid, ("SUCCESS", {"dispatchState": "DONE", "isDone": True}))
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def find_job_candidates(
        self,
        *,
        label: str = "",
        owner: str = "",
        app: str = "",
        dispatch_earliest: str = "",
        dispatch_latest: str = "",
        correlation_tag: str = "",
        limit: int = 50,
        page_size: int = 25,
    ):
        self.last_find_kwargs = {
            "label": label,
            "owner": owner,
            "app": app,
            "dispatch_earliest": dispatch_earliest,
            "dispatch_latest": dispatch_latest,
            "correlation_tag": correlation_tag,
            "limit": limit,
            "page_size": page_size,
        }
        self.find_calls += 1
        if self._job_candidates:
            return self._job_candidates.pop(0)
        return []

    def reset_transport(self) -> None:
        self.reset_calls += 1

    def close_transport(self) -> None:
        self.reset_calls += 1

    def _get(self, path: str, **kwargs):
        del kwargs
        parsed_name = str(path).rstrip("/").rsplit("/", 1)[-1] if path else "TestReport"
        del path
        return {
            "entry": [
                {
                    "name": parsed_name,
                    "acl": {
                        "owner": self.username,
                        "app": "search",
                        "sharing": "user",
                    },
                    "content": {
                        "dispatch.earliest_time": "-1d@d",
                        "dispatch.latest_time": "@d",
                        "action.email": "1",
                        "action.email.to": "ops@example.com",
                    },
                }
            ]
        }


def _make_context(run_id: str) -> splunk_engine.RegenContext:
    return splunk_engine.RegenContext(
        run_id=run_id,
        batch_id=f"batch-{run_id}",
        report_names=["TestReport"],
        app="search",
        operator="tester",
        hostname="host1",
    )


def _single_slice_range() -> tuple[datetime, datetime]:
    return datetime(2026, 3, 1, 0, 0, 0), datetime(2026, 3, 2, 0, 0, 0)


class SliceTransactionFlowTests(unittest.TestCase):
    def test_dispatch_timeout_reconcile_passes_then_retries_once_in_fresh_context(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_timeout()
        client.queue_dispatch_success("retry_success_sid")
        client.queue_job_candidates([])
        client.queue_job_candidates([])
        client.set_snapshot_success("retry_success_sid")
        context = _make_context("run-retry-once")
        start, end = _single_slice_range()
        with patch.multiple(
            splunk_engine,
            RECONCILE_PASS2_WAIT_SECONDS=0,
            RETRY_BACKOFF_SECONDS=0,
            MAX_RETRY_ATTEMPTS_PER_SLICE=1,
        ):
            logs = splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
                report_name="TestReport",
                frequency="Daily",
                start=start,
                end=end,
                no_change=False,
                wait_seconds=2,
                poll_interval=1,
                log_callback=None,
                sid_callback=None,
                regen_context=context,
                continue_on_timeout=True,
                timeout_status="PENDING",
                dispatch_call_timeout_seconds=1,
            )
        self.assertEqual(client.dispatch_calls, 2)
        self.assertGreaterEqual(client.reset_calls, 1)
        self.assertEqual(len(set(client.dispatch_trace_ids)), 2)
        self.assertEqual(len(context.slices), 1)
        slice_record = context.slices[0]
        self.assertEqual(slice_record.status, "OK")
        self.assertEqual(slice_record.lifecycle_state, splunk_engine.SLICE_STATE_SUCCESS)
        self.assertEqual(slice_record.retry_count, 1)
        self.assertEqual(slice_record.attempt_id, 2)
        self.assertEqual(slice_record.sid, "retry_success_sid")
        self.assertEqual(slice_record.error, "")
        self.assertEqual(slice_record.state_reason, "")
        self.assertIn("retrying once in a fresh context", "\n".join(logs))
        self.assertIn("TRANSIENT_SLICE_ERROR_CLEARED", "\n".join(logs))

    def test_dispatch_attempt_diagnostics_compare_timeout_then_retry_success(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_timeout(
            meta={
                "request_class": "dispatch_critical",
                "broker_lane_name": "dispatch",
                "transport_freshness": "fresh_proxy_request",
                "preflight_dispatch_lane_active": 1,
                "recent_metadata_outcome": "timeout_metadata_fetch",
                "recent_metadata_age_ms": 1500,
            }
        )
        client.queue_dispatch_success(
            "retry_success_sid",
            meta={
                "request_class": "dispatch_critical",
                "broker_lane_name": "dispatch",
                "transport_freshness": "fresh_proxy_request",
                "preflight_dispatch_lane_active": 0,
                "recent_transport_cleanup_reason": "dispatch_timeout_no_sid_metadata_contamination_suspected",
                "recent_transport_cleanup_age_ms": 10,
                "broker_queue_wait_ms": 0,
            },
        )
        client.queue_job_candidates([])
        client.queue_job_candidates([])
        client.set_snapshot_success("retry_success_sid")
        context = _make_context("run-dispatch-diagnostics")
        start, end = _single_slice_range()
        with patch.multiple(
            splunk_engine,
            RECONCILE_PASS2_WAIT_SECONDS=0,
            RETRY_BACKOFF_SECONDS=0,
            MAX_RETRY_ATTEMPTS_PER_SLICE=1,
        ):
            logs = splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
                report_name="TestReport",
                frequency="Daily",
                start=start,
                end=end,
                no_change=False,
                wait_seconds=2,
                poll_interval=1,
                log_callback=None,
                sid_callback=None,
                regen_context=context,
                continue_on_timeout=True,
                timeout_status="PENDING",
                dispatch_call_timeout_seconds=1,
            )
        joined = "\n".join(logs)
        self.assertIn("DISPATCH_ATTEMPT_DIAGNOSTICS", joined)
        self.assertIn("classification=dispatch_timeout_no_sid_metadata_contamination_suspected", joined)
        self.assertIn("DISPATCH_ATTEMPT_COMPARISON", joined)
        self.assertIn(
            "current_cleanup_reason=dispatch_timeout_no_sid_metadata_contamination_suspected",
            joined,
        )

    def test_dispatch_timeout_with_strong_job_evidence_finalizes_without_redispatch(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_timeout()
        context = _make_context("run-evidence-success")
        start, end = _single_slice_range()
        temp_root = TemporaryDirectory()
        self.addCleanup(temp_root.cleanup)
        context.journal_path = os.path.join(temp_root.name, "batch-journal.json")

        def _job_candidates(**kwargs):
            client.last_find_kwargs = dict(kwargs)
            earliest, latest = client.dispatch_windows[-1]
            client.find_calls += 1
            return [
                {
                    "sid": "evidence_sid",
                    "label": "TestReport",
                    "acl": {"owner": "splunk_service", "app": "search"},
                    "content": {
                        "dispatchState": "DONE",
                        "request": {
                            "earliest_time": earliest,
                            "latest_time": latest,
                            "ui_dispatch_app": "search",
                            "ui_dispatch_view": splunk_engine._build_correlation_dispatch_value(kwargs.get("correlation_tag", "")),
                        },
                    },
                }
            ]

        client.find_job_candidates = _job_candidates  # type: ignore[method-assign]
        client.set_snapshot_success("evidence_sid")
        with patch.multiple(
            splunk_engine,
            RECONCILE_PASS2_WAIT_SECONDS=0,
            RETRY_BACKOFF_SECONDS=0,
            MAX_RETRY_ATTEMPTS_PER_SLICE=1,
        ):
            splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
                report_name="TestReport",
                frequency="Daily",
                start=start,
                end=end,
                no_change=False,
                regen_context=context,
                continue_on_timeout=True,
                timeout_status="PENDING",
                dispatch_call_timeout_seconds=1,
                wait_seconds=2,
                poll_interval=1,
            )
        self.assertEqual(client.dispatch_calls, 1)
        self.assertEqual(len(context.slices), 1)
        slice_record = context.slices[0]
        self.assertEqual(slice_record.status, "OK")
        self.assertTrue(slice_record.finalized_from_reconciliation)
        self.assertEqual(slice_record.reconciliation_source, "search_jobs")
        self.assertEqual(slice_record.sid, "evidence_sid")
        self.assertEqual(slice_record.error, "")
        self.assertEqual(slice_record.reconciliation_confidence, "strong")
        self.assertIn("dispatch_view", slice_record.reconciliation_matched_fields)
        self.assertIn("exact slice window", slice_record.reconciliation_decision_reason.lower())
        self.assertEqual(client.last_find_kwargs.get("owner"), "splunk_service")
        self.assertEqual(client.last_find_kwargs.get("app"), "search")
        with open(context.journal_path, "r", encoding="utf-8") as handle:
            journal_payload = json.load(handle)
        persisted_slice = journal_payload["slices"][0]
        self.assertEqual(persisted_slice["reconciliation_confidence"], "strong")
        self.assertIn("dispatch_view", persisted_slice["reconciliation_matched_fields"])
        self.assertTrue(persisted_slice["reconciliation_decision_reason"])

    def test_dispatch_timeout_with_ambiguous_job_evidence_stays_pending_and_records_reason(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_timeout()
        context = _make_context("run-evidence-ambiguous")
        start, end = _single_slice_range()

        def _job_candidates(**kwargs):
            client.last_find_kwargs = dict(kwargs)
            earliest, latest = client.dispatch_windows[-1]
            client.find_calls += 1
            return [
                {
                    "sid": "ambiguous_sid",
                    "label": "TestReport",
                    "acl": {"owner": "splunk_service", "app": "search"},
                    "content": {
                        "dispatchState": "RUNNING",
                        "request": {
                            "earliest_time": earliest,
                            "latest_time": str(int(latest) + 3600),
                            "ui_dispatch_app": "search",
                        },
                    },
                }
            ]

        client.find_job_candidates = _job_candidates  # type: ignore[method-assign]
        with patch.multiple(
            splunk_engine,
            RECONCILE_PASS2_WAIT_SECONDS=0,
            RETRY_BACKOFF_SECONDS=0,
            MAX_RETRY_ATTEMPTS_PER_SLICE=1,
        ):
            splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
                report_name="TestReport",
                frequency="Daily",
                start=start,
                end=end,
                no_change=False,
                regen_context=context,
                continue_on_timeout=True,
                timeout_status="PENDING",
                dispatch_call_timeout_seconds=1,
                wait_seconds=2,
                poll_interval=1,
            )
        self.assertEqual(client.dispatch_calls, 1)
        slice_record = context.slices[0]
        self.assertEqual(slice_record.status, "PENDING")
        self.assertEqual(slice_record.lifecycle_state, splunk_engine.SLICE_STATE_PENDING_RECONCILE)
        self.assertEqual(slice_record.reconciliation_confidence, "weak")
        self.assertIn("name", slice_record.reconciliation_matched_fields)
        self.assertIn("exact slice window was not confirmed", slice_record.reconciliation_decision_reason)

    def test_final_end_of_batch_reconciliation_runs_for_unresolved_slices_even_when_background_reconcile_disabled(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_success("final_sweep_sid")
        client.set_snapshot_sequence(
            "final_sweep_sid",
            [
                RuntimeError(
                    "Local Splunk broker timed out while processing the request (op=get_job_status_snapshot, timeout=7s)"
                ),
                ("SUCCESS", {"dispatchState": "DONE", "isDone": True}),
            ],
        )
        cfg = splunk_engine.SplunkConfig(
            servers=["https://example.invalid:8089"],
            username="splunk_service",
            password="pw",
            postdispatch_config={"enabled": False, "reconcile_pending": False, "reconcile_wait_seconds": 1, "poll_seconds": 1},
        )
        with patch.object(splunk_engine, "DEFAULT_STATUS_SNAPSHOT_TIMEOUT_RETRIES", 0):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/splunk_service/search/saved/searches/TestReport"],
                report_names=["TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 2, 0, 0, 0),
                no_change=False,
                wait_seconds=2,
                poll_interval=1,
                config=cfg,
                app="search",
            )
        joined = "\n".join(logs)
        self.assertIn("Final end-of-batch reconciliation sweep triggered", joined)
        self.assertIn("Email report sent successfully", joined)

    def test_recovery_journal_dismiss_releases_overlap_lock(self) -> None:
        with TemporaryDirectory() as temp_root:
            with patch("Internal.batch_state.tempfile.gettempdir", return_value=temp_root):
                journal_path = batch_state.batch_journal_path("batch-recovery")
                lock_ok, lock_payload, _ = batch_state.acquire_overlap_lock(
                    "overlap-recovery",
                    "batch-recovery",
                    {"report_names": ["TestReport"]},
                )
                self.assertTrue(lock_ok)
                payload = {
                    "schema_version": batch_state.STATE_SCHEMA_VERSION,
                    "tool_version": splunk_engine.TOOL_DISPLAY_NAME,
                    "batch_id": "batch-recovery",
                    "batch_state": "PENDING_RECONCILE",
                    "report_names": ["TestReport"],
                    "journal_path": journal_path,
                    "_journal_path": journal_path,
                    "lock_key": "overlap-recovery",
                    "lock_path": lock_payload.get("lock_path", batch_state.overlap_lock_path("overlap-recovery")),
                    "slices": [],
                }
                batch_state.write_batch_journal(journal_path, payload)
                logs = splunk_engine.recover_unfinished_batch_journal(
                    client=None,
                    journal_payload=payload,
                    action="dismiss",
                )
                self.assertTrue(any("dismiss/archive" in line for line in logs))
                self.assertEqual(batch_state.list_unfinished_journals(), [])
                reacquire_ok, _, _ = batch_state.acquire_overlap_lock(
                    "overlap-recovery",
                    "batch-new",
                    {"report_names": ["TestReport"]},
                )
                self.assertTrue(reacquire_ok)

    def test_recovery_journal_reconcile_finalizes_pending_slice(self) -> None:
        with TemporaryDirectory() as temp_root:
            with patch("Internal.batch_state.tempfile.gettempdir", return_value=temp_root):
                client = TransactionFlowClient()
                client.set_snapshot_success("recover_sid")
                journal_path = batch_state.batch_journal_path("batch-reconcile")
                lock_ok, _, lock_path = batch_state.acquire_overlap_lock(
                    "overlap-reconcile",
                    "batch-reconcile",
                    {"report_names": ["TestReport"]},
                )
                self.assertTrue(lock_ok)
                payload = {
                    "schema_version": batch_state.STATE_SCHEMA_VERSION,
                    "tool_version": splunk_engine.TOOL_DISPLAY_NAME,
                    "batch_id": "batch-reconcile",
                    "run_id": "run-reconcile",
                    "batch_state": "PENDING_RECONCILE",
                    "report_names": ["TestReport"],
                    "app": "search",
                    "journal_path": journal_path,
                    "_journal_path": journal_path,
                    "lock_key": "overlap-reconcile",
                    "lock_path": lock_path,
                    "slices": [
                        {
                            "batch_id": "batch-reconcile",
                            "slice_id": "slice-1",
                            "attempt_id": 1,
                            "report_name": "TestReport",
                            "slice_label": "[1/1]",
                            "slice_index": 1,
                            "slice_total": 1,
                            "earliest": "2026-03-01 00:00:00",
                            "latest": "2026-03-02 00:00:00",
                            "dispatch_earliest": "100",
                            "dispatch_latest": "200",
                            "dispatch_report_id_url": "/servicesNS/splunk_service/search/saved/searches/TestReport",
                            "sid": "recover_sid",
                            "status": "PENDING",
                            "outcome_code": "PENDING_RECONCILE",
                            "lifecycle_state": splunk_engine.SLICE_STATE_PENDING_RECONCILE,
                            "pending_since_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            "correlation_tag": "batch-reconcile:slice-1:a1",
                            "correlation_mode": splunk_engine.CORRELATION_MODE_SPLUNK_UI_CONTEXT_BEST_EFFORT,
                            "report_owner": "splunk_service",
                            "report_app": "search",
                            "verification_mode": "native",
                        }
                    ],
                }
                batch_state.write_batch_journal(journal_path, payload)
                logs = splunk_engine.recover_unfinished_batch_journal(
                    client=client,
                    journal_payload=payload,
                    action="reconcile",
                    wait_seconds=1,
                    poll_interval=1,
                )
                self.assertTrue(any("reconcile/finalize" in line for line in logs))
                journal = batch_state.load_json_file(journal_path)
                self.assertEqual(journal.get("batch_state"), "COMPLETED")
                self.assertEqual(journal["slices"][0]["status"], "OK")

    def test_snapshot_timeout_marks_pending_reconcile_without_redispatch(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_success("snapshot_timeout_sid")
        client.set_snapshot_timeout("snapshot_timeout_sid")
        context = _make_context("run-snapshot-pending")
        start, end = _single_slice_range()
        with patch.object(splunk_engine, "DEFAULT_STATUS_SNAPSHOT_TIMEOUT_RETRIES", 0):
            splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
                report_name="TestReport",
                frequency="Daily",
                start=start,
                end=end,
                no_change=False,
                regen_context=context,
                continue_on_timeout=True,
                timeout_status="PENDING",
                dispatch_call_timeout_seconds=1,
                wait_seconds=2,
                poll_interval=1,
            )
        self.assertEqual(client.dispatch_calls, 1)
        self.assertGreaterEqual(client.reset_calls, 1)
        self.assertEqual(len(context.slices), 1)
        slice_record = context.slices[0]
        self.assertEqual(slice_record.status, "PENDING")
        self.assertEqual(slice_record.lifecycle_state, splunk_engine.SLICE_STATE_PENDING_RECONCILE)
        self.assertEqual(slice_record.outcome_code, "DISPATCHED_PENDING")
        self.assertEqual(slice_record.dispatch_outcome, "SID_CONFIRMED")
        self.assertEqual(slice_record.execution_outcome, "LIKELY_EXECUTED")

    def test_pending_reconcile_eventually_expires(self) -> None:
        client = TransactionFlowClient()
        context = _make_context("run-expire-pending")
        stale_pending = (
            datetime.now(timezone.utc) - timedelta(minutes=splunk_engine.PENDING_RECONCILE_MAX_MINUTES + 1)
        ).isoformat().replace("+00:00", "Z")
        context.add_slice(
            batch_id=context.batch_id,
            slice_id="slice-expired",
            attempt_id=1,
            report_name="TestReport",
            slice_label="[1/1]",
            slice_index=1,
            slice_total=1,
            earliest="2026-03-01",
            latest="2026-03-02",
            sid="stale_sid",
            status="PENDING",
            outcome_code="PENDING_RECONCILE",
            error="Awaiting reconciliation.",
            lifecycle_state=splunk_engine.SLICE_STATE_PENDING_RECONCILE,
            pending_since_utc=stale_pending,
            dispatch_report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
        )
        logs = splunk_engine._reconcile_pending_slices(
            client,
            context,
            wait_seconds=1,
            poll_interval=1,
        )
        self.assertTrue(any("Pending reconciliation window expired" in line for line in logs))
        self.assertEqual(context.slices[0].status, "EXPIRED")
        self.assertEqual(context.slices[0].lifecycle_state, splunk_engine.SLICE_STATE_EXPIRED)

    def test_inspect_unfinished_batch_journals_expires_stale_pending(self) -> None:
        context = _make_context("run-inspect-expire")
        stale_pending = (
            datetime.now(timezone.utc) - timedelta(minutes=splunk_engine.PENDING_RECONCILE_MAX_MINUTES + 1)
        ).isoformat().replace("+00:00", "Z")
        context.batch_state = "PENDING_RECONCILE"
        context.add_slice(
            batch_id=context.batch_id,
            slice_id="slice-inspect-expired",
            attempt_id=1,
            report_name="TestReport",
            slice_label="[1/1]",
            slice_index=1,
            slice_total=1,
            earliest="2026-03-01",
            latest="2026-03-02",
            sid="stale_sid",
            status="PENDING",
            outcome_code="PENDING_RECONCILE",
            error="Awaiting reconciliation.",
            lifecycle_state=splunk_engine.SLICE_STATE_PENDING_RECONCILE,
            pending_since_utc=stale_pending,
            dispatch_report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
        )
        with TemporaryDirectory() as temp_dir:
            journal_path = os.path.join(temp_dir, f"{context.batch_id}.json")
            context.journal_path = journal_path
            splunk_engine._persist_batch_journal(context, reason="test_setup")
            with patch.object(batch_state, "journals_dir", return_value=temp_dir):
                payloads, lines = splunk_engine.inspect_unfinished_batch_journals()
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["batch_state"], "EXPIRED")
        self.assertEqual(payloads[0]["slices"][0]["status"], "EXPIRED")
        self.assertTrue(any("Recovered stale pending slices to EXPIRED" in line for line in lines))

    def test_merge_report_timeout_falls_back_to_native_success(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_success("fallback_success_sid")
        client.set_snapshot_success("fallback_success_sid")
        context = _make_context("run-mergereport-fallback")
        start, end = _single_slice_range()
        with patch.object(
            splunk_engine,
            "_wait_for_merge_report_preferred_evidence",
            return_value=("TIMEOUT", "", "rest", 250),
        ):
            logs = splunk_engine.run_dispatch_single(
                client,
                report_id_url="/servicesNS/splunk_service/search/saved/searches/TestReport",
                report_name="TestReport",
                frequency="Daily",
                start=start,
                end=end,
                no_change=False,
                regen_context=context,
                continue_on_timeout=True,
                timeout_status="PENDING",
                dispatch_call_timeout_seconds=1,
                wait_seconds=2,
                poll_interval=1,
                prefer_merge_report_verification=True,
                merge_report_log_path=r"C:\temp\mergeReport_alert.log",
                merge_report_timeout_seconds=1,
            )
        self.assertTrue(any("Falling back to native Splunk status verification" in line for line in logs))
        self.assertEqual(context.slices[0].status, "OK")
        self.assertEqual(context.slices[0].lifecycle_state, splunk_engine.SLICE_STATE_SUCCESS)

    def test_reconciliation_uses_frozen_owner_and_app_when_runtime_identity_drifts(self) -> None:
        client = TransactionFlowClient()
        context = _make_context("run-frozen-identity")
        start, end = _single_slice_range()
        splunk_engine._prepare_batch_execution_definition(
            context,
            report_ids=["/servicesNS/frozen_owner/frozen_app/saved/searches/TestReport"],
            report_names=["TestReport"],
            selected_indices=[0],
            frequency="Daily",
            start=start,
            end=end,
            no_change=False,
            app="frozen_app",
            owner="frozen_owner",
            prefer_merge_report_verification=False,
            merge_report_log_path="",
        )
        record = context.slices[0]
        client.username = "drifted_owner"
        temp_context = splunk_engine.SliceExecutionContext(
            client=client,
            run_id=context.run_id,
            batch_id=context.batch_id,
            slice_id=record.slice_id,
            attempt_id=1,
            report_id_url=record.dispatch_report_id_url,
            report_name=record.report_name,
            slice_label=record.slice_label,
            slice_index=record.slice_index,
            slice_total=record.slice_total,
            earliest_display=record.earliest,
            latest_display=record.latest,
            dispatch_earliest=record.dispatch_earliest,
            dispatch_latest=record.dispatch_latest,
            dispatch_timeout_seconds=30,
            snapshot_timeout_seconds=7,
            correlation_tag=record.correlation_tag,
            correlation_mode=record.correlation_mode,
            report_owner=record.report_owner,
            report_app=record.report_app,
            verification_mode=record.verification_mode,
        )
        client.queue_job_candidates([])
        splunk_engine._find_reconcile_evidence(
            client,
            context=temp_context,
            identity=splunk_engine.SavedSearchIdentity(
                owner=record.report_owner,
                app=record.report_app,
                name=record.report_name,
            ),
            pass_name="frozen_identity_check",
        )
        self.assertEqual(client.last_find_kwargs.get("owner"), "frozen_owner")
        self.assertEqual(client.last_find_kwargs.get("app"), "frozen_app")
        self.assertEqual(client.last_find_kwargs.get("dispatch_earliest"), record.dispatch_earliest)
        self.assertEqual(client.last_find_kwargs.get("dispatch_latest"), record.dispatch_latest)
        self.assertEqual(client.last_find_kwargs.get("correlation_tag"), record.correlation_tag)

    def test_batch_state_helpers_detect_unfinished_journal_and_overlap_lock(self) -> None:
        with TemporaryDirectory() as temp_root:
            with patch("Internal.batch_state.tempfile.gettempdir", return_value=temp_root):
                journal_path = batch_state.batch_journal_path("batch-open")
                batch_state.write_batch_journal(
                    journal_path,
                    {
                        "schema_version": batch_state.STATE_SCHEMA_VERSION,
                        "tool_version": "CIO Splunk Utility Tool 4.0",
                        "batch_id": "batch-open",
                        "batch_state": "PENDING_RECONCILE",
                        "report_names": ["TestReport"],
                        "slices": [],
                    },
                )
                unfinished = batch_state.list_unfinished_journals()
                self.assertEqual(len(unfinished), 1)
                self.assertEqual(unfinished[0]["batch_id"], "batch-open")

                ok, _, lock_path = batch_state.acquire_overlap_lock(
                    "overlap-1",
                    "batch-open",
                    {"report_names": ["TestReport"]},
                )
                self.assertTrue(ok)
                blocked, payload, _ = batch_state.acquire_overlap_lock(
                    "overlap-1",
                    "batch-other",
                    {"report_names": ["TestReport"]},
                )
                self.assertFalse(blocked)
                self.assertEqual(payload.get("batch_id"), "batch-open")
                self.assertTrue(lock_path.endswith(".lock.json"))
                batch_state.release_overlap_lock("overlap-1", "batch-open")

    def test_find_job_candidates_uses_server_side_filters_and_pagination(self) -> None:
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk token"
        captured_params: list[dict[str, object]] = []
        pages = [
            {
                "entry": [
                    {
                        "name": "sid-1",
                        "label": "TestReport",
                        "acl": {"owner": "splunk_service", "app": "search"},
                        "content": {
                            "qualifiedSearch": "search index=main",
                            "request": {
                                "earliest_time": "100",
                                "latest_time": "200",
                                "ui_dispatch_view": splunk_engine._build_correlation_dispatch_value("batch-1:slice-1:a1"),
                            },
                        },
                    },
                    {
                        "name": "sid-2",
                        "label": "TestReport",
                        "acl": {"owner": "splunk_service", "app": "search"},
                        "content": {
                            "qualifiedSearch": "search index=main",
                            "request": {
                                "earliest_time": "100",
                                "latest_time": "200",
                            },
                        },
                    },
                ]
            },
            {
                "entry": [
                    {
                        "name": "sid-3",
                        "label": "TestReport",
                        "acl": {"owner": "splunk_service", "app": "search"},
                        "content": {
                            "qualifiedSearch": "search index=main correlation_tag=batch-1:slice-1:a1",
                            "request": {
                                "earliest_time": "100",
                                "latest_time": "200",
                            },
                        },
                    }
                ]
            },
        ]

        def _fake_get(path: str, params: dict | None = None, **kwargs):
            del kwargs
            self.assertEqual(path, "/services/search/jobs")
            captured_params.append(dict(params or {}))
            return pages.pop(0)

        client._get = _fake_get  # type: ignore[method-assign]
        results = splunk_engine.SplunkClient.find_job_candidates(
            client,
            label="TestReport",
            owner="splunk_service",
            app="search",
            dispatch_earliest="100",
            dispatch_latest="200",
            correlation_tag="batch-1:slice-1:a1",
            limit=3,
            page_size=2,
        )
        self.assertEqual(len(results), 3)
        self.assertEqual(captured_params[0]["count"], 2)
        self.assertEqual(captured_params[0]["offset"], 0)
        self.assertIn('label="TestReport"', str(captured_params[0]["search"]))
        self.assertIn('acl.owner="splunk_service"', str(captured_params[0]["search"]))
        self.assertIn('request.ui_dispatch_view="sutv4-', str(captured_params[0]["search"]))
        self.assertEqual(captured_params[1]["offset"], 2)
        self.assertEqual(results[0]["content"]["request"]["ui_dispatch_view"], splunk_engine._build_correlation_dispatch_value("batch-1:slice-1:a1"))

    def test_find_job_candidates_accepts_buffered_window_matches(self) -> None:
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk token"

        def _fake_get(path: str, params: dict | None = None, **kwargs):
            del params, kwargs
            self.assertEqual(path, "/services/search/jobs")
            return {
                "entry": [
                    {
                        "name": "sid-buffered",
                        "label": "TestReport",
                        "acl": {"owner": "splunk_service", "app": "search"},
                        "content": {
                            "qualifiedSearch": "search index=main",
                            "request": {
                                "earliest_time": "420",
                                "latest_time": "780",
                            },
                        },
                    }
                ]
            }

        client._get = _fake_get  # type: ignore[method-assign]
        results = splunk_engine.SplunkClient.find_job_candidates(
            client,
            label="TestReport",
            owner="splunk_service",
            app="search",
            dispatch_earliest="300",
            dispatch_latest="900",
            window_buffer_seconds=180,
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["sid"], "sid-buffered")

    def test_run_dispatch_multi_internal_runtime_failure_uses_support_message(self) -> None:
        client = TransactionFlowClient()
        with patch.object(
            splunk_engine,
            "_collect_saved_search_recipients",
            side_effect=TypeError("local runtime defect"),
        ):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/splunk_service/search/saved/searches/TestReport"],
                report_names=["TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 2, 0, 0, 0),
                no_change=False,
                wait_seconds=2,
                poll_interval=1,
                app="search",
            )
        joined = "\n".join(logs)
        self.assertIn("Starting report generation...", joined)
        self.assertIn("Reference ID: batch-", joined)
        self.assertIn("The report could not be started.", joined)
        self.assertIn("classification=internal_runtime_error", joined)

    def test_run_dispatch_multi_connectivity_failure_uses_connectivity_message(self) -> None:
        client = TransactionFlowClient()
        with patch.object(
            splunk_engine,
            "_collect_saved_search_recipients",
            side_effect=RuntimeError("Unable to connect to Splunk services."),
        ):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/splunk_service/search/saved/searches/TestReport"],
                report_names=["TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 2, 0, 0, 0),
                no_change=False,
                wait_seconds=2,
                poll_interval=1,
                app="search",
            )
        joined = "\n".join(logs)
        self.assertIn("Unable to connect to Splunk services.", joined)
        self.assertIn("The report could not be started.", joined)
        self.assertIn("Reference ID: batch-", joined)

    def test_run_dispatch_multi_success_emits_operator_reference_and_final_message(self) -> None:
        client = TransactionFlowClient()
        client.queue_dispatch_success("success_sid")
        client.set_snapshot_success("success_sid")
        with patch.object(splunk_engine, "_collect_saved_search_recipients", return_value=[]):
            logs = splunk_engine.run_dispatch_multi(
                client=client,
                report_ids=["/servicesNS/splunk_service/search/saved/searches/TestReport"],
                report_names=["TestReport"],
                selected_indices=[0],
                frequency="Daily",
                start=datetime(2026, 3, 1, 0, 0, 0),
                end=datetime(2026, 3, 2, 0, 0, 0),
                no_change=False,
                wait_seconds=2,
                poll_interval=1,
                app="search",
            )
        joined = "\n".join(logs)
        self.assertIn("Starting report generation...", joined)
        self.assertIn("Reference ID: batch-", joined)
        self.assertIn("Preparing report...", joined)
        self.assertIn("Running slice 1 of 1...", joined)
        self.assertIn("Finalizing results...", joined)
        self.assertIn("Report generation completed successfully.", joined)
        self.assertIn("All reports have been sent.", joined)

    def test_request_reauth_retries_once_after_401(self) -> None:
        class FakeResponse:
            def __init__(self, status_code: int) -> None:
                self.status_code = status_code
                self.headers = {}
                self.text = ""
                self._closed = False

            def close(self) -> None:
                self._closed = True

        class FakeSession:
            def __init__(self, responses: list[FakeResponse]) -> None:
                self.responses = responses
                self.trust_env = False
                self.verify = True

            def request(self, **kwargs):
                del kwargs
                return self.responses.pop(0)

            def close(self) -> None:
                return

        first = FakeResponse(401)
        second = FakeResponse(200)
        sessions = [FakeSession([first]), FakeSession([second])]

        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk old-token"
        client.auth_mode = "password"

        def _refresh() -> bool:
            client._auth_header = "Splunk refreshed-token"
            return True

        client._refresh_auth_header = _refresh  # type: ignore[method-assign]

        with patch.object(splunk_engine.requests, "Session", side_effect=sessions):
            resp = splunk_engine.SplunkClient._request(
                client,
                "GET",
                "/services/server/info",
                timeout=5,
            )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(first._closed)
        client._close_response_transport(resp)

    def test_dispatch_saved_search_propagates_ui_correlation_fields_when_supported(self) -> None:
        class FakeResponse:
            def __init__(self) -> None:
                self.status_code = 201
                self.headers = {"Location": "https://example.invalid:8089/services/search/jobs/propagated_sid"}
                self.text = ""
                self.elapsed = type("Elapsed", (), {"total_seconds": lambda self: 0.01})()

            def close(self) -> None:
                return

        class FakeSession:
            def __init__(self) -> None:
                self.trust_env = False
                self.verify = True
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                return FakeResponse()

            def close(self) -> None:
                return

        session = FakeSession()
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk token"
        client.auth_mode = "password"
        client._dispatch_trace_context = {
            "correlation_tag": "batch-1:slice-1:a1",
            "report_app": "search",
            "correlation_id": "dispatch-1",
        }

        with patch.object(splunk_engine.requests, "Session", return_value=session):
            ok, sid, err = splunk_engine.SplunkClient.dispatch_saved_search(
                client,
                "/servicesNS/splunk_service/search/saved/searches/TestReport",
                earliest="100",
                latest="200",
                request_timeout_seconds=5,
            )
        self.assertTrue(ok)
        self.assertEqual(sid, "propagated_sid")
        self.assertEqual(err, "")
        request_payload = session.calls[0]["data"]
        self.assertEqual(request_payload["ui_dispatch_app"], "search")
        self.assertEqual(
            request_payload["ui_dispatch_view"],
            splunk_engine._build_correlation_dispatch_value("batch-1:slice-1:a1"),
        )
        self.assertEqual(
            client._last_dispatch_meta["correlation_mode"],
            splunk_engine.CORRELATION_MODE_SPLUNK_UI_CONTEXT_PROPAGATED,
        )
        self.assertEqual(
            client._last_dispatch_meta["request_payload_keys"],
            "dispatch.earliest_time,dispatch.latest_time,output_mode,trigger_actions,ui_dispatch_app,ui_dispatch_view",
        )

    def test_build_dispatch_payload_strips_empty_optional_fields(self) -> None:
        payload, optional_keys = splunk_engine._build_dispatch_payload(
            earliest="100",
            latest="200",
            trigger_actions=True,
            report_app="   ",
            correlation_dispatch_value="",
            include_optional_fields=True,
        )
        self.assertEqual(optional_keys, [])
        self.assertEqual(
            payload,
            {
                "output_mode": "json",
                "trigger_actions": 1,
                "dispatch.earliest_time": "100",
                "dispatch.latest_time": "200",
            },
        )

    def test_dispatch_saved_search_captures_http_400_response_body_snippet_for_minimal_payload(self) -> None:
        class FakeResponse:
            def __init__(self) -> None:
                self.status_code = 400
                self.headers = {}
                self.text = "Dispatch argument validation failed: invalid latest_time token."
                self.elapsed = type("Elapsed", (), {"total_seconds": lambda self: 0.01})()

            def close(self) -> None:
                return

        class FakeSession:
            def __init__(self) -> None:
                self.trust_env = False
                self.verify = True
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                return FakeResponse()

            def close(self) -> None:
                return

        session = FakeSession()
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk token"
        client.auth_mode = "password"
        client._dispatch_trace_context = {}

        with patch.object(splunk_engine.requests, "Session", return_value=session):
            ok, sid, err = splunk_engine.SplunkClient.dispatch_saved_search(
                client,
                "/servicesNS/splunk_service/search/saved/searches/TestReport",
                earliest="100",
                latest="bad-token",
                request_timeout_seconds=5,
            )
        self.assertFalse(ok)
        self.assertIsNone(sid)
        self.assertIn("Dispatch rejected by Splunk (HTTP 400)", err)
        self.assertIn("response=Dispatch argument validation failed", err)
        self.assertEqual(
            client._last_dispatch_meta["failure_classification"],
            "failed_dispatch_http_400_invalid_payload",
        )
        self.assertEqual(
            client._last_dispatch_meta["response_body_snippet"],
            "Dispatch argument validation failed: invalid latest_time token.",
        )
        self.assertEqual(len(session.calls), 1)

    def test_dispatch_saved_search_falls_back_when_optional_dispatch_fields_are_rejected(self) -> None:
        class FakeResponse:
            def __init__(self, status_code: int, *, text: str = "", location: str = "") -> None:
                self.status_code = status_code
                self.headers = {"Location": location} if location else {}
                self.text = text
                self.elapsed = type("Elapsed", (), {"total_seconds": lambda self: 0.01})()

            def close(self) -> None:
                return

        class FakeSession:
            def __init__(self, responses: list[FakeResponse]) -> None:
                self.responses = responses
                self.trust_env = False
                self.verify = True
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                return self.responses.pop(0)

            def close(self) -> None:
                return

        sessions = [
            FakeSession([FakeResponse(400, text="Bad request while dispatching saved search.")]),
            FakeSession([FakeResponse(201, location="https://example.invalid:8089/services/search/jobs/fallback_sid")]),
        ]

        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk token"
        client.auth_mode = "password"
        client._dispatch_trace_context = {
            "correlation_tag": "batch-2:slice-2:a1",
            "report_app": "search",
            "correlation_id": "dispatch-2",
        }

        with patch.object(splunk_engine.requests, "Session", side_effect=sessions):
            ok, sid, err = splunk_engine.SplunkClient.dispatch_saved_search(
                client,
                "/servicesNS/splunk_service/search/saved/searches/TestReport",
                earliest="100",
                latest="200",
                request_timeout_seconds=5,
            )
        self.assertTrue(ok)
        self.assertEqual(sid, "fallback_sid")
        self.assertEqual(err, "")
        self.assertIn("ui_dispatch_view", sessions[0].calls[0]["data"])
        self.assertNotIn("ui_dispatch_view", sessions[1].calls[0]["data"])
        self.assertNotIn("ui_dispatch_app", sessions[1].calls[0]["data"])
        self.assertEqual(
            client._last_dispatch_meta["correlation_mode"],
            splunk_engine.CORRELATION_MODE_TOOL_LOCAL_FALLBACK,
        )
        self.assertTrue(client._last_dispatch_meta["fallback_attempted"])
        self.assertEqual(
            client._last_dispatch_meta["failure_classification"],
            "failed_dispatch_fallback_succeeded",
        )
        self.assertEqual(
            client._last_dispatch_meta["initial_response_body_snippet"],
            "Bad request while dispatching saved search.",
        )

    def test_dispatch_saved_search_minimal_http_400_does_not_retry(self) -> None:
        class FakeResponse:
            def __init__(self) -> None:
                self.status_code = 400
                self.headers = {}
                self.text = "Invalid dispatch payload."
                self.elapsed = type("Elapsed", (), {"total_seconds": lambda self: 0.01})()

            def close(self) -> None:
                return

        class FakeSession:
            def __init__(self) -> None:
                self.trust_env = False
                self.verify = True
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                return FakeResponse()

            def close(self) -> None:
                return

        session = FakeSession()
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk token"
        client.auth_mode = "password"
        client._dispatch_trace_context = {}

        with patch.object(splunk_engine.requests, "Session", return_value=session):
            ok, sid, err = splunk_engine.SplunkClient.dispatch_saved_search(
                client,
                "/servicesNS/splunk_service/search/saved/searches/TestReport",
                earliest="100",
                latest="200",
                request_timeout_seconds=5,
            )
        self.assertFalse(ok)
        self.assertIsNone(sid)
        self.assertIn("classification=failed_dispatch_http_400_invalid_payload", err)
        self.assertEqual(len(session.calls), 1)
        self.assertFalse(bool(client._last_dispatch_meta.get("fallback_attempted")))

    def test_dispatch_saved_search_classifies_namespace_mismatch_clearly(self) -> None:
        class FakeResponse:
            def __init__(self) -> None:
                self.status_code = 400
                self.headers = {}
                self.text = "Could not find object id for saved search dispatch."
                self.elapsed = type("Elapsed", (), {"total_seconds": lambda self: 0.01})()

            def close(self) -> None:
                return

        class FakeSession:
            def __init__(self) -> None:
                self.trust_env = False
                self.verify = True
                self.calls: list[dict[str, object]] = []

            def request(self, **kwargs):
                self.calls.append(dict(kwargs))
                return FakeResponse()

            def close(self) -> None:
                return

        session = FakeSession()
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.base_url = "https://example.invalid:8089"
        client.username = "splunk_service"
        client._password = "pw"
        client.verify_ssl = True
        client._auth_header = "Splunk token"
        client.auth_mode = "password"
        client._dispatch_trace_context = {
            "report_owner": "frozen_owner",
        }

        with patch.object(splunk_engine.requests, "Session", return_value=session):
            ok, sid, err = splunk_engine.SplunkClient.dispatch_saved_search(
                client,
                "/servicesNS/live_owner/live_app/saved/searches/TestReport",
                earliest="100",
                latest="200",
                request_timeout_seconds=5,
            )
        self.assertFalse(ok)
        self.assertIsNone(sid)
        self.assertIn("classification=failed_dispatch_http_400_invalid_namespace", err)
        self.assertIn("path_validation=Frozen owner 'frozen_owner' does not match dispatch path owner 'live_owner'.", err)
        self.assertEqual(
            client._last_dispatch_meta["failure_classification"],
            "failed_dispatch_http_400_invalid_namespace",
        )
        self.assertEqual(client._last_dispatch_meta["namespace_consistency"], "owner_mismatch")

if __name__ == "__main__":
    unittest.main()
