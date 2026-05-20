from __future__ import annotations

import unittest

import splunk_engine
import splunk_report_tk


class OperatorStatusFlowTests(unittest.TestCase):
    def test_operator_display_line_filters_technical_runtime_lines(self) -> None:
        self.assertEqual(splunk_report_tk._operator_display_line("[Debug] broker details"), "")
        self.assertEqual(
            splunk_report_tk._operator_display_line("Running slice 2 of 4..."),
            "Running slice 2 of 4...",
        )
        self.assertEqual(
            splunk_report_tk._operator_display_line("Reference ID: batch-123"),
            "Reference ID: batch-123",
        )

    def test_operator_display_line_maps_recovery_notice_to_reference_id(self) -> None:
        rendered = splunk_report_tk._operator_display_line(
            "Recovery journal detected for batch_id=batch-20260325-abc123"
        )
        self.assertIn("Recovery journal detected.", rendered)
        self.assertIn("Reference ID: batch-20260325-abc123", rendered)

    def test_operator_final_message_templates_match_expected_outcomes(self) -> None:
        success = splunk_engine._operator_final_message_lines(batch_id="batch-1", outcome="success")
        partial = splunk_engine._operator_final_message_lines(batch_id="batch-2", outcome="partial_success")
        pending = splunk_engine._operator_final_message_lines(batch_id="batch-3", outcome="pending_verification")
        connectivity = splunk_engine._operator_final_message_lines(batch_id="batch-4", outcome="connectivity_prestart")
        evidence = splunk_engine._operator_final_message_lines(batch_id="batch-5", outcome="evidence_warning")

        self.assertEqual(success[0], "Report generation completed successfully.")
        self.assertEqual(success[-1], "Reference ID: batch-1")
        self.assertEqual(partial[0], "Report completed with issues.")
        self.assertEqual(partial[-1], "Reference ID: batch-2")
        self.assertEqual(pending[0], "Report processing completed, but final verification is still pending.")
        self.assertEqual(pending[-1], "Reference ID: batch-3")
        self.assertEqual(connectivity[0], "Unable to connect to Splunk services.")
        self.assertEqual(connectivity[-1], "Reference ID: batch-4")
        self.assertEqual(
            evidence[0],
            "Reports were generated, but evidence confirmation could not be fully completed.",
        )
        self.assertEqual(evidence[-1], "Reference ID: batch-5")

    def test_dispatch_transient_warning_lines_are_operator_visible(self) -> None:
        self.assertEqual(
            splunk_report_tk._operator_display_line(
                "Temporary dispatch uncertainty detected. Verifying status..."
            ),
            "Temporary dispatch uncertainty detected. Verifying status...",
        )
        self.assertEqual(
            splunk_report_tk._operator_display_line(
                "Retrying slice in a fresh execution context..."
            ),
            "Retrying slice in a fresh execution context...",
        )

    def test_successful_final_outcome_suppresses_terminal_dispatch_error(self) -> None:
        outcome = splunk_report_tk._dispatch_final_outcome_from_log_lines(
            [
                "Temporary dispatch uncertainty detected. Verifying status...",
                "Retrying slice in a fresh execution context...",
                "Report generation completed successfully.",
                "All reports have been sent.",
                "Reference ID: batch-1",
            ]
        )
        self.assertEqual(outcome, "success")
        self.assertFalse(
            splunk_report_tk._should_show_dispatch_terminal_error(
                outcome,
                RuntimeError("dispatch_timeout_no_sid_unknown"),
            )
        )

    def test_reconciliation_success_without_retry_suppresses_terminal_dispatch_error(self) -> None:
        outcome = splunk_report_tk._dispatch_final_outcome_from_log_lines(
            [
                "Temporary dispatch uncertainty detected. Verifying status...",
                "Report generation completed successfully.",
                "All reports have been sent.",
                "Reference ID: batch-2",
            ]
        )
        self.assertEqual(outcome, "success")
        self.assertFalse(
            splunk_report_tk._should_show_dispatch_terminal_error(
                outcome,
                RuntimeError("TIMEOUT_UNCERTAIN"),
            )
        )

    def test_true_terminal_failure_still_allows_dispatch_error_dialog(self) -> None:
        outcome = splunk_report_tk._dispatch_final_outcome_from_log_lines(
            [
                "The report could not be started.",
                "Reference ID: batch-3",
            ]
        )
        self.assertEqual(outcome, "could_not_start")
        self.assertTrue(
            splunk_report_tk._should_show_dispatch_terminal_error(
                outcome,
                RuntimeError("metadata load failed"),
            )
        )

    def test_multi_slice_success_with_transient_timeout_keeps_success_outcome(self) -> None:
        outcome = splunk_report_tk._dispatch_final_outcome_from_log_lines(
            [
                "Running slice 1 of 2...",
                "Temporary dispatch uncertainty detected. Verifying status...",
                "Retrying slice in a fresh execution context...",
                "Running slice 2 of 2...",
                "Report generation completed successfully.",
                "All reports have been sent.",
                "Reference ID: batch-4",
            ]
        )
        self.assertEqual(outcome, "success")
        self.assertFalse(
            splunk_report_tk._should_show_dispatch_terminal_error(
                outcome,
                RuntimeError("Unknown background error"),
            )
        )


if __name__ == "__main__":
    unittest.main()
