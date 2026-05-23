from __future__ import annotations

import unittest

import splunk_engine


class RegenContextUnitTests(unittest.TestCase):
    def test_regen_context_tracks_fake_saved_search_recipients_and_summary(self) -> None:
        context = splunk_engine.RegenContext(
            run_id="run-unit",
            batch_id="batch-unit",
            report_names=["saved_search_example"],
            app="app_example",
            operator="operator_example",
            hostname="host_example",
            savedsearch_recipients=["ops@example.com"],
        )
        context.add_slice(
            batch_id=context.batch_id,
            slice_id="slice-unit",
            attempt_id=1,
            report_name="saved_search_example",
            slice_label="[1/1]",
            slice_index=1,
            slice_total=1,
            status="OK",
            sid="sid_example",
        )

        ok_count, fail_count, pending_count = context.summary_counts()

        self.assertEqual(context.savedsearch_recipients, ["ops@example.com"])
        self.assertEqual((ok_count, fail_count, pending_count), (1, 0, 0))
        self.assertEqual(context.overall_status(), "OK")


if __name__ == "__main__":
    unittest.main()
