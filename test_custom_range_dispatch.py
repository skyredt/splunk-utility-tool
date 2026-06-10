import unittest
from datetime import datetime

import splunk_engine
from splunk_report_tk import (
    ReportsApp,
    build_manual_regen_mode_text,
    build_saved_search_time_range_text,
)


class CustomRangeDispatchTests(unittest.TestCase):
    def test_custom_range_returns_one_slice(self):
        start = datetime(2026, 1, 1)
        end = datetime(2026, 1, 10)

        starts, ends = splunk_engine.build_slices(start, end, "Custom")

        self.assertEqual(starts, [start])
        self.assertEqual(ends, [end])

    def test_daily_behavior_remains_unchanged(self):
        start = datetime(2026, 1, 1)
        end = datetime(2026, 1, 4)

        starts, ends = splunk_engine.build_slices(start, end, "Daily")

        self.assertEqual(
            starts,
            [
                datetime(2026, 1, 1),
                datetime(2026, 1, 2),
                datetime(2026, 1, 3),
            ],
        )
        self.assertEqual(
            ends,
            [
                datetime(2026, 1, 2),
                datetime(2026, 1, 3),
                datetime(2026, 1, 4),
            ],
        )

    def test_weekly_behavior_remains_unchanged(self):
        start = datetime(2026, 1, 1)
        end = datetime(2026, 1, 10)

        starts, ends = splunk_engine.build_slices(start, end, "Weekly")

        self.assertEqual(starts, [datetime(2026, 1, 1), datetime(2026, 1, 8)])
        self.assertEqual(ends, [datetime(2026, 1, 8), datetime(2026, 1, 10)])

    def test_monthly_behavior_remains_unchanged(self):
        start = datetime(2026, 1, 1)
        end = datetime(2026, 3, 15)

        starts, ends = splunk_engine.build_slices(start, end, "Monthly")

        self.assertEqual(
            starts,
            [datetime(2026, 1, 1), datetime(2026, 2, 1), datetime(2026, 3, 1)],
        )
        self.assertEqual(
            ends,
            [datetime(2026, 2, 1), datetime(2026, 3, 1), datetime(2026, 3, 15)],
        )

    def test_custom_confirmation_text_says_one_dispatch_per_report(self):
        text = build_manual_regen_mode_text(
            frequency="Custom",
            selected_report_count=3,
            slice_count=1,
        )

        self.assertEqual(text, "custom range, 1 dispatch per selected report (3 total)")
        self.assertNotIn("slices:", text)

    def test_sliced_confirmation_text_shows_dispatch_count(self):
        cases = [
            ("Daily", 9, "daily slices: 9 per report (27 total)"),
            ("Weekly", 2, "weekly slices: 2 per report (6 total)"),
            ("Monthly", 1, "monthly slices: 1 per report (3 total)"),
        ]
        for frequency, slice_count, expected in cases:
            with self.subTest(frequency=frequency):
                text = build_manual_regen_mode_text(
                    frequency=frequency,
                    selected_report_count=3,
                    slice_count=slice_count,
                )

                self.assertEqual(text, expected)

    def test_custom_override_confirmation_shows_selected_range(self):
        prompt = ReportsApp._manual_regen_prompt_text(
            object(),
            selected_report_names=["Report A", "Report B"],
            range_label="Date range override",
            range_text="2026-01-01 to 2026-01-10",
            mode_text=build_manual_regen_mode_text(
                frequency="Custom",
                selected_report_count=2,
                slice_count=1,
            ),
        )

        self.assertIn("Date range override: 2026-01-01 to 2026-01-10", prompt)
        self.assertIn(
            "Dispatch plan: custom range, 1 dispatch per selected report (2 total)",
            prompt,
        )
        self.assertNotIn("saved search time range in effect", prompt)

    def test_no_override_confirmation_for_one_report_uses_saved_range(self):
        prompt = ReportsApp._manual_regen_prompt_text(
            object(),
            selected_report_names=["Report A"],
            range_label="Saved search time range",
            range_text=build_saved_search_time_range_text([("-24h", "now")]),
            mode_text="single run per selected report using saved-search time range (1 total)",
        )

        self.assertIn("Saved search time range: earliest=-24h, latest=now", prompt)
        self.assertIn(
            "Duration: relative range, resolved by Splunk at dispatch time",
            prompt,
        )
        self.assertIn(
            "Dispatch plan: single run per selected report using saved-search time range (1 total)",
            prompt,
        )
        self.assertNotIn("Date range: 2026-01-01 to 2026-01-10", prompt)
        self.assertNotIn("saved search time range in effect", prompt)

    def test_no_override_confirmation_for_multiple_reports_with_different_ranges(self):
        prompt = ReportsApp._manual_regen_prompt_text(
            object(),
            selected_report_names=["Report A", "Report B"],
            range_label="Saved search time range",
            range_text=build_saved_search_time_range_text(
                [("-24h", "now"), ("-7d", "now")]
            ),
            mode_text="single run per selected report using saved-search time range (2 total)",
        )

        self.assertIn("Saved search time range: varies by selected report", prompt)
        self.assertNotIn("Date range override", prompt)

    def test_epoch_saved_search_range_converts_to_sgt_with_duration(self):
        text = build_saved_search_time_range_text([("1773244800", "1773504000")])

        self.assertIn("2026-03-12 00:00:00 SGT to 2026-03-15 00:00:00 SGT", text)
        self.assertIn(
            "Raw Splunk range: earliest=1773244800, latest=1773504000",
            text,
        )
        self.assertIn("Duration: 3 days", text)

    def test_relative_saved_search_range_preserves_raw_expressions(self):
        text = build_saved_search_time_range_text([("-7d@d", "now")])

        self.assertIn("earliest=-7d@d, latest=now", text)
        self.assertIn(
            "Duration: relative range, resolved by Splunk at dispatch time",
            text,
        )
        self.assertNotIn("SGT", text)

    def test_mixed_epoch_and_relative_saved_search_range_does_not_crash(self):
        text = build_saved_search_time_range_text([("1773244800", "now")])

        self.assertIn("2026-03-12 00:00:00 SGT to latest=now", text)
        self.assertIn("Raw Splunk range: earliest=1773244800, latest=now", text)
        self.assertIn(
            "Duration: mixed absolute/relative range, resolved by Splunk at dispatch time",
            text,
        )

    def test_confirmation_uses_human_epoch_range_as_primary_display(self):
        prompt = ReportsApp._manual_regen_prompt_text(
            object(),
            selected_report_names=["Report A"],
            range_label="Saved search time range",
            range_text=build_saved_search_time_range_text(
                [("1773244800", "1773504000")]
            ),
            mode_text="single run per selected report using saved-search time range (1 total)",
        )

        self.assertIn(
            "Saved search time range:\n2026-03-12 00:00:00 SGT to 2026-03-15 00:00:00 SGT",
            prompt,
        )
        self.assertIn(
            "Raw Splunk range: earliest=1773244800, latest=1773504000",
            prompt,
        )
        self.assertNotIn(
            "Saved search time range: earliest=1773244800, latest=1773504000",
            prompt,
        )


if __name__ == "__main__":
    unittest.main()
