from __future__ import annotations

import unittest
from datetime import date, datetime

import splunk_engine


class ReportDispatchStabilizationTests(unittest.TestCase):
    def test_stable_report_id_prefers_existing_report_url(self) -> None:
        self.assertEqual(
            splunk_engine.stable_report_id(
                "/servicesNS/admin/search/saved/searches/WebLogic",
                "WebLogic",
                app="search",
                owner="admin",
            ),
            "/servicesNS/admin/search/saved/searches/WebLogic",
        )

    def test_filtering_preserves_hidden_selected_reports(self) -> None:
        report_ids = ["id-weblogic", "id-archer", "id-firewall"]
        report_names = ["WebLogic Errors", "Archer Access", "Firewall Summary"]
        selected = {
            splunk_engine.stable_report_id(report_ids[0], report_names[0]),
            splunk_engine.stable_report_id(report_ids[1], report_names[1]),
        }

        archer_view = splunk_engine.filter_report_indices(
            report_names,
            report_ids,
            search_term="archer",
            selected_report_ids=selected,
        )
        selected_only_view = splunk_engine.filter_report_indices(
            report_names,
            report_ids,
            search_term="weblogic",
            selected_report_ids=selected,
            show_selected_only=True,
        )
        full_view = splunk_engine.filter_report_indices(
            report_names,
            report_ids,
            search_term="",
            selected_report_ids=selected,
        )

        self.assertEqual(archer_view, [1])
        self.assertEqual(selected_only_view, [0, 1])
        self.assertEqual(full_view, [0, 1, 2])

    def test_custom_range_validation_rejects_missing_and_non_forward_ranges(self) -> None:
        start = datetime(2026, 3, 12, 10, 0)
        same = datetime(2026, 3, 12, 10, 0)
        before = datetime(2026, 3, 12, 9, 59)
        after = datetime(2026, 3, 12, 10, 1)

        self.assertEqual(splunk_engine.validate_custom_range(None, after)[0], False)
        self.assertEqual(splunk_engine.validate_custom_range(start, None)[0], False)
        self.assertEqual(splunk_engine.validate_custom_range(start, before)[0], False)
        self.assertEqual(splunk_engine.validate_custom_range(start, same)[0], False)
        self.assertEqual(splunk_engine.validate_custom_range(start, after), (True, ""))

    def test_combine_date_time_requires_hhmm_time(self) -> None:
        self.assertEqual(
            splunk_engine.combine_date_time(date(2026, 3, 12), "09:30"),
            datetime(2026, 3, 12, 9, 30),
        )
        with self.assertRaises(ValueError):
            splunk_engine.combine_date_time(date(2026, 3, 12), "")
        with self.assertRaises(ValueError):
            splunk_engine.combine_date_time(date(2026, 3, 12), "24:00")

    def test_mode_decision_uses_selected_reports_not_slices(self) -> None:
        self.assertEqual(splunk_engine.selected_handling_mode(7), "Premium Handling")
        self.assertEqual(splunk_engine.selected_handling_mode(8), "Throughput Handling")

        seven_report_ids = [f"id-{i}" for i in range(7)]
        seven_report_names = [f"Report {i}" for i in range(7)]
        seven_plan = splunk_engine.build_run_plan(
            seven_report_ids,
            seven_report_names,
            list(range(7)),
            date_mode="Daily",
            start=datetime(2026, 3, 1),
            end=datetime(2026, 3, 11),
        )

        self.assertEqual(seven_plan.selected_report_count, 7)
        self.assertEqual(seven_plan.planned_execution_count, 70)
        self.assertEqual(seven_plan.handling_mode, "Premium Handling")

    def test_custom_range_creates_one_execution_per_selected_report(self) -> None:
        start = datetime(2026, 3, 12, 10, 0)
        end = datetime(2026, 3, 13, 15, 0)
        plan = splunk_engine.build_run_plan(
            ["id-a", "id-b"],
            ["Firewall Summary", "Archer Review"],
            [0, 1],
            date_mode=splunk_engine.DATE_MODE_CUSTOM_RANGE,
            start=start,
            end=end,
            app="search",
        )

        self.assertEqual(plan.selected_report_count, 2)
        self.assertEqual(plan.planned_execution_count, 2)
        self.assertEqual(plan.handling_mode, "Premium Handling")
        self.assertEqual(plan.executions[0].earliest_time, "2026-03-12 10:00")
        self.assertEqual(plan.executions[0].latest_time, "2026-03-13 15:00")
        self.assertEqual(plan.executions[0].dispatch_earliest, splunk_engine.to_epoch(start))
        self.assertEqual(plan.executions[0].dispatch_latest, splunk_engine.to_epoch(end))

    def test_daily_weekly_monthly_run_plan_uses_existing_slice_builder(self) -> None:
        plan = splunk_engine.build_run_plan(
            ["id-a"],
            ["Daily Summary"],
            [0],
            date_mode="Daily",
            start=datetime(2026, 3, 1),
            end=datetime(2026, 3, 4),
        )

        self.assertEqual(plan.planned_execution_count, 3)
        self.assertEqual([item.slice_number for item in plan.executions], [1, 2, 3])
        self.assertEqual([item.slice_total for item in plan.executions], [3, 3, 3])


if __name__ == "__main__":
    unittest.main()
