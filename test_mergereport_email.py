from __future__ import annotations

import unittest

import splunk_engine


class MergeReportRecipientUnitTests(unittest.TestCase):
    def test_extracts_mergereport_recipients_from_saved_search_content(self) -> None:
        content = {
            "action.mergeReport": "1",
            "action.mergeReport.param.To": "primary@example.com;secondary@example.com",
        }

        recipients = splunk_engine._extract_recipients_from_content(content)

        self.assertEqual(recipients, ["primary@example.com", "secondary@example.com"])

    def test_dedupes_native_and_mergereport_recipients(self) -> None:
        content = {
            "action.email.to": "primary@example.com, shared@example.com",
            "action.mergeReport.param.To": "shared@example.com; merge@example.com",
        }

        recipients = splunk_engine._extract_recipients_from_content(content)

        self.assertEqual(recipients, ["primary@example.com", "shared@example.com", "merge@example.com"])


if __name__ == "__main__":
    unittest.main()
