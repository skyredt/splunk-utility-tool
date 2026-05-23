from __future__ import annotations

import unittest

import splunk_engine


class FakeSavedSearchClient:
    def __init__(self, metadata: dict) -> None:
        self.metadata = metadata
        self.paths: list[str] = []

    def _get(self, path: str, **kwargs):
        del kwargs
        self.paths.append(path)
        return self.metadata


class RecipientExtractionUnitTests(unittest.TestCase):
    def test_collect_saved_search_recipients_uses_fake_metadata_only(self) -> None:
        client = FakeSavedSearchClient(
            {
                "entry": [
                    {
                        "name": "saved_search_example",
                        "content": {
                            "action.email.to": "ops@example.com;owner@example.com",
                            "action.mergeReport.param.To": "owner@example.com;merge@example.com",
                        },
                    }
                ]
            }
        )

        recipients = splunk_engine._collect_saved_search_recipients(
            client,
            "/servicesNS/user_example/app_example/saved/searches/saved_search_example",
            "saved_search_example",
            "app_example",
            "user_example",
        )

        self.assertEqual(recipients, ["ops@example.com", "owner@example.com", "merge@example.com"])
        self.assertTrue(client.paths)


if __name__ == "__main__":
    unittest.main()
