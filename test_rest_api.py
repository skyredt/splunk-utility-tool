from __future__ import annotations

import unittest

import splunk_engine


class FakeMetadataClient:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def _get(self, path: str, **kwargs):
        del kwargs
        self.paths.append(path)
        return {
            "entry": [
                {
                    "name": "saved_search_example",
                    "acl": {
                        "owner": "user_example",
                        "app": "app_example",
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


class RestMetadataUnitTests(unittest.TestCase):
    def test_fetch_saved_search_entry_uses_fake_rest_metadata(self) -> None:
        client = FakeMetadataClient()

        content, used_path, entry, namespace = splunk_engine._fetch_saved_search_entry(
            client,
            report_id_url="/servicesNS/user_example/app_example/saved/searches/saved_search_example",
            report_name="saved_search_example",
            app="app_example",
            username="user_example",
        )

        self.assertEqual(used_path, "/servicesNS/user_example/app_example/saved/searches/saved_search_example")
        self.assertEqual(entry["name"], "saved_search_example")
        self.assertEqual(content["action.email.to"], "ops@example.com")
        self.assertEqual(namespace["owner"], "user_example")
        self.assertEqual(namespace["app"], "app_example")
        self.assertEqual(client.paths[0], used_path)


if __name__ == "__main__":
    unittest.main()
