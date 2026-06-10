import unittest

import splunk_engine


class _FakeSignal:
    def emit(self, *args, **kwargs):
        return None


class SavedSearchListingTests(unittest.TestCase):
    def test_disabled_saved_searches_are_not_listed(self):
        client = splunk_engine.SplunkClient.__new__(splunk_engine.SplunkClient)
        client.searches_loaded = _FakeSignal()
        client.finished = _FakeSignal()
        client.error = _FakeSignal()

        def fake_get(*args, **kwargs):
            return {
                "entry": [
                    {
                        "id": "enabled-id",
                        "name": "Enabled Report",
                        "acl": {"app": "search"},
                        "content": {"disabled": "0", "action.email": "1"},
                    },
                    {
                        "id": "disabled-id",
                        "name": "Disabled Report",
                        "acl": {"app": "search"},
                        "content": {"disabled": "1", "action.email": "1"},
                    },
                    {
                        "id": "disabled-bool-id",
                        "name": "Disabled Bool Report",
                        "acl": {"app": "search"},
                        "content": {"disabled": True, "action.email": "1"},
                    },
                ]
            }

        client._get = fake_get

        ids, names, email_flags, saved_time_ranges = client.list_saved_searches("search")

        self.assertEqual(ids, ["enabled-id"])
        self.assertEqual(names, ["Enabled Report"])
        self.assertEqual(email_flags, [True])
        self.assertEqual(saved_time_ranges, [("", "")])


if __name__ == "__main__":
    unittest.main()
