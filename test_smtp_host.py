from __future__ import annotations

import unittest
from urllib.parse import urlparse

import splunk_engine


class SmtpHostUnitTests(unittest.TestCase):
    def test_smtp_settings_use_fake_config_without_real_client_login(self) -> None:
        cfg = splunk_engine.SplunkConfig(
            servers=["https://splunk-example.invalid:8089"],
            username="unit_user",
            password="unit_password",
            smtp_host="smtp-example.invalid",
            smtp_port=2525,
        )

        settings = splunk_engine._resolve_smtp_settings(cfg)

        self.assertEqual(settings["host"], "smtp-example.invalid")
        self.assertEqual(settings["port"], 2525)

    def test_hostname_can_be_derived_from_fake_splunk_management_url(self) -> None:
        parsed = urlparse("https://splunk-example.invalid:8089")

        self.assertEqual(parsed.hostname, "splunk-example.invalid")
        self.assertEqual(parsed.port, 8089)


if __name__ == "__main__":
    unittest.main()
