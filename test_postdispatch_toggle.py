from __future__ import annotations

import os
import tempfile
import textwrap
import unittest

from Internal.security_policy import load_security_policy
from splunk_engine import load_config, resolve_postdispatch_enabled


class PostDispatchToggleTests(unittest.TestCase):
    def test_resolve_postdispatch_enabled_defaults_true_when_missing(self) -> None:
        self.assertTrue(resolve_postdispatch_enabled(None))

    def test_load_config_reads_postdispatch_enabled_false(self) -> None:
        template = textwrap.dedent(
            """\
            [splunk]
            host = https://splunk.example:8089
            servers = https://splunk.example:8089
            auth_mode = password
            verify_ssl = true

            [Credentials]
            username = splunk_service
            secret_file = secret.dpapi
            dpapi_scope = machine

            [Security]
            build_mode = production
            policy_mode = enforced
            allow_insecure_overrides = false

            [Logging]
            level = INFO
            verbose = false
            max_bytes = 10485760
            backup_count = 10

            [runtime]
            test_mode = false

            [dispatch]
            per_slice_wait_seconds = 30
            continue_on_timeout = true
            timeout_result = pending

            [email]
            ack_enabled = 1

            [postdispatch]
            enabled = false
            reconcile_pending = true
            reconcile_wait_seconds = 60
            poll_seconds = 5
            status_check_timeout_seconds = 300
            broker_request_timeout_seconds = 300
            """
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            template_path = os.path.join(tmpdir, "config.ini.example")
            with open(template_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(template)
            policy = load_security_policy(exe_dir=tmpdir)
            config = load_config(exe_dir=tmpdir, policy=policy)

            self.assertIsInstance(config.postdispatch_config, dict)
            self.assertFalse(config.postdispatch_config["enabled"])
            self.assertFalse(resolve_postdispatch_enabled(config))


if __name__ == "__main__":
    unittest.main()
