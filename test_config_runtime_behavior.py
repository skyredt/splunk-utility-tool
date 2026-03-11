from __future__ import annotations

import os
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from Internal.config_manager import ConfigFormatError, ConfigMissingError, load_and_validate_config
from Internal.dpapi_store import load_or_enroll_password
from Internal.security_policy import PolicyViolation, load_security_policy
from splunk_engine import load_config


BASE_TEMPLATE = textwrap.dedent(
    """\
    # Runtime configuration template.
    # The tool recreates config.ini from this file when config.ini is missing.

    [splunk]
    # Primary endpoint (Splunk management port)
    host = https://splunk.example:8089

    # Backward-compatible list form (first entry is used for startup checks/connect)
    servers = https://splunk.example:8089

    # v4 is password-only (DPAPI secret file). Token/CLI auth is not supported.
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

    [dispatch]
    per_slice_wait_seconds = 30
    continue_on_timeout = true
    timeout_result = pending

    [email]
    ack_enabled = 1
    ack_on_pending = 0
    ack_recipients =
    ack_use_savedsearch_recipients = 0
    ack_attach_manifest = 0
    smtp_host = 127.0.0.1
    smtp_port = 25
    smtp_tls = 0
    smtp_user =
    smtp_pass =
    from_addr = Splunk Notification <splunk-donotreply@localhost>

    [postdispatch]
    merge_report_enabled = true
    merge_report_index = _internal
    merge_report_source_contains = mergeReport_alert.log
    merge_report_sourcetype =
    merge_report_timeout_seconds = 300
    native_email_enabled = true
    native_email_index = _internal
    native_email_source_contains = python.log
    native_email_sourcetype =
    native_email_timeout_seconds = 300
    broker_request_timeout_seconds = 300
    reconcile_pending = true
    reconcile_wait_seconds = 60
    native_email_strict_success = false
    poll_seconds = 5
    lookback_seconds = 900
    """
)


class _AuditStub:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def log_event(self, event: str, level: str = "INFO", **fields) -> None:
        self.events.append((event, level, fields))


class ConfigRuntimeBehaviorTests(unittest.TestCase):
    def _write(self, path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)

    def _write_template(self, exe_dir: str, content: str = BASE_TEMPLATE) -> str:
        template_path = os.path.join(exe_dir, "config.ini.example")
        self._write(template_path, content)
        return template_path

    def test_missing_config_is_created_from_example(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_template(tmpdir)

            loaded = load_and_validate_config(exe_dir=tmpdir)

            config_path = os.path.join(tmpdir, "config.ini")
            self.assertTrue(os.path.isfile(config_path))
            self.assertTrue(loaded.created_from_template)
            self.assertIn("Created config.ini from config.ini.example.", loaded.changes)
            self.assertIn("[splunk]\n# Primary endpoint (Splunk management port)\nhost = https://splunk.example:8089\n", loaded.canonical_text)

    def test_both_config_and_template_missing_raise_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ConfigMissingError) as ctx:
                load_and_validate_config(exe_dir=tmpdir)
            self.assertIn("config.ini is missing", str(ctx.exception))

    def test_malformed_config_line_reports_line_number(self) -> None:
        malformed = textwrap.dedent(
            """\
            [splunk]
            host = https://splunk.example:8089
            servers = https://splunk.example:8089 [Security]
            """
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_template(tmpdir)
            self._write(os.path.join(tmpdir, "config.ini"), malformed)

            with self.assertRaises(ConfigFormatError) as ctx:
                load_and_validate_config(exe_dir=tmpdir)

            self.assertEqual(ctx.exception.line_number, 3)
            self.assertIn("Possible merged section header", str(ctx.exception))

    def test_canonical_formatting_rewrites_file_and_creates_backup(self) -> None:
        noncanonical = textwrap.dedent(
            """\
            # Runtime configuration template.
            [splunk]
            servers=https://splunk.example:8089
            host=https://splunk.example:8089
            verify_ssl=true
            auth_mode=password
            [Credentials]
            username=splunk_service
            secret_file=secret.dpapi
            dpapi_scope=machine
            [Security]
            build_mode=production
            policy_mode=enforced
            allow_insecure_overrides=false
            [Logging]
            level=INFO
            verbose=false
            max_bytes=10485760
            backup_count=10
            """
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_template(tmpdir)
            config_path = os.path.join(tmpdir, "config.ini")
            self._write(config_path, noncanonical)

            loaded = load_and_validate_config(exe_dir=tmpdir)

            self.assertTrue(loaded.repaired)
            self.assertTrue(os.path.isfile(config_path + ".bak"))
            with open(config_path, "r", encoding="utf-8") as f:
                repaired = f.read()
            self.assertTrue(repaired.endswith("\n"))
            self.assertIn("\n\n[Credentials]\n", repaired)
            self.assertIn("host = https://splunk.example:8089\n", repaired)
            self.assertIn("servers = https://splunk.example:8089\n", repaired)
            self.assertNotIn("servers=https://", repaired)

    def test_hardening_policy_runs_after_successful_parse(self) -> None:
        insecure = BASE_TEMPLATE.replace("policy_mode = enforced", "policy_mode = permissive")
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_template(tmpdir)
            self._write(os.path.join(tmpdir, "config.ini"), insecure)

            with self.assertRaises(PolicyViolation) as ctx:
                load_security_policy(exe_dir=tmpdir)

            self.assertEqual(ctx.exception.control, "POLICY_MODE_INVALID")

    def test_startup_smoke_recovers_missing_config_and_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_template(tmpdir)

            policy = load_security_policy(exe_dir=tmpdir)
            cfg = load_config(exe_dir=tmpdir, policy=policy)

            self.assertEqual(os.path.normcase(cfg.config_path), os.path.normcase(os.path.join(tmpdir, "config.ini")))
            self.assertEqual(cfg.username, "splunk_service")
            self.assertEqual(cfg.servers, ["https://splunk.example:8089"])

    def test_unsupported_legacy_config_is_rejected_after_parse(self) -> None:
        legacy = BASE_TEMPLATE.replace("auth_mode = password", "auth_mode = token")
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_template(tmpdir)
            self._write(os.path.join(tmpdir, "config.ini"), legacy)

            policy = load_security_policy(exe_dir=tmpdir)
            with self.assertRaises(PolicyViolation) as ctx:
                load_config(exe_dir=tmpdir, policy=policy)

            self.assertEqual(ctx.exception.control, "LEGACY_FEATURE_DISABLED")

    def test_existing_path_regression_no_longer_raises_unboundlocal(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target_path = os.path.join(tmpdir, "secret.dpapi")
            audit = _AuditStub()

            with patch("Internal.dpapi_store.resolve_secret_candidates", return_value=[]), patch(
                "Internal.dpapi_store.choose_writable_secret_path",
                return_value=target_path,
            ), patch("Internal.dpapi_store._path_acl_is_weak", return_value=False), patch(
                "Internal.dpapi_store.dpapi_protect_machine",
                return_value=b"encrypted",
            ), patch("Internal.dpapi_store.save_secret_b64") as save_mock:
                password, saved_path = load_or_enroll_password(
                    prompt_fn=lambda: "correct horse battery staple",
                    exe_dir=tmpdir,
                    logger=audit,
                    secret_file="secret.dpapi",
                )

            self.assertEqual(password, "correct horse battery staple")
            self.assertEqual(saved_path, target_path)
            save_mock.assert_called_once()
            self.assertIn(("CRED_ENROLL_CREATE", "INFO", {"secret_path_used": target_path}), audit.events)


if __name__ == "__main__":
    unittest.main()
