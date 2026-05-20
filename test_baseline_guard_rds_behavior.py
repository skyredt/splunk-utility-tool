from __future__ import annotations

import copy
import os
import tempfile
import unittest
from unittest import mock

from Internal.baseline_guard import (
    _resolve_baseline_candidates,
    build_security_fingerprint,
    enforce_security_baseline,
    is_weaker_fingerprint,
)
from Internal.security_policy import SecurityPolicy


class BaselineGuardRdsBehaviorTests(unittest.TestCase):
    def _policy(self, exe_dir: str) -> SecurityPolicy:
        return SecurityPolicy(
            exe_dir=exe_dir,
            config_path=os.path.join(exe_dir, "config.ini"),
            build_mode="production",
            policy_mode="enforced",
            allow_insecure_overrides=False,
        )

    def _safe_fingerprint(self, exe_dir: str) -> dict:
        return build_security_fingerprint(
            tool_version="v4",
            policy=self._policy(exe_dir),
            logging_level="INFO",
            logging_max_bytes=10_485_760,
            logging_backup_count=10,
        )

    def test_missing_previous_fingerprint_is_not_automatic_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            exe_dir = os.path.join(temp_dir, "tool")
            os.makedirs(os.path.join(exe_dir, "Internal"), exist_ok=True)
            local_appdata = os.path.join(temp_dir, "LocalAppData")
            env = {
                "LOCALAPPDATA": local_appdata,
                "TEMP": os.path.join(local_appdata, "Temp"),
                "TMP": os.path.join(local_appdata, "Temp"),
                "USERDOMAIN": "TESTDOM",
            }
            with mock.patch.dict(os.environ, env, clear=False):
                with mock.patch("Internal.baseline_guard.getpass.getuser", return_value="alice"):
                    current = self._safe_fingerprint(exe_dir)
                    self.assertFalse(is_weaker_fingerprint({}, current, exe_dir=exe_dir))

    def test_approved_current_user_roots_are_allowed_but_unrelated_user_and_temp_paths_are_weaker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            exe_dir = os.path.join(temp_dir, "tool")
            os.makedirs(os.path.join(exe_dir, "Internal"), exist_ok=True)
            local_appdata = os.path.join(temp_dir, "Users", "alice", "AppData", "Local")
            env = {
                "LOCALAPPDATA": local_appdata,
                "TEMP": os.path.join(local_appdata, "Temp"),
                "TMP": os.path.join(local_appdata, "Temp"),
                "USERDOMAIN": "TESTDOM",
            }
            with mock.patch.dict(os.environ, env, clear=False):
                with mock.patch("Internal.baseline_guard.getpass.getuser", return_value="alice"):
                    previous = self._safe_fingerprint(exe_dir)
                    approved = copy.deepcopy(previous)
                    approved["allowed_artifact_roots"] = [
                        exe_dir,
                        os.path.join(exe_dir, "Internal"),
                        os.path.join(local_appdata, "SplunkUtilityTool"),
                    ]
                    unrelated_user = copy.deepcopy(previous)
                    unrelated_user["allowed_artifact_roots"] = [
                        r"C:\Users\bob\AppData\Roaming\SplunkUtilityTool",
                    ]
                    transient_temp = copy.deepcopy(previous)
                    transient_temp["allowed_artifact_roots"] = [
                        os.path.join(local_appdata, "Temp", "random-tool-root"),
                    ]
                    self.assertFalse(is_weaker_fingerprint(previous, approved, exe_dir=exe_dir))
                    self.assertTrue(is_weaker_fingerprint(previous, unrelated_user, exe_dir=exe_dir))
                    self.assertTrue(is_weaker_fingerprint(previous, transient_temp, exe_dir=exe_dir))

    def test_first_run_bootstraps_scoped_baseline_and_emits_audit_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            exe_dir = os.path.join(temp_dir, "shared-tool")
            internal_dir = os.path.join(exe_dir, "Internal")
            os.makedirs(internal_dir, exist_ok=True)
            legacy_baseline = os.path.join(internal_dir, "security_baseline.json")
            with open(legacy_baseline, "w", encoding="utf-8") as handle:
                handle.write("{}")

            local_appdata = os.path.join(temp_dir, "Users", "alice", "AppData", "Local")
            env = {
                "LOCALAPPDATA": local_appdata,
                "TEMP": os.path.join(local_appdata, "Temp"),
                "TMP": os.path.join(local_appdata, "Temp"),
                "USERDOMAIN": "TESTDOM",
            }
            audit_events: list[tuple[str, str, dict]] = []
            with mock.patch.dict(os.environ, env, clear=False):
                with mock.patch("Internal.baseline_guard.getpass.getuser", return_value="alice"):
                    ok, reason = enforce_security_baseline(
                        exe_dir=exe_dir,
                        policy=self._policy(exe_dir),
                        fingerprint=self._safe_fingerprint(exe_dir),
                        config_hash="cfg1",
                        audit_event_fn=lambda event, level="INFO", **fields: audit_events.append((event, level, fields)),
                    )
                    scoped_path = _resolve_baseline_candidates(exe_dir)[0]

            self.assertTrue(ok)
            self.assertEqual(reason, "baseline_bootstrapped")
            self.assertTrue(os.path.isfile(scoped_path))
            self.assertTrue(any(event == "BASELINE_BOOTSTRAPPED" for event, _, _ in audit_events))

    def test_profile_a_baseline_does_not_block_profile_b_but_same_user_downgrade_still_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            exe_dir = os.path.join(temp_dir, "shared-tool")
            os.makedirs(os.path.join(exe_dir, "Internal"), exist_ok=True)

            alice_local = os.path.join(temp_dir, "Users", "alice", "AppData", "Local")
            bob_local = os.path.join(temp_dir, "Users", "bob", "AppData", "Local")
            alice_env = {
                "LOCALAPPDATA": alice_local,
                "TEMP": os.path.join(alice_local, "Temp"),
                "TMP": os.path.join(alice_local, "Temp"),
                "USERDOMAIN": "TESTDOM",
            }
            bob_env = {
                "LOCALAPPDATA": bob_local,
                "TEMP": os.path.join(bob_local, "Temp"),
                "TMP": os.path.join(bob_local, "Temp"),
                "USERDOMAIN": "TESTDOM",
            }

            with mock.patch.dict(os.environ, alice_env, clear=False):
                with mock.patch("Internal.baseline_guard.getpass.getuser", return_value="alice"):
                    ok_a, _ = enforce_security_baseline(
                        exe_dir=exe_dir,
                        policy=self._policy(exe_dir),
                        fingerprint=self._safe_fingerprint(exe_dir),
                        config_hash="cfg-alice",
                    )
                    alice_path = _resolve_baseline_candidates(exe_dir)[0]

                    downgraded = self._safe_fingerprint(exe_dir)
                    downgraded["allowed_artifact_roots"] = [r"C:\Users\other-user\AppData\Roaming\SplunkUtilityTool"]
                    ok_downgrade, reason_downgrade = enforce_security_baseline(
                        exe_dir=exe_dir,
                        policy=self._policy(exe_dir),
                        fingerprint=downgraded,
                        config_hash="cfg-alice-2",
                    )

            with mock.patch.dict(os.environ, bob_env, clear=False):
                with mock.patch("Internal.baseline_guard.getpass.getuser", return_value="bob"):
                    weak_first_run = self._safe_fingerprint(exe_dir)
                    weak_first_run["allowed_artifact_roots"] = [r"C:\Users\other-user\AppData\Roaming\SplunkUtilityTool"]
                    ok_b, reason_b = enforce_security_baseline(
                        exe_dir=exe_dir,
                        policy=self._policy(exe_dir),
                        fingerprint=weak_first_run,
                        config_hash="cfg-bob",
                    )
                    bob_path = _resolve_baseline_candidates(exe_dir)[0]

            self.assertTrue(ok_a)
            self.assertFalse(ok_downgrade)
            self.assertEqual(reason_downgrade, "Security configuration downgrade detected.")
            self.assertTrue(ok_b)
            self.assertEqual(reason_b, "baseline_bootstrapped")
            self.assertNotEqual(alice_path, bob_path)
            self.assertTrue(os.path.isfile(alice_path))
            self.assertTrue(os.path.isfile(bob_path))


if __name__ == "__main__":
    unittest.main()
