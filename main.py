"""Launcher for Splunk Utility Tool (Tkinter).

This launcher calls the Tk-based GUI implemented in `splunk_report_tk.py`.
It intentionally avoids Qt/PySide6 so the tool can run on Windows machines
without Visual Studio or extra GUI dependencies.
"""

from __future__ import annotations

import inspect
import json
import os
import sys
import uuid


def _print_usage() -> None:
    print("Usage:")
    print("  python main.py")
    print("  python main.py --set-token      (unsupported in v4 production)")
    print("  python main.py --test-auth      (unsupported in v4 production)")
    print("  python main.py --security-selfcheck")
    print("  python main.py --run-splunk-broker --exe-dir <path>   (internal)")


def _runtime_exe_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _emit_cli_audit(event: str, level: str = "WARN", **fields) -> None:
    try:
        from Internal.logging_broker import start_local_logging_broker
        from Internal.security_policy import load_security_policy
    except Exception:
        return
    exe_dir = _runtime_exe_dir()
    try:
        policy = load_security_policy(exe_dir=exe_dir)
        allow_local_appdata = (not policy.is_production) and policy.insecure_overrides_active
    except Exception:
        allow_local_appdata = False
    broker_handle = start_local_logging_broker(
        exe_dir=exe_dir,
        tool_version="v4",
        allow_local_appdata=allow_local_appdata,
    )
    try:
        broker_handle.audit_logger.log_event(event, level=level, **fields)
    finally:
        broker_handle.shutdown()


def _run_legacy_feature_blocked(feature_name: str) -> int:
    _emit_cli_audit(
        "LEGACY_FEATURE_BLOCKED",
        level="WARN",
        feature=feature_name,
        reason="Not supported in v4 production build",
    )
    print("Not supported in v4 production build")
    return 2


def _run_splunk_broker(argv: list[str]) -> int:
    try:
        from Internal.splunk_broker import run_splunk_broker_server
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True, separators=(",", ":"), ensure_ascii=True), flush=True)
        return 1
    exe_dir = _runtime_exe_dir()
    if "--exe-dir" in argv:
        idx = argv.index("--exe-dir")
        if idx + 1 < len(argv):
            exe_dir = str(argv[idx + 1])
    return run_splunk_broker_server(exe_dir=exe_dir)


def _run_security_selfcheck() -> int:
    try:
        from collections import deque
        from Internal.audit_logger import FIXED_PROGRAMDATA_ROOT, verify_log_integrity
        from Internal.dpapi_store import resolve_secret_candidates
        from Internal.logging_broker import (
            BROKER_BIND_HOST,
            PERSISTENT_AUDIT_UNAVAILABLE_WARNING,
            BrokerAuditLogger,
            start_local_logging_broker,
        )
        from Internal.splunk_broker import (
            SPLUNK_BROKER_BIND_HOST,
            SPLUNK_BROKER_UNAVAILABLE_WARNING,
            start_local_splunk_broker,
        )
        from Internal.security_policy import PolicyViolation, load_security_policy, redact_text
        from Internal.baseline_guard import is_weaker_fingerprint
        from splunk_engine import SplunkClient, load_config, set_security_policy
    except Exception as exc:
        print(f"Self-check failed to import modules: {exc}")
        return 1

    exe_dir = _runtime_exe_dir()
    checks: list[tuple[str, bool, str]] = []

    try:
        policy = load_security_policy(exe_dir=exe_dir)
        set_security_policy(policy)
        checks.append(("build_mode_valid", policy.build_mode in ("production", "dev"), policy.build_mode))
        checks.append(("policy_mode_enforced", policy.is_enforced or (not policy.is_production), policy.policy_mode))
        checks.append(("env_overrides_blocked", not policy.env_overrides_allowed(), str(policy.env_overrides_allowed())))
        expected_cfg = os.path.join(exe_dir, "config.ini")
        checks.append(("config_path_bound", os.path.normcase(policy.config_path) == os.path.normcase(expected_cfg), policy.config_path))
        if policy.is_production and policy.policy_mode == "permissive":
            checks.append(("production_permissive_requires_breakglass", policy.break_glass_token.valid, policy.break_glass_token.error or "ok"))
    except PolicyViolation as exc:
        print(f"Self-check POLICY FAIL: {exc.control}: {exc.detail}")
        return 1
    except Exception as exc:
        print(f"Self-check failed to load policy: {exc}")
        return 1

    try:
        cfg = load_config(exe_dir=exe_dir, policy=policy)
        https_only = all(str(url).lower().startswith("https://") for url in cfg.servers)
        checks.append(("https_only_endpoints", https_only, ";".join(cfg.servers)))
        checks.append(("secret_file_basename", (cfg.secret_file == os.path.basename(cfg.secret_file)), cfg.secret_file))
        checks.append(("auth_mode_password_only", cfg.auth_mode == "password", cfg.auth_mode))
    except Exception as exc:
        checks.append(("secure_config_load", False, str(exc)))

    try:
        SplunkClient("http://example.invalid:8089", username="x", password="y", verify_ssl=False)
        checks.append(("http_endpoint_rejected", False, "http:// endpoint accepted"))
    except PolicyViolation:
        checks.append(("http_endpoint_rejected", True, "http:// endpoint blocked"))
    except Exception as exc:
        checks.append(("http_endpoint_rejected", False, f"unexpected error type: {type(exc).__name__}"))

    sig = inspect.signature(SplunkClient.__init__)
    default_verify = sig.parameters["verify_ssl"].default if "verify_ssl" in sig.parameters else True
    checks.append(("tls_verify_default_true", bool(default_verify) is True, repr(default_verify)))
    try:
        SplunkClient("https://example.invalid:8089", username="x", password="y", verify_ssl=False)
        checks.append(("tls_disable_allowed", True, "verify_ssl=False accepted"))
    except PolicyViolation:
        checks.append(("tls_disable_allowed", False, "verify_ssl=False blocked by policy"))
    except Exception as exc:
        checks.append(("tls_disable_allowed", True, f"verify_ssl=False allowed ({type(exc).__name__})"))

    try:
        resolve_secret_candidates(exe_dir, secret_file="..\\secret.dpapi")
        checks.append(("secret_file_validation", False, "path traversal accepted"))
    except Exception:
        checks.append(("secret_file_validation", True, "rejected invalid name"))
    try:
        resolve_secret_candidates(exe_dir, secret_file="secret.dpapi:stream")
        checks.append(("secret_file_ads_blocked", False, "ADS accepted"))
    except Exception:
        checks.append(("secret_file_ads_blocked", True, "ADS rejected"))

    old_programdata = os.environ.get("PROGRAMDATA")
    os.environ["PROGRAMDATA"] = r"C:\Users\Public\attacker_override"
    try:
        candidates = resolve_secret_candidates(exe_dir, secret_file="secret.dpapi")
        joined = ";".join(candidates)
        checks.append(("programdata_root_fixed", FIXED_PROGRAMDATA_ROOT in joined, joined))
        checks.append(("programdata_env_ignored", "attacker_override" not in joined.lower(), joined))
    finally:
        if old_programdata is None:
            os.environ.pop("PROGRAMDATA", None)
        else:
            os.environ["PROGRAMDATA"] = old_programdata

    try:
        from Internal.dpapi_store import _icacls_path  # type: ignore[attr-defined]
        icacls_exe = _icacls_path()
        checks.append(("icacls_absolute_system32", os.path.isabs(icacls_exe) and icacls_exe.lower().endswith("\\system32\\icacls.exe"), icacls_exe))
    except Exception as exc:
        checks.append(("icacls_absolute_system32", False, str(exc)))

    sample_ui = r"Sending email to alice@example.com from C:\Sensitive\file.txt"
    redacted_ui = redact_text(sample_ui)
    checks.append(("ui_email_path_visible", ("alice@" in redacted_ui.lower()) and ("c:\\" in redacted_ui.lower()), redacted_ui))

    sample_secret = "Authorization: Bearer abcdef1234567890"
    redacted_secret = redact_text(sample_secret)
    checks.append(("ui_secret_redaction_auth", "Bearer " not in redacted_secret and "[REDACTED]" in redacted_secret, redacted_secret))

    try:
        from auth_manager import get_splunk_token
        get_splunk_token()
        checks.append(("legacy_auth_helpers_removed", False, "legacy token helper still callable"))
    except Exception:
        checks.append(("legacy_auth_helpers_removed", True, "legacy token helper blocked"))

    stronger = {
        "build_mode": "production",
        "policy_mode": "enforced",
        "allow_insecure_overrides": False,
        "env_overrides_allowed": False,
        "legacy_features_enabled": False,
        "audit_min_retention_ok": True,
    }
    weaker = dict(stronger)
    weaker["policy_mode"] = "permissive"
    checks.append(("baseline_weaker_detected", is_weaker_fingerprint(stronger, weaker), "policy_mode downgrade"))

    broker_handle = start_local_logging_broker(
        exe_dir=exe_dir,
        tool_version="v4",
        allow_local_appdata=(not policy.is_production) and policy.insecure_overrides_active,
    )
    try:
        checks.append(
            (
                "broker_bind_loopback_only",
                broker_handle.bind_host == BROKER_BIND_HOST,
                f"{broker_handle.bind_host}:{broker_handle.bind_port}",
            )
        )
        checks.append(("broker_started", broker_handle.audit_logger.is_available, broker_handle.startup_error or "ok"))

        if broker_handle.audit_logger.is_available:
            no_token_status, _ = broker_handle.selfcheck_post(
                "/v1/log",
                {"event": "TOOL_START", "level": "INFO", "fields": {}},
                token="",
            )
            checks.append(("broker_requires_auth_token", no_token_status == 401, f"http_{no_token_status}"))

            unknown_status, _ = broker_handle.selfcheck_post(
                "/v1/log",
                {"event": "BROKER_UNKNOWN_EVENT_TEST", "level": "INFO", "fields": {}},
            )
            checks.append(("broker_rejects_unknown_event", unknown_status == 400, f"http_{unknown_status}"))

            secret_marker = f"broker_secret_{uuid.uuid4().hex}"
            secret_status, _ = broker_handle.selfcheck_post(
                "/v1/log",
                {
                    "event": "EMAIL_SEND_FAILED",
                    "level": "ERROR",
                    "fields": {
                        "run_id": f"selfcheck-{uuid.uuid4().hex[:12]}",
                        "recipient_count": 1,
                        "reason": f"Authorization: Bearer {secret_marker}",
                    },
                },
            )
            secret_ok = secret_status in (200, 400)
            secret_detail = f"http_{secret_status}"
            if secret_status == 200:
                try:
                    with open(broker_handle.audit_logger.log_path, "r", encoding="utf-8", errors="replace") as f:
                        tail_text = "".join(deque(f, maxlen=120))
                    leaked = (secret_marker in tail_text) or ("authorization: bearer" in tail_text.lower())
                    secret_ok = secret_ok and (not leaked)
                    secret_detail = f"{secret_detail};leaked={leaked}"
                except Exception as exc:
                    secret_ok = False
                    secret_detail = f"tail_read_failed:{exc}"
            checks.append(("broker_secret_field_guard", secret_ok, secret_detail))

            persistent_run_id = f"selfcheck-{uuid.uuid4().hex[:12]}"
            emit_ok = broker_handle.audit_logger.log_event(
                "EMAIL_SEND_FAILED",
                level="WARN",
                run_id=persistent_run_id,
                recipient_count=0,
                reason="selfcheck",
            )
            persistent_ok = bool(emit_ok)
            persistent_detail = broker_handle.audit_logger.log_path or "no_log_path"
            if persistent_ok and os.path.isfile(broker_handle.audit_logger.log_path):
                chain_ok = verify_log_integrity(broker_handle.audit_logger.log_path)
                persistent_ok = persistent_ok and chain_ok
                if chain_ok:
                    try:
                        with open(broker_handle.audit_logger.log_path, "r", encoding="utf-8", errors="replace") as f:
                            tail_text = "".join(deque(f, maxlen=200))
                        marker_found = persistent_run_id in tail_text
                        persistent_ok = persistent_ok and marker_found
                        persistent_detail = f"{persistent_detail};marker_found={marker_found}"
                    except Exception as exc:
                        persistent_ok = False
                        persistent_detail = f"tail_read_failed:{exc}"
                else:
                    persistent_detail = f"{persistent_detail};chain_ok={chain_ok}"
            else:
                persistent_ok = False
                persistent_detail = f"emit_ok={emit_ok};path={persistent_detail}"
            checks.append(("broker_persistent_logging_works", persistent_ok, persistent_detail))
        else:
            checks.append(("broker_requires_auth_token", False, broker_handle.startup_error or "broker_not_available"))
            checks.append(("broker_rejects_unknown_event", False, broker_handle.startup_error or "broker_not_available"))
            checks.append(("broker_secret_field_guard", False, broker_handle.startup_error or "broker_not_available"))
            checks.append(("broker_persistent_logging_works", False, broker_handle.startup_error or "broker_not_available"))
    finally:
        broker_handle.shutdown()

    session_only_logger = BrokerAuditLogger.session_only(startup_error="selfcheck")
    fallback_warning = session_only_logger.unavailable_warning()
    checks.append(
        (
            "broker_gui_fallback_warning",
            fallback_warning == PERSISTENT_AUDIT_UNAVAILABLE_WARNING,
            fallback_warning or "missing_warning",
        )
    )
    try:
        gui_path = os.path.join(exe_dir, "splunk_report_tk.py")
        with open(gui_path, "r", encoding="utf-8", errors="replace") as f:
            gui_source = f.read()
        wired = ("unavailable_warning" in gui_source) and ("PERSISTENT_AUDIT_UNAVAILABLE_WARNING" in gui_source)
        checks.append(("broker_gui_warning_wired", wired, gui_path))
        gui_no_dpapi = ("load_or_enroll_password" not in gui_source) and ("dpapi_unprotect" not in gui_source)
        checks.append(("gui_no_direct_dpapi_decrypt", gui_no_dpapi, gui_path))
        gui_no_direct_splunk_auth = ("SplunkClient(" not in gui_source)
        checks.append(("gui_no_direct_splunk_session_auth", gui_no_direct_splunk_auth, gui_path))
        gui_no_direct_config_load = ("load_config(" not in gui_source)
        checks.append(("gui_no_direct_config_load", gui_no_direct_config_load, gui_path))
        splunk_broker_wired = ("start_local_splunk_broker" in gui_source) and ("SplunkBrokerProxyClient" in gui_source)
        checks.append(("gui_broker_wiring_present", splunk_broker_wired, gui_path))
    except Exception as exc:
        checks.append(("broker_gui_warning_wired", False, str(exc)))
        checks.append(("gui_no_direct_dpapi_decrypt", False, str(exc)))
        checks.append(("gui_no_direct_splunk_session_auth", False, str(exc)))
        checks.append(("gui_no_direct_config_load", False, str(exc)))
        checks.append(("gui_broker_wiring_present", False, str(exc)))

    log_broker = start_local_logging_broker(
        exe_dir=exe_dir,
        tool_version="v4",
        allow_local_appdata=(not policy.is_production) and policy.insecure_overrides_active,
    )
    splunk_broker = None
    try:
        log_url, log_token = log_broker.child_auth_config()
        splunk_broker = start_local_splunk_broker(
            exe_dir=exe_dir,
            logging_broker_url=log_url,
            logging_broker_token=log_token,
        )
        checks.append(
            (
                "splunk_broker_bind_loopback_only",
                splunk_broker.bind_host == SPLUNK_BROKER_BIND_HOST,
                f"{splunk_broker.bind_host}:{splunk_broker.bind_port}",
            )
        )
        checks.append(
            (
                "splunk_broker_started",
                splunk_broker.is_available,
                splunk_broker.startup_error or "ok",
            )
        )
        if splunk_broker.is_available:
            no_token_status, _ = splunk_broker.selfcheck_post({"op": "health", "args": {}}, token="")
            checks.append(("splunk_broker_requires_auth_token", no_token_status == 401, f"http_{no_token_status}"))

            unknown_status, _ = splunk_broker.selfcheck_post({"op": "not_real_operation", "args": {}})
            checks.append(("splunk_broker_rejects_unknown_operation", unknown_status == 400, f"http_{unknown_status}"))

            malformed_status, _ = splunk_broker.selfcheck_post({"op": "health", "args": []})
            checks.append(("splunk_broker_rejects_malformed_payload", malformed_status == 400, f"http_{malformed_status}"))

            health_status, health_payload = splunk_broker.selfcheck_post({"op": "health", "args": {}})
            health_blob = json.dumps(health_payload, sort_keys=True).lower()
            no_session_exposed = (
                (health_status == 200)
                and ("sessionkey" not in health_blob)
                and ("authorization" not in health_blob)
                and ("cookie" not in health_blob)
            )
            checks.append(("splunk_broker_session_not_exposed", no_session_exposed, f"http_{health_status}"))

            config_status, config_payload = splunk_broker.selfcheck_post({"op": "get_runtime_config", "args": {}})
            core_routing = config_status in (200, 503)
            checks.append(("splunk_broker_core_path_wired", core_routing, f"http_{config_status}"))
        else:
            checks.append(("splunk_broker_requires_auth_token", False, splunk_broker.startup_error or "broker_not_available"))
            checks.append(("splunk_broker_rejects_unknown_operation", False, splunk_broker.startup_error or "broker_not_available"))
            checks.append(("splunk_broker_rejects_malformed_payload", False, splunk_broker.startup_error or "broker_not_available"))
            checks.append(("splunk_broker_session_not_exposed", False, splunk_broker.startup_error or "broker_not_available"))
            checks.append(("splunk_broker_core_path_wired", False, SPLUNK_BROKER_UNAVAILABLE_WARNING))
    finally:
        try:
            if splunk_broker is not None:
                splunk_broker.shutdown()
        except Exception:
            pass
        log_broker.shutdown()

    audit_path = os.path.join(exe_dir, "Internal", "logs", "audit.jsonl")
    if os.path.isfile(audit_path):
        checks.append(("audit_chain_valid", verify_log_integrity(audit_path), audit_path))
    else:
        checks.append(("audit_chain_valid", False, "audit.jsonl missing"))

    failed = [item for item in checks if not item[1]]
    for name, ok, detail in checks:
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {name}: {detail}")
    if failed:
        return 1
    return 0


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]

    if argv and argv[0] in ("-h", "--help"):
        _print_usage()
        return 0

    if argv and argv[0] == "--set-token":
        return _run_legacy_feature_blocked("--set-token")

    if argv and argv[0] == "--test-auth":
        return _run_legacy_feature_blocked("--test-auth")

    if argv and argv[0] == "--security-selfcheck":
        return _run_security_selfcheck()

    if argv and argv[0] == "--run-splunk-broker":
        return _run_splunk_broker(argv[1:])

    # Import and run the Tk GUI. Import is deferred so importing this module
    # doesn't require tkinter to be present immediately.
    try:
        from splunk_report_tk import main as tk_main
    except Exception as e:
        print(f"Failed to start Tk GUI: {e}")
        return 1

    tk_main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

