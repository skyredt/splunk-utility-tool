from __future__ import annotations

import importlib
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import quote, unquote, urlparse

import getpass
import socket
import smtplib
from email.message import EmailMessage

# Optional Qt signals support; dynamic import keeps Tk builds from pulling Qt.
try:
    QtCore = importlib.import_module("PySide6.QtCore")
    QObject = QtCore.QObject
    Signal = QtCore.Signal
except Exception:  # PySide6 may not be installed for Tk-only usage
    class QObject:  # minimal fallback
        pass

    class Signal:  # minimal fallback that provides an emit() method
        def __init__(self, *args, **kwargs):
            pass

        def emit(self, *args, **kwargs):
            return None

# Try to import zoneinfo for proper SGT timezone handling (Python 3.9+)
try:
    from zoneinfo import ZoneInfo
    HAS_ZONEINFO = True
except ImportError:
    HAS_ZONEINFO = False

import requests
from Internal.config_manager import load_and_validate_config
from Internal.security_policy import PolicyViolation, SecurityPolicy, load_security_policy, redact_text


VALID_AUTH_MODES = ("password",)
TOOL_DISPLAY_NAME = "Splunk Utility Tool v4"
DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS = 30
DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS = 30
DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT = True
DEFAULT_DISPATCH_TIMEOUT_RESULT = "pending"
DEFAULT_MERGEREPORT_TIMEOUT_SECONDS = 300
DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS = 300
DEFAULT_POSTDISPATCH_POLL_SECONDS = 5
DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS = 900
DEFAULT_POSTDISPATCH_ENABLED = True
DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS = DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS
DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS = 300
DEFAULT_RECONCILE_PENDING_ENABLED = True
DEFAULT_RECONCILE_WAIT_SECONDS = 60
FAILED_DISPATCH_STATES = {"FAILED", "ERROR", "CANCELED", "CANCELLED"}


_SECURITY_AUDIT_LOGGER = None
_SECURITY_POLICY: Optional[SecurityPolicy] = None


def set_security_audit_logger(audit_logger) -> None:
    global _SECURITY_AUDIT_LOGGER
    _SECURITY_AUDIT_LOGGER = audit_logger


def set_security_policy(policy: Optional[SecurityPolicy]) -> None:
    global _SECURITY_POLICY
    _SECURITY_POLICY = policy


def _audit_event(event: str, level: str = "INFO", **fields) -> None:
    logger = _SECURITY_AUDIT_LOGGER
    if logger is None or not hasattr(logger, "log_event"):
        return
    logger.log_event(event, level=level, **fields)


def _active_policy() -> Optional[SecurityPolicy]:
    return _SECURITY_POLICY


def _env_override_allowed() -> bool:
    policy = _active_policy()
    if policy is None:
        return False
    return policy.env_overrides_allowed()


def _audit_blocked_env_override(*names: str) -> None:
    if _env_override_allowed():
        return
    for name in names:
        raw = os.getenv(name, "")
        if raw and raw.strip():
            _audit_event(
                "POLICY_VIOLATION_BLOCKED",
                level="WARN",
                control="ENV_OVERRIDE_BLOCKED",
                setting=name,
            )


@dataclass
class SplunkConfig:
    servers: List[str]
    username: str
    password: str
    secret_file: str = "secret.dpapi"
    dpapi_scope: str = "machine"
    auth_mode: str = "password"
    verify_ssl: bool = True
    config_path: str = "config.ini"
    logging_level: str = "INFO"
    logging_verbose: bool = False
    logging_max_bytes: int = 10_485_760
    logging_backup_count: int = 10
    legacy_password_present: bool = False
    merge_report_enabled: bool = False
    merge_report_log_path: str = ""
    merge_report_timeout_seconds: int = DEFAULT_MERGEREPORT_TIMEOUT_SECONDS
    dispatch_config: Optional[dict] = None
    # Manual regeneration acknowledgement settings
    ack_enabled: bool = True
    ack_on_pending: bool = False
    ack_on_unknown: bool = False
    ack_recipients: List[str] = field(default_factory=list)
    ack_use_savedsearch_recipients: bool = False
    ack_attach_manifest: bool = False
    # SMTP settings for ACK email
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_use_tls: bool = False
    smtp_from: str = "Splunk Notification <splunk-donotreply@localhost>"
    # Post-dispatch verification settings (Phase 2)
    postdispatch_config: Optional[dict] = None
    # Plain-text logging settings propagated to the UI runtime payload
    file_logging_config: Optional[dict] = None
    runtime_config: Optional[dict] = None

    def load_auth_token(self) -> str:
        raise PolicyViolation(
            "LEGACY_FEATURE_DISABLED",
            "Token authentication is not supported in v4 production build.",
        )

    def save_auth_token(self, token: str) -> None:
        raise PolicyViolation(
            "LEGACY_FEATURE_DISABLED",
            "Token storage is not supported in v4 production build.",
        )

    @property
    def uses_token_auth(self) -> bool:
        return False


def get_sgt_now() -> datetime:
    """Get current time in Singapore timezone (SGT, UTC+8).
    
    Prefers zoneinfo (Python 3.9+), falls back to fixed +08:00 offset.
    """
    if HAS_ZONEINFO:
        try:
            return datetime.now(ZoneInfo("Asia/Singapore"))
        except Exception:
            # Timezone lookup failed; fall through to fixed offset
            pass
    
    # Fallback: UTC+8 fixed offset (no DST in Singapore)
    return datetime.now(timezone(timedelta(hours=8)))


def format_sgt(dt: datetime) -> str:
    """Return a consistent Singapore-time timestamp label."""
    return dt.strftime("%Y-%m-%d %H:%M:%S") + " SGT"


def _parse_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _parse_int(value: object, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _parse_min_int(value: object, default: int, minimum: int) -> int:
    return max(minimum, _parse_int(value, default))


def _parse_recipients(raw: str) -> List[str]:
    if not raw:
        return []
    return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]


def _dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _normalize_timeout_result(value: object) -> str:
    raw = str(value or "").strip().lower()
    if raw == "unknown":
        return "UNKNOWN"
    return "PENDING"


def _is_pending_status(value: object) -> bool:
    return str(value or "").strip().upper() in ("PENDING", "UNKNOWN")


def _display_slice_status(value: object) -> str:
    status = str(value or "").strip().upper()
    if status == "UNKNOWN":
        return "PENDING"
    return status or "UNKNOWN"


def get_effective_username() -> str:
    """Resolve operator username safely on Windows and non-interactive sessions."""
    try:
        user = getpass.getuser()
        if user and user.strip():
            return user.strip()
    except Exception:
        pass

    for key in ("USERNAME", "USER", "LOGNAME"):
        value = os.getenv(key, "").strip()
        if value:
            return value
    return "unknown-user"


def validate_token_for_server(server_url: str, token: str, verify_ssl: bool = True) -> Tuple[bool, str]:
    _ = (server_url, token, verify_ssl)
    return False, "Token authentication is not supported in v4 production build."


@dataclass
class RegenSliceRecord:
    """Record of a single slice dispatch outcome."""
    report_name: str
    slice_label: str
    slice_index: int = 0
    slice_total: int = 0
    earliest: str = ""
    latest: str = ""
    sid: str = ""
    status: str = "UNKNOWN"  # OK, FAILED, PENDING/UNKNOWN
    outcome_code: str = "DISPATCHED_PENDING"
    error: str = ""


@dataclass
class RegenContext:
    """Context for a manual regeneration run."""
    run_id: str
    report_names: List[str]  # selected report names
    app: str  # app name
    operator: str  # username running the tool
    hostname: str  # hostname where tool is running
    tool_name: str = TOOL_DISPLAY_NAME
    
    # Timing (SGT)
    start_time_sgt: Optional[datetime] = None
    end_time_sgt: Optional[datetime] = None
    
    # Slicing config
    slicing_enabled: bool = False
    slice_count: int = 0
    frequency: str = ""  # Daily, Weekly, Monthly
    earliest_configured: str = ""  # earliest date configured
    latest_configured: str = ""  # latest date configured
    mode_description: str = "single run"

    # Recipients and outcome
    savedsearch_recipients: List[str] = field(default_factory=list)
    slices: List[RegenSliceRecord] = field(default_factory=list)
    ack_attach_manifest: bool = False

    def add_slice(
        self,
        report_name: str,
        slice_label: str,
        slice_index: int = 0,
        slice_total: int = 0,
        earliest: str = "",
        latest: str = "",
        sid: str = "",
        status: str = "UNKNOWN",
        outcome_code: str = "DISPATCHED_PENDING",
        error: str = "",
    ) -> None:
        self.slices.append(
            RegenSliceRecord(
                report_name=report_name,
                slice_label=slice_label,
                slice_index=max(0, int(slice_index or 0)),
                slice_total=max(0, int(slice_total or 0)),
                earliest=earliest,
                latest=latest,
                sid=sid,
                status=(str(status or "").strip().upper() or "UNKNOWN"),
                outcome_code=outcome_code,
                error=error,
            )
        )

    def summary_counts(self) -> Tuple[int, int, int]:
        ok_count = sum(1 for s in self.slices if s.status == "OK")
        fail_count = sum(1 for s in self.slices if s.status == "FAILED")
        pending_count = sum(1 for s in self.slices if _is_pending_status(s.status))
        return ok_count, fail_count, pending_count

    def overall_status(self) -> str:
        ok_count, fail_count, pending_count = self.summary_counts()
        total = len(self.slices)
        if pending_count > 0:
            if ok_count > 0 or fail_count > 0:
                return "PARTIAL / PENDING VERIFICATION"
            return "PENDING VERIFICATION"
        if fail_count > 0:
            return "FAILED"
        if total == 0:
            return "UNKNOWN"
        return "OK"


def load_config(
    path: Optional[str] = None,
    *,
    exe_dir: Optional[str] = None,
    policy: Optional[SecurityPolicy] = None,
) -> SplunkConfig:
    requested_path = (path or "").strip() or None
    if requested_path and requested_path.lower() == "config.ini":
        requested_path = None
    if policy is not None and requested_path and (not policy.config_in_exe_dir(requested_path)):
        raise PolicyViolation(
            "CONFIG_PATH_BINDING",
            f"config.ini must be loaded from exe_dir only: {policy.config_path}",
        )
    active_policy = policy or load_security_policy(exe_dir=exe_dir, requested_config_path=requested_path)
    set_security_policy(active_policy)
    config_root = getattr(active_policy, "exe_dir", "") or os.path.dirname(str(active_policy.config_path))
    loaded = load_and_validate_config(exe_dir=config_root)
    for change in loaded.changes:
        logging.getLogger(__name__).info(change)
    cfg = loaded.parser

    if "splunk" not in cfg:
        raise KeyError("Missing [splunk] section in config.ini")

    splunk_section = cfg["splunk"]
    servers_raw = splunk_section.get("servers", "").strip()
    host_raw = splunk_section.get("host", "").strip()
    servers = [s.strip() for s in servers_raw.split(";") if s.strip()]
    if not servers and host_raw:
        servers = [host_raw]
    if not servers:
        raise ValueError("No servers defined in [splunk].servers (or [splunk].host)")
    servers = [active_policy.enforce_https_url(server) for server in servers]

    credentials_section = cfg["Credentials"] if "Credentials" in cfg else cfg["credentials"] if "credentials" in cfg else None
    username = splunk_section.get("username", "").strip()
    if credentials_section is not None:
        username = credentials_section.get("username", username).strip()

    legacy_password = splunk_section.get("password", "")
    legacy_password_present = bool(str(legacy_password or "").strip())
    if legacy_password_present:
        logging.getLogger(__name__).warning(
            "Legacy [splunk].password was found and ignored; DPAPI secret file is used instead."
        )
    password = ""

    secret_file = "secret.dpapi"
    dpapi_scope = "machine"
    if credentials_section is not None:
        secret_file = credentials_section.get("secret_file", secret_file).strip() or secret_file
    secret_file = active_policy.validate_secret_filename(secret_file)
    if credentials_section is not None:
        dpapi_scope = credentials_section.get("dpapi_scope", dpapi_scope).strip().lower() or dpapi_scope
    if dpapi_scope != "machine":
        raise PolicyViolation(
            "DPAPI_SCOPE",
            f"Unsupported dpapi_scope={dpapi_scope!r}; only 'machine' is permitted.",
        )

    auth_mode = splunk_section.get("auth_mode", "password").strip().lower() or "password"
    if auth_mode not in VALID_AUTH_MODES:
        raise PolicyViolation(
            "LEGACY_FEATURE_DISABLED",
            "Only auth_mode=password is supported in v4 production build.",
        )
    if auth_mode != "password":
        raise PolicyViolation(
            "LEGACY_FEATURE_DISABLED",
            "Token authentication is not supported in v4 production build.",
        )

    legacy_fields = {
        "token_storage": splunk_section.get("token_storage", "").strip(),
        "token": splunk_section.get("token", "").strip(),
        "token_ini": splunk_section.get("token_ini", "").strip(),
        "token_encrypted": splunk_section.get("token_encrypted", "").strip(),
        "splunk_cli_path": splunk_section.get("splunk_cli_path", "").strip(),
    }
    if any(value for value in legacy_fields.values()):
        raise PolicyViolation(
            "LEGACY_FEATURE_DISABLED",
            "Legacy token/CLI settings are not supported in v4 production build.",
        )

    if auth_mode == "password" and not username:
        raise ValueError("username not set in [Credentials] (or [splunk]) for auth_mode=password")
    verify_ssl = _parse_bool(splunk_section.get("verify_ssl", "true"), True)

    # Security/audit logging config
    logging_level = "INFO"
    logging_verbose = False
    logging_max_bytes = 10_485_760
    logging_backup_count = 10
    logging_section = None
    file_logging_config = {}
    if "Logging" in cfg or "logging" in cfg:
        logging_section = cfg["Logging"] if "Logging" in cfg else cfg["logging"]
        logging_level = (logging_section.get("level", logging_level) or logging_level).strip().upper()
        if logging_level not in ("DEBUG", "INFO", "WARN", "ERROR"):
            logging_level = "INFO"
        logging_verbose = _parse_bool(logging_section.get("verbose", str(int(logging_verbose))), logging_verbose)
        logging_max_bytes = _parse_int(logging_section.get("max_bytes", str(logging_max_bytes)), logging_max_bytes)
        logging_backup_count = _parse_int(logging_section.get("backup_count", str(logging_backup_count)), logging_backup_count)
        if "runtime_log_enabled" in logging_section:
            file_logging_config["runtime_log_enabled"] = _parse_bool(
                logging_section.get("runtime_log_enabled", "1"),
                True,
            )
        if "runtime_log_level" in logging_section:
            file_logging_config["runtime_log_level"] = (
                logging_section.get("runtime_log_level", "INFO") or "INFO"
            ).strip().upper()
        if "runtime_log_path" in logging_section:
            file_logging_config["runtime_log_path"] = logging_section.get("runtime_log_path", "").strip()
        if "debug_log_enabled" in logging_section:
            file_logging_config["debug_log_enabled"] = _parse_bool(
                logging_section.get("debug_log_enabled", "0"),
                False,
            )
        if "debug_log_level" in logging_section:
            file_logging_config["debug_log_level"] = (
                logging_section.get("debug_log_level", "DEBUG") or "DEBUG"
            ).strip().upper()
        if "debug_log_path" in logging_section:
            file_logging_config["debug_log_path"] = logging_section.get("debug_log_path", "").strip()
        if "debug_broker_enabled" in logging_section:
            file_logging_config["debug_broker_enabled"] = _parse_bool(
                logging_section.get("debug_broker_enabled", "0"),
                False,
            )
        if "debug_rest_enabled" in logging_section:
            file_logging_config["debug_rest_enabled"] = _parse_bool(
                logging_section.get("debug_rest_enabled", "0"),
                False,
            )
        if "debug_dispatch_enabled" in logging_section:
            file_logging_config["debug_dispatch_enabled"] = _parse_bool(
                logging_section.get("debug_dispatch_enabled", "0"),
                False,
            )
        if "debug_tracebacks_enabled" in logging_section:
            file_logging_config["debug_tracebacks_enabled"] = _parse_bool(
                logging_section.get("debug_tracebacks_enabled", "0"),
                False,
            )
    logging_level, logging_max_bytes, logging_backup_count = active_policy.enforce_audit_settings(
        logging_level,
        logging_max_bytes,
        logging_backup_count,
    )
    if not file_logging_config:
        file_logging_config = None

    runtime_config = {}
    if "runtime" in cfg or "Runtime" in cfg:
        runtime_section = cfg["runtime"] if "runtime" in cfg else cfg["Runtime"]
        if "test_mode" in runtime_section:
            runtime_config["test_mode"] = _parse_bool(
                runtime_section.get("test_mode", "0"),
                False,
            )
    if not runtime_config:
        runtime_config = None

    # MergeReport config (canonical: [postdispatch], legacy: [mergereport])
    merge_report_enabled = False
    merge_report_log_path = ""
    merge_report_timeout_seconds = DEFAULT_MERGEREPORT_TIMEOUT_SECONDS

    postdispatch_section = cfg["postdispatch"] if "postdispatch" in cfg else None
    legacy_mergereport_section = cfg["mergereport"] if "mergereport" in cfg else None
    postdispatch_has_merge_report = False
    if postdispatch_section:
        postdispatch_has_merge_report = any(
            cfg.has_option("postdispatch", key)
            for key in ("merge_report_enabled", "merge_report_log_path", "merge_report_timeout_seconds")
        )

    if postdispatch_section and postdispatch_has_merge_report:
        merge_report_enabled = _parse_bool(
            postdispatch_section.get("merge_report_enabled", "true"),
            True,
        )
        merge_report_log_path = postdispatch_section.get("merge_report_log_path", "").strip()
        merge_report_timeout_seconds = _parse_min_int(
            postdispatch_section.get(
                "merge_report_timeout_seconds",
                str(DEFAULT_MERGEREPORT_TIMEOUT_SECONDS),
            ),
            DEFAULT_MERGEREPORT_TIMEOUT_SECONDS,
            1,
        )
        if legacy_mergereport_section is not None:
            logging.getLogger(__name__).warning(
                "Config section [mergereport] is legacy and ignored; use [postdispatch] merge_report_* keys."
            )
    elif legacy_mergereport_section is not None:
        enabled_str = legacy_mergereport_section.get("enabled", "false").lower()
        merge_report_enabled = enabled_str in ("true", "1", "yes")
        merge_report_log_path = legacy_mergereport_section.get("log_path", "").strip()
        merge_report_timeout_seconds = _parse_min_int(
            legacy_mergereport_section.get(
                "timeout_seconds",
                str(DEFAULT_MERGEREPORT_TIMEOUT_SECONDS),
            ),
            DEFAULT_MERGEREPORT_TIMEOUT_SECONDS,
            1,
        )
        logging.getLogger(__name__).warning(
            "Config section [mergereport] is legacy; mapping to [postdispatch] merge_report_* settings."
        )

    # Validate MergeReport config if enabled
    merge_report_log_path_validated = ""
    if merge_report_enabled:
        if not merge_report_log_path:
            # Enabled but path not set; treat as disabled
            merge_report_enabled = False
        elif not os.path.isabs(merge_report_log_path):
            # Path is not absolute
            raise ValueError(
                f"MergeReport log_path must be absolute, got: {merge_report_log_path}"
            )
        else:
            merge_report_log_path_validated = merge_report_log_path

    dispatch_config = {}
    if "dispatch" in cfg:
        section = cfg["dispatch"]
        dispatch_config = {
            "per_slice_wait_seconds": _parse_min_int(
                section.get(
                    "per_slice_wait_seconds",
                    str(DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS),
                ),
                DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS,
                1,
            ),
            "continue_on_timeout": _parse_bool(
                section.get(
                    "continue_on_timeout",
                    str(int(DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT)),
                ),
                DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT,
            ),
            "timeout_result": _normalize_timeout_result(
                section.get("timeout_result", DEFAULT_DISPATCH_TIMEOUT_RESULT)
            ).lower(),
            "dispatch_call_timeout_seconds": _parse_min_int(
                section.get(
                    "dispatch_call_timeout_seconds",
                    str(DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS),
                ),
                DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS,
                1,
            ),
        }

    # Manual ACK + SMTP defaults
    ack_enabled = True
    ack_on_pending = False
    ack_on_unknown = False
    ack_recipients: List[str] = []
    ack_use_savedsearch_recipients = False
    ack_attach_manifest = False
    smtp_host = "127.0.0.1"
    smtp_port = 25
    smtp_user = ""
    smtp_pass = ""
    smtp_use_tls = False
    smtp_from = "Splunk Notification <splunk-donotreply@localhost>"

    # Legacy [smtp] section compatibility
    if "smtp" in cfg:
        section = cfg["smtp"]
        ack_enabled = _parse_bool(
            section.get("enabled", str(int(ack_enabled))),
            ack_enabled,
        )
        smtp_host = section.get("host", "127.0.0.1").strip() or smtp_host
        smtp_port = _parse_int(section.get("port", "25"), 25)
        smtp_user = section.get("username", "").strip()
        smtp_pass = section.get("password", "").strip()
        smtp_use_tls = _parse_bool(section.get("use_tls", "false"), False)
        smtp_from = (
            section.get("from_address", "Splunk Notification <splunk-donotreply@localhost>").strip()
            or smtp_from
        )

    # Preferred [email] section
    if "email" in cfg:
        section = cfg["email"]
        ack_enabled = _parse_bool(section.get("ack_enabled", str(int(ack_enabled))), ack_enabled)
        ack_on_pending = _parse_bool(
            section.get("ack_on_pending", section.get("ack_on_unknown", "0")),
            False,
        )
        ack_on_unknown = ack_on_pending
        ack_recipients = _parse_recipients(section.get("ack_recipients", ""))
        ack_use_savedsearch_recipients = _parse_bool(
            section.get("ack_use_savedsearch_recipients", "0"), False
        )
        ack_attach_manifest = _parse_bool(section.get("ack_attach_manifest", "0"), False)
        smtp_host = section.get("smtp_host", smtp_host).strip() or smtp_host
        smtp_port = _parse_int(section.get("smtp_port", str(smtp_port)), smtp_port)
        smtp_use_tls = _parse_bool(
            section.get("smtp_tls", section.get("use_tls", str(int(smtp_use_tls)))),
            smtp_use_tls,
        )
        smtp_user = section.get("smtp_user", smtp_user).strip()
        smtp_pass = section.get("smtp_pass", smtp_pass).strip()
        smtp_from = (
            section.get("from_addr", section.get("from_address", smtp_from)).strip()
            or smtp_from
        )

    # Post-dispatch verification config (Phase 2: REST search-based)
    postdispatch_config = {}
    if "postdispatch" in cfg:
        section = cfg["postdispatch"]
        postdispatch_config = {
            "enabled": _parse_bool(
                section.get("enabled", str(int(DEFAULT_POSTDISPATCH_ENABLED))),
                DEFAULT_POSTDISPATCH_ENABLED,
            ),
            "merge_report_enabled": section.get("merge_report_enabled", "true").lower() in ("true", "1", "yes"),
            "merge_report_log_path": section.get("merge_report_log_path", "").strip(),
            "merge_report_index": section.get("merge_report_index", "_internal"),
            "merge_report_source_contains": section.get("merge_report_source_contains", "mergeReport_alert.log"),
            "merge_report_sourcetype": section.get("merge_report_sourcetype", "").strip(),
            "merge_report_timeout_seconds": _parse_min_int(
                section.get(
                    "merge_report_timeout_seconds",
                    str(DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS),
                ),
                DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS,
                1,
            ),
            "native_email_enabled": section.get("native_email_enabled", "true").lower() in ("true", "1", "yes"),
            "native_email_index": section.get("native_email_index", "_internal"),
            "native_email_source_contains": section.get("native_email_source_contains", "python.log"),
            "native_email_sourcetype": section.get("native_email_sourcetype", "").strip(),
            "native_email_timeout_seconds": _parse_min_int(
                section.get(
                    "native_email_timeout_seconds",
                    str(DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS),
                ),
                DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS,
                1,
            ),
            "native_email_strict_success": section.get("native_email_strict_success", "false").lower() in ("true", "1", "yes"),
            "poll_seconds": _parse_min_int(
                section.get("poll_seconds", str(DEFAULT_POSTDISPATCH_POLL_SECONDS)),
                DEFAULT_POSTDISPATCH_POLL_SECONDS,
                1,
            ),
            "reconcile_pending": _parse_bool(
                section.get(
                    "reconcile_pending",
                    str(int(DEFAULT_RECONCILE_PENDING_ENABLED)),
                ),
                DEFAULT_RECONCILE_PENDING_ENABLED,
            ),
            "reconcile_wait_seconds": _parse_min_int(
                section.get(
                    "reconcile_wait_seconds",
                    str(DEFAULT_RECONCILE_WAIT_SECONDS),
                ),
                DEFAULT_RECONCILE_WAIT_SECONDS,
                1,
            ),
            "lookback_seconds": _parse_min_int(
                section.get("lookback_seconds", str(DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS)),
                DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS,
                1,
            ),
            "broker_request_timeout_seconds": _parse_min_int(
                section.get(
                    "broker_request_timeout_seconds",
                    str(DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS),
                ),
                DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS,
                1,
            ),
            "status_check_timeout_seconds": _parse_min_int(
                section.get(
                    "status_check_timeout_seconds",
                    str(DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS),
                ),
                DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS,
                1,
            ),
        }

    return SplunkConfig(
        servers=servers,
        username=username,
        password=password,
        secret_file=secret_file,
        dpapi_scope=dpapi_scope,
        auth_mode=auth_mode,
        verify_ssl=verify_ssl,
        config_path=active_policy.config_path,
        logging_level=logging_level,
        logging_verbose=logging_verbose,
        logging_max_bytes=logging_max_bytes,
        logging_backup_count=logging_backup_count,
        legacy_password_present=legacy_password_present,
        merge_report_enabled=merge_report_enabled,
        merge_report_log_path=merge_report_log_path_validated,
        merge_report_timeout_seconds=merge_report_timeout_seconds,
        dispatch_config=dispatch_config if dispatch_config else None,
        ack_enabled=ack_enabled,
        ack_on_pending=ack_on_pending,
        ack_on_unknown=ack_on_unknown,
        ack_recipients=ack_recipients,
        ack_use_savedsearch_recipients=ack_use_savedsearch_recipients,
        ack_attach_manifest=ack_attach_manifest,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_pass=smtp_pass,
        smtp_use_tls=smtp_use_tls,
        smtp_from=smtp_from,
        postdispatch_config=postdispatch_config if postdispatch_config else None,
        file_logging_config=file_logging_config,
        runtime_config=runtime_config,
    )


class SplunkClient(QObject):
    finished = Signal()
    error = Signal(str)
    apps_loaded = Signal(list)
    searches_loaded = Signal(list, list)
    dispatch_log = Signal(list)

    def __init__(
        self,
        base_url: str,
        username: str = "",
        password: str = "",
        verify_ssl: bool = True,
    ):
        super().__init__()
        self.base_url = base_url.rstrip("/")
        parsed_url = urlparse(self.base_url)
        if parsed_url.scheme.lower() != "https":
            raise PolicyViolation(
                "ENDPOINT_HTTPS_REQUIRED",
                f"Only https:// endpoints are allowed: {self.base_url!r}",
            )
        self.username = (username or "").strip()
        self.auth_mode = "password"
        self.verify_ssl = bool(verify_ssl)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self.session.headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )
        self._auth_header = f"Splunk {self._login_with_password(self.username, password)}"
        self._last_snapshot_meta: dict[str, Any] = {}

    def _login_with_password(self, username: str, password: str) -> str:
        if not username or not password:
            raise ValueError("username/password are required for auth_mode=password")

        try:
            resp = self.session.post(
                self.base_url + "/services/auth/login",
                data={
                    "output_mode": "json",
                    "username": username,
                    "password": password,
                },
                timeout=60,
            )
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(
                "TLS error while connecting to Splunk management port. "
                "Certificate verification settings are unchanged from current behavior."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Network error while logging in to Splunk: {redact_text(str(exc))}") from exc

        if resp.status_code in (401, 403):
            raise RuntimeError(
                "Authentication failed (401/403) for username/password mode."
            )
        if resp.status_code >= 400:
            raise RuntimeError(f"Splunk login failed with HTTP {resp.status_code}.")

        session_key = ""
        try:
            payload = resp.json()
            session_key = str(payload.get("sessionKey", "")).strip()
            if not session_key:
                entry = payload.get("entry", [])
                if entry and isinstance(entry, list):
                    content = entry[0].get("content", {})
                    session_key = str(content.get("sessionKey", "")).strip()
        except Exception:
            session_key = ""

        if not session_key:
            body = resp.text or ""
            start = body.find("<sessionKey>")
            end = body.find("</sessionKey>")
            if start >= 0 and end > start:
                session_key = body[start + len("<sessionKey>") : end].strip()

        if not session_key:
            raise RuntimeError("Splunk login response did not include a sessionKey.")
        return session_key

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        timeout: int = 60,
    ):
        url = path if path.startswith("http://") or path.startswith("https://") else self.base_url + path
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme.lower() != "https":
            raise PolicyViolation(
                "ENDPOINT_HTTPS_REQUIRED",
                f"Only https:// endpoints are allowed: {url!r}",
            )
        headers = {"Authorization": self._auth_header}
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(
                "TLS error while connecting to Splunk management port. "
                "Certificate verification settings are unchanged from current behavior."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Network error while calling Splunk REST API: {redact_text(str(exc))}") from exc

        if resp.status_code in (401, 403):
            raise RuntimeError(
                "Authentication failed (401/403). Username/password login may be invalid "
                "or this account lacks required permissions."
            )

        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code} returned by Splunk REST API.")
        return resp

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        merged = {"output_mode": "json", "count": 0}
        if params:
            merged.update(params)
        resp = self._request("GET", path, params=merged, timeout=60)
        return resp.json()

    def _post(self, path: str, data: Optional[dict] = None) -> dict:
        merged = {"output_mode": "json"}
        if data:
            merged.update(data)
        resp = self._request("POST", path, data=merged, timeout=60)
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {"_raw": resp.text}

    def validate_auth(self) -> None:
        self._get("/services/server/info", params={"count": 1})

    def fetch_results_csv(self, sid: str) -> Optional[bytes]:
        """Fetch job results as CSV bytes for the given SID."""
        try:
            params = {"output_mode": "csv", "count": 0}
            resp = self._request(
                "GET",
                f"/services/search/jobs/{sid}/results",
                params=params,
                timeout=60,
            )
            return resp.content
        except Exception:
            return None

    def list_apps(self):
        try:
            data = self._get("/services/apps/local")
            apps: List[str] = []
            for entry in data.get("entry", []):
                content = entry.get("content", {})
                if not content.get("visible", False):
                    continue
                name = entry.get("name")
                # Filter similar to original tool
                if name in {
                    "launcher",
                    "splunk_instrumentation",
                    "user-prefs",
                    "gettingstarted",
                }:
                    continue
                apps.append(name)
            apps_sorted = sorted(apps)
            self.apps_loaded.emit(apps_sorted)
            return apps_sorted
        except Exception as e:
            self.error.emit(f"Failed to list apps: {e!r}")
        finally:
            self.finished.emit()

    def list_saved_searches(self, app: str):
        try:
            data = self._get(f"/servicesNS/-/{app}/saved/searches")
            ids: List[str] = []
            names: List[str] = []
            email_flags: List[bool] = []
            for entry in data.get("entry", []):
                acl = entry.get("acl", {})
                if acl.get("app") != app:
                    continue
                ids.append(entry.get("id", ""))
                names.append(entry.get("name", ""))
                # Detect if the saved search has an email action enabled.
                content = entry.get("content", {})
                flag = False
                # Common Splunk saved search structures may include 'action.email'
                # or an 'actions' collection indicating enabled actions.
                ae = content.get("action.email")
                if ae in (1, "1", True, "true", "True"):
                    flag = True
                else:
                    acts = content.get("actions")
                    if isinstance(acts, dict) and acts.get("email"):
                        flag = True
                    elif isinstance(acts, list) and "email" in acts:
                        flag = True

                # MergeReport custom action (often used instead of native email).
                if not flag:
                    merge_action = content.get("action.mergeReport")
                    if merge_action in (1, "1", True, "true", "True"):
                        flag = True
                    elif str(content.get("action.mergeReport.param.To", "")).strip():
                        flag = True
                    else:
                        # Case-insensitive fallback for non-standard key casing.
                        for key, value in content.items():
                            if key.lower() == "action.mergereport.param.to" and str(value).strip():
                                flag = True
                                break
                email_flags.append(flag)
            # Keep existing signal for compatibility (two-arg signature).
            self.searches_loaded.emit(ids, names)
            return ids, names, email_flags
        except Exception as e:
            self.error.emit(f"Failed to list saved searches for app '{app}': {e!r}")
        finally:
            self.finished.emit()

    def dispatch_saved_search(
        self,
        report_id_url: str,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        trigger_actions: bool = True,
    ) -> Tuple[bool, Optional[str], str]:
        """
        Dispatch a saved search.

        Returns (ok, sid, error_message).
        """
        path = urlparse(report_id_url).path  # /servicesNS/.../saved/searches/<name>
        data: dict = {}
        if trigger_actions:
            data["trigger_actions"] = 1
        if earliest is not None:
            data["dispatch.earliest_time"] = earliest
        if latest is not None:
            data["dispatch.latest_time"] = latest
        payload = {"output_mode": "json", **data}
        dispatch_path = path + "/dispatch"
        url = self.base_url + dispatch_path
        connect_timeout_seconds = 10
        read_timeout_seconds = 30
        request_start_time = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        trace_context = getattr(self, "_dispatch_trace_context", {})
        if not isinstance(trace_context, dict):
            trace_context = {}
        request_body_summary = json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        self._last_dispatch_meta = {
            "transport_mode": "oneshot_request",
            "request_start_time": request_start_time,
            "request_body_summary": request_body_summary,
            "connect_timeout_seconds": connect_timeout_seconds,
            "read_timeout_seconds": read_timeout_seconds,
            "rest_endpoint": dispatch_path,
            "rest_method": "POST",
            "correlation_id": str(trace_context.get("correlation_id", "") or ""),
        }
        backend_trace_fields = {
            "run_id": str(trace_context.get("run_id", "") or ""),
            "report_name": str(trace_context.get("report_name", "") or ""),
            "slice_label": str(trace_context.get("slice_label", "") or ""),
            "slice_index": trace_context.get("slice_index"),
            "slice_total": trace_context.get("slice_total"),
            "correlation_id": str(trace_context.get("correlation_id", "") or ""),
            "earliest": str(trace_context.get("earliest", earliest or "") or ""),
            "latest": str(trace_context.get("latest", latest or "") or ""),
            "transport_mode": "oneshot_request",
            "thread_name": threading.current_thread().name,
        }
        rest_start_monotonic = time.monotonic()
        _audit_event(
            "SPLUNK_DISPATCH_REST_START",
            level="INFO",
            **backend_trace_fields,
        )

        oneshot_session = requests.Session()
        oneshot_session.trust_env = False
        resp = None
        try:
            resp = oneshot_session.request(
                method="POST",
                url=url,
                data=payload,
                headers={
                    "Authorization": self._auth_header,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close",
                },
                timeout=(connect_timeout_seconds, read_timeout_seconds),
                verify=self.verify_ssl,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            self._last_dispatch_meta["failure_classification"] = "ssl_error"
            _audit_event(
                "SPLUNK_DISPATCH_REST_EXCEPTION",
                level="WARN",
                **backend_trace_fields,
                elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                exception_type=type(exc).__name__,
                exception_message=_short_error(redact_text(str(exc) or repr(exc))),
            )
            return False, None, f"Request error: {exc!r}"
        except requests.exceptions.RequestException as exc:
            self._last_dispatch_meta["failure_classification"] = "request_exception"
            _audit_event(
                "SPLUNK_DISPATCH_REST_EXCEPTION",
                level="WARN",
                **backend_trace_fields,
                elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                exception_type=type(exc).__name__,
                exception_message=_short_error(redact_text(str(exc) or repr(exc))),
            )
            return False, None, f"Request error: {exc!r}"

        response_headers_elapsed_ms = 0
        try:
            response_headers_elapsed_ms = int(
                max(0.0, float(resp.elapsed.total_seconds())) * 1000
            )
        except Exception:
            response_headers_elapsed_ms = 0
        self._last_dispatch_meta["response_status_code"] = int(resp.status_code)
        self._last_dispatch_meta["response_headers_elapsed_ms"] = response_headers_elapsed_ms
        self._last_dispatch_meta["response_location"] = str(resp.headers.get("Location", "") or "")
        _audit_event(
            "SPLUNK_DISPATCH_REST_RESPONSE",
            level="INFO" if int(resp.status_code) < 400 else "WARN",
            **backend_trace_fields,
            elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
            response_status_code=int(resp.status_code),
        )

        try:
            if resp.status_code in (401, 403):
                self._last_dispatch_meta["failure_classification"] = "auth_error"
                return False, None, "Request error: RuntimeError('Authentication failed (401/403).')"
            if resp.status_code >= 400:
                self._last_dispatch_meta["failure_classification"] = "http_error"
                return False, None, f"Request error: RuntimeError('HTTP {resp.status_code} returned by Splunk REST API.')"

            location = str(resp.headers.get("Location", "") or "").strip()
            if location:
                sid = location.rstrip("/").rsplit("/", 1)[-1].strip()
                if sid:
                    self._last_dispatch_meta["sid_source"] = "location_header"
                    self._last_dispatch_meta["sid"] = sid
                    self._last_dispatch_meta["response_body_read_elapsed_ms"] = 0
                    self._last_dispatch_meta["json_parse_elapsed_ms"] = 0
                    self._last_dispatch_meta["post_sid_return_work_ms"] = 0
                    _audit_event(
                        "SPLUNK_DISPATCH_SID_PARSED",
                        level="INFO",
                        **backend_trace_fields,
                        elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                        sid=sid,
                        sid_source="location_header",
                    )
                    return True, sid, ""

            body_read_start = time.monotonic()
            response_text = str(resp.text or "")
            self._last_dispatch_meta["response_body_read_elapsed_ms"] = int(
                (time.monotonic() - body_read_start) * 1000
            )
            self._last_dispatch_meta["response_body_snippet"] = redact_text(response_text[:500])

            json_parse_start = time.monotonic()
            try:
                response_payload = json.loads(response_text)
            except json.JSONDecodeError:
                self._last_dispatch_meta["json_parse_elapsed_ms"] = int(
                    (time.monotonic() - json_parse_start) * 1000
                )
                self._last_dispatch_meta["failure_classification"] = "non_json_response"
                return False, None, f"Non-JSON response: {response_text[:500]}"
            self._last_dispatch_meta["json_parse_elapsed_ms"] = int(
                (time.monotonic() - json_parse_start) * 1000
            )
            if isinstance(response_payload, dict):
                self._last_dispatch_meta["response_payload"] = dict(response_payload)
            sid = str(response_payload.get("sid", "") or "").strip() if isinstance(response_payload, dict) else ""
            if not sid:
                self._last_dispatch_meta["failure_classification"] = "missing_sid"
                return False, None, f"No sid in dispatch response: {response_payload}"

            self._last_dispatch_meta["sid_source"] = "json_body"
            self._last_dispatch_meta["sid"] = sid
            self._last_dispatch_meta["post_sid_return_work_ms"] = 0
            _audit_event(
                "SPLUNK_DISPATCH_SID_PARSED",
                level="INFO",
                **backend_trace_fields,
                elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                sid=sid,
                sid_source="json_body",
            )
            return True, sid, ""
        finally:
            close_response = getattr(resp, "close", None)
            if callable(close_response):
                close_response()
            close_session = getattr(oneshot_session, "close", None)
            if callable(close_session):
                close_session()

    def get_job_status_snapshot(
        self,
        sid: str,
        request_timeout_seconds: float = 10.0,
        max_total_timeout_seconds: Optional[float] = None,
    ) -> Tuple[str, dict]:
        effective_timeout = max(1.0, float(request_timeout_seconds))
        if max_total_timeout_seconds is not None:
            try:
                effective_timeout = min(effective_timeout, max(1.0, float(max_total_timeout_seconds)))
            except Exception:
                effective_timeout = max(1.0, float(request_timeout_seconds))
        start = time.monotonic()
        resp = self._request(
            "GET",
            f"/services/search/jobs/{sid}",
            params={"output_mode": "json", "count": 0},
            timeout=effective_timeout,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._last_snapshot_meta = {
            "splunk_elapsed_ms": elapsed_ms,
            "request_timeout_seconds": effective_timeout,
        }
        data = resp.json()
        entry = data.get("entry", [{}])[0]
        content = entry.get("content", {})
        if not isinstance(content, dict):
            content = {}

        dispatch_state = str(content.get("dispatchState", "") or "").strip().upper()
        is_done = _parse_bool(content.get("isDone"), False)
        is_failed = _parse_bool(content.get("isFailed"), False)

        if dispatch_state in FAILED_DISPATCH_STATES or is_failed:
            return "FAILED", content
        if is_done:
            return "SUCCESS", content
        return "RUNNING", content

    def check_job_status(
        self, sid: str, wait_seconds: int = 10, poll_interval: int = 2
    ) -> Tuple[str, dict]:
        """
        Check job status for a given sid.

        Returns (state, content) where state is 'SUCCESS', 'FAILED', or 'TIMEOUT'.
        """
        last_content: dict = {}
        deadline = time.monotonic() + max(1, int(wait_seconds))
        poll_seconds = max(1.0, float(poll_interval))

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            request_timeout = min(max(1.0, poll_seconds), max(1.0, remaining))
            state, content = self.get_job_status_snapshot(
                sid,
                request_timeout_seconds=request_timeout,
            )
            last_content = content
            if state in ("SUCCESS", "FAILED"):
                return state, content
            sleep_seconds = min(poll_seconds, max(0.0, deadline - time.monotonic()))
            if sleep_seconds <= 0:
                break
            time.sleep(sleep_seconds)

        return "TIMEOUT", last_content


def build_slices(start: datetime, end: datetime, frequency: str):
    starts: List[datetime] = []
    ends: List[datetime] = []

    pointer = start

    if end <= start:
        return starts, ends

    while pointer < end:
        starts.append(pointer)

        if frequency == "Monthly":
            year = pointer.year + (pointer.month // 12)
            month = pointer.month % 12 + 1
            next_pointer = datetime(year, month, 1)
            if (end - pointer).days < 7:
                next_pointer = end

        elif frequency == "Weekly":
            if (end - pointer).days >= 7:
                next_pointer = pointer + timedelta(days=7)
            else:
                next_pointer = end

        elif frequency == "Daily":
            next_pointer = pointer + timedelta(days=1)

        else:
            raise ValueError(f"Unknown frequency: {frequency}")

        if next_pointer > end:
            next_pointer = end

        ends.append(next_pointer)
        pointer = next_pointer

    return starts, ends


def to_epoch(dt: datetime) -> str:
    return str(int(dt.timestamp()))


def send_email_via_smtp(
    to_addrs: List[str], subject: str, body: str, attachments: Optional[List[tuple]] = None
) -> bool:
    """Send an email via SMTP without authentication.

    attachments: list of tuples (filename, bytes, maintype, subtype)
    """
    if _env_override_allowed():
        host = os.getenv("SPLUNK_TOOL_SMTP_HOST", "localhost")
        port = int(os.getenv("SPLUNK_TOOL_SMTP_PORT", "25"))
        from_addr = os.getenv("SPLUNK_TOOL_FROM", "splunk-donotreply@localhost")
    else:
        _audit_blocked_env_override("SPLUNK_TOOL_SMTP_HOST", "SPLUNK_TOOL_SMTP_PORT", "SPLUNK_TOOL_FROM")
        host = "localhost"
        port = 25
        from_addr = "splunk-donotreply@localhost"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ",".join(to_addrs) if isinstance(to_addrs, (list, tuple)) else str(to_addrs)
    msg.set_content(body)

    if attachments:
        for fn, data, maintype, subtype in attachments:
            try:
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fn)
            except Exception:
                # fallback: attach as application/octet-stream
                msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=fn)

    try:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.send_message(msg)
        return True
    except Exception:
        return False


def _append_log(
    logs: List[str],
    line: str,
    log_callback: Optional[Callable[[str], None]],
    sid_callback: Optional[Callable[[str, str], None]] = None,
) -> None:
    logs.append(line)
    if log_callback:
        log_callback(line)


def _dispatch_saved_search_with_budget(
    client: SplunkClient,
    *,
    report_id_url: str,
    earliest: Optional[str],
    latest: Optional[str],
    timeout_seconds: int,
    trace_context: Optional[dict[str, Any]] = None,
) -> Tuple[str, bool, str, str, int]:
    dispatch_timeout = max(0.01, float(timeout_seconds))
    start = time.monotonic()
    result_queue: "queue.Queue[tuple[str, bool, str, str]]" = queue.Queue(maxsize=1)
    worker_name = f"dispatch-call-{uuid.uuid4().hex[:8]}"

    def _worker() -> None:
        previous_trace_context = getattr(client, "_dispatch_trace_context", None)
        if trace_context:
            setattr(client, "_dispatch_trace_context", dict(trace_context))
        try:
            ok, sid, err = client.dispatch_saved_search(
                report_id_url,
                earliest=earliest,
                latest=latest,
            )
            result_queue.put(
                (
                    "RETURNED",
                    bool(ok),
                    str(sid or ""),
                    redact_text(str(err or "")),
                )
            )
        except Exception as exc:
            result_queue.put(
                (
                    "EXCEPTION",
                    False,
                    "",
                    redact_text(str(exc) or repr(exc)),
                )
            )
        finally:
            if previous_trace_context is None:
                try:
                    delattr(client, "_dispatch_trace_context")
                except Exception:
                    pass
            else:
                setattr(client, "_dispatch_trace_context", previous_trace_context)

    worker = threading.Thread(target=_worker, name=worker_name, daemon=True)
    worker.start()
    setattr(
        client,
        "_last_dispatch_call_budget_meta",
        {
            "worker_thread_name": worker.name,
            "worker_thread_ident": worker.ident,
            "timeout_seconds": dispatch_timeout,
        },
    )
    try:
        dispatch_state, ok, sid, err = result_queue.get(timeout=dispatch_timeout)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        setattr(
            client,
            "_last_dispatch_call_budget_meta",
            {
                "worker_thread_name": worker.name,
                "worker_thread_ident": worker.ident,
                "timeout_seconds": dispatch_timeout,
                "dispatch_state": dispatch_state,
                "elapsed_ms": elapsed_ms,
                "sid_present": bool(sid),
            },
        )
        return dispatch_state, ok, sid, err, elapsed_ms
    except queue.Empty:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        setattr(
            client,
            "_last_dispatch_call_budget_meta",
            {
                "worker_thread_name": worker.name,
                "worker_thread_ident": worker.ident,
                "timeout_seconds": dispatch_timeout,
                "dispatch_state": "TIMEOUT_NO_SID",
                "elapsed_ms": elapsed_ms,
                "sid_present": False,
            },
        )
        return "TIMEOUT_NO_SID", False, "", "", elapsed_ms


def _reset_slice_transport_state(
    logs: List[str],
    *,
    client: SplunkClient,
    report_name: str,
    slice_label: str,
    slice_index: int,
    slice_total: int,
    log_callback: Optional[Callable[[str], None]],
    audit_slice_event: Callable[..., None],
) -> None:
    _append_log(
        logs,
        f"[Debug] SLICE_RESOURCES_RESET report_name={report_name} slice_label={slice_label}",
        log_callback,
    )
    audit_slice_event(
        "SLICE_RESOURCES_RESET",
        level="DEBUG",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
    )
    reset_actions: list[str] = []
    if hasattr(client, "_last_dispatch_meta"):
        try:
            client._last_dispatch_meta = {}
            reset_actions.append("last_dispatch_meta")
        except Exception:
            pass
    if hasattr(client, "_last_snapshot_meta"):
        try:
            client._last_snapshot_meta = {}
            reset_actions.append("last_snapshot_meta")
        except Exception:
            pass
    if hasattr(client, "_dispatch_context"):
        try:
            client._dispatch_context = {}
            reset_actions.append("dispatch_context")
        except Exception:
            pass
    for method_name in ("reset_dispatch_context", "reset_transport", "close_transport"):
        method = getattr(client, method_name, None)
        if callable(method):
            try:
                method()
                reset_actions.append(method_name)
            except Exception:
                reset_actions.append(f"{method_name}_failed")
    _append_log(
        logs,
        f"[Debug] ACTIVE_BATCH_TRANSPORT_RESET report_name={report_name} actions={','.join(reset_actions) or 'none'}",
        log_callback,
    )
    audit_slice_event(
        "ACTIVE_BATCH_TRANSPORT_RESET",
        level="DEBUG",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        reset_actions=",".join(reset_actions),
    )


def _dispatch_slice_and_wait(
    logs: List[str],
    *,
    client: SplunkClient,
    report_id_url: str,
    report_name: str,
    slice_label: str,
    slice_index: int = 0,
    slice_total: int = 0,
    earliest_display: str,
    latest_display: str,
    dispatch_earliest: Optional[str],
    dispatch_latest: Optional[str],
    run_id: str,
    wait_seconds: int,
    poll_interval: int,
    timeout_status: str,
    dispatch_call_timeout_seconds: int,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
    merge_report_timeout_seconds: int,
    log_prefix: str,
    log_callback: Optional[Callable[[str], None]],
    sid_callback: Optional[Callable[[str, str], None]],
    record_slice: Callable[..., None],
    audit_slice_event: Callable[..., None],
) -> Tuple[str, str]:
    slice_index = max(0, int(slice_index or 0))
    slice_total = max(0, int(slice_total or 0))
    dispatch_call_timeout_seconds = max(1, int(dispatch_call_timeout_seconds or 0))
    dispatch_call_id = uuid.uuid4().hex[:12]
    dispatch_transport_mode = (
        "broker_proxy"
        if client.__class__.__name__ == "SplunkBrokerProxyClient"
        else "direct_client"
    )
    dispatch_trace_context = {
        "run_id": str(run_id or "").strip(),
        "report_name": report_name,
        "slice_label": slice_label,
        "slice_index": slice_index,
        "slice_total": slice_total,
        "correlation_id": dispatch_call_id,
        "earliest": earliest_display,
        "latest": latest_display,
        "transport_mode": dispatch_transport_mode,
        "thread_name": threading.current_thread().name,
    }
    audit_slice_event(
        "SLICE_DISPATCH_ENGINE_START",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        correlation_id=dispatch_call_id,
        earliest=earliest_display,
        latest=latest_display,
        transport_mode=dispatch_transport_mode,
        thread_name=threading.current_thread().name,
    )
    audit_slice_event(
        "ENGINE_BROKER_CALL_ENTER",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        correlation_id=dispatch_call_id,
        dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        earliest=earliest_display,
        latest=latest_display,
        transport_mode=dispatch_transport_mode,
        thread_name=threading.current_thread().name,
        thread_ident=threading.get_ident(),
    )
    audit_slice_event(
        "SLICE_DISPATCH_ENGINE_CALL_BROKER",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        correlation_id=dispatch_call_id,
        earliest=earliest_display,
        latest=latest_display,
        transport_mode=dispatch_transport_mode,
        thread_name=threading.current_thread().name,
    )
    dispatch_state, ok, sid, err, dispatch_elapsed_ms = _dispatch_saved_search_with_budget(
        client,
        report_id_url=report_id_url,
        earliest=dispatch_earliest,
        latest=dispatch_latest,
        timeout_seconds=dispatch_call_timeout_seconds,
        trace_context=dispatch_trace_context,
    )
    dispatch_call_meta = getattr(client, "_last_dispatch_call_budget_meta", {})
    if not isinstance(dispatch_call_meta, dict):
        dispatch_call_meta = {}
    audit_slice_event(
        "ENGINE_BROKER_CALL_EXIT",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        correlation_id=dispatch_call_id,
        dispatch_call_state=dispatch_state,
        dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        elapsed_ms=dispatch_elapsed_ms,
        sid_present=bool(sid),
        transport_mode=dispatch_transport_mode,
        worker_thread_name=dispatch_call_meta.get("worker_thread_name"),
        worker_thread_ident=dispatch_call_meta.get("worker_thread_ident"),
    )
    audit_slice_event(
        "SLICE_DISPATCH_ENGINE_RETURN",
        level="INFO" if dispatch_state == "RETURNED" else "WARN",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        correlation_id=dispatch_call_id,
        earliest=earliest_display,
        latest=latest_display,
        elapsed_ms=dispatch_elapsed_ms,
        transport_mode=dispatch_transport_mode,
        sid=sid if sid else None,
        dispatch_call_state=dispatch_state,
        exception_type="DispatchException" if dispatch_state == "EXCEPTION" else None,
        exception_message=_short_error(err) if dispatch_state == "EXCEPTION" and err else None,
        thread_name=threading.current_thread().name,
    )
    if dispatch_state == "TIMEOUT_NO_SID":
        err_msg = (
            f"Dispatch not confirmed within {dispatch_call_timeout_seconds} seconds "
            "before SID was returned."
        )
        _append_log(
            logs,
            f"  {log_prefix}{_display_slice_status(timeout_status)} - {err_msg}",
            log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_DISPATCH_TIMEOUT_NO_SID",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            elapsed_ms=dispatch_elapsed_ms,
            sid_present=False,
            earliest=earliest_display,
            latest=latest_display,
            reason=_short_error(err_msg),
            error_phase="dispatch",
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        )
        audit_slice_event(
            "REPORT_SLICE_MARKED_PENDING",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid="",
            reason=_short_error(err_msg),
            error_phase="dispatch",
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status=timeout_status,
            earliest=earliest_display,
            latest=latest_display,
            sid="",
            outcome_code=_pending_no_sid_outcome_code(timeout_status),
            error=err_msg,
        )
        return timeout_status, ""
    if dispatch_state == "EXCEPTION":
        safe_error = redact_text(err or "Dispatch call raised an exception before returning.")
        _append_log(logs, f"  {log_prefix}FAILED: {safe_error}", log_callback)
        audit_slice_event(
            "REPORT_SLICE_DISPATCH_EXCEPTION",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            elapsed_ms=dispatch_elapsed_ms,
            sid_present=False,
            earliest=earliest_display,
            latest=latest_display,
            reason=_short_error(safe_error),
            error_type="DispatchException",
            error_phase="dispatch",
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status="FAILED",
            earliest=earliest_display,
            latest=latest_display,
            outcome_code="DISPATCH_FAILED",
            error=safe_error,
        )
        return "FAILED", ""
    if not ok:
        _append_log(logs, f"  {log_prefix}FAILED: {err}", log_callback)
        broker_op, broker_timeout = _extract_broker_context(text=err)
        error_type = "TimeoutError" if _error_looks_like_timeout(err) else "DispatchError"
        audit_fields = {
            "slice_label": slice_label,
            "slice_index": slice_index,
            "slice_total": slice_total,
            "reason": _short_error(err),
            "error_type": error_type,
            "error_phase": "dispatch",
        }
        if broker_op:
            audit_fields["broker_op"] = broker_op
        if broker_timeout is not None:
            audit_fields["timeout_seconds"] = broker_timeout
        audit_slice_event(
            "REPORT_SLICE_FAILED",
            level="WARN",
            **audit_fields,
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status="FAILED",
            earliest=earliest_display,
            latest=latest_display,
            outcome_code="DISPATCH_FAILED",
            error=err,
        )
        return "FAILED", ""
    if not sid:
        err_msg = "Dispatch returned without a SID."
        _append_log(
            logs,
            f"  {log_prefix}{_display_slice_status(timeout_status)} - {err_msg}",
            log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_DISPATCH_NO_SID",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            elapsed_ms=dispatch_elapsed_ms,
            sid_present=False,
            earliest=earliest_display,
            latest=latest_display,
            reason=_short_error(err_msg),
            error_phase="dispatch",
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        )
        audit_slice_event(
            "REPORT_SLICE_MARKED_PENDING",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid="",
            reason=_short_error(err_msg),
            error_phase="dispatch",
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status=timeout_status,
            earliest=earliest_display,
            latest=latest_display,
            sid="",
            outcome_code=_pending_no_sid_outcome_code(timeout_status),
            error=err_msg,
        )
        return timeout_status, ""
    audit_slice_event(
        "REPORT_SLICE_SID_RECEIVED",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
    )
    audit_slice_event(
        "REPORT_SLICE_DISPATCHED",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
    )
    if sid_callback:
        sid_callback(sid, report_name)

    if prefer_merge_report_verification and merge_report_log_path:
        verification_wait_seconds = max(1, int(merge_report_timeout_seconds or wait_seconds))
        _append_log(
            logs,
            (
                f"  {log_prefix}DISPATCHED (sid={sid}) - "
                f"awaiting MergeReport verification for up to {verification_wait_seconds}s..."
            ),
            log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_MERGEREPORT_WAIT_START",
            level="INFO",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
            wait_seconds=verification_wait_seconds,
            merge_report_log_path=merge_report_log_path,
        )
        merge_state, merge_detail, merge_elapsed_ms = _wait_for_mergereport_sid_result(
            merge_report_log_path,
            sid,
            wait_seconds=verification_wait_seconds,
            poll_interval=poll_interval,
        )
        audit_slice_event(
            "REPORT_SLICE_MERGEREPORT_WAIT_END",
            level="INFO" if merge_state == "SUCCESS" else "WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
            result_state=merge_state,
            elapsed_ms=merge_elapsed_ms,
        )
        if merge_state == "SUCCESS":
            _append_log(logs, f"  {log_prefix}OK (sid={sid})", log_callback)
            audit_slice_event(
                "REPORT_SLICE_OK",
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                sid=sid,
                verification_source="merge_report",
            )
            record_slice(
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                status="OK",
                earliest=earliest_display,
                latest=latest_display,
                sid=sid,
                outcome_code="SUCCESS_MERGEREPORT",
            )
            return "OK", sid
        if merge_state == "FAILED":
            failure_detail = merge_detail or "MergeReport reported an explicit failure marker."
            _append_log(
                logs,
                f"  {log_prefix}FAILED (sid={sid}) - {_short_error(failure_detail)}",
                log_callback,
            )
            audit_slice_event(
                "REPORT_SLICE_FAILED",
                level="WARN",
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                sid=sid,
                reason=_short_error(failure_detail),
                error_phase="merge_report",
                verification_source="merge_report",
            )
            record_slice(
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                status="FAILED",
                earliest=earliest_display,
                latest=latest_display,
                sid=sid,
                outcome_code="MERGEREPORT_FAILED",
                error=failure_detail,
            )
            return "FAILED", sid

        fallback_detail = (
            f"MergeReport terminal evidence not found within {verification_wait_seconds} seconds. "
            "Falling back to native Splunk status verification."
        )
        _append_log(
            logs,
            f"  {log_prefix}{fallback_detail}",
            log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_MERGEREPORT_FALLBACK_NATIVE",
            level="INFO",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
            reason=_short_error(fallback_detail),
            error_phase="merge_report",
            verification_source="merge_report",
        )

    _append_log(
        logs,
        (
            f"  {log_prefix}DISPATCHED (sid={sid}) - "
            f"awaiting status verification for up to {wait_seconds}s..."
        ),
        log_callback,
    )

    status_check_start_utc = _utc_now_iso()
    status_check_start = time.monotonic()
    poll_count = 0

    audit_slice_event(
        "REPORT_SLICE_STATUS_CHECK_START",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
        outer_wait_seconds=max(1, int(wait_seconds)),
        poll_interval_seconds=max(1, int(poll_interval)),
        start_utc=status_check_start_utc,
    )

    def _poll_audit(**payload: object) -> None:
        nonlocal poll_count
        poll_count = int(payload.get("poll_count", poll_count))
        meta = getattr(client, "_last_snapshot_meta", {})
        if not isinstance(meta, dict):
            meta = {}
        audit_slice_event(
            "REPORT_SLICE_STATUS_CHECK_POLL",
            level="INFO",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
            poll_index=payload.get("poll_count"),
            poll_elapsed_ms=payload.get("poll_elapsed_ms"),
            request_timeout_seconds=payload.get("request_timeout_seconds"),
            remaining_seconds=payload.get("remaining_seconds"),
            state=payload.get("state"),
            broker_timeout_seconds=meta.get("broker_timeout_seconds"),
            broker_elapsed_ms=meta.get("broker_elapsed_ms"),
            splunk_elapsed_ms=meta.get("splunk_elapsed_ms"),
        )

    try:
        state, info, poll_count = _poll_job_status_with_budget(
            client,
            sid,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            poll_callback=_poll_audit,
        )
    except Exception as exc:
        raw_error = str(exc) or repr(exc)
        safe_error = redact_text(raw_error)
        err_msg = _build_pending_status_message(safe_error, wait_seconds=wait_seconds)
        error_type = type(exc).__name__
        broker_op, broker_timeout = _extract_broker_context(exc=exc, text=raw_error)
        status_check_end_utc = _utc_now_iso()
        status_elapsed_ms = int((time.monotonic() - status_check_start) * 1000)
        last_meta = getattr(client, "_last_snapshot_meta", {})
        if not isinstance(last_meta, dict):
            last_meta = {}
        audit_slice_event(
            "REPORT_SLICE_STATUS_CHECK_END",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
            result_state="EXCEPTION",
            error_type=error_type,
            outer_wait_seconds=max(1, int(wait_seconds)),
            poll_interval_seconds=max(1, int(poll_interval)),
            poll_count=poll_count,
            elapsed_ms=status_elapsed_ms,
            start_utc=status_check_start_utc,
            end_utc=status_check_end_utc,
            broker_timeout_seconds=broker_timeout
            if broker_timeout is not None
            else last_meta.get("broker_timeout_seconds"),
            request_timeout_seconds=last_meta.get("request_timeout_seconds"),
            broker_elapsed_ms=last_meta.get("broker_elapsed_ms"),
            splunk_elapsed_ms=last_meta.get("splunk_elapsed_ms"),
        )
        _append_log(
            logs,
            f"  {log_prefix}{_display_slice_status(timeout_status)} (sid={sid}) - {err_msg}",
            log_callback,
        )
        if _error_looks_like_timeout(raw_error):
            audit_slice_event(
                "REPORT_SLICE_ACTIVE_WAIT_EXPIRED",
                level="WARN",
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                sid=sid,
                reason=_short_error(safe_error),
                error_type=error_type,
                error_phase="status_check",
                broker_op=broker_op if broker_op else None,
                timeout_seconds=broker_timeout,
            )
        else:
            audit_slice_event(
                "REPORT_SLICE_STATUS_CHECK_ERROR",
                level="WARN",
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                sid=sid,
                reason=_short_error(safe_error),
                error_type=error_type,
                error_phase="status_check",
                broker_op=broker_op if broker_op else None,
                timeout_seconds=broker_timeout,
            )
        audit_slice_event(
            "REPORT_SLICE_MARKED_PENDING",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
            reason=_short_error(err_msg),
            error_phase="status_check",
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status=timeout_status,
            earliest=earliest_display,
            latest=latest_display,
            sid=sid,
            outcome_code="DISPATCHED_PENDING",
            error=err_msg,
        )
        return timeout_status, sid

    status_check_end_utc = _utc_now_iso()
    status_elapsed_ms = int((time.monotonic() - status_check_start) * 1000)
    last_meta = getattr(client, "_last_snapshot_meta", {})
    if not isinstance(last_meta, dict):
        last_meta = {}
    audit_slice_event(
        "REPORT_SLICE_STATUS_CHECK_END",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
        result_state=state,
        outer_wait_seconds=max(1, int(wait_seconds)),
        poll_interval_seconds=max(1, int(poll_interval)),
        poll_count=poll_count,
        elapsed_ms=status_elapsed_ms,
        start_utc=status_check_start_utc,
        end_utc=status_check_end_utc,
        broker_timeout_seconds=last_meta.get("broker_timeout_seconds"),
        request_timeout_seconds=last_meta.get("request_timeout_seconds"),
        broker_elapsed_ms=last_meta.get("broker_elapsed_ms"),
        splunk_elapsed_ms=last_meta.get("splunk_elapsed_ms"),
    )

    if state == "SUCCESS":
        _append_log(logs, f"  {log_prefix}OK (sid={sid})", log_callback)
        audit_slice_event(
            "REPORT_SLICE_OK",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status="OK",
            earliest=earliest_display,
            latest=latest_display,
            sid=sid,
            outcome_code="SUCCESS",
        )
        return "OK", sid

    if state == "FAILED":
        dispatch_state = str(info.get("dispatchState", "Unknown error") or "Unknown error")
        _append_log(
            logs,
            f"  {log_prefix}FAILED (sid={sid}, state={dispatch_state})",
            log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_FAILED",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid=sid,
            reason=_short_error(dispatch_state),
            error_phase="status_check",
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status="FAILED",
            earliest=earliest_display,
            latest=latest_display,
            sid=sid,
            outcome_code="VERIFIED_FAILED",
            error=dispatch_state,
        )
        return "FAILED", sid

    last_dispatch_state = str(info.get("dispatchState", "")).strip()
    timeout_detail = f"Status not confirmed within {wait_seconds} seconds."
    if last_dispatch_state:
        timeout_detail += f" Last dispatchState={last_dispatch_state}."
    err_msg = _build_pending_status_message(timeout_detail, wait_seconds=wait_seconds)
    _append_log(
        logs,
        f"  {log_prefix}{_display_slice_status(timeout_status)} (sid={sid}) - {err_msg}",
        log_callback,
    )
    audit_slice_event(
        "REPORT_SLICE_ACTIVE_WAIT_EXPIRED",
        level="WARN",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
        reason=_short_error(timeout_detail),
        error_phase="status_check",
    )
    audit_slice_event(
        "REPORT_SLICE_MARKED_PENDING",
        level="WARN",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
        reason=_short_error(err_msg),
        error_phase="status_check",
    )
    record_slice(
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        status=timeout_status,
        earliest=earliest_display,
        latest=latest_display,
        sid=sid,
        outcome_code="DISPATCHED_PENDING",
        error=err_msg,
    )
    return timeout_status, sid


def run_dispatch_single(
    client: SplunkClient,
    report_id_url: str,
    report_name: str,
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
    wait_seconds: int = 10,
    poll_interval: int = 2,
    log_callback: Optional[Callable[[str], None]] = None,
    sid_callback: Optional[Callable[[str, str], None]] = None,
    regen_context: Optional[RegenContext] = None,
    continue_on_timeout: bool = DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT,
    timeout_status: str = "PENDING",
    dispatch_call_timeout_seconds: int = DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS,
    prefer_merge_report_verification: bool = False,
    merge_report_log_path: str = "",
    merge_report_timeout_seconds: int = DEFAULT_MERGEREPORT_TIMEOUT_SECONDS,
) -> List[str]:
    logs: List[str] = []

    def _record_slice(
        slice_label: str,
        status: str,
        slice_index: int = 0,
        slice_total: int = 0,
        earliest: str = "",
        latest: str = "",
        sid: str = "",
        outcome_code: str = "DISPATCHED_PENDING",
        error: str = "",
    ) -> None:
        if regen_context is None:
            return
        regen_context.add_slice(
            report_name=report_name,
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            earliest=earliest,
            latest=latest,
            sid=sid,
            status=status,
            outcome_code=outcome_code,
            error=error,
        )

    def _audit_slice_event(event: str, *, level: str = "INFO", **fields) -> None:
        if regen_context is None:
            return
        _audit_event(
            event,
            level=level,
            run_id=regen_context.run_id,
            report_name=report_name,
            **fields,
        )

    if no_change:
        slice_label = "single run"
        _append_log(
            logs,
            f"Dispatching '{report_name}' with saved search time range...",
            log_callback,
        )
        _dispatch_slice_and_wait(
            logs,
            client=client,
            report_id_url=report_id_url,
            report_name=report_name,
            slice_label=slice_label,
            slice_index=1,
            slice_total=1,
            earliest_display=str(start),
            latest_display=str(end),
            dispatch_earliest=None,
            dispatch_latest=None,
            run_id=(regen_context.run_id if regen_context is not None else ""),
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            log_prefix="",
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=_record_slice,
            audit_slice_event=_audit_slice_event,
        )
        return logs

    starts, ends = build_slices(start, end, frequency)
    if len(starts) == 0:
        raise ValueError("Selected date range generates 0 slices/emails.")
    if len(starts) > 12:
        raise ValueError("Selected date range generates more than 12 slices/emails.")
    _append_log(
        logs,
        f"Dispatching '{report_name}' with {len(starts)} slice(s) ({frequency}) from {start} to {end}.",
        log_callback,
    )
    for i, (s, e) in enumerate(zip(starts, ends), start=1):
        slice_label = f"[{i}/{len(starts)}]"
        earliest = to_epoch(s)
        latest = to_epoch(e)
        if i > 1:
            _reset_slice_transport_state(
                logs,
                client=client,
                report_name=report_name,
                slice_label=slice_label,
                slice_index=i,
                slice_total=len(starts),
                log_callback=log_callback,
                audit_slice_event=_audit_slice_event,
            )
        _append_log(
            logs,
            f"  [{i}/{len(starts)}] Earliest: {s}, Latest: {e} - sending...",
            log_callback,
        )
        status, sid = _dispatch_slice_and_wait(
            logs,
            client=client,
            report_id_url=report_id_url,
            report_name=report_name,
            slice_label=slice_label,
            slice_index=i,
            slice_total=len(starts),
            earliest_display=str(s),
            latest_display=str(e),
            dispatch_earliest=earliest,
            dispatch_latest=latest,
            run_id=(regen_context.run_id if regen_context is not None else ""),
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            log_prefix=f"[{i}/{len(starts)}] ",
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=_record_slice,
            audit_slice_event=_audit_slice_event,
        )
        if _is_pending_status(status) and i < len(starts):
            if continue_on_timeout:
                _append_log(
                    logs,
                    (
                        f"  [{i}/{len(starts)}] Status not confirmed within {wait_seconds} seconds. "
                        "Continuing to next slice."
                    ),
                    log_callback,
                )
                _audit_slice_event(
                    "REPORT_BATCH_CONTINUE_AFTER_PENDING",
                    level="INFO",
                    slice_label=slice_label,
                    slice_index=i,
                    slice_total=len(starts),
                    sid=sid,
                    remaining_slices=len(starts) - i,
                )
                continue
            _append_log(
                logs,
                f"  [{i}/{len(starts)}] Halting remaining slices because continue_on_timeout=false.",
                log_callback,
            )
            _audit_slice_event(
                "REPORT_BATCH_STOPPED_AFTER_PENDING",
                level="WARN",
                slice_label=slice_label,
                slice_index=i,
                slice_total=len(starts),
                sid=sid,
                remaining_slices=len(starts) - i,
            )
            break
    return logs

@dataclass
class AckEmailResult:
    attempted: bool
    success: bool
    recipients: List[str] = field(default_factory=list)
    reason: str = ""
    error: str = ""


def _short_error(text: str, limit: int = 180) -> str:
    clean = (text or "").replace("\n", " ").replace("\r", " ").strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def _utc_now_iso() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


_BROKER_TIMEOUT_RE = re.compile(
    r"Local Splunk broker timed out while processing the request"
    r"(?:\s*\(op=([^,]+),\s*timeout=(\d+)s\))?",
    re.IGNORECASE,
)


def _error_looks_like_timeout(text: str) -> bool:
    lower = (text or "").lower()
    return "timed out" in lower or "timeout" in lower


def _extract_broker_context(exc: Optional[Exception] = None, text: str = "") -> Tuple[Optional[str], Optional[int]]:
    op = getattr(exc, "broker_op", None) if exc is not None else None
    timeout_seconds = getattr(exc, "timeout_seconds", None) if exc is not None else None

    if (not op or timeout_seconds is None) and text:
        match = _BROKER_TIMEOUT_RE.search(text)
        if match:
            if not op:
                op = match.group(1) or ""
            if timeout_seconds is None:
                try:
                    timeout_seconds = int(match.group(2))
                except Exception:
                    timeout_seconds = None

    op = str(op).strip() if isinstance(op, str) else ""
    if isinstance(timeout_seconds, (int, float)):
        try:
            timeout_seconds = int(timeout_seconds)
        except Exception:
            timeout_seconds = None
    else:
        timeout_seconds = None

    return (op if op else None), timeout_seconds


def _poll_job_status_with_budget(
    client: SplunkClient,
    sid: str,
    wait_seconds: int,
    poll_interval: int,
    *,
    poll_callback: Optional[Callable[..., None]] = None,
) -> Tuple[str, dict, int]:
    last_content: dict = {}
    deadline = time.monotonic() + max(1, int(wait_seconds))
    poll_seconds = max(1.0, float(poll_interval))
    poll_count = 0

    snapshot_fn = getattr(client, "get_job_status_snapshot", None)
    can_snapshot = callable(snapshot_fn)

    if not can_snapshot:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or remaining < 1.0:
                break
            request_timeout = min(poll_seconds, remaining)
            poll_count += 1
            poll_start = time.monotonic()
            state, content = client.check_job_status(
                sid,
                wait_seconds=max(1, int(request_timeout)),
                poll_interval=max(1, int(min(poll_seconds, request_timeout))),
            )
            poll_elapsed = time.monotonic() - poll_start
            poll_elapsed_ms = int(poll_elapsed * 1000)
            last_content = content

            if poll_callback:
                poll_callback(
                    poll_count=poll_count,
                    state=state,
                    content=content,
                    poll_elapsed_ms=poll_elapsed_ms,
                    request_timeout_seconds=request_timeout,
                    remaining_seconds=max(0.0, remaining),
                )

            if state in ("SUCCESS", "FAILED"):
                return state, content, poll_count

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sleep_seconds = max(0.0, poll_seconds - poll_elapsed)
            sleep_seconds = min(sleep_seconds, max(0.0, remaining))
            if sleep_seconds <= 0:
                continue
            time.sleep(sleep_seconds)

        return "TIMEOUT", last_content, poll_count

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or remaining < 1.0:
            break

        request_timeout = min(poll_seconds, remaining)
        poll_count += 1
        poll_start = time.monotonic()
        state, content = snapshot_fn(
            sid,
            request_timeout_seconds=request_timeout,
            max_total_timeout_seconds=remaining,
        )
        poll_elapsed_ms = int((time.monotonic() - poll_start) * 1000)
        last_content = content

        if poll_callback:
            poll_callback(
                poll_count=poll_count,
                state=state,
                content=content,
                poll_elapsed_ms=poll_elapsed_ms,
                request_timeout_seconds=request_timeout,
                remaining_seconds=max(0.0, remaining),
            )

        if state in ("SUCCESS", "FAILED"):
            return state, content, poll_count

        sleep_seconds = min(poll_seconds, max(0.0, deadline - time.monotonic()))
        if sleep_seconds <= 0:
            break
        time.sleep(sleep_seconds)

    return "TIMEOUT", last_content, poll_count


def _build_pending_status_message(detail: str = "", *, wait_seconds: Optional[int] = None) -> str:
    active_wait = max(1, int(wait_seconds or DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS))
    if _error_looks_like_timeout(detail):
        base = (
            f"Status not confirmed within {active_wait} seconds. "
            "Splunk may still complete pending jobs asynchronously."
        )
    else:
        base = (
            "Slice dispatched successfully and remains pending verification. "
            "Splunk may still complete pending jobs asynchronously."
        )
    clean_detail = (detail or "").strip()
    if clean_detail:
        return f"{base} Detail: {clean_detail}"
    return base


def _pending_no_sid_outcome_code(timeout_status: str) -> str:
    return "PENDING_NO_SID" if _is_pending_status(timeout_status) else "DISPATCH_NO_SID"


def _classify_mergereport_terminal_message(message: str, level: str) -> Optional[Tuple[str, str]]:
    lower_message = str(message or "").strip().lower()
    upper_level = str(level or "").strip().upper()
    if "action=email sent" in lower_message or lower_message.startswith("action=email sent"):
        return ("SUCCESS", "MergeReport confirmed Action=Email sent.")
    if upper_level == "ERROR":
        return ("FAILED", str(message or "MergeReport reported an error.").strip())
    failure_markers = (
        "failed",
        "smtp empty",
        "smtp error",
        "error sending",
        "unable to send",
    )
    if any(marker in lower_message for marker in failure_markers):
        return ("FAILED", str(message or "MergeReport reported a failure marker.").strip())
    return None


def _scan_mergereport_log_for_sid(log_path: str, sid: str) -> Tuple[str, str]:
    sid = str(sid or "").strip()
    if not log_path or not sid:
        return ("RUNNING", "")
    try:
        from mergereport_monitor import MergeReportParser
    except Exception as exc:
        return ("FAILED", f"Unable to import MergeReport parser: {exc}")

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                event = MergeReportParser.parse_line(raw_line.rstrip("\r\n"))
                if event is None or str(event.sid or "").strip() != sid:
                    continue
                classified = _classify_mergereport_terminal_message(
                    event.message,
                    event.level,
                )
                if classified is not None:
                    return classified
    except FileNotFoundError:
        return ("RUNNING", "")
    except Exception as exc:
        safe_error = redact_text(str(exc) or repr(exc))
        return ("FAILED", f"MergeReport log read failed: {safe_error}")
    return ("RUNNING", "")


def _wait_for_mergereport_sid_result(
    log_path: str,
    sid: str,
    *,
    wait_seconds: int,
    poll_interval: int,
) -> Tuple[str, str, int]:
    wait_budget = max(1, int(wait_seconds))
    deadline = time.monotonic() + wait_budget
    poll_seconds = max(1.0, float(poll_interval))
    start_time = time.monotonic()

    while True:
        state, detail = _scan_mergereport_log_for_sid(log_path, sid)
        if state in ("SUCCESS", "FAILED"):
            return (state, detail, int((time.monotonic() - start_time) * 1000))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_seconds, max(0.0, remaining)))

    return ("TIMEOUT", "", int((time.monotonic() - start_time) * 1000))


def resolve_status_check_timeout_seconds(config: Optional[SplunkConfig]) -> int:
    if (
        config is not None
        and isinstance(config.dispatch_config, dict)
        and "per_slice_wait_seconds" in config.dispatch_config
    ):
        return _parse_min_int(
            config.dispatch_config.get("per_slice_wait_seconds"),
            DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS,
            1,
        )
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("status_check_timeout_seconds"),
        DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS,
        1,
    )


def resolve_status_check_poll_seconds(config: Optional[SplunkConfig]) -> int:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_POSTDISPATCH_POLL_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("poll_seconds"),
        DEFAULT_POSTDISPATCH_POLL_SECONDS,
        1,
    )


def resolve_broker_request_timeout_seconds(config: Optional[SplunkConfig]) -> int:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("broker_request_timeout_seconds"),
        DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS,
        1,
    )


def resolve_continue_on_timeout(config: Optional[SplunkConfig]) -> bool:
    if (
        config is None
        or not isinstance(config.dispatch_config, dict)
        or "continue_on_timeout" not in config.dispatch_config
    ):
        return DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT
    return _parse_bool(
        config.dispatch_config.get("continue_on_timeout"),
        DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT,
    )


def resolve_dispatch_call_timeout_seconds(config: Optional[SplunkConfig]) -> int:
    if (
        config is None
        or not isinstance(config.dispatch_config, dict)
        or "dispatch_call_timeout_seconds" not in config.dispatch_config
    ):
        return DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS
    return _parse_min_int(
        config.dispatch_config.get("dispatch_call_timeout_seconds"),
        DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS,
        1,
    )


def resolve_timeout_result(config: Optional[SplunkConfig]) -> str:
    if (
        config is None
        or not isinstance(config.dispatch_config, dict)
        or "timeout_result" not in config.dispatch_config
    ):
        return _normalize_timeout_result(DEFAULT_DISPATCH_TIMEOUT_RESULT)
    return _normalize_timeout_result(
        config.dispatch_config.get("timeout_result", DEFAULT_DISPATCH_TIMEOUT_RESULT)
    )


def resolve_reconcile_pending(config: Optional[SplunkConfig]) -> bool:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_RECONCILE_PENDING_ENABLED
    return _parse_bool(
        config.postdispatch_config.get("reconcile_pending"),
        DEFAULT_RECONCILE_PENDING_ENABLED,
    )


def resolve_postdispatch_enabled(config: Optional[SplunkConfig]) -> bool:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_POSTDISPATCH_ENABLED
    return _parse_bool(
        config.postdispatch_config.get("enabled"),
        DEFAULT_POSTDISPATCH_ENABLED,
    )


def resolve_primary_slice_mergereport_enabled(config: Optional[SplunkConfig]) -> bool:
    if config is None:
        return False
    return bool(
        getattr(config, "merge_report_enabled", False)
        and str(getattr(config, "merge_report_log_path", "") or "").strip()
    )


def resolve_reconcile_wait_seconds(config: Optional[SplunkConfig]) -> int:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_RECONCILE_WAIT_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("reconcile_wait_seconds"),
        DEFAULT_RECONCILE_WAIT_SECONDS,
        1,
    )


def _pending_slice_records(context: RegenContext) -> List[RegenSliceRecord]:
    return [item for item in context.slices if _is_pending_status(item.status)]


def _fetch_job_status_snapshot(
    client: SplunkClient,
    sid: str,
    *,
    request_timeout_seconds: int,
    poll_interval: int,
) -> Tuple[str, dict]:
    if hasattr(client, "get_job_status_snapshot"):
        return client.get_job_status_snapshot(
            sid,
            request_timeout_seconds=max(1, int(request_timeout_seconds)),
            max_total_timeout_seconds=max(1, int(request_timeout_seconds)),
        )
    return client.check_job_status(
        sid,
        wait_seconds=max(1, int(request_timeout_seconds)),
        poll_interval=max(1, int(poll_interval)),
    )


def _reconcile_pending_slices(
    client: SplunkClient,
    context: RegenContext,
    *,
    wait_seconds: int,
    poll_interval: int,
    log_callback: Optional[Callable[[str], None]] = None,
) -> List[str]:
    logs: List[str] = []
    pending = [item for item in _pending_slice_records(context) if item.sid]
    if not pending:
        return logs

    _append_log(
        logs,
        (
            f"Starting pending reconciliation for {len(pending)} slice(s). "
            f"Budget={max(1, int(wait_seconds))} seconds."
        ),
        log_callback,
    )
    _audit_event(
        "REPORT_PENDING_RECONCILIATION_STARTED",
        level="INFO",
        run_id=context.run_id,
        pending_slices=len(pending),
        wait_seconds=max(1, int(wait_seconds)),
    )

    unresolved = list(pending)
    deadline = time.monotonic() + max(1, int(wait_seconds))
    poll_seconds = max(1, int(poll_interval))

    while unresolved and time.monotonic() < deadline:
        next_unresolved: List[RegenSliceRecord] = []
        for item in unresolved:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                next_unresolved.append(item)
                continue
            request_timeout = min(max(1, poll_seconds), max(1, int(remaining)))
            try:
                state, info = _fetch_job_status_snapshot(
                    client,
                    item.sid,
                    request_timeout_seconds=request_timeout,
                    poll_interval=poll_seconds,
                )
            except Exception as exc:
                raw_error = str(exc) or repr(exc)
                safe_msg = _short_error(redact_text(raw_error))
                error_type = type(exc).__name__
                broker_op, broker_timeout = _extract_broker_context(exc=exc, text=raw_error)
                _audit_event(
                    "REPORT_PENDING_RECONCILIATION_CHECK_FAILED",
                    level="WARN",
                    run_id=context.run_id,
                    sid=item.sid,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    reason=safe_msg,
                    error_type=error_type,
                    error_phase="reconciliation",
                    broker_op=broker_op if broker_op else None,
                    timeout_seconds=broker_timeout,
                )
                next_unresolved.append(item)
                continue

            if state == "SUCCESS":
                item.status = "OK"
                item.outcome_code = "RECONCILED_OK"
                item.error = ""
                _append_log(
                    logs,
                    f"  Pending slice resolved to OK (sid={item.sid}).",
                    log_callback,
                )
                _audit_event(
                    "REPORT_PENDING_RESOLVED_OK",
                    level="INFO",
                    run_id=context.run_id,
                    sid=item.sid,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                )
                continue

            if state == "FAILED":
                dispatch_state = str(info.get("dispatchState", "Unknown error") or "Unknown error")
                item.status = "FAILED"
                item.outcome_code = "RECONCILED_FAILED"
                item.error = dispatch_state
                _append_log(
                    logs,
                    f"  Pending slice resolved to FAILED (sid={item.sid}, state={dispatch_state}).",
                    log_callback,
                )
                _audit_event(
                    "REPORT_PENDING_RESOLVED_FAILED",
                    level="WARN",
                    run_id=context.run_id,
                    sid=item.sid,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    reason=_short_error(dispatch_state),
                    error_phase="reconciliation",
                )
                continue

            next_unresolved.append(item)

        unresolved = next_unresolved
        if unresolved:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(float(poll_seconds), max(0.0, remaining)))

    for item in unresolved:
        _append_log(
            logs,
            (
                f"  Pending slice remains unresolved (sid={item.sid}). "
                "Splunk may still complete pending jobs asynchronously."
            ),
            log_callback,
        )
        _audit_event(
            "REPORT_PENDING_REMAINED_UNRESOLVED",
            level="WARN",
            run_id=context.run_id,
            sid=item.sid,
            report_name=item.report_name,
            slice_label=item.slice_label,
            slice_index=item.slice_index,
            slice_total=item.slice_total,
            error_phase="reconciliation",
        )

    return logs


def _format_slice_summary_line(item: RegenSliceRecord) -> str:
    range_parts = [part for part in (item.earliest, item.latest) if part]
    range_text = " to ".join(range_parts) if len(range_parts) == 2 else (range_parts[0] if range_parts else "saved search range")
    sid_text = f" (sid={item.sid})" if item.sid else ""
    status_label = _display_slice_status(item.status)
    line = f"  [{status_label}] {item.report_name} {item.slice_label}: {range_text}{sid_text}"
    if status_label != "OK" and item.error:
        line += f" - {_short_error(item.error)}"
    return line


def _build_run_summary_lines(context: RegenContext) -> List[str]:
    ok_count, fail_count, pending_count = context.summary_counts()
    lines = [
        "Summary:",
        f"  Total slices: {len(context.slices)}",
        f"  Succeeded: {ok_count}",
        f"  Failed: {fail_count}",
        f"  Pending: {pending_count}",
    ]
    for item in context.slices:
        lines.append(_format_slice_summary_line(item))
    if pending_count:
        lines.append(
            "  One or more slices remain PENDING because active status verification did not complete."
        )
        lines.append("  Splunk may still complete pending jobs asynchronously.")
    return lines


def _extract_recipients_from_content(content: dict) -> List[str]:
    recipients: List[str] = []
    direct_keys = [
        "action.email.to",
        "action.mergeReport.param.To",
        "action.mergeReport.param.to",
        "action.mergereport.param.To",
        "action.mergereport.param.to",
    ]
    for key in direct_keys:
        recipients.extend(_parse_recipients(str(content.get(key, ""))))

    # Case-insensitive fallback in case field key casing differs.
    for key, value in content.items():
        key_lower = key.lower()
        if key_lower == "action.email.to" or key_lower.endswith(".param.to"):
            recipients.extend(_parse_recipients(str(value)))

    return _dedupe_keep_order(recipients)


def _build_saved_search_candidate_paths(
    report_id_url: str,
    report_name: str,
    app: str,
    username: str,
) -> List[str]:
    candidates: List[str] = []

    def _add(path: str) -> None:
        if path and path not in candidates:
            candidates.append(path)

    parsed = urlparse(report_id_url)
    raw_path = parsed.path
    if raw_path:
        _add(raw_path)

    owner_from_path = ""
    app_from_path = app
    name_from_path = report_name
    parts = raw_path.strip("/").split("/") if raw_path else []
    # Expected: /servicesNS/<owner>/<app>/saved/searches/<encoded-name>
    if len(parts) >= 6 and parts[0] == "servicesNS" and parts[3] == "saved" and parts[4] == "searches":
        owner_from_path = parts[1]
        app_from_path = app_from_path or parts[2]
        if not name_from_path:
            name_from_path = unquote(parts[5])

    if not app_from_path or not name_from_path:
        return candidates

    encoded_name = quote(name_from_path, safe="")
    owners: List[str] = []
    if username:
        owners.append(username)
    if owner_from_path and owner_from_path not in owners:
        owners.append(owner_from_path)
    for owner in ("nobody", "-"):
        if owner not in owners:
            owners.append(owner)

    for owner in owners:
        _add(f"/servicesNS/{owner}/{app_from_path}/saved/searches/{encoded_name}")

    return candidates


def _collect_saved_search_recipients(
    client: SplunkClient,
    report_id_url: str,
    report_name: str,
    app: str,
    username: str,
) -> List[str]:
    recipients: List[str] = []
    candidate_paths = _build_saved_search_candidate_paths(
        report_id_url=report_id_url,
        report_name=report_name,
        app=app,
        username=username,
    )

    for path in candidate_paths:
        try:
            meta = client._get(path)
            entries = meta.get("entry", [])
            if not entries:
                continue
            content = entries[0].get("content", {})
            recipients.extend(_extract_recipients_from_content(content))
        except Exception:
            continue

    return _dedupe_keep_order(recipients)


def _resolve_ack_enabled(config: Optional[SplunkConfig]) -> bool:
    default_enabled = True if config is None else config.ack_enabled
    if not _env_override_allowed():
        _audit_blocked_env_override("SPLUNK_TOOL_ACK_ENABLED", "SPLUNK_TOOL_ACK_ENABLE")
        return default_enabled
    env_value = os.getenv("SPLUNK_TOOL_ACK_ENABLED", "").strip()
    if not env_value:
        env_value = os.getenv("SPLUNK_TOOL_ACK_ENABLE", "").strip()
    if not env_value:
        return default_enabled
    return _parse_bool(env_value, default_enabled)


def _resolve_ack_on_pending(config: Optional[SplunkConfig]) -> bool:
    if config is None:
        return False
    return bool(getattr(config, "ack_on_pending", False) or getattr(config, "ack_on_unknown", False))


def _resolve_ack_recipients(
    context: RegenContext,
    config: Optional[SplunkConfig],
) -> List[str]:
    env_recipients = []
    if _env_override_allowed():
        env_recipients = _parse_recipients(os.getenv("SPLUNK_TOOL_ACK_RECIPIENTS", "").strip())
    else:
        _audit_blocked_env_override("SPLUNK_TOOL_ACK_RECIPIENTS")
    recipients: List[str] = []
    if env_recipients:
        recipients.extend(env_recipients)
    elif config is not None:
        recipients.extend(config.ack_recipients)

    include_savedsearch = False
    if config is not None and config.ack_use_savedsearch_recipients:
        include_savedsearch = True
    elif not recipients:
        # Fallback to REST-discovered saved-search recipients when explicit ACK
        # recipients are not configured.
        include_savedsearch = True

    if include_savedsearch:
        recipients.extend(context.savedsearch_recipients)
    return _dedupe_keep_order(recipients)
def _resolve_smtp_settings(config: Optional[SplunkConfig]) -> dict:
    default_host = "127.0.0.1"
    default_port = 25
    default_tls = False
    default_user = ""
    default_pass = ""
    default_from = "Splunk Notification <splunk-donotreply@localhost>"
    if config is not None:
        default_host = config.smtp_host or default_host
        default_port = config.smtp_port or default_port
        default_tls = config.smtp_use_tls
        default_user = config.smtp_user
        default_pass = config.smtp_pass
        default_from = config.smtp_from or default_from
    if _env_override_allowed():
        smtp_host = os.getenv("SPLUNK_TOOL_SMTP_HOST", "").strip() or default_host
        smtp_port_raw = os.getenv("SPLUNK_TOOL_SMTP_PORT", "").strip()
        smtp_port = _parse_int(smtp_port_raw, default_port) if smtp_port_raw else default_port
        tls_raw = os.getenv("SPLUNK_TOOL_SMTP_TLS", "").strip()
        smtp_use_tls = _parse_bool(tls_raw, default_tls) if tls_raw else default_tls
        smtp_user = os.getenv("SPLUNK_TOOL_SMTP_USER", "").strip() or default_user
        smtp_pass = os.getenv("SPLUNK_TOOL_SMTP_PASS", "").strip() or default_pass
        smtp_from = (
            os.getenv("SPLUNK_TOOL_SMTP_FROM", "").strip()
            or os.getenv("SPLUNK_TOOL_MAIL_FROM", "").strip()
            or default_from
        )
    else:
        _audit_blocked_env_override(
            "SPLUNK_TOOL_SMTP_HOST",
            "SPLUNK_TOOL_SMTP_PORT",
            "SPLUNK_TOOL_SMTP_TLS",
            "SPLUNK_TOOL_SMTP_USER",
            "SPLUNK_TOOL_SMTP_PASS",
            "SPLUNK_TOOL_SMTP_FROM",
            "SPLUNK_TOOL_MAIL_FROM",
        )
        smtp_host = default_host
        smtp_port = default_port
        smtp_use_tls = default_tls
        smtp_user = default_user
        smtp_pass = default_pass
        smtp_from = default_from
    return {
        "host": smtp_host,
        "port": smtp_port,
        "use_tls": smtp_use_tls,
        "user": smtp_user,
        "password": smtp_pass,
        "from_addr": smtp_from,
    }
def _build_ack_subject(context: RegenContext) -> str:
    run_time = context.end_time_sgt or context.start_time_sgt or get_sgt_now()
    if len(context.report_names) == 1:
        report_label = context.report_names[0]
    else:
        report_label = f"{context.report_names[0]} (+{len(context.report_names) - 1} more)"
    overall_status = context.overall_status()
    status_prefix = f"{overall_status} | " if overall_status != "OK" else ""
    return (
        f"*** MANUALLY REGENERATED *** {status_prefix}{report_label} | "
        f"{context.earliest_configured} to {context.latest_configured} | "
        f"{format_sgt(run_time)}"
    )
def _build_ack_body(context: RegenContext) -> str:
    generated_at = context.end_time_sgt or context.start_time_sgt or get_sgt_now()
    ok_count, fail_count, pending_count = context.summary_counts()
    total = len(context.slices)
    slices_with_sid = [item for item in context.slices if item.sid]
    failed_slices = [item for item in context.slices if item.status == "FAILED"]
    pending_slices = [item for item in context.slices if _is_pending_status(item.status)]
    body_lines = [
        "*** MANUALLY REGENERATED ***",
        f"User: {context.operator}",
        f"Host: {context.hostname}",
        f"Generated: {format_sgt(generated_at)}",
        f"Report: {', '.join(context.report_names)}",
        f"App: {context.app or '(unknown)'}",
        f"Mode: {context.mode_description}",
        f"Range: {context.earliest_configured} to {context.latest_configured}",
        "",
        "Result summary:",
        f"  - Overall status: {context.overall_status()}",
        f"  - Total slices: {total}",
        f"  - Succeeded: {ok_count}",
        f"  - Failed: {fail_count}",
        f"  - Pending: {pending_count}",
    ]
    if context.slicing_enabled and context.slices:
        body_lines.append("  - Per-slice ranges:")
        for item in context.slices:
            body_lines.append(f"    * {_format_slice_summary_line(item).strip()}")
    if failed_slices:
        body_lines.append("  - Failed slices:")
        for item in failed_slices:
            body_lines.append(
                f"    * {item.report_name} {item.slice_label}: {_short_error(item.error or 'Unknown error')}"
            )
    if pending_slices:
        body_lines.append("  - Pending / awaiting verification:")
        for item in pending_slices:
            body_lines.append(
                f"    * {item.report_name} {item.slice_label}: {_short_error(item.error or 'Final status not yet known')}"
            )
        body_lines.append("  - Splunk may still complete pending jobs asynchronously.")
    body_lines.append("")
    body_lines.append("SIDs issued by dispatch:")
    if slices_with_sid:
        for item in slices_with_sid:
            body_lines.append(f"  - {item.report_name} {item.slice_label}: {item.sid}")
    else:
        body_lines.append("  - None")
    return "\n".join(body_lines)
def _build_manifest_attachment(context: RegenContext) -> Optional[tuple]:
    if not context.ack_attach_manifest:
        return None
    lines = ["report,slice_label,earliest,latest,status,sid,error"]
    for item in context.slices:
        row = [
            item.report_name,
            item.slice_label,
            item.earliest,
            item.latest,
            item.status,
            item.sid,
            item.error,
        ]
        escaped = []
        for value in row:
            value = value or ""
            if "," in value or '"' in value or "\n" in value:
                escaped.append('"' + value.replace('"', '""') + '"')
            else:
                escaped.append(value)
        lines.append(",".join(escaped))
    filename = f"manual_regen_manifest_{context.run_id}.csv"
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return (filename, payload, "text", "csv")
def send_ack_summary_email(context: RegenContext, config: Optional[SplunkConfig] = None) -> AckEmailResult:
    ack_enabled = _resolve_ack_enabled(config)
    ack_on_pending = _resolve_ack_on_pending(config)
    recipients = _resolve_ack_recipients(context, config) if ack_enabled else []
    _, fail_count, pending_count = context.summary_counts()
    _audit_event(
        "EMAIL_SEND_REQUESTED",
        level="INFO",
        run_id=context.run_id,
        report_count=len(context.report_names),
        recipient_count=len(recipients),
        ack_enabled=ack_enabled,
    )
    if not ack_enabled:
        _audit_event(
            "ACK_EMAIL_SKIPPED_DISABLED",
            level="WARN",
            run_id=context.run_id,
            recipient_count=0,
            reason="ack_disabled",
            error_type="ack_disabled",
            error_phase="ack_decision",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            reason="ack_disabled",
        )
    if pending_count > 0 and not ack_on_pending:
        _audit_event(
            "ACK_EMAIL_SKIPPED_PENDING",
            level="WARN",
            run_id=context.run_id,
            recipient_count=len(recipients),
            pending_slices=pending_count,
            reason="pending_slices_present",
            error_type="pending_slices_present",
            error_phase="ack_decision",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            recipients=recipients,
            reason="pending_slices_present",
        )
    if not recipients:
        _audit_event(
            "EMAIL_SEND_FAILED",
            level="WARN",
            run_id=context.run_id,
            recipient_count=0,
            reason="no_recipients",
            error_type="no_recipients",
            error_phase="ack_decision",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            reason="no_recipients",
        )
    smtp_settings = _resolve_smtp_settings(config)
    subject = _build_ack_subject(context)
    body = _build_ack_body(context)
    if pending_count > 0:
        _audit_event(
            "ACK_EMAIL_SENT_PENDING",
            level="INFO",
            run_id=context.run_id,
            recipient_count=len(recipients),
            pending_slices=pending_count,
            failed_slices=fail_count,
        )
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_settings["from_addr"]
    msg["To"] = ",".join(recipients)
    msg.set_content(body)
    attachment = _build_manifest_attachment(context)
    if attachment:
        filename, data, maintype, subtype = attachment
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    try:
        with smtplib.SMTP(
            smtp_settings["host"],
            smtp_settings["port"],
            timeout=20,
        ) as server:
            if smtp_settings["use_tls"]:
                server.starttls()
            if smtp_settings["user"] and smtp_settings["password"]:
                server.login(smtp_settings["user"], smtp_settings["password"])
            server.send_message(msg)
        _audit_event(
            "EMAIL_SEND_SUCCESS",
            level="INFO",
            run_id=context.run_id,
            recipient_count=len(recipients),
        )
        return AckEmailResult(
            attempted=True,
            success=True,
            recipients=recipients,
            reason="pending_verification" if pending_count > 0 else "",
        )
    except Exception as exc:
        _audit_event(
            "EMAIL_SEND_FAILED",
            level="ERROR",
            run_id=context.run_id,
            recipient_count=len(recipients),
            reason="smtp_send_failed",
            error_type=type(exc).__name__,
            error_phase="email_send",
        )
        return AckEmailResult(
            attempted=True,
            success=False,
            recipients=recipients,
            reason="smtp_send_failed",
            error=repr(exc),
        )

def run_dispatch_multi(
    client: SplunkClient,
    report_ids: List[str],
    report_names: List[str],
    selected_indices: List[int],
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
    wait_seconds: int = 10,
    poll_interval: int = 2,
    log_callback: Optional[Callable[[str], None]] = None,
    sid_callback: Optional[Callable[[str, str], None]] = None,
    config: Optional["SplunkConfig"] = None,
    app: str = "",
) -> List[str]:
    try:
        logs: List[str] = []
        if not selected_indices:
            raise ValueError("No reports selected.")
        selected_report_names = [report_names[i] for i in selected_indices]
        start_time_sgt = get_sgt_now()
        if no_change:
            slices_per_report = 1
            mode_description = "single run"
        else:
            starts, _ = build_slices(start, end, frequency)
            slices_per_report = len(starts)
            mode_description = f"{frequency.lower()} slices: {slices_per_report}"
        regen_context = RegenContext(
            run_id=f"regen-{start_time_sgt.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}",
            report_names=selected_report_names,
            app=app,
            operator=get_effective_username(),
            hostname=socket.gethostname(),
            tool_name=TOOL_DISPLAY_NAME,
            start_time_sgt=start_time_sgt,
            end_time_sgt=None,
            slicing_enabled=not no_change,
            slice_count=max(0, slices_per_report * len(selected_indices)),
            frequency=frequency,
            earliest_configured=start.strftime("%Y-%m-%d %H:%M:%S"),
            latest_configured=end.strftime("%Y-%m-%d %H:%M:%S"),
            mode_description=mode_description,
            ack_attach_manifest=(config.ack_attach_manifest if config else False),
        )
        _audit_event(
            "REPORT_DISPATCH_REQUESTED",
            level="INFO",
            run_id=regen_context.run_id,
            app=app,
            report_names=selected_report_names,
            slicing_mode=mode_description,
            earliest=regen_context.earliest_configured,
            latest=regen_context.latest_configured,
            report_count=len(selected_indices),
        )
        splunk_username = str(getattr(client, "username", "") or "").strip()

        collected: List[str] = []
        for i in selected_indices:
            collected.extend(
                _collect_saved_search_recipients(
                    client=client,
                    report_id_url=report_ids[i],
                    report_name=report_names[i],
                    app=app,
                    username=splunk_username,
                )
            )
        regen_context.savedsearch_recipients = _dedupe_keep_order(collected)
        if regen_context.savedsearch_recipients:
            _append_log(
                logs,
                (
                    "[ACK] Saved-search recipients discovered via REST: "
                    f"{len(regen_context.savedsearch_recipients)} recipient(s)."
                ),
                log_callback,
            )
        else:
            _append_log(
                logs,
                "[ACK] No saved-search recipients discovered via REST.",
                log_callback,
            )
        _append_log(
            logs,
            (
                f"Starting dispatch for {len(selected_indices)} report(s) - "
                f"frequency={frequency}, range={start} -> {end}, no_change={no_change}"
            ),
            log_callback,
        )
        for idx_num, i in enumerate(selected_indices, start=1):
            report_id_url = report_ids[i]
            report_name = report_names[i]
            _append_log(logs, "", log_callback)
            _append_log(
                logs,
                f"=== [{idx_num}/{len(selected_indices)}] {report_name} ===",
                log_callback,
            )
            report_logs = run_dispatch_single(
                client,
                report_id_url=report_id_url,
                report_name=report_name,
                frequency=frequency,
                start=start,
                end=end,
                no_change=no_change,
                wait_seconds=wait_seconds,
                poll_interval=poll_interval,
                log_callback=log_callback,
                sid_callback=sid_callback,
                regen_context=regen_context,
                continue_on_timeout=resolve_continue_on_timeout(config),
                timeout_status=resolve_timeout_result(config),
                dispatch_call_timeout_seconds=resolve_dispatch_call_timeout_seconds(config),
                prefer_merge_report_verification=resolve_primary_slice_mergereport_enabled(config),
                merge_report_log_path=(
                    str(getattr(config, "merge_report_log_path", "") or "")
                    if config is not None
                    else ""
                ),
                merge_report_timeout_seconds=(
                    int(
                        getattr(
                            config,
                            "merge_report_timeout_seconds",
                            DEFAULT_MERGEREPORT_TIMEOUT_SECONDS,
                        )
                        or DEFAULT_MERGEREPORT_TIMEOUT_SECONDS
                    )
                    if config is not None
                    else DEFAULT_MERGEREPORT_TIMEOUT_SECONDS
                ),
            )
            logs.extend(report_logs)
        pending_slices = _pending_slice_records(regen_context)
        if pending_slices:
            if not resolve_postdispatch_enabled(config):
                _append_log(
                    logs,
                    (
                        "Post-dispatch verification disabled by configuration; "
                        "skipping pending reconciliation."
                    ),
                    log_callback,
                )
                _audit_event(
                    "REPORT_POSTDISPATCH_SKIPPED_DISABLED",
                    level="INFO",
                    run_id=regen_context.run_id,
                    app=app,
                    pending_slices=len(pending_slices),
                )
            elif resolve_reconcile_pending(config):
                reconcile_logs = _reconcile_pending_slices(
                    client,
                    regen_context,
                    wait_seconds=resolve_reconcile_wait_seconds(config),
                    poll_interval=resolve_status_check_poll_seconds(config),
                    log_callback=log_callback,
                )
                logs.extend(reconcile_logs)
        regen_context.end_time_sgt = get_sgt_now()
        regen_context.slice_count = len(regen_context.slices)
        ok_count, fail_count, pending_count = regen_context.summary_counts()
        total_count = len(regen_context.slices)
        _append_log(logs, "", log_callback)
        for line in _build_run_summary_lines(regen_context):
            _append_log(logs, line, log_callback)
        if pending_count > 0:
            _append_log(
                logs,
                "Splunk may still complete pending jobs asynchronously.",
                log_callback,
            )
        if fail_count == 0 and pending_count == 0:
            _audit_event(
                "REPORT_DISPATCH_SUCCESS",
                level="INFO",
                run_id=regen_context.run_id,
                app=app,
                report_count=len(selected_indices),
                total_slices=total_count,
            )
        elif fail_count == 0:
            _audit_event(
                "REPORT_DISPATCH_PENDING",
                level="WARN",
                run_id=regen_context.run_id,
                app=app,
                report_count=len(selected_indices),
                total_slices=total_count,
                pending_slices=pending_count,
            )
        else:
            _audit_event(
                "REPORT_DISPATCH_FAILED",
                level="WARN",
                run_id=regen_context.run_id,
                app=app,
                report_count=len(selected_indices),
                total_slices=total_count,
                failed_slices=fail_count,
                pending_slices=pending_count,
            )
        ack_result = send_ack_summary_email(regen_context, config=config)
        report_audit = ",".join(selected_report_names)
        recipient_count = len(ack_result.recipients)
        if ack_result.success:
            status = "sent"
        elif ack_result.attempted:
            status = "failed"
        else:
            status = "skipped"
        reason = ack_result.reason or "-"
        _append_log(
            logs,
            (
                f"ACK_EMAIL_SENT run_id={regen_context.run_id} report={report_audit} "
                f"recipient_count={recipient_count} status={status} reason={reason}"
            ),
            log_callback,
        )
        if ack_result.reason == "pending_slices_present":
            _append_log(
                logs,
                "Acknowledgement email skipped because one or more slices are still pending.",
                log_callback,
            )
        elif ack_result.reason == "pending_verification":
            _append_log(
                logs,
                "Acknowledgement email sent with PARTIAL / PENDING VERIFICATION status because pending slices remain.",
                log_callback,
            )
        elif ack_result.reason == "ack_disabled":
            _append_log(
                logs,
                "Acknowledgement email skipped because ack_enabled=false.",
                log_callback,
            )
        if ack_result.error:
            _append_log(
                logs,
                "ACK email failure details are available in security audit logs.",
                log_callback,
            )
        client.dispatch_log.emit(logs)
        return logs
    except Exception as e:
        _audit_event(
            "REPORT_DISPATCH_FAILED",
            level="ERROR",
            app=app,
            report_count=len(selected_indices) if "selected_indices" in locals() else 0,
            reason=repr(e),
        )
        client.error.emit(f"Error during dispatch: {e!r}")
        return []
    finally:
        client.finished.emit()
