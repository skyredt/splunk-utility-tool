from __future__ import annotations

import configparser
import importlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, List, Optional, Tuple
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
from Internal.security_policy import PolicyViolation, SecurityPolicy, load_security_policy, redact_text


VALID_AUTH_MODES = ("password",)
TOOL_DISPLAY_NAME = "Splunk Utility Tool v4"


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
    merge_report_timeout_seconds: int = 90
    # Manual regeneration acknowledgement settings
    ack_enabled: bool = True
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
    earliest: str = ""
    latest: str = ""
    sid: str = ""
    status: str = "UNKNOWN"  # OK, FAILED, UNKNOWN
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
        earliest: str = "",
        latest: str = "",
        sid: str = "",
        status: str = "UNKNOWN",
        error: str = "",
    ) -> None:
        self.slices.append(
            RegenSliceRecord(
                report_name=report_name,
                slice_label=slice_label,
                earliest=earliest,
                latest=latest,
                sid=sid,
                status=status,
                error=error,
            )
        )

    def summary_counts(self) -> Tuple[int, int, int]:
        ok_count = sum(1 for s in self.slices if s.status == "OK")
        fail_count = sum(1 for s in self.slices if s.status == "FAILED")
        unknown_count = sum(1 for s in self.slices if s.status == "UNKNOWN")
        return ok_count, fail_count, unknown_count


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

    cfg = configparser.ConfigParser()
    read_files = cfg.read(active_policy.config_path)
    if not read_files:
        raise FileNotFoundError(f"Config file not found: {active_policy.config_path}")

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
    if "Logging" in cfg or "logging" in cfg:
        logging_section = cfg["Logging"] if "Logging" in cfg else cfg["logging"]
        logging_level = (logging_section.get("level", logging_level) or logging_level).strip().upper()
        if logging_level not in ("DEBUG", "INFO", "WARN", "ERROR"):
            logging_level = "INFO"
        logging_verbose = _parse_bool(logging_section.get("verbose", str(int(logging_verbose))), logging_verbose)
        logging_max_bytes = _parse_int(logging_section.get("max_bytes", str(logging_max_bytes)), logging_max_bytes)
        logging_backup_count = _parse_int(logging_section.get("backup_count", str(logging_backup_count)), logging_backup_count)
    logging_level, logging_max_bytes, logging_backup_count = active_policy.enforce_audit_settings(
        logging_level,
        logging_max_bytes,
        logging_backup_count,
    )

    # MergeReport config (optional section)
    merge_report_enabled = False
    merge_report_log_path = ""
    merge_report_timeout_seconds = 90

    if "mergereport" in cfg:
        enabled_str = cfg["mergereport"].get("enabled", "false").lower()
        merge_report_enabled = enabled_str in ("true", "1", "yes")
        merge_report_log_path = cfg["mergereport"].get("log_path", "").strip()
        try:
            merge_report_timeout_seconds = int(
                cfg["mergereport"].get("timeout_seconds", "90")
            )
        except ValueError:
            merge_report_timeout_seconds = 90

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

    # Manual ACK + SMTP defaults
    ack_enabled = True
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
        ack_enabled = _parse_bool(section.get("enabled", "true"), True)
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
            "merge_report_enabled": section.get("merge_report_enabled", "true").lower() in ("true", "1", "yes"),
            "merge_report_index": section.get("merge_report_index", "_internal"),
            "merge_report_source_contains": section.get("merge_report_source_contains", "mergeReport_alert.log"),
            "merge_report_sourcetype": section.get("merge_report_sourcetype", "").strip(),
            "merge_report_timeout_seconds": int(section.get("merge_report_timeout_seconds", "120")) if section.get("merge_report_timeout_seconds") else 120,
            "native_email_enabled": section.get("native_email_enabled", "true").lower() in ("true", "1", "yes"),
            "native_email_index": section.get("native_email_index", "_internal"),
            "native_email_source_contains": section.get("native_email_source_contains", "python.log"),
            "native_email_sourcetype": section.get("native_email_sourcetype", "").strip(),
            "native_email_timeout_seconds": int(section.get("native_email_timeout_seconds", "120")) if section.get("native_email_timeout_seconds") else 120,
            "native_email_strict_success": section.get("native_email_strict_success", "false").lower() in ("true", "1", "yes"),
            "poll_seconds": int(section.get("poll_seconds", "3")) if section.get("poll_seconds") else 3,
            "lookback_seconds": int(section.get("lookback_seconds", "300")) if section.get("lookback_seconds") else 300,
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
        ack_enabled=ack_enabled,
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

        try:
            resp = self._request(
                "POST",
                path + "/dispatch",
                data={"output_mode": "json", **data},
                timeout=60,
            )
        except Exception as e:
            return False, None, f"Request error: {e!r}"

        try:
            payload = resp.json()
        except json.JSONDecodeError:
            return False, None, f"Non-JSON response: {resp.text[:500]}"

        sid = payload.get("sid")
        if not sid:
            return False, None, f"No sid in dispatch response: {payload}"

        return True, sid, ""

    def check_job_status(
        self, sid: str, wait_seconds: int = 10, poll_interval: int = 2
    ) -> Tuple[str, dict]:
        """
        Check job status for a given sid.

        Returns (state, content) where state is 'SUCCESS', 'FAILED', or 'TIMEOUT'.
        """
        import time

        last_content: dict = {}
        deadline = time.time() + wait_seconds

        while time.time() < deadline:
            data = self._get(f"/services/search/jobs/{sid}")
            entry = data.get("entry", [{}])[0]
            content = entry.get("content", {})
            last_content = content

            is_done = content.get("isDone")
            dispatch_state = content.get("dispatchState")

            if is_done:
                if dispatch_state in ("DONE", "SUCCESS", None):
                    return "SUCCESS", content
                else:
                    return "FAILED", content

            time.sleep(poll_interval)

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
) -> List[str]:
    logs: List[str] = []
    def _record_slice(
        slice_label: str,
        status: str,
        earliest: str = "",
        latest: str = "",
        sid: str = "",
        error: str = "",
    ) -> None:
        if regen_context is None:
            return
        regen_context.add_slice(
            report_name=report_name,
            slice_label=slice_label,
            earliest=earliest,
            latest=latest,
            sid=sid,
            status=status,
            error=error,
        )
    if no_change:
        _append_log(
            logs,
            f"Dispatching '{report_name}' with saved search time range...",
            log_callback,
        )
        ok, sid, err = client.dispatch_saved_search(report_id_url)
        if not ok:
            _append_log(logs, f"  FAILED: {err}", log_callback)
            _record_slice(
                slice_label="single run",
                status="FAILED",
                earliest=str(start),
                latest=str(end),
                error=err,
            )
            return logs
        if sid is None:
            _append_log(logs, "  FAILED: No sid returned", log_callback)
            _record_slice(
                slice_label="single run",
                status="FAILED",
                earliest=str(start),
                latest=str(end),
                error="No SID returned",
            )
            return logs
        if sid_callback:
            sid_callback(sid, report_name)
        try:
            state, info = client.check_job_status(
                sid, wait_seconds=wait_seconds, poll_interval=poll_interval
            )
        except Exception as exc:
            err_msg = f"Status check error: {exc!r}"
            _append_log(logs, f"  FAILED (sid={sid}, error={err_msg})", log_callback)
            _record_slice(
                slice_label="single run",
                status="FAILED",
                earliest=str(start),
                latest=str(end),
                sid=sid,
                error=err_msg,
            )
            return logs
        if state == "SUCCESS":
            _append_log(logs, f"  OK (sid={sid})", log_callback)
            _record_slice(
                slice_label="single run",
                status="OK",
                earliest=str(start),
                latest=str(end),
                sid=sid,
            )
        elif state == "FAILED":
            dispatch_state = str(info.get("dispatchState", "Unknown error"))
            _append_log(
                logs,
                f"  FAILED (sid={sid}, state={dispatch_state})",
                log_callback,
            )
            _record_slice(
                slice_label="single run",
                status="FAILED",
                earliest=str(start),
                latest=str(end),
                sid=sid,
                error=dispatch_state,
            )
        else:
            _append_log(
                logs,
                f"  UNKNOWN (sid={sid}) - job still running / timeout while checking",
                log_callback,
            )
            _record_slice(
                slice_label="single run",
                status="UNKNOWN",
                earliest=str(start),
                latest=str(end),
                sid=sid,
                error="Job still running / timeout",
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
        earliest = to_epoch(s)
        latest = to_epoch(e)
        _append_log(
            logs,
            f"  [{i}/{len(starts)}] Earliest: {s}, Latest: {e} - sending...",
            log_callback,
        )
        ok, sid, err = client.dispatch_saved_search(
            report_id_url, earliest=earliest, latest=latest
        )
        if not ok:
            _append_log(logs, f"  [{i}/{len(starts)}] FAILED: {err}", log_callback)
            _record_slice(
                slice_label=f"[{i}/{len(starts)}]",
                status="FAILED",
                earliest=str(s),
                latest=str(e),
                error=err,
            )
            continue
        if sid is None:
            _append_log(
                logs, f"  [{i}/{len(starts)}] FAILED: No sid returned", log_callback
            )
            _record_slice(
                slice_label=f"[{i}/{len(starts)}]",
                status="FAILED",
                earliest=str(s),
                latest=str(e),
                error="No SID returned",
            )
            continue
        if sid_callback:
            sid_callback(sid, report_name)
        try:
            state, info = client.check_job_status(
                sid, wait_seconds=wait_seconds, poll_interval=poll_interval
            )
        except Exception as exc:
            err_msg = f"Status check error: {exc!r}"
            _append_log(
                logs,
                f"  [{i}/{len(starts)}] FAILED (sid={sid}, error={err_msg})",
                log_callback,
            )
            _record_slice(
                slice_label=f"[{i}/{len(starts)}]",
                status="FAILED",
                earliest=str(s),
                latest=str(e),
                sid=sid,
                error=err_msg,
            )
            continue
        if state == "SUCCESS":
            _append_log(logs, f"  [{i}/{len(starts)}] OK (sid={sid})", log_callback)
            _record_slice(
                slice_label=f"[{i}/{len(starts)}]",
                status="OK",
                earliest=str(s),
                latest=str(e),
                sid=sid,
            )
        elif state == "FAILED":
            dispatch_state = str(info.get("dispatchState", "Unknown error"))
            _append_log(
                logs,
                f"  [{i}/{len(starts)}] FAILED (sid={sid}, state={dispatch_state})",
                log_callback,
            )
            _record_slice(
                slice_label=f"[{i}/{len(starts)}]",
                status="FAILED",
                earliest=str(s),
                latest=str(e),
                sid=sid,
                error=dispatch_state,
            )
        else:
            _append_log(
                logs,
                f"  [{i}/{len(starts)}] UNKNOWN (sid={sid}) - job still running / timeout while checking",
                log_callback,
            )
            _record_slice(
                slice_label=f"[{i}/{len(starts)}]",
                status="UNKNOWN",
                earliest=str(s),
                latest=str(e),
                sid=sid,
                error="Job still running / timeout",
            )
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
    return (
        f"*** MANUALLY REGENERATED *** {report_label} | "
        f"{context.earliest_configured} to {context.latest_configured} | "
        f"{format_sgt(run_time)}"
    )
def _build_ack_body(context: RegenContext) -> str:
    generated_at = context.end_time_sgt or context.start_time_sgt or get_sgt_now()
    ok_count, fail_count, unknown_count = context.summary_counts()
    total = len(context.slices)
    successful_slices = [item for item in context.slices if item.status == "OK" and item.sid]
    failed_slices = [item for item in context.slices if item.status == "FAILED"]
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
        f"  - Total slices: {total}",
        f"  - Succeeded: {ok_count}",
        f"  - Failed: {fail_count}",
    ]
    if unknown_count:
        body_lines.append(f"  - Unknown: {unknown_count}")
    if context.slicing_enabled and context.slices:
        body_lines.append("  - Per-slice ranges:")
        for item in context.slices:
            body_lines.append(
                f"    * {item.report_name} {item.slice_label}: {item.earliest} to {item.latest} [{item.status}]"
            )
    if failed_slices:
        body_lines.append("  - Failures:")
        for item in failed_slices:
            body_lines.append(
                f"    * {item.report_name} {item.slice_label}: {_short_error(item.error or 'Unknown error')}"
            )
    body_lines.append("")
    body_lines.append("SIDs:")
    if successful_slices:
        for item in successful_slices:
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
    recipients = _resolve_ack_recipients(context, config) if ack_enabled else []
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
            "EMAIL_SEND_FAILED",
            level="WARN",
            run_id=context.run_id,
            recipient_count=0,
            reason="ack_disabled",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            reason="ack_disabled",
        )
    if not recipients:
        _audit_event(
            "EMAIL_SEND_FAILED",
            level="WARN",
            run_id=context.run_id,
            recipient_count=0,
            reason="no_recipients",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            reason="no_recipients",
        )
    smtp_settings = _resolve_smtp_settings(config)
    subject = _build_ack_subject(context)
    body = _build_ack_body(context)
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
        )
    except Exception as exc:
        _audit_event(
            "EMAIL_SEND_FAILED",
            level="ERROR",
            run_id=context.run_id,
            recipient_count=len(recipients),
            reason="smtp_send_failed",
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
            )
            logs.extend(report_logs)
        regen_context.end_time_sgt = get_sgt_now()
        regen_context.slice_count = len(regen_context.slices)
        ok_count, fail_count, unknown_count = regen_context.summary_counts()
        total_count = ok_count + fail_count + unknown_count
        _append_log(logs, "", log_callback)
        _append_log(
            logs,
            (
                f"Summary: {ok_count} OK, {fail_count} failed, {unknown_count} unknown "
                f"out of {total_count} slice run(s)."
            ),
            log_callback,
        )
        if fail_count == 0 and unknown_count == 0:
            _audit_event(
                "REPORT_DISPATCH_SUCCESS",
                level="INFO",
                run_id=regen_context.run_id,
                app=app,
                report_count=len(selected_indices),
                total_slices=total_count,
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
                unknown_slices=unknown_count,
            )
        ack_result = send_ack_summary_email(regen_context, config=config)
        report_audit = ",".join(selected_report_names)
        recipient_count = len(ack_result.recipients)
        status = "success" if ack_result.success else "failure"
        reason = ack_result.reason or "-"
        _append_log(
            logs,
            (
                f"ACK_EMAIL_SENT run_id={regen_context.run_id} report={report_audit} "
                f"recipient_count={recipient_count} status={status} reason={reason}"
            ),
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
