from __future__ import annotations

import hmac
import http.client
import http.server
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional
from urllib.parse import unquote, urlparse

from Internal.dpapi_store import load_or_enroll_password
from Internal.security_policy import load_security_policy, redact_text
from Internal.tool_logging import debug_category_enabled, debug_event
from splunk_engine import SplunkClient, load_config, set_security_audit_logger, set_security_policy


SPLUNK_BROKER_BIND_HOST = "127.0.0.1"
SPLUNK_BROKER_UNAVAILABLE_WARNING = "Local Splunk broker unavailable. Please restart the tool or contact Splunk team."
MAX_REQUEST_BYTES = 65_536
MAX_RESPONSE_BYTES = 131_072
MAX_STRING_LENGTH = 512
RATE_WINDOW_SECONDS = 5.0
RATE_MAX_REQUESTS = 500

_SENSITIVE_KEY_PARTS = (
    "password",
    "token",
    "authorization",
    "cookie",
    "sessionkey",
    "session_key",
    "auth_header",
    "dpapi",
    "blob",
)
_CTRL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SAVED_SEARCH_PATH_RE = re.compile(
    r"^/servicesNS/[^/\s]+/[^/\s]+/saved/searches/[^/\s]+$",
    re.IGNORECASE,
)
_SID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,200}$")


class _NullSignal:
    def emit(self, *args, **kwargs) -> None:
        return


class _BrokerError(Exception):
    def __init__(self, status: int, error_code: str, message: str = ""):
        super().__init__(message or error_code)
        self.status = int(status)
        self.error_code = str(error_code)
        self.message = str(message or "")


def _sanitize_text(value: str) -> str:
    cleaned = _CTRL_CHAR_RE.sub("", str(value).replace("\r", " ").replace("\n", " ")).strip()
    if len(cleaned) > MAX_STRING_LENGTH:
        return cleaned[:MAX_STRING_LENGTH]
    return cleaned


def _safe_error_text(exc: Exception) -> str:
    return _sanitize_text(redact_text(str(exc)))


def _emit_broker_debug_event(event: str, *, level: str = "DEBUG", **fields: Any) -> None:
    if not debug_category_enabled("broker"):
        return
    safe_fields = _redact_sensitive(fields, key_hint="broker_dispatch")
    if not isinstance(safe_fields, dict):
        safe_fields = {}
    # Keep transport metadata in a single payload dict so duplicate keyword forwarding
    # cannot raise when client meta already includes transport_mode.
    transport_mode = safe_fields.pop("transport_mode", None)
    if transport_mode not in (None, ""):
        safe_fields["transport_mode"] = transport_mode
    debug_event(
        event,
        category="broker",
        level=level,
        **safe_fields,
    )


def _dispatch_request_context(report_id_url: str) -> dict[str, str]:
    requested_path = urlparse(str(report_id_url or "")).path
    report_name = ""
    app = ""
    owner = ""
    parts = [part for part in requested_path.split("/") if part]
    if len(parts) >= 6 and parts[0] == "servicesNS":
        owner = parts[1]
        app = parts[2]
        report_name = unquote(parts[-1])
    return {
        "requested_path": requested_path,
        "rest_endpoint": requested_path + "/dispatch" if requested_path else "",
        "rest_method": "POST",
        "report_name": _sanitize_text(report_name),
        "app": _sanitize_text(app),
        "owner": _sanitize_text(owner),
    }


def _sanitize_dispatch_trace_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    for key in (
        "run_id",
        "report_name",
        "slice_label",
        "correlation_id",
        "earliest",
        "latest",
        "transport_mode",
        "thread_name",
    ):
        raw = value.get(key)
        if raw not in (None, ""):
            out[key] = _sanitize_text(str(raw))
    for key in ("slice_index", "slice_total"):
        raw = value.get(key)
        if raw in (None, ""):
            continue
        try:
            out[key] = max(0, int(raw))
        except Exception:
            continue
    return out


def _coerce_timeout_seconds(timeout_seconds: float) -> Optional[int]:
    try:
        value = int(round(float(timeout_seconds)))
        return max(1, value)
    except Exception:
        return None


class LocalSplunkBrokerTimeout(RuntimeError):
    def __init__(self, op: str, timeout_seconds: float) -> None:
        self.broker_op = str(op or "").strip()
        self.timeout_seconds = _coerce_timeout_seconds(timeout_seconds)
        detail_parts: list[str] = []
        if self.broker_op:
            detail_parts.append(f"op={self.broker_op}")
        if self.timeout_seconds:
            detail_parts.append(f"timeout={self.timeout_seconds}s")
        message = "Local Splunk broker timed out while processing the request"
        if detail_parts:
            message += " (" + ", ".join(detail_parts) + ")"
        message += "."
        super().__init__(message)


def _redact_sensitive(value: Any, key_hint: str = "") -> Any:
    key_lower = key_hint.lower()
    if any(part in key_lower for part in _SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            out[str(k)] = _redact_sensitive(v, key_hint=str(k))
        return out
    if isinstance(value, list):
        return [_redact_sensitive(v, key_hint=key_hint) for v in value]
    if isinstance(value, tuple):
        return [_redact_sensitive(v, key_hint=key_hint) for v in value]
    if isinstance(value, str):
        return _sanitize_text(value)
    return value


def _parse_json_bytes(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
    except Exception:
        raise _BrokerError(400, "invalid_json")
    if not isinstance(parsed, dict):
        raise _BrokerError(400, "payload_must_be_object")
    return parsed


def _validate_string_field(data: dict[str, Any], key: str, *, required: bool = True, max_len: int = MAX_STRING_LENGTH) -> str:
    if key not in data:
        if required:
            raise _BrokerError(400, f"missing_{key}")
        return ""
    value = data.get(key)
    if not isinstance(value, str):
        raise _BrokerError(400, f"invalid_type_{key}")
    cleaned = _sanitize_text(value)
    if required and not cleaned:
        raise _BrokerError(400, f"missing_{key}")
    if len(cleaned) > max_len:
        raise _BrokerError(400, f"invalid_length_{key}")
    return cleaned


def _validate_bool_field(data: dict[str, Any], key: str, *, default: bool = False) -> bool:
    if key not in data:
        return bool(default)
    value = data.get(key)
    if not isinstance(value, bool):
        raise _BrokerError(400, f"invalid_type_{key}")
    return value


def _validate_int_field(
    data: dict[str, Any],
    key: str,
    *,
    default: int,
    min_value: int,
    max_value: int,
) -> int:
    if key not in data:
        return int(default)
    value = data.get(key)
    if (not isinstance(value, int)) or isinstance(value, bool):
        raise _BrokerError(400, f"invalid_type_{key}")
    if value < min_value or value > max_value:
        raise _BrokerError(400, f"invalid_range_{key}")
    return int(value)


def _validate_optional_iso_dt(value: str) -> Optional[datetime]:
    cleaned = _sanitize_text(value)
    if not cleaned:
        return None
    try:
        return datetime.fromisoformat(cleaned)
    except Exception:
        raise _BrokerError(400, "invalid_datetime")


def _http_post_json(
    host: str,
    port: int,
    path: str,
    payload: dict[str, Any],
    *,
    token: str,
    token_header: str = "X-Splunk-Broker-Token",
    timeout: float = 2.0,
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        token_header: token,
        "Connection": "close",
    }
    try:
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        status = int(response.status)
        raw = response.read(MAX_RESPONSE_BYTES)
    finally:
        conn.close()
    if not raw:
        return status, {}
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return status, {}
    if isinstance(parsed, dict):
        return status, parsed
    return status, {}


class _AuditForwarder:
    def __init__(self, base_url: str, token: str):
        self._base_url = _sanitize_text(base_url)
        self._token = _sanitize_text(token)
        parsed = urlparse(self._base_url)
        self._host = parsed.hostname or ""
        self._port = int(parsed.port or 0)
        self._path = parsed.path or "/v1/log"
        if self._path != "/v1/log":
            self._path = "/v1/log"

    def _is_ready(self) -> bool:
        return bool(self._host and self._port and self._token)

    def log_event(self, event: str, level: str = "INFO", **fields) -> None:
        if not self._is_ready():
            return
        payload = {
            "event": _sanitize_text(event).upper(),
            "level": _sanitize_text(level).upper() or "INFO",
            "fields": _redact_sensitive(fields),
        }
        try:
            _http_post_json(
                self._host,
                self._port,
                self._path,
                payload,
                token=self._token,
                token_header="X-Audit-Token",
                timeout=1.2,
            )
        except Exception:
            return


def _prompt_password_for_enroll() -> Optional[str]:
    # Keep password entry inside broker process so plaintext never crosses back to GUI.
    try:
        import tkinter as tk
        from tkinter import simpledialog
    except Exception:
        return None
    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except tk.TclError:
            pass
        return simpledialog.askstring(
            "Splunk Credential Enrollment",
            "Enter Splunk password for secure local enrollment:",
            show="*",
            parent=root,
        )
    except Exception:
        return None
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass


class SplunkBrokerProxyClient:
    finished = _NullSignal()
    error = _NullSignal()
    apps_loaded = _NullSignal()
    searches_loaded = _NullSignal()
    dispatch_log = _NullSignal()

    def __init__(self, *, host: str, port: int, auth_token: str, username: str = ""):
        self._host = host
        self._port = int(port)
        self._auth_token = auth_token
        self.username = username
        self._request_timeout_seconds = 300.0
        self._last_snapshot_meta: dict[str, Any] = {}

    def configure_request_timeout(self, timeout_seconds: float) -> None:
        try:
            self._request_timeout_seconds = max(1.0, float(timeout_seconds))
        except Exception:
            self._request_timeout_seconds = 300.0

    def _op(self, op: str, args: Optional[dict[str, Any]] = None, *, timeout: float = 30.0) -> dict[str, Any]:
        payload = {"op": op, "args": args or {}}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise RuntimeError("Local broker request is too large.")
        conn = http.client.HTTPConnection(self._host, self._port, timeout=timeout)
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Splunk-Broker-Token": self._auth_token,
            "Connection": "close",
        }
        try:
            conn.request("POST", "/v1/op", body=body, headers=headers)
            resp = conn.getresponse()
            status = int(resp.status)
            raw = resp.read(MAX_RESPONSE_BYTES)
        except (TimeoutError, socket.timeout):
            raise LocalSplunkBrokerTimeout(op, timeout)
        except (ConnectionError, OSError, http.client.HTTPException):
            raise RuntimeError("Local Splunk broker is unavailable. Please restart the tool.")
        finally:
            conn.close()
        parsed: dict[str, Any] = {}
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
                if not isinstance(parsed, dict):
                    parsed = {}
            except Exception:
                parsed = {}
        if status != 200:
            code = str(parsed.get("error", "broker_request_failed"))
            msg = _sanitize_text(str(parsed.get("message", "")))
            if msg:
                raise RuntimeError(msg)
            raise RuntimeError(f"Local Splunk broker request failed ({code}).")
        if not bool(parsed.get("ok")):
            code = str(parsed.get("error", "broker_operation_failed"))
            msg = _sanitize_text(str(parsed.get("message", "")))
            if msg:
                raise RuntimeError(msg)
            raise RuntimeError(f"Local Splunk broker operation failed ({code}).")
        result = parsed.get("result", {})
        if isinstance(result, dict):
            return result
        return {}

    def health(self) -> dict[str, Any]:
        return self._op("health", {})

    def shutdown_broker(self) -> bool:
        try:
            self._op("shutdown", {})
            return True
        except Exception:
            return False

    def get_runtime_config(self) -> dict[str, Any]:
        return self._op("get_runtime_config", {})

    def connect(self, server_url: str) -> dict[str, Any]:
        return self._op("connect", {"server_url": server_url}, timeout=240.0)

    def disconnect(self) -> dict[str, Any]:
        return self._op("disconnect", {})

    def validate_auth(self) -> None:
        result = self.health()
        if not bool(result.get("connected")):
            raise RuntimeError("Not connected to Splunk.")

    def list_apps(self):
        try:
            result = self._op("list_apps", {})
            apps = result.get("apps", [])
            if not isinstance(apps, list):
                raise RuntimeError("Invalid apps payload from local broker.")
            apps_clean = [str(x) for x in apps]
            self.apps_loaded.emit(apps_clean)
            return apps_clean
        except Exception as exc:
            self.error.emit(f"Failed to list apps: {exc!r}")
            raise
        finally:
            self.finished.emit()

    def list_saved_searches(self, app: str):
        try:
            result = self._op("list_saved_searches", {"app": app})
            ids = result.get("ids", [])
            names = result.get("names", [])
            email_flags = result.get("email_flags", [])
            if not (isinstance(ids, list) and isinstance(names, list) and isinstance(email_flags, list)):
                raise RuntimeError("Invalid saved-search payload from local broker.")
            ids_out = [str(x) for x in ids]
            names_out = [str(x) for x in names]
            flags_out = [bool(x) for x in email_flags]
            self.searches_loaded.emit(ids_out, names_out)
            return ids_out, names_out, flags_out
        except Exception as exc:
            self.error.emit(f"Failed to list saved searches: {exc!r}")
            raise
        finally:
            self.finished.emit()

    def dispatch_saved_search(
        self,
        report_id_url: str,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        trigger_actions: bool = True,
    ):
        trace_context = _sanitize_dispatch_trace_context(
            getattr(self, "_dispatch_trace_context", {})
        )
        payload = {
            "report_id_url": str(report_id_url or ""),
            "earliest": str(earliest or ""),
            "latest": str(latest or ""),
            "trigger_actions": bool(trigger_actions),
        }
        if trace_context:
            payload["trace_context"] = trace_context
        try:
            result = self._op(
                "dispatch_saved_search",
                payload,
                timeout=max(70.0, self._request_timeout_seconds),
            )
            return bool(result.get("ok")), str(result.get("sid", "") or "") or None, str(result.get("error", "") or "")
        except Exception as exc:
            return False, None, _safe_error_text(exc)

    def check_job_status(self, sid: str, wait_seconds: int = 10, poll_interval: int = 2):
        last_content: dict = {}
        deadline = time.monotonic() + max(1, int(wait_seconds))
        poll_seconds = max(1.0, float(poll_interval))

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            request_timeout = min(poll_seconds, max(1.0, remaining))
            state, content = self.get_job_status_snapshot(
                sid,
                request_timeout_seconds=request_timeout,
                max_total_timeout_seconds=remaining,
            )
            last_content = content
            if state in ("SUCCESS", "FAILED"):
                return state, content
            sleep_seconds = min(poll_seconds, max(0.0, deadline - time.monotonic()))
            if sleep_seconds <= 0:
                break
            time.sleep(sleep_seconds)

        return "TIMEOUT", last_content

    def get_job_status_snapshot(
        self,
        sid: str,
        request_timeout_seconds: int = 5,
        max_total_timeout_seconds: Optional[float] = None,
    ):
        payload = {
            "sid": str(sid or ""),
            "request_timeout_seconds": int(request_timeout_seconds),
        }
        op_timeout = max(1.0, float(request_timeout_seconds) + 2.0)
        if max_total_timeout_seconds is not None:
            try:
                op_timeout = min(op_timeout, max(1.0, float(max_total_timeout_seconds)))
            except Exception:
                op_timeout = max(1.0, float(request_timeout_seconds) + 2.0)
        op_start = time.monotonic()
        result = self._op("get_job_status_snapshot", payload, timeout=op_timeout)
        broker_elapsed_ms = int((time.monotonic() - op_start) * 1000)
        state = str(result.get("state", "UNKNOWN"))
        content = result.get("content", {})
        meta = result.get("meta", {})
        if isinstance(meta, dict):
            meta = dict(meta)
        else:
            meta = {}
        meta["broker_timeout_seconds"] = op_timeout
        meta["request_timeout_seconds"] = max(1.0, float(request_timeout_seconds))
        meta["broker_elapsed_ms"] = broker_elapsed_ms
        self._last_snapshot_meta = meta
        if not isinstance(content, dict):
            content = {}
        return state, content

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        del params
        result = self._op("get_saved_search_metadata", {"path": str(path or "")})
        meta = result.get("meta", {})
        if isinstance(meta, dict):
            return meta
        return {}


@dataclass
class LocalSplunkBrokerHandle:
    client: Optional[SplunkBrokerProxyClient]
    bind_host: str = ""
    bind_port: int = 0
    startup_error: str = ""
    process: Optional[subprocess.Popen[str]] = None
    auth_token: str = ""

    @property
    def is_available(self) -> bool:
        return self.client is not None and bool(self.bind_host and self.bind_port and self.auth_token)

    def unavailable_warning(self) -> str:
        if self.is_available:
            return ""
        return SPLUNK_BROKER_UNAVAILABLE_WARNING

    def shutdown(self) -> None:
        client = self.client
        if client is not None:
            try:
                client.shutdown_broker()
            except Exception:
                pass
        proc = self.process
        if proc is None:
            return
        try:
            proc.wait(timeout=2.0)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self.process = None

    def selfcheck_post(self, payload: dict[str, Any], *, token: Optional[str] = None) -> tuple[int, dict[str, Any]]:
        if not self.bind_host or not self.bind_port:
            return 0, {"ok": False, "error": "broker_not_running"}
        try:
            return _http_post_json(
                self.bind_host,
                self.bind_port,
                "/v1/op",
                payload,
                token=self.auth_token if token is None else str(token),
                timeout=2.0,
            )
        except Exception:
            return 0, {"ok": False, "error": "request_failed"}


def _spawn_ready_line(proc: subprocess.Popen[str], timeout_seconds: float) -> str:
    if proc.stdout is None:
        return ""
    holder: dict[str, str] = {"line": ""}

    def _readline() -> None:
        try:
            holder["line"] = proc.stdout.readline()
        except Exception:
            holder["line"] = ""

    t = threading.Thread(target=_readline, name="SplunkBrokerReadyRead", daemon=True)
    t.start()
    t.join(timeout_seconds)
    if t.is_alive():
        return ""
    return holder["line"] or ""


def start_local_splunk_broker(
    *,
    exe_dir: str,
    logging_broker_url: str = "",
    logging_broker_token: str = "",
) -> LocalSplunkBrokerHandle:
    cmd: list[str]
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "--run-splunk-broker", "--exe-dir", exe_dir]
    else:
        main_path = os.path.join(exe_dir, "main.py")
        cmd = [sys.executable, main_path, "--run-splunk-broker", "--exe-dir", exe_dir]
    env = os.environ.copy()
    if logging_broker_url:
        env["SPLUNK_TOOL_LOG_BROKER_URL"] = logging_broker_url
    if logging_broker_token:
        env["SPLUNK_TOOL_LOG_BROKER_TOKEN"] = logging_broker_token

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=exe_dir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        return LocalSplunkBrokerHandle(
            client=None,
            startup_error=_safe_error_text(exc),
            process=None,
        )

    ready_line = _spawn_ready_line(proc, timeout_seconds=8.0)
    if not ready_line:
        try:
            proc.terminate()
        except Exception:
            pass
        err_tail = ""
        try:
            if proc.stderr is not None:
                err_tail = proc.stderr.read(2048)
        except Exception:
            err_tail = ""
        return LocalSplunkBrokerHandle(
            client=None,
            startup_error=_sanitize_text(err_tail) or "Broker startup timeout.",
            process=None,
        )

    try:
        payload = json.loads(ready_line)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
        return LocalSplunkBrokerHandle(
            client=None,
            startup_error="Broker startup handshake failed.",
            process=None,
        )

    if not isinstance(payload, dict) or not payload.get("ok"):
        startup_error = _sanitize_text(str(payload.get("error", "Broker startup failed.")))
        try:
            proc.terminate()
        except Exception:
            pass
        return LocalSplunkBrokerHandle(
            client=None,
            startup_error=startup_error or "Broker startup failed.",
            process=None,
        )

    bind_host = str(payload.get("host", "")).strip()
    bind_port = int(payload.get("port", 0) or 0)
    auth_token = str(payload.get("token", "")).strip()
    username = str(payload.get("username", "")).strip()
    if bind_host != SPLUNK_BROKER_BIND_HOST or bind_port <= 0 or not auth_token:
        try:
            proc.terminate()
        except Exception:
            pass
        return LocalSplunkBrokerHandle(
            client=None,
            startup_error="Broker startup returned invalid metadata.",
            process=None,
        )

    client = SplunkBrokerProxyClient(host=bind_host, port=bind_port, auth_token=auth_token, username=username)
    return LocalSplunkBrokerHandle(
        client=client,
        bind_host=bind_host,
        bind_port=bind_port,
        startup_error="",
        process=proc,
        auth_token=auth_token,
    )


class _SplunkBrokerState:
    def __init__(self, exe_dir: str, audit: _AuditForwarder):
        self.exe_dir = exe_dir
        self.audit = audit
        self.lock = threading.Lock()
        self.policy = None
        self.cfg = None
        self.client: Optional[SplunkClient] = None
        self.connected_server = ""
        self.config_error = ""
        self._load_policy_and_config()

    def _load_policy_and_config(self) -> None:
        try:
            self.policy = load_security_policy(exe_dir=self.exe_dir)
            set_security_policy(self.policy)
            self.cfg = load_config(exe_dir=self.exe_dir, policy=self.policy)
            self.config_error = ""
        except Exception as exc:
            self.policy = None
            self.cfg = None
            self.config_error = _safe_error_text(exc)

    def _require_cfg(self):
        if self.cfg is None:
            raise _BrokerError(503, "config_unavailable", self.config_error or "Configuration unavailable.")
        return self.cfg

    def _require_client(self) -> SplunkClient:
        if self.client is None:
            raise _BrokerError(409, "not_connected", "Not connected to Splunk.")
        return self.client

    def _disconnect_internal(self) -> None:
        if self.client is None:
            self.connected_server = ""
            return
        try:
            if hasattr(self.client, "_auth_header"):
                self.client._auth_header = ""
            if hasattr(self.client, "session") and hasattr(self.client.session, "close"):
                self.client.session.close()
        except Exception:
            pass
        self.client = None
        self.connected_server = ""

    def _runtime_config_payload(self) -> dict[str, Any]:
        cfg = self._require_cfg()
        return {
            "servers": list(cfg.servers),
            "username": str(cfg.username),
            "verify_ssl": bool(cfg.verify_ssl),
            "config_path": str(cfg.config_path),
            "logging_level": str(cfg.logging_level),
            "logging_verbose": bool(cfg.logging_verbose),
            "logging_max_bytes": int(cfg.logging_max_bytes),
            "logging_backup_count": int(cfg.logging_backup_count),
            "file_logging_config": dict(cfg.file_logging_config) if isinstance(cfg.file_logging_config, dict) else None,
            "legacy_password_present": bool(cfg.legacy_password_present),
            "merge_report_enabled": bool(cfg.merge_report_enabled),
            "merge_report_log_path": str(cfg.merge_report_log_path or ""),
            "merge_report_timeout_seconds": int(cfg.merge_report_timeout_seconds),
            "dispatch_config": dict(cfg.dispatch_config) if isinstance(cfg.dispatch_config, dict) else None,
            "ack_enabled": bool(cfg.ack_enabled),
            "ack_on_pending": bool(getattr(cfg, "ack_on_pending", False)),
            "ack_on_unknown": bool(cfg.ack_on_unknown),
            "ack_recipients": list(cfg.ack_recipients),
            "ack_use_savedsearch_recipients": bool(cfg.ack_use_savedsearch_recipients),
            "ack_attach_manifest": bool(cfg.ack_attach_manifest),
            "smtp_host": str(cfg.smtp_host),
            "smtp_port": int(cfg.smtp_port),
            "smtp_user": str(cfg.smtp_user),
            "smtp_pass": str(cfg.smtp_pass),
            "smtp_use_tls": bool(cfg.smtp_use_tls),
            "smtp_from": str(cfg.smtp_from),
            "postdispatch_config": dict(cfg.postdispatch_config) if isinstance(cfg.postdispatch_config, dict) else None,
            "runtime_config": dict(cfg.runtime_config) if isinstance(cfg.runtime_config, dict) else None,
        }

    def op_health(self, _args: dict[str, Any]) -> dict[str, Any]:
        username = ""
        cfg = self.cfg
        if cfg is not None:
            username = str(cfg.username or "")
        return {
            "connected": self.client is not None,
            "server": self.connected_server,
            "config_loaded": self.cfg is not None,
            "config_error": self.config_error,
            "username": username,
        }

    def op_get_runtime_config(self, _args: dict[str, Any]) -> dict[str, Any]:
        return self._runtime_config_payload()

    def op_connect(self, args: dict[str, Any]) -> dict[str, Any]:
        cfg = self._require_cfg()
        server_url = _validate_string_field(args, "server_url", required=True, max_len=300)
        allowed_servers = {str(s).strip() for s in cfg.servers}
        if server_url not in allowed_servers:
            raise _BrokerError(400, "server_not_allowlisted", "Selected server is not in the approved config list.")

        self.audit.log_event("SPLUNK_CONNECT_REQUESTED", level="INFO", server=server_url)
        self._disconnect_internal()

        try:
            password, secret_path = load_or_enroll_password(
                prompt_fn=_prompt_password_for_enroll,
                exe_dir=self.exe_dir,
                logger=self.audit,
                secret_file=cfg.secret_file,
                allow_ephemeral_on_save_failure=True,
            )
            credential_persisted = bool(secret_path)
            client = SplunkClient(
                base_url=server_url,
                username=cfg.username,
                password=password,
                verify_ssl=cfg.verify_ssl,
            )
            password = ""
            client.validate_auth()
            self.client = client
            self.connected_server = server_url
            self.audit.log_event("SPLUNK_CONNECT_SUCCESS", level="INFO", server=server_url)
            return {
                "connected": True,
                "server": server_url,
                "credential_persisted": credential_persisted,
            }
        except Exception as exc:
            self._disconnect_internal()
            safe_msg = _safe_error_text(exc) or "Unable to connect to Splunk."
            self.audit.log_event("SPLUNK_CONNECT_FAILED", level="WARN", server=server_url, reason=safe_msg)
            raise _BrokerError(401, "connect_failed", safe_msg)

    def op_disconnect(self, _args: dict[str, Any]) -> dict[str, Any]:
        self._disconnect_internal()
        return {"connected": False}

    def op_list_apps(self, _args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        apps = client.list_apps()
        if not isinstance(apps, list):
            raise _BrokerError(502, "list_apps_failed", "Failed to list apps.")
        return {"apps": [str(x) for x in apps]}

    def op_list_saved_searches(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        app = _validate_string_field(args, "app", required=True, max_len=120)
        self.audit.log_event("SAVED_SEARCH_LIST_REQUESTED", level="INFO", app=app)
        payload = client.list_saved_searches(app)
        if not (isinstance(payload, tuple) and len(payload) == 3):
            raise _BrokerError(502, "list_saved_searches_failed", "Failed to list saved searches.")
        ids, names, email_flags = payload
        if not (isinstance(ids, list) and isinstance(names, list) and isinstance(email_flags, list)):
            raise _BrokerError(502, "list_saved_searches_failed", "Failed to list saved searches.")
        return {
            "ids": [str(x) for x in ids],
            "names": [str(x) for x in names],
            "email_flags": [bool(x) for x in email_flags],
        }

    def op_dispatch_saved_search(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        report_id_url = _validate_string_field(args, "report_id_url", required=True, max_len=2000)
        earliest = _validate_string_field(args, "earliest", required=False, max_len=80)
        latest = _validate_string_field(args, "latest", required=False, max_len=80)
        trigger_actions = _validate_bool_field(args, "trigger_actions", default=True)
        trace_context = _sanitize_dispatch_trace_context(args.get("trace_context", {}))
        request_context = _dispatch_request_context(report_id_url)
        trace_fields = {
            **trace_context,
            "earliest": _sanitize_text(earliest),
            "latest": _sanitize_text(latest),
            "thread_name": threading.current_thread().name,
        }
        self.audit.log_event(
            "BROKER_DISPATCH_REQUEST_RECEIVED",
            level="INFO",
            **trace_fields,
        )
        _emit_broker_debug_event(
            "DISPATCH_SAVED_SEARCH_REQUESTED",
            operation="dispatch_saved_search",
            request_format="form_body",
            earliest_time=earliest,
            latest_time=latest,
            trigger_actions=trigger_actions,
            **request_context,
        )
        op_start = time.monotonic()
        self.audit.log_event(
            "BROKER_DISPATCH_BACKEND_START",
            level="INFO",
            **trace_fields,
        )
        previous_trace_context = getattr(client, "_dispatch_trace_context", None)
        setattr(client, "_dispatch_trace_context", trace_context)
        try:
            ok, sid, err = client.dispatch_saved_search(
                report_id_url=report_id_url,
                earliest=earliest or None,
                latest=latest or None,
                trigger_actions=trigger_actions,
            )
        finally:
            if previous_trace_context is None:
                try:
                    delattr(client, "_dispatch_trace_context")
                except Exception:
                    pass
            else:
                setattr(client, "_dispatch_trace_context", previous_trace_context)
        elapsed_ms = int((time.monotonic() - op_start) * 1000)
        self.audit.log_event(
            "BROKER_DISPATCH_BACKEND_RETURN",
            level="INFO" if ok and sid else "WARN",
            **trace_fields,
            elapsed_ms=elapsed_ms,
            sid=_sanitize_text(str(sid or "")),
            exception_message=_sanitize_text(str(err or "")),
        )
        raw_meta = getattr(client, "_last_dispatch_meta", {})
        client_meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
        broker_fields = {
            "operation": "dispatch_saved_search",
            "request_format": "form_body",
            "earliest_time": earliest,
            "latest_time": latest,
            "trigger_actions": trigger_actions,
            "sid": _sanitize_text(str(sid or client_meta.get("sid", "") or "")),
            "elapsed_ms": elapsed_ms,
            "operation_elapsed_ms": elapsed_ms,
            "request_body_summary": str(client_meta.get("request_body_summary", "") or ""),
            "request_start_time": str(client_meta.get("request_start_time", "") or ""),
            "connect_timeout_seconds": client_meta.get("connect_timeout_seconds", ""),
            "read_timeout_seconds": client_meta.get("read_timeout_seconds", ""),
            "response_status_code": client_meta.get("response_status_code", ""),
            "response_headers_elapsed_ms": client_meta.get("response_headers_elapsed_ms", ""),
            "response_body_read_elapsed_ms": client_meta.get("response_body_read_elapsed_ms", ""),
            "json_parse_elapsed_ms": client_meta.get("json_parse_elapsed_ms", ""),
            "post_sid_return_work_ms": client_meta.get("post_sid_return_work_ms", ""),
            "sid_source": str(client_meta.get("sid_source", "") or ""),
            "response_location": str(client_meta.get("response_location", "") or ""),
            "response_body_snippet": str(client_meta.get("response_body_snippet", "") or ""),
            "failure_classification": str(client_meta.get("failure_classification", "") or ""),
            "transport_mode": str(client_meta.get("transport_mode", "") or ""),
            **request_context,
        }
        if client_meta.get("response_status_code", "") != "":
            _emit_broker_debug_event(
                "DISPATCH_SAVED_SEARCH_RESPONSE_HEADERS",
                **broker_fields,
            )
        if broker_fields["sid"]:
            _emit_broker_debug_event(
                "DISPATCH_SAVED_SEARCH_SID_PARSED",
                **broker_fields,
            )
        if ok and sid:
            _emit_broker_debug_event(
                "DISPATCH_SAVED_SEARCH_COMPLETED",
                **broker_fields,
            )
        else:
            _emit_broker_debug_event(
                "DISPATCH_SAVED_SEARCH_FAILED",
                level="WARN",
                error_detail=err,
                **broker_fields,
            )
        return {
            "ok": bool(ok),
            "sid": _sanitize_text(str(sid or "")),
            "error": _sanitize_text(redact_text(str(err or ""))),
        }

    def op_check_job_status(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        sid = _validate_string_field(args, "sid", required=True, max_len=200)
        if not _SID_RE.match(sid):
            raise _BrokerError(400, "invalid_sid", "Invalid SID format.")
        wait_seconds = _validate_int_field(args, "wait_seconds", default=10, min_value=1, max_value=3600)
        poll_interval = _validate_int_field(args, "poll_interval", default=2, min_value=1, max_value=60)
        state, content = client.check_job_status(sid=sid, wait_seconds=wait_seconds, poll_interval=poll_interval)
        safe_content = _redact_sensitive(content, key_hint="content")
        if not isinstance(safe_content, dict):
            safe_content = {}
        return {"state": _sanitize_text(str(state or "UNKNOWN")), "content": safe_content}

    def op_get_job_status_snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        sid = _validate_string_field(args, "sid", required=True, max_len=200)
        if not _SID_RE.match(sid):
            raise _BrokerError(400, "invalid_sid", "Invalid SID format.")
        request_timeout_seconds = _validate_int_field(
            args,
            "request_timeout_seconds",
            default=5,
            min_value=1,
            max_value=60,
        )
        start = time.monotonic()
        state, content = client.get_job_status_snapshot(
            sid=sid,
            request_timeout_seconds=request_timeout_seconds,
        )
        splunk_elapsed_ms = int((time.monotonic() - start) * 1000)
        safe_content = _redact_sensitive(content, key_hint="content")
        if not isinstance(safe_content, dict):
            safe_content = {}
        return {
            "state": _sanitize_text(str(state or "UNKNOWN")),
            "content": safe_content,
            "meta": {
                "splunk_elapsed_ms": splunk_elapsed_ms,
                "request_timeout_seconds": int(request_timeout_seconds),
            },
        }

    def op_get_saved_search_metadata(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        path = _validate_string_field(args, "path", required=True, max_len=2000)
        if not _SAVED_SEARCH_PATH_RE.match(path):
            raise _BrokerError(400, "invalid_saved_search_path", "Saved-search path is invalid.")
        meta = client._get(path)
        safe_meta = _redact_sensitive(meta, key_hint="meta")
        if not isinstance(safe_meta, dict):
            safe_meta = {}
        return {"meta": safe_meta}


class _SplunkBrokerHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, state: _SplunkBrokerState, auth_token: str):
        super().__init__((SPLUNK_BROKER_BIND_HOST, 0), _SplunkBrokerRequestHandler)
        self.state = state
        self.auth_token = auth_token
        self.state_lock = threading.Lock()
        self.rate_lock = threading.Lock()
        self.request_times: deque[float] = deque()
        self.should_shutdown = False

    def consume_rate_slot(self) -> bool:
        now = time.monotonic()
        cutoff = now - RATE_WINDOW_SECONDS
        with self.rate_lock:
            while self.request_times and self.request_times[0] < cutoff:
                self.request_times.popleft()
            if len(self.request_times) >= RATE_MAX_REQUESTS:
                return False
            self.request_times.append(now)
            return True


class _SplunkBrokerRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SplunkBroker/1.0"
    sys_version = ""

    @property
    def _server(self) -> _SplunkBrokerHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except _BrokerError as exc:
            payload = {"ok": False, "error": exc.error_code}
            if exc.message:
                payload["message"] = _sanitize_text(exc.message)
            self._send_json(exc.status, payload)
        except Exception:
            self._send_json(500, {"ok": False, "error": "internal_error"})

    def _handle_post(self) -> None:
        if self.path != "/v1/op":
            raise _BrokerError(404, "not_found")
        client_ip = str(self.client_address[0] or "")
        if client_ip != SPLUNK_BROKER_BIND_HOST:
            raise _BrokerError(403, "non_local_client")
        incoming = str(self.headers.get("X-Splunk-Broker-Token", ""))
        if not incoming:
            raise _BrokerError(401, "missing_token")
        if not hmac.compare_digest(incoming, self._server.auth_token):
            raise _BrokerError(401, "invalid_token")
        if not self._server.consume_rate_slot():
            raise _BrokerError(429, "rate_limited")

        raw_length = str(self.headers.get("Content-Length", "0")).strip()
        try:
            length = int(raw_length)
        except Exception:
            raise _BrokerError(400, "invalid_content_length")
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise _BrokerError(413, "payload_too_large")
        raw = self.rfile.read(length) if length else b"{}"
        if length and len(raw) != length:
            raise _BrokerError(400, "truncated_payload")
        payload = _parse_json_bytes(raw)
        op = _validate_string_field(payload, "op", required=True, max_len=80).lower()
        args = payload.get("args", {})
        if not isinstance(args, dict):
            raise _BrokerError(400, "invalid_args")

        with self._server.state_lock:
            result = self._dispatch_operation(op, args)
        self._send_json(200, {"ok": True, "result": result})

        if op == "shutdown":
            self._server.should_shutdown = True
            threading.Thread(target=self._server.shutdown, name="SplunkBrokerShutdown", daemon=True).start()

    def _dispatch_operation(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        state = self._server.state
        if op == "health":
            return state.op_health(args)
        if op == "get_runtime_config":
            return state.op_get_runtime_config(args)
        if op == "connect":
            return state.op_connect(args)
        if op == "disconnect":
            return state.op_disconnect(args)
        if op == "list_apps":
            return state.op_list_apps(args)
        if op == "list_saved_searches":
            return state.op_list_saved_searches(args)
        if op == "dispatch_saved_search":
            return state.op_dispatch_saved_search(args)
        if op == "check_job_status":
            return state.op_check_job_status(args)
        if op == "get_job_status_snapshot":
            return state.op_get_job_status_snapshot(args)
        if op == "get_saved_search_metadata":
            return state.op_get_saved_search_metadata(args)
        if op == "shutdown":
            return {"shutdown": True}
        raise _BrokerError(400, "unknown_operation")

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_splunk_broker_server(*, exe_dir: str) -> int:
    log_url = str(os.environ.get("SPLUNK_TOOL_LOG_BROKER_URL", "") or "").strip()
    log_token = str(os.environ.get("SPLUNK_TOOL_LOG_BROKER_TOKEN", "") or "").strip()
    audit = _AuditForwarder(log_url, log_token)
    set_security_audit_logger(audit)

    state = _SplunkBrokerState(exe_dir=exe_dir, audit=audit)
    token = secrets.token_urlsafe(32)
    try:
        server = _SplunkBrokerHTTPServer(state=state, auth_token=token)
    except Exception as exc:
        out = {"ok": False, "error": _safe_error_text(exc) or "server_start_failed"}
        print(json.dumps(out, sort_keys=True, separators=(",", ":"), ensure_ascii=True), flush=True)
        return 1

    bind_port = int(server.server_address[1])
    username = ""
    if state.cfg is not None:
        username = str(state.cfg.username or "")
    ready = {
        "ok": True,
        "host": SPLUNK_BROKER_BIND_HOST,
        "port": bind_port,
        "token": token,
        "username": username,
    }
    audit.log_event("BROKER_START", level="INFO", broker="splunk", bind_host=SPLUNK_BROKER_BIND_HOST, bind_port=bind_port, pid=os.getpid())
    print(json.dumps(ready, sort_keys=True, separators=(",", ":"), ensure_ascii=True), flush=True)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        try:
            state.op_disconnect({})
        except Exception:
            pass
        try:
            server.server_close()
        except Exception:
            pass
        audit.log_event("BROKER_STOP", level="INFO", broker="splunk", pid=os.getpid())
    return 0
