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
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import quote, unquote, urlparse

from Internal.dpapi_store import load_or_enroll_password
from Internal.security_policy import load_security_policy, redact_text
from Internal.tool_logging import debug_category_enabled, debug_event, runtime_log
from splunk_engine import (
    RECONCILIATION_WINDOW_BUFFER_SECONDS,
    SplunkClient,
    load_config,
    set_security_audit_logger,
    set_security_policy,
)


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
_EXPORT_SEARCH_PATH = "/services/search/jobs/export"
_SID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,200}$")
_BROKER_DISPATCH_WATCHDOG_SECONDS = (15, 30, 60, 120, 240)
_BROKER_METADATA_WATCHDOG_SECONDS = (5, 15, 30, 60)
BROKER_REQUEST_CLASS_DISPATCH = "dispatch_critical"
BROKER_REQUEST_CLASS_VERIFICATION = "verification_light"
BROKER_REQUEST_CLASS_EVIDENCE = "evidence_secondary"
BROKER_REQUEST_CLASS_METADATA = "metadata_background"
BROKER_BREAKER_FAILURE_THRESHOLD = 3
BROKER_BREAKER_WINDOW_SECONDS = 120.0
BROKER_BREAKER_OPEN_SECONDS = 60.0
_INTERNAL_RUNTIME_EXCEPTION_TYPES = (
    TypeError,
    ValueError,
    KeyError,
    IndexError,
    AttributeError,
    AssertionError,
)


def _normalize_saved_search_path(path: str) -> str:
    parts = str(path or "").strip().split("/")
    if len(parts) >= 7 and parts[1].lower() == "servicesns" and parts[4].lower() == "saved" and parts[5].lower() == "searches":
        report_name = unquote(parts[6])
        parts[6] = quote(report_name, safe="")
        return "/".join(parts[:7])
    return str(path or "").strip()


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


def _looks_like_auth_failure(text: str) -> bool:
    lower = str(text or "").strip().lower()
    return (
        "authentication failed" in lower
        or "unauthorized" in lower
        or "401" in lower
        or "403" in lower
        or "session expired" in lower
        or "not connected to splunk" in lower
    )


def _looks_like_network_interruption(text: str) -> bool:
    lower = str(text or "").strip().lower()
    return any(
        marker in lower
        for marker in (
            "connection aborted",
            "connection reset",
            "broken pipe",
            "remote end closed",
            "read timed out",
            "connect timeout",
            "network interruption",
        )
    )


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


def _format_trace_fields(fields: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in sorted(fields.keys()):
        value = fields.get(key)
        if value in (None, ""):
            continue
        parts.append(f"{key}={_sanitize_text(str(value))}")
    return " ".join(parts)


def _emit_broker_dispatch_runtime_trace(event: str, *, level: str = "INFO", **fields: Any) -> None:
    safe_fields = _redact_sensitive(fields, key_hint="broker_dispatch")
    if not isinstance(safe_fields, dict):
        safe_fields = {}
    message = event
    rendered_fields = _format_trace_fields(safe_fields)
    if rendered_fields:
        message = f"{message} {rendered_fields}"
    runtime_log(message, level=level)


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
        "batch_id",
        "slice_id",
        "report_name",
        "slice_label",
        "correlation_tag",
        "correlation_mode",
        "correlation_id",
        "earliest",
        "latest",
        "report_owner",
        "report_app",
        "verification_mode",
        "transport_mode",
        "thread_name",
    ):
        raw = value.get(key)
        if raw not in (None, ""):
            out[key] = _sanitize_text(str(raw))
    for key in ("slice_index", "slice_total", "attempt_id"):
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


class LocalSplunkBrokerRequestError(RuntimeError):
    def __init__(self, op: str, status: int, error_code: str, message: str = "") -> None:
        self.broker_op = str(op or "").strip()
        self.status = int(status)
        self.error_code = str(error_code or "broker_request_failed").strip() or "broker_request_failed"
        detail = _sanitize_text(message or "")
        parts = [f"op={self.broker_op or 'unknown'}", f"category={self.error_code}", f"status={self.status}"]
        rendered = "Local Splunk broker request failed (" + ", ".join(parts) + ")"
        if detail:
            rendered += f": {detail}"
        super().__init__(rendered)


LocalSplunkBrokerOperationError = LocalSplunkBrokerRequestError


@dataclass(frozen=True)
class _BrokerLaneSpec:
    request_class: str
    lane_name: str
    max_workers: int
    connect_timeout_seconds: float
    read_timeout_seconds: float
    total_budget_seconds: float


@dataclass
class _BrokerRequestContext:
    request_id: str
    op: str
    request_class: str
    lane_name: str
    queue_budget_seconds: float
    enqueued_monotonic: float
    enqueue_utc: str
    cleanup_callbacks: list[Callable[[], None]] = field(default_factory=list)
    started_monotonic: float = 0.0
    start_utc: str = ""
    processing_ms: int = 0
    total_elapsed_ms: int = 0
    queue_wait_ms: int = 0
    lane_active_at_enqueue: int = 0
    lane_busy_at_enqueue: bool = False
    result_category: str = ""
    session_recycled: bool = False
    breaker_state: str = ""
    half_open_probe: bool = False
    timed_out: bool = False


@dataclass
class _BrokerBreakerState:
    failures: deque[float] = field(default_factory=deque)
    open_until: float = 0.0
    half_open_probe_inflight: bool = False


_BROKER_LANE_SPECS: dict[str, _BrokerLaneSpec] = {
    BROKER_REQUEST_CLASS_DISPATCH: _BrokerLaneSpec(
        request_class=BROKER_REQUEST_CLASS_DISPATCH,
        lane_name="dispatch",
        max_workers=1,
        connect_timeout_seconds=3.0,
        read_timeout_seconds=30.0,
        total_budget_seconds=35.0,
    ),
    BROKER_REQUEST_CLASS_VERIFICATION: _BrokerLaneSpec(
        request_class=BROKER_REQUEST_CLASS_VERIFICATION,
        lane_name="verification",
        max_workers=2,
        connect_timeout_seconds=2.0,
        read_timeout_seconds=10.0,
        total_budget_seconds=12.0,
    ),
    BROKER_REQUEST_CLASS_EVIDENCE: _BrokerLaneSpec(
        request_class=BROKER_REQUEST_CLASS_EVIDENCE,
        lane_name="evidence",
        max_workers=1,
        connect_timeout_seconds=2.0,
        read_timeout_seconds=8.0,
        total_budget_seconds=10.0,
    ),
    BROKER_REQUEST_CLASS_METADATA: _BrokerLaneSpec(
        request_class=BROKER_REQUEST_CLASS_METADATA,
        lane_name="metadata",
        max_workers=1,
        connect_timeout_seconds=2.0,
        read_timeout_seconds=10.0,
        total_budget_seconds=12.0,
    ),
}


def _broker_request_class_for_op(op: str) -> str:
    safe_op = str(op or "").strip().lower()
    if safe_op in {"dispatch_saved_search"}:
        return BROKER_REQUEST_CLASS_DISPATCH
    if safe_op in {"get_job_status_snapshot", "check_job_status"}:
        return BROKER_REQUEST_CLASS_VERIFICATION
    if safe_op in {"find_job_candidates", "export_search_json"}:
        return BROKER_REQUEST_CLASS_EVIDENCE
    return BROKER_REQUEST_CLASS_METADATA


def _broker_lane_spec_for_op(op: str) -> _BrokerLaneSpec:
    return _BROKER_LANE_SPECS[_broker_request_class_for_op(op)]


def _broker_timeout_category(request_class: str) -> str:
    if request_class == BROKER_REQUEST_CLASS_DISPATCH:
        return "timeout_dispatch_unknown"
    if request_class == BROKER_REQUEST_CLASS_VERIFICATION:
        return "timeout_verification_delay"
    if request_class == BROKER_REQUEST_CLASS_EVIDENCE:
        return "timeout_evidence_delay"
    return "timeout_metadata_fetch"


def _broker_result_category_for_exception(request_class: str, exc: Exception) -> tuple[int, str, str]:
    if isinstance(exc, _BrokerError):
        return exc.status, exc.error_code, str(exc.message or exc.error_code)
    if isinstance(exc, _INTERNAL_RUNTIME_EXCEPTION_TYPES):
        safe_msg = _safe_error_text(exc)
        return 500, "internal_runtime_error", safe_msg or "Internal runtime error while processing broker request."
    safe_msg = _safe_error_text(exc)
    lower = safe_msg.lower()
    if _looks_like_auth_failure(safe_msg):
        return 401, "auth_expired", safe_msg or "Authentication expired while talking to Splunk."
    if "timeout" in lower:
        return 504, _broker_timeout_category(request_class), safe_msg or "Broker request timed out."
    if _looks_like_network_interruption(safe_msg):
        return 503, "transport_interrupted", safe_msg or "Transport interruption while talking to Splunk."
    if "connection" in lower or "temporarily unavailable" in lower:
        return 503, "retryable_connection_failure", safe_msg or "Retryable connection failure while talking to Splunk."
    if request_class == BROKER_REQUEST_CLASS_METADATA:
        return 502, "failed_metadata_fetch", safe_msg or "Metadata fetch failed."
    return 502, "nonretryable_request_failure", safe_msg or "Broker request failed."


def _broker_failure_counts_toward_breaker(error_code: str) -> bool:
    normalized = str(error_code or "").strip().lower()
    return normalized in {
        "timeout_dispatch_unknown",
        "timeout_verification_delay",
        "timeout_evidence_delay",
        "timeout_metadata_fetch",
        "failed_metadata_fetch",
        "broker_overloaded",
        "transport_interrupted",
        "retryable_connection_failure",
    }


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


def _validate_params_field(
    data: dict[str, Any],
    key: str,
    *,
    allowed_keys: Optional[set[str]] = None,
    max_items: int = 20,
) -> dict[str, Any]:
    if key not in data:
        return {}
    value = data.get(key)
    if not isinstance(value, dict):
        raise _BrokerError(400, f"invalid_type_{key}")
    if len(value) > max_items:
        raise _BrokerError(400, f"invalid_length_{key}")
    sanitized: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            raise _BrokerError(400, f"invalid_type_{key}")
        safe_key = _sanitize_text(raw_key)
        if not safe_key:
            raise _BrokerError(400, f"invalid_{key}_name")
        if allowed_keys is not None and safe_key not in allowed_keys:
            raise _BrokerError(400, f"invalid_{key}_name")
        if raw_value is None:
            continue
        if isinstance(raw_value, str):
            sanitized[safe_key] = _sanitize_text(raw_value)
            continue
        if isinstance(raw_value, bool):
            sanitized[safe_key] = raw_value
            continue
        if isinstance(raw_value, (int, float)) and not isinstance(raw_value, bool):
            sanitized[safe_key] = raw_value
            continue
        raise _BrokerError(400, f"invalid_type_{key}")
    return sanitized


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
    connect_timeout = max(1.0, min(5.0, float(timeout)))
    read_timeout = max(1.0, float(timeout))
    conn = http.client.HTTPConnection(host, port, timeout=connect_timeout)
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        token_header: token,
        "Connection": "close",
    }
    try:
        conn.connect()
        if conn.sock is not None:
            conn.sock.settimeout(read_timeout)
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
        self._last_dispatch_meta: dict[str, Any] = {}
        self._connected_server_url = ""
        self._broker_tainted = False
        self._broker_taint_reason = ""
        self._broker_taint_op = ""
        self._broker_recycler = None
        self._broker_recycle_lock = threading.Lock()
        self._broker_recycle_in_progress = False

    def configure_request_timeout(self, timeout_seconds: float) -> None:
        try:
            self._request_timeout_seconds = max(1.0, float(timeout_seconds))
        except Exception:
            self._request_timeout_seconds = 300.0

    def install_broker_recycler(self, recycler) -> None:
        self._broker_recycler = recycler

    def needs_transport_reset(self) -> bool:
        return bool(self._broker_tainted)

    def transport_reset_reason(self) -> str:
        if not self._broker_tainted:
            return ""
        op = str(self._broker_taint_op or "").strip() or "unknown_op"
        reason = str(self._broker_taint_reason or "").strip() or "broker_tainted"
        return f"{reason}_after_{op}"

    def _mark_broker_tainted(self, op: str, reason: str) -> None:
        self._broker_tainted = True
        self._broker_taint_op = str(op or "").strip()
        self._broker_taint_reason = _sanitize_text(reason or "broker_request_failed")
        _emit_broker_dispatch_runtime_trace(
            "BROKER_TRANSPORT_TAINTED",
            level="WARN",
            operation=self._broker_taint_op,
            reason=self._broker_taint_reason,
            bind_host=self._host,
            bind_port=self._port,
        )

    def _clear_broker_taint(self) -> None:
        self._broker_tainted = False
        self._broker_taint_op = ""
        self._broker_taint_reason = ""

    def _ensure_healthy_broker(self, op: str) -> None:
        if str(op or "").strip().lower() == "shutdown":
            return
        if (not self._broker_tainted) or self._broker_recycle_in_progress:
            return
        recycler = self._broker_recycler
        if not callable(recycler):
            return
        with self._broker_recycle_lock:
            if (not self._broker_tainted) or self._broker_recycle_in_progress:
                return
            reason = self.transport_reset_reason() or "broker_tainted"
            self._broker_recycle_in_progress = True
            try:
                _emit_broker_dispatch_runtime_trace(
                    "BROKER_RECYCLE_START",
                    level="WARN",
                    operation=op,
                    reason=reason,
                    bind_host=self._host,
                    bind_port=self._port,
                )
                recycler(reason=reason)
                self._clear_broker_taint()
                _emit_broker_dispatch_runtime_trace(
                    "BROKER_RECYCLE_DONE",
                    level="INFO",
                    operation=op,
                    reason=reason,
                    bind_host=self._host,
                    bind_port=self._port,
                )
            finally:
                self._broker_recycle_in_progress = False

    def reset_transport(self) -> None:
        self._last_snapshot_meta = {}
        for attr in ("_dispatch_trace_context", "_last_dispatch_meta", "_last_dispatch_call_budget_meta"):
            if hasattr(self, attr):
                try:
                    setattr(self, attr, {})
                except Exception:
                    pass
        if self._broker_tainted:
            self._ensure_healthy_broker("reset_transport")

    def close_transport(self) -> None:
        self.reset_transport()

    def _request_timeout_budget(self, op: str, requested_timeout: float) -> float:
        safe_op = str(op or "").strip().lower()
        if safe_op in {"connect", "disconnect", "shutdown", "health", "get_runtime_config"}:
            return max(1.0, float(requested_timeout))
        spec = _broker_lane_spec_for_op(safe_op)
        return max(1.0, min(float(requested_timeout), float(spec.total_budget_seconds)))

    def _send_op_request(self, op: str, args: Optional[dict[str, Any]] = None, *, timeout: float = 30.0) -> tuple[int, dict[str, Any]]:
        self._ensure_healthy_broker(op)
        payload = {"op": op, "args": args or {}}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise RuntimeError("Local broker request is too large.")
        safe_op = str(op or "").strip().lower()
        if safe_op in {"connect", "disconnect", "shutdown", "health", "get_runtime_config"}:
            connect_timeout = max(1.0, min(5.0, float(timeout)))
            read_timeout = max(1.0, float(timeout))
            request_class = "lifecycle"
            lane_name = "inline"
        else:
            spec = _broker_lane_spec_for_op(safe_op)
            connect_timeout = float(spec.connect_timeout_seconds)
            read_timeout = self._request_timeout_budget(safe_op, timeout)
            request_class = spec.request_class
            lane_name = spec.lane_name
        conn = http.client.HTTPConnection(self._host, self._port, timeout=connect_timeout)
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Splunk-Broker-Token": self._auth_token,
            "Connection": "close",
        }
        request_started = time.monotonic()
        _emit_broker_dispatch_runtime_trace(
            "BROKER_PROXY_REQUEST_START",
            level="INFO",
            operation=safe_op,
            request_class=request_class,
            lane_name=lane_name,
            timeout_seconds=int(round(read_timeout)),
            connect_timeout_seconds=connect_timeout,
            bind_host=self._host,
            bind_port=self._port,
        )
        try:
            conn.connect()
            if conn.sock is not None:
                conn.sock.settimeout(read_timeout)
            conn.request("POST", "/v1/op", body=body, headers=headers)
            resp = conn.getresponse()
            status = int(resp.status)
            raw = resp.read(MAX_RESPONSE_BYTES)
        except (TimeoutError, socket.timeout):
            self._mark_broker_tainted(op, "broker_timeout")
            raise LocalSplunkBrokerTimeout(op, read_timeout)
        except (ConnectionError, OSError, http.client.HTTPException):
            failure_text = _sanitize_text(str(sys.exc_info()[1] or ""))
            taint_reason = "transport_interrupted" if _looks_like_network_interruption(failure_text) else "broker_connection_error"
            self._mark_broker_tainted(op, taint_reason)
            if taint_reason == "transport_interrupted":
                raise LocalSplunkBrokerRequestError(op, 503, "transport_interrupted", "Local broker transport was interrupted.")
            raise LocalSplunkBrokerRequestError(op, 503, "retryable_connection_failure", "Local Splunk broker is unavailable. Please restart the tool.")
        finally:
            conn.close()
            _emit_broker_dispatch_runtime_trace(
                "BROKER_PROXY_REQUEST_END",
                level="INFO",
                operation=safe_op,
                request_class=request_class,
                lane_name=lane_name,
                elapsed_ms=int((time.monotonic() - request_started) * 1000),
                bind_host=self._host,
                bind_port=self._port,
            )
        parsed: dict[str, Any] = {}
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
                if not isinstance(parsed, dict):
                    parsed = {}
            except Exception:
                parsed = {}
        return status, parsed

    def _response_requires_reconnect(self, status: int, parsed: dict[str, Any]) -> bool:
        code = str(parsed.get("error", "") or "").strip().lower()
        message = _sanitize_text(str(parsed.get("message", "") or ""))
        return (
            status in (401, 403)
            or code in {"not_connected", "connect_failed", "splunk_auth_failed"}
            or _looks_like_auth_failure(message)
        )

    def _reconnect_to_splunk(self, *, reason: str) -> bool:
        if not str(self._connected_server_url or "").strip():
            return False
        _emit_broker_dispatch_runtime_trace(
            "BROKER_PROXY_RECONNECT_START",
            level="WARN",
            reason=reason,
            bind_host=self._host,
            bind_port=self._port,
        )
        try:
            status, parsed = self._send_op_request(
                "connect",
                {"server_url": self._connected_server_url},
                timeout=240.0,
            )
        except Exception as exc:
            _emit_broker_dispatch_runtime_trace(
                "BROKER_PROXY_RECONNECT_FAILED",
                level="WARN",
                reason=reason,
                error_detail=_safe_error_text(exc),
                bind_host=self._host,
                bind_port=self._port,
            )
            return False
        if status == 200 and bool(parsed.get("ok")):
            _emit_broker_dispatch_runtime_trace(
                "BROKER_PROXY_RECONNECT_DONE",
                level="INFO",
                reason=reason,
                bind_host=self._host,
                bind_port=self._port,
            )
            return True
        _emit_broker_dispatch_runtime_trace(
            "BROKER_PROXY_RECONNECT_FAILED",
            level="WARN",
            reason=reason,
            error_code=str(parsed.get("error", "") or ""),
            error_detail=_sanitize_text(str(parsed.get("message", "") or "")),
            bind_host=self._host,
            bind_port=self._port,
        )
        return False

    def _op(
        self,
        op: str,
        args: Optional[dict[str, Any]] = None,
        *,
        timeout: float = 30.0,
        allow_reconnect: bool = True,
    ) -> dict[str, Any]:
        status, parsed = self._send_op_request(op, args, timeout=timeout)
        if allow_reconnect and str(op or "").strip().lower() != "connect" and self._response_requires_reconnect(status, parsed):
            reconnect_reason = str(parsed.get("error", "") or parsed.get("message", "") or "splunk_reconnect_required")
            if self._reconnect_to_splunk(reason=reconnect_reason):
                status, parsed = self._send_op_request(op, args, timeout=timeout)
        if status != 200:
            code = str(parsed.get("error", "broker_request_failed"))
            msg = _sanitize_text(str(parsed.get("message", "")))
            if self._response_requires_reconnect(status, parsed):
                raise LocalSplunkBrokerRequestError(op, status, "auth_expired", "Broker-side Splunk authentication or connection state could not be refreshed.")
            raise LocalSplunkBrokerRequestError(op, status, code, msg)
        if not bool(parsed.get("ok")):
            code = str(parsed.get("error", "broker_operation_failed"))
            msg = _sanitize_text(str(parsed.get("message", "")))
            if self._response_requires_reconnect(status, parsed):
                raise LocalSplunkBrokerRequestError(op, status, "auth_expired", "Broker-side Splunk authentication or connection state could not be refreshed.")
            raise LocalSplunkBrokerRequestError(op, status, code, msg)
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
        result = self._op("connect", {"server_url": server_url}, timeout=240.0)
        self._connected_server_url = str(server_url or "").strip()
        return result

    def disconnect(self) -> dict[str, Any]:
        result = self._op("disconnect", {})
        self._connected_server_url = ""
        return result

    def validate_auth(self) -> None:
        result = self.health()
        if not bool(result.get("connected")):
            raise RuntimeError("Not connected to Splunk.")

    def list_apps(self):
        try:
            result = self._op(
                "list_apps",
                {},
                timeout=_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_METADATA].total_budget_seconds,
            )
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
            result = self._op(
                "list_saved_searches",
                {"app": app},
                timeout=_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_METADATA].total_budget_seconds,
            )
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
        request_timeout_seconds: Optional[float] = None,
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
            requested_timeout = (
                float(request_timeout_seconds)
                if request_timeout_seconds is not None
                else float(self._request_timeout_seconds)
            )
            op_timeout = min(
                _BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_DISPATCH].total_budget_seconds,
                max(
                    1.0,
                    min(requested_timeout, float(_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_DISPATCH].read_timeout_seconds))
                    + 1.0,
                ),
            )
            recent_metadata = getattr(self, "_recent_metadata_activity", {})
            if not isinstance(recent_metadata, dict):
                recent_metadata = {}
            recent_cleanup = getattr(self, "_recent_transport_cleanup", {})
            if not isinstance(recent_cleanup, dict):
                recent_cleanup = {}
            preflight_dispatch_lane_active = 0
            preflight_dispatch_recent_timeouts = 0
            preflight_metadata_recent_timeouts = 0
            preflight_health_observed = False
            preflight_recycle_triggered = False
            try:
                health_payload = self.health()
            except Exception:
                health_payload = {}
            if isinstance(health_payload, dict):
                broker_runtime = health_payload.get("broker_runtime", {})
                if isinstance(broker_runtime, dict):
                    preflight_health_observed = True
                    active_by_class = broker_runtime.get("active_requests_by_class", {})
                    if isinstance(active_by_class, dict):
                        try:
                            preflight_dispatch_lane_active = max(
                                0,
                                int(active_by_class.get(BROKER_REQUEST_CLASS_DISPATCH, 0) or 0),
                            )
                        except Exception:
                            preflight_dispatch_lane_active = 0
                    timeout_by_class = broker_runtime.get("recent_timeout_count_by_class", {})
                    if isinstance(timeout_by_class, dict):
                        try:
                            preflight_dispatch_recent_timeouts = max(
                                0,
                                int(timeout_by_class.get(BROKER_REQUEST_CLASS_DISPATCH, 0) or 0),
                            )
                        except Exception:
                            preflight_dispatch_recent_timeouts = 0
                        try:
                            preflight_metadata_recent_timeouts = max(
                                0,
                                int(timeout_by_class.get(BROKER_REQUEST_CLASS_METADATA, 0) or 0),
                            )
                        except Exception:
                            preflight_metadata_recent_timeouts = 0
            self._last_dispatch_meta = {
                "request_class": BROKER_REQUEST_CLASS_DISPATCH,
                "broker_lane_name": _BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_DISPATCH].lane_name,
                "broker_timeout_seconds": op_timeout,
                "transport_freshness": "fresh_proxy_request",
                "recent_metadata_outcome": str(recent_metadata.get("outcome", "") or ""),
                "recent_metadata_elapsed_ms": recent_metadata.get("elapsed_ms", ""),
                "recent_metadata_age_ms": recent_metadata.get("age_ms", ""),
                "recent_metadata_path": str(recent_metadata.get("path", "") or ""),
                "recent_transport_cleanup_reason": str(recent_cleanup.get("reason", "") or ""),
                "recent_transport_cleanup_age_ms": recent_cleanup.get("age_ms", ""),
                "recent_transport_cleanup_operation": str(recent_cleanup.get("operation", "") or ""),
                "preflight_dispatch_lane_active": preflight_dispatch_lane_active,
                "preflight_dispatch_recent_timeouts": preflight_dispatch_recent_timeouts,
                "preflight_metadata_recent_timeouts": preflight_metadata_recent_timeouts,
                "preflight_health_observed": bool(preflight_health_observed),
                "preflight_recycle_triggered": False,
            }
            if preflight_dispatch_lane_active > 0:
                preflight_recycle_triggered = True
                self._last_dispatch_meta["preflight_recycle_triggered"] = True
                self._last_dispatch_meta["preflight_recycle_reason"] = "dispatch_lane_busy_preflight"
                self._mark_broker_tainted("dispatch_saved_search", "dispatch_lane_busy_preflight")
                self._ensure_healthy_broker("dispatch_saved_search")
            result = self._op(
                "dispatch_saved_search",
                payload,
                timeout=op_timeout,
            )
            meta = result.get("meta", {})
            broker_request_meta = result.get("_broker_request_meta", {})
            merged_meta = dict(self._last_dispatch_meta)
            if isinstance(meta, dict):
                merged_meta.update(meta)
            if isinstance(broker_request_meta, dict):
                merged_meta["broker_request_id"] = str(broker_request_meta.get("request_id", "") or "")
                merged_meta["broker_request_class"] = str(broker_request_meta.get("request_class", "") or "")
                merged_meta["broker_lane_name"] = str(broker_request_meta.get("lane_name", "") or merged_meta.get("broker_lane_name", ""))
                merged_meta["broker_queue_wait_ms"] = broker_request_meta.get("queue_wait_ms", "")
                merged_meta["broker_processing_ms"] = broker_request_meta.get("processing_ms", "")
                merged_meta["broker_total_elapsed_ms"] = broker_request_meta.get("total_elapsed_ms", "")
                merged_meta["broker_lane_active_at_enqueue"] = broker_request_meta.get("lane_active_at_enqueue", "")
                merged_meta["broker_lane_busy_at_enqueue"] = broker_request_meta.get("lane_busy_at_enqueue", "")
                merged_meta["broker_result_category"] = str(broker_request_meta.get("result_category", "") or "")
            merged_meta["preflight_dispatch_lane_active"] = preflight_dispatch_lane_active
            merged_meta["preflight_dispatch_recent_timeouts"] = preflight_dispatch_recent_timeouts
            merged_meta["preflight_metadata_recent_timeouts"] = preflight_metadata_recent_timeouts
            merged_meta["preflight_health_observed"] = bool(preflight_health_observed)
            merged_meta["preflight_recycle_triggered"] = bool(preflight_recycle_triggered)
            self._last_dispatch_meta = merged_meta
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
        retry_count: int = 0,
        stage_name: str = "",
    ):
        payload = {
            "sid": str(sid or ""),
            "request_timeout_seconds": int(request_timeout_seconds),
            "retry_count": int(retry_count or 0),
            "stage_name": str(stage_name or ""),
        }
        op_timeout = min(
            _BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_VERIFICATION].total_budget_seconds,
            max(
                1.0,
                min(
                    float(_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_VERIFICATION].read_timeout_seconds),
                    float(request_timeout_seconds),
                )
                + 1.0,
            ),
        )
        if max_total_timeout_seconds is not None:
            try:
                op_timeout = min(op_timeout, max(1.0, float(max_total_timeout_seconds)))
            except Exception:
                op_timeout = min(
                    _BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_VERIFICATION].total_budget_seconds,
                    max(
                        1.0,
                        min(
                            float(_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_VERIFICATION].read_timeout_seconds),
                            float(request_timeout_seconds),
                        )
                        + 1.0,
                    ),
                )
        op_start = time.monotonic()
        result = self._op("get_job_status_snapshot", payload, timeout=op_timeout)
        broker_elapsed_ms = int((time.monotonic() - op_start) * 1000)
        state = str(result.get("state", "UNKNOWN"))
        content = result.get("content", {})
        meta = result.get("meta", {})
        broker_request_meta = result.get("_broker_request_meta", {})
        if isinstance(meta, dict):
            meta = dict(meta)
        else:
            meta = {}
        if isinstance(broker_request_meta, dict):
            meta["broker_request_id"] = str(broker_request_meta.get("request_id", "") or "")
            meta["broker_request_class"] = str(broker_request_meta.get("request_class", "") or "")
            meta["broker_lane_name"] = str(broker_request_meta.get("lane_name", "") or "")
            meta["queue_wait_ms"] = broker_request_meta.get("queue_wait_ms", "")
            meta["processing_ms"] = broker_request_meta.get("processing_ms", "")
            meta["total_elapsed_ms"] = broker_request_meta.get("total_elapsed_ms", "")
            meta["lane_active_at_enqueue"] = broker_request_meta.get("lane_active_at_enqueue", "")
            meta["lane_busy_at_enqueue"] = broker_request_meta.get("lane_busy_at_enqueue", "")
            meta["broker_result_category"] = str(broker_request_meta.get("result_category", "") or "")
        meta["broker_timeout_seconds"] = op_timeout
        meta["request_timeout_seconds"] = max(1.0, float(request_timeout_seconds))
        meta["broker_elapsed_ms"] = broker_elapsed_ms
        self._last_snapshot_meta = meta
        if not isinstance(content, dict):
            content = {}
        return state, content

    def find_job_candidates(
        self,
        *,
        label: str = "",
        owner: str = "",
        app: str = "",
        dispatch_earliest: str = "",
        dispatch_latest: str = "",
        correlation_tag: str = "",
        limit: int = 50,
        page_size: int = 25,
        window_buffer_seconds: int = RECONCILIATION_WINDOW_BUFFER_SECONDS,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(100, int(limit or 50)))
        safe_page_size = max(1, min(50, int(page_size or 25)))
        result = self._op(
            "find_job_candidates",
            {
                "label": str(label or "").strip(),
                "owner": str(owner or "").strip(),
                "app": str(app or "").strip(),
                "dispatch_earliest": str(dispatch_earliest or "").strip(),
                "dispatch_latest": str(dispatch_latest or "").strip(),
                "correlation_tag": str(correlation_tag or "").strip(),
                "limit": safe_limit,
                "page_size": safe_page_size,
                "window_buffer_seconds": max(0, int(window_buffer_seconds or 0)),
            },
            timeout=_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_EVIDENCE].total_budget_seconds,
        )
        jobs = result.get("jobs", [])
        if not isinstance(jobs, list):
            return []
        return [dict(job) for job in jobs if isinstance(job, dict)]

    def _get(
        self,
        path: str,
        params: Optional[dict] = None,
        *,
        timeout: int = 60,
        connect_timeout_seconds: Optional[float] = None,
    ) -> dict:
        del connect_timeout_seconds
        normalized_path = urlparse(str(path or "")).path or str(path or "")
        if str(normalized_path or "").strip().lower() == _EXPORT_SEARCH_PATH:
            result = self._op(
                "export_search_json",
                {"path": _EXPORT_SEARCH_PATH, "params": dict(params or {})},
                timeout=self._request_timeout_budget("export_search_json", float(timeout or 60.0)),
            )
            data = result.get("data", {})
            if isinstance(data, dict):
                return data
            return {}
        result = self._op(
            "get_saved_search_metadata",
            {"path": str(path or "")},
            timeout=self._request_timeout_budget("get_saved_search_metadata", float(timeout or 60.0)),
        )
        meta = result.get("meta", {})
        if isinstance(meta, dict):
            return meta
        return {}

    def export_search_json(self, search_query: str, *, earliest_time: str = "-1s", timeout_seconds: int = 60) -> dict:
        result = self._op(
            "export_search_json",
            {
                "path": _EXPORT_SEARCH_PATH,
                "params": {
                    "search": str(search_query or ""),
                    "earliest_time": str(earliest_time or "-1s"),
                    "output_mode": "json",
                },
            },
            timeout=self._request_timeout_budget("export_search_json", float(timeout_seconds or 60.0)),
        )
        data = result.get("data", {})
        if isinstance(data, dict):
            return data
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


def _launch_local_splunk_broker(
    *,
    exe_dir: str,
    logging_broker_url: str = "",
    logging_broker_token: str = "",
) -> tuple[Optional[subprocess.Popen[str]], str, int, str, str]:
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
        return None, "", 0, "", _safe_error_text(exc)

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
        return None, "", 0, "", _sanitize_text(err_tail) or "Broker startup timeout."

    try:
        payload = json.loads(ready_line)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
        return None, "", 0, "", "Broker startup handshake failed."

    if not isinstance(payload, dict) or not payload.get("ok"):
        startup_error = _sanitize_text(str(payload.get("error", "Broker startup failed.")))
        try:
            proc.terminate()
        except Exception:
            pass
        return None, "", 0, "", startup_error or "Broker startup failed."

    bind_host = str(payload.get("host", "")).strip()
    bind_port = int(payload.get("port", 0) or 0)
    auth_token = str(payload.get("token", "")).strip()
    username = str(payload.get("username", "")).strip()
    if bind_host != SPLUNK_BROKER_BIND_HOST or bind_port <= 0 or not auth_token:
        try:
            proc.terminate()
        except Exception:
            pass
        return None, "", 0, "", "Broker startup returned invalid metadata."

    return proc, bind_host, bind_port, auth_token, username


def start_local_splunk_broker(
    *,
    exe_dir: str,
    logging_broker_url: str = "",
    logging_broker_token: str = "",
) -> LocalSplunkBrokerHandle:
    proc, bind_host, bind_port, auth_token, username_or_error = _launch_local_splunk_broker(
        exe_dir=exe_dir,
        logging_broker_url=logging_broker_url,
        logging_broker_token=logging_broker_token,
    )
    if proc is None:
        return LocalSplunkBrokerHandle(
            client=None,
            startup_error=username_or_error,
            process=None,
        )
    username = username_or_error
    client = SplunkBrokerProxyClient(host=bind_host, port=bind_port, auth_token=auth_token, username=username)
    handle = LocalSplunkBrokerHandle(
        client=client,
        bind_host=bind_host,
        bind_port=bind_port,
        startup_error="",
        process=proc,
        auth_token=auth_token,
    )
    recycle_lock = threading.Lock()

    def _recycle_broker(*, reason: str = "") -> None:
        del reason
        with recycle_lock:
            old_proc = handle.process
            old_host = handle.bind_host
            old_port = handle.bind_port
            old_token = handle.auth_token
            connected_server = str(client._connected_server_url or "").strip()

            new_proc, new_host, new_port, new_token, new_username = _launch_local_splunk_broker(
                exe_dir=exe_dir,
                logging_broker_url=logging_broker_url,
                logging_broker_token=logging_broker_token,
            )
            if new_proc is None:
                raise RuntimeError(new_username or "Broker recycle failed.")

            connect_error = ""
            if connected_server:
                status, payload = _http_post_json(
                    new_host,
                    new_port,
                    "/v1/op",
                    {"op": "connect", "args": {"server_url": connected_server}},
                    token=new_token,
                    timeout=240.0,
                )
                if status != 200 or (not bool(payload.get("ok"))):
                    connect_error = _sanitize_text(str(payload.get("message", ""))) or "Broker reconnect failed."

            if connect_error:
                try:
                    _http_post_json(
                        new_host,
                        new_port,
                        "/v1/op",
                        {"op": "shutdown", "args": {}},
                        token=new_token,
                        timeout=2.0,
                    )
                except Exception:
                    pass
                try:
                    new_proc.wait(timeout=2.0)
                except Exception:
                    try:
                        new_proc.kill()
                    except Exception:
                        pass
                raise RuntimeError(connect_error)

            handle.process = new_proc
            handle.bind_host = new_host
            handle.bind_port = new_port
            handle.auth_token = new_token
            handle.startup_error = ""
            client._host = new_host
            client._port = new_port
            client._auth_token = new_token
            client.username = new_username

            if old_proc is not None:
                try:
                    if old_host and old_port and old_token:
                        _http_post_json(
                            old_host,
                            old_port,
                            "/v1/op",
                            {"op": "shutdown", "args": {}},
                            token=old_token,
                            timeout=2.0,
                        )
                except Exception:
                    pass
                try:
                    old_proc.wait(timeout=2.0)
                except Exception:
                    try:
                        old_proc.terminate()
                    except Exception:
                        pass
                    try:
                        old_proc.wait(timeout=2.0)
                    except Exception:
                        try:
                            old_proc.kill()
                        except Exception:
                            pass

    client.install_broker_recycler(_recycle_broker)
    return handle


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
        self._ensure_runtime_initialized()

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

    def _ensure_runtime_initialized(self) -> None:
        runtime_lock = getattr(self, "_runtime_init_lock", None)
        if runtime_lock is None:
            runtime_lock = threading.Lock()
            self._runtime_init_lock = runtime_lock
        with runtime_lock:
            if not hasattr(self, "_request_local") or self._request_local is None:
                self._request_local = threading.local()
            if not hasattr(self, "_runtime_metrics_lock") or self._runtime_metrics_lock is None:
                self._runtime_metrics_lock = threading.Lock()
            if not hasattr(self, "_breaker_lock") or self._breaker_lock is None:
                self._breaker_lock = threading.Lock()
            if not hasattr(self, "_breakers") or not isinstance(self._breakers, dict):
                self._breakers = {
                    request_class: _BrokerBreakerState()
                    for request_class in _BROKER_LANE_SPECS.keys()
                }
            if not hasattr(self, "_active_requests_by_class") or not isinstance(self._active_requests_by_class, dict):
                self._active_requests_by_class = {
                    request_class: 0 for request_class in _BROKER_LANE_SPECS.keys()
                }
            if not hasattr(self, "_recent_timeout_count_by_class") or not isinstance(self._recent_timeout_count_by_class, dict):
                self._recent_timeout_count_by_class = {
                    request_class: 0 for request_class in _BROKER_LANE_SPECS.keys()
                }
            if not hasattr(self, "_session_recycle_count"):
                self._session_recycle_count = 0
            executors = getattr(self, "_lane_executors", None)
            if not isinstance(executors, dict):
                self._lane_executors = {
                    request_class: ThreadPoolExecutor(
                        max_workers=spec.max_workers,
                        thread_name_prefix=f"splunk-broker-{spec.lane_name}",
                    )
                    for request_class, spec in _BROKER_LANE_SPECS.items()
                }

    def shutdown_runtime(self) -> None:
        self._ensure_runtime_initialized()
        executors = getattr(self, "_lane_executors", {})
        if not isinstance(executors, dict):
            return
        for executor in executors.values():
            shutdown = getattr(executor, "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown(wait=False, cancel_futures=True)
                except TypeError:
                    try:
                        shutdown(wait=False)
                    except Exception:
                        pass
                except Exception:
                    pass

    def _current_request_context(self) -> Optional[_BrokerRequestContext]:
        self._ensure_runtime_initialized()
        current = getattr(self._request_local, "current_request", None)
        if isinstance(current, _BrokerRequestContext):
            return current
        return None

    def _register_timeout_cleanup(self, callback: Callable[[], None]) -> None:
        context = self._current_request_context()
        if context is None:
            return
        context.cleanup_callbacks.append(callback)

    def _register_transport_cleanup(self, transport_client: Any) -> None:
        close_transport = getattr(transport_client, "close_transport", None)
        if not callable(close_transport):
            return

        def _cleanup() -> None:
            try:
                close_transport()
            except Exception:
                pass

        self._register_timeout_cleanup(_cleanup)

    def _cleanup_request_context(self, context: _BrokerRequestContext, *, reason: str) -> int:
        callbacks = list(context.cleanup_callbacks)
        context.cleanup_callbacks.clear()
        recycled = 0
        for callback in callbacks:
            try:
                callback()
            finally:
                recycled += 1
        if recycled > 0:
            context.session_recycled = True
            with self._runtime_metrics_lock:
                self._session_recycle_count = int(getattr(self, "_session_recycle_count", 0)) + recycled
            _emit_broker_dispatch_runtime_trace(
                "BROKER_SESSION_RECYCLED",
                level="WARN",
                operation=context.op,
                request_id=context.request_id,
                request_class=context.request_class,
                lane_name=context.lane_name,
                recycle_count=recycled,
                reason=reason,
            )
        return recycled

    def _update_active_request_count(self, request_class: str, delta: int) -> int:
        self._ensure_runtime_initialized()
        with self._runtime_metrics_lock:
            current = int(self._active_requests_by_class.get(request_class, 0)) + int(delta)
            self._active_requests_by_class[request_class] = max(0, current)
            return int(self._active_requests_by_class.get(request_class, 0))

    def _breaker_state_for_class(self, request_class: str) -> _BrokerBreakerState:
        self._ensure_runtime_initialized()
        state = self._breakers.get(request_class)
        if isinstance(state, _BrokerBreakerState):
            return state
        state = _BrokerBreakerState()
        self._breakers[request_class] = state
        return state

    def _prune_breaker_failures(self, breaker: _BrokerBreakerState, *, now: float) -> None:
        cutoff = now - BROKER_BREAKER_WINDOW_SECONDS
        while breaker.failures and breaker.failures[0] < cutoff:
            breaker.failures.popleft()

    def _breaker_decision(self, request_class: str, *, op: str) -> tuple[bool, str, bool]:
        self._ensure_runtime_initialized()
        with self._breaker_lock:
            breaker = self._breaker_state_for_class(request_class)
            now = time.monotonic()
            self._prune_breaker_failures(breaker, now=now)
            if breaker.open_until > now:
                if request_class in {BROKER_REQUEST_CLASS_EVIDENCE, BROKER_REQUEST_CLASS_METADATA}:
                    _emit_broker_dispatch_runtime_trace(
                        "BROKER_REQUEST_SHORT_CIRCUITED",
                        level="WARN",
                        operation=op,
                        request_class=request_class,
                        lane_name=_BROKER_LANE_SPECS[request_class].lane_name,
                        breaker_state="open",
                    )
                    return False, "open", False
                return True, "open_bypass", False
            if breaker.open_until and breaker.open_until <= now:
                if not breaker.half_open_probe_inflight:
                    breaker.half_open_probe_inflight = True
                    _emit_broker_dispatch_runtime_trace(
                        "BROKER_DEGRADED_HALF_OPEN",
                        level="WARN",
                        operation=op,
                        request_class=request_class,
                        lane_name=_BROKER_LANE_SPECS[request_class].lane_name,
                    )
                    return True, "half_open_probe", True
                if request_class in {BROKER_REQUEST_CLASS_EVIDENCE, BROKER_REQUEST_CLASS_METADATA}:
                    _emit_broker_dispatch_runtime_trace(
                        "BROKER_REQUEST_SHORT_CIRCUITED",
                        level="WARN",
                        operation=op,
                        request_class=request_class,
                        lane_name=_BROKER_LANE_SPECS[request_class].lane_name,
                        breaker_state="half_open_wait",
                    )
                    return False, "half_open_wait", False
                return True, "half_open_bypass", False
        return True, "closed", False

    def _record_breaker_success(self, request_class: str, *, op: str, was_probe: bool) -> None:
        if not was_probe:
            return
        with self._breaker_lock:
            breaker = self._breaker_state_for_class(request_class)
            breaker.failures.clear()
            breaker.open_until = 0.0
            breaker.half_open_probe_inflight = False
        _emit_broker_dispatch_runtime_trace(
            "BROKER_DEGRADED_CLOSED",
            level="INFO",
            operation=op,
            request_class=request_class,
            lane_name=_BROKER_LANE_SPECS[request_class].lane_name,
        )

    def _record_breaker_failure(self, request_class: str, *, op: str, error_code: str, was_probe: bool) -> None:
        if not _broker_failure_counts_toward_breaker(error_code):
            return
        self._ensure_runtime_initialized()
        increment_timeout_count = False
        should_open = False
        with self._breaker_lock:
            breaker = self._breaker_state_for_class(request_class)
            now = time.monotonic()
            self._prune_breaker_failures(breaker, now=now)
            breaker.failures.append(now)
            if str(error_code or "").strip().lower().startswith("timeout_"):
                increment_timeout_count = True
            should_open = was_probe or len(breaker.failures) >= BROKER_BREAKER_FAILURE_THRESHOLD
            if should_open:
                breaker.open_until = now + BROKER_BREAKER_OPEN_SECONDS
                breaker.half_open_probe_inflight = False
        if increment_timeout_count:
            with self._runtime_metrics_lock:
                self._recent_timeout_count_by_class[request_class] = int(
                    self._recent_timeout_count_by_class.get(request_class, 0)
                ) + 1
        if should_open:
            _emit_broker_dispatch_runtime_trace(
                "BROKER_DEGRADED_OPEN",
                level="WARN",
                operation=op,
                request_class=request_class,
                lane_name=_BROKER_LANE_SPECS[request_class].lane_name,
                error_code=error_code,
                reopen_probe=bool(was_probe),
            )

    def _health_counters_payload(self) -> dict[str, Any]:
        self._ensure_runtime_initialized()
        with self._runtime_metrics_lock:
            active_requests = dict(self._active_requests_by_class)
            timeout_counts = dict(self._recent_timeout_count_by_class)
            session_recycle_count = int(getattr(self, "_session_recycle_count", 0))
        now = time.monotonic()
        with self._breaker_lock:
            degraded: dict[str, Any] = {}
            for request_class, breaker in self._breakers.items():
                degraded[request_class] = {
                    "open": bool(breaker.open_until > now),
                    "half_open_probe_inflight": bool(breaker.half_open_probe_inflight),
                    "recent_failures": len(breaker.failures),
                    "open_for_seconds": max(0, int(round(breaker.open_until - now))) if breaker.open_until else 0,
                }
        return {
            "active_requests_by_class": active_requests,
            "recent_timeout_count_by_class": timeout_counts,
            "session_recycle_count": session_recycle_count,
            "degraded_mode": degraded,
        }

    def _execute_operation(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        safe_op = str(op or "").strip().lower()
        if safe_op == "shutdown":
            return {"shutdown": True}
        handler = getattr(self, f"op_{safe_op}", None)
        if not callable(handler):
            raise _BrokerError(400, "unknown_operation")
        return handler(args)

    def _run_request(self, context: _BrokerRequestContext, args: dict[str, Any]) -> dict[str, Any]:
        self._ensure_runtime_initialized()
        self._request_local.current_request = context
        context.started_monotonic = time.monotonic()
        context.start_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        context.queue_wait_ms = int((context.started_monotonic - context.enqueued_monotonic) * 1000)
        active_now = self._update_active_request_count(context.request_class, 1)
        _emit_broker_dispatch_runtime_trace(
            "BROKER_REQUEST_START",
            level="INFO",
            operation=context.op,
            request_id=context.request_id,
            request_class=context.request_class,
            lane_name=context.lane_name,
            enqueue_utc=context.enqueue_utc,
            start_utc=context.start_utc,
            queue_wait_ms=context.queue_wait_ms,
            lane_active_at_enqueue=context.lane_active_at_enqueue,
            lane_busy_at_enqueue=context.lane_busy_at_enqueue,
            active_requests=active_now,
            breaker_state=context.breaker_state,
            half_open_probe=context.half_open_probe,
        )
        result: dict[str, Any] = {}
        level = "INFO"
        try:
            result = self._execute_operation(context.op, args)
            if not context.timed_out:
                context.result_category = "completed"
                self._record_breaker_success(
                    context.request_class,
                    op=context.op,
                    was_probe=context.half_open_probe,
                )
            return result
        except Exception as exc:
            status, error_code, message = _broker_result_category_for_exception(context.request_class, exc)
            if not context.timed_out:
                context.result_category = error_code
                self._record_breaker_failure(
                    context.request_class,
                    op=context.op,
                    error_code=error_code,
                    was_probe=context.half_open_probe,
                )
            level = "WARN"
            if isinstance(exc, _BrokerError):
                raise
            raise _BrokerError(status, error_code, message) from exc
        finally:
            context.processing_ms = int((time.monotonic() - context.started_monotonic) * 1000)
            context.total_elapsed_ms = int((time.monotonic() - context.enqueued_monotonic) * 1000)
            active_now = self._update_active_request_count(context.request_class, -1)
            _emit_broker_dispatch_runtime_trace(
                "BROKER_REQUEST_FINISH",
                level=level,
                operation=context.op,
                request_id=context.request_id,
                request_class=context.request_class,
                lane_name=context.lane_name,
                queue_wait_ms=context.queue_wait_ms,
                processing_ms=context.processing_ms,
                total_elapsed_ms=context.total_elapsed_ms,
                lane_active_at_enqueue=context.lane_active_at_enqueue,
                lane_busy_at_enqueue=context.lane_busy_at_enqueue,
                result_category=context.result_category or "unknown",
                active_requests=active_now,
                session_recycled=context.session_recycled,
                breaker_state=context.breaker_state,
            )
            context.cleanup_callbacks.clear()
            self._request_local.current_request = None

    def submit_lane_request(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        self._ensure_runtime_initialized()
        spec = _broker_lane_spec_for_op(op)
        allow_request, breaker_state, half_open_probe = self._breaker_decision(spec.request_class, op=op)
        if not allow_request:
            raise _BrokerError(503, "broker_overloaded", "Local Splunk broker is temporarily degraded for this request class.")
        lane_active_at_enqueue = 0
        with self._runtime_metrics_lock:
            try:
                lane_active_at_enqueue = max(
                    0,
                    int(self._active_requests_by_class.get(spec.request_class, 0) or 0),
                )
            except Exception:
                lane_active_at_enqueue = 0
        context = _BrokerRequestContext(
            request_id=uuid.uuid4().hex[:12],
            op=str(op or "").strip().lower(),
            request_class=spec.request_class,
            lane_name=spec.lane_name,
            queue_budget_seconds=float(spec.total_budget_seconds),
            enqueued_monotonic=time.monotonic(),
            enqueue_utc=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            lane_active_at_enqueue=lane_active_at_enqueue,
            lane_busy_at_enqueue=bool(lane_active_at_enqueue > 0),
            breaker_state=breaker_state,
            half_open_probe=half_open_probe,
        )
        _emit_broker_dispatch_runtime_trace(
            "BROKER_REQUEST_ENQUEUED",
            level="INFO",
            operation=context.op,
            request_id=context.request_id,
            request_class=context.request_class,
            lane_name=context.lane_name,
            enqueue_utc=context.enqueue_utc,
            timeout_budget_seconds=int(round(context.queue_budget_seconds)),
            lane_active_at_enqueue=context.lane_active_at_enqueue,
            lane_busy_at_enqueue=context.lane_busy_at_enqueue,
            breaker_state=breaker_state,
        )
        executor = self._lane_executors[spec.request_class]
        future = executor.submit(self._run_request, context, dict(args or {}))
        try:
            result = future.result(timeout=context.queue_budget_seconds)
            if isinstance(result, dict):
                result["_broker_request_meta"] = {
                    "request_id": context.request_id,
                    "request_class": context.request_class,
                    "lane_name": context.lane_name,
                    "queue_wait_ms": context.queue_wait_ms,
                    "processing_ms": context.processing_ms,
                    "total_elapsed_ms": context.total_elapsed_ms,
                    "lane_active_at_enqueue": context.lane_active_at_enqueue,
                    "lane_busy_at_enqueue": context.lane_busy_at_enqueue,
                    "result_category": context.result_category or "completed",
                    "enqueue_utc": context.enqueue_utc,
                    "start_utc": context.start_utc,
                }
            return result
        except FutureTimeoutError:
            context.timed_out = True
            context.result_category = _broker_timeout_category(spec.request_class)
            self._cleanup_request_context(context, reason=_broker_timeout_category(spec.request_class))
            self._record_breaker_failure(
                spec.request_class,
                op=context.op,
                error_code=_broker_timeout_category(spec.request_class),
                was_probe=context.half_open_probe,
            )
            raise _BrokerError(
                504,
                _broker_timeout_category(spec.request_class),
                (
                    "Local Splunk broker timed out while processing the request class "
                    f"{spec.request_class} (request_id={context.request_id}, lane={context.lane_name}, "
                    f"lane_busy_at_enqueue={str(bool(context.lane_busy_at_enqueue)).lower()}, "
                    f"lane_active_at_enqueue={int(context.lane_active_at_enqueue)}, "
                    f"queue_wait_ms={int(context.queue_wait_ms)}, started={str(bool(context.start_utc)).lower()})."
                ),
            )

    def _require_cfg(self):
        if self.cfg is None:
            raise _BrokerError(503, "config_unavailable", self.config_error or "Configuration unavailable.")
        return self.cfg

    def _require_client(self) -> SplunkClient:
        if self.client is None:
            raise _BrokerError(409, "not_connected", "Not connected to Splunk.")
        return self.client

    def _borrow_operation_client(self, client: SplunkClient) -> tuple[SplunkClient, bool]:
        create_isolated_rest_client = getattr(client, "create_isolated_rest_client", None)
        if callable(create_isolated_rest_client):
            try:
                borrowed = create_isolated_rest_client()
                self._register_transport_cleanup(borrowed)
                return borrowed, True
            except Exception:
                self._register_transport_cleanup(client)
                return client, False
        self._register_transport_cleanup(client)
        return client, False

    def _close_operation_client(self, borrowed_client: SplunkClient, base_client: SplunkClient) -> None:
        if borrowed_client is base_client:
            return
        close_transport = getattr(borrowed_client, "close_transport", None)
        if callable(close_transport):
            try:
                close_transport()
            except Exception:
                pass

    def _disconnect_internal(self) -> None:
        if self.client is None:
            self.connected_server = ""
            return
        try:
            if hasattr(self.client, "_auth_header"):
                self.client._auth_header = ""
            close_transport = getattr(self.client, "close_transport", None)
            if callable(close_transport):
                close_transport()
            elif hasattr(self.client, "session") and hasattr(self.client.session, "close"):
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
            "broker_runtime": self._health_counters_payload(),
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
        op_client, _ = self._borrow_operation_client(client)
        try:
            apps = op_client.list_apps()
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            if _looks_like_auth_failure(safe_msg):
                raise _BrokerError(401, "splunk_auth_failed", safe_msg)
            raise
        finally:
            self._close_operation_client(op_client, client)
        if not isinstance(apps, list):
            raise _BrokerError(502, "list_apps_failed", "Failed to list apps.")
        return {"apps": [str(x) for x in apps]}

    def op_list_saved_searches(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        app = _validate_string_field(args, "app", required=True, max_len=120)
        self.audit.log_event("SAVED_SEARCH_LIST_REQUESTED", level="INFO", app=app)
        op_client, _ = self._borrow_operation_client(client)
        try:
            payload = op_client.list_saved_searches(app)
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            if _looks_like_auth_failure(safe_msg):
                raise _BrokerError(401, "splunk_auth_failed", safe_msg)
            raise
        finally:
            self._close_operation_client(op_client, client)
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
        _emit_broker_dispatch_runtime_trace(
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
        dispatch_client = client
        create_isolated_dispatch_client = getattr(client, "create_isolated_dispatch_client", None)
        if callable(create_isolated_dispatch_client):
            try:
                dispatch_client = create_isolated_dispatch_client()
                trace_fields["dispatch_client_mode"] = "isolated_per_slice"
            except Exception:
                dispatch_client = client
                trace_fields["dispatch_client_mode"] = "shared_client_fallback"
        else:
            trace_fields["dispatch_client_mode"] = "shared_client"
        self._register_transport_cleanup(dispatch_client)
        self.audit.log_event(
            "BROKER_DISPATCH_BACKEND_START",
            level="INFO",
            **trace_fields,
        )
        _emit_broker_dispatch_runtime_trace(
            "BROKER_DISPATCH_BACKEND_START",
            level="INFO",
            **trace_fields,
        )
        watchdog_done = threading.Event()

        def _watch_backend_dispatch() -> None:
            previous_checkpoint = 0
            for checkpoint_seconds in _BROKER_DISPATCH_WATCHDOG_SECONDS:
                wait_seconds = max(0, checkpoint_seconds - previous_checkpoint)
                previous_checkpoint = checkpoint_seconds
                if watchdog_done.wait(wait_seconds):
                    return
                elapsed_ms = int((time.monotonic() - op_start) * 1000)
                _emit_broker_dispatch_runtime_trace(
                    "BROKER_DISPATCH_BACKEND_STILL_WAITING",
                    level="WARN",
                    **trace_fields,
                    elapsed_ms=elapsed_ms,
                    watchdog_seconds=checkpoint_seconds,
                )

        watchdog_thread = threading.Thread(
            target=_watch_backend_dispatch,
            name=f"broker-dispatch-watchdog-{uuid.uuid4().hex[:8]}",
            daemon=True,
        )
        watchdog_thread.start()
        previous_trace_context = getattr(dispatch_client, "_dispatch_trace_context", None)
        setattr(dispatch_client, "_dispatch_trace_context", trace_context)
        dispatch_exc: Optional[Exception] = None
        ok = False
        sid: Optional[str] = ""
        err = ""
        try:
            ok, sid, err = dispatch_client.dispatch_saved_search(
                report_id_url=report_id_url,
                earliest=earliest or None,
                latest=latest or None,
                trigger_actions=trigger_actions,
                request_timeout_seconds=int(_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_DISPATCH].read_timeout_seconds),
            )
        except Exception as exc:
            dispatch_exc = exc
            err = _safe_error_text(exc)
        finally:
            if previous_trace_context is None:
                try:
                    delattr(dispatch_client, "_dispatch_trace_context")
                except Exception:
                    pass
            else:
                setattr(dispatch_client, "_dispatch_trace_context", previous_trace_context)
            if dispatch_client is not client:
                close_transport = getattr(dispatch_client, "close_transport", None)
                if callable(close_transport):
                    try:
                        close_transport()
                    except Exception:
                        pass
            watchdog_done.set()
        elapsed_ms = int((time.monotonic() - op_start) * 1000)
        if dispatch_exc is not None:
            self.audit.log_event(
                "BROKER_DISPATCH_BACKEND_EXCEPTION",
                level="ERROR",
                **trace_fields,
                elapsed_ms=elapsed_ms,
                exception_type=type(dispatch_exc).__name__,
                exception_message=_sanitize_text(err),
            )
            _emit_broker_dispatch_runtime_trace(
                "BROKER_DISPATCH_BACKEND_EXCEPTION",
                level="ERROR",
                **trace_fields,
                elapsed_ms=elapsed_ms,
                exception_type=type(dispatch_exc).__name__,
                exception_message=_sanitize_text(err),
            )
            _emit_broker_debug_event(
                "DISPATCH_SAVED_SEARCH_FAILED",
                level="WARN",
                operation="dispatch_saved_search",
                request_format="form_body",
                earliest_time=earliest,
                latest_time=latest,
                trigger_actions=trigger_actions,
                error_detail=err,
                failure_classification="dispatch_backend_exception",
                exception_type=type(dispatch_exc).__name__,
                exception_message=_sanitize_text(err),
                elapsed_ms=elapsed_ms,
                **request_context,
            )
            raise _BrokerError(502, "dispatch_saved_search_failed", _sanitize_text(err))
        if (not ok) and _looks_like_auth_failure(str(err or "")):
            raise _BrokerError(401, "splunk_auth_failed", _sanitize_text(str(err or "")))
        self.audit.log_event(
            "BROKER_DISPATCH_BACKEND_RETURN",
            level="INFO" if ok and sid else "WARN",
            **trace_fields,
            elapsed_ms=elapsed_ms,
            sid=_sanitize_text(str(sid or "")),
            exception_message=_sanitize_text(str(err or "")),
        )
        _emit_broker_dispatch_runtime_trace(
            "BROKER_DISPATCH_BACKEND_RETURN",
            level="INFO" if ok and sid else "WARN",
            **trace_fields,
            elapsed_ms=elapsed_ms,
            sid=_sanitize_text(str(sid or "")),
            exception_message=_sanitize_text(str(err or "")),
        )
        raw_meta = getattr(dispatch_client, "_last_dispatch_meta", {})
        client_meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
        client_meta["dispatch_client_mode"] = str(trace_fields.get("dispatch_client_mode", "") or "")
        broker_fields = {
            "operation": "dispatch_saved_search",
            "request_class": str(client_meta.get("request_class", "") or BROKER_REQUEST_CLASS_DISPATCH),
            "lane_name": str(client_meta.get("broker_lane_name", "") or "dispatch"),
            "request_format": "form_body",
            "earliest_time": earliest,
            "latest_time": latest,
            "trigger_actions": trigger_actions,
            "sid": _sanitize_text(str(sid or client_meta.get("sid", "") or "")),
            "elapsed_ms": elapsed_ms,
            "operation_elapsed_ms": elapsed_ms,
            "request_body_summary": str(client_meta.get("request_body_summary", "") or ""),
            "request_payload_keys": str(client_meta.get("request_payload_keys", "") or ""),
            "request_optional_payload_keys": str(client_meta.get("request_optional_payload_keys", "") or ""),
            "request_start_time": str(client_meta.get("request_start_time", "") or ""),
            "transport_freshness": str(client_meta.get("transport_freshness", "") or ""),
            "dispatch_client_mode": str(client_meta.get("dispatch_client_mode", "") or ""),
            "preflight_dispatch_lane_active": client_meta.get("preflight_dispatch_lane_active", ""),
            "preflight_dispatch_recent_timeouts": client_meta.get("preflight_dispatch_recent_timeouts", ""),
            "preflight_metadata_recent_timeouts": client_meta.get("preflight_metadata_recent_timeouts", ""),
            "preflight_health_observed": client_meta.get("preflight_health_observed", ""),
            "preflight_recycle_triggered": client_meta.get("preflight_recycle_triggered", ""),
            "connect_timeout_seconds": client_meta.get("connect_timeout_seconds", ""),
            "read_timeout_seconds": client_meta.get("read_timeout_seconds", ""),
            "response_status_code": client_meta.get("response_status_code", ""),
            "response_headers_elapsed_ms": client_meta.get("response_headers_elapsed_ms", ""),
            "response_body_read_elapsed_ms": client_meta.get("response_body_read_elapsed_ms", ""),
            "json_parse_elapsed_ms": client_meta.get("json_parse_elapsed_ms", ""),
            "post_sid_return_work_ms": client_meta.get("post_sid_return_work_ms", ""),
            "broker_request_id": str(client_meta.get("broker_request_id", "") or ""),
            "broker_queue_wait_ms": client_meta.get("broker_queue_wait_ms", ""),
            "broker_processing_ms": client_meta.get("broker_processing_ms", ""),
            "broker_total_elapsed_ms": client_meta.get("broker_total_elapsed_ms", ""),
            "broker_lane_active_at_enqueue": client_meta.get("broker_lane_active_at_enqueue", ""),
            "broker_lane_busy_at_enqueue": client_meta.get("broker_lane_busy_at_enqueue", ""),
            "sid_source": str(client_meta.get("sid_source", "") or ""),
            "response_location": str(client_meta.get("response_location", "") or ""),
            "response_body_snippet": str(client_meta.get("response_body_snippet", "") or ""),
            "failure_classification": str(client_meta.get("failure_classification", "") or ""),
            "namespace_consistency": str(client_meta.get("namespace_consistency", "") or ""),
            "path_validation_error": str(client_meta.get("path_validation_error", "") or ""),
            "fallback_attempted": str(client_meta.get("fallback_attempted", "") or ""),
            "fallback_response_status_code": str(client_meta.get("fallback_response_status_code", "") or ""),
            "fallback_response_body_snippet": str(client_meta.get("fallback_response_body_snippet", "") or ""),
            "recent_metadata_outcome": str(client_meta.get("recent_metadata_outcome", "") or ""),
            "recent_metadata_elapsed_ms": client_meta.get("recent_metadata_elapsed_ms", ""),
            "recent_metadata_age_ms": client_meta.get("recent_metadata_age_ms", ""),
            "recent_metadata_path": str(client_meta.get("recent_metadata_path", "") or ""),
            "recent_transport_cleanup_reason": str(client_meta.get("recent_transport_cleanup_reason", "") or ""),
            "recent_transport_cleanup_age_ms": client_meta.get("recent_transport_cleanup_age_ms", ""),
            "recent_transport_cleanup_operation": str(client_meta.get("recent_transport_cleanup_operation", "") or ""),
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
        meta_payload = {
            "request_start_time": str(client_meta.get("request_start_time", "") or ""),
            "request_body_summary": str(client_meta.get("request_body_summary", "") or ""),
            "request_payload_keys": str(client_meta.get("request_payload_keys", "") or ""),
            "request_optional_payload_keys": str(client_meta.get("request_optional_payload_keys", "") or ""),
            "transport_freshness": str(client_meta.get("transport_freshness", "") or ""),
            "dispatch_client_mode": str(client_meta.get("dispatch_client_mode", "") or ""),
            "broker_lane_name": str(client_meta.get("broker_lane_name", "") or "dispatch"),
            "preflight_dispatch_lane_active": client_meta.get("preflight_dispatch_lane_active", ""),
            "preflight_dispatch_recent_timeouts": client_meta.get("preflight_dispatch_recent_timeouts", ""),
            "preflight_metadata_recent_timeouts": client_meta.get("preflight_metadata_recent_timeouts", ""),
            "preflight_health_observed": client_meta.get("preflight_health_observed", ""),
            "preflight_recycle_triggered": client_meta.get("preflight_recycle_triggered", ""),
            "connect_timeout_seconds": client_meta.get("connect_timeout_seconds", ""),
            "read_timeout_seconds": client_meta.get("read_timeout_seconds", ""),
            "response_status_code": client_meta.get("response_status_code", ""),
            "response_location": str(client_meta.get("response_location", "") or ""),
            "response_body_snippet": str(client_meta.get("response_body_snippet", "") or ""),
            "failure_classification": str(client_meta.get("failure_classification", "") or ""),
            "request_class": str(client_meta.get("request_class", "") or ""),
            "broker_request_id": str(client_meta.get("broker_request_id", "") or ""),
            "broker_queue_wait_ms": client_meta.get("broker_queue_wait_ms", ""),
            "broker_processing_ms": client_meta.get("broker_processing_ms", ""),
            "broker_total_elapsed_ms": client_meta.get("broker_total_elapsed_ms", ""),
            "broker_lane_active_at_enqueue": client_meta.get("broker_lane_active_at_enqueue", ""),
            "broker_lane_busy_at_enqueue": client_meta.get("broker_lane_busy_at_enqueue", ""),
            "namespace_consistency": str(client_meta.get("namespace_consistency", "") or ""),
            "path_validation_error": str(client_meta.get("path_validation_error", "") or ""),
            "fallback_attempted": client_meta.get("fallback_attempted", ""),
            "fallback_response_status_code": client_meta.get("fallback_response_status_code", ""),
            "fallback_response_body_snippet": str(client_meta.get("fallback_response_body_snippet", "") or ""),
            "recent_metadata_outcome": str(client_meta.get("recent_metadata_outcome", "") or ""),
            "recent_metadata_elapsed_ms": client_meta.get("recent_metadata_elapsed_ms", ""),
            "recent_metadata_age_ms": client_meta.get("recent_metadata_age_ms", ""),
            "recent_metadata_path": str(client_meta.get("recent_metadata_path", "") or ""),
            "recent_transport_cleanup_reason": str(client_meta.get("recent_transport_cleanup_reason", "") or ""),
            "recent_transport_cleanup_age_ms": client_meta.get("recent_transport_cleanup_age_ms", ""),
            "recent_transport_cleanup_operation": str(client_meta.get("recent_transport_cleanup_operation", "") or ""),
            "sid": str(client_meta.get("sid", "") or ""),
            "sid_source": str(client_meta.get("sid_source", "") or ""),
            "transport_mode": str(client_meta.get("transport_mode", "") or ""),
            "correlation_tag": str(client_meta.get("correlation_tag", "") or trace_context.get("correlation_tag", "") or ""),
            "correlation_dispatch_value": str(client_meta.get("correlation_dispatch_value", "") or ""),
            "correlation_mode": str(client_meta.get("correlation_mode", "") or trace_context.get("correlation_mode", "") or ""),
            "correlation_fallback_reason": str(client_meta.get("correlation_fallback_reason", "") or ""),
        }
        return {
            "ok": bool(ok),
            "sid": _sanitize_text(str(sid or "")),
            "error": _sanitize_text(redact_text(str(err or ""))),
            "meta": meta_payload,
        }

    def op_check_job_status(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        sid = _validate_string_field(args, "sid", required=True, max_len=200)
        if not _SID_RE.match(sid):
            raise _BrokerError(400, "invalid_sid", "Invalid SID format.")
        wait_seconds = _validate_int_field(args, "wait_seconds", default=10, min_value=1, max_value=3600)
        poll_interval = _validate_int_field(args, "poll_interval", default=2, min_value=1, max_value=60)
        op_client, _ = self._borrow_operation_client(client)
        try:
            state, content = op_client.check_job_status(sid=sid, wait_seconds=wait_seconds, poll_interval=poll_interval)
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            if _looks_like_auth_failure(safe_msg):
                raise _BrokerError(401, "splunk_auth_failed", safe_msg)
            raise
        finally:
            self._close_operation_client(op_client, client)
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
        retry_count = _validate_int_field(args, "retry_count", default=0, min_value=0, max_value=20)
        stage_name = _validate_string_field(args, "stage_name", required=False, max_len=80)
        debug_event(
            "GET_JOB_STATUS_SNAPSHOT_REQUESTED",
            sid=sid,
            retry_count=retry_count,
            stage_name=stage_name,
        )
        start = time.monotonic()
        op_client, _ = self._borrow_operation_client(client)
        try:
            state, content = op_client.get_job_status_snapshot(
                sid=sid,
                request_timeout_seconds=request_timeout_seconds,
                retry_count=retry_count,
                stage_name=stage_name,
            )
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            if _looks_like_auth_failure(safe_msg):
                raise _BrokerError(401, "splunk_auth_failed", safe_msg)
            if "timed out" in safe_msg.lower() or "timeout" in safe_msg.lower():
                debug_event(
                    "GET_JOB_STATUS_SNAPSHOT_FAILED",
                    sid=sid,
                    retry_count=retry_count,
                    stage_name=stage_name,
                    rest_method="GET",
                    error_code="job_status_snapshot_timeout",
                )
                raise _BrokerError(504, "job_status_snapshot_timeout", safe_msg)
            raise
        finally:
            self._close_operation_client(op_client, client)
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

    def op_find_job_candidates(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        limit = _validate_int_field(args, "limit", default=50, min_value=1, max_value=100)
        page_size = _validate_int_field(args, "page_size", default=25, min_value=1, max_value=50)
        window_buffer_seconds = _validate_int_field(
            args,
            "window_buffer_seconds",
            default=RECONCILIATION_WINDOW_BUFFER_SECONDS,
            min_value=0,
            max_value=900,
        )
        label = _validate_string_field(args, "label", required=False, max_len=200)
        owner = _validate_string_field(args, "owner", required=False, max_len=200)
        app = _validate_string_field(args, "app", required=False, max_len=200)
        dispatch_earliest = _validate_string_field(args, "dispatch_earliest", required=False, max_len=200)
        dispatch_latest = _validate_string_field(args, "dispatch_latest", required=False, max_len=200)
        correlation_tag = _validate_string_field(args, "correlation_tag", required=False, max_len=300)
        op_client, _ = self._borrow_operation_client(client)
        try:
            jobs = op_client.find_job_candidates(
                label=label,
                owner=owner,
                app=app,
                dispatch_earliest=dispatch_earliest,
                dispatch_latest=dispatch_latest,
                correlation_tag=correlation_tag,
                limit=limit,
                page_size=page_size,
                window_buffer_seconds=window_buffer_seconds,
            )
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            if _looks_like_auth_failure(safe_msg):
                raise _BrokerError(401, "splunk_auth_failed", safe_msg)
            raise
        finally:
            self._close_operation_client(op_client, client)
        if not isinstance(jobs, list):
            jobs = []
        return {"jobs": [dict(job) for job in jobs if isinstance(job, dict)]}

    def op_export_search_json(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        path = _validate_string_field(args, "path", required=False, max_len=2000) or _EXPORT_SEARCH_PATH
        if str(path or "").strip().lower() != _EXPORT_SEARCH_PATH:
            raise _BrokerError(400, "invalid_export_search_path", "Export-search path is invalid.")
        params = _validate_params_field(
            args,
            "params",
            allowed_keys={"search", "earliest_time", "latest_time", "output_mode", "count"},
            max_items=8,
        )
        search_query = str(params.get("search", "") or "").strip()
        if not search_query:
            raise _BrokerError(400, "missing_search", "Export search query is required.")
        if "output_mode" not in params:
            params["output_mode"] = "json"
        audit = getattr(self, "audit", None)
        if hasattr(audit, "log_event"):
            audit.log_event(
                "EXPORT_SEARCH_REQUESTED",
                rest_method="POST",
                request_format="form_body",
                endpoint=_EXPORT_SEARCH_PATH,
            )
        trace_fields = {
            "requested_path": _sanitize_text(path),
            "query_keys": ",".join(sorted(str(key) for key in params.keys())),
            "thread_name": threading.current_thread().name,
        }
        _emit_broker_dispatch_runtime_trace(
            "BROKER_EXPORT_SEARCH_REQUEST_RECEIVED",
            level="INFO",
            **trace_fields,
        )
        op_client, _ = self._borrow_operation_client(client)
        op_start = time.monotonic()
        try:
            exporter = getattr(op_client, "export_search_json", None)
            if callable(exporter):
                data = exporter(
                    search_query,
                    earliest_time=str(params.get("earliest_time", "-1s") or "-1s"),
                    timeout_seconds=int(_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_EVIDENCE].read_timeout_seconds),
                )
            else:
                try:
                    data = op_client._get(
                        path,
                        params=params,
                        timeout=int(_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_EVIDENCE].read_timeout_seconds),
                        connect_timeout_seconds=_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_EVIDENCE].connect_timeout_seconds,
                    )
                except TypeError:
                    data = op_client._get(path, params=params)
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            if _looks_like_auth_failure(safe_msg):
                raise _BrokerError(401, "splunk_auth_failed", safe_msg)
            if "malformed expression" in safe_msg.lower() or "invalid time" in safe_msg.lower():
                if hasattr(audit, "log_event"):
                    audit.log_event(
                        "EXPORT_SEARCH_FAILED",
                        error_code="invalid_time_spec",
                        response_status_code=400,
                    )
                raise _BrokerError(400, "invalid_time_spec", safe_msg)
            raise
        finally:
            self._close_operation_client(op_client, client)
        safe_data = _redact_sensitive(data, key_hint="data")
        if not isinstance(safe_data, dict):
            safe_data = {}
        if not isinstance(safe_data.get("results", []), list):
            if hasattr(audit, "log_event"):
                audit.log_event(
                    "EXPORT_SEARCH_FAILED",
                    error_code="malformed_rest_response",
                    response_status_code=200,
                )
            raise _BrokerError(502, "malformed_rest_response", "Malformed export search response.")
        result_count = 0
        if isinstance(safe_data.get("results"), list):
            result_count = len(safe_data.get("results", []))
        _emit_broker_dispatch_runtime_trace(
            "BROKER_EXPORT_SEARCH_REQUEST_RETURN",
            level="INFO",
            **trace_fields,
            elapsed_ms=int((time.monotonic() - op_start) * 1000),
            result_count=result_count,
        )
        if hasattr(audit, "log_event"):
            audit.log_event(
                "EXPORT_SEARCH_COMPLETED",
                response_status_code=200,
                expected_fields_present=True,
            )
        return {"data": safe_data}

    def op_export_search(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        search_query = _validate_string_field(args, "search_query", required=True, max_len=10000)
        earliest_time = _validate_string_field(args, "earliest_time", required=False, max_len=200) or "-1s"
        timeout_seconds = _validate_int_field(args, "timeout_seconds", default=15, min_value=1, max_value=300)
        audit = getattr(self, "audit", None)
        if hasattr(audit, "log_event"):
            audit.log_event(
                "EXPORT_SEARCH_REQUESTED",
                rest_method="POST",
                request_format="form_body",
                endpoint=_EXPORT_SEARCH_PATH,
            )
        op_client, _ = self._borrow_operation_client(client)
        try:
            exporter = getattr(op_client, "export_search_json", None)
            if callable(exporter):
                data = exporter(search_query, earliest_time=earliest_time, timeout_seconds=timeout_seconds)
            else:
                response = op_client._request(
                    "POST",
                    _EXPORT_SEARCH_PATH,
                    data={
                        "search": search_query,
                        "earliest_time": earliest_time,
                        "output_mode": "json",
                    },
                    timeout=timeout_seconds,
                )
                text = str(getattr(response, "text", "") or "")
                rows = []
                for line in text.splitlines() or [text]:
                    if not line.strip():
                        continue
                    payload = json.loads(line)
                    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
                        rows.append(payload["result"])
                data = {"results": rows}
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            status_code = 400 if "HTTP 400" in safe_msg else (405 if "HTTP 405" in safe_msg else 500)
            if "malformed expression" in safe_msg.lower() or "invalid time" in safe_msg.lower():
                error_code = "invalid_time_spec"
            elif status_code == 405:
                error_code = "export_search_failed"
            else:
                error_code = "export_search_failed"
            if hasattr(audit, "log_event"):
                fields = {"error_code": error_code, "response_status_code": status_code}
                if status_code == 405:
                    fields.update(
                        {
                            "rest_method": "POST",
                            "request_format": "form_body",
                            "response_body_snippet": "Method Not Allowed",
                        }
                    )
                audit.log_event("EXPORT_SEARCH_FAILED", **fields)
            detail = safe_msg
            if status_code == 405:
                detail = "export_search_failed method=POST endpoint=/services/search/jobs/export request_format=form_body status=405"
            raise _BrokerError(status_code, error_code, detail)
        finally:
            self._close_operation_client(op_client, client)
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            if hasattr(audit, "log_event"):
                audit.log_event("EXPORT_SEARCH_FAILED", error_code="malformed_rest_response", response_status_code=200)
            raise _BrokerError(502, "malformed_rest_response", "Malformed export search response.")
        if hasattr(audit, "log_event"):
            audit.log_event(
                "EXPORT_SEARCH_COMPLETED",
                response_status_code=200,
                expected_fields_present=True,
            )
        return {"results": data}

    def op_get_saved_search_metadata(self, args: dict[str, Any]) -> dict[str, Any]:
        client = self._require_client()
        requested_path = _validate_string_field(args, "path", required=True, max_len=2000)
        path = _normalize_saved_search_path(requested_path)
        if not _SAVED_SEARCH_PATH_RE.match(path):
            raise _BrokerError(400, "invalid_saved_search_path", "Saved-search path is invalid.")
        audit = getattr(self, "audit", None)
        if hasattr(audit, "log_event"):
            audit.log_event(
                "SAVED_SEARCH_METADATA_REQUESTED",
                requested_path=requested_path,
                rest_path=path,
            )
        trace_fields = {
            "requested_path": _sanitize_text(requested_path),
            "thread_name": threading.current_thread().name,
        }
        _emit_broker_dispatch_runtime_trace(
            "BROKER_METADATA_REQUEST_RECEIVED",
            level="INFO",
            **trace_fields,
        )
        op_client, _ = self._borrow_operation_client(client)
        op_start = time.monotonic()
        _emit_broker_dispatch_runtime_trace(
            "BROKER_METADATA_BACKEND_START",
            level="INFO",
            **trace_fields,
        )
        watchdog_done = threading.Event()

        def _watch_metadata_fetch() -> None:
            previous_checkpoint = 0
            for checkpoint_seconds in _BROKER_METADATA_WATCHDOG_SECONDS:
                wait_seconds = max(0, checkpoint_seconds - previous_checkpoint)
                previous_checkpoint = checkpoint_seconds
                if watchdog_done.wait(wait_seconds):
                    return
                _emit_broker_dispatch_runtime_trace(
                    "BROKER_METADATA_BACKEND_STILL_WAITING",
                    level="WARN",
                    **trace_fields,
                    elapsed_ms=int((time.monotonic() - op_start) * 1000),
                    watchdog_seconds=checkpoint_seconds,
                )

        watchdog_thread = threading.Thread(
            target=_watch_metadata_fetch,
            name=f"broker-metadata-watchdog-{uuid.uuid4().hex[:8]}",
            daemon=True,
        )
        watchdog_thread.start()
        try:
            try:
                meta = op_client._get(
                    path,
                    timeout=int(_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_METADATA].read_timeout_seconds),
                    connect_timeout_seconds=_BROKER_LANE_SPECS[BROKER_REQUEST_CLASS_METADATA].connect_timeout_seconds,
                )
            except TypeError:
                meta = op_client._get(path)
        except Exception as exc:
            safe_msg = _safe_error_text(exc)
            if _looks_like_auth_failure(safe_msg):
                raise _BrokerError(401, "splunk_auth_failed", safe_msg)
            if "404" in safe_msg or "not found" in safe_msg.lower():
                if hasattr(audit, "log_event"):
                    audit.log_event(
                        "SAVED_SEARCH_METADATA_FAILED",
                        rest_path=path,
                        error_code="saved_search_not_found",
                    )
                raise _BrokerError(404, "saved_search_not_found", f"saved_search_not_found at {path}")
            raise
        finally:
            self._close_operation_client(op_client, client)
            watchdog_done.set()
        safe_meta = _redact_sensitive(meta, key_hint="meta")
        if not isinstance(safe_meta, dict):
            safe_meta = {}
        entry_count = 0
        if isinstance(safe_meta.get("entry"), list):
            entry_count = len(safe_meta.get("entry", []))
        _emit_broker_dispatch_runtime_trace(
            "BROKER_METADATA_BACKEND_RETURN",
            level="INFO",
            **trace_fields,
            elapsed_ms=int((time.monotonic() - op_start) * 1000),
            entry_count=entry_count,
        )
        if hasattr(audit, "log_event"):
            audit.log_event(
                "SAVED_SEARCH_METADATA_RESOLVED",
                rest_path=path,
                response_status_code=200,
            )
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
    _LIFECYCLE_LOCKED_OPS = {"connect", "disconnect", "shutdown"}

    @property
    def _server(self) -> _SplunkBrokerHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except OSError:
            return
        except _BrokerError as exc:
            payload = {"ok": False, "error": exc.error_code}
            if exc.message:
                payload["message"] = _sanitize_text(exc.message)
            try:
                self._send_json(exc.status, payload)
            except OSError:
                return
        except Exception as exc:
            _emit_broker_dispatch_runtime_trace(
                "BROKER_INTERNAL_ERROR",
                level="ERROR",
                exception_type=type(exc).__name__,
                error_detail=_safe_error_text(exc),
            )
            try:
                self._send_json(500, {"ok": False, "error": "internal_error"})
            except OSError:
                return

    def _handle_post(self) -> None:
        if self.path != "/v1/op":
            raise _BrokerError(404, "not_found")
        state = self._server.state
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

        # The broker server is threaded. Only lifecycle mutations should hold
        # the global state lock; long-running per-slice operations must not
        # serialize behind status polls or dispatch calls from other threads.
        if op in self._LIFECYCLE_LOCKED_OPS:
            with self._server.state_lock:
                result = state._execute_operation(op, args)
        elif op in {"health", "get_runtime_config"}:
            result = state._execute_operation(op, args)
        else:
            result = state.submit_lane_request(op, args)
        try:
            self._send_json(200, {"ok": True, "result": result})
        except OSError:
            try:
                state._disconnect_internal()
            except Exception:
                pass
            try:
                state._record_breaker_failure(
                    _broker_request_class_for_op(op),
                    op=op,
                    error_code="transport_interrupted",
                    was_probe=False,
                )
            except Exception:
                pass
            _emit_broker_dispatch_runtime_trace(
                "BROKER_RESPONSE_WRITE_ABORTED",
                level="WARN",
                operation=op,
                request_class=_broker_request_class_for_op(op),
                client_ip=client_ip,
            )
            raise

        if op == "shutdown":
            self._server.should_shutdown = True
            threading.Thread(target=self._server.shutdown, name="SplunkBrokerShutdown", daemon=True).start()

    def _dispatch_operation(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        return self._server.state._execute_operation(op, args)

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
            state.shutdown_runtime()
        except Exception:
            pass
        try:
            server.server_close()
        except Exception:
            pass
        audit.log_event("BROKER_STOP", level="INFO", broker="splunk", pid=os.getpid())
    return 0
