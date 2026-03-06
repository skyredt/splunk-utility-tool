from __future__ import annotations

import hashlib
import hmac
import http.client
import http.server
import json
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

from Internal.audit_logger import (
    DEFAULT_BACKUP_COUNT,
    DEFAULT_LEVEL,
    DEFAULT_MAX_BYTES,
    DEFAULT_VERBOSE,
    MIN_BACKUP_COUNT,
    MIN_MAX_BYTES,
    SecurityAuditLogger,
)


BROKER_BIND_HOST = "127.0.0.1"
PERSISTENT_AUDIT_UNAVAILABLE_WARNING = "Persistent audit logging unavailable; session logging only."
MAX_REQUEST_BYTES = 32_768
MAX_RESPONSE_BYTES = 16_384
MAX_FIELDS_PER_EVENT = 24
MAX_LIST_ITEMS = 100
MAX_STRING_LENGTH = 512
RATE_WINDOW_SECONDS = 5.0
RATE_MAX_REQUESTS = 400

_LEVELS = {"DEBUG", "INFO", "WARN", "ERROR"}
_TYPE_STR = "str"
_TYPE_INT = "int"
_TYPE_BOOL = "bool"
_TYPE_STR_LIST = "str_list"
_MAX_INT = 1_000_000_000

_FORBIDDEN_FIELD_PARTS = (
    "password",
    "decrypted",
    "dpapi",
    "blob",
    "authorization",
    "auth_header",
    "cookie",
    "sessionkey",
    "session_key",
)
_CTRL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_TEXT_PATTERNS = (
    re.compile(r"\b(?:authorization|cookie|set-cookie)\s*:", re.IGNORECASE),
    re.compile(r"\bsessionkey\b", re.IGNORECASE),
    re.compile(r"\b(?:bearer|basic|splunk)\s+[A-Za-z0-9._~+/=\-]{8,}", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]", re.IGNORECASE),
)
_BASE64_LIKE_RE = re.compile(r"^[A-Za-z0-9+/=]{80,}$")

_EVENT_SCHEMAS: dict[str, dict[str, Any]] = {
    "BROKER_START": {
        "fields": {
            "broker": _TYPE_STR,
            "bind_host": _TYPE_STR,
            "bind_port": _TYPE_INT,
            "pid": _TYPE_INT,
        },
        "required": ("broker",),
    },
    "BROKER_STOP": {
        "fields": {
            "broker": _TYPE_STR,
            "pid": _TYPE_INT,
        },
        "required": ("broker",),
    },
    "SPLUNK_CONNECT_REQUESTED": {"fields": {"server": _TYPE_STR}, "required": ("server",)},
    "SPLUNK_CONNECT_SUCCESS": {"fields": {"server": _TYPE_STR}, "required": ("server",)},
    "SPLUNK_CONNECT_FAILED": {
        "fields": {
            "server": _TYPE_STR,
            "reason": _TYPE_STR,
        },
        "required": ("server",),
    },
    "SAVED_SEARCH_LIST_REQUESTED": {"fields": {"app": _TYPE_STR}, "required": ("app",)},
    "TOOL_START": {"fields": {}, "required": ()},
    "TOOL_EXIT": {"fields": {}, "required": ()},
    "CONFIG_LOADED": {
        "fields": {
            "config_path": _TYPE_STR,
            "config_sha256": _TYPE_STR,
        },
        "required": ("config_path", "config_sha256"),
    },
    "CONFIG_CHANGE_DETECTED": {
        "fields": {
            "previous_config_sha256": _TYPE_STR,
            "current_config_sha256": _TYPE_STR,
        },
        "required": (),
    },
    "CRED_ENROLL_CREATE": {"fields": {"secret_path_used": _TYPE_STR}, "required": ()},
    "CRED_REENROLL_OVERWRITE": {"fields": {"secret_path_used": _TYPE_STR}, "required": ()},
    "CRED_DECRYPT_FAILED": {
        "fields": {
            "secret_path_used": _TYPE_STR,
            "reason": _TYPE_STR,
        },
        "required": (),
    },
    "SECRET_FILE_MISSING": {"fields": {"secret_file": _TYPE_STR}, "required": ()},
    "SECRET_FILE_WRITE_FAILED": {
        "fields": {
            "secret_path_used": _TYPE_STR,
            "reason": _TYPE_STR,
        },
        "required": (),
    },
    "REPORT_DISPATCH_REQUESTED": {
        "fields": {
            "run_id": _TYPE_STR,
            "app": _TYPE_STR,
            "report_names": _TYPE_STR_LIST,
            "slicing_mode": _TYPE_STR,
            "earliest": _TYPE_STR,
            "latest": _TYPE_STR,
            "report_count": _TYPE_INT,
        },
        "required": ("run_id", "app", "report_count"),
    },
    "REPORT_DISPATCH_SUCCESS": {
        "fields": {
            "run_id": _TYPE_STR,
            "app": _TYPE_STR,
            "report_count": _TYPE_INT,
            "total_slices": _TYPE_INT,
        },
        "required": ("run_id", "app", "report_count", "total_slices"),
    },
    "REPORT_DISPATCH_FAILED": {
        "fields": {
            "run_id": _TYPE_STR,
            "app": _TYPE_STR,
            "report_count": _TYPE_INT,
            "total_slices": _TYPE_INT,
            "failed_slices": _TYPE_INT,
            "unknown_slices": _TYPE_INT,
            "reason": _TYPE_STR,
        },
        "required": ("app", "report_count"),
    },
    "EMAIL_SEND_REQUESTED": {
        "fields": {
            "run_id": _TYPE_STR,
            "report_count": _TYPE_INT,
            "recipient_count": _TYPE_INT,
            "ack_enabled": _TYPE_BOOL,
        },
        "required": ("run_id", "recipient_count", "ack_enabled"),
    },
    "EMAIL_SEND_SUCCESS": {
        "fields": {
            "run_id": _TYPE_STR,
            "recipient_count": _TYPE_INT,
        },
        "required": ("run_id", "recipient_count"),
    },
    "EMAIL_SEND_FAILED": {
        "fields": {
            "run_id": _TYPE_STR,
            "recipient_count": _TYPE_INT,
            "reason": _TYPE_STR,
        },
        "required": ("run_id", "recipient_count"),
    },
    "TLS_VERIFY_DISABLED": {"fields": {"reason": _TYPE_STR}, "required": ()},
    "POLICY_VIOLATION_BLOCKED": {
        "fields": {
            "control": _TYPE_STR,
            "reason": _TYPE_STR,
            "setting": _TYPE_STR,
        },
        "required": ("control",),
    },
    "POLICY_BREAK_GLASS_USED": {"fields": {"break_glass_token_sha256": _TYPE_STR}, "required": ()},
    "HARDENING_REVERSAL_BLOCKED": {"fields": {"reason": _TYPE_STR}, "required": ()},
    "HARDENING_BASELINE_UPDATED": {
        "fields": {
            "old_hash": _TYPE_STR,
            "new_hash": _TYPE_STR,
        },
        "required": (),
    },
    "CONFIG_LEGACY_PASSWORD_IGNORED": {"fields": {}, "required": ()},
    "CONFIG_LOAD_FAILED": {"fields": {"reason": _TYPE_STR}, "required": ()},
    "LEGACY_FEATURE_BLOCKED": {
        "fields": {
            "feature": _TYPE_STR,
            "reason": _TYPE_STR,
        },
        "required": (),
    },
    "SPLUNK_AUTH_FAILED_USING_STORED_SECRET": {"fields": {"server": _TYPE_STR}, "required": ()},
    "SECRET_FILENAME_REJECTED": {"fields": {"reason": _TYPE_STR}, "required": ()},
    "SECRET_FILE_WEAK_ACL_BLOCKED": {"fields": {"secret_path_used": _TYPE_STR}, "required": ()},
    "CRED_SECRET_PATH_SELECTED": {"fields": {"secret_path_used": _TYPE_STR}, "required": ()},
    "SECURITY_ARTIFACT_PATH_UNAVAILABLE": {"fields": {"reason": _TYPE_STR}, "required": ()},
    "SECURITY_ARTIFACT_DEV_FALLBACK": {
        "fields": {
            "secret_path_used": _TYPE_STR,
            "log_path": _TYPE_STR,
            "state_path": _TYPE_STR,
        },
        "required": (),
    },
    "LOG_PATH_SELECTED": {"fields": {"log_path": _TYPE_STR}, "required": ()},
}


class _BrokerRequestError(Exception):
    def __init__(self, status: int, error_code: str):
        super().__init__(error_code)
        self.status = int(status)
        self.error_code = str(error_code)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _looks_secret_like(text: str) -> bool:
    if not text:
        return False
    for pattern in _SECRET_TEXT_PATTERNS:
        if pattern.search(text):
            return True
    if _BASE64_LIKE_RE.match(text):
        return True
    return False


def _sanitize_string(value: str, key_hint: str = "") -> str:
    cleaned = _CTRL_CHAR_RE.sub("", value.replace("\r", " ").replace("\n", " ")).strip()
    if len(cleaned) > MAX_STRING_LENGTH:
        cleaned = cleaned[:MAX_STRING_LENGTH]
    lowered_key = key_hint.lower()
    if any(part in lowered_key for part in _FORBIDDEN_FIELD_PARTS):
        return "[REDACTED]"
    if _looks_secret_like(cleaned):
        return "[REDACTED]"
    return cleaned


def _validate_value(value: Any, expected_type: str, field_name: str) -> Any:
    if expected_type == _TYPE_STR:
        if not isinstance(value, str):
            raise _BrokerRequestError(400, f"invalid_type_{field_name}")
        return _sanitize_string(value, key_hint=field_name)
    if expected_type == _TYPE_INT:
        if (not isinstance(value, int)) or isinstance(value, bool):
            raise _BrokerRequestError(400, f"invalid_type_{field_name}")
        if value < 0 or value > _MAX_INT:
            raise _BrokerRequestError(400, f"invalid_range_{field_name}")
        return value
    if expected_type == _TYPE_BOOL:
        if not isinstance(value, bool):
            raise _BrokerRequestError(400, f"invalid_type_{field_name}")
        return value
    if expected_type == _TYPE_STR_LIST:
        if not isinstance(value, list):
            raise _BrokerRequestError(400, f"invalid_type_{field_name}")
        if len(value) > MAX_LIST_ITEMS:
            raise _BrokerRequestError(400, f"list_too_large_{field_name}")
        out: list[str] = []
        for idx, item in enumerate(value):
            if not isinstance(item, str):
                raise _BrokerRequestError(400, f"invalid_type_{field_name}_{idx}")
            out.append(_sanitize_string(item, key_hint=field_name))
        return out
    raise _BrokerRequestError(400, "unsupported_schema_type")


def _validate_event_payload(event: str, fields: Any) -> dict[str, Any]:
    schema = _EVENT_SCHEMAS.get(event)
    if schema is None:
        raise _BrokerRequestError(400, "unknown_event")
    if fields is None:
        fields = {}
    if not isinstance(fields, dict):
        raise _BrokerRequestError(400, "fields_must_be_object")
    if len(fields) > MAX_FIELDS_PER_EVENT:
        raise _BrokerRequestError(413, "too_many_fields")

    allowed_fields = schema["fields"]
    required_fields = schema["required"]
    for key in fields:
        if key not in allowed_fields:
            raise _BrokerRequestError(400, f"unexpected_field_{key}")
    for required in required_fields:
        if required not in fields:
            raise _BrokerRequestError(400, f"missing_field_{required}")

    sanitized: dict[str, Any] = {}
    for key, value in fields.items():
        sanitized[key] = _validate_value(value, allowed_fields[key], key)
    return sanitized


def _parse_json_bytes(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
    except Exception:
        raise _BrokerRequestError(400, "invalid_json")
    if not isinstance(parsed, dict):
        raise _BrokerRequestError(400, "payload_must_be_object")
    return parsed


def _http_post_json(
    host: str,
    port: int,
    path: str,
    payload: dict[str, Any],
    *,
    token: Optional[str],
    timeout: float = 1.5,
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        return 413, {"ok": False, "error": "payload_too_large"}

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    if token:
        headers["X-Audit-Token"] = token
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


class _BrokerHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, backend_logger: SecurityAuditLogger, auth_token: str):
        super().__init__((BROKER_BIND_HOST, 0), _BrokerRequestHandler)
        self.backend_logger = backend_logger
        self.auth_token = auth_token
        self.logger_lock = threading.Lock()
        self.rate_lock = threading.Lock()
        self.request_times: deque[float] = deque()

    def consume_rate_limit_slot(self) -> bool:
        now = time.monotonic()
        cutoff = now - RATE_WINDOW_SECONDS
        with self.rate_lock:
            while self.request_times and self.request_times[0] < cutoff:
                self.request_times.popleft()
            if len(self.request_times) >= RATE_MAX_REQUESTS:
                return False
            self.request_times.append(now)
            return True


class _BrokerRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SplunkAuditBroker/1.0"
    sys_version = ""

    @property
    def _server(self) -> _BrokerHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except _BrokerRequestError as exc:
            self._send_json(exc.status, {"ok": False, "error": exc.error_code})
        except Exception:
            self._send_json(500, {"ok": False, "error": "internal_error"})

    def _handle_post(self) -> None:
        self._ensure_local_client()
        self._ensure_token()
        self._ensure_rate_limit()

        if self.path == "/v1/log":
            self._handle_log()
            return
        if self.path == "/v1/configure":
            self._handle_configure()
            return
        if self.path == "/v1/record-config-loaded":
            self._handle_record_config_loaded()
            return
        if self.path == "/v1/verify-log-set":
            self._handle_verify_log_set()
            return
        if self.path == "/v1/status":
            self._handle_status()
            return
        raise _BrokerRequestError(404, "not_found")

    def _ensure_local_client(self) -> None:
        client_ip = str(self.client_address[0] or "")
        if client_ip != BROKER_BIND_HOST:
            raise _BrokerRequestError(403, "non_local_client")

    def _ensure_rate_limit(self) -> None:
        if not self._server.consume_rate_limit_slot():
            raise _BrokerRequestError(429, "rate_limited")

    def _ensure_token(self) -> None:
        incoming = str(self.headers.get("X-Audit-Token", ""))
        if not incoming:
            raise _BrokerRequestError(401, "missing_token")
        if not hmac.compare_digest(incoming, self._server.auth_token):
            raise _BrokerRequestError(401, "invalid_token")

    def _read_payload(self) -> dict[str, Any]:
        raw_length = str(self.headers.get("Content-Length", "0")).strip()
        try:
            length = int(raw_length)
        except Exception:
            raise _BrokerRequestError(400, "invalid_content_length")
        if length < 0:
            raise _BrokerRequestError(400, "invalid_content_length")
        if length > MAX_REQUEST_BYTES:
            raise _BrokerRequestError(413, "payload_too_large")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise _BrokerRequestError(400, "truncated_payload")
        return _parse_json_bytes(raw)

    def _handle_log(self) -> None:
        payload = self._read_payload()
        event = str(payload.get("event", "")).strip().upper()
        level = str(payload.get("level", "INFO")).strip().upper()
        if level not in _LEVELS:
            raise _BrokerRequestError(400, "invalid_level")
        if not event:
            raise _BrokerRequestError(400, "missing_event")
        fields = _validate_event_payload(event, payload.get("fields", {}))
        with self._server.logger_lock:
            self._server.backend_logger.log_event(event, level=level, **fields)
        self._send_json(200, {"ok": True})

    def _handle_configure(self) -> None:
        payload = self._read_payload()
        updates: dict[str, Any] = {}

        if "level" in payload:
            lvl = str(payload.get("level", DEFAULT_LEVEL)).strip().upper()
            if lvl not in _LEVELS:
                raise _BrokerRequestError(400, "invalid_level")
            updates["level"] = lvl
        if "verbose" in payload:
            verbose = payload.get("verbose")
            if not isinstance(verbose, bool):
                raise _BrokerRequestError(400, "invalid_verbose")
            updates["verbose"] = verbose
        if "max_bytes" in payload:
            max_b = payload.get("max_bytes")
            if (not isinstance(max_b, int)) or isinstance(max_b, bool):
                raise _BrokerRequestError(400, "invalid_max_bytes")
            if max_b <= 0:
                raise _BrokerRequestError(400, "invalid_max_bytes")
            updates["max_bytes"] = max(max_b, MIN_MAX_BYTES)
        if "backup_count" in payload:
            backups = payload.get("backup_count")
            if (not isinstance(backups, int)) or isinstance(backups, bool):
                raise _BrokerRequestError(400, "invalid_backup_count")
            if backups <= 0:
                raise _BrokerRequestError(400, "invalid_backup_count")
            updates["backup_count"] = max(backups, MIN_BACKUP_COUNT)

        with self._server.logger_lock:
            if "level" in updates:
                self._server.backend_logger.level = updates["level"]
            if "verbose" in updates:
                self._server.backend_logger.verbose = updates["verbose"]
            if "max_bytes" in updates:
                self._server.backend_logger.max_bytes = updates["max_bytes"]
            if "backup_count" in updates:
                self._server.backend_logger.backup_count = updates["backup_count"]
            current = {
                "level": self._server.backend_logger.level,
                "verbose": bool(self._server.backend_logger.verbose),
                "max_bytes": int(self._server.backend_logger.max_bytes),
                "backup_count": int(self._server.backend_logger.backup_count),
                "log_path": str(self._server.backend_logger.log_path),
            }
        self._send_json(200, {"ok": True, "current": current})

    def _handle_record_config_loaded(self) -> None:
        payload = self._read_payload()
        config_path_raw = payload.get("config_path", "")
        if not isinstance(config_path_raw, str):
            raise _BrokerRequestError(400, "invalid_config_path")
        config_path = _sanitize_string(config_path_raw, key_hint="config_path")
        if not config_path:
            raise _BrokerRequestError(400, "missing_config_path")
        with self._server.logger_lock:
            config_sha256 = self._server.backend_logger.record_config_loaded(config_path)
        self._send_json(200, {"ok": True, "config_sha256": config_sha256})

    def _handle_verify_log_set(self) -> None:
        _ = self._read_payload()
        with self._server.logger_lock:
            ok = bool(self._server.backend_logger.verify_log_set())
        self._send_json(200, {"ok": True, "verified": ok})

    def _handle_status(self) -> None:
        _ = self._read_payload()
        with self._server.logger_lock:
            payload = {
                "ok": True,
                "bind_host": BROKER_BIND_HOST,
                "bind_port": int(self._server.server_address[1]),
                "log_path": str(self._server.backend_logger.log_path),
                "level": self._server.backend_logger.level,
                "max_bytes": int(self._server.backend_logger.max_bytes),
                "backup_count": int(self._server.backend_logger.backup_count),
            }
        self._send_json(200, payload)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class BrokerAuditLogger:
    def __init__(
        self,
        *,
        base_url: str = "",
        auth_token: str = "",
        available: bool,
        log_path: str = "",
        level: str = DEFAULT_LEVEL,
        verbose: bool = DEFAULT_VERBOSE,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
        startup_error: str = "",
    ):
        self.base_url = base_url
        self._auth_token = auth_token
        self._available = bool(available)
        self.startup_error = startup_error
        self.log_path = log_path
        self.level = (level or DEFAULT_LEVEL).upper()
        self.verbose = bool(verbose)
        self.max_bytes = max(int(max_bytes or DEFAULT_MAX_BYTES), MIN_MAX_BYTES)
        self.backup_count = max(int(backup_count or DEFAULT_BACKUP_COUNT), MIN_BACKUP_COUNT)
        self._lock = threading.Lock()
        self._last_config_hash = ""
        parsed = urlparse(base_url if base_url else f"http://{BROKER_BIND_HOST}:0")
        self._host = parsed.hostname or BROKER_BIND_HOST
        self._port = int(parsed.port or 0)

    @classmethod
    def session_only(
        cls,
        *,
        startup_error: str = "",
        level: str = DEFAULT_LEVEL,
        verbose: bool = DEFAULT_VERBOSE,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ) -> "BrokerAuditLogger":
        return cls(
            base_url="",
            auth_token="",
            available=False,
            log_path="",
            level=level,
            verbose=verbose,
            max_bytes=max_bytes,
            backup_count=backup_count,
            startup_error=startup_error,
        )

    @property
    def is_available(self) -> bool:
        return bool(self._available)

    def unavailable_warning(self) -> str:
        if self._available:
            return ""
        return PERSISTENT_AUDIT_UNAVAILABLE_WARNING

    def _disable(self, reason: str) -> None:
        with self._lock:
            self._available = False
            self.startup_error = self.startup_error or reason
            self._auth_token = ""

    def _post(self, path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if not self._available or not self._port:
            raise RuntimeError("broker_unavailable")
        return _http_post_json(
            self._host,
            self._port,
            path,
            payload,
            token=self._auth_token,
            timeout=1.5,
        )

    def configure(
        self,
        *,
        level: Optional[str] = None,
        verbose: Optional[bool] = None,
        max_bytes: Optional[int] = None,
        backup_count: Optional[int] = None,
    ) -> bool:
        updates: dict[str, Any] = {}
        if level is not None:
            lvl = str(level).strip().upper()
            if lvl in _LEVELS:
                self.level = lvl
                updates["level"] = lvl
        if verbose is not None:
            self.verbose = bool(verbose)
            updates["verbose"] = self.verbose
        if max_bytes is not None:
            self.max_bytes = max(int(max_bytes), MIN_MAX_BYTES)
            updates["max_bytes"] = self.max_bytes
        if backup_count is not None:
            self.backup_count = max(int(backup_count), MIN_BACKUP_COUNT)
            updates["backup_count"] = self.backup_count

        if not self._available or not updates:
            return False
        try:
            status, data = self._post("/v1/configure", updates)
        except Exception:
            self._disable("broker_unreachable")
            return False
        if status != 200 or not bool(data.get("ok")):
            return False
        current = data.get("current", {})
        if isinstance(current, dict):
            self.level = str(current.get("level", self.level)).upper()
            self.verbose = bool(current.get("verbose", self.verbose))
            self.max_bytes = max(int(current.get("max_bytes", self.max_bytes)), MIN_MAX_BYTES)
            self.backup_count = max(int(current.get("backup_count", self.backup_count)), MIN_BACKUP_COUNT)
            self.log_path = str(current.get("log_path", self.log_path))
        return True

    def log_event(self, event: str, level: str = "INFO", **fields) -> bool:
        if not self._available:
            return False
        payload = {
            "event": str(event or "").strip().upper(),
            "level": str(level or "INFO").strip().upper(),
            "fields": fields if isinstance(fields, dict) else {},
        }
        try:
            status, data = self._post("/v1/log", payload)
        except Exception:
            self._disable("broker_unreachable")
            return False
        if status >= 500:
            self._disable("broker_error")
            return False
        return status == 200 and bool(data.get("ok"))

    def record_config_loaded(self, config_path: str) -> str:
        path = str(config_path or "")
        if self._available:
            try:
                status, data = self._post("/v1/record-config-loaded", {"config_path": path})
                if status == 200 and bool(data.get("ok")):
                    config_sha256 = str(data.get("config_sha256", ""))
                    if config_sha256:
                        self._last_config_hash = config_sha256
                    return config_sha256
            except Exception:
                self._disable("broker_unreachable")
        try:
            config_sha256 = _sha256_file(path)
        except Exception:
            return ""
        self._last_config_hash = config_sha256
        return config_sha256

    def verify_log_set(self) -> bool:
        if not self._available:
            return False
        try:
            status, data = self._post("/v1/verify-log-set", {})
        except Exception:
            self._disable("broker_unreachable")
            return False
        if status != 200 or not bool(data.get("ok")):
            return False
        return bool(data.get("verified"))


@dataclass
class LocalLoggingBrokerHandle:
    audit_logger: BrokerAuditLogger
    bind_host: str = ""
    bind_port: int = 0
    startup_error: str = ""
    _server: Optional[_BrokerHTTPServer] = None
    _thread: Optional[threading.Thread] = None
    _auth_token: str = ""

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._server is not None)

    def shutdown(self) -> None:
        server = self._server
        if server is None:
            return
        try:
            server.shutdown()
        except Exception:
            pass
        try:
            server.server_close()
        except Exception:
            pass
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)
        self._server = None
        self._thread = None

    def selfcheck_post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        token: Optional[str] = None,
    ) -> tuple[int, dict[str, Any]]:
        if not self.bind_host or not self.bind_port:
            return 0, {"ok": False, "error": "broker_not_running"}
        effective_token = self._auth_token if token is None else token
        try:
            return _http_post_json(
                self.bind_host,
                self.bind_port,
                path,
                payload,
                token=effective_token,
                timeout=1.5,
            )
        except Exception:
            return 0, {"ok": False, "error": "request_failed"}

    def child_auth_config(self) -> tuple[str, str]:
        if not self.bind_host or not self.bind_port or not self._auth_token:
            return "", ""
        return f"http://{self.bind_host}:{self.bind_port}/v1/log", self._auth_token


def start_local_logging_broker(
    *,
    exe_dir: str,
    tool_version: str,
    allow_local_appdata: bool = False,
    level: str = DEFAULT_LEVEL,
    verbose: bool = DEFAULT_VERBOSE,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> LocalLoggingBrokerHandle:
    try:
        backend_logger = SecurityAuditLogger(
            exe_dir=exe_dir,
            tool_version=tool_version,
            level=level,
            verbose=verbose,
            max_bytes=max_bytes,
            backup_count=backup_count,
            allow_local_appdata=allow_local_appdata,
        )
    except Exception as exc:
        client = BrokerAuditLogger.session_only(
            startup_error=str(exc),
            level=level,
            verbose=verbose,
            max_bytes=max_bytes,
            backup_count=backup_count,
        )
        return LocalLoggingBrokerHandle(
            audit_logger=client,
            bind_host="",
            bind_port=0,
            startup_error=str(exc),
        )

    auth_token = secrets.token_urlsafe(32)
    try:
        server = _BrokerHTTPServer(backend_logger=backend_logger, auth_token=auth_token)
        thread = threading.Thread(target=server.serve_forever, name="LocalAuditBroker", daemon=True)
        thread.start()
        bind_port = int(server.server_address[1])
        base_url = f"http://{BROKER_BIND_HOST}:{bind_port}"
        client = BrokerAuditLogger(
            base_url=base_url,
            auth_token=auth_token,
            available=True,
            log_path=backend_logger.log_path,
            level=backend_logger.level,
            verbose=backend_logger.verbose,
            max_bytes=backend_logger.max_bytes,
            backup_count=backend_logger.backup_count,
        )
        return LocalLoggingBrokerHandle(
            audit_logger=client,
            bind_host=BROKER_BIND_HOST,
            bind_port=bind_port,
            startup_error="",
            _server=server,
            _thread=thread,
            _auth_token=auth_token,
        )
    except Exception as exc:
        try:
            server.server_close()  # type: ignore[name-defined]
        except Exception:
            pass
        client = BrokerAuditLogger.session_only(
            startup_error=str(exc),
            level=level,
            verbose=verbose,
            max_bytes=max_bytes,
            backup_count=backup_count,
        )
        return LocalLoggingBrokerHandle(
            audit_logger=client,
            bind_host="",
            bind_port=0,
            startup_error=str(exc),
        )
