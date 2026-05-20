from __future__ import annotations

import http.client
import json
import logging
import os
import threading
from logging.handlers import RotatingFileHandler
from typing import Any, Optional
from urllib.parse import urlparse


DEFAULT_RUNTIME_LOG_ENABLED = True
DEFAULT_RUNTIME_LOG_LEVEL = "INFO"
DEFAULT_RUNTIME_LOG_PATH = os.path.join("Internal", "logs", "runtime.log")
DEFAULT_DEBUG_LOG_ENABLED = False
DEFAULT_DEBUG_LOG_LEVEL = "DEBUG"
DEFAULT_DEBUG_LOG_PATH = os.path.join("Internal", "logs", "debug.log")
DEFAULT_DEBUG_BROKER_ENABLED = False
DEFAULT_DEBUG_REST_ENABLED = False
DEFAULT_DEBUG_DISPATCH_ENABLED = False
DEFAULT_DEBUG_TRACEBACKS_ENABLED = False
DEFAULT_MAX_BYTES = 10_485_760
DEFAULT_BACKUP_COUNT = 10

_LEVELS = {"DEBUG", "INFO", "WARN", "ERROR"}
_CATEGORY_TO_FLAG = {
    "broker": "debug_broker_enabled",
    "rest": "debug_rest_enabled",
    "dispatch": "debug_dispatch_enabled",
    "tracebacks": "debug_tracebacks_enabled",
}
_STATE_LOCK = threading.Lock()
_BROKER_HOST = ""
_BROKER_PORT = 0
_BROKER_TOKEN = ""
_LOCAL_LOGS: Optional["PlainTextLogSet"] = None
_SETTINGS: dict[str, Any] = {}
_EXE_DIR = ""


def _coerce_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _coerce_int(value: object, default: int, minimum: int = 1) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        parsed = int(default)
    return max(minimum, parsed)


def _coerce_level(value: object, default: str) -> str:
    candidate = str(value or default).strip().upper() or str(default).strip().upper()
    if candidate not in _LEVELS:
        return str(default).strip().upper() or "INFO"
    return candidate


def _sanitize_text(value: object, limit: int = 1024) -> str:
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    if len(text) > limit:
        return text[:limit]
    return text


def _resolve_log_path(exe_dir: str, raw_path: object, default_relative: str) -> str:
    candidate = str(raw_path or "").strip() or default_relative
    if not os.path.isabs(candidate):
        candidate = os.path.join(exe_dir, candidate)
    return os.path.realpath(os.path.abspath(candidate))


def normalize_file_logging_settings(
    raw: Optional[dict[str, Any]],
    *,
    exe_dir: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    verbose: bool = False,
    test_mode: bool = False,
) -> dict[str, Any]:
    source = dict(raw or {})
    debug_default = bool(verbose or test_mode)
    return {
        "runtime_log_enabled": _coerce_bool(
            source.get("runtime_log_enabled"),
            DEFAULT_RUNTIME_LOG_ENABLED,
        ),
        "runtime_log_level": _coerce_level(
            source.get("runtime_log_level"),
            DEFAULT_RUNTIME_LOG_LEVEL,
        ),
        "runtime_log_path": _resolve_log_path(
            exe_dir,
            source.get("runtime_log_path"),
            DEFAULT_RUNTIME_LOG_PATH,
        ),
        "debug_log_enabled": _coerce_bool(
            source.get("debug_log_enabled"),
            debug_default,
        ),
        "debug_log_level": _coerce_level(
            source.get("debug_log_level"),
            DEFAULT_DEBUG_LOG_LEVEL,
        ),
        "debug_log_path": _resolve_log_path(
            exe_dir,
            source.get("debug_log_path"),
            DEFAULT_DEBUG_LOG_PATH,
        ),
        "debug_broker_enabled": _coerce_bool(
            source.get("debug_broker_enabled"),
            debug_default or DEFAULT_DEBUG_BROKER_ENABLED,
        ),
        "debug_rest_enabled": _coerce_bool(
            source.get("debug_rest_enabled"),
            debug_default or DEFAULT_DEBUG_REST_ENABLED,
        ),
        "debug_dispatch_enabled": _coerce_bool(
            source.get("debug_dispatch_enabled"),
            debug_default or DEFAULT_DEBUG_DISPATCH_ENABLED,
        ),
        "debug_tracebacks_enabled": _coerce_bool(
            source.get("debug_tracebacks_enabled"),
            debug_default or DEFAULT_DEBUG_TRACEBACKS_ENABLED,
        ),
        "max_bytes": _coerce_int(
            source.get("max_bytes", max_bytes),
            max_bytes,
            minimum=1,
        ),
        "backup_count": _coerce_int(
            source.get("backup_count", backup_count),
            backup_count,
            minimum=1,
        ),
    }


class PlainTextLogWriter:
    def __init__(self, logger_name: str):
        self._logger_name = str(logger_name)
        self._logger = logging.getLogger(self._logger_name)
        self._logger.propagate = False
        self._lock = threading.Lock()
        self._path = ""
        self._enabled = False

    @property
    def path(self) -> str:
        return self._path

    def configure(
        self,
        *,
        enabled: bool,
        level: str,
        path: str,
        max_bytes: int,
        backup_count: int,
    ) -> None:
        with self._lock:
            for handler in list(self._logger.handlers):
                self._logger.removeHandler(handler)
                try:
                    handler.close()
                except Exception:
                    pass
            self._enabled = bool(enabled)
            self._path = str(path or "")
            self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
            if not self._enabled or not self._path:
                return
            parent = os.path.dirname(self._path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            handler = RotatingFileHandler(
                self._path,
                maxBytes=max(1, int(max_bytes)),
                backupCount=max(1, int(backup_count)),
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            self._logger.addHandler(handler)

    def write(self, level: str, message: str) -> bool:
        if not self._enabled:
            return False
        with self._lock:
            if not self._logger.handlers:
                return False
            log_level = getattr(logging, str(level or "INFO").upper(), logging.INFO)
            self._logger.log(log_level, _sanitize_text(message, limit=4096))
        return True

    def close(self) -> None:
        with self._lock:
            for handler in list(self._logger.handlers):
                self._logger.removeHandler(handler)
                try:
                    handler.close()
                except Exception:
                    pass
            self._enabled = False


class PlainTextLogSet:
    def __init__(self, *, exe_dir: str, settings: dict[str, Any]):
        self.exe_dir = exe_dir
        self.runtime_writer = PlainTextLogWriter("splunk_tool.runtime")
        self.debug_writer = PlainTextLogWriter("splunk_tool.debug")
        self.settings: dict[str, Any] = {}
        self.configure(settings)

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = dict(settings or {})
        self.runtime_writer.configure(
            enabled=bool(self.settings.get("runtime_log_enabled", DEFAULT_RUNTIME_LOG_ENABLED)),
            level=str(self.settings.get("runtime_log_level", DEFAULT_RUNTIME_LOG_LEVEL)),
            path=str(self.settings.get("runtime_log_path", "")),
            max_bytes=int(self.settings.get("max_bytes", DEFAULT_MAX_BYTES)),
            backup_count=int(self.settings.get("backup_count", DEFAULT_BACKUP_COUNT)),
        )
        self.debug_writer.configure(
            enabled=bool(self.settings.get("debug_log_enabled", DEFAULT_DEBUG_LOG_ENABLED)),
            level=str(self.settings.get("debug_log_level", DEFAULT_DEBUG_LOG_LEVEL)),
            path=str(self.settings.get("debug_log_path", "")),
            max_bytes=int(self.settings.get("max_bytes", DEFAULT_MAX_BYTES)),
            backup_count=int(self.settings.get("backup_count", DEFAULT_BACKUP_COUNT)),
        )

    def write(self, channel: str, level: str, message: str) -> bool:
        if str(channel or "").strip().lower() == "runtime":
            return self.runtime_writer.write(level, message)
        if str(channel or "").strip().lower() == "debug":
            return self.debug_writer.write(level, message)
        return False

    def status(self) -> dict[str, Any]:
        return {
            "runtime_log_path": self.runtime_writer.path,
            "debug_log_path": self.debug_writer.path,
            "settings": dict(self.settings),
        }

    def close(self) -> None:
        self.runtime_writer.close()
        self.debug_writer.close()


def _disabled_settings_from(settings: dict[str, Any]) -> dict[str, Any]:
    disabled = dict(settings or {})
    disabled["runtime_log_enabled"] = False
    disabled["debug_log_enabled"] = False
    return disabled


def _config_mapping(config: object) -> dict[str, Any]:
    if isinstance(config, dict):
        return dict(config)
    if config is None:
        return {}
    payload = getattr(config, "file_logging_config", None)
    if isinstance(payload, dict):
        return dict(payload)
    return {}


def _config_max_bytes(config: object) -> int:
    if config is None:
        return DEFAULT_MAX_BYTES
    try:
        return max(1, int(getattr(config, "logging_max_bytes", DEFAULT_MAX_BYTES)))
    except Exception:
        return DEFAULT_MAX_BYTES


def _config_backup_count(config: object) -> int:
    if config is None:
        return DEFAULT_BACKUP_COUNT
    try:
        return max(1, int(getattr(config, "logging_backup_count", DEFAULT_BACKUP_COUNT)))
    except Exception:
        return DEFAULT_BACKUP_COUNT


def _config_verbose(config: object) -> bool:
    try:
        return bool(getattr(config, "logging_verbose", False))
    except Exception:
        return False


def _config_test_mode(config: object) -> bool:
    runtime_config = getattr(config, "runtime_config", None)
    if isinstance(runtime_config, dict):
        return _coerce_bool(runtime_config.get("test_mode"), False)
    return False


def _broker_target_from_url(url: str) -> tuple[str, int]:
    parsed = urlparse(str(url or "").strip())
    host = str(parsed.hostname or "").strip()
    port = int(parsed.port or 0)
    return host, port


def _http_post_json(
    host: str,
    port: int,
    path: str,
    payload: dict[str, Any],
    *,
    token: str,
    timeout: float = 1.5,
) -> bool:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "Connection": "close",
        "X-Audit-Token": token,
    }
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        status = int(response.status)
        raw = response.read(32_768)
    finally:
        conn.close()
    if status != 200:
        return False
    if not raw:
        return True
    try:
        payload_out = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False
    return isinstance(payload_out, dict) and bool(payload_out.get("ok"))


def configure_tool_logging(
    *,
    exe_dir: str,
    config: object = None,
    broker_url: str = "",
    broker_token: str = "",
) -> dict[str, Any]:
    raw_settings = _config_mapping(config)
    settings = normalize_file_logging_settings(
        raw_settings,
        exe_dir=exe_dir,
        max_bytes=_config_max_bytes(config),
        backup_count=_config_backup_count(config),
        verbose=_config_verbose(config),
        test_mode=_config_test_mode(config),
    )
    effective_broker_url = str(broker_url or os.getenv("SPLUNK_TOOL_LOG_BROKER_URL", "")).strip()
    effective_broker_token = str(broker_token or os.getenv("SPLUNK_TOOL_LOG_BROKER_TOKEN", "")).strip()
    host, port = _broker_target_from_url(effective_broker_url)
    with _STATE_LOCK:
        global _BROKER_HOST, _BROKER_PORT, _BROKER_TOKEN, _LOCAL_LOGS, _SETTINGS, _EXE_DIR
        _SETTINGS = dict(settings)
        _EXE_DIR = exe_dir
        _BROKER_HOST = host
        _BROKER_PORT = port
        _BROKER_TOKEN = effective_broker_token
        if _LOCAL_LOGS is None:
            _LOCAL_LOGS = PlainTextLogSet(
                exe_dir=exe_dir,
                settings=_disabled_settings_from(settings) if (host and port and effective_broker_token) else settings,
            )
        else:
            _LOCAL_LOGS.configure(
                _disabled_settings_from(settings) if (host and port and effective_broker_token) else settings
            )
    if host and port and effective_broker_token:
        try:
            _http_post_json(
                host,
                port,
                "/v1/text-config",
                {"settings": settings},
                token=effective_broker_token,
                timeout=1.5,
            )
        except Exception:
            pass
    return settings


def current_logging_settings() -> dict[str, Any]:
    with _STATE_LOCK:
        return dict(_SETTINGS)


def shutdown_tool_logging() -> None:
    global _LOCAL_LOGS
    with _STATE_LOCK:
        logs = _LOCAL_LOGS
        _LOCAL_LOGS = None
    if logs is not None:
        logs.close()


def runtime_logging_enabled(config: object = None) -> bool:
    settings = _config_mapping(config) if config is not None else current_logging_settings()
    return _coerce_bool(settings.get("runtime_log_enabled"), DEFAULT_RUNTIME_LOG_ENABLED)


def debug_logging_enabled(config: object = None) -> bool:
    settings = _config_mapping(config) if config is not None else current_logging_settings()
    return _coerce_bool(settings.get("debug_log_enabled"), DEFAULT_DEBUG_LOG_ENABLED)


def debug_category_enabled(category: str, config: object = None) -> bool:
    settings = _config_mapping(config) if config is not None else current_logging_settings()
    if not _coerce_bool(settings.get("debug_log_enabled"), DEFAULT_DEBUG_LOG_ENABLED):
        return False
    flag = _CATEGORY_TO_FLAG.get(str(category or "").strip().lower())
    if not flag:
        return True
    return _coerce_bool(settings.get(flag), False)


def _write_via_broker(channel: str, level: str, message: str) -> bool:
    with _STATE_LOCK:
        host = _BROKER_HOST
        port = _BROKER_PORT
        token = _BROKER_TOKEN
    if not host or not port or not token:
        return False
    path = "/v1/runtime-line" if channel == "runtime" else "/v1/debug-line"
    try:
        return _http_post_json(
            host,
            port,
            path,
            {
                "level": _coerce_level(level, "INFO"),
                "message": _sanitize_text(message, limit=4096),
            },
            token=token,
            timeout=1.5,
        )
    except Exception:
        return False


def _write_local(channel: str, level: str, message: str) -> bool:
    global _LOCAL_LOGS
    with _STATE_LOCK:
        logs = _LOCAL_LOGS
        settings = dict(_SETTINGS)
        exe_dir = _EXE_DIR
    if logs is None:
        if not exe_dir:
            return False
        logs = PlainTextLogSet(exe_dir=exe_dir, settings=settings)
        with _STATE_LOCK:
            _LOCAL_LOGS = logs
    elif (
        not bool(logs.settings.get("runtime_log_enabled"))
        and not bool(logs.settings.get("debug_log_enabled"))
    ):
        logs.configure(settings)
    return logs.write(channel, level, message)


def runtime_log(message: str, *, level: str = "INFO") -> bool:
    if not runtime_logging_enabled():
        return False
    clean = _sanitize_text(message, limit=4096)
    if _write_via_broker("runtime", level, clean):
        return True
    return _write_local("runtime", level, clean)


def debug_log(message: str, *, level: str = "DEBUG", category: str = "general") -> bool:
    if not debug_category_enabled(category):
        return False
    clean = _sanitize_text(message, limit=4096)
    if _write_via_broker("debug", level, clean):
        return True
    return _write_local("debug", level, clean)


def _format_debug_fields(fields: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in sorted(fields.keys()):
        value = fields.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, (dict, list, tuple)):
            try:
                rendered = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            except Exception:
                rendered = _sanitize_text(value)
        else:
            rendered = _sanitize_text(value)
        if rendered:
            parts.append(f"{key}={rendered}")
    return " ".join(parts)


def debug_event(event: str, *, category: str = "general", level: str = "DEBUG", **fields: Any) -> bool:
    label = _sanitize_text(str(event or "").strip().upper(), limit=128) or "DEBUG_EVENT"
    suffix = _format_debug_fields(fields if isinstance(fields, dict) else {})
    message = label if not suffix else f"{label} {suffix}"
    return debug_log(message, level=level, category=category)
