from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import getpass
import socket


DEFAULT_MAX_BYTES = 10_485_760
DEFAULT_BACKUP_COUNT = 10
DEFAULT_LEVEL = "INFO"
DEFAULT_VERBOSE = False
MIN_MAX_BYTES = 10_485_760
MIN_BACKUP_COUNT = 10
APP_DIRNAME = "SplunkUtilityTool"
FIXED_PROGRAMDATA_ROOT = r"C:\ProgramData\SplunkUtilityTool"
AUDIT_FILENAME = "audit.jsonl"
STATE_FILENAME = "state.json"
ZERO_HASH = "0" * 64
SENSITIVE_KEY_PARTS = (
    "password",
    "token",
    "session",
    "authorization",
    "cookie",
    "auth_header",
    "dpapi",
    "blob",
    "protected",
    "decrypted",
)
SAFE_PATH_KEYS = {
    "secret_path_used",
    "secret_file",
    "config_path",
    "log_path",
    "state_path",
    "baseline_path",
    "missing_path",
    "rotated_path",
}
LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARN": 30,
    "ERROR": 40,
}
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^<>:\"|?*\r\n]+\\)*[^<>:\"|?*\r\n]*")
_TOKENISH_RE = re.compile(r"\b(?:\$7\$|Bearer\s+|Splunk\s+)[A-Za-z0-9._~+/=\-]{6,}", re.IGNORECASE)
SECURITY_ALWAYS_EVENTS = {
    "TOOL_START",
    "TOOL_EXIT",
    "CONFIG_LOADED",
    "CONFIG_CHANGE_DETECTED",
    "CONFIG_LEGACY_PASSWORD_IGNORED",
    "CONFIG_LOAD_FAILED",
    "SECRET_FILE_MISSING",
    "SECRET_FILE_WRITE_FAILED",
    "SECRET_FILE_WEAK_ACL_BLOCKED",
    "CRED_DECRYPT_FAILED",
    "CRED_ENROLL_CREATE",
    "CRED_REENROLL_OVERWRITE",
    "SPLUNK_AUTH_FAILED_USING_STORED_SECRET",
    "TLS_VERIFY_DISABLED",
    "SECRET_FILENAME_REJECTED",
    "SECURITY_ARTIFACT_PATH_UNAVAILABLE",
    "LEGACY_FEATURE_BLOCKED",
    "LOG_CHAIN_START",
    "LOG_ROTATED",
    "LOG_TAMPER_SUSPECTED",
    "LOG_MISSING_DETECTED",
    "POLICY_VIOLATION_BLOCKED",
    "POLICY_BREAK_GLASS_USED",
    "HARDENING_REVERSAL_BLOCKED",
    "HARDENING_BASELINE_UPDATED",
}

# Try to import zoneinfo for proper SGT timezone handling (Python 3.9+)
try:
    from zoneinfo import ZoneInfo
    _HAS_ZONEINFO = True
except ImportError:
    _HAS_ZONEINFO = False


def _sgt_now() -> datetime:
    if _HAS_ZONEINFO:
        try:
            return datetime.now(ZoneInfo("Asia/Singapore"))
        except Exception:
            pass
    return datetime.now(timezone(timedelta(hours=8)))


def _sgt_now_iso() -> str:
    return _sgt_now().isoformat()


def _utc_now_iso() -> str:
    # Legacy helper name; returns SGT timestamps (UTC+8).
    return _sgt_now_iso()


def _canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _compute_entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update((prev_hash or ZERO_HASH).encode("ascii", errors="ignore"))
    digest.update(_canonical_payload_bytes(payload))
    return digest.hexdigest()


def _read_json_line(line: str) -> Optional[dict[str, Any]]:
    raw = line.strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def verify_log_integrity(file_path: str) -> bool:
    if not os.path.isfile(file_path):
        return False
    prev_hash = ZERO_HASH
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            record = _read_json_line(line)
            if not record:
                return False
            record_prev = str(record.get("prev_hash", ""))
            record_entry = str(record.get("entry_hash", ""))
            payload = dict(record)
            payload.pop("prev_hash", None)
            payload.pop("entry_hash", None)
            expected = _compute_entry_hash(prev_hash, payload)
            if record_prev != prev_hash:
                return False
            if record_entry != expected:
                return False
            prev_hash = record_entry
    return True


def _resolve_log_candidates(exe_dir: str, include_local_appdata: bool = False) -> list[str]:
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    candidates = [os.path.join(exe_dir, "Internal", "logs", AUDIT_FILENAME)]
    candidates.append(os.path.join(FIXED_PROGRAMDATA_ROOT, "logs", AUDIT_FILENAME))
    if include_local_appdata and local_app_data:
        candidates.append(os.path.join(local_app_data, APP_DIRNAME, "logs", AUDIT_FILENAME))
    return candidates


def _resolve_state_candidates(exe_dir: str, include_local_appdata: bool = False) -> list[str]:
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    candidates = [os.path.join(exe_dir, "Internal", STATE_FILENAME)]
    candidates.append(os.path.join(FIXED_PROGRAMDATA_ROOT, STATE_FILENAME))
    if include_local_appdata and local_app_data:
        candidates.append(os.path.join(local_app_data, APP_DIRNAME, STATE_FILENAME))
    return candidates


def _first_existing(paths: list[str]) -> Optional[str]:
    for path in paths:
        if os.path.isfile(path):
            return path
    return None


def _choose_writable_path(paths: list[str]) -> str:
    for path in paths:
        parent = os.path.dirname(path)
        try:
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "ab"):
                pass
            return path
        except OSError:
            continue
    raise PermissionError("No writable path available.")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sanitize(value: Any, key_hint: str = "") -> Any:
    key_lower = key_hint.lower()
    if key_lower in SAFE_PATH_KEYS:
        if not value:
            return value
        digest = hashlib.sha256(str(value).encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"<PATH_HASH:{digest}>"
    if any(part in key_lower for part in SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: _sanitize(v, key_hint=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v, key_hint=key_hint) for v in value]
    if isinstance(value, tuple):
        return [_sanitize(v, key_hint=key_hint) for v in value]
    if isinstance(value, str):
        scrubbed = _EMAIL_RE.sub(lambda m: f"<EMAIL_REDACTED>@{m.group(2)}", value)
        scrubbed = _WIN_PATH_RE.sub("<PATH_REDACTED>", scrubbed)
        scrubbed = _TOKENISH_RE.sub("[REDACTED]", scrubbed)
        lowered = scrubbed.lower()
        if "authorization:" in lowered or "sessionkey" in lowered:
            return "[REDACTED]"
        return scrubbed
    return value


class SecurityAuditLogger:
    def __init__(
        self,
        exe_dir: str,
        tool_version: str,
        level: str = DEFAULT_LEVEL,
        verbose: bool = DEFAULT_VERBOSE,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
        allow_local_appdata: bool = False,
    ):
        self.exe_dir = exe_dir
        self.tool_version = tool_version
        self.level = (level or DEFAULT_LEVEL).upper()
        if self.level not in LEVELS:
            self.level = DEFAULT_LEVEL
        self.verbose = bool(verbose)
        self.max_bytes = int(max_bytes) if int(max_bytes) > 0 else DEFAULT_MAX_BYTES
        self.max_bytes = max(self.max_bytes, MIN_MAX_BYTES)
        self.backup_count = int(backup_count) if int(backup_count) > 0 else DEFAULT_BACKUP_COUNT
        self.backup_count = max(self.backup_count, MIN_BACKUP_COUNT)
        self.session_id = str(uuid.uuid4())
        self.run_id = self.session_id
        self.hostname = socket.gethostname()
        self.windows_user = getpass.getuser()
        self.pid = os.getpid()
        self._lock = threading.Lock()
        self._state = {}
        self._last_tamper_error = ""
        self._log_candidates = _resolve_log_candidates(exe_dir, include_local_appdata=allow_local_appdata)
        self._state_candidates = _resolve_state_candidates(exe_dir, include_local_appdata=allow_local_appdata)
        self.log_path = _choose_writable_path(self._log_candidates)
        self.state_path = _first_existing(self._state_candidates) or _choose_writable_path(self._state_candidates)
        self._load_state()

        self._missing_expected_log = None
        previous_log_path = str(self._state.get("last_log_path", "")).strip()
        if previous_log_path and not os.path.exists(previous_log_path):
            self._missing_expected_log = previous_log_path

        self._prev_hash = ZERO_HASH
        self._ensure_chain_ready()
        self._state["last_log_path"] = self.log_path
        self._save_state()

        if self._missing_expected_log:
            self.log_event(
                "LOG_MISSING_DETECTED",
                level="WARN",
                missing_path=self._missing_expected_log,
            )
        if allow_local_appdata:
            local_app_data = os.environ.get("LOCALAPPDATA", "").strip().lower()
            if local_app_data:
                log_path_lower = self.log_path.lower()
                state_path_lower = self.state_path.lower()
                if log_path_lower.startswith(local_app_data) or state_path_lower.startswith(local_app_data):
                    self.log_event(
                        "SECURITY_ARTIFACT_DEV_FALLBACK",
                        level="WARN",
                        log_path=self.log_path,
                        state_path=self.state_path,
                    )

    def _load_state(self) -> None:
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._state = data
                else:
                    self._state = {}
        except Exception:
            self._state = {}

    def _save_state(self) -> None:
        parent = os.path.dirname(self.state_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f, sort_keys=True, ensure_ascii=True, indent=2)
        os.replace(tmp, self.state_path)

    def _should_emit(self, level: str) -> bool:
        level_upper = (level or "INFO").upper()
        current = LEVELS.get(level_upper, LEVELS["INFO"])
        threshold = LEVELS.get(self.level, LEVELS["INFO"])
        return current >= threshold

    def _read_last_entry_hash(self) -> str:
        if not os.path.isfile(self.log_path):
            return ZERO_HASH
        last_line = None
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return ZERO_HASH
        record = _read_json_line(last_line)
        if not record:
            return ZERO_HASH
        return str(record.get("entry_hash", ZERO_HASH))

    def _ensure_chain_ready(self) -> None:
        log_exists = os.path.isfile(self.log_path)
        log_size = os.path.getsize(self.log_path) if log_exists else 0
        if not log_exists or log_size == 0:
            self._prev_hash = ZERO_HASH
            self._write_event(
                "LOG_CHAIN_START",
                level="INFO",
                allow_rotation=False,
                prev_hash_seed=ZERO_HASH,
            )
            return

        if not verify_log_integrity(self.log_path):
            self._last_tamper_error = "hash_chain_verification_failed"
            self._archive_tampered_log()
            self._prev_hash = ZERO_HASH
            self._write_event(
                "LOG_CHAIN_START",
                level="INFO",
                allow_rotation=False,
                prev_hash_seed=ZERO_HASH,
            )
            self._write_event(
                "LOG_TAMPER_SUSPECTED",
                level="ERROR",
                allow_rotation=False,
                reason=self._last_tamper_error,
            )
            return

        self._prev_hash = self._read_last_entry_hash()

    def _archive_tampered_log(self) -> None:
        if not os.path.isfile(self.log_path):
            return
        ts = _sgt_now().strftime("%Y%m%d%H%M%S")
        tampered_path = f"{self.log_path}.tampered_{ts}"
        try:
            os.replace(self.log_path, tampered_path)
        except OSError:
            # If archive move fails, continue and append in place.
            pass

    def _rotate_files(self) -> None:
        if self.backup_count <= 0:
            return
        oldest = f"{self.log_path}.{self.backup_count}"
        if os.path.exists(oldest):
            os.remove(oldest)
        for idx in range(self.backup_count - 1, 0, -1):
            src = f"{self.log_path}.{idx}"
            dst = f"{self.log_path}.{idx + 1}"
            if os.path.exists(src):
                os.replace(src, dst)
        if os.path.exists(self.log_path):
            os.replace(self.log_path, f"{self.log_path}.1")

    def _rotate_if_needed(self, next_line_size: int) -> None:
        current_size = os.path.getsize(self.log_path) if os.path.exists(self.log_path) else 0
        if current_size + next_line_size <= self.max_bytes:
            return
        self._rotate_files()
        self._prev_hash = ZERO_HASH
        self._write_event(
            "LOG_CHAIN_START",
            level="INFO",
            allow_rotation=False,
            prev_hash_seed=ZERO_HASH,
        )
        self._write_event(
            "LOG_ROTATED",
            level="INFO",
            allow_rotation=False,
            rotated_path=self.log_path,
            max_bytes=self.max_bytes,
            backup_count=self.backup_count,
        )

    def _build_payload(self, event: str, level: str, fields: dict[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ts_utc": _utc_now_iso(),
            "level": (level or "INFO").upper(),
            "event": event,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "tool_version": self.tool_version,
            "exe_path": self.exe_dir,
            "hostname": self.hostname,
            "windows_user": self.windows_user,
            "pid": self.pid,
        }
        for key, value in fields.items():
            payload[key] = _sanitize(value, key_hint=key)
        return payload

    def _append_payload(self, payload: dict[str, Any], allow_rotation: bool = True, prev_hash_seed: Optional[str] = None) -> None:
        prev_hash = self._prev_hash if prev_hash_seed is None else prev_hash_seed
        entry_hash = _compute_entry_hash(prev_hash, payload)
        record = dict(payload)
        record["prev_hash"] = prev_hash
        record["entry_hash"] = entry_hash
        line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        encoded = line.encode("utf-8")

        if allow_rotation:
            self._rotate_if_needed(len(encoded))
            prev_hash = self._prev_hash
            entry_hash = _compute_entry_hash(prev_hash, payload)
            record["prev_hash"] = prev_hash
            record["entry_hash"] = entry_hash
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"

        parent = os.path.dirname(self.log_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
        self._prev_hash = record["entry_hash"]
        self._state["last_log_path"] = self.log_path
        self._state["last_entry_hash"] = self._prev_hash
        self._state["last_write_utc"] = payload.get("ts_utc", _utc_now_iso())
        self._save_state()

    def _write_event(
        self,
        event: str,
        level: str = "INFO",
        allow_rotation: bool = True,
        prev_hash_seed: Optional[str] = None,
        **fields,
    ) -> None:
        force_emit = event in SECURITY_ALWAYS_EVENTS
        if (not force_emit) and (not self._should_emit(level)):
            return
        payload = self._build_payload(event, level, fields)
        self._append_payload(payload, allow_rotation=allow_rotation, prev_hash_seed=prev_hash_seed)

    def log_event(self, event: str, level: str = "INFO", **fields) -> None:
        with self._lock:
            self._write_event(event, level=level, allow_rotation=True, **fields)

    def record_config_loaded(self, config_path: str) -> str:
        config_hash = _sha256_file(config_path)
        old_hash = str(self._state.get("last_config_hash", "")).strip()
        self.log_event("CONFIG_LOADED", level="INFO", config_path=config_path, config_sha256=config_hash)
        if old_hash and old_hash != config_hash:
            self.log_event(
                "CONFIG_CHANGE_DETECTED",
                level="WARN",
                previous_config_sha256=old_hash,
                current_config_sha256=config_hash,
            )
        self._state["last_config_hash"] = config_hash
        self._save_state()
        return config_hash

    def verify_current_log(self) -> bool:
        ok = verify_log_integrity(self.log_path)
        if not ok:
            self.log_event("LOG_TAMPER_SUSPECTED", level="ERROR", reason="verification_failed")
        return ok

    def verify_recent_lines(self, recent_lines: int = 1000) -> bool:
        if not os.path.isfile(self.log_path):
            self.log_event("LOG_MISSING_DETECTED", level="WARN", missing_path=self.log_path)
            return False
        if recent_lines <= 0:
            return self.verify_current_log()

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
            tail = deque(f, maxlen=recent_lines)
        if len(tail) < recent_lines:
            return self.verify_current_log()

        prev_hash = None
        for idx, line in enumerate(tail):
            record = _read_json_line(line)
            if not record:
                self.log_event("LOG_TAMPER_SUSPECTED", level="ERROR", reason="invalid_json_tail")
                return False
            if idx == 0:
                prev_hash = str(record.get("prev_hash", ZERO_HASH))
            record_prev = str(record.get("prev_hash", ""))
            record_entry = str(record.get("entry_hash", ""))
            payload = dict(record)
            payload.pop("prev_hash", None)
            payload.pop("entry_hash", None)
            expected = _compute_entry_hash(prev_hash or ZERO_HASH, payload)
            if record_prev != (prev_hash or ZERO_HASH) or record_entry != expected:
                self.log_event("LOG_TAMPER_SUSPECTED", level="ERROR", reason="tail_hash_mismatch")
                return False
            prev_hash = record_entry
        return True

    def verify_log_set(self) -> bool:
        checked_any = False
        files_to_check = [self.log_path]
        for idx in range(1, self.backup_count + 1):
            candidate = f"{self.log_path}.{idx}"
            if os.path.isfile(candidate):
                files_to_check.append(candidate)
        for file_path in files_to_check:
            if not os.path.isfile(file_path):
                continue
            checked_any = True
            if not verify_log_integrity(file_path):
                self.log_event(
                    "LOG_TAMPER_SUSPECTED",
                    level="ERROR",
                    reason="backup_chain_verification_failed",
                    missing_path=file_path,
                )
                return False
        if not checked_any:
            self.log_event("LOG_MISSING_DETECTED", level="WARN", missing_path=self.log_path)
            return False
        return True
