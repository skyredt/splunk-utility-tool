from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Optional


STATE_SCHEMA_VERSION = 2
TERMINAL_BATCH_STATES = {"COMPLETED", "FAILED", "EXPIRED", "ABORTED"}
LOCK_STALE_SECONDS = 4 * 60 * 60
_REQUIRED_JOURNAL_FIELDS = ("schema_version", "batch_id", "batch_state", "slices")
_REQUIRED_LOCK_FIELDS = ("schema_version", "lock_key", "batch_id", "active")


def _sanitize_filename(value: str) -> str:
    cleaned = []
    for ch in str(value or "").strip():
        if ch.isalnum() or ch in ("-", "_", "."):
            cleaned.append(ch)
        else:
            cleaned.append("_")
    text = "".join(cleaned).strip("._")
    return text or "unnamed"


def state_root_dir() -> str:
    root = os.path.join(tempfile.gettempdir(), "SplunkUtilityTool_v4", "state")
    os.makedirs(root, exist_ok=True)
    return root


def journals_dir() -> str:
    path = os.path.join(state_root_dir(), "journals")
    os.makedirs(path, exist_ok=True)
    return path


def locks_dir() -> str:
    path = os.path.join(state_root_dir(), "locks")
    os.makedirs(path, exist_ok=True)
    return path


def archived_dir() -> str:
    path = os.path.join(state_root_dir(), "archived")
    os.makedirs(path, exist_ok=True)
    return path


def batch_journal_path(batch_id: str) -> str:
    return os.path.join(journals_dir(), f"{_sanitize_filename(batch_id)}.json")


def overlap_lock_path(lock_key: str) -> str:
    return os.path.join(locks_dir(), f"{_sanitize_filename(lock_key)}.lock.json")


def hash_lock_key(raw_key: str) -> str:
    return hashlib.sha1(str(raw_key or "").encode("utf-8")).hexdigest()[:20]


def _best_effort_fsync_directory(path: str) -> None:
    directory = os.path.dirname(path)
    if not directory:
        return
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(directory, flags)
    except Exception:
        return
    try:
        os.fsync(fd)
    except Exception:
        pass
    finally:
        try:
            os.close(fd)
        except Exception:
            pass


def _atomic_write_json(path: str, payload: dict[str, Any]) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    temp_path = os.path.join(parent, f".{os.path.basename(path)}.{os.getpid()}.{time.time_ns()}.tmp")
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    replace_error: Optional[Exception] = None
    for attempt in range(5):
        try:
            os.replace(temp_path, path)
            replace_error = None
            break
        except PermissionError as exc:
            replace_error = exc
            time.sleep(0.05 * (attempt + 1))
    if replace_error is not None:
        raise replace_error
    _best_effort_fsync_directory(path)


def _write_json_exclusive(path: str, payload: dict[str, Any]) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        raise
    _best_effort_fsync_directory(path)


def _load_json_file_with_error(path: str) -> tuple[dict[str, Any], str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return {}, "missing_file"
    except json.JSONDecodeError as exc:
        return {}, f"invalid_json:{exc.msg}"
    except OSError as exc:
        return {}, f"io_error:{type(exc).__name__}"
    except Exception as exc:
        return {}, f"unexpected_load_error:{type(exc).__name__}"
    if not isinstance(payload, dict):
        return {}, "payload_not_object"
    return payload, ""


def _validate_state_payload(payload: dict[str, Any], *, kind: str) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "payload_not_object"
    required_fields = _REQUIRED_JOURNAL_FIELDS if kind == "journal" else _REQUIRED_LOCK_FIELDS
    for key in required_fields:
        if key not in payload:
            return False, f"missing_{key}"
    try:
        schema_version = int(payload.get("schema_version", 0) or 0)
    except Exception:
        return False, "invalid_schema_version"
    if schema_version != STATE_SCHEMA_VERSION:
        return False, f"unsupported_schema_version:{schema_version}"
    if kind == "journal" and not isinstance(payload.get("slices"), list):
        return False, "invalid_slices"
    if kind == "lock" and not isinstance(payload.get("active"), bool):
        return False, "invalid_active_flag"
    return True, ""


def _parse_timestamp_epoch(value: Any) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc).timestamp()
    except Exception:
        return 0.0


def _stale_lock_reason(payload: dict[str, Any], *, path: str) -> str:
    if not isinstance(payload, dict) or not payload:
        return "invalid_lock_payload"
    if not bool(payload.get("active", True)):
        return "inactive_lock"
    journal_path = str(payload.get("journal_path", "") or "").strip()
    if journal_path:
        journal_payload, journal_error = _load_json_file_with_error(journal_path)
        if journal_error:
            return f"missing_or_invalid_journal:{journal_error}"
        valid_journal, journal_reason = _validate_state_payload(journal_payload, kind="journal")
        if not valid_journal:
            return f"invalid_journal:{journal_reason}"
        if journal_is_terminal(journal_payload):
            return f"terminal_journal:{str(journal_payload.get('batch_state', '') or '').strip() or 'UNKNOWN'}"
    started_epoch = _parse_timestamp_epoch(payload.get("started_utc"))
    if not started_epoch:
        try:
            started_epoch = os.path.getmtime(path)
        except Exception:
            started_epoch = 0.0
    if started_epoch and (time.time() - started_epoch) > LOCK_STALE_SECONDS:
        return "lock_age_exceeded"
    return ""


def load_json_file(path: str) -> dict[str, Any]:
    payload, _ = _load_json_file_with_error(path)
    return payload


def write_batch_journal(path: str, payload: dict[str, Any]) -> None:
    _atomic_write_json(path, payload)


def journal_is_terminal(payload: dict[str, Any]) -> bool:
    state = str(payload.get("batch_state", "") or "").strip().upper()
    return state in TERMINAL_BATCH_STATES


def list_unfinished_journals() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    root = journals_dir()
    for name in sorted(os.listdir(root)):
        if not name.lower().endswith(".json"):
            continue
        path = os.path.join(root, name)
        payload, load_error = _load_json_file_with_error(path)
        if load_error:
            entries.append(
                {
                    "schema_version": STATE_SCHEMA_VERSION,
                    "batch_id": os.path.splitext(name)[0] or "unknown-batch",
                    "batch_state": "INVALID",
                    "report_names": [],
                    "slices": [],
                    "invalid_journal": True,
                    "invalid_reason": load_error,
                    "_journal_path": path,
                }
            )
            continue
        valid, reason = _validate_state_payload(payload, kind="journal")
        if not valid:
            payload["invalid_journal"] = True
            payload["invalid_reason"] = reason
            payload["_journal_path"] = path
            entries.append(payload)
            continue
        if journal_is_terminal(payload):
            continue
        payload["_journal_path"] = path
        entries.append(payload)
    return entries


def acquire_overlap_lock(lock_key: str, batch_id: str, metadata: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
    path = overlap_lock_path(lock_key)
    payload = {
        "schema_version": STATE_SCHEMA_VERSION,
        "lock_key": str(lock_key or "").strip(),
        "batch_id": str(batch_id or "").strip(),
        "active": True,
        **(metadata if isinstance(metadata, dict) else {}),
    }
    for _ in range(3):
        try:
            _write_json_exclusive(path, payload)
            return True, payload, path
        except FileExistsError:
            current, load_error = _load_json_file_with_error(path)
            if load_error:
                try:
                    os.remove(path)
                    _best_effort_fsync_directory(path)
                    payload["_stale_lock_recovered"] = True
                    payload["_stale_lock_reason"] = f"invalid_existing_lock:{load_error}"
                    continue
                except Exception:
                    return False, {"invalid_lock": True, "invalid_reason": load_error}, path
            valid, reason = _validate_state_payload(current, kind="lock")
            if not valid:
                try:
                    os.remove(path)
                    _best_effort_fsync_directory(path)
                    payload["_stale_lock_recovered"] = True
                    payload["_stale_lock_reason"] = f"invalid_existing_lock:{reason}"
                    continue
                except Exception:
                    current["invalid_lock"] = True
                    current["invalid_reason"] = reason
                    return False, current, path
            stale_reason = _stale_lock_reason(current, path=path)
            if stale_reason:
                try:
                    os.remove(path)
                    _best_effort_fsync_directory(path)
                    payload["_stale_lock_recovered"] = True
                    payload["_stale_lock_reason"] = stale_reason
                    continue
                except Exception:
                    current["_stale_lock_reason"] = stale_reason
                    return False, current, path
            existing_batch_id = str(current.get("batch_id", "") or "").strip()
            if existing_batch_id and existing_batch_id != str(batch_id or "").strip() and bool(current.get("active", True)):
                return False, current, path
            _atomic_write_json(path, payload)
            return True, payload, path
    return False, {"lock_key": str(lock_key or "").strip(), "batch_id": str(batch_id or "").strip()}, path


def release_overlap_lock(lock_key: str, batch_id: str) -> None:
    path = overlap_lock_path(lock_key)
    if not os.path.exists(path):
        return
    payload, load_error = _load_json_file_with_error(path)
    if load_error:
        try:
            os.remove(path)
            _best_effort_fsync_directory(path)
        except Exception:
            pass
        return
    existing_batch_id = str(payload.get("batch_id", "") or "").strip()
    if existing_batch_id and existing_batch_id != str(batch_id or "").strip():
        return
    try:
        os.remove(path)
        _best_effort_fsync_directory(path)
    except Exception:
        payload["active"] = False
        _atomic_write_json(path, payload)


def archive_batch_artifacts(payload: dict[str, Any], *, reason: str = "") -> dict[str, str]:
    batch_id = str(payload.get("batch_id", "") or "").strip() or "unknown-batch"
    stamp = f"{int(time.time())}-{time.time_ns() % 1_000_000}"
    archive_base = os.path.join(archived_dir(), f"{_sanitize_filename(batch_id)}-{stamp}")
    journal_src = str(payload.get("_journal_path", payload.get("journal_path", "")) or "").strip()
    lock_src = str(payload.get("lock_path", "") or "").strip()
    archived_payload = dict(payload)
    archived_payload["batch_state"] = str(payload.get("batch_state", "") or "ABORTED").strip() or "ABORTED"
    archived_payload["archived_reason"] = str(reason or "").strip()
    archived_payload["archived_epoch"] = int(time.time())
    archived_journal_path = f"{archive_base}.journal.json"
    _atomic_write_json(archived_journal_path, archived_payload)

    if journal_src and os.path.exists(journal_src):
        try:
            os.remove(journal_src)
        except Exception:
            pass

    archived_lock_path = ""
    if lock_src:
        lock_payload = load_json_file(lock_src) if os.path.exists(lock_src) else {}
        if lock_payload:
            lock_payload["active"] = False
            lock_payload["archived_reason"] = str(reason or "").strip()
        archived_lock_path = f"{archive_base}.lock.json"
        _atomic_write_json(archived_lock_path, lock_payload if lock_payload else {"active": False})
        if os.path.exists(lock_src):
            try:
                os.remove(lock_src)
            except Exception:
                pass

    return {
        "journal_path": archived_journal_path,
        "lock_path": archived_lock_path,
    }
