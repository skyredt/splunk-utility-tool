from __future__ import annotations

import getpass
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Callable, Optional

from Internal.audit_logger import MIN_BACKUP_COUNT, MIN_MAX_BYTES, SECURITY_ALWAYS_EVENTS
from Internal.security_policy import SecurityPolicy, consume_break_glass_token


BASELINE_FILENAME = "security_baseline.json"
BASELINE_SENTINEL = "security_baseline.initialized"
FIXED_PROGRAMDATA_ROOT = r"C:\ProgramData\SplunkUtilityTool"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_payload_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def fingerprint_hash(fingerprint: dict) -> str:
    return hashlib.sha256(_canonical_payload_bytes(fingerprint)).hexdigest()


def _canonical_path(path_value: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path_value)))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()


def _current_user_scope_hash() -> str:
    domain = os.environ.get("USERDOMAIN", "").strip()
    username = ""
    try:
        username = getpass.getuser().strip()
    except Exception:
        username = ""
    if not username:
        username = os.environ.get("USERNAME", "").strip() or os.environ.get("USER", "").strip()
    identity = f"{domain}\\{username}".strip("\\") or "unknown-user"
    return _sha256_text(identity)[:16]


def _install_root_hash(exe_dir: str) -> str:
    return _sha256_text(_canonical_path(exe_dir))[:16]


def _local_appdata_tool_root() -> str:
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    if not local_app_data:
        return ""
    return _canonical_path(os.path.join(local_app_data, "SplunkUtilityTool"))


def _is_subpath(path_value: str, parent_value: str) -> bool:
    if not path_value or not parent_value:
        return False
    try:
        return os.path.commonpath([path_value, parent_value]) == parent_value
    except ValueError:
        return False


def _approved_current_user_artifact_roots(exe_dir: Optional[str]) -> list[str]:
    roots: list[str] = []
    if exe_dir:
        exe_root = _canonical_path(exe_dir)
        roots.append(exe_root)
        roots.append(_canonical_path(os.path.join(exe_root, "Internal")))
    local_tool_root = _local_appdata_tool_root()
    if local_tool_root:
        roots.append(local_tool_root)
    deduped: list[str] = []
    seen: set[str] = set()
    for root in roots:
        if root and root not in seen:
            seen.add(root)
            deduped.append(root)
    return deduped


def _temp_roots() -> list[str]:
    candidates = [
        os.environ.get("TEMP", "").strip(),
        os.environ.get("TMP", "").strip(),
        os.path.join(os.environ.get("LOCALAPPDATA", "").strip(), "Temp"),
        r"C:\Windows\Temp",
    ]
    roots: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        canonical = _canonical_path(candidate)
        if canonical not in seen:
            seen.add(canonical)
            roots.append(canonical)
    return roots


def _looks_user_profile_path(path_value: str) -> bool:
    value = (path_value or "").replace("/", "\\").lower()
    return ("\\users\\" in value) or ("\\appdata\\" in value) or ("\\local\\temp\\" in value)


def _infer_exe_dir_from_fingerprint(current: dict) -> Optional[str]:
    for raw_path in current.get("allowed_artifact_roots", []):
        candidate = _canonical_path(str(raw_path))
        if os.path.basename(candidate).lower() == "internal":
            return os.path.dirname(candidate)
    return None


def _artifact_root_is_weaker(path_value: str, *, exe_dir: Optional[str]) -> bool:
    candidate = _canonical_path(path_value)
    approved_roots = _approved_current_user_artifact_roots(exe_dir)
    if any(_is_subpath(candidate, approved_root) for approved_root in approved_roots):
        return False
    if any(_is_subpath(candidate, temp_root) for temp_root in _temp_roots()):
        return True
    return _looks_user_profile_path(candidate)


def _scoped_baseline_path(root_dir: str, install_root_hash: str, user_scope_hash: str) -> str:
    return os.path.join(root_dir, "baseline", install_root_hash, user_scope_hash, BASELINE_FILENAME)


def build_security_fingerprint(
    *,
    tool_version: str,
    policy: SecurityPolicy,
    logging_level: str,
    logging_max_bytes: int,
    logging_backup_count: int,
) -> dict:
    allowed_roots = [
        _canonical_path(policy.exe_dir),
        _canonical_path(os.path.join(policy.exe_dir, "Internal")),
        _canonical_path(FIXED_PROGRAMDATA_ROOT),
    ]
    local_tool_root = _local_appdata_tool_root()
    if local_tool_root:
        allowed_roots.append(local_tool_root)
    return {
        "tool_version": tool_version,
        "build_mode": policy.build_mode,
        "policy_mode": policy.policy_mode,
        "allow_insecure_overrides": bool(policy.allow_insecure_overrides),
        "https_only_enforced": True,
        "tls_verify_enforced": False,
        "ui_log_redaction_enabled": False,
        "allowed_auth_modes": ["password"],
        "legacy_features_enabled": False,
        "allowed_artifact_roots": allowed_roots,
        "env_overrides_allowed": bool(policy.env_overrides_allowed()),
        "audit_level": (logging_level or "INFO").upper(),
        "audit_max_bytes": int(logging_max_bytes),
        "audit_backup_count": int(logging_backup_count),
        "audit_min_retention_ok": int(logging_max_bytes) >= MIN_MAX_BYTES and int(logging_backup_count) >= MIN_BACKUP_COUNT,
        "audit_always_events": sorted(SECURITY_ALWAYS_EVENTS),
    }


def is_weaker_fingerprint(previous: dict, current: dict, *, exe_dir: Optional[str] = None) -> bool:
    if not previous:
        return False
    if previous.get("build_mode", "production") == "production" and current.get("build_mode") != "production":
        return True
    if current.get("policy_mode") == "permissive":
        return True
    if bool(current.get("allow_insecure_overrides")):
        return True
    if not bool(current.get("https_only_enforced", True)):
        return True
    if bool(current.get("legacy_features_enabled")):
        return True
    if list(current.get("allowed_auth_modes", [])) != ["password"]:
        return True
    if bool(current.get("env_overrides_allowed")):
        return True
    if not bool(current.get("audit_min_retention_ok")):
        return True
    current_exe_dir = exe_dir or _infer_exe_dir_from_fingerprint(current)
    for path_value in current.get("allowed_artifact_roots", []):
        if _artifact_root_is_weaker(str(path_value), exe_dir=current_exe_dir):
            return True
    required_events = set(SECURITY_ALWAYS_EVENTS)
    current_events = set(current.get("audit_always_events", []))
    if not required_events.issubset(current_events):
        return True
    return False


def _resolve_baseline_candidates(
    exe_dir: str,
) -> list[str]:
    install_root_hash = _install_root_hash(exe_dir)
    user_scope_hash = _current_user_scope_hash()
    candidates = [
        _scoped_baseline_path(os.path.join(exe_dir, "Internal"), install_root_hash, user_scope_hash),
        _scoped_baseline_path(FIXED_PROGRAMDATA_ROOT, install_root_hash, user_scope_hash),
    ]
    local_tool_root = _local_appdata_tool_root()
    if local_tool_root:
        candidates.append(_scoped_baseline_path(local_tool_root, install_root_hash, user_scope_hash))
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
    raise PermissionError("No writable baseline path available.")


def _sentinel_path_for_baseline(path: str) -> str:
    return os.path.join(os.path.dirname(path), BASELINE_SENTINEL)


def _has_prior_baseline_indicator(candidates: list[str]) -> bool:
    for path in candidates:
        if os.path.isfile(_sentinel_path_for_baseline(path)):
            return True
    return False


def _load_baseline(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _save_baseline(
    *,
    path: str,
    baseline_hash: str,
    config_hash: str,
    fingerprint: dict,
    scope_user: str,
    install_root_hash: str,
    created_at: Optional[str] = None,
) -> None:
    now = _utc_now_iso()
    payload = {
        "baseline_scope_version": 2,
        "baseline_hash": baseline_hash,
        "created_at": created_at or now,
        "last_seen_at": now,
        "last_seen_hash": baseline_hash,
        "config_hash": config_hash,
        "scope_user": scope_user,
        "install_root_hash": install_root_hash,
        "baseline_fingerprint": fingerprint,
    }
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, sort_keys=True, ensure_ascii=True, indent=2)
    os.replace(tmp, path)
    sentinel = _sentinel_path_for_baseline(path)
    with open(sentinel, "w", encoding="utf-8") as f:
        f.write("initialized\n")


def enforce_security_baseline(
    *,
    exe_dir: str,
    policy: SecurityPolicy,
    fingerprint: dict,
    config_hash: str,
    confirm_update_fn: Optional[Callable[[str], bool]] = None,
    audit_event_fn: Optional[Callable[..., None]] = None,
) -> tuple[bool, str]:
    current_hash = fingerprint_hash(fingerprint)
    scope_user = _current_user_scope_hash()
    install_root_hash = _install_root_hash(exe_dir)
    candidates = _resolve_baseline_candidates(exe_dir)
    existing = _first_existing(candidates)
    prior_indicator = _has_prior_baseline_indicator(candidates)

    def _audit(event: str, level: str = "WARN", **fields) -> None:
        if audit_event_fn is None:
            return
        audit_event_fn(event, level=level, **fields)

    def _consume_break_glass_if_needed() -> tuple[bool, str]:
        if not (policy.is_production and policy.policy_mode == "permissive" and policy.break_glass_token.valid):
            return True, "not_required"
        prompt = (
            "Production permissive mode requested.\n\n"
            f"Reason: {policy.break_glass_token.reason}\n"
            f"Issued by: {policy.break_glass_token.issued_by}\n"
            f"Expires: {policy.break_glass_token.expires_at}\n\n"
            "Use one-time break-glass token now?"
        )
        if confirm_update_fn is not None and not bool(confirm_update_fn(prompt)):
            _audit("HARDENING_REVERSAL_BLOCKED", level="ERROR", reason="breakglass_confirmation_declined")
            return False, "Break-glass confirmation declined."
        try:
            consume_break_glass_token(exe_dir)
        except Exception:
            _audit("HARDENING_REVERSAL_BLOCKED", level="ERROR", reason="breakglass_consume_failed")
            return False, "Break-glass token consumption failed."
        _audit(
            "POLICY_BREAK_GLASS_USED",
            level="WARN",
            break_glass_token_sha256=policy.break_glass_token_sha256,
        )
        return True, "consumed"

    if existing:
        record = _load_baseline(existing)
        if not record:
            _audit("HARDENING_REVERSAL_BLOCKED", level="ERROR", reason="baseline_invalid_json")
            return False, "Security baseline file is invalid."
        baseline_hash = str(record.get("baseline_hash", "")).strip()
        previous_fp = record.get("baseline_fingerprint", {})
        previous_fp_dict = previous_fp if isinstance(previous_fp, dict) else {}
        created_at = str(record.get("created_at", "")).strip() or None
        if not previous_fp_dict:
            _save_baseline(
                path=existing,
                baseline_hash=current_hash,
                config_hash=config_hash,
                fingerprint=fingerprint,
                scope_user=scope_user,
                install_root_hash=install_root_hash,
                created_at=created_at,
            )
            _audit(
                "BASELINE_BOOTSTRAPPED",
                level="INFO",
                baseline_path=existing,
                scope_user=scope_user,
                install_root_hash=install_root_hash,
                reason="missing_prior_fingerprint",
            )
            consumed_ok, consumed_msg = _consume_break_glass_if_needed()
            if not consumed_ok:
                return False, consumed_msg
            return True, "baseline_bootstrapped"
        if baseline_hash and baseline_hash != current_hash:
            weaker = is_weaker_fingerprint(previous_fp_dict, fingerprint, exe_dir=exe_dir)
            if policy.is_production and weaker:
                if not policy.break_glass_token.valid:
                    _audit("HARDENING_REVERSAL_BLOCKED", level="ERROR", reason="weaker_fingerprint_without_breakglass")
                    return False, "Security configuration downgrade detected."
                prompt = (
                    "A security downgrade was detected.\n\n"
                    f"Reason: {policy.break_glass_token.reason}\n"
                    f"Issued by: {policy.break_glass_token.issued_by}\n"
                    f"Expires: {policy.break_glass_token.expires_at}\n\n"
                    "Apply break-glass baseline update?"
                )
                if confirm_update_fn is not None and not bool(confirm_update_fn(prompt)):
                    _audit("HARDENING_REVERSAL_BLOCKED", level="ERROR", reason="breakglass_confirmation_declined")
                    return False, "Security downgrade update was not confirmed."
                _save_baseline(
                    path=existing,
                    baseline_hash=current_hash,
                    config_hash=config_hash,
                    fingerprint=fingerprint,
                    scope_user=scope_user,
                    install_root_hash=install_root_hash,
                    created_at=created_at,
                )
                _audit(
                    "HARDENING_BASELINE_UPDATED",
                    level="WARN",
                    old_hash=baseline_hash,
                    new_hash=current_hash,
                )
                consumed_ok, consumed_msg = _consume_break_glass_if_needed()
                if not consumed_ok:
                    return False, consumed_msg
                return True, "baseline_updated_breakglass"
            _save_baseline(
                path=existing,
                baseline_hash=current_hash,
                config_hash=config_hash,
                fingerprint=fingerprint,
                scope_user=scope_user,
                install_root_hash=install_root_hash,
                created_at=created_at,
            )
            _audit(
                "HARDENING_BASELINE_UPDATED",
                level="INFO",
                old_hash=baseline_hash,
                new_hash=current_hash,
            )
            consumed_ok, consumed_msg = _consume_break_glass_if_needed()
            if not consumed_ok:
                return False, consumed_msg
            return True, "baseline_updated"
        _save_baseline(
            path=existing,
            baseline_hash=current_hash,
            config_hash=config_hash,
            fingerprint=fingerprint,
            scope_user=scope_user,
            install_root_hash=install_root_hash,
            created_at=created_at,
        )
        consumed_ok, consumed_msg = _consume_break_glass_if_needed()
        if not consumed_ok:
            return False, consumed_msg
        return True, "baseline_ok"

    if policy.is_production and prior_indicator:
        _audit("HARDENING_REVERSAL_BLOCKED", level="ERROR", reason="baseline_missing_with_prior_indicator")
        return False, "Security baseline missing after prior initialization."

    try:
        target = _choose_writable_path(candidates)
    except Exception as exc:
        _audit("SECURITY_ARTIFACT_PATH_UNAVAILABLE", level="ERROR", reason=str(exc))
        return False, "Security artifact path unavailable."
    _save_baseline(
        path=target,
        baseline_hash=current_hash,
        config_hash=config_hash,
        fingerprint=fingerprint,
        scope_user=scope_user,
        install_root_hash=install_root_hash,
        created_at=None,
    )
    _audit(
        "BASELINE_BOOTSTRAPPED",
        level="INFO",
        baseline_path=target,
        scope_user=scope_user,
        install_root_hash=install_root_hash,
        reason="new_scope",
    )
    consumed_ok, consumed_msg = _consume_break_glass_if_needed()
    if not consumed_ok:
        return False, consumed_msg
    return True, "baseline_bootstrapped"
