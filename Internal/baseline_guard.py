from __future__ import annotations

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


def build_security_fingerprint(
    *,
    tool_version: str,
    policy: SecurityPolicy,
    logging_level: str,
    logging_max_bytes: int,
    logging_backup_count: int,
) -> dict:
    allowed_roots = [
        os.path.normcase(os.path.realpath(os.path.join(policy.exe_dir, "Internal"))),
        os.path.normcase(os.path.realpath(FIXED_PROGRAMDATA_ROOT)),
    ]
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


def _looks_user_profile_path(path_value: str) -> bool:
    value = (path_value or "").replace("/", "\\").lower()
    return ("\\users\\" in value) or ("\\appdata\\" in value) or ("\\local\\temp\\" in value)


def is_weaker_fingerprint(previous: dict, current: dict) -> bool:
    if not previous:
        return True
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
    for path_value in current.get("allowed_artifact_roots", []):
        if _looks_user_profile_path(str(path_value)):
            return True
    required_events = set(SECURITY_ALWAYS_EVENTS)
    current_events = set(current.get("audit_always_events", []))
    if not required_events.issubset(current_events):
        return True
    return False


def _resolve_baseline_candidates(
    exe_dir: str,
    *,
    is_production: bool,
    allow_local_appdata: bool,
) -> list[str]:
    candidates = [
        os.path.join(exe_dir, "Internal", BASELINE_FILENAME),
        os.path.join(FIXED_PROGRAMDATA_ROOT, BASELINE_FILENAME),
    ]
    if (not is_production) and allow_local_appdata:
        local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
        if local_app_data:
            candidates.append(os.path.join(local_app_data, "SplunkUtilityTool", BASELINE_FILENAME))
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
    created_at: Optional[str] = None,
) -> None:
    now = _utc_now_iso()
    payload = {
        "baseline_hash": baseline_hash,
        "created_at": created_at or now,
        "last_seen_at": now,
        "last_seen_hash": baseline_hash,
        "config_hash": config_hash,
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
    allow_local_appdata = (not policy.is_production) and policy.insecure_overrides_active
    candidates = _resolve_baseline_candidates(
        exe_dir,
        is_production=policy.is_production,
        allow_local_appdata=allow_local_appdata,
    )
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
        if baseline_hash and baseline_hash != current_hash:
            weaker = is_weaker_fingerprint(previous_fp if isinstance(previous_fp, dict) else {}, fingerprint)
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
                    created_at=str(record.get("created_at", "")).strip() or None,
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
                created_at=str(record.get("created_at", "")).strip() or None,
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
            created_at=str(record.get("created_at", "")).strip() or None,
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
        created_at=None,
    )
    consumed_ok, consumed_msg = _consume_break_glass_if_needed()
    if not consumed_ok:
        return False, consumed_msg
    return True, "baseline_created"
