from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from Internal.config_manager import LoadedConfig, load_and_validate_config


DEFAULT_POLICY_MODE = "enforced"
DEFAULT_BUILD_MODE = "production"
DEFAULT_ALLOW_INSECURE_OVERRIDES = False
BREAK_GLASS_FILENAME = "policy_break_glass.json"
BREAK_GLASS_USED_FILENAME = "policy_break_glass.used"
MIN_AUDIT_LEVEL = "INFO"
MIN_AUDIT_MAX_BYTES = 10_485_760
MIN_AUDIT_BACKUP_COUNT = 10
_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
_VALID_BUILD_MODES = {"production", "dev"}
_VALID_POLICY_MODES = {"enforced", "permissive"}
_ALWAYS_ON_CONTROLS = {
    "CONFIG_PATH_BINDING",
    "ENDPOINT_HTTPS_REQUIRED",
    "LEGACY_FEATURE_DISABLED",
    "AUTH_MODE",
    "LEGACY_EXTERNAL_CLI_DISABLED",
    "SECRET_FILE_NAME",
    "SECRET_FILE_PATH",
    "SECRET_FILENAME_REJECTED",
}
_TOKENISH_RE = re.compile(
    r"\b(?:"
    r"\$7\$[A-Za-z0-9._~+/=\-]{12,}"
    r"|Bearer\s+[A-Za-z0-9._~+/=\-]{12,}"
    r"|Splunk\s+(?=[A-Za-z0-9._~+/=\-]*\d)[A-Za-z0-9._~+/=\-]{12,}"
    r")\b",
    re.IGNORECASE,
)
_AUTH_LINE_RE = re.compile(r"(authorization\s*:\s*)(.+)", re.IGNORECASE)
_COOKIE_LINE_RE = re.compile(r"(cookie\s*:\s*)(.+)", re.IGNORECASE)
_SECRET_ASSIGN_RE = re.compile(
    r"\b(password|token|sessionkey|authorization|cookie|dpapi|blob|protected|decrypted|auth_header)\s*=\s*([^\s,;]+)",
    re.IGNORECASE,
)
_SAFE_SECRET_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class PolicyViolation(RuntimeError):
    def __init__(self, control: str, detail: str):
        super().__init__(f"{control}: {detail}")
        self.control = control
        self.detail = detail


@dataclass(frozen=True)
class BreakGlassToken:
    valid: bool
    token_sha256: str = ""
    expires_at: str = ""
    reason: str = ""
    issued_by: str = ""
    nonce: str = ""
    error: str = ""
    raw_payload: dict = field(default_factory=dict)


def _canonical(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso8601_utc(raw: str) -> datetime:
    value = (raw or "").strip()
    if not value:
        raise ValueError("empty timestamp")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def resolve_runtime_exe_dir(exe_dir: Optional[str] = None) -> str:
    if exe_dir:
        return _canonical(exe_dir)
    module_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(module_dir).lower() == "internal":
        return _canonical(os.path.dirname(module_dir))
    return _canonical(module_dir)


def expected_config_path(exe_dir: str) -> str:
    return _canonical(os.path.join(exe_dir, "config.ini"))


def break_glass_path(exe_dir: str) -> str:
    return os.path.join(exe_dir, BREAK_GLASS_FILENAME)


def break_glass_used_path(exe_dir: str) -> str:
    return os.path.join(exe_dir, BREAK_GLASS_USED_FILENAME)


def consume_break_glass_token(exe_dir: str) -> None:
    source = break_glass_path(exe_dir)
    target = break_glass_used_path(exe_dir)
    if not os.path.isfile(source):
        raise FileNotFoundError("Break-glass token file is missing.")
    os.replace(source, target)


def _parse_bool(raw: object, default: bool = False) -> bool:
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _read_break_glass_token(exe_dir: str) -> BreakGlassToken:
    token_path = break_glass_path(exe_dir)
    if not os.path.isfile(token_path):
        return BreakGlassToken(valid=False, error="token_file_missing")
    try:
        with open(token_path, "r", encoding="utf-8", errors="replace") as f:
            payload = json.load(f)
    except Exception:
        return BreakGlassToken(valid=False, error="token_json_invalid")
    if not isinstance(payload, dict):
        return BreakGlassToken(valid=False, error="token_json_invalid")

    expires_at = str(payload.get("expires_at", "")).strip()
    reason = str(payload.get("reason", "")).strip()
    issued_by = str(payload.get("issued_by", "")).strip()
    nonce = str(payload.get("nonce", "")).strip()
    if not (expires_at and reason and issued_by and nonce):
        return BreakGlassToken(valid=False, error="token_required_fields_missing")
    try:
        expiry_utc = _parse_iso8601_utc(expires_at)
    except Exception:
        return BreakGlassToken(valid=False, error="token_expiry_invalid")
    if expiry_utc <= _utc_now():
        return BreakGlassToken(valid=False, error="token_expired")

    canonical = json.dumps(
        {
            "expires_at": expires_at,
            "issued_by": issued_by,
            "nonce": nonce,
            "reason": reason,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return BreakGlassToken(
        valid=True,
        token_sha256=digest,
        expires_at=expires_at,
        reason=reason,
        issued_by=issued_by,
        nonce=nonce,
        raw_payload=payload,
    )


@dataclass(frozen=True)
class SecurityPolicy:
    exe_dir: str
    config_path: str
    build_mode: str = DEFAULT_BUILD_MODE
    policy_mode: str = DEFAULT_POLICY_MODE
    allow_insecure_overrides: bool = DEFAULT_ALLOW_INSECURE_OVERRIDES
    break_glass_token: BreakGlassToken = BreakGlassToken(valid=False)

    @property
    def is_production(self) -> bool:
        return (self.build_mode or DEFAULT_BUILD_MODE).strip().lower() == "production"

    @property
    def is_enforced(self) -> bool:
        return (self.policy_mode or DEFAULT_POLICY_MODE).strip().lower() == "enforced"

    @property
    def break_glass_used(self) -> bool:
        return bool(self.break_glass_token.valid)

    @property
    def break_glass_token_sha256(self) -> str:
        return self.break_glass_token.token_sha256

    @property
    def break_glass_active(self) -> bool:
        return (
            self.is_production
            and self.allow_insecure_overrides
            and (self.policy_mode == "permissive")
            and self.break_glass_token.valid
        )

    @property
    def insecure_overrides_active(self) -> bool:
        if self.is_production:
            return self.break_glass_active
        return self.allow_insecure_overrides and (self.policy_mode == "permissive")

    def enforce(self, condition: bool, control: str, detail: str) -> None:
        if condition:
            return
        control_name = (control or "").strip().upper()
        if control_name in _ALWAYS_ON_CONTROLS:
            raise PolicyViolation(control_name, detail)
        if self.is_production and not self.break_glass_active:
            raise PolicyViolation(control_name, detail)
        if self.is_enforced and not self.insecure_overrides_active:
            raise PolicyViolation(control_name, detail)

    def enforce_https_url(self, url: str, control: str = "ENDPOINT_HTTPS_REQUIRED") -> str:
        value = (url or "").strip()
        parsed = urlparse(value)
        self.enforce(bool(parsed.scheme and parsed.netloc), control, f"Invalid endpoint URL: {value!r}")
        self.enforce(parsed.scheme.lower() == "https", control, f"Only https:// endpoints are allowed: {value!r}")
        return value

    def validate_secret_filename(self, secret_file: str) -> str:
        value = (secret_file or "").strip()
        self.enforce(bool(value), "SECRET_FILE_NAME", "secret_file cannot be empty.")
        basename = os.path.basename(value)
        has_sep = ("\\" in value) or ("/" in value)
        has_drive = bool(os.path.splitdrive(value)[0])
        has_control = any(ord(ch) < 32 for ch in value)
        has_colon = ":" in value
        ends_bad = value.endswith(" ") or value.endswith(".")
        self.enforce(not has_sep and not has_drive and value == basename, "SECRET_FILE_PATH", "secret_file must be basename-only.")
        self.enforce(value not in (".", ".."), "SECRET_FILE_PATH", "secret_file cannot be '.' or '..'.")
        self.enforce(not has_colon, "SECRET_FILENAME_REJECTED", "secret_file cannot contain ':'.")
        self.enforce(not has_control, "SECRET_FILENAME_REJECTED", "secret_file cannot contain control characters.")
        self.enforce(not ends_bad, "SECRET_FILENAME_REJECTED", "secret_file cannot end with dot or space.")
        self.enforce(bool(_SAFE_SECRET_FILENAME_RE.match(value)), "SECRET_FILENAME_REJECTED", "secret_file contains unsupported characters.")
        self.enforce(value.lower().endswith(".dpapi"), "SECRET_FILENAME_REJECTED", "secret_file must use .dpapi suffix.")
        return value

    def enforce_tls_verify(self, verify_ssl: bool) -> bool:
        return bool(verify_ssl)

    def enforce_audit_settings(self, level: str, max_bytes: int, backup_count: int) -> tuple[str, int, int]:
        lvl = (level or MIN_AUDIT_LEVEL).strip().upper()
        if lvl not in _LEVELS:
            lvl = MIN_AUDIT_LEVEL
        self.enforce(
            _LEVELS.get(lvl, 0) >= _LEVELS[MIN_AUDIT_LEVEL],
            "AUDIT_LEVEL_MINIMUM",
            f"Audit level must be >= {MIN_AUDIT_LEVEL}.",
        )
        max_b = int(max_bytes)
        backups = int(backup_count)
        self.enforce(max_b >= MIN_AUDIT_MAX_BYTES, "AUDIT_RETENTION_MINIMUM", f"max_bytes must be >= {MIN_AUDIT_MAX_BYTES}.")
        self.enforce(backups >= MIN_AUDIT_BACKUP_COUNT, "AUDIT_RETENTION_MINIMUM", f"backup_count must be >= {MIN_AUDIT_BACKUP_COUNT}.")
        return lvl, max_b, backups

    def config_in_exe_dir(self, candidate_path: str) -> bool:
        return _canonical(candidate_path) == _canonical(expected_config_path(self.exe_dir))

    def env_overrides_allowed(self) -> bool:
        if self.is_production:
            return False
        return self.insecure_overrides_active


def load_security_policy(
    exe_dir: Optional[str] = None,
    requested_config_path: Optional[str] = None,
) -> SecurityPolicy:
    resolved_exe_dir = resolve_runtime_exe_dir(exe_dir)
    expected_cfg = expected_config_path(resolved_exe_dir)

    if requested_config_path:
        requested = _canonical(requested_config_path)
        if requested != expected_cfg:
            raise PolicyViolation(
                "CONFIG_PATH_BINDING",
                f"config.ini must be loaded from exe_dir only: {expected_cfg}",
            )
    loaded = load_and_validate_config(exe_dir=resolved_exe_dir)
    return check_hardening_policy(loaded, exe_dir=resolved_exe_dir, config_path=expected_cfg)


def check_hardening_policy(
    loaded: LoadedConfig,
    *,
    exe_dir: str,
    config_path: str,
) -> SecurityPolicy:
    cfg = loaded.parser
    section = cfg["Security"] if "Security" in cfg else cfg["security"] if "security" in cfg else None
    build_mode = DEFAULT_BUILD_MODE
    mode = DEFAULT_POLICY_MODE
    allow_insecure = DEFAULT_ALLOW_INSECURE_OVERRIDES
    if section is not None:
        build_mode = (section.get("build_mode", build_mode) or build_mode).strip().lower()
        if build_mode not in _VALID_BUILD_MODES:
            raise PolicyViolation("BUILD_MODE_INVALID", f"Unsupported Security.build_mode={build_mode!r}")
        mode = (section.get("policy_mode", mode) or mode).strip().lower()
        if mode not in _VALID_POLICY_MODES:
            raise PolicyViolation("POLICY_MODE_INVALID", f"Unsupported Security.policy_mode={mode!r}")
        allow_insecure = _parse_bool(section.get("allow_insecure_overrides", str(int(allow_insecure))), allow_insecure)

    token = _read_break_glass_token(exe_dir)
    if build_mode == "production" and mode == "permissive":
        if not allow_insecure:
            raise PolicyViolation(
                "POLICY_MODE_INVALID",
                "production/permissive requires allow_insecure_overrides=true and a valid break-glass token.",
            )
        if not token.valid:
            raise PolicyViolation(
                "BREAK_GLASS_REQUIRED",
                f"production/permissive requires a valid unexpired break-glass token ({token.error or 'invalid_token'}).",
            )

    return SecurityPolicy(
        exe_dir=exe_dir,
        config_path=config_path,
        build_mode=build_mode,
        policy_mode=mode,
        allow_insecure_overrides=allow_insecure,
        break_glass_token=token,
    )


def redact_text(text: str) -> str:
    value = str(text or "")
    if not value:
        return value
    redacted = _AUTH_LINE_RE.sub(r"\1[REDACTED]", value)
    redacted = _COOKIE_LINE_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", redacted)
    redacted = _TOKENISH_RE.sub("[REDACTED]", redacted)
    lowered = redacted.lower()
    if ("sessionkey" in lowered) or ("bearer " in lowered) or ("authorization:" in lowered) or ("cookie:" in lowered):
        return "[REDACTED]"
    return redacted
