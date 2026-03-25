from __future__ import annotations

import inspect
import importlib
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, List, Optional, Tuple
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
from Internal.batch_state import (
    STATE_SCHEMA_VERSION,
    acquire_overlap_lock,
    archive_batch_artifacts,
    batch_journal_path,
    hash_lock_key,
    load_json_file,
    list_unfinished_journals,
    release_overlap_lock,
    write_batch_journal,
)
from Internal.config_manager import load_and_validate_config
from Internal.security_policy import PolicyViolation, SecurityPolicy, load_security_policy, redact_text

logger = logging.getLogger(__name__)

VALID_AUTH_MODES = ("password",)
TOOL_DISPLAY_NAME = "Splunk Utility Tool"
DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS = 30
DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS = 30
DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT = True
DEFAULT_DISPATCH_TIMEOUT_RESULT = "pending"
DEFAULT_MERGEREPORT_TIMEOUT_SECONDS = 300
DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS = 300
DEFAULT_POSTDISPATCH_POLL_SECONDS = 5
DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS = 900
DEFAULT_POSTDISPATCH_ENABLED = True
DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS = DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS
DISPATCH_TIMEOUT_SECONDS = 30
SNAPSHOT_TIMEOUT_SECONDS = 7
RECONCILE_PASS2_WAIT_SECONDS = 15
RETRY_BACKOFF_SECONDS = 5
PENDING_RECONCILE_MAX_MINUTES = 30
MAX_RETRY_ATTEMPTS_PER_SLICE = 1
RECONCILIATION_WINDOW_BUFFER_SECONDS = 300
DEFAULT_HTTP_CONNECT_TIMEOUT_SECONDS = 10
DEFAULT_HTTP_READ_TIMEOUT_SECONDS = 60
DISPATCH_HTTP_CONNECT_TIMEOUT_SECONDS = 3
DISPATCH_HTTP_READ_TIMEOUT_SECONDS = 30
VERIFICATION_HTTP_CONNECT_TIMEOUT_SECONDS = 2
VERIFICATION_HTTP_READ_TIMEOUT_SECONDS = 10
EVIDENCE_HTTP_CONNECT_TIMEOUT_SECONDS = 2
EVIDENCE_HTTP_READ_TIMEOUT_SECONDS = 8
METADATA_HTTP_CONNECT_TIMEOUT_SECONDS = 2
METADATA_HTTP_READ_TIMEOUT_SECONDS = 10
DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS = 300
DEFAULT_RECONCILE_PENDING_ENABLED = True
DEFAULT_RECONCILE_WAIT_SECONDS = 60
DEFAULT_STATUS_SNAPSHOT_TIMEOUT_RETRIES = 1
FAILED_DISPATCH_STATES = {"FAILED", "ERROR", "CANCELED", "CANCELLED"}
CORRELATION_MODE_TOOL_LOCAL_ONLY = "tool_local_only"
CORRELATION_MODE_SPLUNK_UI_CONTEXT_BEST_EFFORT = "splunk_ui_context_best_effort"
CORRELATION_MODE_SPLUNK_UI_CONTEXT_PROPAGATED = "splunk_ui_context_propagated"
CORRELATION_MODE_TOOL_LOCAL_FALLBACK = "tool_local_fallback"
DISPATCH_REQUEST_CLASS = "dispatch_critical"
_DISPATCH_MINIMAL_FORM_FIELDS = (
    "output_mode",
    "trigger_actions",
    "dispatch.earliest_time",
    "dispatch.latest_time",
)
_DISPATCH_OPTIONAL_FORM_FIELDS = (
    "ui_dispatch_app",
    "ui_dispatch_view",
)
_DISPATCH_ALLOWED_FORM_FIELDS = set(_DISPATCH_MINIMAL_FORM_FIELDS + _DISPATCH_OPTIONAL_FORM_FIELDS)

SLICE_STATE_QUEUED = "QUEUED"
SLICE_STATE_DISPATCHING = "DISPATCHING"
SLICE_STATE_DISPATCHED = "DISPATCHED"
SLICE_STATE_VERIFYING = "VERIFYING"
SLICE_STATE_SUCCESS = "SUCCESS"
SLICE_STATE_FAILED_DISPATCH = "FAILED_DISPATCH"
SLICE_STATE_FAILED_VERIFICATION = "FAILED_VERIFICATION"
SLICE_STATE_TIMEOUT_UNCERTAIN = "TIMEOUT_UNCERTAIN"
SLICE_STATE_PENDING_RECONCILE = "PENDING_RECONCILE"
SLICE_STATE_EXPIRED = "EXPIRED"
PENDING_SLICE_STATES = {
    SLICE_STATE_TIMEOUT_UNCERTAIN,
    SLICE_STATE_PENDING_RECONCILE,
}
_INTERNAL_RUNTIME_EXCEPTION_TYPES = (
    TypeError,
    ValueError,
    KeyError,
    IndexError,
    AttributeError,
    AssertionError,
)


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
    merge_report_timeout_seconds: int = DEFAULT_MERGEREPORT_TIMEOUT_SECONDS
    dispatch_config: Optional[dict] = None
    # Manual regeneration acknowledgement settings
    ack_enabled: bool = True
    ack_on_pending: bool = False
    ack_on_unknown: bool = False
    ack_recipients: List[str] = field(default_factory=list)
    ack_use_savedsearch_recipients: bool = False
    ack_attach_manifest: bool = False
    # SMTP settings for ACK email
    smtp_host: str = "127.0.0.1"
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_use_tls: bool = False
    smtp_from: str = "Splunk Notification <noreply@example.com>"
    # Post-dispatch verification settings (Phase 2)
    postdispatch_config: Optional[dict] = None
    # Plain-text logging settings propagated to the UI runtime payload
    file_logging_config: Optional[dict] = None
    runtime_config: Optional[dict] = None

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


def _parse_min_int(value: object, default: int, minimum: int) -> int:
    return max(minimum, _parse_int(value, default))


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


def _normalize_timeout_result(value: object) -> str:
    raw = str(value or "").strip().lower()
    if raw == "unknown":
        return "UNKNOWN"
    return "PENDING"


def _is_pending_status(value: object) -> bool:
    return str(value or "").strip().upper() in ("PENDING", "UNKNOWN")


def _display_slice_status(value: object) -> str:
    status = str(value or "").strip().upper()
    if status == "UNKNOWN":
        return "PENDING"
    return status or "UNKNOWN"


def _looks_like_connectivity_failure(text: str) -> bool:
    lower = str(text or "").strip().lower()
    return any(
        marker in lower
        for marker in (
            "unable to connect",
            "failed to connect",
            "not connected to splunk",
            "connect_failed",
            "network error",
            "network interruption",
            "transport interrupted",
            "splunk broker unavailable",
            "temporarily degraded",
            "temporarily unavailable",
            "authentication failed",
            "session refresh was unsuccessful",
            "splunk_auth_failed",
            "auth_expired",
            "connect timeout",
            "read timed out",
        )
    )


def _parse_epoch_int(value: object) -> Optional[int]:
    try:
        text = str(value or "").strip()
        if not text:
            return None
        return int(float(text))
    except Exception:
        return None


def _window_match_with_buffer(
    expected_earliest: object,
    expected_latest: object,
    candidate_earliest: object,
    candidate_latest: object,
    *,
    buffer_seconds: int = RECONCILIATION_WINDOW_BUFFER_SECONDS,
) -> tuple[bool, bool]:
    expected_start = _parse_epoch_int(expected_earliest)
    expected_end = _parse_epoch_int(expected_latest)
    candidate_start = _parse_epoch_int(candidate_earliest)
    candidate_end = _parse_epoch_int(candidate_latest)
    exact = (
        expected_start is not None
        and expected_end is not None
        and candidate_start is not None
        and candidate_end is not None
        and expected_start == candidate_start
        and expected_end == candidate_end
    )
    if exact:
        return True, True
    if None in {expected_start, expected_end, candidate_start, candidate_end}:
        return False, False
    safe_buffer = max(0, int(buffer_seconds or 0))
    buffered = (
        abs(expected_start - candidate_start) <= safe_buffer
        and abs(expected_end - candidate_end) <= safe_buffer
    )
    return False, buffered


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
    batch_id: str = ""
    slice_id: str = ""
    attempt_id: int = 0
    report_name: str = ""
    slice_label: str = ""
    slice_index: int = 0
    slice_total: int = 0
    earliest: str = ""
    latest: str = ""
    sid: str = ""
    status: str = "UNKNOWN"  # OK, FAILED, PENDING/UNKNOWN
    outcome_code: str = "DISPATCHED_PENDING"
    error: str = ""
    dispatch_correlation_id: str = ""
    dispatch_started_utc: str = ""
    dispatch_timeout_seconds: int = 0
    dispatch_report_id_url: str = ""
    dispatch_earliest: str = ""
    dispatch_latest: str = ""
    lifecycle_state: str = SLICE_STATE_QUEUED
    state_reason: str = ""
    retry_count: int = 0
    retry_exhausted: bool = False
    finalized_from_reconciliation: bool = False
    reconciliation_source: str = ""
    reconcile_pass_count: int = 0
    pending_since_utc: str = ""
    last_state_change_utc: str = ""
    expired_utc: str = ""
    tainted: bool = False
    taint_reason: str = ""
    execution_context_id: str = ""
    correlation_tag: str = ""
    correlation_mode: str = "tool_local_only"
    report_owner: str = ""
    report_app: str = ""
    verification_mode: str = ""
    reconciliation_confidence: str = ""
    reconciliation_matched_fields: str = ""
    reconciliation_decision_reason: str = ""
    dispatch_outcome: str = ""
    execution_outcome: str = ""
    evidence_outcome: str = ""
    business_outcome: str = ""


@dataclass
class RegenContext:
    """Context for a manual regeneration run."""
    run_id: str
    batch_id: str
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
    batch_state: str = "QUEUED"
    journal_path: str = ""
    lock_key: str = ""
    lock_path: str = ""
    correlation_mode: str = "tool_local_only"
    frozen_definition: dict[str, Any] = field(default_factory=dict)
    recovery_notices: List[str] = field(default_factory=list)

    def add_slice(
        self,
        batch_id: str = "",
        slice_id: str = "",
        attempt_id: int = 0,
        report_name: str = "",
        slice_label: str = "",
        slice_index: int = 0,
        slice_total: int = 0,
        earliest: str = "",
        latest: str = "",
        sid: str = "",
        status: str = "UNKNOWN",
        outcome_code: str = "DISPATCHED_PENDING",
        error: str = "",
        dispatch_correlation_id: str = "",
        dispatch_started_utc: str = "",
        dispatch_timeout_seconds: int = 0,
        dispatch_report_id_url: str = "",
        dispatch_earliest: str = "",
        dispatch_latest: str = "",
        lifecycle_state: str = SLICE_STATE_QUEUED,
        state_reason: str = "",
        retry_count: int = 0,
        retry_exhausted: bool = False,
        finalized_from_reconciliation: bool = False,
        reconciliation_source: str = "",
        reconcile_pass_count: int = 0,
        pending_since_utc: str = "",
        last_state_change_utc: str = "",
        expired_utc: str = "",
        tainted: bool = False,
        taint_reason: str = "",
        execution_context_id: str = "",
        correlation_tag: str = "",
        correlation_mode: str = "tool_local_only",
        report_owner: str = "",
        report_app: str = "",
        verification_mode: str = "",
        reconciliation_confidence: str = "",
        reconciliation_matched_fields: str = "",
        reconciliation_decision_reason: str = "",
        dispatch_outcome: str = "",
        execution_outcome: str = "",
        evidence_outcome: str = "",
        business_outcome: str = "",
    ) -> None:
        self.slices.append(
            RegenSliceRecord(
                batch_id=str(batch_id or self.batch_id or "").strip(),
                slice_id=str(slice_id or "").strip(),
                attempt_id=max(0, int(attempt_id or 0)),
                report_name=report_name,
                slice_label=slice_label,
                slice_index=max(0, int(slice_index or 0)),
                slice_total=max(0, int(slice_total or 0)),
                earliest=earliest,
                latest=latest,
                sid=sid,
                status=(str(status or "").strip().upper() or "UNKNOWN"),
                outcome_code=outcome_code,
                error=error,
                dispatch_correlation_id=str(dispatch_correlation_id or "").strip(),
                dispatch_started_utc=str(dispatch_started_utc or "").strip(),
                dispatch_timeout_seconds=max(0, int(dispatch_timeout_seconds or 0)),
                dispatch_report_id_url=str(dispatch_report_id_url or "").strip(),
                dispatch_earliest=str(dispatch_earliest or "").strip(),
                dispatch_latest=str(dispatch_latest or "").strip(),
                lifecycle_state=str(lifecycle_state or SLICE_STATE_QUEUED).strip().upper() or SLICE_STATE_QUEUED,
                state_reason=str(state_reason or "").strip(),
                retry_count=max(0, int(retry_count or 0)),
                retry_exhausted=bool(retry_exhausted),
                finalized_from_reconciliation=bool(finalized_from_reconciliation),
                reconciliation_source=str(reconciliation_source or "").strip(),
                reconcile_pass_count=max(0, int(reconcile_pass_count or 0)),
                pending_since_utc=str(pending_since_utc or "").strip(),
                last_state_change_utc=str(last_state_change_utc or "").strip(),
                expired_utc=str(expired_utc or "").strip(),
                tainted=bool(tainted),
                taint_reason=str(taint_reason or "").strip(),
                execution_context_id=str(execution_context_id or "").strip(),
                correlation_tag=str(correlation_tag or "").strip(),
                correlation_mode=str(correlation_mode or "tool_local_only").strip() or "tool_local_only",
                report_owner=str(report_owner or "").strip(),
                report_app=str(report_app or "").strip(),
                verification_mode=str(verification_mode or "").strip(),
                reconciliation_confidence=str(reconciliation_confidence or "").strip(),
                reconciliation_matched_fields=str(reconciliation_matched_fields or "").strip(),
                reconciliation_decision_reason=str(reconciliation_decision_reason or "").strip(),
                dispatch_outcome=str(dispatch_outcome or "").strip(),
                execution_outcome=str(execution_outcome or "").strip(),
                evidence_outcome=str(evidence_outcome or "").strip(),
                business_outcome=str(business_outcome or "").strip(),
            )
        )

    def summary_counts(self) -> Tuple[int, int, int]:
        ok_count = sum(1 for s in self.slices if s.status == "OK")
        fail_count = sum(1 for s in self.slices if str(s.status or "").strip().upper() in {"FAILED", "EXPIRED"})
        pending_count = sum(1 for s in self.slices if _is_pending_status(s.status))
        return ok_count, fail_count, pending_count

    def overall_status(self) -> str:
        ok_count, fail_count, pending_count = self.summary_counts()
        total = len(self.slices)
        if pending_count > 0:
            if ok_count > 0 or fail_count > 0:
                return "PARTIAL / PENDING VERIFICATION"
            return "PENDING VERIFICATION"
        if fail_count > 0:
            return "FAILED"
        if total == 0:
            return "UNKNOWN"
        return "OK"


@dataclass
class SliceExecutionContext:
    client: SplunkClient
    run_id: str
    batch_id: str
    slice_id: str
    attempt_id: int
    report_id_url: str
    report_name: str
    slice_label: str
    slice_index: int
    slice_total: int
    earliest_display: str
    latest_display: str
    dispatch_earliest: Optional[str]
    dispatch_latest: Optional[str]
    dispatch_timeout_seconds: int
    snapshot_timeout_seconds: int
    retry_count: int = 0
    current_state: str = SLICE_STATE_QUEUED
    sid: str = ""
    dispatch_correlation_id: str = ""
    tainted: bool = False
    taint_reason: str = ""
    finalized_from_reconciliation: bool = False
    reconciliation_source: str = ""
    reconcile_pass_count: int = 0
    execution_context_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    correlation_tag: str = ""
    correlation_mode: str = "tool_local_only"
    report_owner: str = ""
    report_app: str = ""
    verification_mode: str = ""
    reconciliation_confidence: str = ""
    reconciliation_matched_fields: str = ""
    reconciliation_decision_reason: str = ""

    def mark_state(self, state: str) -> None:
        self.current_state = str(state or SLICE_STATE_QUEUED).strip().upper() or SLICE_STATE_QUEUED

    def mark_tainted(self, reason: str) -> None:
        self.tainted = True
        self.taint_reason = str(reason or "unsafe_reuse").strip() or "unsafe_reuse"


@dataclass
class SavedSearchIdentity:
    owner: str = ""
    app: str = ""
    name: str = ""


@dataclass
class SliceReconcileEvidence:
    confidence: str = "none"
    sid: str = ""
    source: str = ""
    detail: str = ""
    matched_fields: List[str] = field(default_factory=list)
    decision_reason: str = ""
    candidate: Optional[dict[str, Any]] = None


def _normalize_slice_state(value: object) -> str:
    state = str(value or "").strip().upper()
    return state or SLICE_STATE_QUEUED


def _status_for_slice_state(state: str) -> str:
    normalized = _normalize_slice_state(state)
    if normalized == SLICE_STATE_SUCCESS:
        return "OK"
    if normalized in {SLICE_STATE_FAILED_DISPATCH, SLICE_STATE_FAILED_VERIFICATION}:
        return "FAILED"
    if normalized == SLICE_STATE_EXPIRED:
        return "EXPIRED"
    if normalized in PENDING_SLICE_STATES:
        return "PENDING"
    if normalized in {SLICE_STATE_DISPATCHED, SLICE_STATE_VERIFYING, SLICE_STATE_DISPATCHING, SLICE_STATE_QUEUED}:
        return "PENDING"
    return "UNKNOWN"


def _parse_utc_iso(value: object) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _coerce_epoch_seconds(value: object) -> Optional[int]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(float(text))
    except Exception:
        return None


def _pending_expired(item: RegenSliceRecord, *, now_utc: Optional[datetime] = None) -> bool:
    pending_since = _parse_utc_iso(item.pending_since_utc) or _parse_utc_iso(item.dispatch_started_utc)
    if pending_since is None:
        return False
    reference = now_utc or datetime.now(timezone.utc)
    return (reference - pending_since) >= timedelta(minutes=PENDING_RECONCILE_MAX_MINUTES)


def _set_slice_record_state(
    item: RegenSliceRecord,
    *,
    lifecycle_state: str,
    status: Optional[str] = None,
    attempt_id: Optional[int] = None,
    sid: Optional[str] = None,
    outcome_code: Optional[str] = None,
    error: Optional[str] = None,
    state_reason: Optional[str] = None,
    retry_count: Optional[int] = None,
    retry_exhausted: Optional[bool] = None,
    finalized_from_reconciliation: Optional[bool] = None,
    reconciliation_source: Optional[str] = None,
    reconcile_pass_count: Optional[int] = None,
    tainted: Optional[bool] = None,
    taint_reason: Optional[str] = None,
    execution_context_id: Optional[str] = None,
    correlation_tag: Optional[str] = None,
    reconciliation_confidence: Optional[str] = None,
    reconciliation_matched_fields: Optional[str] = None,
    reconciliation_decision_reason: Optional[str] = None,
    dispatch_outcome: Optional[str] = None,
    execution_outcome: Optional[str] = None,
    evidence_outcome: Optional[str] = None,
    business_outcome: Optional[str] = None,
) -> None:
    item.lifecycle_state = _normalize_slice_state(lifecycle_state)
    item.status = str(status or _status_for_slice_state(item.lifecycle_state)).strip().upper()
    if attempt_id is not None:
        item.attempt_id = max(0, int(attempt_id or 0))
    if sid is not None:
        item.sid = str(sid or "").strip()
    if outcome_code is not None:
        item.outcome_code = str(outcome_code or "").strip()
    if error is not None:
        item.error = str(error or "").strip()
    if state_reason is not None:
        item.state_reason = str(state_reason or "").strip()
    if retry_count is not None:
        item.retry_count = max(0, int(retry_count or 0))
    if retry_exhausted is not None:
        item.retry_exhausted = bool(retry_exhausted)
    if finalized_from_reconciliation is not None:
        item.finalized_from_reconciliation = bool(finalized_from_reconciliation)
    if reconciliation_source is not None:
        item.reconciliation_source = str(reconciliation_source or "").strip()
    if reconcile_pass_count is not None:
        item.reconcile_pass_count = max(0, int(reconcile_pass_count or 0))
    if tainted is not None:
        item.tainted = bool(tainted)
    if taint_reason is not None:
        item.taint_reason = str(taint_reason or "").strip()
    if execution_context_id is not None:
        item.execution_context_id = str(execution_context_id or "").strip()
    if correlation_tag is not None:
        item.correlation_tag = str(correlation_tag or "").strip()
    if reconciliation_confidence is not None:
        item.reconciliation_confidence = str(reconciliation_confidence or "").strip()
    if reconciliation_matched_fields is not None:
        item.reconciliation_matched_fields = str(reconciliation_matched_fields or "").strip()
    if reconciliation_decision_reason is not None:
        item.reconciliation_decision_reason = str(reconciliation_decision_reason or "").strip()
    derived_dispatch_outcome, derived_execution_outcome, derived_evidence_outcome, derived_business_outcome = (
        _derive_slice_outcomes(
            lifecycle_state=item.lifecycle_state,
            sid=item.sid,
            finalized_from_reconciliation=item.finalized_from_reconciliation,
            evidence_confidence=item.reconciliation_confidence,
        )
    )
    if dispatch_outcome is not None:
        item.dispatch_outcome = str(dispatch_outcome or "").strip()
    else:
        item.dispatch_outcome = derived_dispatch_outcome
    if execution_outcome is not None:
        item.execution_outcome = str(execution_outcome or "").strip()
    else:
        item.execution_outcome = derived_execution_outcome
    if evidence_outcome is not None:
        item.evidence_outcome = str(evidence_outcome or "").strip()
    else:
        item.evidence_outcome = derived_evidence_outcome
    if business_outcome is not None:
        item.business_outcome = str(business_outcome or "").strip()
    else:
        item.business_outcome = derived_business_outcome
    now_utc = _utc_now_iso()
    item.last_state_change_utc = now_utc
    if item.lifecycle_state in PENDING_SLICE_STATES and not item.pending_since_utc:
        item.pending_since_utc = now_utc
    if item.lifecycle_state == SLICE_STATE_EXPIRED:
        item.expired_utc = now_utc


def _derive_slice_id(
    batch_id: str,
    report_id_url: str,
    report_name: str,
    slice_label: str,
    dispatch_earliest: str,
    dispatch_latest: str,
) -> str:
    raw = "|".join(
        [
            str(batch_id or "").strip(),
            str(report_id_url or "").strip(),
            str(report_name or "").strip(),
            str(slice_label or "").strip(),
            str(dispatch_earliest or "").strip(),
            str(dispatch_latest or "").strip(),
        ]
    )
    return f"slice-{hash_lock_key(raw)}"


def _build_correlation_tag(batch_id: str, slice_id: str, attempt_id: int) -> str:
    return f"{str(batch_id or '').strip()}:{str(slice_id or '').strip()}:a{max(1, int(attempt_id or 1))}"


def _build_correlation_dispatch_value(correlation_tag: str) -> str:
    safe_tag = str(correlation_tag or "").strip()
    if not safe_tag:
        return ""
    return f"sutv4-{hash_lock_key(safe_tag)}"


def _record_recent_metadata_activity(
    client: Any,
    *,
    outcome: str,
    elapsed_ms: int,
    path: str = "",
    error_detail: str = "",
) -> None:
    try:
        setattr(
            client,
            "_recent_metadata_activity",
            {
                "outcome": str(outcome or "").strip(),
                "elapsed_ms": max(0, int(elapsed_ms or 0)),
                "path": str(path or "").strip(),
                "error_detail": _short_error(redact_text(error_detail)) if error_detail else "",
                "recorded_monotonic": time.monotonic(),
                "recorded_utc": _utc_now_iso(),
            },
        )
    except Exception:
        pass


def _get_recent_metadata_activity(client: Any) -> dict[str, Any]:
    raw = getattr(client, "_recent_metadata_activity", {})
    meta = dict(raw) if isinstance(raw, dict) else {}
    recorded_monotonic = meta.get("recorded_monotonic")
    if isinstance(recorded_monotonic, (int, float)):
        try:
            meta["age_ms"] = max(0, int((time.monotonic() - float(recorded_monotonic)) * 1000))
        except Exception:
            meta["age_ms"] = ""
    else:
        meta["age_ms"] = ""
    return meta


def _record_transport_cleanup_activity(
    client: Any,
    *,
    reason: str,
    operation: str = "",
    batch_id: str = "",
    slice_id: str = "",
    attempt_id: int = 0,
) -> None:
    try:
        setattr(
            client,
            "_recent_transport_cleanup",
            {
                "reason": str(reason or "").strip(),
                "operation": str(operation or "").strip(),
                "batch_id": str(batch_id or "").strip(),
                "slice_id": str(slice_id or "").strip(),
                "attempt_id": max(0, int(attempt_id or 0)),
                "recorded_monotonic": time.monotonic(),
                "recorded_utc": _utc_now_iso(),
            },
        )
    except Exception:
        pass


def _get_recent_transport_cleanup(client: Any) -> dict[str, Any]:
    raw = getattr(client, "_recent_transport_cleanup", {})
    meta = dict(raw) if isinstance(raw, dict) else {}
    recorded_monotonic = meta.get("recorded_monotonic")
    if isinstance(recorded_monotonic, (int, float)):
        try:
            meta["age_ms"] = max(0, int((time.monotonic() - float(recorded_monotonic)) * 1000))
        except Exception:
            meta["age_ms"] = ""
    else:
        meta["age_ms"] = ""
    return meta


def _build_dispatch_payload(
    *,
    earliest: Optional[str],
    latest: Optional[str],
    trigger_actions: bool,
    report_app: str = "",
    correlation_dispatch_value: str = "",
    include_optional_fields: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    payload: dict[str, Any] = {"output_mode": "json"}
    optional_keys: list[str] = []
    if trigger_actions:
        payload["trigger_actions"] = 1
    safe_earliest = str(earliest or "").strip()
    safe_latest = str(latest or "").strip()
    if safe_earliest:
        payload["dispatch.earliest_time"] = safe_earliest
    if safe_latest:
        payload["dispatch.latest_time"] = safe_latest
    if include_optional_fields:
        safe_report_app = str(report_app or "").strip()
        safe_dispatch_value = str(correlation_dispatch_value or "").strip()
        if safe_report_app:
            payload["ui_dispatch_app"] = safe_report_app
            optional_keys.append("ui_dispatch_app")
        if safe_dispatch_value:
            payload["ui_dispatch_view"] = safe_dispatch_value
            optional_keys.append("ui_dispatch_view")
    sanitized_payload = {
        key: value
        for key, value in payload.items()
        if key in _DISPATCH_ALLOWED_FORM_FIELDS and value not in (None, "")
    }
    return sanitized_payload, optional_keys


def _summarize_dispatch_payload(payload: dict[str, Any]) -> str:
    safe_payload: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, (int, float, bool)):
            safe_payload[str(key)] = value
            continue
        safe_payload[str(key)] = redact_text(str(value or ""))[:180]
    return json.dumps(
        safe_payload,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _dispatch_payload_keys_text(payload: dict[str, Any]) -> str:
    return ",".join(sorted(str(key or "").strip() for key in payload.keys() if str(key or "").strip()))


def _inspect_dispatch_target(
    report_id_url: str,
    *,
    expected_owner: str = "",
    expected_app: str = "",
) -> dict[str, str]:
    parsed = urlparse(str(report_id_url or "").strip())
    raw_path = str(parsed.path or "").strip()
    path = raw_path[:-9] if raw_path.endswith("/dispatch") else raw_path
    dispatch_path = f"{path.rstrip('/')}/dispatch" if path else ""
    owner = ""
    app = ""
    name = ""
    validation_error = ""
    namespace_consistency = "matched"
    parts = path.strip("/").split("/") if path else []
    if len(parts) >= 6 and parts[0] == "servicesNS" and parts[3] == "saved" and parts[4] == "searches":
        owner = str(parts[1] or "").strip()
        app = str(parts[2] or "").strip()
        name = unquote(parts[5])
    else:
        validation_error = (
            "Saved-search dispatch path must match "
            "/servicesNS/{owner}/{app}/saved/searches/{name}."
        )
        namespace_consistency = "invalid"
    safe_expected_owner = str(expected_owner or "").strip()
    safe_expected_app = str(expected_app or "").strip()
    if not validation_error and safe_expected_owner and owner and safe_expected_owner != owner:
        namespace_consistency = "owner_mismatch"
        validation_error = (
            f"Frozen owner '{safe_expected_owner}' does not match dispatch path owner '{owner}'."
        )
    if not validation_error and safe_expected_app and app and safe_expected_app != app:
        namespace_consistency = "app_mismatch"
        validation_error = (
            f"Frozen app '{safe_expected_app}' does not match dispatch path app '{app}'."
        )
    return {
        "path": path,
        "dispatch_path": dispatch_path,
        "owner": owner,
        "app": app,
        "name": name,
        "validation_error": validation_error,
        "namespace_consistency": namespace_consistency,
    }


def _correlation_scope_for_mode(correlation_mode: str) -> str:
    mode = str(correlation_mode or "").strip().lower()
    if mode in {
        CORRELATION_MODE_SPLUNK_UI_CONTEXT_BEST_EFFORT,
        CORRELATION_MODE_SPLUNK_UI_CONTEXT_PROPAGATED,
        CORRELATION_MODE_TOOL_LOCAL_FALLBACK,
    }:
        return "best_effort_dispatch_ui_context"
    return "tool_local_only"


def _matched_fields_text(values: List[str]) -> str:
    cleaned = [str(value or "").strip() for value in values if str(value or "").strip()]
    return ",".join(cleaned)


def _emit_reconciliation_decision(
    *,
    logs: Optional[List[str]],
    log_callback: Optional[Callable[[str], None]],
    audit_event: Optional[Callable[..., None]],
    context: SliceExecutionContext,
    pass_name: str,
    evidence: SliceReconcileEvidence,
    decision: str,
) -> None:
    matched_fields = _matched_fields_text(evidence.matched_fields)
    decision_reason = str(evidence.decision_reason or evidence.detail or "").strip()
    if logs is not None:
        _append_log(
            logs,
            (
                f"[Debug] RECONCILIATION_DECISION batch_id={context.batch_id} "
                f"slice_id={context.slice_id} attempt_id={context.attempt_id} "
                f"slice_label={context.slice_label} stage_name={pass_name} "
                f"confidence={evidence.confidence or 'none'} matched_fields={matched_fields or '-'} "
                f"decision={decision or 'unspecified'} reason={decision_reason or '-'} "
                f"source={evidence.source or '-'} sid={evidence.sid or '-'}"
            ),
            log_callback,
        )
    if callable(audit_event):
        audit_event(
            "REPORT_SLICE_RECONCILIATION_DECISION",
            level="INFO" if str(evidence.confidence or "").strip().lower() == "strong" else "WARN",
            slice_label=context.slice_label,
            slice_index=context.slice_index,
            slice_total=context.slice_total,
            batch_id=context.batch_id,
            slice_id=context.slice_id,
            attempt_id=context.attempt_id,
            correlation_tag=context.correlation_tag,
            execution_context_id=context.execution_context_id,
            stage_name=pass_name,
            confidence=evidence.confidence or "none",
            matched_fields=matched_fields,
            decision=decision,
            reason=decision_reason,
            evidence_source=evidence.source or "",
            sid=evidence.sid or None,
        )


def _find_slice_record(
    context: Optional[RegenContext],
    *,
    slice_id: str = "",
    report_name: str = "",
    slice_label: str = "",
    earliest: str = "",
    latest: str = "",
) -> Optional[RegenSliceRecord]:
    if context is None:
        return None
    safe_slice_id = str(slice_id or "").strip()
    for item in context.slices:
        if safe_slice_id and str(item.slice_id or "").strip() == safe_slice_id:
            return item
    for item in context.slices:
        if (
            str(item.report_name or "").strip() == str(report_name or "").strip()
            and str(item.slice_label or "").strip() == str(slice_label or "").strip()
            and str(item.earliest or "").strip() == str(earliest or "").strip()
            and str(item.latest or "").strip() == str(latest or "").strip()
        ):
            return item
    return None


def _context_has_active_slices(context: RegenContext) -> bool:
    active_states = {
        SLICE_STATE_QUEUED,
        SLICE_STATE_DISPATCHING,
        SLICE_STATE_DISPATCHED,
        SLICE_STATE_VERIFYING,
        SLICE_STATE_TIMEOUT_UNCERTAIN,
        SLICE_STATE_PENDING_RECONCILE,
    }
    return any(_normalize_slice_state(item.lifecycle_state) in active_states for item in context.slices)


def _derive_batch_state_from_slices(context: RegenContext) -> str:
    if _unresolved_slice_records(context):
        return "PENDING_RECONCILE"
    if any(_normalize_slice_state(item.lifecycle_state) == SLICE_STATE_EXPIRED for item in context.slices):
        return "EXPIRED"
    if any(str(item.status or "").strip().upper() == "FAILED" for item in context.slices):
        return "FAILED"
    if context.slices:
        return "COMPLETED"
    return str(context.batch_state or "QUEUED").strip().upper() or "QUEUED"


def _expire_stale_pending_slices_in_context(
    context: RegenContext,
    *,
    persist_reason: str,
) -> int:
    expired_count = 0
    for item in context.slices:
        if _normalize_slice_state(item.lifecycle_state) not in PENDING_SLICE_STATES:
            continue
        if not _pending_expired(item):
            continue
        _set_slice_record_state(
            item,
            lifecycle_state=SLICE_STATE_EXPIRED,
            status="EXPIRED",
            outcome_code="EXPIRED",
            error=item.error or "Pending reconciliation window expired.",
        )
        expired_count += 1
    if expired_count > 0:
        context.batch_state = _derive_batch_state_from_slices(context)
        _persist_batch_journal(context, reason=persist_reason)
    return expired_count


def _slice_record_to_journal_payload(item: RegenSliceRecord) -> dict[str, Any]:
    return {
        "batch_id": item.batch_id,
        "slice_id": item.slice_id,
        "attempt_id": int(item.attempt_id or 0),
        "report_name": item.report_name,
        "slice_label": item.slice_label,
        "slice_index": int(item.slice_index or 0),
        "slice_total": int(item.slice_total or 0),
        "earliest": item.earliest,
        "latest": item.latest,
        "dispatch_earliest": item.dispatch_earliest,
        "dispatch_latest": item.dispatch_latest,
        "sid": item.sid,
        "status": item.status,
        "lifecycle_state": item.lifecycle_state,
        "outcome_code": item.outcome_code,
        "state_reason": item.state_reason,
        "error": item.error,
        "retry_count": int(item.retry_count or 0),
        "retry_exhausted": bool(item.retry_exhausted),
        "finalized_from_reconciliation": bool(item.finalized_from_reconciliation),
        "reconciliation_source": item.reconciliation_source,
        "reconcile_pass_count": int(item.reconcile_pass_count or 0),
        "pending_since_utc": item.pending_since_utc,
        "last_state_change_utc": item.last_state_change_utc,
        "expired_utc": item.expired_utc,
        "tainted": bool(item.tainted),
        "taint_reason": item.taint_reason,
        "execution_context_id": item.execution_context_id,
        "correlation_tag": item.correlation_tag,
        "correlation_mode": item.correlation_mode,
        "report_owner": item.report_owner,
        "report_app": item.report_app,
        "verification_mode": item.verification_mode,
        "reconciliation_confidence": item.reconciliation_confidence,
        "reconciliation_matched_fields": item.reconciliation_matched_fields,
        "reconciliation_decision_reason": item.reconciliation_decision_reason,
        "dispatch_outcome": item.dispatch_outcome,
        "execution_outcome": item.execution_outcome,
        "evidence_outcome": item.evidence_outcome,
        "business_outcome": item.business_outcome,
    }


def _persist_batch_journal(context: Optional[RegenContext], *, reason: str) -> None:
    if context is None or not context.journal_path:
        return
    payload = {
        "schema_version": STATE_SCHEMA_VERSION,
        "tool_version": TOOL_DISPLAY_NAME,
        "batch_id": context.batch_id,
        "run_id": context.run_id,
        "batch_state": context.batch_state,
        "reason": str(reason or "").strip(),
        "journal_updated_utc": _utc_now_iso(),
        "journal_path": context.journal_path,
        "lock_key": context.lock_key,
        "lock_path": context.lock_path,
        "correlation_mode": context.correlation_mode,
        "report_names": list(context.report_names),
        "app": context.app,
        "operator": context.operator,
        "hostname": context.hostname,
        "savedsearch_recipients": list(context.savedsearch_recipients),
        "frozen_definition": dict(context.frozen_definition) if isinstance(context.frozen_definition, dict) else {},
        "recovery_notices": list(context.recovery_notices),
        "slices": [_slice_record_to_journal_payload(item) for item in context.slices],
    }
    write_batch_journal(context.journal_path, payload)


def _compute_overlap_lock_key(*, report_ids: List[str], frequency: str, start: datetime, end: datetime, no_change: bool) -> str:
    raw = json.dumps(
        {
            "report_ids": [str(value or "").strip() for value in report_ids],
            "frequency": str(frequency or "").strip(),
            "start": start.isoformat(),
            "end": end.isoformat(),
            "no_change": bool(no_change),
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return f"overlap-{hash_lock_key(raw)}"


def _recoverable_batch_lines(payload: dict[str, Any]) -> List[str]:
    batch_id = str(payload.get("batch_id", "") or "").strip() or "unknown-batch"
    invalid_reason = str(payload.get("invalid_reason", "") or "").strip()
    if bool(payload.get("invalid_journal")):
        return [
            f"Recovery journal detected for batch_id={batch_id}",
            f"  Reference ID: {batch_id}",
            f"  Recovery journal is invalid or incompatible: {invalid_reason or 'unknown_reason'}",
        ]
    report_names = payload.get("report_names", [])
    if not isinstance(report_names, list):
        report_names = []
    batch_state = str(payload.get("batch_state", "") or "").strip() or "UNKNOWN"
    return [
        f"Incomplete batch detected: batch_id={batch_id} state={batch_state}",
        f"  Reference ID: {batch_id}",
        f"  Reports: {', '.join(str(name) for name in report_names) or '(unknown)'}",
    ]


def _unresolved_slice_records(context: RegenContext) -> List[RegenSliceRecord]:
    unresolved_states = {
        SLICE_STATE_TIMEOUT_UNCERTAIN,
        SLICE_STATE_PENDING_RECONCILE,
        SLICE_STATE_DISPATCHING,
        SLICE_STATE_DISPATCHED,
        SLICE_STATE_VERIFYING,
    }
    return [
        item
        for item in context.slices
        if _normalize_slice_state(item.lifecycle_state) in unresolved_states or _is_pending_status(item.status)
    ]


def _completed_business_effect_exists(
    context: Optional[RegenContext],
    *,
    slice_id: str,
    report_name: str,
    dispatch_earliest: str,
    dispatch_latest: str,
    exclude_execution_context_id: str = "",
) -> bool:
    if context is None:
        return False
    safe_slice_id = str(slice_id or "").strip()
    safe_report_name = str(report_name or "").strip()
    safe_earliest = str(dispatch_earliest or "").strip()
    safe_latest = str(dispatch_latest or "").strip()
    excluded = str(exclude_execution_context_id or "").strip()
    for item in context.slices:
        if excluded and str(item.execution_context_id or "").strip() == excluded:
            continue
        same_slice = safe_slice_id and str(item.slice_id or "").strip() == safe_slice_id
        same_window = (
            str(item.report_name or "").strip() == safe_report_name
            and str(item.dispatch_earliest or "").strip() == safe_earliest
            and str(item.dispatch_latest or "").strip() == safe_latest
        )
        if not (same_slice or same_window):
            continue
        if str(item.business_outcome or "").strip().upper() == "SUCCESS" or str(item.status or "").strip().upper() == "OK":
            return True
    return False


def _journal_payload_to_context(payload: dict[str, Any]) -> RegenContext:
    context = RegenContext(
        run_id=str(payload.get("run_id", "") or "").strip() or f"recover-{uuid.uuid4().hex[:8]}",
        batch_id=str(payload.get("batch_id", "") or "").strip() or f"batch-recover-{uuid.uuid4().hex[:8]}",
        report_names=[str(name) for name in payload.get("report_names", []) if str(name or "").strip()],
        app=str(payload.get("app", "") or "").strip(),
        operator=str(payload.get("operator", "") or "").strip() or get_effective_username(),
        hostname=str(payload.get("hostname", "") or "").strip() or socket.gethostname(),
        tool_name=str(payload.get("tool_version", TOOL_DISPLAY_NAME) or TOOL_DISPLAY_NAME),
    )
    context.batch_state = str(payload.get("batch_state", "") or "PENDING_RECONCILE").strip().upper()
    context.journal_path = str(payload.get("_journal_path", payload.get("journal_path", "")) or "").strip()
    context.lock_key = str(payload.get("lock_key", "") or "").strip()
    context.lock_path = str(payload.get("lock_path", "") or "").strip()
    context.correlation_mode = str(payload.get("correlation_mode", "tool_local_only") or "tool_local_only").strip() or "tool_local_only"
    context.savedsearch_recipients = [
        str(value)
        for value in payload.get("savedsearch_recipients", [])
        if str(value or "").strip()
    ]
    frozen_definition = payload.get("frozen_definition", {})
    if isinstance(frozen_definition, dict):
        context.frozen_definition = dict(frozen_definition)
    recovery_notices = payload.get("recovery_notices", [])
    if isinstance(recovery_notices, list):
        context.recovery_notices = [str(value) for value in recovery_notices if str(value or "").strip()]
    for item in payload.get("slices", []):
        if not isinstance(item, dict):
            continue
        context.add_slice(
            batch_id=str(item.get("batch_id", context.batch_id) or "").strip(),
            slice_id=str(item.get("slice_id", "") or "").strip(),
            attempt_id=int(item.get("attempt_id", 0) or 0),
            report_name=str(item.get("report_name", "") or "").strip(),
            slice_label=str(item.get("slice_label", "") or "").strip(),
            slice_index=int(item.get("slice_index", 0) or 0),
            slice_total=int(item.get("slice_total", 0) or 0),
            earliest=str(item.get("earliest", "") or "").strip(),
            latest=str(item.get("latest", "") or "").strip(),
            sid=str(item.get("sid", "") or "").strip(),
            status=str(item.get("status", "UNKNOWN") or "UNKNOWN").strip().upper(),
            outcome_code=str(item.get("outcome_code", "") or "").strip(),
            error=str(item.get("error", "") or "").strip(),
            dispatch_correlation_id=str(item.get("dispatch_correlation_id", "") or "").strip(),
            dispatch_started_utc=str(item.get("dispatch_started_utc", "") or "").strip(),
            dispatch_timeout_seconds=int(item.get("dispatch_timeout_seconds", 0) or 0),
            dispatch_report_id_url=str(item.get("dispatch_report_id_url", "") or "").strip(),
            dispatch_earliest=str(item.get("dispatch_earliest", "") or "").strip(),
            dispatch_latest=str(item.get("dispatch_latest", "") or "").strip(),
            lifecycle_state=str(item.get("lifecycle_state", SLICE_STATE_QUEUED) or SLICE_STATE_QUEUED).strip(),
            state_reason=str(item.get("state_reason", "") or "").strip(),
            retry_count=int(item.get("retry_count", 0) or 0),
            retry_exhausted=bool(item.get("retry_exhausted", False)),
            finalized_from_reconciliation=bool(item.get("finalized_from_reconciliation", False)),
            reconciliation_source=str(item.get("reconciliation_source", "") or "").strip(),
            reconcile_pass_count=int(item.get("reconcile_pass_count", 0) or 0),
            pending_since_utc=str(item.get("pending_since_utc", "") or "").strip(),
            last_state_change_utc=str(item.get("last_state_change_utc", "") or "").strip(),
            expired_utc=str(item.get("expired_utc", "") or "").strip(),
            tainted=bool(item.get("tainted", False)),
            taint_reason=str(item.get("taint_reason", "") or "").strip(),
            execution_context_id=str(item.get("execution_context_id", "") or "").strip(),
            correlation_tag=str(item.get("correlation_tag", "") or "").strip(),
            correlation_mode=str(item.get("correlation_mode", "tool_local_only") or "tool_local_only").strip(),
            report_owner=str(item.get("report_owner", "") or "").strip(),
            report_app=str(item.get("report_app", "") or "").strip(),
            verification_mode=str(item.get("verification_mode", "") or "").strip(),
            reconciliation_confidence=str(item.get("reconciliation_confidence", "") or "").strip(),
            reconciliation_matched_fields=str(item.get("reconciliation_matched_fields", "") or "").strip(),
            reconciliation_decision_reason=str(item.get("reconciliation_decision_reason", "") or "").strip(),
            dispatch_outcome=str(item.get("dispatch_outcome", "") or "").strip(),
            execution_outcome=str(item.get("execution_outcome", "") or "").strip(),
            evidence_outcome=str(item.get("evidence_outcome", "") or "").strip(),
            business_outcome=str(item.get("business_outcome", "") or "").strip(),
        )
    return context


def inspect_unfinished_batch_journals() -> tuple[List[dict[str, Any]], List[str]]:
    payloads = list_unfinished_journals()
    lines: List[str] = []
    if not payloads:
        return payloads, lines
    refreshed_payloads: List[dict[str, Any]] = []
    for payload in payloads:
        if bool(payload.get("invalid_journal")):
            refreshed_payloads.append(payload)
            lines.extend(_recoverable_batch_lines(payload))
            continue
        context = _journal_payload_to_context(payload)
        expired_count = _expire_stale_pending_slices_in_context(
            context,
            persist_reason="recovery_pending_expired",
        )
        if expired_count > 0 and context.journal_path:
            payload = load_json_file(context.journal_path) or payload
            payload["_journal_path"] = context.journal_path
            lines.append(
                f"Recovered stale pending slices to EXPIRED for batch_id={context.batch_id} count={expired_count}"
            )
        refreshed_payloads.append(payload)
        lines.append(f"Recovery journal detected for batch_id={str(payload.get('batch_id', '') or '').strip() or 'unknown-batch'}")
        lines.extend(_recoverable_batch_lines(payload))
    return refreshed_payloads, lines


def _report_definition_matches(definition: dict[str, Any], *, report_id_url: str, report_name: str) -> bool:
    if not isinstance(definition, dict):
        return False
    if str(definition.get("report_id_url", "") or "").strip() == str(report_id_url or "").strip():
        return True
    return str(definition.get("report_name", "") or "").strip() == str(report_name or "").strip()


def _find_report_definition(
    context: Optional[RegenContext],
    *,
    report_id_url: str,
    report_name: str,
) -> Optional[dict[str, Any]]:
    if context is None or not isinstance(context.frozen_definition, dict):
        return None
    definitions = context.frozen_definition.get("report_definitions", [])
    if not isinstance(definitions, list):
        return None
    for definition in definitions:
        if _report_definition_matches(definition, report_id_url=report_id_url, report_name=report_name):
            return definition
    return None


def recover_unfinished_batch_journal(
    *,
    client: Optional["SplunkClient"],
    journal_payload: dict[str, Any],
    action: str,
    wait_seconds: int = DEFAULT_RECONCILE_WAIT_SECONDS,
    poll_interval: int = DEFAULT_POSTDISPATCH_POLL_SECONDS,
    prefer_merge_report_verification: bool = False,
    merge_report_log_path: str = "",
    merge_report_settings: Optional[dict[str, Any]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> List[str]:
    action_name = str(action or "").strip().lower()
    if action_name not in {"inspect", "reconcile", "dismiss"}:
        raise ValueError(f"Unsupported recovery action: {action}")
    logs: List[str] = []
    for line in _recoverable_batch_lines(journal_payload):
        _append_log(logs, line, log_callback)
    batch_id = str(journal_payload.get("batch_id", "") or "").strip()
    if bool(journal_payload.get("invalid_journal")):
        if action_name == "inspect":
            _append_log(
                logs,
                "Recovery action selected: inspect/report. Invalid journal left unchanged.",
                log_callback,
            )
            return logs
        if action_name == "dismiss":
            archive_info = archive_batch_artifacts(journal_payload, reason="dismissed_invalid_journal")
            release_overlap_lock(
                str(journal_payload.get("lock_key", "") or "").strip(),
                batch_id,
            )
            _append_log(
                logs,
                (
                    "Recovery action selected: dismiss/archive. Archived invalid journal to "
                    f"{archive_info.get('journal_path', '(unknown)')}."
                ),
                log_callback,
            )
            return logs
        raise RuntimeError("Recovery reconcile is unavailable because the saved journal is invalid or incompatible.")
    if action_name == "inspect":
        _append_log(
            logs,
            "Recovery action selected: inspect/report. Journal state left unchanged.",
            log_callback,
        )
        return logs

    if action_name == "dismiss":
        archive_info = archive_batch_artifacts(journal_payload, reason="dismissed_by_operator")
        release_overlap_lock(
            str(journal_payload.get("lock_key", "") or "").strip(),
            batch_id,
        )
        _append_log(
            logs,
            (
                f"Recovery action selected: dismiss/archive. Archived journal to "
                f"{archive_info.get('journal_path', '(unknown)')}."
            ),
            log_callback,
        )
        return logs

    if client is None:
        raise RuntimeError("Recovery reconcile requires an active Splunk connection.")
    context = _journal_payload_to_context(journal_payload)
    _set_batch_state(context, "RECONCILING", logs=logs, log_callback=log_callback, reason="recovery_reconcile")
    unresolved_before = len(_unresolved_slice_records(context))
    _append_log(
        logs,
        f"Recovery action selected: reconcile/finalize. Unresolved slices before sweep: {unresolved_before}.",
        log_callback,
    )
    reconcile_logs = _reconcile_pending_slices(
        client,
        context,
        wait_seconds=max(1, int(wait_seconds or DEFAULT_RECONCILE_WAIT_SECONDS)),
        poll_interval=max(1, int(poll_interval or DEFAULT_POSTDISPATCH_POLL_SECONDS)),
        prefer_merge_report_verification=prefer_merge_report_verification,
        merge_report_log_path=merge_report_log_path,
        merge_report_settings=merge_report_settings,
        log_callback=log_callback,
    )
    logs.extend(reconcile_logs)
    unresolved_after = _unresolved_slice_records(context)
    final_state = "COMPLETED"
    if unresolved_after:
        final_state = "PENDING_RECONCILE"
    elif any(_normalize_slice_state(item.lifecycle_state) == SLICE_STATE_EXPIRED for item in context.slices):
        final_state = "EXPIRED"
    elif any(str(item.status or "").strip().upper() == "FAILED" for item in context.slices):
        final_state = "FAILED"
    _set_batch_state(context, final_state, logs=logs, log_callback=log_callback, reason="recovery_finalize")
    if final_state in {"COMPLETED", "FAILED", "EXPIRED"}:
        release_overlap_lock(context.lock_key, context.batch_id)
    _append_log(
        logs,
        (
            f"Recovery reconciliation complete for batch_id={context.batch_id}. "
            f"final_state={context.batch_state} unresolved_slices={len(unresolved_after)}"
        ),
        log_callback,
    )
    return logs


def _derive_slice_outcomes(
    *,
    lifecycle_state: str,
    sid: str = "",
    finalized_from_reconciliation: bool = False,
    evidence_confidence: str = "",
) -> tuple[str, str, str, str]:
    state = _normalize_slice_state(lifecycle_state)
    has_sid = bool(str(sid or "").strip())
    confidence = str(evidence_confidence or "").strip().lower()
    if state == SLICE_STATE_QUEUED:
        return ("QUEUED", "UNKNOWN", "NONE", "QUEUED")
    if state == SLICE_STATE_DISPATCHING:
        return ("IN_FLIGHT", "UNKNOWN", "NONE", "RUNNING")
    if state == SLICE_STATE_DISPATCHED:
        return ("SID_CONFIRMED", "RUNNING", "NONE", "RUNNING")
    if state == SLICE_STATE_VERIFYING:
        return ("SID_CONFIRMED", "RUNNING", "PENDING", "VERIFYING")
    if state == SLICE_STATE_TIMEOUT_UNCERTAIN:
        return ("TIMEOUT_UNCERTAIN", "UNKNOWN", "NONE", "PENDING_RECONCILE")
    if state == SLICE_STATE_PENDING_RECONCILE:
        dispatch_outcome = "SID_CONFIRMED" if has_sid else "TIMEOUT_UNCERTAIN"
        execution_outcome = "LIKELY_EXECUTED" if has_sid else "UNKNOWN"
        evidence_outcome = "AMBIGUOUS" if confidence in {"weak", "conflict"} else "PENDING"
        return (dispatch_outcome, execution_outcome, evidence_outcome, "PENDING_RECONCILE")
    if state == SLICE_STATE_SUCCESS:
        evidence_outcome = "RECONCILED" if finalized_from_reconciliation else "VERIFIED"
        return ("SID_CONFIRMED" if has_sid else "TIMEOUT_UNCERTAIN", "SUCCEEDED", evidence_outcome, "SUCCESS")
    if state == SLICE_STATE_FAILED_DISPATCH:
        return ("FAILED", "UNKNOWN", "NONE", "FAILED")
    if state == SLICE_STATE_FAILED_VERIFICATION:
        evidence_outcome = "NEGATIVE" if has_sid else "NONE"
        return ("SID_CONFIRMED" if has_sid else "FAILED", "FAILED", evidence_outcome, "FAILED")
    if state == SLICE_STATE_EXPIRED:
        dispatch_outcome = "SID_CONFIRMED" if has_sid else "TIMEOUT_UNCERTAIN"
        execution_outcome = "UNKNOWN" if not has_sid else "LIKELY_EXECUTED"
        return (dispatch_outcome, execution_outcome, "EXPIRED", "EXPIRED")
    return ("UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN")


def _set_batch_state(
    context: Optional[RegenContext],
    state: str,
    *,
    reason: str = "",
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    if context is None:
        return
    context.batch_state = str(state or "").strip().upper() or "UNKNOWN"
    if logs is not None:
        _append_log(
            logs,
            f"[Debug] BATCH_STATE batch_id={context.batch_id} state={context.batch_state} reason={reason or '-'}",
            log_callback,
        )
    _persist_batch_journal(context, reason=reason or context.batch_state.lower())


def _ensure_report_definition_frozen(
    context: Optional[RegenContext],
    *,
    report_id_url: str,
    report_name: str,
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
    default_app: str,
    default_owner: str,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
) -> List[dict[str, Any]]:
    if context is None:
        return []
    existing = _find_report_definition(
        context,
        report_id_url=report_id_url,
        report_name=report_name,
    )
    if isinstance(existing, dict):
        slices = existing.get("slices", [])
        if isinstance(slices, list) and slices:
            return [dict(item) for item in slices if isinstance(item, dict)]

    verification_mode = _verification_mode_label(
        prefer_merge_report_verification=prefer_merge_report_verification,
        merge_report_log_path=merge_report_log_path,
    )
    if not isinstance(context.frozen_definition, dict) or not context.frozen_definition:
        context.frozen_definition = {
            "batch_id": context.batch_id,
            "correlation_mode": context.correlation_mode,
            "correlation_scope": _correlation_scope_for_mode(context.correlation_mode),
            "report_definitions": [],
            "verification_mode": verification_mode,
            "savedsearch_recipients": [],
            "reconciliation_correlation_fields": [
                "correlation_tag",
                "saved_search_name",
                "execution_owner",
                "app_namespace",
                "slice_window",
                "merge_report_sid",
            ],
            "reconciliation_confidence_rules": {
                "strong": "saved_search_name + execution_owner + app_namespace + exact slice_window",
                "weak": "saved_search_name + execution_owner + app_namespace without exact slice_window",
                "conflict": "partial name/window match without a safe exact identity match",
            },
        }
    definitions = context.frozen_definition.setdefault("report_definitions", [])
    if not isinstance(definitions, list):
        definitions = []
        context.frozen_definition["report_definitions"] = definitions
    identity = _parse_saved_search_identity(
        report_id_url,
        report_name,
        default_app=default_app,
        default_owner=default_owner,
    )
    blueprints = _build_batch_slice_blueprints(
        batch_id=context.batch_id,
        report_id_url=report_id_url,
        report_name=report_name,
        frequency=frequency,
        start=start,
        end=end,
        no_change=no_change,
        app=identity.app,
        owner=identity.owner,
        verification_mode=verification_mode,
        correlation_mode=context.correlation_mode,
    )
    definition = {
        "report_id_url": report_id_url,
        "report_name": report_name,
        "owner": identity.owner,
        "app": identity.app,
        "verification_mode": verification_mode,
        "slices": [dict(item) for item in blueprints],
    }
    definitions.append(definition)
    for blueprint in blueprints:
        if _find_slice_record(context, slice_id=blueprint["slice_id"]) is not None:
            continue
        context.add_slice(
            batch_id=context.batch_id,
            slice_id=blueprint["slice_id"],
            attempt_id=0,
            report_name=report_name,
            slice_label=blueprint["slice_label"],
            slice_index=blueprint["slice_index"],
            slice_total=blueprint["slice_total"],
            earliest=blueprint["earliest"],
            latest=blueprint["latest"],
            status="QUEUED",
            outcome_code="QUEUED",
            dispatch_report_id_url=report_id_url,
            dispatch_earliest=blueprint["dispatch_earliest"],
            dispatch_latest=blueprint["dispatch_latest"],
            lifecycle_state=SLICE_STATE_QUEUED,
            state_reason="Queued at batch start.",
            execution_context_id="",
            correlation_tag=blueprint["correlation_tag"],
            correlation_mode=blueprint["correlation_mode"],
            report_owner=blueprint["report_owner"],
            report_app=blueprint["report_app"],
            verification_mode=blueprint["verification_mode"],
            reconciliation_confidence="",
            dispatch_outcome="QUEUED",
            execution_outcome="UNKNOWN",
            evidence_outcome="NONE",
            business_outcome="QUEUED",
        )
    return [dict(item) for item in blueprints]


def _parse_saved_search_identity(
    report_id_url: str,
    report_name: str,
    *,
    default_app: str = "",
    default_owner: str = "",
) -> SavedSearchIdentity:
    parsed = urlparse(str(report_id_url or ""))
    raw_path = parsed.path
    owner = str(default_owner or "").strip()
    app = str(default_app or "").strip()
    name = str(report_name or "").strip()
    parts = raw_path.strip("/").split("/") if raw_path else []
    if len(parts) >= 6 and parts[0] == "servicesNS" and parts[3] == "saved" and parts[4] == "searches":
        owner = owner or str(parts[1] or "").strip()
        app = app or str(parts[2] or "").strip()
        if not name:
            name = unquote(parts[5])
    return SavedSearchIdentity(owner=owner, app=app, name=name)


def _extract_candidate_window(candidate: dict[str, Any]) -> tuple[str, str]:
    content = candidate.get("content", {})
    if not isinstance(content, dict):
        content = {}
    request = content.get("request", {})
    if not isinstance(request, dict):
        request = {}
    earliest = str(request.get("earliest_time", "") or "").strip()
    latest = str(request.get("latest_time", "") or "").strip()
    return earliest, latest


def _rank_job_candidate(
    candidate: dict[str, Any],
    *,
    identity: SavedSearchIdentity,
    dispatch_earliest: Optional[str],
    dispatch_latest: Optional[str],
    correlation_tag: str = "",
) -> SliceReconcileEvidence:
    sid = str(candidate.get("sid", "") or "").strip()
    if not sid:
        return SliceReconcileEvidence()
    label = str(candidate.get("label", "") or "").strip()
    acl = candidate.get("acl", {})
    if not isinstance(acl, dict):
        acl = {}
    owner = str(acl.get("owner", "") or "").strip()
    app = str(acl.get("app", "") or "").strip()
    candidate_earliest, candidate_latest = _extract_candidate_window(candidate)
    content = candidate.get("content", {})
    if not isinstance(content, dict):
        content = {}
    qualified_search = str(content.get("qualifiedSearch", "") or "").strip()
    request = content.get("request", {})
    if not isinstance(request, dict):
        request = {}
    request_search = str(request.get("search", "") or "").strip()
    request_dispatch_view = str(
        request.get("ui_dispatch_view", "")
        or content.get("request.ui_dispatch_view", "")
        or ""
    ).strip()
    dispatch_correlation_value = _build_correlation_dispatch_value(correlation_tag)
    reasons: List[str] = []
    score = 0
    exact_dispatch_view = bool(dispatch_correlation_value) and request_dispatch_view == dispatch_correlation_value
    exact_correlation_tag = bool(correlation_tag) and (
        str(correlation_tag or "").strip() in qualified_search
        or str(correlation_tag or "").strip() in request_search
    )
    exact_correlation = exact_dispatch_view or exact_correlation_tag
    exact_name = bool(identity.name) and label == identity.name
    exact_owner = bool(identity.owner) and owner == identity.owner
    exact_app = bool(identity.app) and app == identity.app
    exact_window, buffered_window = _window_match_with_buffer(
        dispatch_earliest,
        dispatch_latest,
        candidate_earliest,
        candidate_latest,
    )
    partial_window = (
        (dispatch_earliest and candidate_earliest == str(dispatch_earliest or "").strip())
        or (dispatch_latest and candidate_latest == str(dispatch_latest or "").strip())
    )
    if exact_dispatch_view:
        score += 100
        reasons.append("dispatch_view")
    elif exact_correlation_tag:
        score += 80
        reasons.append("correlation_tag")
    if exact_name:
        score += 40
        reasons.append("name")
    if exact_owner:
        score += 20
        reasons.append("owner")
    if exact_app:
        score += 20
        reasons.append("app")
    if exact_window:
        score += 40
        reasons.append("window_exact")
    elif buffered_window:
        score += 35
        reasons.append("window_buffered")
    elif partial_window:
        score += 15
        reasons.append("window_partial")

    matched_fields = list(reasons)
    strong_window_match = exact_window or buffered_window
    if exact_dispatch_view and exact_owner and exact_app and strong_window_match:
        return SliceReconcileEvidence(
            confidence="strong",
            sid=sid,
            source="search_jobs",
            detail=f"strong_match:{','.join(reasons)}",
            candidate=candidate,
            matched_fields=matched_fields,
            decision_reason=(
                "Dispatch correlation token, owner, app, and exact slice window matched."
                if exact_window
                else "Dispatch correlation token, owner, app, and a buffered slice window matched."
            ),
        )
    if exact_correlation and exact_owner and exact_app and strong_window_match:
        return SliceReconcileEvidence(
            confidence="strong",
            sid=sid,
            source="search_jobs",
            detail=f"strong_match:{','.join(reasons)}",
            candidate=candidate,
            matched_fields=matched_fields,
            decision_reason=(
                "Correlation evidence, owner, app, and exact slice window matched."
                if exact_window
                else "Correlation evidence, owner, app, and a buffered slice window matched."
            ),
        )
    if exact_name and exact_owner and exact_app and strong_window_match:
        return SliceReconcileEvidence(
            confidence="strong",
            sid=sid,
            source="search_jobs",
            detail=f"strong_match:{','.join(reasons)}",
            candidate=candidate,
            matched_fields=matched_fields,
            decision_reason=(
                "Saved search identity and exact slice window matched."
                if exact_window
                else "Saved search identity and a buffered slice window matched."
            ),
        )
    if exact_name and exact_owner and exact_app:
        return SliceReconcileEvidence(
            confidence="weak",
            sid=sid,
            source="search_jobs",
            detail=f"weak_match:{','.join(reasons)}",
            candidate=candidate,
            matched_fields=matched_fields,
            decision_reason="Saved search identity matched, but the exact slice window was not confirmed.",
        )
    if exact_name and score >= 40:
        return SliceReconcileEvidence(
            confidence="conflict",
            sid=sid,
            source="search_jobs",
            detail=f"conflicting_match:{','.join(reasons) or 'name_only'}",
            candidate=candidate,
            matched_fields=matched_fields or ["name"],
            decision_reason="A partial name match was found without enough identity or slice-window evidence to finalize safely.",
        )
    return SliceReconcileEvidence()


@dataclass
class PendingDispatchAttempt:
    correlation_id: str
    result_queue: "queue.Queue[tuple[str, bool, str, str]]"
    worker_thread_name: str = ""
    worker_thread_ident: Optional[int] = None
    report_name: str = ""
    slice_label: str = ""
    slice_index: int = 0
    slice_total: int = 0
    earliest: str = ""
    latest: str = ""
    report_id_url: str = ""
    started_monotonic: float = 0.0
    started_utc: str = ""
    timeout_seconds: int = 0
    run_id: str = ""
    completed: bool = False
    harvested: bool = False
    dispatch_state: str = ""
    ok: bool = False
    sid: str = ""
    error: str = ""


@dataclass
class PendingDispatchHarvestResult:
    state: str
    ok: bool = False
    sid: str = ""
    error: str = ""
    entry: Optional[PendingDispatchAttempt] = None


_PENDING_DISPATCH_REGISTRY_LOCK = threading.Lock()
_PENDING_DISPATCH_REGISTRY: dict[str, PendingDispatchAttempt] = {}


def _register_pending_dispatch_attempt(
    correlation_id: str,
    *,
    result_queue: "queue.Queue[tuple[str, bool, str, str]]",
    worker_thread_name: str,
    worker_thread_ident: Optional[int],
    report_name: str,
    slice_label: str,
    slice_index: int,
    slice_total: int,
    earliest: str,
    latest: str,
    report_id_url: str,
    started_monotonic: float,
    started_utc: str,
    timeout_seconds: int,
    run_id: str,
) -> None:
    correlation_id = str(correlation_id or "").strip()
    if not correlation_id:
        return
    entry = PendingDispatchAttempt(
        correlation_id=correlation_id,
        result_queue=result_queue,
        worker_thread_name=str(worker_thread_name or ""),
        worker_thread_ident=worker_thread_ident,
        report_name=str(report_name or ""),
        slice_label=str(slice_label or ""),
        slice_index=max(0, int(slice_index or 0)),
        slice_total=max(0, int(slice_total or 0)),
        earliest=str(earliest or ""),
        latest=str(latest or ""),
        report_id_url=str(report_id_url or ""),
        started_monotonic=float(started_monotonic or 0.0),
        started_utc=str(started_utc or ""),
        timeout_seconds=max(0, int(timeout_seconds or 0)),
        run_id=str(run_id or ""),
    )
    with _PENDING_DISPATCH_REGISTRY_LOCK:
        _PENDING_DISPATCH_REGISTRY[correlation_id] = entry


def _clear_pending_dispatch_attempt(correlation_id: str) -> None:
    correlation_id = str(correlation_id or "").strip()
    if not correlation_id:
        return
    with _PENDING_DISPATCH_REGISTRY_LOCK:
        _PENDING_DISPATCH_REGISTRY.pop(correlation_id, None)


def _clear_pending_dispatch_attempts_for_run(
    run_id: str = "",
    *,
    clear_all: bool = False,
) -> int:
    target_run_id = str(run_id or "").strip()
    cleared = 0
    with _PENDING_DISPATCH_REGISTRY_LOCK:
        keys_to_remove = [
            correlation_id
            for correlation_id, entry in _PENDING_DISPATCH_REGISTRY.items()
            if clear_all or (target_run_id and str(entry.run_id or "").strip() == target_run_id)
        ]
        for correlation_id in keys_to_remove:
            _PENDING_DISPATCH_REGISTRY.pop(correlation_id, None)
            cleared += 1
    return cleared


def _harvest_pending_dispatch_result(
    correlation_id: str,
    *,
    wait_seconds: float = 0.0,
) -> PendingDispatchHarvestResult:
    correlation_id = str(correlation_id or "").strip()
    if not correlation_id:
        return PendingDispatchHarvestResult(state="MISSING")

    with _PENDING_DISPATCH_REGISTRY_LOCK:
        entry = _PENDING_DISPATCH_REGISTRY.get(correlation_id)
    if entry is None:
        return PendingDispatchHarvestResult(state="MISSING")
    if entry.completed:
        entry.harvested = True
        return PendingDispatchHarvestResult(
            state=str(entry.dispatch_state or "RETURNED"),
            ok=bool(entry.ok),
            sid=str(entry.sid or ""),
            error=str(entry.error or ""),
            entry=entry,
        )

    try:
        if float(wait_seconds or 0.0) > 0.0:
            dispatch_state, ok, sid, err = entry.result_queue.get(timeout=max(0.01, float(wait_seconds)))
        else:
            dispatch_state, ok, sid, err = entry.result_queue.get_nowait()
    except queue.Empty:
        return PendingDispatchHarvestResult(state="PENDING", entry=entry)

    entry.completed = True
    entry.harvested = True
    entry.dispatch_state = str(dispatch_state or "")
    entry.ok = bool(ok)
    entry.sid = str(sid or "")
    entry.error = str(err or "")
    return PendingDispatchHarvestResult(
        state=entry.dispatch_state or "RETURNED",
        ok=entry.ok,
        sid=entry.sid,
        error=entry.error,
        entry=entry,
    )


def _slice_has_pending_dispatch(item: RegenSliceRecord) -> bool:
    return bool(str(getattr(item, "dispatch_correlation_id", "") or "").strip())


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
    config_root = getattr(active_policy, "exe_dir", "") or os.path.dirname(str(active_policy.config_path))
    loaded = load_and_validate_config(exe_dir=config_root)
    for change in loaded.changes:
        logging.getLogger(__name__).info(change)
    cfg = loaded.parser

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
    logging_section = None
    file_logging_config = {}
    if "Logging" in cfg or "logging" in cfg:
        logging_section = cfg["Logging"] if "Logging" in cfg else cfg["logging"]
        logging_level = (logging_section.get("level", logging_level) or logging_level).strip().upper()
        if logging_level not in ("DEBUG", "INFO", "WARN", "ERROR"):
            logging_level = "INFO"
        logging_verbose = _parse_bool(logging_section.get("verbose", str(int(logging_verbose))), logging_verbose)
        logging_max_bytes = _parse_int(logging_section.get("max_bytes", str(logging_max_bytes)), logging_max_bytes)
        logging_backup_count = _parse_int(logging_section.get("backup_count", str(logging_backup_count)), logging_backup_count)
        if "runtime_log_enabled" in logging_section:
            file_logging_config["runtime_log_enabled"] = _parse_bool(
                logging_section.get("runtime_log_enabled", "1"),
                True,
            )
        if "runtime_log_level" in logging_section:
            file_logging_config["runtime_log_level"] = (
                logging_section.get("runtime_log_level", "INFO") or "INFO"
            ).strip().upper()
        if "runtime_log_path" in logging_section:
            file_logging_config["runtime_log_path"] = logging_section.get("runtime_log_path", "").strip()
        if "debug_log_enabled" in logging_section:
            file_logging_config["debug_log_enabled"] = _parse_bool(
                logging_section.get("debug_log_enabled", "0"),
                False,
            )
        if "debug_log_level" in logging_section:
            file_logging_config["debug_log_level"] = (
                logging_section.get("debug_log_level", "DEBUG") or "DEBUG"
            ).strip().upper()
        if "debug_log_path" in logging_section:
            file_logging_config["debug_log_path"] = logging_section.get("debug_log_path", "").strip()
        if "debug_broker_enabled" in logging_section:
            file_logging_config["debug_broker_enabled"] = _parse_bool(
                logging_section.get("debug_broker_enabled", "0"),
                False,
            )
        if "debug_rest_enabled" in logging_section:
            file_logging_config["debug_rest_enabled"] = _parse_bool(
                logging_section.get("debug_rest_enabled", "0"),
                False,
            )
        if "debug_dispatch_enabled" in logging_section:
            file_logging_config["debug_dispatch_enabled"] = _parse_bool(
                logging_section.get("debug_dispatch_enabled", "0"),
                False,
            )
        if "debug_tracebacks_enabled" in logging_section:
            file_logging_config["debug_tracebacks_enabled"] = _parse_bool(
                logging_section.get("debug_tracebacks_enabled", "0"),
                False,
            )
    logging_level, logging_max_bytes, logging_backup_count = active_policy.enforce_audit_settings(
        logging_level,
        logging_max_bytes,
        logging_backup_count,
    )
    if not file_logging_config:
        file_logging_config = None

    runtime_config = {}
    if "runtime" in cfg or "Runtime" in cfg:
        runtime_section = cfg["runtime"] if "runtime" in cfg else cfg["Runtime"]
        if "test_mode" in runtime_section:
            runtime_config["test_mode"] = _parse_bool(
                runtime_section.get("test_mode", "0"),
                False,
            )
    if not runtime_config:
        runtime_config = None

    # MergeReport config (canonical: [postdispatch], legacy: [mergereport])
    merge_report_enabled = False
    merge_report_log_path = ""
    merge_report_timeout_seconds = DEFAULT_MERGEREPORT_TIMEOUT_SECONDS

    postdispatch_section = cfg["postdispatch"] if "postdispatch" in cfg else None
    legacy_mergereport_section = cfg["mergereport"] if "mergereport" in cfg else None
    postdispatch_has_merge_report = False
    if postdispatch_section:
        postdispatch_has_merge_report = any(
            cfg.has_option("postdispatch", key)
            for key in ("merge_report_enabled", "merge_report_log_path", "merge_report_timeout_seconds")
        )

    if postdispatch_section and postdispatch_has_merge_report:
        merge_report_enabled = _parse_bool(
            postdispatch_section.get("merge_report_enabled", "true"),
            True,
        )
        merge_report_log_path = postdispatch_section.get("merge_report_log_path", "").strip()
        merge_report_timeout_seconds = _parse_min_int(
            postdispatch_section.get(
                "merge_report_timeout_seconds",
                str(DEFAULT_MERGEREPORT_TIMEOUT_SECONDS),
            ),
            DEFAULT_MERGEREPORT_TIMEOUT_SECONDS,
            1,
        )
        if legacy_mergereport_section is not None:
            logging.getLogger(__name__).warning(
                "Config section [mergereport] is legacy and ignored when canonical [postdispatch] "
                "merge_report_* keys are present. Blank [postdispatch].merge_report_log_path now means "
                "local file verification is disabled, not legacy fallback."
            )
    elif legacy_mergereport_section is not None:
        enabled_str = legacy_mergereport_section.get("enabled", "false").lower()
        merge_report_enabled = enabled_str in ("true", "1", "yes")
        merge_report_log_path = legacy_mergereport_section.get("log_path", "").strip()
        merge_report_timeout_seconds = _parse_min_int(
            legacy_mergereport_section.get(
                "timeout_seconds",
                str(DEFAULT_MERGEREPORT_TIMEOUT_SECONDS),
            ),
            DEFAULT_MERGEREPORT_TIMEOUT_SECONDS,
            1,
        )
        logging.getLogger(__name__).warning(
            "Config section [mergereport] is legacy; mapping to [postdispatch] merge_report_* settings."
        )

    # Validate MergeReport config if enabled
    merge_report_log_path_validated = ""
    if merge_report_enabled:
        if not merge_report_log_path:
            logging.getLogger(__name__).info(
                "MERGEREPORT_CONFIG_NORMALIZED enabled=true local_file_path=(blank) "
                "local_file_mode=disabled_nonfatal verification_mode=rest_preferred"
            )
        elif not os.path.isabs(merge_report_log_path):
            logging.getLogger(__name__).warning(
                "MERGEREPORT_CONFIG_NORMALIZED enabled=true local_file_path=%s "
                "local_file_mode=disabled_nonfatal reason=non_absolute_path verification_mode=rest_preferred",
                merge_report_log_path,
            )
        else:
            merge_report_log_path_validated = merge_report_log_path
            logging.getLogger(__name__).info(
                "MERGEREPORT_CONFIG_NORMALIZED enabled=true local_file_path=%s "
                "local_file_mode=optional verification_mode=rest_preferred",
                merge_report_log_path_validated,
            )

    dispatch_config = {}
    if "dispatch" in cfg:
        section = cfg["dispatch"]
        dispatch_config = {
            "per_slice_wait_seconds": _parse_min_int(
                section.get(
                    "per_slice_wait_seconds",
                    str(DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS),
                ),
                DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS,
                1,
            ),
            "continue_on_timeout": _parse_bool(
                section.get(
                    "continue_on_timeout",
                    str(int(DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT)),
                ),
                DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT,
            ),
            "timeout_result": _normalize_timeout_result(
                section.get("timeout_result", DEFAULT_DISPATCH_TIMEOUT_RESULT)
            ).lower(),
            "dispatch_call_timeout_seconds": _parse_min_int(
                section.get(
                    "dispatch_call_timeout_seconds",
                    str(DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS),
                ),
                DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS,
                1,
            ),
        }

    # Manual ACK + SMTP defaults
    ack_enabled = True
    ack_on_pending = False
    ack_on_unknown = False
    ack_recipients: List[str] = []
    ack_use_savedsearch_recipients = False
    ack_attach_manifest = False
    smtp_host = "127.0.0.1"
    smtp_port = 25
    smtp_user = ""
    smtp_pass = ""
    smtp_use_tls = False
    smtp_from = "Splunk Notification <noreply@example.com>"

    # Legacy [smtp] section compatibility
    if "smtp" in cfg:
        section = cfg["smtp"]
        ack_enabled = _parse_bool(
            section.get("enabled", str(int(ack_enabled))),
            ack_enabled,
        )
        smtp_host = section.get("host", "127.0.0.1").strip() or smtp_host
        smtp_port = _parse_int(section.get("port", "25"), 25)
        smtp_user = section.get("username", "").strip()
        smtp_pass = section.get("password", "").strip()
        smtp_use_tls = _parse_bool(section.get("use_tls", "false"), False)
        smtp_from = (
            section.get("from_address", "Splunk Notification <noreply@example.com>").strip()
            or smtp_from
        )

    # Preferred [email] section
    if "email" in cfg:
        section = cfg["email"]
        ack_enabled = _parse_bool(section.get("ack_enabled", str(int(ack_enabled))), ack_enabled)
        ack_on_pending = _parse_bool(
            section.get("ack_on_pending", section.get("ack_on_unknown", "0")),
            False,
        )
        ack_on_unknown = ack_on_pending
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
            "enabled": _parse_bool(
                section.get("enabled", str(int(DEFAULT_POSTDISPATCH_ENABLED))),
                DEFAULT_POSTDISPATCH_ENABLED,
            ),
            "merge_report_enabled": section.get("merge_report_enabled", "true").lower() in ("true", "1", "yes"),
            "merge_report_log_path": section.get("merge_report_log_path", "").strip(),
            "merge_report_index": section.get("merge_report_index", "_internal"),
            "merge_report_source_contains": section.get("merge_report_source_contains", "mergeReport_alert.log"),
            "merge_report_sourcetype": section.get("merge_report_sourcetype", "").strip(),
            "merge_report_timeout_seconds": _parse_min_int(
                section.get(
                    "merge_report_timeout_seconds",
                    str(DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS),
                ),
                DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS,
                1,
            ),
            "native_email_enabled": section.get("native_email_enabled", "true").lower() in ("true", "1", "yes"),
            "native_email_index": section.get("native_email_index", "_internal"),
            "native_email_source_contains": section.get("native_email_source_contains", "python.log"),
            "native_email_sourcetype": section.get("native_email_sourcetype", "").strip(),
            "native_email_timeout_seconds": _parse_min_int(
                section.get(
                    "native_email_timeout_seconds",
                    str(DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS),
                ),
                DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS,
                1,
            ),
            "native_email_strict_success": section.get("native_email_strict_success", "false").lower() in ("true", "1", "yes"),
            "poll_seconds": _parse_min_int(
                section.get("poll_seconds", str(DEFAULT_POSTDISPATCH_POLL_SECONDS)),
                DEFAULT_POSTDISPATCH_POLL_SECONDS,
                1,
            ),
            "reconcile_pending": _parse_bool(
                section.get(
                    "reconcile_pending",
                    str(int(DEFAULT_RECONCILE_PENDING_ENABLED)),
                ),
                DEFAULT_RECONCILE_PENDING_ENABLED,
            ),
            "reconcile_wait_seconds": _parse_min_int(
                section.get(
                    "reconcile_wait_seconds",
                    str(DEFAULT_RECONCILE_WAIT_SECONDS),
                ),
                DEFAULT_RECONCILE_WAIT_SECONDS,
                1,
            ),
            "lookback_seconds": _parse_min_int(
                section.get("lookback_seconds", str(DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS)),
                DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS,
                1,
            ),
            "broker_request_timeout_seconds": _parse_min_int(
                section.get(
                    "broker_request_timeout_seconds",
                    str(DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS),
                ),
                DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS,
                1,
            ),
            "status_check_timeout_seconds": _parse_min_int(
                section.get(
                    "status_check_timeout_seconds",
                    str(DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS),
                ),
                DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS,
                1,
            ),
        }
        postdispatch_config["merge_report_log_path"] = merge_report_log_path_validated
    elif legacy_mergereport_section is not None:
        postdispatch_config = {
            "enabled": DEFAULT_POSTDISPATCH_ENABLED,
            "merge_report_enabled": bool(merge_report_enabled),
            "merge_report_log_path": merge_report_log_path_validated,
            "merge_report_index": "_internal",
            "merge_report_source_contains": "mergeReport_alert.log",
            "merge_report_sourcetype": "",
            "merge_report_timeout_seconds": merge_report_timeout_seconds,
            "native_email_enabled": True,
            "native_email_index": "_internal",
            "native_email_source_contains": "python.log",
            "native_email_sourcetype": "",
            "native_email_timeout_seconds": DEFAULT_POSTDISPATCH_TIMEOUT_SECONDS,
            "native_email_strict_success": False,
            "poll_seconds": DEFAULT_POSTDISPATCH_POLL_SECONDS,
            "reconcile_pending": DEFAULT_RECONCILE_PENDING_ENABLED,
            "reconcile_wait_seconds": DEFAULT_RECONCILE_WAIT_SECONDS,
            "lookback_seconds": DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS,
            "broker_request_timeout_seconds": DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS,
            "status_check_timeout_seconds": DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS,
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
        dispatch_config=dispatch_config if dispatch_config else None,
        ack_enabled=ack_enabled,
        ack_on_pending=ack_on_pending,
        ack_on_unknown=ack_on_unknown,
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
        file_logging_config=file_logging_config,
        runtime_config=runtime_config,
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
        self._password = str(password or "")
        self.auth_mode = "password"
        self.verify_ssl = bool(verify_ssl)
        self.session = self._new_session()
        self._auth_header = f"Splunk {self._login_with_password(self.username, password)}"
        self._last_snapshot_meta: dict[str, Any] = {}
        self._last_dispatch_meta: dict[str, Any] = {}
        self._active_transport_lock = threading.Lock()
        self._active_transports: dict[str, dict[str, Any]] = {}

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        session.trust_env = False
        session.verify = self.verify_ssl
        session.headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded",
            }
        )
        return session

    def _ensure_transport_runtime_initialized(self) -> None:
        if not hasattr(self, "_active_transport_lock") or self._active_transport_lock is None:
            self._active_transport_lock = threading.Lock()
        if not hasattr(self, "_active_transports") or not isinstance(self._active_transports, dict):
            self._active_transports = {}
        if not hasattr(self, "_last_dispatch_meta") or not isinstance(self._last_dispatch_meta, dict):
            self._last_dispatch_meta = {}
        if not hasattr(self, "_last_snapshot_meta") or not isinstance(self._last_snapshot_meta, dict):
            self._last_snapshot_meta = {}

    def _timeout_pair(
        self,
        read_timeout_seconds: float,
        *,
        connect_timeout_seconds: Optional[float] = None,
    ) -> tuple[float, float]:
        connect_timeout = max(
            1.0,
            float(
                connect_timeout_seconds
                if connect_timeout_seconds is not None
                else DEFAULT_HTTP_CONNECT_TIMEOUT_SECONDS
            ),
        )
        read_timeout = max(1.0, float(read_timeout_seconds or DEFAULT_HTTP_READ_TIMEOUT_SECONDS))
        return (connect_timeout, read_timeout)

    def _refresh_auth_header(self) -> bool:
        if self.auth_mode != "password" or not self.username or not self._password:
            return False
        try:
            self._auth_header = f"Splunk {self._login_with_password(self.username, self._password)}"
            return True
        except Exception:
            return False

    def _clone_isolated_client(self) -> "SplunkClient":
        clone = SplunkClient.__new__(SplunkClient)
        QObject.__init__(clone)
        clone.base_url = self.base_url
        clone.username = self.username
        clone._password = self._password
        clone.auth_mode = self.auth_mode
        clone.verify_ssl = self.verify_ssl
        clone.session = clone._new_session()
        clone._auth_header = self._auth_header
        clone._last_snapshot_meta = {}
        clone._last_dispatch_meta = {}
        clone._active_transport_lock = threading.Lock()
        clone._active_transports = {}
        clone._recent_metadata_activity = dict(getattr(self, "_recent_metadata_activity", {}) or {})
        clone._recent_transport_cleanup = dict(getattr(self, "_recent_transport_cleanup", {}) or {})
        return clone

    def create_isolated_dispatch_client(self) -> "SplunkClient":
        return self._clone_isolated_client()

    def create_isolated_rest_client(self) -> "SplunkClient":
        return self._clone_isolated_client()

    def close_transport(self) -> None:
        self._ensure_transport_runtime_initialized()
        self._close_active_transports()
        try:
            self.session.close()
        except Exception:
            pass

    def reset_transport(self) -> None:
        self.close_transport()
        self.session = self._new_session()

    def _close_response_transport(self, resp: Any) -> None:
        self._ensure_transport_runtime_initialized()
        token = str(getattr(resp, "_splunk_tool_transport_token", "") or "").strip()
        transport_meta = self._release_active_transport(token) if token else {}
        close_response = getattr(resp, "close", None)
        if callable(close_response):
            try:
                close_response()
            except Exception:
                pass
        transport_session = transport_meta.get("session") or getattr(resp, "_splunk_tool_session", None)
        close_session = getattr(transport_session, "close", None)
        if callable(close_session):
            try:
                close_session()
            except Exception:
                pass

    def _register_active_transport(self, session: requests.Session) -> str:
        self._ensure_transport_runtime_initialized()
        token = uuid.uuid4().hex
        with self._active_transport_lock:
            self._active_transports[token] = {"session": session}
        return token

    def _release_active_transport(self, token: str) -> dict[str, Any]:
        self._ensure_transport_runtime_initialized()
        safe_token = str(token or "").strip()
        if not safe_token:
            return {}
        with self._active_transport_lock:
            payload = self._active_transports.pop(safe_token, {})
        return payload if isinstance(payload, dict) else {}

    def _bind_response_transport(self, resp: Any, *, session: requests.Session, token: str) -> None:
        self._ensure_transport_runtime_initialized()
        with self._active_transport_lock:
            current = self._active_transports.get(token)
            if isinstance(current, dict):
                current["response"] = resp
        try:
            setattr(resp, "_splunk_tool_transport_token", token)
        except Exception:
            pass
        try:
            setattr(resp, "_splunk_tool_session", session)
        except Exception:
            pass

    def _close_active_transports(self) -> int:
        self._ensure_transport_runtime_initialized()
        with self._active_transport_lock:
            active = list(self._active_transports.values())
            self._active_transports.clear()
        closed = 0
        for payload in active:
            if not isinstance(payload, dict):
                continue
            closed += 1
            response = payload.get("response")
            if response is not None:
                close_response = getattr(response, "close", None)
                if callable(close_response):
                    try:
                        close_response()
                    except Exception:
                        pass
            session = payload.get("session")
            close_session = getattr(session, "close", None)
            if callable(close_session):
                try:
                    close_session()
                except Exception:
                    pass
        return closed

    def _login_with_password(self, username: str, password: str) -> str:
        if not username or not password:
            raise ValueError("username/password are required for auth_mode=password")

        resp = None
        try:
            resp = self.session.post(
                self.base_url + "/services/auth/login",
                data={
                    "output_mode": "json",
                    "username": username,
                    "password": password,
                },
                timeout=self._timeout_pair(DEFAULT_HTTP_READ_TIMEOUT_SECONDS),
            )
        except requests.exceptions.SSLError as exc:
            raise RuntimeError(
                "TLS error while connecting to Splunk management port. "
                "Certificate verification settings are unchanged from current behavior."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Network error while logging in to Splunk: {redact_text(str(exc))}") from exc

        try:
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
        finally:
            close_response = getattr(resp, "close", None)
            if callable(close_response):
                close_response()

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        timeout: int = 60,
        allow_reauth: bool = True,
        connect_timeout_seconds: Optional[float] = None,
    ):
        url = path if path.startswith("http://") or path.startswith("https://") else self.base_url + path
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme.lower() != "https":
            raise PolicyViolation(
                "ENDPOINT_HTTPS_REQUIRED",
                f"Only https:// endpoints are allowed: {url!r}",
            )
        headers = {
            "Authorization": self._auth_header,
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "close",
        }
        oneshot_session = requests.Session()
        oneshot_session.trust_env = False
        oneshot_session.verify = self.verify_ssl
        transport_token = self._register_active_transport(oneshot_session)
        resp = None
        try:
            resp = oneshot_session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self._timeout_pair(timeout, connect_timeout_seconds=connect_timeout_seconds),
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            self._release_active_transport(transport_token)
            close_session = getattr(oneshot_session, "close", None)
            if callable(close_session):
                close_session()
            raise RuntimeError(
                "TLS error while connecting to Splunk management port. "
                "Certificate verification settings are unchanged from current behavior."
            ) from exc
        except requests.exceptions.RequestException as exc:
            self._release_active_transport(transport_token)
            close_session = getattr(oneshot_session, "close", None)
            if callable(close_session):
                close_session()
            safe_error = redact_text(str(exc))
            if _error_looks_like_interruption(safe_error):
                raise RuntimeError(f"Network interruption while calling Splunk REST API: {safe_error}") from exc
            raise RuntimeError(f"Network error while calling Splunk REST API: {safe_error}") from exc
        try:
            if resp.status_code in (401, 403):
                self._close_response_transport(resp)
                if allow_reauth and self._refresh_auth_header():
                    return self._request(
                        method,
                        path,
                        params=params,
                        data=data,
                        timeout=timeout,
                        allow_reauth=False,
                        connect_timeout_seconds=connect_timeout_seconds,
                    )
                raise RuntimeError(
                    "Authentication failed (401/403). Session refresh was unsuccessful or this account lacks required permissions."
                )

            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code} returned by Splunk REST API.")
            self._bind_response_transport(resp, session=oneshot_session, token=transport_token)
            return resp
        except Exception:
            self._close_response_transport(resp)
            raise

    def _get(
        self,
        path: str,
        params: Optional[dict] = None,
        *,
        timeout: int = 60,
        connect_timeout_seconds: Optional[float] = None,
    ) -> dict:
        merged = {"output_mode": "json", "count": 0}
        if params:
            merged.update(params)
        resp = self._request(
            "GET",
            path,
            params=merged,
            timeout=timeout,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        try:
            return resp.json()
        finally:
            self._close_response_transport(resp)

    def _post(
        self,
        path: str,
        data: Optional[dict] = None,
        *,
        timeout: int = 60,
        connect_timeout_seconds: Optional[float] = None,
    ) -> dict:
        merged = {"output_mode": "json"}
        if data:
            merged.update(data)
        resp = self._request(
            "POST",
            path,
            data=merged,
            timeout=timeout,
            connect_timeout_seconds=connect_timeout_seconds,
        )
        try:
            return resp.json()
        except json.JSONDecodeError:
            return {"_raw": resp.text}
        finally:
            self._close_response_transport(resp)

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
    ) -> List[dict[str, Any]]:
        safe_limit = max(1, min(200, int(limit or 50)))
        safe_page_size = max(1, min(50, int(page_size or 25)))
        search_terms: List[str] = []
        dispatch_correlation_value = _build_correlation_dispatch_value(correlation_tag)
        if str(label or "").strip():
            search_terms.append(f'label="{str(label).replace(chr(34), "")}"')
        if str(owner or "").strip():
            search_terms.append(f'acl.owner="{str(owner).replace(chr(34), "")}"')
        if str(app or "").strip():
            search_terms.append(f'acl.app="{str(app).replace(chr(34), "")}"')
        if dispatch_correlation_value and str(correlation_tag or "").strip():
            safe_dispatch_value = dispatch_correlation_value.replace(chr(34), "")
            safe_tag = str(correlation_tag).replace(chr(34), "")
            search_terms.append(
                f'(request.ui_dispatch_view="{safe_dispatch_value}" OR qualifiedSearch="*{safe_tag}*")'
            )
        elif str(correlation_tag or "").strip():
            safe_tag = str(correlation_tag).replace(chr(34), "")
            search_terms.append(f'qualifiedSearch="*{safe_tag}*"')
        search_expression = " ".join(search_terms).strip()

        candidates: List[dict[str, Any]] = []
        offset = 0
        while len(candidates) < safe_limit:
            request_count = min(safe_page_size, safe_limit - len(candidates))
            params: dict[str, Any] = {"count": request_count, "offset": offset}
            if search_expression:
                params["search"] = search_expression
            data = self._get(
                "/services/search/jobs",
                params=params,
                timeout=EVIDENCE_HTTP_READ_TIMEOUT_SECONDS,
                connect_timeout_seconds=EVIDENCE_HTTP_CONNECT_TIMEOUT_SECONDS,
            )
            entries = data.get("entry", [])
            if not isinstance(entries, list) or not entries:
                break
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                content = entry.get("content", {})
                if not isinstance(content, dict):
                    content = {}
                acl = entry.get("acl", {})
                if not isinstance(acl, dict):
                    acl = {}
                request = content.get("request", {})
                if not isinstance(request, dict):
                    request = {}
                candidate = {
                    "sid": str(entry.get("name", "") or "").strip(),
                    "label": str(entry.get("label", "") or content.get("label", "") or "").strip(),
                    "published": str(entry.get("published", "") or "").strip(),
                    "updated": str(entry.get("updated", "") or "").strip(),
                    "acl": {
                        "owner": str(acl.get("owner", "") or "").strip(),
                        "app": str(acl.get("app", "") or "").strip(),
                    },
                    "content": {
                        "dispatchState": str(content.get("dispatchState", "") or "").strip(),
                        "isDone": content.get("isDone"),
                        "isFailed": content.get("isFailed"),
                        "qualifiedSearch": str(content.get("qualifiedSearch", "") or "").strip(),
                        "request": {
                            "search": str(request.get("search", "") or "").strip(),
                            "earliest_time": str(
                                request.get("earliest_time", "")
                                or request.get("dispatch.earliest_time", "")
                                or content.get("earliestTime", "")
                                or ""
                            ).strip(),
                            "latest_time": str(
                                request.get("latest_time", "")
                                or request.get("dispatch.latest_time", "")
                                or content.get("latestTime", "")
                                or ""
                            ).strip(),
                            "ui_dispatch_app": str(
                                request.get("ui_dispatch_app", "")
                                or content.get("request.ui_dispatch_app", "")
                                or ""
                            ).strip(),
                            "ui_dispatch_view": str(
                                request.get("ui_dispatch_view", "")
                                or content.get("request.ui_dispatch_view", "")
                                or ""
                            ).strip(),
                        },
                    },
                }
                candidate_earliest = candidate["content"]["request"]["earliest_time"]
                candidate_latest = candidate["content"]["request"]["latest_time"]
                expected_earliest = str(dispatch_earliest or "").strip()
                expected_latest = str(dispatch_latest or "").strip()
                if expected_earliest or expected_latest:
                    exact_window, buffered_window = _window_match_with_buffer(
                        expected_earliest,
                        expected_latest,
                        candidate_earliest,
                        candidate_latest,
                        buffer_seconds=window_buffer_seconds,
                    )
                    if not exact_window and not buffered_window:
                        continue
                candidates.append(candidate)
                if len(candidates) >= safe_limit:
                    break
            if len(entries) < request_count:
                break
            offset += len(entries)
        return candidates

    def validate_auth(self) -> None:
        self._get(
            "/services/server/info",
            params={"count": 1},
            timeout=METADATA_HTTP_READ_TIMEOUT_SECONDS,
            connect_timeout_seconds=METADATA_HTTP_CONNECT_TIMEOUT_SECONDS,
        )

    def fetch_results_csv(self, sid: str) -> Optional[bytes]:
        """Fetch job results as CSV bytes for the given SID."""
        try:
            params = {"output_mode": "csv", "count": 0}
            resp = self._request(
                "GET",
                f"/services/search/jobs/{sid}/results",
                params=params,
                timeout=DEFAULT_HTTP_READ_TIMEOUT_SECONDS,
                connect_timeout_seconds=EVIDENCE_HTTP_CONNECT_TIMEOUT_SECONDS,
            )
            try:
                return resp.content
            finally:
                self._close_response_transport(resp)
        except Exception:
            return None

    def list_apps(self):
        try:
            data = self._get(
                "/services/apps/local",
                timeout=METADATA_HTTP_READ_TIMEOUT_SECONDS,
                connect_timeout_seconds=METADATA_HTTP_CONNECT_TIMEOUT_SECONDS,
            )
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
            data = self._get(
                f"/servicesNS/-/{app}/saved/searches",
                timeout=METADATA_HTTP_READ_TIMEOUT_SECONDS,
                connect_timeout_seconds=METADATA_HTTP_CONNECT_TIMEOUT_SECONDS,
            )
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
        request_timeout_seconds: Optional[float] = None,
    ) -> Tuple[bool, Optional[str], str]:
        """
        Dispatch a saved search.

        Returns (ok, sid, error_message).
        """
        trace_context = getattr(self, "_dispatch_trace_context", {})
        if not isinstance(trace_context, dict):
            trace_context = {}
        report_owner = str(trace_context.get("report_owner", "") or "").strip()
        report_app = str(trace_context.get("report_app", "") or "").strip()
        correlation_tag = str(trace_context.get("correlation_tag", "") or "").strip()
        correlation_dispatch_value = _build_correlation_dispatch_value(correlation_tag)
        target = _inspect_dispatch_target(
            report_id_url,
            expected_owner=report_owner,
            expected_app=report_app,
        )
        dispatch_path = str(target.get("dispatch_path", "") or "").strip()
        url = self.base_url + dispatch_path if dispatch_path else ""
        connect_timeout_seconds = DISPATCH_HTTP_CONNECT_TIMEOUT_SECONDS
        read_timeout_seconds = max(
            1,
            min(
                DISPATCH_HTTP_READ_TIMEOUT_SECONDS,
                int(round(float(request_timeout_seconds)))
                if request_timeout_seconds is not None
                else DISPATCH_HTTP_READ_TIMEOUT_SECONDS,
            ),
        )
        request_start_time = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        initial_payload, initial_optional_keys = _build_dispatch_payload(
            earliest=earliest,
            latest=latest,
            trigger_actions=trigger_actions,
            report_app=report_app,
            correlation_dispatch_value=correlation_dispatch_value,
            include_optional_fields=True,
        )
        minimal_payload, _ = _build_dispatch_payload(
            earliest=earliest,
            latest=latest,
            trigger_actions=trigger_actions,
            report_app=report_app,
            correlation_dispatch_value=correlation_dispatch_value,
            include_optional_fields=False,
        )
        correlation_fields = {
            key: initial_payload.get(key)
            for key in initial_optional_keys
            if key in initial_payload
        }
        recent_metadata = _get_recent_metadata_activity(self)
        recent_cleanup = _get_recent_transport_cleanup(self)
        request_body_summary = _summarize_dispatch_payload(initial_payload)
        self._last_dispatch_meta = {
            "transport_mode": "oneshot_request",
            "request_class": DISPATCH_REQUEST_CLASS,
            "broker_lane_name": "direct_dispatch",
            "transport_freshness": "fresh_oneshot_session",
            "request_start_time": request_start_time,
            "request_body_summary": request_body_summary,
            "request_payload_keys": _dispatch_payload_keys_text(initial_payload),
            "request_optional_payload_keys": ",".join(initial_optional_keys),
            "connect_timeout_seconds": connect_timeout_seconds,
            "read_timeout_seconds": read_timeout_seconds,
            "rest_endpoint": dispatch_path,
            "rest_method": "POST",
            "path_owner": str(target.get("owner", "") or ""),
            "path_app": str(target.get("app", "") or ""),
            "path_saved_search_name": str(target.get("name", "") or ""),
            "namespace_consistency": str(target.get("namespace_consistency", "") or ""),
            "path_validation_error": str(target.get("validation_error", "") or ""),
            "correlation_id": str(trace_context.get("correlation_id", "") or ""),
            "correlation_tag": correlation_tag,
            "correlation_dispatch_value": correlation_dispatch_value,
            "recent_metadata_outcome": str(recent_metadata.get("outcome", "") or ""),
            "recent_metadata_elapsed_ms": recent_metadata.get("elapsed_ms", ""),
            "recent_metadata_age_ms": recent_metadata.get("age_ms", ""),
            "recent_metadata_path": str(recent_metadata.get("path", "") or ""),
            "recent_transport_cleanup_reason": str(recent_cleanup.get("reason", "") or ""),
            "recent_transport_cleanup_age_ms": recent_cleanup.get("age_ms", ""),
            "recent_transport_cleanup_operation": str(recent_cleanup.get("operation", "") or ""),
            "correlation_mode": (
                CORRELATION_MODE_SPLUNK_UI_CONTEXT_BEST_EFFORT
                if correlation_fields
                else CORRELATION_MODE_TOOL_LOCAL_ONLY
            ),
        }
        backend_trace_fields = {
            "run_id": str(trace_context.get("run_id", "") or ""),
            "report_name": str(trace_context.get("report_name", "") or ""),
            "slice_label": str(trace_context.get("slice_label", "") or ""),
            "slice_index": trace_context.get("slice_index"),
            "slice_total": trace_context.get("slice_total"),
            "correlation_id": str(trace_context.get("correlation_id", "") or ""),
            "correlation_tag": correlation_tag,
            "earliest": str(trace_context.get("earliest", earliest or "") or ""),
            "latest": str(trace_context.get("latest", latest or "") or ""),
            "request_class": DISPATCH_REQUEST_CLASS,
            "rest_endpoint": dispatch_path,
            "namespace_consistency": str(target.get("namespace_consistency", "") or ""),
            "transport_mode": "oneshot_request",
            "thread_name": threading.current_thread().name,
        }
        rest_start_monotonic = time.monotonic()
        _audit_event(
            "SPLUNK_DISPATCH_REST_START",
            level="INFO",
            **backend_trace_fields,
        )

        if (not dispatch_path) or str(target.get("namespace_consistency", "") or "").strip().lower() == "invalid":
            classification = "failed_dispatch_nonretryable"
            detail = (
                "Dispatch path could not be constructed from the frozen saved-search definition. "
                f"path_validation={str(target.get('validation_error', '') or 'missing_dispatch_path')}"
            )
            self._last_dispatch_meta["failure_classification"] = classification
            self._last_dispatch_meta["response_body_snippet"] = ""
            _audit_event(
                "SPLUNK_DISPATCH_REST_INVALID_PATH",
                level="WARN",
                **backend_trace_fields,
                failure_classification=classification,
                reason=_short_error(detail),
            )
            return False, None, detail

        def _send_dispatch_request(*, allow_reauth: bool, request_payload: dict[str, Any]) -> Any:
            oneshot_session = requests.Session()
            oneshot_session.trust_env = False
            oneshot_session.verify = self.verify_ssl
            transport_token = self._register_active_transport(oneshot_session)
            try:
                resp_local = oneshot_session.request(
                    method="POST",
                    url=url,
                    data=request_payload,
                    headers={
                        "Authorization": self._auth_header,
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Connection": "close",
                    },
                    timeout=(connect_timeout_seconds, read_timeout_seconds),
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )
            except Exception:
                self._release_active_transport(transport_token)
                close_session = getattr(oneshot_session, "close", None)
                if callable(close_session):
                    close_session()
                raise
            if resp_local.status_code in (401, 403) and allow_reauth and self._refresh_auth_header():
                self._release_active_transport(transport_token)
                close_response = getattr(resp_local, "close", None)
                if callable(close_response):
                    close_response()
                close_session = getattr(oneshot_session, "close", None)
                if callable(close_session):
                    close_session()
                return _send_dispatch_request(
                    allow_reauth=False,
                    request_payload=request_payload,
                )
            self._bind_response_transport(resp_local, session=oneshot_session, token=transport_token)
            return resp_local

        def _response_elapsed_ms(resp_local: Any) -> int:
            try:
                return int(max(0.0, float(resp_local.elapsed.total_seconds())) * 1000)
            except Exception:
                return 0

        def _response_snippet(resp_local: Any) -> str:
            try:
                return redact_text(str(resp_local.text or "")[:500])
            except Exception:
                return ""

        def _dispatch_error_message(
            *,
            status_code: int,
            classification: str,
            request_payload: dict[str, Any],
            response_snippet: str,
            fallback_attempted: bool = False,
            fallback_succeeded: bool = False,
            detail_suffix: str = "",
        ) -> str:
            parts = [
                f"Dispatch rejected by Splunk (HTTP {int(status_code)})",
                f"classification={classification}",
                f"endpoint={dispatch_path or '-'}",
                f"request_class={DISPATCH_REQUEST_CLASS}",
                f"payload_keys={_dispatch_payload_keys_text(request_payload) or '-'}",
            ]
            request_values = _summarize_dispatch_payload(request_payload)
            if request_values:
                parts.append(f"payload={request_values}")
            if response_snippet:
                parts.append(f"response={response_snippet}")
            validation_error = str(target.get("validation_error", "") or "").strip()
            if validation_error:
                parts.append(f"path_validation={validation_error}")
            if fallback_attempted:
                parts.append("compatibility_fallback_attempted=true")
            if fallback_succeeded:
                parts.append("compatibility_fallback_succeeded=true")
            if detail_suffix:
                parts.append(detail_suffix)
            return "; ".join(parts)

        resp = None
        try:
            resp = _send_dispatch_request(
                allow_reauth=True,
                request_payload=initial_payload,
            )
        except requests.exceptions.SSLError as exc:
            self._last_dispatch_meta["failure_classification"] = "ssl_error"
            _audit_event(
                "SPLUNK_DISPATCH_REST_EXCEPTION",
                level="WARN",
                **backend_trace_fields,
                elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                exception_type=type(exc).__name__,
                exception_message=_short_error(redact_text(str(exc) or repr(exc))),
            )
            return False, None, f"Request error: {exc!r}"
        except requests.exceptions.RequestException as exc:
            safe_error = redact_text(str(exc) or repr(exc))
            failure_classification = "network_interruption" if _error_looks_like_interruption(safe_error) else "request_exception"
            self._last_dispatch_meta["failure_classification"] = failure_classification
            _audit_event(
                "SPLUNK_DISPATCH_REST_EXCEPTION",
                level="WARN",
                **backend_trace_fields,
                elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                exception_type=type(exc).__name__,
                exception_message=_short_error(safe_error),
            )
            return False, None, f"Request error: {safe_error}"

        self._last_dispatch_meta["response_status_code"] = int(resp.status_code)
        self._last_dispatch_meta["response_headers_elapsed_ms"] = _response_elapsed_ms(resp)
        self._last_dispatch_meta["response_location"] = str(resp.headers.get("Location", "") or "")
        _audit_event(
            "SPLUNK_DISPATCH_REST_RESPONSE",
            level="INFO" if int(resp.status_code) < 400 else "WARN",
            **backend_trace_fields,
            elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
            response_status_code=int(resp.status_code),
        )

        try:
            correlation_mode = self._last_dispatch_meta.get("correlation_mode", CORRELATION_MODE_TOOL_LOCAL_ONLY)
            if correlation_fields:
                correlation_mode = CORRELATION_MODE_SPLUNK_UI_CONTEXT_PROPAGATED
                self._last_dispatch_meta["correlation_mode"] = correlation_mode
            if resp.status_code in (401, 403):
                self._last_dispatch_meta["failure_classification"] = "auth_error"
                return False, None, "Request error: RuntimeError('Authentication failed (401/403) after re-auth retry.')"
            if resp.status_code >= 400:
                initial_snippet = _response_snippet(resp)
                initial_classification = _classify_dispatch_http_failure(
                    status_code=int(resp.status_code),
                    response_text=initial_snippet,
                    had_optional_fields=bool(initial_optional_keys),
                    namespace_consistency=str(target.get("namespace_consistency", "") or ""),
                    path_validation_error=str(target.get("validation_error", "") or ""),
                )
                self._last_dispatch_meta["response_body_snippet"] = initial_snippet
                self._last_dispatch_meta["failure_classification"] = initial_classification
                self._last_dispatch_meta["initial_response_status_code"] = int(resp.status_code)
                self._last_dispatch_meta["initial_response_body_snippet"] = initial_snippet
                self._last_dispatch_meta["initial_request_body_summary"] = _summarize_dispatch_payload(initial_payload)
                self._last_dispatch_meta["initial_request_payload_keys"] = _dispatch_payload_keys_text(initial_payload)
                self._last_dispatch_meta["fallback_attempted"] = False
                _audit_event(
                    "SPLUNK_DISPATCH_REST_HTTP_400",
                    level="WARN",
                    **backend_trace_fields,
                    failure_classification=initial_classification,
                    response_status_code=int(resp.status_code),
                    response_body_snippet=initial_snippet,
                    request_payload_keys=_dispatch_payload_keys_text(initial_payload),
                    request_payload_summary=_summarize_dispatch_payload(initial_payload),
                )
                should_try_fallback = (
                    int(resp.status_code) == 400
                    and bool(initial_optional_keys)
                    and initial_payload != minimal_payload
                )
                if should_try_fallback:
                    self._last_dispatch_meta["fallback_attempted"] = True
                    self._last_dispatch_meta["correlation_mode"] = CORRELATION_MODE_TOOL_LOCAL_FALLBACK
                    self._last_dispatch_meta["correlation_fallback_reason"] = "dispatch_http_400_optional_fields"
                    self._last_dispatch_meta["fallback_request_body_summary"] = _summarize_dispatch_payload(minimal_payload)
                    self._last_dispatch_meta["fallback_request_payload_keys"] = _dispatch_payload_keys_text(minimal_payload)
                    _audit_event(
                        "SPLUNK_DISPATCH_REST_FALLBACK_START",
                        level="WARN",
                        **backend_trace_fields,
                        initial_failure_classification=initial_classification,
                        initial_response_body_snippet=initial_snippet,
                        fallback_payload_keys=_dispatch_payload_keys_text(minimal_payload),
                    )
                    self._close_response_transport(resp)
                    resp = _send_dispatch_request(
                        allow_reauth=True,
                        request_payload=minimal_payload,
                    )
                    self._last_dispatch_meta["response_status_code"] = int(resp.status_code)
                    self._last_dispatch_meta["response_headers_elapsed_ms"] = _response_elapsed_ms(resp)
                    self._last_dispatch_meta["response_location"] = str(resp.headers.get("Location", "") or "")
                    fallback_snippet = _response_snippet(resp)
                    self._last_dispatch_meta["fallback_response_status_code"] = int(resp.status_code)
                    self._last_dispatch_meta["fallback_response_body_snippet"] = fallback_snippet
                    self._last_dispatch_meta["request_body_summary"] = _summarize_dispatch_payload(minimal_payload)
                    self._last_dispatch_meta["request_payload_keys"] = _dispatch_payload_keys_text(minimal_payload)
                    self._last_dispatch_meta["request_optional_payload_keys"] = ""
                    _audit_event(
                        "SPLUNK_DISPATCH_REST_FALLBACK_RESPONSE",
                        level="INFO" if int(resp.status_code) < 400 else "WARN",
                        **backend_trace_fields,
                        response_status_code=int(resp.status_code),
                        response_body_snippet=fallback_snippet,
                    )
                    if int(resp.status_code) >= 400:
                        fallback_classification = _classify_dispatch_http_failure(
                            status_code=int(resp.status_code),
                            response_text=fallback_snippet,
                            had_optional_fields=False,
                            namespace_consistency=str(target.get("namespace_consistency", "") or ""),
                            path_validation_error=str(target.get("validation_error", "") or ""),
                        )
                        self._last_dispatch_meta["response_body_snippet"] = fallback_snippet
                        self._last_dispatch_meta["failure_classification"] = "failed_dispatch_fallback_failed"
                        return False, None, _dispatch_error_message(
                            status_code=int(resp.status_code),
                            classification="failed_dispatch_fallback_failed",
                            request_payload=minimal_payload,
                            response_snippet=fallback_snippet,
                            fallback_attempted=True,
                            detail_suffix=(
                                f"initial_classification={initial_classification}; "
                                f"fallback_classification={fallback_classification}; "
                                f"initial_response={initial_snippet or '-'}"
                            ),
                        )
                    correlation_mode = CORRELATION_MODE_TOOL_LOCAL_FALLBACK
                    self._last_dispatch_meta["failure_classification"] = "failed_dispatch_fallback_succeeded"
                    self._last_dispatch_meta["response_body_snippet"] = fallback_snippet
                else:
                    return False, None, _dispatch_error_message(
                        status_code=int(resp.status_code),
                        classification=initial_classification,
                        request_payload=initial_payload,
                        response_snippet=initial_snippet,
                    )

            location = str(resp.headers.get("Location", "") or "").strip()
            if location:
                sid = location.rstrip("/").rsplit("/", 1)[-1].strip()
                if sid:
                    self._last_dispatch_meta["sid_source"] = "location_header"
                    self._last_dispatch_meta["sid"] = sid
                    self._last_dispatch_meta["response_body_read_elapsed_ms"] = 0
                    self._last_dispatch_meta["json_parse_elapsed_ms"] = 0
                    self._last_dispatch_meta["post_sid_return_work_ms"] = 0
                    _audit_event(
                        "SPLUNK_DISPATCH_SID_PARSED",
                        level="INFO",
                        **backend_trace_fields,
                        elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                        sid=sid,
                        sid_source="location_header",
                        correlation_mode=correlation_mode,
                    )
                    return True, sid, ""

            body_read_start = time.monotonic()
            response_text = str(resp.text or "")
            self._last_dispatch_meta["response_body_read_elapsed_ms"] = int(
                (time.monotonic() - body_read_start) * 1000
            )
            self._last_dispatch_meta["response_body_snippet"] = redact_text(response_text[:500])

            json_parse_start = time.monotonic()
            try:
                response_payload = json.loads(response_text)
            except json.JSONDecodeError:
                self._last_dispatch_meta["json_parse_elapsed_ms"] = int(
                    (time.monotonic() - json_parse_start) * 1000
                )
                self._last_dispatch_meta["failure_classification"] = "non_json_response"
                return False, None, f"Non-JSON response: {response_text[:500]}"
            self._last_dispatch_meta["json_parse_elapsed_ms"] = int(
                (time.monotonic() - json_parse_start) * 1000
            )
            if isinstance(response_payload, dict):
                self._last_dispatch_meta["response_payload"] = dict(response_payload)
            sid = str(response_payload.get("sid", "") or "").strip() if isinstance(response_payload, dict) else ""
            if not sid:
                self._last_dispatch_meta["failure_classification"] = "missing_sid"
                return False, None, f"No sid in dispatch response: {response_payload}"

            self._last_dispatch_meta["sid_source"] = "json_body"
            self._last_dispatch_meta["sid"] = sid
            self._last_dispatch_meta["post_sid_return_work_ms"] = 0
            _audit_event(
                "SPLUNK_DISPATCH_SID_PARSED",
                level="INFO",
                **backend_trace_fields,
                elapsed_ms=int((time.monotonic() - rest_start_monotonic) * 1000),
                sid=sid,
                sid_source="json_body",
                correlation_mode=correlation_mode,
            )
            return True, sid, ""
        finally:
            self._close_response_transport(resp)

    def get_job_status_snapshot(
        self,
        sid: str,
        request_timeout_seconds: float = 10.0,
        max_total_timeout_seconds: Optional[float] = None,
    ) -> Tuple[str, dict]:
        effective_timeout = min(
            float(VERIFICATION_HTTP_READ_TIMEOUT_SECONDS),
            max(1.0, float(request_timeout_seconds)),
        )
        if max_total_timeout_seconds is not None:
            try:
                effective_timeout = min(effective_timeout, max(1.0, float(max_total_timeout_seconds)))
            except Exception:
                effective_timeout = min(
                    float(VERIFICATION_HTTP_READ_TIMEOUT_SECONDS),
                    max(1.0, float(request_timeout_seconds)),
                )
        start = time.monotonic()
        resp = self._request(
            "GET",
            f"/services/search/jobs/{sid}",
            params={"output_mode": "json", "count": 0},
            timeout=effective_timeout,
            connect_timeout_seconds=VERIFICATION_HTTP_CONNECT_TIMEOUT_SECONDS,
        )
        try:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            self._last_snapshot_meta = {
                "splunk_elapsed_ms": elapsed_ms,
                "request_timeout_seconds": effective_timeout,
            }
            data = resp.json()
        finally:
            self._close_response_transport(resp)
        entry = data.get("entry", [{}])[0]
        content = entry.get("content", {})
        if not isinstance(content, dict):
            content = {}

        dispatch_state = str(content.get("dispatchState", "") or "").strip().upper()
        is_done = _parse_bool(content.get("isDone"), False)
        is_failed = _parse_bool(content.get("isFailed"), False)

        if dispatch_state in FAILED_DISPATCH_STATES or is_failed:
            return "FAILED", content
        if is_done:
            return "SUCCESS", content
        return "RUNNING", content

    def check_job_status(
        self, sid: str, wait_seconds: int = 10, poll_interval: int = 2
    ) -> Tuple[str, dict]:
        """
        Check job status for a given sid.

        Returns (state, content) where state is 'SUCCESS', 'FAILED', or 'TIMEOUT'.
        """
        last_content: dict = {}
        deadline = time.monotonic() + max(1, int(wait_seconds))
        poll_seconds = max(1.0, float(poll_interval))

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            request_timeout = min(max(1.0, poll_seconds), max(1.0, remaining))
            state, content = self.get_job_status_snapshot(
                sid,
                request_timeout_seconds=request_timeout,
            )
            last_content = content
            if state in ("SUCCESS", "FAILED"):
                return state, content
            sleep_seconds = min(poll_seconds, max(0.0, deadline - time.monotonic()))
            if sleep_seconds <= 0:
                break
            time.sleep(sleep_seconds)

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


def _verification_mode_label(*, prefer_merge_report_verification: bool, merge_report_log_path: str) -> str:
    if prefer_merge_report_verification:
        return "merge_report"
    return "native_status"


def _build_batch_slice_blueprints(
    *,
    batch_id: str,
    report_id_url: str,
    report_name: str,
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
    app: str,
    owner: str,
    verification_mode: str,
    correlation_mode: str,
) -> List[dict[str, Any]]:
    blueprints: List[dict[str, Any]] = []
    if no_change:
        slice_label = "single run"
        slice_id = _derive_slice_id(batch_id, report_id_url, report_name, slice_label, "", "")
        blueprints.append(
            {
                "slice_id": slice_id,
                "slice_label": slice_label,
                "slice_index": 1,
                "slice_total": 1,
                "earliest": start.strftime("%Y-%m-%d %H:%M:%S"),
                "latest": end.strftime("%Y-%m-%d %H:%M:%S"),
                "dispatch_earliest": "",
                "dispatch_latest": "",
                "report_owner": owner,
                "report_app": app,
                "verification_mode": verification_mode,
                "correlation_tag": _build_correlation_tag(batch_id, slice_id, 1),
                "correlation_mode": correlation_mode,
            }
        )
        return blueprints

    starts, ends = build_slices(start, end, frequency)
    total = len(starts)
    for index, (slice_start, slice_end) in enumerate(zip(starts, ends), start=1):
        earliest_display = slice_start.strftime("%Y-%m-%d %H:%M:%S")
        latest_display = slice_end.strftime("%Y-%m-%d %H:%M:%S")
        dispatch_earliest = to_epoch(slice_start)
        dispatch_latest = to_epoch(slice_end)
        slice_label = f"[{index}/{total}]"
        slice_id = _derive_slice_id(
            batch_id,
            report_id_url,
            report_name,
            slice_label,
            dispatch_earliest,
            dispatch_latest,
        )
        blueprints.append(
            {
                "slice_id": slice_id,
                "slice_label": slice_label,
                "slice_index": index,
                "slice_total": total,
                "earliest": earliest_display,
                "latest": latest_display,
                "dispatch_earliest": dispatch_earliest,
                "dispatch_latest": dispatch_latest,
                "report_owner": owner,
                "report_app": app,
                "verification_mode": verification_mode,
                "correlation_tag": _build_correlation_tag(batch_id, slice_id, 1),
                "correlation_mode": correlation_mode,
            }
        )
    return blueprints


def _prepare_batch_execution_definition(
    context: RegenContext,
    *,
    report_ids: List[str],
    report_names: List[str],
    selected_indices: List[int],
    frequency: str,
    start: datetime,
    end: datetime,
    no_change: bool,
    app: str,
    owner: str,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
) -> None:
    if context.slices:
        return
    verification_mode = _verification_mode_label(
        prefer_merge_report_verification=prefer_merge_report_verification,
        merge_report_log_path=merge_report_log_path,
    )
    context.frozen_definition = {
        "batch_id": context.batch_id,
        "correlation_mode": context.correlation_mode,
        "correlation_scope": _correlation_scope_for_mode(context.correlation_mode),
        "report_definitions": [],
        "verification_mode": verification_mode,
        "savedsearch_recipients": [],
        "reconciliation_correlation_fields": [
            "correlation_tag",
            "saved_search_name",
            "execution_owner",
            "app_namespace",
            "slice_window",
            "merge_report_sid",
        ],
        "reconciliation_confidence_rules": {
            "strong": "saved_search_name + execution_owner + app_namespace + exact slice_window",
            "weak": "saved_search_name + execution_owner + app_namespace without exact slice_window",
            "conflict": "partial name/window match without a safe exact identity match",
        },
    }
    for selected_index in selected_indices:
        report_id_url = report_ids[selected_index]
        report_name = report_names[selected_index]
        identity = _parse_saved_search_identity(
            report_id_url,
            report_name,
            default_app=app,
            default_owner=owner,
        )
        blueprints = _build_batch_slice_blueprints(
            batch_id=context.batch_id,
            report_id_url=report_id_url,
            report_name=report_name,
            frequency=frequency,
            start=start,
            end=end,
            no_change=no_change,
            app=identity.app,
            owner=identity.owner,
            verification_mode=verification_mode,
            correlation_mode=context.correlation_mode,
        )
        context.frozen_definition["report_definitions"].append(
            {
                "report_id_url": report_id_url,
                "report_name": report_name,
                "owner": identity.owner,
                "app": identity.app,
                "verification_mode": verification_mode,
                "slices": [dict(item) for item in blueprints],
            }
        )
        for blueprint in blueprints:
            context.add_slice(
                batch_id=context.batch_id,
                slice_id=blueprint["slice_id"],
                attempt_id=0,
                report_name=report_name,
                slice_label=blueprint["slice_label"],
                slice_index=blueprint["slice_index"],
                slice_total=blueprint["slice_total"],
                earliest=blueprint["earliest"],
                latest=blueprint["latest"],
                status="QUEUED",
                outcome_code="QUEUED",
                dispatch_report_id_url=report_id_url,
                dispatch_earliest=blueprint["dispatch_earliest"],
                dispatch_latest=blueprint["dispatch_latest"],
                lifecycle_state=SLICE_STATE_QUEUED,
                state_reason="Queued at batch start.",
                execution_context_id="",
                correlation_tag=blueprint["correlation_tag"],
                correlation_mode=blueprint["correlation_mode"],
                report_owner=blueprint["report_owner"],
                report_app=blueprint["report_app"],
                verification_mode=blueprint["verification_mode"],
                reconciliation_confidence="",
                dispatch_outcome="QUEUED",
                execution_outcome="UNKNOWN",
                evidence_outcome="NONE",
                business_outcome="QUEUED",
            )

def send_email_via_smtp(
    to_addrs: List[str], subject: str, body: str, attachments: Optional[List[tuple]] = None
) -> bool:
    """Send an email via SMTP without authentication.

    attachments: list of tuples (filename, bytes, maintype, subtype)
    """
    if _env_override_allowed():
        host = os.getenv("SPLUNK_TOOL_SMTP_HOST", "localhost")
        port = int(os.getenv("SPLUNK_TOOL_SMTP_PORT", "25"))
        from_addr = os.getenv("SPLUNK_TOOL_FROM", "noreply@example.com")
    else:
        _audit_blocked_env_override("SPLUNK_TOOL_SMTP_HOST", "SPLUNK_TOOL_SMTP_PORT", "SPLUNK_TOOL_FROM")
        host = "localhost"
        port = 25
        from_addr = "noreply@example.com"

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


def _emit_broker_call_log(
    *,
    logs: Optional[List[str]],
    log_callback: Optional[Callable[[str], None]],
    audit_event: Optional[Callable[..., None]],
    event: str,
    op: str,
    slice_label: str,
    slice_index: int = 0,
    slice_total: int = 0,
    batch_id: str = "",
    slice_id: str = "",
    attempt_id: int = 0,
    correlation_tag: str = "",
    started_utc: str = "",
    ended_utc: str = "",
    elapsed_ms: Optional[int] = None,
    outcome: str = "",
    stage_name: str = "",
    attempt: int = 0,
    error_detail: str = "",
) -> None:
    safe_slice_label = str(slice_label or "").strip() or "n/a"
    fields: dict[str, Any] = {
        "op": str(op or "").strip(),
        "batch_id": str(batch_id or "").strip(),
        "slice_id": str(slice_id or "").strip(),
        "slice_label": safe_slice_label,
        "slice_index": max(0, int(slice_index or 0)),
        "slice_total": max(0, int(slice_total or 0)),
    }
    if attempt_id > 0:
        fields["attempt_id"] = int(attempt_id)
    if correlation_tag:
        fields["correlation_tag"] = str(correlation_tag)
    if started_utc:
        fields["started_utc"] = started_utc
    if ended_utc:
        fields["ended_utc"] = ended_utc
    if elapsed_ms is not None:
        fields["elapsed_ms"] = max(0, int(elapsed_ms))
    if outcome:
        fields["outcome"] = str(outcome)
    if stage_name:
        fields["stage_name"] = str(stage_name)
    if attempt > 0:
        fields["attempt"] = int(attempt)
    if error_detail:
        fields["error_detail"] = _short_error(redact_text(error_detail))

    line_parts = [f"[Debug] {event}"]
    for key in (
        "op",
        "batch_id",
        "slice_id",
        "slice_label",
        "slice_index",
        "slice_total",
        "attempt_id",
        "correlation_tag",
        "started_utc",
        "ended_utc",
        "elapsed_ms",
        "outcome",
        "stage_name",
        "attempt",
        "error_detail",
    ):
        value = fields.get(key, "")
        if value == "" or value is None:
            continue
        line_parts.append(f"{key}={value}")
    if logs is not None:
        _append_log(logs, " ".join(line_parts), log_callback)
    if callable(audit_event):
        level = "WARN" if fields.get("outcome") in {"timeout", "exception", "failed", "timeout_no_sid"} else "INFO"
        audit_event(event, level=level, **fields)


def _coerce_int_field(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except Exception:
        try:
            return int(round(float(value)))
        except Exception:
            return None


def _dispatch_attempt_store_key(batch_id: str, slice_id: str) -> str:
    return f"{str(batch_id or '').strip()}::{str(slice_id or '').strip()}"


def _build_dispatch_attempt_diagnostics(
    *,
    client: SplunkClient,
    execution_context: SliceExecutionContext,
    dispatch_state: str,
    dispatch_elapsed_ms: int,
    dispatch_call_meta: dict[str, Any],
    dispatch_runtime_meta: dict[str, Any],
    dispatch_outcome: str,
) -> dict[str, Any]:
    recent_metadata = _get_recent_metadata_activity(client)
    recent_cleanup = _get_recent_transport_cleanup(client)
    return {
        "dispatch_state": str(dispatch_state or "").strip(),
        "dispatch_outcome": str(dispatch_outcome or "").strip(),
        "request_class": str(dispatch_runtime_meta.get("request_class", "") or DISPATCH_REQUEST_CLASS),
        "lane_name": str(dispatch_runtime_meta.get("broker_lane_name", "") or dispatch_runtime_meta.get("lane_name", "") or ""),
        "broker_request_id": str(dispatch_runtime_meta.get("broker_request_id", "") or ""),
        "queue_wait_ms": _coerce_int_field(dispatch_runtime_meta.get("broker_queue_wait_ms", "")),
        "broker_processing_ms": _coerce_int_field(dispatch_runtime_meta.get("broker_processing_ms", "")),
        "broker_total_elapsed_ms": _coerce_int_field(dispatch_runtime_meta.get("broker_total_elapsed_ms", "")),
        "lane_active_at_enqueue": _coerce_int_field(dispatch_runtime_meta.get("broker_lane_active_at_enqueue", "")),
        "lane_busy_at_enqueue": bool(dispatch_runtime_meta.get("broker_lane_busy_at_enqueue", False)),
        "preflight_dispatch_lane_active": _coerce_int_field(dispatch_runtime_meta.get("preflight_dispatch_lane_active", "")),
        "preflight_recycle_triggered": bool(dispatch_runtime_meta.get("preflight_recycle_triggered", False)),
        "preflight_dispatch_recent_timeouts": _coerce_int_field(dispatch_runtime_meta.get("preflight_dispatch_recent_timeouts", "")),
        "preflight_metadata_recent_timeouts": _coerce_int_field(dispatch_runtime_meta.get("preflight_metadata_recent_timeouts", "")),
        "splunk_rest_ms": _coerce_int_field(dispatch_runtime_meta.get("response_headers_elapsed_ms", "")),
        "response_body_ms": _coerce_int_field(dispatch_runtime_meta.get("response_body_read_elapsed_ms", "")),
        "dispatch_elapsed_ms": max(0, int(dispatch_elapsed_ms or 0)),
        "transport_mode": str(dispatch_runtime_meta.get("transport_mode", "") or ""),
        "transport_freshness": str(dispatch_runtime_meta.get("transport_freshness", "") or ""),
        "dispatch_client_mode": str(dispatch_runtime_meta.get("dispatch_client_mode", "") or ""),
        "recent_metadata_outcome": str(
            dispatch_runtime_meta.get("recent_metadata_outcome", "") or recent_metadata.get("outcome", "") or ""
        ),
        "recent_metadata_elapsed_ms": _coerce_int_field(
            dispatch_runtime_meta.get("recent_metadata_elapsed_ms", "") or recent_metadata.get("elapsed_ms", "")
        ),
        "recent_metadata_age_ms": _coerce_int_field(
            dispatch_runtime_meta.get("recent_metadata_age_ms", "") or recent_metadata.get("age_ms", "")
        ),
        "recent_metadata_path": str(
            dispatch_runtime_meta.get("recent_metadata_path", "") or recent_metadata.get("path", "") or ""
        ),
        "recent_transport_cleanup_reason": str(
            dispatch_runtime_meta.get("recent_transport_cleanup_reason", "")
            or recent_cleanup.get("reason", "")
            or ""
        ),
        "recent_transport_cleanup_age_ms": _coerce_int_field(
            dispatch_runtime_meta.get("recent_transport_cleanup_age_ms", "") or recent_cleanup.get("age_ms", "")
        ),
        "recent_transport_cleanup_operation": str(
            dispatch_runtime_meta.get("recent_transport_cleanup_operation", "")
            or recent_cleanup.get("operation", "")
            or ""
        ),
        "worker_thread_name": str(dispatch_call_meta.get("worker_thread_name", "") or ""),
        "started_utc": str(dispatch_call_meta.get("started_utc", "") or ""),
        "batch_id": execution_context.batch_id,
        "slice_id": execution_context.slice_id,
        "attempt_id": execution_context.attempt_id,
    }


def _classify_dispatch_timeout_no_sid(diag: dict[str, Any]) -> str:
    recent_metadata_outcome = str(diag.get("recent_metadata_outcome", "") or "").strip().lower()
    recent_metadata_age_ms = _coerce_int_field(diag.get("recent_metadata_age_ms", ""))
    lane_active_at_enqueue = _coerce_int_field(diag.get("lane_active_at_enqueue", ""))
    preflight_dispatch_lane_active = _coerce_int_field(diag.get("preflight_dispatch_lane_active", ""))
    queue_wait_ms = _coerce_int_field(diag.get("queue_wait_ms", ""))
    dispatch_client_mode = str(diag.get("dispatch_client_mode", "") or "").strip().lower()
    if recent_metadata_outcome in {"timeout_metadata_fetch", "failed_metadata_fetch"} and (
        recent_metadata_age_ms is None or recent_metadata_age_ms <= 120000
    ):
        return "dispatch_timeout_no_sid_metadata_contamination_suspected"
    if (
        bool(diag.get("lane_busy_at_enqueue"))
        or (lane_active_at_enqueue is not None and lane_active_at_enqueue > 0)
        or (preflight_dispatch_lane_active is not None and preflight_dispatch_lane_active > 0)
        or (queue_wait_ms is not None and queue_wait_ms >= 500)
    ):
        return "dispatch_timeout_no_sid_queue_delay_suspected"
    if dispatch_client_mode == "shared_client_fallback":
        return "dispatch_timeout_no_sid_stale_transport_suspected"
    return "dispatch_timeout_no_sid_unknown"


def _emit_dispatch_attempt_diagnostics(
    *,
    logs: Optional[List[str]],
    log_callback: Optional[Callable[[str], None]],
    audit_event: Optional[Callable[..., None]],
    execution_context: SliceExecutionContext,
    diag: dict[str, Any],
    classification: str = "",
) -> None:
    line_parts = [
        "[Debug] DISPATCH_ATTEMPT_DIAGNOSTICS",
        f"batch_id={execution_context.batch_id}",
        f"slice_id={execution_context.slice_id}",
        f"attempt_id={execution_context.attempt_id}",
        f"slice_label={execution_context.slice_label}",
        f"request_class={diag.get('request_class') or DISPATCH_REQUEST_CLASS}",
    ]
    for key in (
        "lane_name",
        "broker_request_id",
        "queue_wait_ms",
        "broker_processing_ms",
        "broker_total_elapsed_ms",
        "preflight_dispatch_lane_active",
        "preflight_recycle_triggered",
        "splunk_rest_ms",
        "dispatch_elapsed_ms",
        "transport_mode",
        "transport_freshness",
        "dispatch_client_mode",
        "recent_metadata_outcome",
        "recent_metadata_age_ms",
        "recent_transport_cleanup_reason",
        "recent_transport_cleanup_age_ms",
        "dispatch_outcome",
        "dispatch_state",
    ):
        value = diag.get(key, "")
        if value in ("", None):
            continue
        line_parts.append(f"{key}={value}")
    if classification:
        line_parts.append(f"classification={classification}")
    if logs is not None:
        _append_log(logs, " ".join(line_parts), log_callback)
    if callable(audit_event):
        extra_fields = {
            k: v
            for k, v in diag.items()
            if v not in ("", None) and k not in {"batch_id", "slice_id", "attempt_id"}
        }
        audit_event(
            "DISPATCH_ATTEMPT_DIAGNOSTICS",
            level="INFO",
            batch_id=execution_context.batch_id,
            slice_id=execution_context.slice_id,
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            attempt_id=execution_context.attempt_id,
            correlation_tag=execution_context.correlation_tag,
            classification=classification,
            **extra_fields,
        )


def _emit_dispatch_attempt_comparison(
    *,
    logs: Optional[List[str]],
    log_callback: Optional[Callable[[str], None]],
    audit_event: Optional[Callable[..., None]],
    execution_context: SliceExecutionContext,
    previous_diag: dict[str, Any],
    current_diag: dict[str, Any],
) -> None:
    line = (
        "[Debug] DISPATCH_ATTEMPT_COMPARISON "
        f"batch_id={execution_context.batch_id} slice_id={execution_context.slice_id} "
        f"previous_attempt_id={previous_diag.get('attempt_id', '')} current_attempt_id={current_diag.get('attempt_id', '')} "
        f"previous_lane_name={previous_diag.get('lane_name', '-') or '-'} current_lane_name={current_diag.get('lane_name', '-') or '-'} "
        f"previous_queue_wait_ms={previous_diag.get('queue_wait_ms', '-') if previous_diag.get('queue_wait_ms', None) is not None else '-'} "
        f"current_queue_wait_ms={current_diag.get('queue_wait_ms', '-') if current_diag.get('queue_wait_ms', None) is not None else '-'} "
        f"previous_transport_freshness={previous_diag.get('transport_freshness', '-') or '-'} "
        f"current_transport_freshness={current_diag.get('transport_freshness', '-') or '-'} "
        f"previous_recent_metadata_outcome={previous_diag.get('recent_metadata_outcome', '-') or '-'} "
        f"current_recent_metadata_outcome={current_diag.get('recent_metadata_outcome', '-') or '-'} "
        f"previous_cleanup_reason={previous_diag.get('recent_transport_cleanup_reason', '-') or '-'} "
        f"current_cleanup_reason={current_diag.get('recent_transport_cleanup_reason', '-') or '-'} "
        f"previous_outcome={previous_diag.get('dispatch_outcome', '-') or '-'} "
        f"current_outcome={current_diag.get('dispatch_outcome', '-') or '-'}"
    )
    if logs is not None:
        _append_log(logs, line, log_callback)
    if callable(audit_event):
        audit_event(
            "DISPATCH_ATTEMPT_COMPARISON",
            level="INFO",
            batch_id=execution_context.batch_id,
            slice_id=execution_context.slice_id,
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            attempt_id=execution_context.attempt_id,
            previous_attempt_id=previous_diag.get("attempt_id", ""),
            current_attempt_id=current_diag.get("attempt_id", ""),
            previous_outcome=previous_diag.get("dispatch_outcome", ""),
            current_outcome=current_diag.get("dispatch_outcome", ""),
            previous_queue_wait_ms=previous_diag.get("queue_wait_ms", ""),
            current_queue_wait_ms=current_diag.get("queue_wait_ms", ""),
            previous_transport_freshness=previous_diag.get("transport_freshness", ""),
            current_transport_freshness=current_diag.get("transport_freshness", ""),
            previous_recent_metadata_outcome=previous_diag.get("recent_metadata_outcome", ""),
            current_recent_metadata_outcome=current_diag.get("recent_metadata_outcome", ""),
            previous_cleanup_reason=previous_diag.get("recent_transport_cleanup_reason", ""),
            current_cleanup_reason=current_diag.get("recent_transport_cleanup_reason", ""),
        )


def _remember_dispatch_attempt_diagnostics(client: Any, *, batch_id: str, slice_id: str, diag: dict[str, Any]) -> None:
    store = getattr(client, "_dispatch_attempt_diagnostics", {})
    if not isinstance(store, dict):
        store = {}
    store[_dispatch_attempt_store_key(batch_id, slice_id)] = dict(diag)
    setattr(client, "_dispatch_attempt_diagnostics", store)


def _get_previous_dispatch_attempt_diagnostics(client: Any, *, batch_id: str, slice_id: str) -> dict[str, Any]:
    store = getattr(client, "_dispatch_attempt_diagnostics", {})
    if not isinstance(store, dict):
        return {}
    value = store.get(_dispatch_attempt_store_key(batch_id, slice_id), {})
    return dict(value) if isinstance(value, dict) else {}


def _slice_range_text(earliest: str, latest: str) -> str:
    range_parts = [part for part in (earliest, latest) if part]
    if len(range_parts) == 2:
        return f"{range_parts[0]} to {range_parts[1]}"
    if range_parts:
        return range_parts[0]
    return "saved search range"


def _append_user_slice_status(
    logs: List[str],
    *,
    slice_index: int,
    slice_total: int,
    report_name: str,
    earliest: str,
    latest: str,
    status: str,
    pending_detail_mode: str = "",
    log_callback: Optional[Callable[[str], None]] = None,
) -> None:
    prefix = f"[{slice_index}/{slice_total}]" if slice_index > 0 and slice_total > 0 else "[Report]"
    range_text = _slice_range_text(earliest, latest)
    normalized = str(status or "").strip().upper()
    if normalized == "OK":
        _append_log(logs, f"  {prefix} Email report sent successfully.", log_callback)
        _append_log(logs, f"     Report: {report_name}", log_callback)
        _append_log(logs, f"     Time range: {range_text}", log_callback)
        return
    if normalized == "EXPIRED":
        _append_log(logs, f"  {prefix} Pending reconciliation window expired.", log_callback)
        _append_log(logs, f"     Report: {report_name}", log_callback)
        _append_log(logs, f"     Time range: {range_text}", log_callback)
        return
    if _is_pending_status(normalized):
        if str(pending_detail_mode or "").strip().lower() == "dispatch_unconfirmed":
            _append_log(logs, f"  {prefix} Dispatch not yet confirmed; awaiting SID from Splunk.", log_callback)
            _append_log(
                logs,
                "     Splunk accepted the request path, but the SID has not been returned yet.",
                log_callback,
            )
            _append_log(
                logs,
                "     The original in-flight dispatch will continue to be checked.",
                log_callback,
            )
        elif str(pending_detail_mode or "").strip().lower() == "pending_reconcile":
            _append_log(logs, f"  {prefix} Pending reconciliation.", log_callback)
            _append_log(
                logs,
                "     A timeout left the final outcome uncertain, so the slice will be reconciled instead of redispatched blindly.",
                log_callback,
            )
        else:
            _append_log(logs, f"  {prefix} Report is still processing.", log_callback)
            _append_log(
                logs,
                "     Splunk may still be generating the report or preparing the email.",
                log_callback,
            )
            _append_log(
                logs,
                "     Please wait a moment and check your inbox shortly.",
                log_callback,
            )
        return
    _append_log(logs, f"  {prefix} Sending of email failed.", log_callback)
    _append_log(logs, "     Please contact the Splunk team for assistance.", log_callback)


def _client_identity_app(default_app: str) -> str:
    return str(default_app or "").strip()


def _mark_client_transport_tainted(client: SplunkClient, *, operation: str, reason: str) -> None:
    mark_broker_tainted = getattr(client, "_mark_broker_tainted", None)
    if callable(mark_broker_tainted):
        try:
            mark_broker_tainted(operation, reason)
        except Exception:
            pass


def _teardown_slice_execution_context(
    context: SliceExecutionContext,
    *,
    operation: str,
    reason: str,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    audit_event: Optional[Callable[..., None]] = None,
) -> None:
    context.mark_tainted(reason)
    _mark_client_transport_tainted(context.client, operation=operation, reason=reason)
    _record_transport_cleanup_activity(
        context.client,
        reason=reason,
        operation=operation,
        batch_id=context.batch_id,
        slice_id=context.slice_id,
        attempt_id=context.attempt_id,
    )
    if logs is not None:
        _append_log(
            logs,
            (
                f"[Debug] SLICE_EXECUTION_TAINTED execution_context_id={context.execution_context_id} "
                f"batch_id={context.batch_id} slice_id={context.slice_id} attempt_id={context.attempt_id} "
                f"slice_label={context.slice_label} correlation_tag={context.correlation_tag or '-'} "
                f"op={operation} reason={reason}"
            ),
            log_callback,
        )
    if callable(audit_event):
        audit_event(
            "SLICE_EXECUTION_TAINTED",
            level="WARN",
            slice_label=context.slice_label,
            slice_index=context.slice_index,
            slice_total=context.slice_total,
            batch_id=context.batch_id,
            slice_id=context.slice_id,
            attempt_id=context.attempt_id,
            correlation_tag=context.correlation_tag,
            execution_context_id=context.execution_context_id,
            operation=operation,
            reason=reason,
        )
    reset_transport = getattr(context.client, "reset_transport", None)
    close_transport = getattr(context.client, "close_transport", None)
    if callable(reset_transport):
        reset_transport()
    elif callable(close_transport):
        close_transport()
    if callable(audit_event):
        audit_event(
            "SLICE_EXECUTION_RECYCLED",
            level="INFO",
            slice_label=context.slice_label,
            slice_index=context.slice_index,
            slice_total=context.slice_total,
            batch_id=context.batch_id,
            slice_id=context.slice_id,
            attempt_id=context.attempt_id,
            correlation_tag=context.correlation_tag,
            execution_context_id=context.execution_context_id,
            operation=operation,
            reason=reason,
        )


def _find_reconcile_evidence(
    client: SplunkClient,
    *,
    context: SliceExecutionContext,
    identity: SavedSearchIdentity,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    audit_event: Optional[Callable[..., None]] = None,
    pass_name: str,
    prefer_merge_report_verification: bool = False,
    merge_report_log_path: str = "",
    merge_report_settings: Optional[dict[str, Any]] = None,
) -> SliceReconcileEvidence:
    if context.dispatch_correlation_id and not context.sid:
        harvest = _harvest_pending_dispatch_result(context.dispatch_correlation_id, wait_seconds=0.0)
        if harvest.state == "RETURNED" and harvest.ok and str(harvest.sid or "").strip():
            return SliceReconcileEvidence(
                confidence="strong",
                sid=str(harvest.sid or "").strip(),
                source="late_dispatch_result",
                detail=f"{pass_name}:late_sid_attached",
                matched_fields=["late_dispatch_result"],
                decision_reason="The original timed-out dispatch later returned a SID from the pending foreground request.",
            )

    find_candidates = getattr(client, "find_job_candidates", None)
    if not callable(find_candidates):
        return SliceReconcileEvidence()
    try:
        find_kwargs: dict[str, Any] = {"limit": 100}
        if _find_job_candidates_supports_keyword(find_candidates, "label"):
            find_kwargs["label"] = identity.name
        if _find_job_candidates_supports_keyword(find_candidates, "owner"):
            find_kwargs["owner"] = context.report_owner or identity.owner
        if _find_job_candidates_supports_keyword(find_candidates, "app"):
            find_kwargs["app"] = context.report_app or identity.app
        if _find_job_candidates_supports_keyword(find_candidates, "dispatch_earliest"):
            find_kwargs["dispatch_earliest"] = context.dispatch_earliest or ""
        if _find_job_candidates_supports_keyword(find_candidates, "dispatch_latest"):
            find_kwargs["dispatch_latest"] = context.dispatch_latest or ""
        if _find_job_candidates_supports_keyword(find_candidates, "correlation_tag"):
            find_kwargs["correlation_tag"] = context.correlation_tag or ""
        if _find_job_candidates_supports_keyword(find_candidates, "page_size"):
            find_kwargs["page_size"] = 25
        if _find_job_candidates_supports_keyword(find_candidates, "window_buffer_seconds"):
            find_kwargs["window_buffer_seconds"] = RECONCILIATION_WINDOW_BUFFER_SECONDS
        jobs = find_candidates(**find_kwargs)
    except Exception as exc:
        if callable(audit_event):
            audit_event(
                "REPORT_SLICE_RECONCILE_EVIDENCE_QUERY_FAILED",
                level="WARN",
                slice_label=context.slice_label,
                slice_index=context.slice_index,
                slice_total=context.slice_total,
                execution_context_id=context.execution_context_id,
                stage_name=pass_name,
                reason=_short_error(redact_text(str(exc) or repr(exc))),
            )
        return SliceReconcileEvidence()

    best = SliceReconcileEvidence()
    for candidate in jobs if isinstance(jobs, list) else []:
        if not isinstance(candidate, dict):
            continue
        evidence = _rank_job_candidate(
            candidate,
            identity=identity,
            dispatch_earliest=context.dispatch_earliest,
            dispatch_latest=context.dispatch_latest,
            correlation_tag=context.correlation_tag,
        )
        if evidence.confidence == "strong":
            if prefer_merge_report_verification and evidence.sid:
                merge_state, merge_payload = _check_merge_report_preferred_evidence(
                    client,
                    sid=evidence.sid,
                    prefer_merge_report_verification=prefer_merge_report_verification,
                    merge_report_log_path=merge_report_log_path,
                    merge_report_timeout_seconds=int(
                        (merge_report_settings or {}).get("timeout_seconds", DEFAULT_MERGEREPORT_TIMEOUT_SECONDS)
                    ),
                    merge_report_settings=merge_report_settings,
                    stage_name=f"{pass_name}_reconcile_evidence",
                    logs=logs,
                    log_callback=log_callback,
                    query_timeout_seconds=EVIDENCE_HTTP_READ_TIMEOUT_SECONDS,
                    saved_search_context={
                        "report_id_url": context.report_id_url,
                        "report_name": context.report_name,
                        "report_owner": context.report_owner or identity.owner,
                        "report_app": context.report_app or identity.app,
                    },
                )
                if merge_state == "SUCCESS":
                    merge_source = str(merge_payload.get("source", "merge_report") or "merge_report").strip()
                    evidence.source = f"search_jobs+merge_report_{merge_source}"
                    evidence.detail = f"{evidence.detail};merge_report_success"
            return evidence
        if evidence.confidence in {"weak", "conflict"} and best.confidence == "none":
            best = evidence
    return best


def _dispatch_saved_search_with_budget(
    client: SplunkClient,
    *,
    report_id_url: str,
    earliest: Optional[str],
    latest: Optional[str],
    timeout_seconds: int,
    trace_context: Optional[dict[str, Any]] = None,
) -> Tuple[str, bool, str, str, int]:
    dispatch_timeout = max(0.01, float(timeout_seconds))
    start = time.monotonic()
    started_utc = _utc_now_iso()
    result_queue: "queue.Queue[tuple[str, bool, str, str]]" = queue.Queue(maxsize=1)
    worker_name = f"dispatch-call-{uuid.uuid4().hex[:8]}"
    correlation_id = ""
    if isinstance(trace_context, dict):
        correlation_id = str(trace_context.get("correlation_id", "") or "").strip()

    def _worker() -> None:
        previous_trace_context = getattr(client, "_dispatch_trace_context", None)
        if trace_context:
            setattr(client, "_dispatch_trace_context", dict(trace_context))
        try:
            dispatch_fn = getattr(client, "dispatch_saved_search")
            kwargs: dict[str, Any] = {
                "earliest": earliest,
                "latest": latest,
            }
            if _dispatch_call_supports_keyword(dispatch_fn, "request_timeout_seconds"):
                kwargs["request_timeout_seconds"] = dispatch_timeout
            ok, sid, err = dispatch_fn(
                report_id_url,
                **kwargs,
            )
            result_queue.put(
                (
                    "RETURNED",
                    bool(ok),
                    str(sid or ""),
                    redact_text(str(err or "")),
                )
            )
        except Exception as exc:
            result_queue.put(
                (
                    "EXCEPTION",
                    False,
                    "",
                    redact_text(str(exc) or repr(exc)),
                )
            )
        finally:
            if previous_trace_context is None:
                try:
                    delattr(client, "_dispatch_trace_context")
                except Exception:
                    pass
            else:
                setattr(client, "_dispatch_trace_context", previous_trace_context)

    worker = threading.Thread(target=_worker, name=worker_name, daemon=True)
    worker.start()
    _register_pending_dispatch_attempt(
        correlation_id,
        result_queue=result_queue,
        worker_thread_name=worker.name,
        worker_thread_ident=worker.ident,
        report_name=str((trace_context or {}).get("report_name", "") or ""),
        slice_label=str((trace_context or {}).get("slice_label", "") or ""),
        slice_index=int((trace_context or {}).get("slice_index", 0) or 0),
        slice_total=int((trace_context or {}).get("slice_total", 0) or 0),
        earliest=str((trace_context or {}).get("earliest", earliest or "") or ""),
        latest=str((trace_context or {}).get("latest", latest or "") or ""),
        report_id_url=report_id_url,
        started_monotonic=start,
        started_utc=started_utc,
        timeout_seconds=int(dispatch_timeout),
        run_id=str((trace_context or {}).get("run_id", "") or ""),
    )
    setattr(
        client,
        "_last_dispatch_call_budget_meta",
        {
            "correlation_id": correlation_id,
            "worker_thread_name": worker.name,
            "worker_thread_ident": worker.ident,
            "timeout_seconds": dispatch_timeout,
            "started_utc": started_utc,
        },
    )
    try:
        dispatch_state, ok, sid, err = result_queue.get(timeout=dispatch_timeout)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        setattr(
            client,
            "_last_dispatch_call_budget_meta",
            {
                "correlation_id": correlation_id,
                "worker_thread_name": worker.name,
                "worker_thread_ident": worker.ident,
                "timeout_seconds": dispatch_timeout,
                "dispatch_state": dispatch_state,
                "elapsed_ms": elapsed_ms,
                "sid_present": bool(sid),
                "started_utc": started_utc,
            },
        )
        return dispatch_state, ok, sid, err, elapsed_ms
    except queue.Empty:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        setattr(
            client,
            "_last_dispatch_call_budget_meta",
            {
                "correlation_id": correlation_id,
                "worker_thread_name": worker.name,
                "worker_thread_ident": worker.ident,
                "timeout_seconds": dispatch_timeout,
                "dispatch_state": "TIMEOUT_NO_SID",
                "elapsed_ms": elapsed_ms,
                "sid_present": False,
                "started_utc": started_utc,
            },
        )
        return "TIMEOUT_NO_SID", False, "", "", elapsed_ms


def _snapshot_call_supports_keyword(snapshot_fn: Callable[..., Any], keyword: str) -> bool:
    try:
        signature = inspect.signature(snapshot_fn)
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == keyword:
            return True
    return False


def _dispatch_call_supports_keyword(dispatch_fn: Callable[..., Any], keyword: str) -> bool:
    try:
        signature = inspect.signature(dispatch_fn)
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == keyword:
            return True
    return False


def _find_job_candidates_supports_keyword(find_fn: Callable[..., Any], keyword: str) -> bool:
    try:
        signature = inspect.signature(find_fn)
    except (TypeError, ValueError):
        return False
    for parameter in signature.parameters.values():
        if parameter.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if parameter.name == keyword:
            return True
    return False


def _call_snapshot_with_retry(
    client: SplunkClient,
    sid: str,
    *,
    request_timeout_seconds: float,
    max_total_timeout_seconds: Optional[float],
    retry_count: int,
    stage_name: str,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    audit_event: Optional[Callable[..., None]] = None,
    slice_label: str = "",
    slice_index: int = 0,
    slice_total: int = 0,
    batch_id: str = "",
    slice_id: str = "",
    attempt_id: int = 0,
    correlation_tag: str = "",
) -> Tuple[str, dict]:
    snapshot_fn = getattr(client, "get_job_status_snapshot")
    kwargs: dict[str, Any] = {
        "request_timeout_seconds": request_timeout_seconds,
        "max_total_timeout_seconds": max_total_timeout_seconds,
    }
    if _snapshot_call_supports_keyword(snapshot_fn, "retry_count"):
        kwargs["retry_count"] = max(0, int(retry_count))
    if _snapshot_call_supports_keyword(snapshot_fn, "stage_name"):
        kwargs["stage_name"] = stage_name

    attempts = max(0, int(retry_count)) + 1
    last_exc: Optional[Exception] = None
    for attempt_index in range(1, attempts + 1):
        call_started_utc = _utc_now_iso()
        call_start = time.monotonic()
        _emit_broker_call_log(
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_event,
            event="BROKER_CALL_ENTER",
            op="get_job_status_snapshot",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            batch_id=batch_id,
            slice_id=slice_id,
            attempt_id=attempt_id,
            correlation_tag=correlation_tag,
            started_utc=call_started_utc,
            stage_name=stage_name,
            attempt=attempt_index,
        )
        try:
            state, content = snapshot_fn(sid, **kwargs)
            _emit_broker_call_log(
                logs=logs,
                log_callback=log_callback,
                audit_event=audit_event,
                event="BROKER_CALL_EXIT",
                op="get_job_status_snapshot",
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                batch_id=batch_id,
                slice_id=slice_id,
                attempt_id=attempt_id,
                correlation_tag=correlation_tag,
                started_utc=call_started_utc,
                ended_utc=_utc_now_iso(),
                elapsed_ms=int((time.monotonic() - call_start) * 1000),
                outcome=f"returned_{str(state or 'unknown').strip().lower()}",
                stage_name=stage_name,
                attempt=attempt_index,
            )
            return state, content
        except Exception as exc:
            last_exc = exc
            _emit_broker_call_log(
                logs=logs,
                log_callback=log_callback,
                audit_event=audit_event,
                event="BROKER_CALL_EXIT",
                op="get_job_status_snapshot",
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                batch_id=batch_id,
                slice_id=slice_id,
                attempt_id=attempt_id,
                correlation_tag=correlation_tag,
                started_utc=call_started_utc,
                ended_utc=_utc_now_iso(),
                elapsed_ms=int((time.monotonic() - call_start) * 1000),
                outcome="timeout" if _error_looks_like_timeout(str(exc) or repr(exc)) else "exception",
                stage_name=stage_name,
                attempt=attempt_index,
                error_detail=str(exc) or repr(exc),
            )
            meta = getattr(client, "_last_snapshot_meta", {})
            if not isinstance(meta, dict):
                meta = {}
            meta["retry_stage"] = stage_name
            meta["retry_attempt"] = attempt_index
            meta["retry_count"] = max(0, int(retry_count))
            meta["retryable_timeout"] = bool(_error_looks_like_timeout(str(exc) or repr(exc)))
            setattr(client, "_last_snapshot_meta", meta)
            if (attempt_index >= attempts) or (not _error_looks_like_timeout(str(exc) or repr(exc))):
                raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Snapshot retry loop exited unexpectedly.")


def _reset_slice_transport_state(
    logs: List[str],
    *,
    client: SplunkClient,
    report_name: str,
    slice_label: str,
    slice_index: int,
    slice_total: int,
    log_callback: Optional[Callable[[str], None]],
    audit_slice_event: Callable[..., None],
    force_transport_reset: bool = False,
    reason: str = "slice_transition",
) -> None:
    _append_log(
        logs,
        f"[Debug] SLICE_RESOURCES_RESET report_name={report_name} slice_label={slice_label}",
        log_callback,
    )
    audit_slice_event(
        "SLICE_RESOURCES_RESET",
        level="DEBUG",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
    )
    _append_log(
        logs,
        (
            f"[Debug] TRANSPORT_RESET_DECISION report_name={report_name} slice_label={slice_label} "
            f"reason={reason} force_transport_reset={bool(force_transport_reset)}"
        ),
        log_callback,
    )
    audit_slice_event(
        "TRANSPORT_RESET_DECISION",
        level="DEBUG",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        reason=reason,
        force_transport_reset=bool(force_transport_reset),
    )
    reset_actions: list[str] = []
    if hasattr(client, "_last_dispatch_meta"):
        try:
            client._last_dispatch_meta = {}
            reset_actions.append("last_dispatch_meta")
        except Exception:
            pass
    if hasattr(client, "_last_snapshot_meta"):
        try:
            client._last_snapshot_meta = {}
            reset_actions.append("last_snapshot_meta")
        except Exception:
            pass
    if hasattr(client, "_dispatch_context"):
        try:
            client._dispatch_context = {}
            reset_actions.append("dispatch_context")
        except Exception:
            pass
    reset_dispatch_context = getattr(client, "reset_dispatch_context", None)
    if callable(reset_dispatch_context):
        try:
            reset_dispatch_context()
            reset_actions.append("reset_dispatch_context")
        except Exception:
            reset_actions.append("reset_dispatch_context_failed")
    elif force_transport_reset:
        reset_actions.append("transport_reset_requested")

    if force_transport_reset:
        for method_name in ("reset_transport", "close_transport"):
            method = getattr(client, method_name, None)
            if callable(method):
                try:
                    method()
                    reset_actions.append(method_name)
                except Exception:
                    reset_actions.append(f"{method_name}_failed")
    elif any(callable(getattr(client, name, None)) for name in ("reset_transport", "close_transport")):
        reset_actions.append("transport_preserved")

    _append_log(
        logs,
        (
            f"[Debug] ACTIVE_BATCH_TRANSPORT_RESET report_name={report_name} slice_label={slice_label} "
            f"reason={reason} transport_reset_applied={bool(force_transport_reset)} "
            f"actions={','.join(reset_actions) or 'none'}"
        ),
        log_callback,
    )
    audit_slice_event(
        "ACTIVE_BATCH_TRANSPORT_RESET",
        level="DEBUG",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        reset_actions=",".join(reset_actions),
        reason=reason,
        transport_reset_applied=bool(force_transport_reset),
    )


def _verify_dispatched_slice(
    logs: List[str],
    *,
    client: SplunkClient,
    execution_context: SliceExecutionContext,
    report_name: str,
    sid: str,
    wait_seconds: int,
    poll_interval: int,
    timeout_status: str,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
    merge_report_timeout_seconds: int,
    merge_report_settings: Optional[dict[str, Any]],
    log_prefix: str,
    log_callback: Optional[Callable[[str], None]],
    record_slice: Callable[..., None],
    audit_slice_event: Callable[..., None],
) -> Tuple[str, str, str]:
    execution_context.sid = str(sid or "").strip()
    execution_context.mark_state(SLICE_STATE_DISPATCHED)
    record_slice(
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        status="PENDING",
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        sid=execution_context.sid,
        outcome_code="DISPATCHED",
        dispatch_correlation_id=execution_context.dispatch_correlation_id,
        dispatch_timeout_seconds=execution_context.dispatch_timeout_seconds,
        dispatch_report_id_url=execution_context.report_id_url,
        dispatch_earliest=execution_context.dispatch_earliest or "",
        dispatch_latest=execution_context.dispatch_latest or "",
        lifecycle_state=SLICE_STATE_DISPATCHED,
        state_reason="SID received; verification pending.",
        retry_count=execution_context.retry_count,
        execution_context_id=execution_context.execution_context_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_mode=execution_context.correlation_mode,
        report_owner=execution_context.report_owner,
        report_app=execution_context.report_app,
        verification_mode=execution_context.verification_mode,
        reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
        reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
        dispatch_outcome="SID_CONFIRMED",
        execution_outcome="RUNNING",
        evidence_outcome="NONE",
        business_outcome="RUNNING",
    )
    if prefer_merge_report_verification:
        verification_wait_seconds = max(1, int(merge_report_timeout_seconds or wait_seconds))
        _append_log(
            logs,
            (
                f"  {log_prefix}DISPATCHED (sid={sid}) - "
                f"awaiting MergeReport verification for up to {verification_wait_seconds}s..."
            ),
            log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_MERGEREPORT_WAIT_START",
            level="INFO",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
            wait_seconds=verification_wait_seconds,
            merge_report_log_path=merge_report_log_path,
        )
        merge_state, merge_detail, merge_source, merge_elapsed_ms = _wait_for_merge_report_preferred_evidence(
            client,
            sid=sid,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            merge_report_settings=merge_report_settings,
            wait_seconds=verification_wait_seconds,
            poll_interval=poll_interval,
            logs=logs,
            log_callback=log_callback,
            saved_search_context={
                "report_id_url": execution_context.report_id_url,
                "report_name": execution_context.report_name,
                "report_owner": execution_context.report_owner,
                "report_app": execution_context.report_app,
            },
        )
        audit_slice_event(
            "REPORT_SLICE_MERGEREPORT_WAIT_END",
            level="INFO" if merge_state == "SUCCESS" else "WARN",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
            result_state=merge_state,
            elapsed_ms=merge_elapsed_ms,
        )
        if merge_state == "SUCCESS":
            execution_context.mark_state(SLICE_STATE_SUCCESS)
            _append_user_slice_status(
                logs,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                report_name=report_name,
                earliest=execution_context.earliest_display,
                latest=execution_context.latest_display,
                status="OK",
                log_callback=log_callback,
            )
            audit_slice_event(
                "REPORT_SLICE_OK",
                slice_label=execution_context.slice_label,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                sid=sid,
                verification_source=f"merge_report_{merge_source or 'rest'}",
            )
            record_slice(
                slice_label=execution_context.slice_label,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                status="OK",
                earliest=execution_context.earliest_display,
                latest=execution_context.latest_display,
                sid=sid,
                outcome_code="SUCCESS_MERGEREPORT",
                dispatch_earliest=execution_context.dispatch_earliest or "",
                dispatch_latest=execution_context.dispatch_latest or "",
                lifecycle_state=SLICE_STATE_SUCCESS,
                retry_count=execution_context.retry_count,
                finalized_from_reconciliation=execution_context.finalized_from_reconciliation,
                reconciliation_source=execution_context.reconciliation_source,
                reconcile_pass_count=execution_context.reconcile_pass_count,
                reconciliation_confidence=execution_context.reconciliation_confidence,
                reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
                reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
                tainted=execution_context.tainted,
                taint_reason=execution_context.taint_reason,
                execution_context_id=execution_context.execution_context_id,
            )
            return "OK", sid, ""
        if merge_state == "FAILED":
            execution_context.mark_state(SLICE_STATE_FAILED_VERIFICATION)
            failure_detail = merge_detail or "MergeReport reported an explicit failure marker."
            _append_user_slice_status(
                logs,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                report_name=report_name,
                earliest=execution_context.earliest_display,
                latest=execution_context.latest_display,
                status="FAILED",
                log_callback=log_callback,
            )
            audit_slice_event(
                "REPORT_SLICE_FAILED",
                level="WARN",
                slice_label=execution_context.slice_label,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                sid=sid,
                reason=_short_error(failure_detail),
                error_phase="merge_report",
                verification_source=f"merge_report_{merge_source or 'rest'}",
            )
            record_slice(
                slice_label=execution_context.slice_label,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                status="FAILED",
                earliest=execution_context.earliest_display,
                latest=execution_context.latest_display,
                sid=sid,
                outcome_code="MERGEREPORT_FAILED",
                error=failure_detail,
                dispatch_earliest=execution_context.dispatch_earliest or "",
                dispatch_latest=execution_context.dispatch_latest or "",
                lifecycle_state=SLICE_STATE_FAILED_VERIFICATION,
                retry_count=execution_context.retry_count,
                finalized_from_reconciliation=execution_context.finalized_from_reconciliation,
                reconciliation_source=execution_context.reconciliation_source,
                reconcile_pass_count=execution_context.reconcile_pass_count,
                reconciliation_confidence=execution_context.reconciliation_confidence,
                reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
                reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
                tainted=execution_context.tainted,
                taint_reason=execution_context.taint_reason,
                execution_context_id=execution_context.execution_context_id,
            )
            return "FAILED", sid, ""

        fallback_detail = (
            "MergeReport verification source unavailable; falling back to native Splunk status verification."
            if merge_state == "UNAVAILABLE"
            else (
                f"MergeReport terminal evidence not found within {verification_wait_seconds} seconds. "
                "Falling back to native Splunk status verification."
            )
        )
        _append_log(logs, f"  {log_prefix}{fallback_detail}", log_callback)
        audit_slice_event(
            "REPORT_SLICE_MERGEREPORT_FALLBACK_NATIVE",
            level="INFO",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
            reason=_short_error(fallback_detail),
            error_phase="merge_report",
            verification_source=f"merge_report_{merge_source or 'rest'}",
        )

    execution_context.mark_state(SLICE_STATE_VERIFYING)
    record_slice(
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        status="PENDING",
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        sid=execution_context.sid,
        outcome_code="VERIFYING",
        dispatch_correlation_id=execution_context.dispatch_correlation_id,
        dispatch_timeout_seconds=execution_context.dispatch_timeout_seconds,
        dispatch_report_id_url=execution_context.report_id_url,
        dispatch_earliest=execution_context.dispatch_earliest or "",
        dispatch_latest=execution_context.dispatch_latest or "",
        lifecycle_state=SLICE_STATE_VERIFYING,
        state_reason="Verification in progress.",
        retry_count=execution_context.retry_count,
        execution_context_id=execution_context.execution_context_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_mode=execution_context.correlation_mode,
        report_owner=execution_context.report_owner,
        report_app=execution_context.report_app,
        verification_mode=execution_context.verification_mode,
        reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
        reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
        dispatch_outcome="SID_CONFIRMED",
        execution_outcome="RUNNING",
        evidence_outcome="PENDING",
        business_outcome="VERIFYING",
    )
    _append_log(
        logs,
        (
            f"  {log_prefix}DISPATCHED (sid={sid}) - "
            f"awaiting status verification for up to {wait_seconds}s..."
        ),
        log_callback,
    )

    status_check_start_utc = _utc_now_iso()
    status_check_start = time.monotonic()
    poll_count = 0
    audit_slice_event(
        "REPORT_SLICE_STATUS_CHECK_START",
        level="INFO",
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        sid=sid,
        outer_wait_seconds=max(1, int(wait_seconds)),
        poll_interval_seconds=max(1, int(poll_interval)),
        start_utc=status_check_start_utc,
    )

    def _poll_audit(**payload: object) -> None:
        nonlocal poll_count
        poll_count = int(payload.get("poll_count", poll_count))
        meta = getattr(client, "_last_snapshot_meta", {})
        if not isinstance(meta, dict):
            meta = {}
        audit_slice_event(
            "REPORT_SLICE_STATUS_CHECK_POLL",
            level="INFO",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
            poll_index=payload.get("poll_count"),
            poll_elapsed_ms=payload.get("poll_elapsed_ms"),
            request_timeout_seconds=payload.get("request_timeout_seconds"),
            remaining_seconds=payload.get("remaining_seconds"),
            state=payload.get("state"),
            broker_timeout_seconds=meta.get("broker_timeout_seconds"),
            broker_elapsed_ms=meta.get("broker_elapsed_ms"),
            splunk_elapsed_ms=meta.get("splunk_elapsed_ms"),
        )

    try:
        state, info, poll_count = _poll_job_status_with_budget(
            client,
            sid,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            poll_callback=_poll_audit,
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_slice_event,
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            batch_id=execution_context.batch_id,
            slice_id=execution_context.slice_id,
            attempt_id=execution_context.attempt_id,
            correlation_tag=execution_context.correlation_tag,
        )
    except Exception as exc:
        execution_context.mark_state(SLICE_STATE_PENDING_RECONCILE)
        raw_error = str(exc) or repr(exc)
        safe_error = redact_text(raw_error)
        err_msg = _build_pending_status_message(safe_error, wait_seconds=wait_seconds)
        error_type = type(exc).__name__
        broker_op, broker_timeout = _extract_broker_context(exc=exc, text=raw_error)
        status_check_end_utc = _utc_now_iso()
        status_elapsed_ms = int((time.monotonic() - status_check_start) * 1000)
        last_meta = getattr(client, "_last_snapshot_meta", {})
        if not isinstance(last_meta, dict):
            last_meta = {}
        audit_slice_event(
            "REPORT_SLICE_STATUS_CHECK_END",
            level="WARN",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
            result_state="EXCEPTION",
            error_type=error_type,
            outer_wait_seconds=max(1, int(wait_seconds)),
            poll_interval_seconds=max(1, int(poll_interval)),
            poll_count=poll_count,
            elapsed_ms=status_elapsed_ms,
            start_utc=status_check_start_utc,
            end_utc=status_check_end_utc,
            broker_timeout_seconds=broker_timeout
            if broker_timeout is not None
            else last_meta.get("broker_timeout_seconds"),
            request_timeout_seconds=last_meta.get("request_timeout_seconds"),
            broker_elapsed_ms=last_meta.get("broker_elapsed_ms"),
            splunk_elapsed_ms=last_meta.get("splunk_elapsed_ms"),
        )
        _append_log(logs, f"  {log_prefix}{_display_slice_status(timeout_status)} (sid={sid}) - {err_msg}", log_callback)
        if _error_looks_like_timeout(raw_error):
            _teardown_slice_execution_context(
                execution_context,
                operation=broker_op or "get_job_status_snapshot",
                reason="snapshot_timeout_uncertain",
                logs=logs,
                log_callback=log_callback,
                audit_event=audit_slice_event,
            )
        audit_slice_event(
            "REPORT_SLICE_MARKED_PENDING",
            level="WARN",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
            reason=_short_error(err_msg),
            error_phase="status_check",
        )
        record_slice(
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            status=timeout_status,
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            sid=sid,
            outcome_code="PENDING_RECONCILE",
            error=err_msg,
            dispatch_earliest=execution_context.dispatch_earliest or "",
            dispatch_latest=execution_context.dispatch_latest or "",
            lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
            state_reason=err_msg,
            retry_count=execution_context.retry_count,
            finalized_from_reconciliation=execution_context.finalized_from_reconciliation,
            reconciliation_source=execution_context.reconciliation_source,
            reconcile_pass_count=execution_context.reconcile_pass_count,
            reconciliation_confidence=execution_context.reconciliation_confidence,
            reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
            reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
            pending_since_utc=_utc_now_iso(),
            tainted=execution_context.tainted,
            taint_reason=execution_context.taint_reason,
            execution_context_id=execution_context.execution_context_id,
        )
        return timeout_status, sid, ""

    status_check_end_utc = _utc_now_iso()
    status_elapsed_ms = int((time.monotonic() - status_check_start) * 1000)
    last_meta = getattr(client, "_last_snapshot_meta", {})
    if not isinstance(last_meta, dict):
        last_meta = {}
    audit_slice_event(
        "REPORT_SLICE_STATUS_CHECK_END",
        level="INFO",
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        sid=sid,
        result_state=state,
        outer_wait_seconds=max(1, int(wait_seconds)),
        poll_interval_seconds=max(1, int(poll_interval)),
        poll_count=poll_count,
        elapsed_ms=status_elapsed_ms,
        start_utc=status_check_start_utc,
        end_utc=status_check_end_utc,
        broker_timeout_seconds=last_meta.get("broker_timeout_seconds"),
        request_timeout_seconds=last_meta.get("request_timeout_seconds"),
        broker_elapsed_ms=last_meta.get("broker_elapsed_ms"),
        splunk_elapsed_ms=last_meta.get("splunk_elapsed_ms"),
    )

    if state == "SUCCESS":
        execution_context.mark_state(SLICE_STATE_SUCCESS)
        _append_user_slice_status(
            logs,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            report_name=report_name,
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            status="OK",
            log_callback=log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_OK",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
        )
        record_slice(
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            status="OK",
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            sid=sid,
            outcome_code="SUCCESS" if not execution_context.finalized_from_reconciliation else "RECONCILED_SUCCESS",
            dispatch_earliest=execution_context.dispatch_earliest or "",
            dispatch_latest=execution_context.dispatch_latest or "",
            lifecycle_state=SLICE_STATE_SUCCESS,
            retry_count=execution_context.retry_count,
            finalized_from_reconciliation=execution_context.finalized_from_reconciliation,
            reconciliation_source=execution_context.reconciliation_source,
            reconcile_pass_count=execution_context.reconcile_pass_count,
            reconciliation_confidence=execution_context.reconciliation_confidence,
            reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
            reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
            tainted=execution_context.tainted,
            taint_reason=execution_context.taint_reason,
            execution_context_id=execution_context.execution_context_id,
        )
        return "OK", sid, ""

    if state == "FAILED":
        execution_context.mark_state(SLICE_STATE_FAILED_VERIFICATION)
        dispatch_state = str(info.get("dispatchState", "Unknown error") or "Unknown error")
        _append_user_slice_status(
            logs,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            report_name=report_name,
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            status="FAILED",
            log_callback=log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_FAILED",
            level="WARN",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            sid=sid,
            reason=_short_error(dispatch_state),
            error_phase="status_check",
        )
        record_slice(
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            status="FAILED",
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            sid=sid,
            outcome_code="VERIFIED_FAILED",
            error=dispatch_state,
            dispatch_earliest=execution_context.dispatch_earliest or "",
            dispatch_latest=execution_context.dispatch_latest or "",
            lifecycle_state=SLICE_STATE_FAILED_VERIFICATION,
            retry_count=execution_context.retry_count,
            finalized_from_reconciliation=execution_context.finalized_from_reconciliation,
            reconciliation_source=execution_context.reconciliation_source,
            reconcile_pass_count=execution_context.reconcile_pass_count,
            reconciliation_confidence=execution_context.reconciliation_confidence,
            reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
            reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
            tainted=execution_context.tainted,
            taint_reason=execution_context.taint_reason,
            execution_context_id=execution_context.execution_context_id,
        )
        return "FAILED", sid, ""

    execution_context.mark_state(SLICE_STATE_PENDING_RECONCILE)
    last_dispatch_state = str(info.get("dispatchState", "")).strip()
    timeout_detail = f"Status not confirmed within {wait_seconds} seconds."
    if last_dispatch_state:
        timeout_detail += f" Last dispatchState={last_dispatch_state}."
    err_msg = _build_pending_status_message(timeout_detail, wait_seconds=wait_seconds)
    _append_user_slice_status(
        logs,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        report_name=report_name,
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        status=timeout_status,
        log_callback=log_callback,
    )
    audit_slice_event(
        "REPORT_SLICE_ACTIVE_WAIT_EXPIRED",
        level="WARN",
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        sid=sid,
        reason=_short_error(timeout_detail),
        error_phase="status_check",
    )
    record_slice(
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        status=timeout_status,
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        sid=sid,
        outcome_code="PENDING_RECONCILE",
        error=err_msg,
        dispatch_earliest=execution_context.dispatch_earliest or "",
        dispatch_latest=execution_context.dispatch_latest or "",
        lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
        state_reason=err_msg,
        retry_count=execution_context.retry_count,
        finalized_from_reconciliation=execution_context.finalized_from_reconciliation,
        reconciliation_source=execution_context.reconciliation_source,
        reconcile_pass_count=execution_context.reconcile_pass_count,
        reconciliation_confidence=execution_context.reconciliation_confidence,
        pending_since_utc=_utc_now_iso(),
        tainted=execution_context.tainted,
        taint_reason=execution_context.taint_reason,
        execution_context_id=execution_context.execution_context_id,
    )
    return timeout_status, sid, ""


def _resolve_uncertain_dispatch_timeout(
    logs: List[str],
    *,
    client: SplunkClient,
    execution_context: SliceExecutionContext,
    report_name: str,
    wait_seconds: int,
    poll_interval: int,
    timeout_status: str,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
    merge_report_timeout_seconds: int,
    merge_report_settings: Optional[dict[str, Any]],
    log_prefix: str,
    log_callback: Optional[Callable[[str], None]],
    sid_callback: Optional[Callable[[str, str], None]],
    record_slice: Callable[..., None],
    audit_slice_event: Callable[..., None],
    timeout_classification: str = "",
    business_effect_guard: Optional[Callable[[SliceExecutionContext], bool]] = None,
) -> Tuple[str, str, str]:
    execution_context.mark_state(SLICE_STATE_TIMEOUT_UNCERTAIN)
    _teardown_slice_execution_context(
        execution_context,
        operation="dispatch_saved_search",
        reason=str(timeout_classification or "dispatch_timeout_uncertain"),
        logs=logs,
        log_callback=log_callback,
        audit_event=audit_slice_event,
    )
    _append_log(
        logs,
        (
            f"[Debug] TRANSIENT_DISPATCH_TIMEOUT_CAPTURED batch_id={execution_context.batch_id} "
            f"slice_id={execution_context.slice_id} attempt_id={execution_context.attempt_id} "
            f"classification={timeout_classification or 'dispatch_timeout_no_sid_unknown'} "
            f"execution_context_id={execution_context.execution_context_id}"
        ),
        log_callback,
    )
    _append_log(
        logs,
        "Temporary dispatch uncertainty detected. Verifying status...",
        log_callback,
    )
    timeout_detail = "Dispatch timed out before SID confirmation; reconciliation started."
    if timeout_classification:
        timeout_detail += f" classification={timeout_classification}."
    record_slice(
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        status="PENDING",
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        sid="",
        outcome_code="TIMEOUT_UNCERTAIN",
        error=timeout_detail,
        dispatch_correlation_id=execution_context.dispatch_correlation_id,
        dispatch_started_utc=_utc_now_iso(),
        dispatch_timeout_seconds=execution_context.dispatch_timeout_seconds,
        dispatch_report_id_url=execution_context.report_id_url,
        dispatch_earliest=execution_context.dispatch_earliest or "",
        dispatch_latest=execution_context.dispatch_latest or "",
        lifecycle_state=SLICE_STATE_TIMEOUT_UNCERTAIN,
        state_reason=timeout_detail,
        retry_count=execution_context.retry_count,
        reconcile_pass_count=execution_context.reconcile_pass_count,
        tainted=execution_context.tainted,
        taint_reason=execution_context.taint_reason,
        execution_context_id=execution_context.execution_context_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_mode=execution_context.correlation_mode,
        report_owner=execution_context.report_owner,
        report_app=execution_context.report_app,
        verification_mode=execution_context.verification_mode,
        reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
        reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
        dispatch_outcome="TIMEOUT_UNCERTAIN",
        execution_outcome="UNKNOWN",
        evidence_outcome="NONE",
        business_outcome="PENDING_RECONCILE",
    )
    identity = _parse_saved_search_identity(
        execution_context.report_id_url,
        report_name,
        default_app=execution_context.report_app,
        default_owner=execution_context.report_owner or str(getattr(client, "username", "") or "").strip(),
    )
    pending_detail_mode = "dispatch_unconfirmed"
    for pass_index in (1, 2):
        execution_context.reconcile_pass_count = pass_index
        pass_name = f"dispatch_timeout_reconcile_pass{pass_index}"
        audit_slice_event(
            "REPORT_SLICE_RECONCILE_PASS_START",
            level="INFO",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            execution_context_id=execution_context.execution_context_id,
            stage_name=pass_name,
            retry_count=execution_context.retry_count,
        )
        evidence = _find_reconcile_evidence(
            client,
            context=execution_context,
            identity=identity,
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_slice_event,
            pass_name=pass_name,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_settings=merge_report_settings,
        )
        audit_slice_event(
            "REPORT_SLICE_RECONCILE_PASS_END",
            level="INFO" if evidence.confidence == "strong" else "WARN",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            execution_context_id=execution_context.execution_context_id,
            stage_name=pass_name,
            evidence_confidence=evidence.confidence,
            evidence_source=evidence.source,
            sid=evidence.sid or None,
            detail=evidence.detail or None,
        )
        if evidence.confidence == "strong" and evidence.sid:
            execution_context.sid = evidence.sid
            execution_context.reconciliation_source = evidence.source
            execution_context.reconciliation_confidence = evidence.confidence
            execution_context.reconciliation_matched_fields = _matched_fields_text(evidence.matched_fields)
            execution_context.reconciliation_decision_reason = (
                str(evidence.decision_reason or evidence.detail or "").strip()
            )
            execution_context.finalized_from_reconciliation = True
            _emit_reconciliation_decision(
                logs=logs,
                log_callback=log_callback,
                audit_event=audit_slice_event,
                context=execution_context,
                pass_name=pass_name,
                evidence=evidence,
                decision="finalize_from_reconciliation",
            )
            if execution_context.dispatch_correlation_id:
                _clear_pending_dispatch_attempt(execution_context.dispatch_correlation_id)
            if sid_callback:
                sid_callback(evidence.sid, report_name)
            return _verify_dispatched_slice(
                logs,
                client=client,
                execution_context=execution_context,
                report_name=report_name,
                sid=evidence.sid,
                wait_seconds=wait_seconds,
                poll_interval=poll_interval,
                timeout_status=timeout_status,
                prefer_merge_report_verification=prefer_merge_report_verification,
                merge_report_log_path=merge_report_log_path,
                merge_report_timeout_seconds=merge_report_timeout_seconds,
                merge_report_settings=merge_report_settings,
                log_prefix=log_prefix,
                log_callback=log_callback,
                record_slice=record_slice,
                audit_slice_event=audit_slice_event,
            )
        if evidence.confidence in {"weak", "conflict"}:
            err_msg = (
                "Reconciliation found possible matching job evidence, so the slice will not be redispatched "
                "without stronger confirmation."
            )
            execution_context.mark_state(SLICE_STATE_PENDING_RECONCILE)
            execution_context.reconciliation_source = evidence.source or "search_jobs"
            execution_context.reconciliation_confidence = evidence.confidence
            execution_context.reconciliation_matched_fields = _matched_fields_text(evidence.matched_fields)
            execution_context.reconciliation_decision_reason = (
                str(evidence.decision_reason or evidence.detail or "").strip()
            )
            _emit_reconciliation_decision(
                logs=logs,
                log_callback=log_callback,
                audit_event=audit_slice_event,
                context=execution_context,
                pass_name=pass_name,
                evidence=evidence,
                decision="pending_reconcile_retry_suppressed",
            )
            record_slice(
                slice_label=execution_context.slice_label,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                status="PENDING",
                earliest=execution_context.earliest_display,
                latest=execution_context.latest_display,
                sid=evidence.sid,
                outcome_code="PENDING_RECONCILE_EVIDENCE",
                error=err_msg,
                dispatch_correlation_id=execution_context.dispatch_correlation_id,
                dispatch_timeout_seconds=execution_context.dispatch_timeout_seconds,
                dispatch_report_id_url=execution_context.report_id_url,
                dispatch_earliest=execution_context.dispatch_earliest or "",
                dispatch_latest=execution_context.dispatch_latest or "",
                lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
                state_reason=err_msg,
                retry_count=execution_context.retry_count,
                finalized_from_reconciliation=False,
                reconciliation_source=evidence.source or "search_jobs",
                reconcile_pass_count=execution_context.reconcile_pass_count,
                pending_since_utc=_utc_now_iso(),
                tainted=execution_context.tainted,
                taint_reason=execution_context.taint_reason,
                execution_context_id=execution_context.execution_context_id,
                batch_id=execution_context.batch_id,
                slice_id=execution_context.slice_id,
                attempt_id=execution_context.attempt_id,
                correlation_tag=execution_context.correlation_tag,
                reconciliation_confidence=evidence.confidence,
                reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
                reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
                dispatch_outcome="TIMEOUT_UNCERTAIN",
                execution_outcome="UNKNOWN",
                evidence_outcome="AMBIGUOUS",
                business_outcome="PENDING_RECONCILE",
            )
            _append_user_slice_status(
                logs,
                slice_index=execution_context.slice_index,
                slice_total=execution_context.slice_total,
                report_name=report_name,
                earliest=execution_context.earliest_display,
                latest=execution_context.latest_display,
                status="PENDING",
                pending_detail_mode="pending_reconcile",
                log_callback=log_callback,
            )
            return "PENDING", evidence.sid, pending_detail_mode
        if pass_index == 1:
            _append_log(
                logs,
                f"  {log_prefix}No dispatch evidence found in reconcile pass 1; waiting {RECONCILE_PASS2_WAIT_SECONDS}s before pass 2.",
                log_callback,
            )
            time.sleep(RECONCILE_PASS2_WAIT_SECONDS)

    if callable(business_effect_guard) and business_effect_guard(execution_context):
        err_msg = (
            "Retry suppressed because the current batch journal already records a completed business outcome "
            "for this frozen slice window."
        )
        execution_context.mark_state(SLICE_STATE_PENDING_RECONCILE)
        execution_context.reconciliation_decision_reason = err_msg
        evidence = SliceReconcileEvidence(
            confidence="none",
            source="batch_journal",
            decision_reason=err_msg,
        )
        _emit_reconciliation_decision(
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_slice_event,
            context=execution_context,
            pass_name="dispatch_timeout_retry_suppressed",
            evidence=evidence,
            decision="retry_suppressed_business_effect",
        )
        record_slice(
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            status="PENDING",
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            sid="",
            outcome_code="TIMEOUT_UNCERTAIN_PENDING_RECONCILE",
            error=err_msg,
            dispatch_correlation_id=execution_context.dispatch_correlation_id,
            dispatch_started_utc=_utc_now_iso(),
            dispatch_timeout_seconds=execution_context.dispatch_timeout_seconds,
            dispatch_report_id_url=execution_context.report_id_url,
            dispatch_earliest=execution_context.dispatch_earliest or "",
            dispatch_latest=execution_context.dispatch_latest or "",
            lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
            state_reason=err_msg,
            retry_count=execution_context.retry_count,
            reconcile_pass_count=execution_context.reconcile_pass_count,
            pending_since_utc=_utc_now_iso(),
            tainted=execution_context.tainted,
            taint_reason=execution_context.taint_reason,
            execution_context_id=execution_context.execution_context_id,
            batch_id=execution_context.batch_id,
            slice_id=execution_context.slice_id,
            attempt_id=execution_context.attempt_id,
            correlation_tag=execution_context.correlation_tag,
            correlation_mode=execution_context.correlation_mode,
            report_owner=execution_context.report_owner,
            report_app=execution_context.report_app,
            verification_mode=execution_context.verification_mode,
            reconciliation_confidence="none",
            reconciliation_matched_fields="",
            reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
            dispatch_outcome="TIMEOUT_UNCERTAIN",
            execution_outcome="UNKNOWN",
            evidence_outcome="NONE",
            business_outcome="SUCCESS_ALREADY_RECORDED",
        )
        _append_user_slice_status(
            logs,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            report_name=report_name,
            earliest=execution_context.earliest_display,
            latest=execution_context.latest_display,
            status="PENDING",
            pending_detail_mode="pending_reconcile",
            log_callback=log_callback,
        )
        return "PENDING", "", "pending_reconcile"

    if execution_context.retry_count < MAX_RETRY_ATTEMPTS_PER_SLICE:
        evidence = SliceReconcileEvidence(
            confidence="none",
            source="search_jobs",
            decision_reason=(
                "No reconciliation evidence was found after two passes, so one clean retry is allowed "
                "in a fresh execution context."
            ),
        )
        _emit_reconciliation_decision(
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_slice_event,
            context=execution_context,
            pass_name="dispatch_timeout_retry",
            evidence=evidence,
            decision="retry_after_no_evidence",
        )
        _append_log(
            logs,
            f"  {log_prefix}No dispatch evidence found after two reconciliation passes; retrying once in a fresh context after {RETRY_BACKOFF_SECONDS}s.",
            log_callback,
        )
        _append_log(
            logs,
            "Retrying slice in a fresh execution context...",
            log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_RETRY_SCHEDULED",
            level="WARN",
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            retry_count=execution_context.retry_count + 1,
            execution_context_id=execution_context.execution_context_id,
        )
        time.sleep(RETRY_BACKOFF_SECONDS)
        return _dispatch_slice_and_wait(
            logs,
            client=client,
            batch_id=execution_context.batch_id,
            slice_id=execution_context.slice_id,
            report_id_url=execution_context.report_id_url,
            report_name=report_name,
            slice_label=execution_context.slice_label,
            slice_index=execution_context.slice_index,
            slice_total=execution_context.slice_total,
            earliest_display=execution_context.earliest_display,
            latest_display=execution_context.latest_display,
            dispatch_earliest=execution_context.dispatch_earliest,
            dispatch_latest=execution_context.dispatch_latest,
            run_id=execution_context.run_id,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            dispatch_call_timeout_seconds=execution_context.dispatch_timeout_seconds,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            merge_report_settings=merge_report_settings,
            log_prefix=log_prefix,
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=record_slice,
            audit_slice_event=audit_slice_event,
            retry_count=execution_context.retry_count + 1,
            correlation_tag=_build_correlation_tag(
                execution_context.batch_id,
                execution_context.slice_id,
                execution_context.retry_count + 2,
            ),
            correlation_mode=execution_context.correlation_mode,
            report_owner=execution_context.report_owner,
            report_app=execution_context.report_app,
            verification_mode=execution_context.verification_mode,
            business_effect_guard=business_effect_guard,
        )

    err_msg = (
        "Dispatch outcome remains uncertain after two reconciliation passes and the allowed retry budget is exhausted."
    )
    execution_context.mark_state(SLICE_STATE_PENDING_RECONCILE)
    execution_context.reconciliation_decision_reason = err_msg
    _emit_reconciliation_decision(
        logs=logs,
        log_callback=log_callback,
        audit_event=audit_slice_event,
        context=execution_context,
        pass_name="dispatch_timeout_retry_exhausted",
        evidence=SliceReconcileEvidence(
            confidence="none",
            source="search_jobs",
            decision_reason=err_msg,
        ),
        decision="pending_reconcile_retry_exhausted",
    )
    record_slice(
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        status=timeout_status,
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        sid="",
        outcome_code="TIMEOUT_UNCERTAIN_PENDING_RECONCILE",
        error=err_msg,
        dispatch_correlation_id=execution_context.dispatch_correlation_id,
        dispatch_started_utc=_utc_now_iso(),
        dispatch_timeout_seconds=execution_context.dispatch_timeout_seconds,
        dispatch_report_id_url=execution_context.report_id_url,
        dispatch_earliest=execution_context.dispatch_earliest or "",
        dispatch_latest=execution_context.dispatch_latest or "",
        lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
        state_reason=err_msg,
        retry_count=execution_context.retry_count,
        retry_exhausted=True,
        reconcile_pass_count=execution_context.reconcile_pass_count,
        pending_since_utc=_utc_now_iso(),
        tainted=execution_context.tainted,
        taint_reason=execution_context.taint_reason,
        execution_context_id=execution_context.execution_context_id,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        reconciliation_confidence="none",
        reconciliation_matched_fields=execution_context.reconciliation_matched_fields,
        reconciliation_decision_reason=execution_context.reconciliation_decision_reason,
        dispatch_outcome="TIMEOUT_UNCERTAIN",
        execution_outcome="UNKNOWN",
        evidence_outcome="PENDING",
        business_outcome="PENDING_RECONCILE",
    )
    _append_user_slice_status(
        logs,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        report_name=report_name,
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        status=timeout_status,
        pending_detail_mode=pending_detail_mode,
        log_callback=log_callback,
    )
    return timeout_status, "", pending_detail_mode


def _dispatch_slice_and_wait(
    logs: List[str],
    *,
    client: SplunkClient,
    batch_id: str,
    slice_id: str,
    report_id_url: str,
    report_name: str,
    slice_label: str,
    slice_index: int = 0,
    slice_total: int = 0,
    earliest_display: str,
    latest_display: str,
    dispatch_earliest: Optional[str],
    dispatch_latest: Optional[str],
    run_id: str,
    wait_seconds: int,
    poll_interval: int,
    timeout_status: str,
    dispatch_call_timeout_seconds: int,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
    merge_report_timeout_seconds: int,
    merge_report_settings: Optional[dict[str, Any]],
    log_prefix: str,
    log_callback: Optional[Callable[[str], None]],
    sid_callback: Optional[Callable[[str, str], None]],
    record_slice: Callable[..., None],
    audit_slice_event: Callable[..., None],
    retry_count: int = 0,
    correlation_tag: str = "",
    correlation_mode: str = "tool_local_only",
    report_owner: str = "",
    report_app: str = "",
    verification_mode: str = "",
    business_effect_guard: Optional[Callable[[SliceExecutionContext], bool]] = None,
) -> Tuple[str, str, str]:
    slice_index = max(0, int(slice_index or 0))
    slice_total = max(0, int(slice_total or 0))
    dispatch_call_timeout_seconds = max(1, int(dispatch_call_timeout_seconds or 0))
    attempt_id = max(1, int(retry_count or 0) + 1)
    execution_context = SliceExecutionContext(
        client=client,
        run_id=str(run_id or "").strip(),
        batch_id=str(batch_id or "").strip(),
        slice_id=str(slice_id or "").strip(),
        attempt_id=attempt_id,
        report_id_url=report_id_url,
        report_name=report_name,
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        earliest_display=earliest_display,
        latest_display=latest_display,
        dispatch_earliest=dispatch_earliest,
        dispatch_latest=dispatch_latest,
        dispatch_timeout_seconds=dispatch_call_timeout_seconds,
        snapshot_timeout_seconds=SNAPSHOT_TIMEOUT_SECONDS,
        retry_count=max(0, int(retry_count or 0)),
        correlation_tag=str(correlation_tag or "").strip() or _build_correlation_tag(batch_id, slice_id, attempt_id),
        correlation_mode=str(correlation_mode or "tool_local_only").strip() or "tool_local_only",
        report_owner=str(report_owner or "").strip(),
        report_app=str(report_app or "").strip(),
        verification_mode=str(verification_mode or "").strip(),
    )
    dispatch_call_id = uuid.uuid4().hex[:12]
    execution_context.dispatch_correlation_id = dispatch_call_id
    dispatch_transport_mode = (
        "broker_proxy"
        if client.__class__.__name__ == "SplunkBrokerProxyClient"
        else "direct_client"
    )
    dispatch_trace_context = {
        "run_id": str(run_id or "").strip(),
        "report_name": report_name,
        "slice_label": slice_label,
        "slice_index": slice_index,
        "slice_total": slice_total,
        "batch_id": execution_context.batch_id,
        "slice_id": execution_context.slice_id,
        "attempt_id": execution_context.attempt_id,
        "correlation_tag": execution_context.correlation_tag,
        "correlation_mode": execution_context.correlation_mode,
        "correlation_id": dispatch_call_id,
        "earliest": earliest_display,
        "latest": latest_display,
        "report_owner": execution_context.report_owner,
        "report_app": execution_context.report_app,
        "verification_mode": execution_context.verification_mode,
        "transport_mode": dispatch_transport_mode,
        "thread_name": threading.current_thread().name,
    }
    dispatch_call_started_utc = _utc_now_iso()
    audit_slice_event(
        "SLICE_DISPATCH_ENGINE_START",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_id=dispatch_call_id,
        earliest=earliest_display,
        latest=latest_display,
        transport_mode=dispatch_transport_mode,
        thread_name=threading.current_thread().name,
    )
    _emit_broker_call_log(
        logs=logs,
        log_callback=log_callback,
        audit_event=audit_slice_event,
        event="BROKER_CALL_ENTER",
        op="dispatch_saved_search",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        started_utc=dispatch_call_started_utc,
    )
    audit_slice_event(
        "ENGINE_BROKER_CALL_ENTER",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_id=dispatch_call_id,
        dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        earliest=earliest_display,
        latest=latest_display,
        transport_mode=dispatch_transport_mode,
        thread_name=threading.current_thread().name,
        thread_ident=threading.get_ident(),
    )
    audit_slice_event(
        "SLICE_DISPATCH_ENGINE_CALL_BROKER",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_id=dispatch_call_id,
        earliest=earliest_display,
        latest=latest_display,
        transport_mode=dispatch_transport_mode,
        thread_name=threading.current_thread().name,
    )
    execution_context.mark_state(SLICE_STATE_DISPATCHING)
    record_slice(
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        slice_label=execution_context.slice_label,
        slice_index=execution_context.slice_index,
        slice_total=execution_context.slice_total,
        status="PENDING",
        earliest=execution_context.earliest_display,
        latest=execution_context.latest_display,
        sid="",
        outcome_code="DISPATCHING",
        dispatch_correlation_id=dispatch_call_id,
        dispatch_started_utc=dispatch_call_started_utc,
        dispatch_timeout_seconds=execution_context.dispatch_timeout_seconds,
        dispatch_report_id_url=execution_context.report_id_url,
        dispatch_earliest=execution_context.dispatch_earliest or "",
        dispatch_latest=execution_context.dispatch_latest or "",
        lifecycle_state=SLICE_STATE_DISPATCHING,
        state_reason="Dispatch in progress.",
        retry_count=execution_context.retry_count,
        execution_context_id=execution_context.execution_context_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_mode=execution_context.correlation_mode,
        report_owner=execution_context.report_owner,
        report_app=execution_context.report_app,
        verification_mode=execution_context.verification_mode,
        dispatch_outcome="IN_FLIGHT",
        execution_outcome="UNKNOWN",
        evidence_outcome="NONE",
        business_outcome="RUNNING",
    )
    dispatch_state, ok, sid, err, dispatch_elapsed_ms = _dispatch_saved_search_with_budget(
        client,
        report_id_url=report_id_url,
        earliest=dispatch_earliest,
        latest=dispatch_latest,
        timeout_seconds=dispatch_call_timeout_seconds,
        trace_context=dispatch_trace_context,
    )
    dispatch_call_meta = getattr(client, "_last_dispatch_call_budget_meta", {})
    if not isinstance(dispatch_call_meta, dict):
        dispatch_call_meta = {}
    dispatch_runtime_meta = getattr(client, "_last_dispatch_meta", {})
    if isinstance(dispatch_runtime_meta, dict):
        execution_context.correlation_mode = str(
            dispatch_runtime_meta.get("correlation_mode", execution_context.correlation_mode) or execution_context.correlation_mode
        ).strip() or execution_context.correlation_mode
    pending_detail_mode = ""

    def _clear_registered_dispatch() -> None:
        _clear_pending_dispatch_attempt(dispatch_call_id)
    dispatch_outcome = "returned"
    if dispatch_state == "TIMEOUT_NO_SID":
        dispatch_outcome = "timeout_no_sid"
    elif dispatch_state == "EXCEPTION":
        dispatch_outcome = "exception"
    elif not ok:
        dispatch_outcome = "failed"
    elif not sid:
        dispatch_outcome = "returned_no_sid"
    elif ok and sid:
        dispatch_outcome = "success"
    dispatch_attempt_diag = _build_dispatch_attempt_diagnostics(
        client=client,
        execution_context=execution_context,
        dispatch_state=dispatch_state,
        dispatch_elapsed_ms=dispatch_elapsed_ms,
        dispatch_call_meta=dispatch_call_meta,
        dispatch_runtime_meta=dispatch_runtime_meta if isinstance(dispatch_runtime_meta, dict) else {},
        dispatch_outcome=dispatch_outcome,
    )
    timeout_no_sid_classification = (
        _classify_dispatch_timeout_no_sid(dispatch_attempt_diag)
        if dispatch_state == "TIMEOUT_NO_SID"
        else ""
    )
    previous_dispatch_diag = _get_previous_dispatch_attempt_diagnostics(
        client,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
    )
    _emit_dispatch_attempt_diagnostics(
        logs=logs,
        log_callback=log_callback,
        audit_event=audit_slice_event,
        execution_context=execution_context,
        diag=dispatch_attempt_diag,
        classification=timeout_no_sid_classification,
    )
    if execution_context.attempt_id > 1 and previous_dispatch_diag:
        _emit_dispatch_attempt_comparison(
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_slice_event,
            execution_context=execution_context,
            previous_diag=previous_dispatch_diag,
            current_diag=dispatch_attempt_diag,
        )
    _remember_dispatch_attempt_diagnostics(
        client,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        diag=dispatch_attempt_diag,
    )
    _emit_broker_call_log(
        logs=logs,
        log_callback=log_callback,
        audit_event=audit_slice_event,
        event="BROKER_CALL_EXIT",
        op="dispatch_saved_search",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        started_utc=dispatch_call_started_utc,
        ended_utc=_utc_now_iso(),
        elapsed_ms=dispatch_elapsed_ms,
        outcome=dispatch_outcome,
        error_detail=err,
    )
    audit_slice_event(
        "ENGINE_BROKER_CALL_EXIT",
        level="INFO",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_id=dispatch_call_id,
        dispatch_call_state=dispatch_state,
        dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        elapsed_ms=dispatch_elapsed_ms,
        sid_present=bool(sid),
        transport_mode=dispatch_transport_mode,
        worker_thread_name=dispatch_call_meta.get("worker_thread_name"),
        worker_thread_ident=dispatch_call_meta.get("worker_thread_ident"),
    )
    audit_slice_event(
        "SLICE_DISPATCH_ENGINE_RETURN",
        level="INFO" if dispatch_state == "RETURNED" else "WARN",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        batch_id=execution_context.batch_id,
        slice_id=execution_context.slice_id,
        attempt_id=execution_context.attempt_id,
        correlation_tag=execution_context.correlation_tag,
        correlation_id=dispatch_call_id,
        earliest=earliest_display,
        latest=latest_display,
        elapsed_ms=dispatch_elapsed_ms,
        transport_mode=dispatch_transport_mode,
        sid=sid if sid else None,
        dispatch_call_state=dispatch_state,
        exception_type="DispatchException" if dispatch_state == "EXCEPTION" else None,
        exception_message=_short_error(err) if dispatch_state == "EXCEPTION" and err else None,
        thread_name=threading.current_thread().name,
    )
    if dispatch_state == "TIMEOUT_NO_SID":
        err_msg = (
            f"Dispatch not confirmed within {dispatch_call_timeout_seconds} seconds "
            "before SID was returned."
        )
        audit_slice_event(
            "REPORT_SLICE_DISPATCH_TIMEOUT_NO_SID",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            elapsed_ms=dispatch_elapsed_ms,
            sid_present=False,
            earliest=earliest_display,
            latest=latest_display,
            reason=_short_error(err_msg),
            error_phase="dispatch",
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
            timeout_classification=timeout_no_sid_classification,
            broker_queue_wait_ms=dispatch_attempt_diag.get("queue_wait_ms"),
            broker_processing_ms=dispatch_attempt_diag.get("broker_processing_ms"),
            broker_total_elapsed_ms=dispatch_attempt_diag.get("broker_total_elapsed_ms"),
            broker_lane_name=dispatch_attempt_diag.get("lane_name"),
            transport_freshness=dispatch_attempt_diag.get("transport_freshness"),
            recent_metadata_outcome=dispatch_attempt_diag.get("recent_metadata_outcome"),
            recent_metadata_age_ms=dispatch_attempt_diag.get("recent_metadata_age_ms"),
            recent_transport_cleanup_reason=dispatch_attempt_diag.get("recent_transport_cleanup_reason"),
        )
        audit_slice_event(
            "REPORT_SLICE_PENDING_DISPATCH_REGISTERED",
            level="INFO",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            correlation_id=dispatch_call_id,
            dispatch_started_utc=dispatch_call_meta.get("started_utc"),
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
            earliest=earliest_display,
            latest=latest_display,
        )
        return _resolve_uncertain_dispatch_timeout(
            logs,
            client=client,
            execution_context=execution_context,
            report_name=report_name,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            merge_report_settings=merge_report_settings,
            log_prefix=log_prefix,
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=record_slice,
            audit_slice_event=audit_slice_event,
            timeout_classification=timeout_no_sid_classification,
            business_effect_guard=business_effect_guard,
        )
    if dispatch_state == "EXCEPTION":
        _clear_registered_dispatch()
        safe_error = redact_text(err or "Dispatch call raised an exception before returning.")
        _append_user_slice_status(
            logs,
            slice_index=slice_index,
            slice_total=slice_total,
            report_name=report_name,
            earliest=earliest_display,
            latest=latest_display,
            status="FAILED",
            log_callback=log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_DISPATCH_EXCEPTION",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            elapsed_ms=dispatch_elapsed_ms,
            sid_present=False,
            earliest=earliest_display,
            latest=latest_display,
            reason=_short_error(safe_error),
            error_type="DispatchException",
            error_phase="dispatch",
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status="FAILED",
            earliest=earliest_display,
            latest=latest_display,
            outcome_code="DISPATCH_FAILED",
            error=safe_error,
            dispatch_earliest=dispatch_earliest or "",
            dispatch_latest=dispatch_latest or "",
            lifecycle_state=SLICE_STATE_FAILED_DISPATCH,
            state_reason=safe_error,
            retry_count=execution_context.retry_count,
            execution_context_id=execution_context.execution_context_id,
        )
        return "FAILED", "", pending_detail_mode
    if not ok:
        _clear_registered_dispatch()
        _append_user_slice_status(
            logs,
            slice_index=slice_index,
            slice_total=slice_total,
            report_name=report_name,
            earliest=earliest_display,
            latest=latest_display,
            status="FAILED",
            log_callback=log_callback,
        )
        broker_op, broker_timeout = _extract_broker_context(text=err)
        error_type = "TimeoutError" if _error_looks_like_timeout(err) else "DispatchError"
        audit_fields = {
            "slice_label": slice_label,
            "slice_index": slice_index,
            "slice_total": slice_total,
            "reason": _short_error(err),
            "error_type": error_type,
            "error_phase": "dispatch",
        }
        if broker_op:
            audit_fields["broker_op"] = broker_op
        if broker_timeout is not None:
            audit_fields["timeout_seconds"] = broker_timeout
        audit_slice_event(
            "REPORT_SLICE_FAILED",
            level="WARN",
            **audit_fields,
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status="FAILED",
            earliest=earliest_display,
            latest=latest_display,
            outcome_code="DISPATCH_FAILED",
            error=err,
            dispatch_earliest=dispatch_earliest or "",
            dispatch_latest=dispatch_latest or "",
            lifecycle_state=SLICE_STATE_FAILED_DISPATCH,
            state_reason=err,
            retry_count=execution_context.retry_count,
            execution_context_id=execution_context.execution_context_id,
        )
        return "FAILED", "", pending_detail_mode
    if not sid:
        _clear_registered_dispatch()
        err_msg = "Dispatch returned without a SID."
        _append_user_slice_status(
            logs,
            slice_index=slice_index,
            slice_total=slice_total,
            report_name=report_name,
            earliest=earliest_display,
            latest=latest_display,
            status=timeout_status,
            log_callback=log_callback,
        )
        audit_slice_event(
            "REPORT_SLICE_DISPATCH_NO_SID",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            elapsed_ms=dispatch_elapsed_ms,
            sid_present=False,
            earliest=earliest_display,
            latest=latest_display,
            reason=_short_error(err_msg),
            error_phase="dispatch",
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
        )
        audit_slice_event(
            "REPORT_SLICE_MARKED_PENDING",
            level="WARN",
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            sid="",
            reason=_short_error(err_msg),
            error_phase="dispatch",
        )
        record_slice(
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            status=timeout_status,
            earliest=earliest_display,
            latest=latest_display,
            sid="",
            outcome_code=_pending_no_sid_outcome_code(timeout_status),
            error=err_msg,
            dispatch_earliest=dispatch_earliest or "",
            dispatch_latest=dispatch_latest or "",
            lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
            state_reason=err_msg,
            retry_count=execution_context.retry_count,
            pending_since_utc=_utc_now_iso(),
            execution_context_id=execution_context.execution_context_id,
        )
        return timeout_status, "", pending_detail_mode
    _clear_registered_dispatch()
    execution_context.sid = sid
    execution_context.mark_state(SLICE_STATE_DISPATCHED)
    audit_slice_event(
        "REPORT_SLICE_SID_RECEIVED",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
    )
    audit_slice_event(
        "REPORT_SLICE_DISPATCHED",
        slice_label=slice_label,
        slice_index=slice_index,
        slice_total=slice_total,
        sid=sid,
    )
    if sid_callback:
        sid_callback(sid, report_name)
    return _verify_dispatched_slice(
        logs,
        client=client,
        execution_context=execution_context,
        report_name=report_name,
        sid=sid,
        wait_seconds=wait_seconds,
        poll_interval=poll_interval,
        timeout_status=timeout_status,
        prefer_merge_report_verification=prefer_merge_report_verification,
        merge_report_log_path=merge_report_log_path,
        merge_report_timeout_seconds=merge_report_timeout_seconds,
        merge_report_settings=merge_report_settings,
        log_prefix=log_prefix,
        log_callback=log_callback,
        record_slice=record_slice,
        audit_slice_event=audit_slice_event,
    )


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
    continue_on_timeout: bool = DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT,
    timeout_status: str = "PENDING",
    dispatch_call_timeout_seconds: int = DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS,
    prefer_merge_report_verification: bool = False,
    merge_report_log_path: str = "",
    merge_report_timeout_seconds: int = DEFAULT_MERGEREPORT_TIMEOUT_SECONDS,
    merge_report_settings: Optional[dict[str, Any]] = None,
) -> List[str]:
    logs: List[str] = []
    default_owner = str(getattr(client, "username", "") or "").strip()
    effective_batch_id = (
        str(getattr(regen_context, "batch_id", "") or "").strip()
        if regen_context is not None
        else ""
    ) or f"batch-{uuid.uuid4().hex[:12]}"
    blueprints: List[dict[str, Any]] = []
    if regen_context is not None:
        blueprints = _ensure_report_definition_frozen(
            regen_context,
            report_id_url=report_id_url,
            report_name=report_name,
            frequency=frequency,
            start=start,
            end=end,
            no_change=no_change,
            default_app=regen_context.app,
            default_owner=default_owner,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
        )
        _persist_batch_journal(regen_context, reason="report_definition_frozen")
    if not blueprints:
        identity = _parse_saved_search_identity(
            report_id_url,
            report_name,
            default_app=(regen_context.app if regen_context is not None else ""),
            default_owner=default_owner,
        )
        blueprints = _build_batch_slice_blueprints(
            batch_id=effective_batch_id,
            report_id_url=report_id_url,
            report_name=report_name,
            frequency=frequency,
            start=start,
            end=end,
            no_change=no_change,
            app=identity.app,
            owner=identity.owner,
            verification_mode=_verification_mode_label(
                prefer_merge_report_verification=prefer_merge_report_verification,
                merge_report_log_path=merge_report_log_path,
            ),
            correlation_mode=(regen_context.correlation_mode if regen_context is not None else "tool_local_only"),
        )

    def _record_slice(
        slice_label: str,
        status: str,
        batch_id: str = "",
        slice_id: str = "",
        attempt_id: int = 0,
        slice_index: int = 0,
        slice_total: int = 0,
        earliest: str = "",
        latest: str = "",
        sid: Optional[str] = None,
        outcome_code: Optional[str] = None,
        error: Optional[str] = None,
        dispatch_correlation_id: str = "",
        dispatch_started_utc: str = "",
        dispatch_timeout_seconds: int = 0,
        dispatch_report_id_url: str = "",
        dispatch_earliest: str = "",
        dispatch_latest: str = "",
        lifecycle_state: str = SLICE_STATE_QUEUED,
        state_reason: Optional[str] = None,
        retry_count: int = 0,
        retry_exhausted: bool = False,
        finalized_from_reconciliation: bool = False,
        reconciliation_source: str = "",
        reconcile_pass_count: int = 0,
        pending_since_utc: str = "",
        last_state_change_utc: str = "",
        expired_utc: str = "",
        tainted: bool = False,
        taint_reason: str = "",
        execution_context_id: str = "",
        correlation_tag: str = "",
        correlation_mode: str = "tool_local_only",
        report_owner: str = "",
        report_app: str = "",
        verification_mode: str = "",
        reconciliation_confidence: str = "",
        reconciliation_matched_fields: str = "",
        reconciliation_decision_reason: str = "",
        dispatch_outcome: str = "",
        execution_outcome: str = "",
        evidence_outcome: str = "",
        business_outcome: str = "",
    ) -> None:
        if regen_context is None:
            return
        resolved_batch_id = str(batch_id or regen_context.batch_id or effective_batch_id).strip()
        resolved_lifecycle_state = _normalize_slice_state(lifecycle_state)
        item = _find_slice_record(
            regen_context,
            slice_id=slice_id,
            report_name=report_name,
            slice_label=slice_label,
            earliest=earliest,
            latest=latest,
        )
        resolved_attempt_id = max(0, int(attempt_id or 0))
        if resolved_attempt_id <= 0:
            existing_attempt_id = max(0, int(getattr(item, "attempt_id", 0) or 0)) if item is not None else 0
            resolved_attempt_id = max(
                existing_attempt_id,
                int(retry_count or 0) + (0 if resolved_lifecycle_state == SLICE_STATE_QUEUED else 1),
            )
        resolved_slice_id = str(slice_id or getattr(item, "slice_id", "") or "").strip()
        if not resolved_slice_id and dispatch_earliest is not None and dispatch_latest is not None:
            resolved_slice_id = _derive_slice_id(
                resolved_batch_id,
                dispatch_report_id_url or report_id_url,
                report_name,
                slice_label,
                dispatch_earliest,
                dispatch_latest,
            )
        resolved_correlation_tag = str(correlation_tag or getattr(item, "correlation_tag", "") or "").strip()
        if not resolved_correlation_tag and resolved_slice_id:
            resolved_correlation_tag = _build_correlation_tag(
                resolved_batch_id,
                resolved_slice_id,
                max(1, resolved_attempt_id or 1),
            )
        resolved_report_owner = str(report_owner or getattr(item, "report_owner", "") or default_owner).strip()
        resolved_report_app = str(
            report_app
            or getattr(item, "report_app", "")
            or (regen_context.app if regen_context is not None else "")
        ).strip()
        resolved_verification_mode = str(
            verification_mode
            or getattr(item, "verification_mode", "")
            or _verification_mode_label(
                prefer_merge_report_verification=prefer_merge_report_verification,
                merge_report_log_path=merge_report_log_path,
            )
        ).strip()
        resolved_sid = str(sid if sid is not None else getattr(item, "sid", "") or "").strip()
        resolved_confidence = str(
            reconciliation_confidence or getattr(item, "reconciliation_confidence", "") or ""
        ).strip()
        resolved_reconciliation_matched_fields = str(
            reconciliation_matched_fields or getattr(item, "reconciliation_matched_fields", "") or ""
        ).strip()
        resolved_reconciliation_decision_reason = str(
            reconciliation_decision_reason or getattr(item, "reconciliation_decision_reason", "") or ""
        ).strip()
        if item is None:
            regen_context.add_slice(
                batch_id=resolved_batch_id,
                slice_id=resolved_slice_id,
                attempt_id=resolved_attempt_id,
                report_name=report_name,
                slice_label=slice_label,
                slice_index=slice_index,
                slice_total=slice_total,
                earliest=earliest,
                latest=latest,
                sid=resolved_sid,
                status=status,
                outcome_code=str(outcome_code or "").strip(),
                error=str(error or "").strip(),
                dispatch_correlation_id=dispatch_correlation_id,
                dispatch_started_utc=dispatch_started_utc,
                dispatch_timeout_seconds=dispatch_timeout_seconds,
                dispatch_report_id_url=dispatch_report_id_url,
                dispatch_earliest=dispatch_earliest,
                dispatch_latest=dispatch_latest,
                lifecycle_state=resolved_lifecycle_state,
                state_reason=str(state_reason or "").strip(),
                retry_count=retry_count,
                retry_exhausted=retry_exhausted,
                finalized_from_reconciliation=finalized_from_reconciliation,
                reconciliation_source=reconciliation_source,
                reconcile_pass_count=reconcile_pass_count,
                pending_since_utc=pending_since_utc,
                last_state_change_utc=last_state_change_utc,
                expired_utc=expired_utc,
                tainted=tainted,
                taint_reason=taint_reason,
                execution_context_id=execution_context_id,
                correlation_tag=resolved_correlation_tag,
                correlation_mode=correlation_mode,
                report_owner=resolved_report_owner,
                report_app=resolved_report_app,
                verification_mode=resolved_verification_mode,
                reconciliation_confidence=resolved_confidence,
                reconciliation_matched_fields=resolved_reconciliation_matched_fields,
                reconciliation_decision_reason=resolved_reconciliation_decision_reason,
            )
            item = regen_context.slices[-1]
        else:
            item.batch_id = resolved_batch_id
            if resolved_slice_id:
                item.slice_id = resolved_slice_id
            item.report_name = report_name
            item.slice_label = slice_label
            item.slice_index = max(0, int(slice_index or 0))
            item.slice_total = max(0, int(slice_total or 0))
            item.earliest = str(earliest or item.earliest or "").strip()
            item.latest = str(latest or item.latest or "").strip()
            if dispatch_correlation_id:
                item.dispatch_correlation_id = str(dispatch_correlation_id or "").strip()
            if dispatch_started_utc:
                item.dispatch_started_utc = str(dispatch_started_utc or "").strip()
            if dispatch_timeout_seconds:
                item.dispatch_timeout_seconds = max(0, int(dispatch_timeout_seconds or 0))
            if dispatch_report_id_url:
                item.dispatch_report_id_url = str(dispatch_report_id_url or "").strip()
            if dispatch_earliest is not None:
                item.dispatch_earliest = str(dispatch_earliest or "").strip()
            if dispatch_latest is not None:
                item.dispatch_latest = str(dispatch_latest or "").strip()
            if pending_since_utc:
                item.pending_since_utc = str(pending_since_utc or "").strip()
            if last_state_change_utc:
                item.last_state_change_utc = str(last_state_change_utc or "").strip()
            if expired_utc:
                item.expired_utc = str(expired_utc or "").strip()
            item.correlation_mode = str(correlation_mode or item.correlation_mode or "tool_local_only").strip() or "tool_local_only"
            item.report_owner = resolved_report_owner
            item.report_app = resolved_report_app
            item.verification_mode = resolved_verification_mode
        derived_dispatch_outcome, derived_execution_outcome, derived_evidence_outcome, derived_business_outcome = (
            _derive_slice_outcomes(
                lifecycle_state=resolved_lifecycle_state,
                sid=resolved_sid,
                finalized_from_reconciliation=bool(finalized_from_reconciliation),
                evidence_confidence=resolved_confidence,
            )
        )
        previous_error = str(getattr(item, "error", "") or "").strip()
        previous_state_reason = str(getattr(item, "state_reason", "") or "").strip()
        resolved_error = str(error or "").strip() if error is not None else previous_error
        resolved_state_reason = (
            str(state_reason or "").strip()
            if state_reason is not None
            else (str(error or "").strip() if error else previous_state_reason)
        )
        clear_transient_error = (
            resolved_lifecycle_state == SLICE_STATE_SUCCESS
            and not resolved_error
            and bool(previous_error)
        )
        if resolved_lifecycle_state == SLICE_STATE_SUCCESS and error is None:
            resolved_error = ""
            if state_reason is None:
                resolved_state_reason = ""
            clear_transient_error = bool(previous_error)
        _set_slice_record_state(
            item,
            lifecycle_state=resolved_lifecycle_state,
            status=status,
            attempt_id=resolved_attempt_id,
            sid=resolved_sid,
            outcome_code=str(outcome_code or item.outcome_code or "").strip(),
            error=resolved_error,
            state_reason=resolved_state_reason,
            retry_count=retry_count,
            retry_exhausted=retry_exhausted,
            finalized_from_reconciliation=finalized_from_reconciliation,
            reconciliation_source=reconciliation_source or item.reconciliation_source,
            reconcile_pass_count=reconcile_pass_count,
            tainted=tainted,
            taint_reason=taint_reason,
            execution_context_id=execution_context_id or item.execution_context_id,
            correlation_tag=resolved_correlation_tag,
            reconciliation_confidence=resolved_confidence,
            reconciliation_matched_fields=resolved_reconciliation_matched_fields,
            reconciliation_decision_reason=resolved_reconciliation_decision_reason,
            dispatch_outcome=dispatch_outcome or derived_dispatch_outcome,
            execution_outcome=execution_outcome or derived_execution_outcome,
            evidence_outcome=evidence_outcome or derived_evidence_outcome,
            business_outcome=business_outcome or derived_business_outcome,
        )
        if clear_transient_error:
            _append_log(
                logs,
                (
                    f"[Debug] TRANSIENT_SLICE_ERROR_CLEARED batch_id={item.batch_id} "
                    f"slice_id={item.slice_id} attempt_id={item.attempt_id} "
                    f"previous_error={_short_error(previous_error)}"
                ),
                log_callback,
            )
        _append_log(
            logs,
            (
                f"[Debug] SLICE_STATE_TRANSITION batch_id={item.batch_id} slice_id={item.slice_id} "
                f"attempt_id={item.attempt_id} correlation_tag={item.correlation_tag or '-'} "
                f"state={item.lifecycle_state} status={item.status} outcome_code={item.outcome_code} "
                f"dispatch_outcome={item.dispatch_outcome} execution_outcome={item.execution_outcome} "
                f"evidence_outcome={item.evidence_outcome} business_outcome={item.business_outcome} "
                f"confidence={item.reconciliation_confidence or '-'} "
                f"matched_fields={item.reconciliation_matched_fields or '-'} "
                f"decision_reason={_short_error(item.reconciliation_decision_reason or '-')}"
            ),
            log_callback,
        )
        _persist_batch_journal(regen_context, reason=f"slice_{item.lifecycle_state.lower()}")

    def _audit_slice_event(event: str, *, level: str = "INFO", **fields) -> None:
        if regen_context is None:
            return
        item = _find_slice_record(
            regen_context,
            slice_id=str(fields.get("slice_id", "") or "").strip(),
            report_name=report_name,
            slice_label=str(fields.get("slice_label", "") or "").strip(),
            earliest=str(fields.get("earliest", "") or "").strip(),
            latest=str(fields.get("latest", "") or "").strip(),
        )
        fields.setdefault("batch_id", regen_context.batch_id)
        if item is not None:
            if item.slice_id:
                fields.setdefault("slice_id", item.slice_id)
            if int(item.attempt_id or 0) > 0:
                fields.setdefault("attempt_id", int(item.attempt_id or 0))
            if item.correlation_tag:
                fields.setdefault("correlation_tag", item.correlation_tag)
        fields.setdefault("batch_state", regen_context.batch_state)
        _audit_event(
            event,
            level=level,
            run_id=regen_context.run_id,
            report_name=report_name,
            **fields,
        )

    def _business_effect_guard(execution_context: SliceExecutionContext) -> bool:
        return _completed_business_effect_exists(
            regen_context,
            slice_id=execution_context.slice_id,
            report_name=report_name,
            dispatch_earliest=execution_context.dispatch_earliest or "",
            dispatch_latest=execution_context.dispatch_latest or "",
            exclude_execution_context_id=execution_context.execution_context_id,
        )

    if len(blueprints) == 1 and str(blueprints[0].get("slice_label", "") or "").strip() == "single run":
        blueprint = blueprints[0]
        _append_log(
            logs,
            f"Dispatching '{report_name}' with saved search time range...",
            log_callback,
        )
        _dispatch_slice_and_wait(
            logs,
            client=client,
            batch_id=effective_batch_id,
            slice_id=str(blueprint.get("slice_id", "") or "").strip(),
            report_id_url=report_id_url,
            report_name=report_name,
            slice_label=str(blueprint.get("slice_label", "single run") or "single run"),
            slice_index=int(blueprint.get("slice_index", 1) or 1),
            slice_total=int(blueprint.get("slice_total", 1) or 1),
            earliest_display=str(blueprint.get("earliest", start.strftime("%Y-%m-%d %H:%M:%S")) or ""),
            latest_display=str(blueprint.get("latest", end.strftime("%Y-%m-%d %H:%M:%S")) or ""),
            dispatch_earliest=str(blueprint.get("dispatch_earliest", "") or "") or None,
            dispatch_latest=str(blueprint.get("dispatch_latest", "") or "") or None,
            run_id=(regen_context.run_id if regen_context is not None else ""),
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            merge_report_settings=merge_report_settings,
            log_prefix="",
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=_record_slice,
            audit_slice_event=_audit_slice_event,
            correlation_tag=str(blueprint.get("correlation_tag", "") or "").strip(),
            correlation_mode=str(blueprint.get("correlation_mode", "tool_local_only") or "tool_local_only"),
            report_owner=str(blueprint.get("report_owner", "") or "").strip(),
            report_app=str(blueprint.get("report_app", "") or "").strip(),
            verification_mode=str(blueprint.get("verification_mode", "") or "").strip(),
            business_effect_guard=_business_effect_guard,
        )
        return logs

    if len(blueprints) == 0:
        raise ValueError("Selected date range generates 0 slices/emails.")
    if len(blueprints) > 12:
        raise ValueError("Selected date range generates more than 12 slices/emails.")
    _append_log(
        logs,
        f"Dispatching '{report_name}' with {len(blueprints)} slice(s) ({frequency}) from {start} to {end}.",
        log_callback,
    )
    force_transport_reset_next_slice = False
    transport_reset_reason = "slice_transition"
    for i, blueprint in enumerate(blueprints, start=1):
        slice_label = str(blueprint.get("slice_label", f"[{i}/{len(blueprints)}]") or f"[{i}/{len(blueprints)}]")
        earliest = str(blueprint.get("dispatch_earliest", "") or "")
        latest = str(blueprint.get("dispatch_latest", "") or "")
        if i > 1:
            _reset_slice_transport_state(
                logs,
                client=client,
                report_name=report_name,
                slice_label=slice_label,
                slice_index=i,
                slice_total=len(blueprints),
                log_callback=log_callback,
                audit_slice_event=_audit_slice_event,
                force_transport_reset=force_transport_reset_next_slice,
                reason=transport_reset_reason,
            )
            force_transport_reset_next_slice = False
            transport_reset_reason = "slice_transition"
        _append_log(
            logs,
            f"Running slice {i} of {len(blueprints)}...",
            log_callback,
        )
        _append_log(
            logs,
            (
                f"  [{i}/{len(blueprints)}] Earliest: {blueprint.get('earliest', '')}, "
                f"Latest: {blueprint.get('latest', '')} - sending..."
            ),
            log_callback,
        )
        status, sid, pending_detail_mode = _dispatch_slice_and_wait(
            logs,
            client=client,
            batch_id=effective_batch_id,
            slice_id=str(blueprint.get("slice_id", "") or "").strip(),
            report_id_url=report_id_url,
            report_name=report_name,
            slice_label=slice_label,
            slice_index=i,
            slice_total=len(blueprints),
            earliest_display=str(blueprint.get("earliest", "") or ""),
            latest_display=str(blueprint.get("latest", "") or ""),
            dispatch_earliest=earliest or None,
            dispatch_latest=latest or None,
            run_id=(regen_context.run_id if regen_context is not None else ""),
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
            timeout_status=timeout_status,
            dispatch_call_timeout_seconds=dispatch_call_timeout_seconds,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            merge_report_settings=merge_report_settings,
            log_prefix=f"[{i}/{len(blueprints)}] ",
            log_callback=log_callback,
            sid_callback=sid_callback,
            record_slice=_record_slice,
            audit_slice_event=_audit_slice_event,
            correlation_tag=str(blueprint.get("correlation_tag", "") or "").strip(),
            correlation_mode=str(blueprint.get("correlation_mode", "tool_local_only") or "tool_local_only"),
            report_owner=str(blueprint.get("report_owner", "") or "").strip(),
            report_app=str(blueprint.get("report_app", "") or "").strip(),
            verification_mode=str(blueprint.get("verification_mode", "") or "").strip(),
            business_effect_guard=_business_effect_guard,
        )
        if str(pending_detail_mode or "").strip().lower() == "dispatch_unconfirmed":
            force_transport_reset_next_slice = True
            transport_reset_reason = "dispatch_timeout_no_sid"
        needs_transport_reset = getattr(client, "needs_transport_reset", None)
        if callable(needs_transport_reset) and bool(needs_transport_reset()):
            force_transport_reset_next_slice = True
            reason_fn = getattr(client, "transport_reset_reason", None)
            transport_reset_reason = (
                str(reason_fn() or "").strip()
                if callable(reason_fn)
                else "broker_timeout_or_connection_error"
            ) or "broker_timeout_or_connection_error"
        if _is_pending_status(status) and i < len(blueprints):
            if continue_on_timeout:
                continue_message = (
                    f"  [{i}/{len(blueprints)}] Status not confirmed within {wait_seconds} seconds. "
                    "Continuing to next slice."
                )
                if pending_detail_mode == "dispatch_unconfirmed" and not sid:
                    continue_message = (
                        f"  [{i}/{len(blueprints)}] Dispatch not yet confirmed; awaiting SID from Splunk. "
                        "Continuing to next slice."
                    )
                _append_log(
                    logs,
                    continue_message,
                    log_callback,
                )
                _audit_slice_event(
                    "REPORT_BATCH_CONTINUE_AFTER_PENDING",
                    level="INFO",
                    slice_label=slice_label,
                    slice_index=i,
                    slice_total=len(blueprints),
                    sid=sid,
                    remaining_slices=len(blueprints) - i,
                )
                continue
            _append_log(
                logs,
                f"  [{i}/{len(blueprints)}] Halting remaining slices because continue_on_timeout=false.",
                log_callback,
            )
            _audit_slice_event(
                "REPORT_BATCH_STOPPED_AFTER_PENDING",
                level="WARN",
                slice_label=slice_label,
                slice_index=i,
                slice_total=len(blueprints),
                sid=sid,
                remaining_slices=len(blueprints) - i,
            )
            break
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


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


_BROKER_TIMEOUT_RE = re.compile(
    r"Local Splunk broker timed out while processing the request"
    r"(?:\s*\(op=([^,]+),\s*timeout=(\d+)s\))?",
    re.IGNORECASE,
)


def _error_looks_like_timeout(text: str) -> bool:
    lower = (text or "").lower()
    return "timed out" in lower or "timeout" in lower


def _error_looks_like_auth_failure(text: str) -> bool:
    lower = (text or "").lower()
    return (
        "authentication failed" in lower
        or "unauthorized" in lower
        or "401" in lower
        or "403" in lower
        or "not connected to splunk" in lower
    )


def _error_looks_like_interruption(text: str) -> bool:
    lower = (text or "").lower()
    markers = (
        "connection aborted",
        "connection reset",
        "broken pipe",
        "remote end closed",
        "read timed out",
        "connect timeout",
        "connection error",
        "network connection interruption",
    )
    return any(marker in lower for marker in markers)


def _error_looks_like_invalid_correlation_field(text: str) -> bool:
    lower = (text or "").lower()
    return (
        ("ui_dispatch_view" in lower and ("unknown" in lower or "invalid" in lower))
        or ("dispatch field" in lower and "invalid" in lower)
        or ("unexpected argument" in lower and "dispatch" in lower)
    )


def _error_looks_like_invalid_dispatch_payload(text: str) -> bool:
    lower = (text or "").lower()
    markers = (
        "invalid dispatch field",
        "invalid dispatch payload",
        "unexpected argument",
        "invalid argument",
        "invalid value",
        "validation failed",
        "bad argument",
        "unsupported argument",
        "unknown argument",
        "cannot parse",
        "malformed",
        "ui_dispatch_app",
        "ui_dispatch_view",
    )
    return any(marker in lower for marker in markers)


def _error_looks_like_invalid_dispatch_namespace(text: str) -> bool:
    lower = (text or "").lower()
    markers = (
        "could not find object id",
        "saved search does not exist",
        "savedsearch does not exist",
        "unknown search",
        "namespace",
        "application does not exist",
        "owner does not exist",
        "sharing is invalid",
        "cannot find object",
    )
    return any(marker in lower for marker in markers)


def _classify_dispatch_http_failure(
    *,
    status_code: int,
    response_text: str,
    had_optional_fields: bool,
    namespace_consistency: str = "",
    path_validation_error: str = "",
) -> str:
    if int(status_code) == 400:
        if path_validation_error or str(namespace_consistency or "").strip().lower() in {
            "invalid",
            "owner_mismatch",
            "app_mismatch",
        } or _error_looks_like_invalid_dispatch_namespace(response_text):
            return "failed_dispatch_http_400_invalid_namespace"
        if had_optional_fields or _error_looks_like_invalid_dispatch_payload(response_text):
            return "failed_dispatch_http_400_invalid_payload"
        return "failed_dispatch_http_400_unknown"
    return "failed_dispatch_nonretryable"


def _extract_broker_context(exc: Optional[Exception] = None, text: str = "") -> Tuple[Optional[str], Optional[int]]:
    op = getattr(exc, "broker_op", None) if exc is not None else None
    timeout_seconds = getattr(exc, "timeout_seconds", None) if exc is not None else None

    if (not op or timeout_seconds is None) and text:
        match = _BROKER_TIMEOUT_RE.search(text)
        if match:
            if not op:
                op = match.group(1) or ""
            if timeout_seconds is None:
                try:
                    timeout_seconds = int(match.group(2))
                except Exception:
                    timeout_seconds = None

    op = str(op).strip() if isinstance(op, str) else ""
    if isinstance(timeout_seconds, (int, float)):
        try:
            timeout_seconds = int(timeout_seconds)
        except Exception:
            timeout_seconds = None
    else:
        timeout_seconds = None

    return (op if op else None), timeout_seconds


def _poll_job_status_with_budget(
    client: SplunkClient,
    sid: str,
    wait_seconds: int,
    poll_interval: int,
    *,
    poll_callback: Optional[Callable[..., None]] = None,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    audit_event: Optional[Callable[..., None]] = None,
    slice_label: str = "",
    slice_index: int = 0,
    slice_total: int = 0,
    batch_id: str = "",
    slice_id: str = "",
    attempt_id: int = 0,
    correlation_tag: str = "",
) -> Tuple[str, dict, int]:
    last_content: dict = {}
    deadline = time.monotonic() + max(1, int(wait_seconds))
    poll_seconds = max(1.0, float(poll_interval))
    poll_count = 0

    snapshot_fn = getattr(client, "get_job_status_snapshot", None)
    can_snapshot = callable(snapshot_fn)

    if not can_snapshot:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or remaining < 1.0:
                break
            request_timeout = min(poll_seconds, remaining)
            poll_count += 1
            poll_start = time.monotonic()
            state, content = client.check_job_status(
                sid,
                wait_seconds=max(1, int(request_timeout)),
                poll_interval=max(1, int(min(poll_seconds, request_timeout))),
            )
            poll_elapsed = time.monotonic() - poll_start
            poll_elapsed_ms = int(poll_elapsed * 1000)
            last_content = content

            if poll_callback:
                poll_callback(
                    poll_count=poll_count,
                    state=state,
                    content=content,
                    poll_elapsed_ms=poll_elapsed_ms,
                    request_timeout_seconds=request_timeout,
                    remaining_seconds=max(0.0, remaining),
                )

            if state in ("SUCCESS", "FAILED"):
                return state, content, poll_count

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sleep_seconds = max(0.0, poll_seconds - poll_elapsed)
            sleep_seconds = min(sleep_seconds, max(0.0, remaining))
            if sleep_seconds <= 0:
                continue
            time.sleep(sleep_seconds)

        return "TIMEOUT", last_content, poll_count

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or remaining < 1.0:
            break

        request_timeout = min(poll_seconds, remaining)
        poll_count += 1
        poll_start = time.monotonic()
        state, content = _call_snapshot_with_retry(
            client,
            sid,
            request_timeout_seconds=request_timeout,
            max_total_timeout_seconds=remaining,
            retry_count=DEFAULT_STATUS_SNAPSHOT_TIMEOUT_RETRIES,
            stage_name="active_wait",
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_event,
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            batch_id=batch_id,
            slice_id=slice_id,
            attempt_id=attempt_id,
            correlation_tag=correlation_tag,
        )
        poll_elapsed_ms = int((time.monotonic() - poll_start) * 1000)
        last_content = content

        if poll_callback:
            poll_callback(
                poll_count=poll_count,
                state=state,
                content=content,
                poll_elapsed_ms=poll_elapsed_ms,
                request_timeout_seconds=request_timeout,
                remaining_seconds=max(0.0, remaining),
            )

        if state in ("SUCCESS", "FAILED"):
            return state, content, poll_count

        sleep_seconds = min(poll_seconds, max(0.0, deadline - time.monotonic()))
        if sleep_seconds <= 0:
            break
        time.sleep(sleep_seconds)

    return "TIMEOUT", last_content, poll_count


def _build_pending_status_message(detail: str = "", *, wait_seconds: Optional[int] = None) -> str:
    active_wait = max(1, int(wait_seconds or DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS))
    if _error_looks_like_timeout(detail):
        base = (
            f"Status not confirmed within {active_wait} seconds. "
            "Splunk may still complete pending jobs asynchronously."
        )
    else:
        base = (
            "Slice dispatched successfully and remains pending verification. "
            "Splunk may still complete pending jobs asynchronously."
        )
    clean_detail = (detail or "").strip()
    if clean_detail:
        return f"{base} Detail: {clean_detail}"
    return base


def _pending_no_sid_outcome_code(timeout_status: str) -> str:
    return "PENDING_NO_SID" if _is_pending_status(timeout_status) else "DISPATCH_NO_SID"


def _classify_mergereport_terminal_message(message: str, level: str) -> Optional[Tuple[str, str]]:
    lower_message = str(message or "").strip().lower()
    upper_level = str(level or "").strip().upper()
    if "action=email sent" in lower_message or lower_message.startswith("action=email sent"):
        return ("SUCCESS", "MergeReport confirmed Action=Email sent.")
    if upper_level == "ERROR":
        return ("FAILED", str(message or "MergeReport reported an error.").strip())
    failure_markers = (
        "failed",
        "smtp empty",
        "smtp error",
        "error sending",
        "unable to send",
    )
    if any(marker in lower_message for marker in failure_markers):
        return ("FAILED", str(message or "MergeReport reported a failure marker.").strip())
    return None


def _prepare_export_search(search_query: str) -> str:
    normalized = str(search_query or "").strip()
    if not normalized:
        return normalized
    lower = normalized.lower()
    if lower.startswith(("search ", "|", "from ", "tstats ", "datamodel ", "makeresults ")):
        return normalized
    return f"search {normalized}"


def _classify_search_error(exc: Exception) -> tuple[str, str]:
    message = str(exc or "").strip() or repr(exc)
    lower = message.lower()
    if "unknown search command 'index'" in lower or 'unknown search command "index"' in lower:
        return (
            "malformed_spl",
            "Malformed SPL sent to /services/search/jobs/export. The search must start with 'search'.",
        )
    if "authentication failed" in lower or "unauthorized" in lower or "401" in lower or "403" in lower:
        return ("auth_expired", message)
    if _error_looks_like_timeout(message):
        return ("timeout", message)
    if _error_looks_like_interruption(message):
        return ("transport_interrupted", message)
    return ("search_error", message)


def _resolve_mergereport_local_file_state(log_path: str) -> dict[str, Any]:
    safe_path = str(log_path or "").strip()
    payload = {
        "requested_path": safe_path,
        "path": safe_path,
        "available": False,
        "reason": "blank_path",
    }
    if not safe_path:
        return payload
    if not os.path.isabs(safe_path):
        payload["reason"] = "non_absolute_path"
        return payload
    try:
        if not os.path.exists(safe_path):
            payload["reason"] = "missing_path"
            return payload
        if not os.path.isfile(safe_path):
            payload["reason"] = "not_a_file"
            return payload
        if not os.access(safe_path, os.R_OK):
            payload["reason"] = "not_readable"
            return payload
    except Exception as exc:
        payload["reason"] = f"io_check_failed:{type(exc).__name__}"
        return payload
    payload["available"] = True
    payload["reason"] = "available"
    return payload


def resolve_merge_report_runtime_settings(config: Optional[SplunkConfig]) -> dict[str, Any]:
    postdispatch = dict(config.postdispatch_config) if (config is not None and isinstance(config.postdispatch_config, dict)) else {}
    enabled = bool(
        _parse_bool(
            postdispatch.get("merge_report_enabled"),
            bool(getattr(config, "merge_report_enabled", False)),
        )
    )
    requested_path = str(
        postdispatch.get(
            "merge_report_log_path",
            getattr(config, "merge_report_log_path", ""),
        )
        or getattr(config, "merge_report_log_path", "")
        or ""
    ).strip()
    file_state = _resolve_mergereport_local_file_state(requested_path)
    return {
        "enabled": enabled,
        "timeout_seconds": _parse_min_int(
            postdispatch.get("merge_report_timeout_seconds"),
            int(getattr(config, "merge_report_timeout_seconds", DEFAULT_MERGEREPORT_TIMEOUT_SECONDS) or DEFAULT_MERGEREPORT_TIMEOUT_SECONDS),
            1,
        ),
        "requested_log_path": requested_path,
        "local_file_path": str(file_state.get("path", "") or "").strip(),
        "local_file_available": bool(file_state.get("available")),
        "local_file_reason": str(file_state.get("reason", "") or "").strip(),
        "rest_enabled": enabled,
        "index": str(postdispatch.get("merge_report_index", "_internal") or "_internal").strip() or "_internal",
        "source_contains": str(postdispatch.get("merge_report_source_contains", "mergeReport_alert.log") or "mergeReport_alert.log").strip() or "mergeReport_alert.log",
        "sourcetype": str(postdispatch.get("merge_report_sourcetype", "") or "").strip(),
        "lookback_seconds": _parse_min_int(
            postdispatch.get("lookback_seconds"),
            DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS,
            1,
        ),
        "source_preference": "rest_then_file" if enabled else "none",
    }


def _coerce_merge_report_runtime_settings(
    *,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
    merge_report_timeout_seconds: int,
    merge_report_settings: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    settings = dict(merge_report_settings) if isinstance(merge_report_settings, dict) else {}
    requested_path = str(
        settings.get("requested_log_path", settings.get("local_file_path", merge_report_log_path))
        or merge_report_log_path
        or ""
    ).strip()
    file_state = _resolve_mergereport_local_file_state(requested_path)
    return {
        "enabled": bool(settings.get("enabled", prefer_merge_report_verification)),
        "timeout_seconds": _parse_min_int(
            settings.get("timeout_seconds"),
            max(1, int(merge_report_timeout_seconds or DEFAULT_MERGEREPORT_TIMEOUT_SECONDS)),
            1,
        ),
        "requested_log_path": requested_path,
        "local_file_path": str(file_state.get("path", "") or "").strip(),
        "local_file_available": bool(file_state.get("available")),
        "local_file_reason": str(file_state.get("reason", "") or "").strip(),
        "rest_enabled": bool(settings.get("rest_enabled", prefer_merge_report_verification)),
        "index": str(settings.get("index", "_internal") or "_internal").strip() or "_internal",
        "source_contains": str(settings.get("source_contains", "mergeReport_alert.log") or "mergeReport_alert.log").strip() or "mergeReport_alert.log",
        "sourcetype": str(settings.get("sourcetype", "") or "").strip(),
        "lookback_seconds": _parse_min_int(
            settings.get("lookback_seconds"),
            DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS,
            1,
        ),
        "source_preference": str(settings.get("source_preference", "rest_then_file" if prefer_merge_report_verification else "none") or "none").strip(),
    }


def _scan_mergereport_search_results_for_sid(results: dict[str, Any], sid: str) -> tuple[str, str, int]:
    safe_sid = str(sid or "").strip()
    if not safe_sid:
        return ("RUNNING", "", 0)
    parser = None
    try:
        from mergereport_monitor import MergeReportParser
        parser = MergeReportParser
    except Exception:
        parser = None
    matched_count = 0
    for result in results.get("results", []) if isinstance(results, dict) else []:
        if not isinstance(result, dict):
            continue
        raw = str(result.get("_raw", "") or "").strip()
        if not raw or (safe_sid.lower() not in raw.lower()):
            continue
        matched_count += 1
        message = raw
        level = str(result.get("level", "INFO") or "INFO").strip()
        if parser is not None:
            try:
                event = parser.parse_line(raw)
            except Exception:
                event = None
            if event is not None and str(getattr(event, "sid", "") or "").strip() == safe_sid:
                message = str(getattr(event, "message", raw) or raw)
                level = str(getattr(event, "level", level) or level)
        classified = _classify_mergereport_terminal_message(message, level)
        if classified is not None:
            return (classified[0], classified[1], matched_count)
    return ("PENDING" if matched_count > 0 else "RUNNING", "", matched_count)


def _check_merge_report_preferred_evidence(
    client: SplunkClient,
    *,
    sid: str,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
    merge_report_timeout_seconds: int,
    merge_report_settings: Optional[dict[str, Any]] = None,
    stage_name: str = "",
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    query_timeout_seconds: Optional[int] = None,
    saved_search_context: Optional[dict[str, str]] = None,
) -> tuple[str, dict[str, Any]]:
    settings = _coerce_merge_report_runtime_settings(
        prefer_merge_report_verification=prefer_merge_report_verification,
        merge_report_log_path=merge_report_log_path,
        merge_report_timeout_seconds=merge_report_timeout_seconds,
        merge_report_settings=merge_report_settings,
    )
    if saved_search_context and str(stage_name or "").strip().lower() != "merge_report_wait":
        namespace_info = _resolve_mergereport_saved_search_namespace(
            report_id_url=str(saved_search_context.get("report_id_url", "") or ""),
            report_name=str(saved_search_context.get("report_name", "") or ""),
            report_app=str(saved_search_context.get("report_app", "") or ""),
            report_owner=str(saved_search_context.get("report_owner", "") or ""),
        )
        _append_log(
            logs,
            (
                f"[Debug] MERGEREPORT_NAMESPACE_RESOLVED owner={namespace_info.get('owner', '') or '-'} "
                f"app={namespace_info.get('app', '') or '-'} "
                f"report_name={namespace_info.get('report_name', '') or '-'} "
                f"saved_search_path={namespace_info.get('saved_search_path', '') or '-'} "
                f"resolution_source={namespace_info.get('resolution_source', '') or 'unknown'}"
            ),
            log_callback,
        )
    safe_sid = str(sid or "").strip()
    if not settings["enabled"] or not safe_sid:
        return ("DISABLED", {"source": "none", "detail": "", "matched_line_count": 0, "settings": settings})

    get_fn = getattr(client, "_get", None)
    rest_checked = False
    rest_state = "RUNNING"
    rest_detail = ""
    rest_matched_count = 0
    if callable(get_fn) and bool(settings.get("rest_enabled", True)):
        lookback_seconds = max(
            int(settings.get("lookback_seconds", DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS) or DEFAULT_POSTDISPATCH_LOOKBACK_SECONDS),
            int(query_timeout_seconds or 0) + RECONCILIATION_WINDOW_BUFFER_SECONDS,
        )
        search_parts = [
            f'index={settings.get("index", "_internal")}',
            f'source="{settings.get("source_contains", "mergeReport_alert.log")}"',
            f'(("SID={safe_sid}" OR "sid={safe_sid}" OR "sid=\\"{safe_sid}\\""))',
        ]
        sourcetype = str(settings.get("sourcetype", "") or "").strip()
        if sourcetype:
            search_parts.append(f'sourcetype="{sourcetype}"')
        search_query = _prepare_export_search(" ".join(search_parts))
        _append_log(
            logs,
            (
                f"[Debug] MERGEREPORT_REST_QUERY_STARTED sid={safe_sid} "
                f"stage_name={stage_name or '-'} earliest_time=-{lookback_seconds}s "
                f"index={settings.get('index', '_internal')} source_contains={settings.get('source_contains', 'mergeReport_alert.log')}"
            ),
            log_callback,
        )
        try:
            rest_checked = True
            get_kwargs: dict[str, Any] = {
                "params": {
                    "search": search_query,
                    "earliest_time": f"-{lookback_seconds}s",
                    "output_mode": "json",
                }
            }
            if _dispatch_call_supports_keyword(get_fn, "timeout"):
                get_kwargs["timeout"] = max(1, int(query_timeout_seconds or EVIDENCE_HTTP_READ_TIMEOUT_SECONDS))
            if _dispatch_call_supports_keyword(get_fn, "connect_timeout_seconds"):
                get_kwargs["connect_timeout_seconds"] = EVIDENCE_HTTP_CONNECT_TIMEOUT_SECONDS
            results = get_fn("/services/search/jobs/export", **get_kwargs)
            state, detail, matched_count = _scan_mergereport_search_results_for_sid(results, safe_sid)
            rest_state = state
            rest_detail = detail
            rest_matched_count = matched_count
            _append_log(
                logs,
                (
                    f"[Debug] MERGEREPORT_REST_QUERY_RESULT sid={safe_sid} "
                    f"stage_name={stage_name or '-'} state={state} matched_line_count={matched_count}"
                ),
                log_callback,
            )
            if state in {"SUCCESS", "FAILED", "PENDING"}:
                return (
                    state,
                    {
                        "source": "rest",
                        "detail": detail,
                        "matched_line_count": matched_count,
                        "settings": settings,
                    },
                )
        except Exception as exc:
            error_code, detail = _classify_search_error(exc)
            _append_log(
                logs,
                (
                    f"[Debug] MERGEREPORT_REST_QUERY_RESULT sid={safe_sid} "
                    f"stage_name={stage_name or '-'} state=UNAVAILABLE error_code={error_code} "
                    f"detail={_short_error(redact_text(detail))}"
                ),
                log_callback,
            )
            if not settings.get("local_file_available"):
                return (
                    "UNAVAILABLE",
                    {
                        "source": "rest",
                        "detail": detail,
                        "error_code": error_code,
                        "matched_line_count": 0,
                        "settings": settings,
                    },
                )

    if bool(settings.get("local_file_available")):
        file_path = str(settings.get("local_file_path", "") or "").strip()
        state, detail = _scan_mergereport_log_for_sid(file_path, safe_sid)
        if state in {"SUCCESS", "FAILED"}:
            return (
                state,
                {
                    "source": "file",
                    "detail": detail,
                    "matched_line_count": 1,
                    "settings": settings,
                },
            )
        return (
            "RUNNING",
            {
                "source": "file",
                "detail": detail,
                "matched_line_count": 0,
                "settings": settings,
            },
        )

    if rest_checked:
        return (
            rest_state,
            {
                "source": "rest",
                "detail": rest_detail,
                "matched_line_count": rest_matched_count,
                "settings": settings,
            },
        )

    return (
        "UNAVAILABLE",
        {
            "source": "none",
            "detail": str(settings.get("local_file_reason", "") or "").strip(),
            "error_code": "file_unavailable",
            "matched_line_count": 0,
            "settings": settings,
        },
    )


def _wait_for_merge_report_preferred_evidence(
    client: SplunkClient,
    *,
    sid: str,
    prefer_merge_report_verification: bool,
    merge_report_log_path: str,
    merge_report_timeout_seconds: int,
    merge_report_settings: Optional[dict[str, Any]] = None,
    wait_seconds: int,
    poll_interval: int,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    saved_search_context: Optional[dict[str, str]] = None,
) -> tuple[str, str, str, int]:
    settings = _coerce_merge_report_runtime_settings(
        prefer_merge_report_verification=prefer_merge_report_verification,
        merge_report_log_path=merge_report_log_path,
        merge_report_timeout_seconds=merge_report_timeout_seconds,
        merge_report_settings=merge_report_settings,
    )
    if saved_search_context:
        namespace_info = _resolve_mergereport_saved_search_namespace(
            report_id_url=str(saved_search_context.get("report_id_url", "") or ""),
            report_name=str(saved_search_context.get("report_name", "") or ""),
            report_app=str(saved_search_context.get("report_app", "") or ""),
            report_owner=str(saved_search_context.get("report_owner", "") or ""),
        )
        _append_log(
            logs,
            (
                f"[Debug] MERGEREPORT_NAMESPACE_RESOLVED owner={namespace_info.get('owner', '') or '-'} "
                f"app={namespace_info.get('app', '') or '-'} "
                f"report_name={namespace_info.get('report_name', '') or '-'} "
                f"saved_search_path={namespace_info.get('saved_search_path', '') or '-'} "
                f"resolution_source={namespace_info.get('resolution_source', '') or 'unknown'}"
            ),
            log_callback,
        )
    preferred_source = "none"
    if settings["enabled"]:
        preferred_source = "rest"
        if not bool(settings.get("rest_enabled", True)) and bool(settings.get("local_file_available")):
            preferred_source = "file"
    _append_log(
        logs,
        (
            f"[Debug] MERGEREPORT_VERIFICATION_SOURCE_SELECTED source={preferred_source} "
            f"file_available={bool(settings.get('local_file_available'))} "
            f"local_file_path={str(settings.get('requested_log_path', '') or '(blank)')}"
        ),
        log_callback,
    )
    if settings["enabled"] and not bool(settings.get("local_file_available")):
        _append_log(
            logs,
            (
                f"[Debug] MERGEREPORT_FILE_UNAVAILABLE local_path="
                f"{str(settings.get('requested_log_path', '') or '(blank)')} "
                f"reason={str(settings.get('local_file_reason', '') or 'unknown')} "
                "falling back to non-file verification"
            ),
            log_callback,
        )
    if not settings["enabled"]:
        return ("DISABLED", "", "none", 0)

    wait_budget = max(1, int(wait_seconds))
    deadline = time.monotonic() + wait_budget
    poll_seconds = max(1.0, float(poll_interval))
    start_time = time.monotonic()
    last_source = preferred_source
    while True:
        state, payload = _check_merge_report_preferred_evidence(
            client,
            sid=sid,
            prefer_merge_report_verification=prefer_merge_report_verification,
            merge_report_log_path=merge_report_log_path,
            merge_report_timeout_seconds=merge_report_timeout_seconds,
            merge_report_settings=settings,
            stage_name="merge_report_wait",
            logs=logs,
            log_callback=log_callback,
            query_timeout_seconds=min(wait_budget, EVIDENCE_HTTP_READ_TIMEOUT_SECONDS),
            saved_search_context=saved_search_context,
        )
        last_source = str(payload.get("source", last_source) or last_source)
        if state in {"SUCCESS", "FAILED"}:
            return (state, str(payload.get("detail", "") or "").strip(), last_source, int((time.monotonic() - start_time) * 1000))
        if state == "UNAVAILABLE":
            _append_log(
                logs,
                (
                    f"[Debug] MERGEREPORT_VERIFICATION_NONFATAL_SOURCE_UNAVAILABLE source={last_source} "
                    f"detail={_short_error(redact_text(str(payload.get('detail', '') or 'source unavailable')))}"
                ),
                log_callback,
            )
            return ("UNAVAILABLE", str(payload.get("detail", "") or "").strip(), last_source, int((time.monotonic() - start_time) * 1000))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_seconds, max(0.0, remaining)))
    return ("TIMEOUT", "", last_source, int((time.monotonic() - start_time) * 1000))


def _scan_mergereport_log_for_sid(log_path: str, sid: str) -> Tuple[str, str]:
    sid = str(sid or "").strip()
    if not log_path or not sid:
        return ("RUNNING", "")
    try:
        from mergereport_monitor import MergeReportParser
    except Exception as exc:
        return ("FAILED", f"Unable to import MergeReport parser: {exc}")

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                event = MergeReportParser.parse_line(raw_line.rstrip("\r\n"))
                if event is None or str(event.sid or "").strip() != sid:
                    continue
                classified = _classify_mergereport_terminal_message(
                    event.message,
                    event.level,
                )
                if classified is not None:
                    return classified
    except FileNotFoundError:
        return ("RUNNING", "")
    except Exception as exc:
        safe_error = redact_text(str(exc) or repr(exc))
        return ("FAILED", f"MergeReport log read failed: {safe_error}")
    return ("RUNNING", "")


def _wait_for_mergereport_sid_result(
    log_path: str,
    sid: str,
    *,
    wait_seconds: int,
    poll_interval: int,
) -> Tuple[str, str, int]:
    wait_budget = max(1, int(wait_seconds))
    deadline = time.monotonic() + wait_budget
    poll_seconds = max(1.0, float(poll_interval))
    start_time = time.monotonic()

    while True:
        state, detail = _scan_mergereport_log_for_sid(log_path, sid)
        if state in ("SUCCESS", "FAILED"):
            return (state, detail, int((time.monotonic() - start_time) * 1000))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_seconds, max(0.0, remaining)))

    return ("TIMEOUT", "", int((time.monotonic() - start_time) * 1000))


def resolve_status_check_timeout_seconds(config: Optional[SplunkConfig]) -> int:
    if (
        config is not None
        and isinstance(config.dispatch_config, dict)
        and "per_slice_wait_seconds" in config.dispatch_config
    ):
        return _parse_min_int(
            config.dispatch_config.get("per_slice_wait_seconds"),
            DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS,
            1,
        )
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_DISPATCH_PER_SLICE_WAIT_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("status_check_timeout_seconds"),
        DEFAULT_STATUS_CHECK_TIMEOUT_SECONDS,
        1,
    )


def resolve_status_check_poll_seconds(config: Optional[SplunkConfig]) -> int:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_POSTDISPATCH_POLL_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("poll_seconds"),
        DEFAULT_POSTDISPATCH_POLL_SECONDS,
        1,
    )


def resolve_broker_request_timeout_seconds(config: Optional[SplunkConfig]) -> int:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("broker_request_timeout_seconds"),
        DEFAULT_BROKER_REQUEST_TIMEOUT_SECONDS,
        1,
    )


def resolve_continue_on_timeout(config: Optional[SplunkConfig]) -> bool:
    if (
        config is None
        or not isinstance(config.dispatch_config, dict)
        or "continue_on_timeout" not in config.dispatch_config
    ):
        return DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT
    return _parse_bool(
        config.dispatch_config.get("continue_on_timeout"),
        DEFAULT_DISPATCH_CONTINUE_ON_TIMEOUT,
    )


def resolve_dispatch_call_timeout_seconds(config: Optional[SplunkConfig]) -> int:
    if (
        config is None
        or not isinstance(config.dispatch_config, dict)
        or "dispatch_call_timeout_seconds" not in config.dispatch_config
    ):
        return DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS
    return _parse_min_int(
        config.dispatch_config.get("dispatch_call_timeout_seconds"),
        DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS,
        1,
    )


def resolve_timeout_result(config: Optional[SplunkConfig]) -> str:
    if (
        config is None
        or not isinstance(config.dispatch_config, dict)
        or "timeout_result" not in config.dispatch_config
    ):
        return _normalize_timeout_result(DEFAULT_DISPATCH_TIMEOUT_RESULT)
    return _normalize_timeout_result(
        config.dispatch_config.get("timeout_result", DEFAULT_DISPATCH_TIMEOUT_RESULT)
    )


def resolve_reconcile_pending(config: Optional[SplunkConfig]) -> bool:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_RECONCILE_PENDING_ENABLED
    return _parse_bool(
        config.postdispatch_config.get("reconcile_pending"),
        DEFAULT_RECONCILE_PENDING_ENABLED,
    )


def resolve_postdispatch_enabled(config: Optional[SplunkConfig]) -> bool:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_POSTDISPATCH_ENABLED
    return _parse_bool(
        config.postdispatch_config.get("enabled"),
        DEFAULT_POSTDISPATCH_ENABLED,
    )


def resolve_primary_slice_mergereport_enabled(config: Optional[SplunkConfig]) -> bool:
    return bool(resolve_merge_report_runtime_settings(config).get("enabled"))


def resolve_reconcile_wait_seconds(config: Optional[SplunkConfig]) -> int:
    if config is None or not isinstance(config.postdispatch_config, dict):
        return DEFAULT_RECONCILE_WAIT_SECONDS
    return _parse_min_int(
        config.postdispatch_config.get("reconcile_wait_seconds"),
        DEFAULT_RECONCILE_WAIT_SECONDS,
        1,
    )


def _resolve_pending_dispatch_status_message(item: RegenSliceRecord) -> str:
    wait_seconds = max(1, int(getattr(item, "dispatch_timeout_seconds", 0) or DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS))
    return (
        f"Dispatch not confirmed within {wait_seconds} seconds before SID was returned. "
        "Awaiting SID from Splunk."
    )


def _harvest_late_dispatch_for_slice(
    item: RegenSliceRecord,
    *,
    run_id: str,
    stage_name: str,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> str:
    correlation_id = str(getattr(item, "dispatch_correlation_id", "") or "").strip()
    if not correlation_id or item.sid:
        return "SKIP"

    harvest = _harvest_pending_dispatch_result(correlation_id, wait_seconds=0.0)
    if harvest.state in ("MISSING", "PENDING"):
        return harvest.state

    if logs is not None:
        _append_log(
            logs,
            (
                f"  [{item.slice_index}/{item.slice_total}] Late dispatch result harvested for "
                f"{item.report_name} {item.slice_label}."
            ) if item.slice_index > 0 and item.slice_total > 0 else (
                f"Late dispatch result harvested for {item.report_name} {item.slice_label}."
            ),
            log_callback,
        )
    _audit_event(
        "REPORT_SLICE_LATE_DISPATCH_HARVESTED",
        level="INFO",
        run_id=run_id,
        report_name=item.report_name,
        slice_label=item.slice_label,
        slice_index=item.slice_index,
        slice_total=item.slice_total,
        correlation_id=correlation_id,
        stage_name=stage_name,
        dispatch_state=harvest.state,
    )

    raw_error = redact_text(str(harvest.error or "") or "")
    if harvest.state == "EXCEPTION" or not harvest.ok or not str(harvest.sid or "").strip():
        failure_detail = raw_error or "Dispatch failed before SID was returned."
        if harvest.state != "EXCEPTION" and harvest.ok and not str(harvest.sid or "").strip():
            failure_detail = "Dispatch returned without a SID after foreground timeout."
        item.status = "FAILED"
        item.outcome_code = "DISPATCH_FAILED"
        item.error = failure_detail
        _set_slice_record_state(
            item,
            lifecycle_state=SLICE_STATE_FAILED_DISPATCH,
            status="FAILED",
            error=failure_detail,
            state_reason=failure_detail,
        )
        _clear_pending_dispatch_attempt(correlation_id)
        if logs is not None:
            _append_log(
                logs,
                (
                    f"  [{item.slice_index}/{item.slice_total}] Late dispatch failed before SID was returned."
                    if item.slice_index > 0 and item.slice_total > 0
                    else f"Late dispatch failed before SID was returned for {item.report_name}."
                ),
                log_callback,
            )
        _audit_event(
            "REPORT_SLICE_LATE_DISPATCH_FAILED",
            level="WARN",
            run_id=run_id,
            report_name=item.report_name,
            slice_label=item.slice_label,
            slice_index=item.slice_index,
            slice_total=item.slice_total,
            correlation_id=correlation_id,
            stage_name=stage_name,
            reason=_short_error(failure_detail),
            error_phase="dispatch",
        )
        return "FAILED"

    item.sid = str(harvest.sid or "").strip()
    _set_slice_record_state(
        item,
        lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
        status="PENDING",
        sid=item.sid,
        outcome_code="PENDING_RECONCILE",
        error=_build_pending_status_message(
            "Dispatch accepted after foreground timeout. Awaiting verification.",
            wait_seconds=max(1, int(getattr(item, "dispatch_timeout_seconds", 0) or DEFAULT_DISPATCH_CALL_TIMEOUT_SECONDS)),
        ),
    )
    _clear_pending_dispatch_attempt(correlation_id)
    if logs is not None:
        _append_log(
            logs,
            (
                f"  [{item.slice_index}/{item.slice_total}] Late SID attached (sid={item.sid}) - awaiting verification."
                if item.slice_index > 0 and item.slice_total > 0
                else f"Late SID attached (sid={item.sid}) - awaiting verification."
            ),
            log_callback,
        )
    _audit_event(
        "REPORT_SLICE_LATE_DISPATCH_SID_ATTACHED",
        level="INFO",
        run_id=run_id,
        report_name=item.report_name,
        slice_label=item.slice_label,
        slice_index=item.slice_index,
        slice_total=item.slice_total,
        correlation_id=correlation_id,
        sid=item.sid,
        stage_name=stage_name,
    )
    return "SID_ATTACHED"


def _finalize_pending_no_sid_dispatches(
    context: RegenContext,
    *,
    log_callback: Optional[Callable[[str], None]] = None,
) -> List[str]:
    logs: List[str] = []
    pending = [
        item
        for item in _pending_slice_records(context)
        if not item.sid and _slice_has_pending_dispatch(item)
    ]
    if not pending:
        return logs

    for item in pending:
        result = _harvest_late_dispatch_for_slice(
            item,
            run_id=context.run_id,
            stage_name="pre_summary",
            logs=logs,
            log_callback=log_callback,
        )
        if result in ("FAILED", "SID_ATTACHED"):
            continue
        item.error = _resolve_pending_dispatch_status_message(item)
        _set_slice_record_state(
            item,
            lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
            status="PENDING",
            error=item.error,
        )
        _append_user_slice_status(
            logs,
            slice_index=item.slice_index,
            slice_total=item.slice_total,
            report_name=item.report_name,
            earliest=item.earliest,
            latest=item.latest,
            status=item.status,
            pending_detail_mode="dispatch_unconfirmed",
            log_callback=log_callback,
        )
        _audit_event(
            "REPORT_PENDING_NO_SID_RECONCILIATION_EXHAUSTED",
            level="WARN",
            run_id=context.run_id,
            report_name=item.report_name,
            slice_label=item.slice_label,
            slice_index=item.slice_index,
            slice_total=item.slice_total,
            correlation_id=item.dispatch_correlation_id,
            error_phase="dispatch",
        )
        _clear_pending_dispatch_attempt(item.dispatch_correlation_id)

    return logs


def _pending_slice_records(context: RegenContext) -> List[RegenSliceRecord]:
    return [item for item in context.slices if _is_pending_status(item.status)]


def _fetch_job_status_snapshot(
    client: SplunkClient,
    sid: str,
    *,
    request_timeout_seconds: int,
    poll_interval: int,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
    audit_event: Optional[Callable[..., None]] = None,
    slice_label: str = "",
    slice_index: int = 0,
    slice_total: int = 0,
    batch_id: str = "",
    slice_id: str = "",
    attempt_id: int = 0,
    correlation_tag: str = "",
) -> Tuple[str, dict]:
    if hasattr(client, "get_job_status_snapshot"):
        return _call_snapshot_with_retry(
            client,
            sid,
            request_timeout_seconds=max(1, int(request_timeout_seconds)),
            max_total_timeout_seconds=max(1, int(request_timeout_seconds)),
            retry_count=DEFAULT_STATUS_SNAPSHOT_TIMEOUT_RETRIES,
            stage_name="reconciliation",
            logs=logs,
            log_callback=log_callback,
            audit_event=audit_event,
            slice_label=slice_label,
            slice_index=slice_index,
            slice_total=slice_total,
            batch_id=batch_id,
            slice_id=slice_id,
            attempt_id=attempt_id,
            correlation_tag=correlation_tag,
        )
    return client.check_job_status(
        sid,
        wait_seconds=max(1, int(request_timeout_seconds)),
        poll_interval=max(1, int(poll_interval)),
    )


def _reconcile_pending_slices(
    client: SplunkClient,
    context: RegenContext,
    *,
    wait_seconds: int,
    poll_interval: int,
    prefer_merge_report_verification: bool = False,
    merge_report_log_path: str = "",
    merge_report_settings: Optional[dict[str, Any]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> List[str]:
    logs: List[str] = []

    def _persist_reconcile_state(reason: str) -> None:
        _persist_batch_journal(context, reason=reason)

    pending = list(_pending_slice_records(context))
    if not pending:
        return logs

    _append_log(
        logs,
        (
            f"Starting pending reconciliation for {len(pending)} slice(s). "
            f"Budget={max(1, int(wait_seconds))} seconds."
        ),
        log_callback,
    )
    _audit_event(
        "REPORT_PENDING_RECONCILIATION_STARTED",
        level="INFO",
        run_id=context.run_id,
        pending_slices=len(pending),
        wait_seconds=max(1, int(wait_seconds)),
    )

    unresolved = list(pending)
    deadline = time.monotonic() + max(1, int(wait_seconds))
    poll_seconds = max(1, int(poll_interval))

    while unresolved and time.monotonic() < deadline:
        next_unresolved: List[RegenSliceRecord] = []
        for item in unresolved:
            if _pending_expired(item):
                _set_slice_record_state(
                    item,
                    lifecycle_state=SLICE_STATE_EXPIRED,
                    status="EXPIRED",
                    outcome_code="EXPIRED",
                    error=item.error or "Pending reconciliation window expired.",
                )
                _persist_reconcile_state("pending_expired")
                _append_user_slice_status(
                    logs,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    report_name=item.report_name,
                    earliest=item.earliest,
                    latest=item.latest,
                    status="EXPIRED",
                    log_callback=log_callback,
                )
                _audit_event(
                    "REPORT_PENDING_EXPIRED",
                    level="WARN",
                    run_id=context.run_id,
                    sid=item.sid,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                )
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                next_unresolved.append(item)
                continue
            if not item.sid and _slice_has_pending_dispatch(item):
                harvest_result = _harvest_late_dispatch_for_slice(
                    item,
                    run_id=context.run_id,
                    stage_name="reconciliation",
                    logs=logs,
                    log_callback=log_callback,
                )
                if harvest_result == "FAILED":
                    _append_user_slice_status(
                        logs,
                        slice_index=item.slice_index,
                        slice_total=item.slice_total,
                        report_name=item.report_name,
                        earliest=item.earliest,
                        latest=item.latest,
                        status="FAILED",
                        log_callback=log_callback,
                    )
                    continue
            if not item.sid:
                identity = _parse_saved_search_identity(
                    item.dispatch_report_id_url,
                    item.report_name,
                    default_app=item.report_app,
                    default_owner=item.report_owner or str(getattr(client, "username", "") or "").strip(),
                )
                temp_context = SliceExecutionContext(
                    client=client,
                    run_id=context.run_id,
                    batch_id=item.batch_id or context.batch_id,
                    slice_id=item.slice_id,
                    attempt_id=max(1, int(item.attempt_id or 1)),
                    report_id_url=item.dispatch_report_id_url,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    earliest_display=item.earliest,
                    latest_display=item.latest,
                    dispatch_earliest=item.dispatch_earliest or None,
                    dispatch_latest=item.dispatch_latest or None,
                    dispatch_timeout_seconds=max(1, int(item.dispatch_timeout_seconds or DISPATCH_TIMEOUT_SECONDS)),
                    snapshot_timeout_seconds=SNAPSHOT_TIMEOUT_SECONDS,
                    retry_count=max(0, int(item.retry_count or 0)),
                    sid=item.sid,
                    dispatch_correlation_id=item.dispatch_correlation_id,
                    reconcile_pass_count=max(1, int(item.reconcile_pass_count or 0)),
                    correlation_tag=item.correlation_tag,
                    correlation_mode=item.correlation_mode,
                    report_owner=item.report_owner,
                    report_app=item.report_app,
                    verification_mode=item.verification_mode,
                    reconciliation_confidence=item.reconciliation_confidence,
                    reconciliation_matched_fields=item.reconciliation_matched_fields,
                    reconciliation_decision_reason=item.reconciliation_decision_reason,
                )
                evidence = _find_reconcile_evidence(
                    client,
                    context=temp_context,
                    identity=identity,
                    logs=logs,
                    log_callback=log_callback,
                    audit_event=lambda event, **fields: _audit_event(
                        event,
                        run_id=context.run_id,
                        report_name=item.report_name,
                        **fields,
                    ),
                    pass_name="pending_reconciliation",
                    prefer_merge_report_verification=prefer_merge_report_verification,
                    merge_report_log_path=merge_report_log_path,
                    merge_report_settings=merge_report_settings,
                )
                if evidence.confidence == "strong" and evidence.sid:
                    item.sid = evidence.sid
                    matched_fields = _matched_fields_text(evidence.matched_fields)
                    decision_reason = str(evidence.decision_reason or evidence.detail or "").strip()
                    temp_context.reconciliation_confidence = evidence.confidence
                    temp_context.reconciliation_matched_fields = matched_fields
                    temp_context.reconciliation_decision_reason = decision_reason
                    _emit_reconciliation_decision(
                        logs=logs,
                        log_callback=log_callback,
                        audit_event=lambda event, **fields: _audit_event(
                            event,
                            run_id=context.run_id,
                            report_name=item.report_name,
                            **fields,
                        ),
                        context=temp_context,
                        pass_name="pending_reconciliation",
                        evidence=evidence,
                        decision="attach_sid_from_reconciliation",
                    )
                    _set_slice_record_state(
                        item,
                        lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
                        status="PENDING",
                        sid=evidence.sid,
                        outcome_code="PENDING_RECONCILE",
                        reconciliation_source=evidence.source,
                        finalized_from_reconciliation=True,
                        reconciliation_confidence=evidence.confidence,
                        reconciliation_matched_fields=matched_fields,
                        reconciliation_decision_reason=decision_reason,
                    )
                    _persist_reconcile_state("pending_sid_evidence_attached")
                elif evidence.confidence in {"weak", "conflict"}:
                    matched_fields = _matched_fields_text(evidence.matched_fields)
                    decision_reason = str(evidence.decision_reason or evidence.detail or "").strip()
                    temp_context.reconciliation_confidence = evidence.confidence
                    temp_context.reconciliation_matched_fields = matched_fields
                    temp_context.reconciliation_decision_reason = decision_reason
                    _emit_reconciliation_decision(
                        logs=logs,
                        log_callback=log_callback,
                        audit_event=lambda event, **fields: _audit_event(
                            event,
                            run_id=context.run_id,
                            report_name=item.report_name,
                            **fields,
                        ),
                        context=temp_context,
                        pass_name="pending_reconciliation",
                        evidence=evidence,
                        decision="keep_pending_due_to_ambiguous_evidence",
                    )
                    _set_slice_record_state(
                        item,
                        lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
                        status="PENDING",
                        sid=evidence.sid or item.sid,
                        outcome_code="PENDING_RECONCILE_EVIDENCE",
                        error=item.error or "Pending reconciliation retained due to ambiguous existing evidence.",
                        reconciliation_source=evidence.source,
                        reconciliation_confidence=evidence.confidence,
                        reconciliation_matched_fields=matched_fields,
                        reconciliation_decision_reason=decision_reason,
                    )
                    _persist_reconcile_state("pending_ambiguous_evidence")
                    next_unresolved.append(item)
                    continue
                if not item.sid:
                    next_unresolved.append(item)
                    continue
            if prefer_merge_report_verification and item.sid:
                merge_state, merge_payload = _check_merge_report_preferred_evidence(
                    client,
                    sid=item.sid,
                    prefer_merge_report_verification=prefer_merge_report_verification,
                    merge_report_log_path=merge_report_log_path,
                    merge_report_timeout_seconds=int(
                        (merge_report_settings or {}).get("timeout_seconds", DEFAULT_MERGEREPORT_TIMEOUT_SECONDS)
                    ),
                    merge_report_settings=merge_report_settings,
                    stage_name="pending_reconciliation",
                    logs=logs,
                    log_callback=log_callback,
                    query_timeout_seconds=EVIDENCE_HTTP_READ_TIMEOUT_SECONDS,
                    saved_search_context={
                        "report_id_url": item.dispatch_report_id_url,
                        "report_name": item.report_name,
                        "report_owner": item.report_owner or str(getattr(client, "username", "") or "").strip(),
                        "report_app": item.report_app or context.app,
                    },
                )
                merge_detail = str(merge_payload.get("detail", "") or "").strip()
                merge_source = str(merge_payload.get("source", "merge_report") or "merge_report").strip()
                if merge_state == "SUCCESS":
                    _append_log(
                        logs,
                        (
                            f"[Debug] MERGEREPORT_RECONCILIATION_RESULT sid={item.sid} "
                            f"state=SUCCESS source={merge_source} decision=resolved_ok"
                        ),
                        log_callback,
                    )
                    _set_slice_record_state(
                        item,
                        lifecycle_state=SLICE_STATE_SUCCESS,
                        status="OK",
                        outcome_code="RECONCILED_OK_MERGEREPORT",
                        error="",
                        finalized_from_reconciliation=True,
                        reconciliation_source=f"merge_report_{merge_source}",
                        reconciliation_confidence=item.reconciliation_confidence or "strong",
                    )
                    _persist_reconcile_state("pending_resolved_merge_report_ok")
                    _append_user_slice_status(
                        logs,
                        slice_index=item.slice_index,
                        slice_total=item.slice_total,
                        report_name=item.report_name,
                        earliest=item.earliest,
                        latest=item.latest,
                        status="OK",
                        log_callback=log_callback,
                    )
                    _audit_event(
                        "REPORT_PENDING_RESOLVED_OK_MERGEREPORT",
                        level="INFO",
                        run_id=context.run_id,
                        sid=item.sid,
                        report_name=item.report_name,
                        slice_label=item.slice_label,
                        slice_index=item.slice_index,
                        slice_total=item.slice_total,
                        verification_source=f"merge_report_{merge_source}",
                    )
                    continue
                if merge_state == "FAILED":
                    failure_detail = merge_detail or "MergeReport reported an explicit failure marker."
                    _append_log(
                        logs,
                        (
                            f"[Debug] MERGEREPORT_RECONCILIATION_RESULT sid={item.sid} "
                            f"state=FAILED source={merge_source} decision=resolved_failed "
                            f"detail={_short_error(redact_text(failure_detail))}"
                        ),
                        log_callback,
                    )
                    _set_slice_record_state(
                        item,
                        lifecycle_state=SLICE_STATE_FAILED_VERIFICATION,
                        status="FAILED",
                        outcome_code="RECONCILED_FAILED_MERGEREPORT",
                        error=failure_detail,
                        finalized_from_reconciliation=True,
                        reconciliation_source=f"merge_report_{merge_source}",
                        reconciliation_confidence=item.reconciliation_confidence or "strong",
                    )
                    _persist_reconcile_state("pending_resolved_merge_report_failed")
                    _append_user_slice_status(
                        logs,
                        slice_index=item.slice_index,
                        slice_total=item.slice_total,
                        report_name=item.report_name,
                        earliest=item.earliest,
                        latest=item.latest,
                        status="FAILED",
                        log_callback=log_callback,
                    )
                    _audit_event(
                        "REPORT_PENDING_RESOLVED_FAILED_MERGEREPORT",
                        level="WARN",
                        run_id=context.run_id,
                        sid=item.sid,
                        report_name=item.report_name,
                        slice_label=item.slice_label,
                        slice_index=item.slice_index,
                        slice_total=item.slice_total,
                        reason=_short_error(failure_detail),
                        error_phase="reconciliation",
                        verification_source=f"merge_report_{merge_source}",
                    )
                    continue
            request_timeout = min(max(1, poll_seconds), max(1, int(remaining)))
            try:
                state, info = _fetch_job_status_snapshot(
                    client,
                    item.sid,
                    request_timeout_seconds=request_timeout,
                    poll_interval=poll_seconds,
                    logs=logs,
                    log_callback=log_callback,
                    audit_event=lambda event, **fields: _audit_event(
                        event,
                        run_id=context.run_id,
                        report_name=item.report_name,
                        **fields,
                    ),
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    batch_id=item.batch_id,
                    slice_id=item.slice_id,
                    attempt_id=item.attempt_id,
                    correlation_tag=item.correlation_tag,
                )
            except Exception as exc:
                raw_error = str(exc) or repr(exc)
                safe_msg = _short_error(redact_text(raw_error))
                error_type = type(exc).__name__
                broker_op, broker_timeout = _extract_broker_context(exc=exc, text=raw_error)
                _audit_event(
                    "REPORT_PENDING_RECONCILIATION_CHECK_FAILED",
                    level="WARN",
                    run_id=context.run_id,
                    sid=item.sid,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    reason=safe_msg,
                    error_type=error_type,
                    error_phase="reconciliation",
                    broker_op=broker_op if broker_op else None,
                    timeout_seconds=broker_timeout,
                )
                next_unresolved.append(item)
                continue

            if state == "SUCCESS":
                _set_slice_record_state(
                    item,
                    lifecycle_state=SLICE_STATE_SUCCESS,
                    status="OK",
                    outcome_code="RECONCILED_OK",
                    error="",
                    finalized_from_reconciliation=True,
                    reconciliation_source=item.reconciliation_source or "search_jobs",
                )
                _persist_reconcile_state("pending_resolved_ok")
                _append_user_slice_status(
                    logs,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    report_name=item.report_name,
                    earliest=item.earliest,
                    latest=item.latest,
                    status="OK",
                    log_callback=log_callback,
                )
                _audit_event(
                    "REPORT_PENDING_RESOLVED_OK",
                    level="INFO",
                    run_id=context.run_id,
                    sid=item.sid,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                )
                continue

            if state == "FAILED":
                dispatch_state = str(info.get("dispatchState", "Unknown error") or "Unknown error")
                _set_slice_record_state(
                    item,
                    lifecycle_state=SLICE_STATE_FAILED_VERIFICATION,
                    status="FAILED",
                    outcome_code="RECONCILED_FAILED",
                    error=dispatch_state,
                    finalized_from_reconciliation=True,
                    reconciliation_source=item.reconciliation_source or "search_jobs",
                )
                _persist_reconcile_state("pending_resolved_failed")
                _append_user_slice_status(
                    logs,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    report_name=item.report_name,
                    earliest=item.earliest,
                    latest=item.latest,
                    status="FAILED",
                    log_callback=log_callback,
                )
                _audit_event(
                    "REPORT_PENDING_RESOLVED_FAILED",
                    level="WARN",
                    run_id=context.run_id,
                    sid=item.sid,
                    report_name=item.report_name,
                    slice_label=item.slice_label,
                    slice_index=item.slice_index,
                    slice_total=item.slice_total,
                    reason=_short_error(dispatch_state),
                    error_phase="reconciliation",
                )
                continue

            next_unresolved.append(item)

        unresolved = next_unresolved
        if unresolved:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(float(poll_seconds), max(0.0, remaining)))

    for item in unresolved:
        if _pending_expired(item):
            _set_slice_record_state(
                item,
                lifecycle_state=SLICE_STATE_EXPIRED,
                status="EXPIRED",
                outcome_code="EXPIRED",
                error=item.error or "Pending reconciliation window expired.",
            )
            _persist_reconcile_state("pending_expired")
            _append_user_slice_status(
                logs,
                slice_index=item.slice_index,
                slice_total=item.slice_total,
                report_name=item.report_name,
                earliest=item.earliest,
                latest=item.latest,
                status="EXPIRED",
                log_callback=log_callback,
            )
            _audit_event(
                "REPORT_PENDING_EXPIRED",
                level="WARN",
                run_id=context.run_id,
                sid=item.sid,
                report_name=item.report_name,
                slice_label=item.slice_label,
                slice_index=item.slice_index,
                slice_total=item.slice_total,
            )
            continue
        pending_detail_mode = ""
        event_name = "REPORT_PENDING_REMAINED_UNRESOLVED"
        if not item.sid and _slice_has_pending_dispatch(item):
            pending_detail_mode = "dispatch_unconfirmed"
            item.error = _resolve_pending_dispatch_status_message(item)
            event_name = "REPORT_PENDING_NO_SID_RECONCILIATION_EXHAUSTED"
        else:
            pending_detail_mode = "pending_reconcile"
        _set_slice_record_state(
            item,
            lifecycle_state=SLICE_STATE_PENDING_RECONCILE,
            status="PENDING",
            error=item.error,
        )
        _persist_reconcile_state("pending_unresolved")
        _append_user_slice_status(
            logs,
            slice_index=item.slice_index,
            slice_total=item.slice_total,
            report_name=item.report_name,
            earliest=item.earliest,
            latest=item.latest,
            status=item.status,
            pending_detail_mode=pending_detail_mode,
            log_callback=log_callback,
        )
        _audit_event(
            event_name,
            level="WARN",
            run_id=context.run_id,
            sid=item.sid,
            report_name=item.report_name,
            slice_label=item.slice_label,
            slice_index=item.slice_index,
            slice_total=item.slice_total,
            correlation_id=item.dispatch_correlation_id if not item.sid else None,
            error_phase="reconciliation",
        )

    return logs


def _format_slice_summary_line(item: RegenSliceRecord) -> str:
    range_text = _slice_range_text(item.earliest, item.latest)
    sid_text = f" (sid={item.sid})" if item.sid else ""
    status_label = _display_slice_status(item.status)
    state_label = _normalize_slice_state(getattr(item, "lifecycle_state", ""))
    line = f"  [{status_label}] {item.report_name} {item.slice_label}: {range_text}{sid_text}"
    if state_label and state_label not in {"", status_label}:
        line += f" state={state_label}"
    if status_label != "OK" and item.error:
        line += f" - {_short_error(item.error)}"
    return line


def _format_slice_user_summary_line(item: RegenSliceRecord) -> str:
    range_text = _slice_range_text(item.earliest, item.latest)
    prefix = (
        f"[{item.slice_index}/{item.slice_total}]"
        if item.slice_index > 0 and item.slice_total > 0
        else "[Report]"
    )
    normalized = str(item.status or "").strip().upper()
    state_label = _normalize_slice_state(getattr(item, "lifecycle_state", ""))
    retry_suffix = " Retried once." if int(getattr(item, "retry_count", 0) or 0) > 0 else ""
    if normalized == "EXPIRED" or state_label == SLICE_STATE_EXPIRED:
        return f"  {prefix} Pending reconciliation expired. Report: {item.report_name}. Time range: {range_text}"
    if normalized == "OK":
        if bool(getattr(item, "finalized_from_reconciliation", False)):
            return f"  {prefix} Finalized from reconciliation. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"
        return f"  {prefix} Email report sent successfully. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"
    if _is_pending_status(normalized):
        if state_label == SLICE_STATE_PENDING_RECONCILE:
            return f"  {prefix} Pending reconciliation. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"
        if item.sid:
            return f"  {prefix} Report dispatched and is awaiting verification. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"
        if _slice_has_pending_dispatch(item):
            return f"  {prefix} Dispatch not yet confirmed; awaiting SID from Splunk. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"
        return f"  {prefix} Dispatch not yet confirmed. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"
    if state_label == SLICE_STATE_FAILED_DISPATCH or str(item.outcome_code or "").strip().upper() == "DISPATCH_FAILED":
        return f"  {prefix} Dispatch failed before verification. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"
    return f"  {prefix} Sending of email failed. Report: {item.report_name}. Time range: {range_text}{retry_suffix}"


def _build_run_summary_lines(context: RegenContext) -> List[str]:
    ok_count, fail_count, pending_count = context.summary_counts()
    lines = [
        "Summary:",
        f"  Total slices: {len(context.slices)}",
        f"  Succeeded: {ok_count}",
        f"  Failed: {fail_count}",
        f"  Pending: {pending_count}",
    ]
    for item in context.slices:
        lines.append(_format_slice_user_summary_line(item))
    if pending_count:
        lines.append("  One or more reports remain pending reconciliation.")
        lines.append("  Splunk may still complete pending jobs asynchronously, or the pending window may later expire.")
    return lines


def _context_started_processing(context: Optional[RegenContext]) -> bool:
    if context is None:
        return False
    started_states = {
        SLICE_STATE_DISPATCHING,
        SLICE_STATE_DISPATCHED,
        SLICE_STATE_VERIFYING,
        SLICE_STATE_SUCCESS,
        SLICE_STATE_FAILED_DISPATCH,
        SLICE_STATE_FAILED_VERIFICATION,
        SLICE_STATE_TIMEOUT_UNCERTAIN,
        SLICE_STATE_PENDING_RECONCILE,
        SLICE_STATE_EXPIRED,
    }
    return any(_normalize_slice_state(item.lifecycle_state) in started_states for item in context.slices)


def _context_has_evidence_warning(context: RegenContext) -> bool:
    for item in context.slices:
        if str(item.status or "").strip().upper() != "OK":
            continue
        evidence_outcome = str(item.evidence_outcome or "").strip().upper()
        if evidence_outcome in {"NONE", "PENDING", "AMBIGUOUS", "UNKNOWN"}:
            return True
    return False


def _operator_reference_lines(batch_id: str) -> List[str]:
    return [f"Reference ID: {str(batch_id or '').strip() or 'unknown-batch'}"]


def _operator_final_message_lines(
    *,
    batch_id: str,
    outcome: str,
) -> List[str]:
    safe_batch_id = str(batch_id or "").strip() or "unknown-batch"
    normalized = str(outcome or "").strip().lower()
    if normalized == "success":
        return [
            "Report generation completed successfully.",
            "All reports have been sent.",
            "",
            f"Reference ID: {safe_batch_id}",
        ]
    if normalized == "connectivity_prestart":
        return [
            "Unable to connect to Splunk services.",
            "The report could not be started.",
            "",
            "Please contact the Splunk team and provide:",
            f"Reference ID: {safe_batch_id}",
        ]
    if normalized == "could_not_start":
        return [
            "The report could not be started.",
            "",
            "Please contact the Splunk team and provide:",
            f"Reference ID: {safe_batch_id}",
        ]
    if normalized == "pending_verification":
        return [
            "Report processing completed, but final verification is still pending.",
            "",
            f"Reference ID: {safe_batch_id}",
        ]
    if normalized == "evidence_warning":
        return [
            "Reports were generated, but evidence confirmation could not be fully completed.",
            "",
            "Please verify manually or contact the Splunk team and provide:",
            f"Reference ID: {safe_batch_id}",
        ]
    return [
        "Report completed with issues.",
        "Some reports may not have been generated or sent.",
        "",
        "Please contact the Splunk team and provide:",
        f"Reference ID: {safe_batch_id}",
    ]


def _classify_batch_exception(exc: Exception, context: Optional[RegenContext]) -> str:
    if isinstance(exc, _INTERNAL_RUNTIME_EXCEPTION_TYPES):
        return "internal_runtime_error"
    raw_error = redact_text(str(exc) or repr(exc))
    if "internal_runtime_error" in raw_error.lower():
        return "internal_runtime_error"
    if not _context_started_processing(context):
        if _looks_like_connectivity_failure(raw_error):
            return "connectivity_prestart"
        return "could_not_start"
    return "partial_success"


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


def _resolve_mergereport_saved_search_namespace(
    *,
    report_id_url: str,
    report_name: str,
    report_app: str,
    report_owner: str,
) -> dict[str, str]:
    raw_path = urlparse(str(report_id_url or "")).path
    parts = raw_path.strip("/").split("/") if raw_path else []
    raw_is_saved_search_path = bool(
        len(parts) >= 6 and parts[0] == "servicesNS" and parts[3] == "saved" and parts[4] == "searches"
    )
    if raw_is_saved_search_path:
        owner = str(parts[1] or "").strip()
        app = str(parts[2] or "").strip()
        name = str(report_name or unquote(parts[5]) or "").strip()
    else:
        identity = _parse_saved_search_identity(
            report_id_url,
            report_name,
            default_app=report_app,
            default_owner=report_owner,
        )
        owner = str(identity.owner or report_owner or "").strip()
        app = str(identity.app or report_app or "").strip()
        name = str(identity.name or report_name or "").strip()
    candidate_paths = _build_saved_search_candidate_paths(
        report_id_url=report_id_url,
        report_name=name,
        app=app,
        username=owner,
    )
    resolved_path = raw_path if raw_is_saved_search_path else (candidate_paths[0] if candidate_paths else raw_path)
    resolution_source = "exact_namespace_path" if raw_is_saved_search_path else "generated_fallback"
    return {
        "owner": owner,
        "app": app,
        "report_name": name,
        "saved_search_path": str(resolved_path or "").strip(),
        "resolution_source": resolution_source,
    }


def _collect_saved_search_recipients(
    client: SplunkClient,
    report_id_url: str,
    report_name: str,
    app: str,
    username: str,
    *,
    logs: Optional[List[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> List[str]:
    recipients: List[str] = []
    candidate_paths = _build_saved_search_candidate_paths(
        report_id_url=report_id_url,
        report_name=report_name,
        app=app,
        username=username,
    )

    for path in candidate_paths:
        call_started_utc = _utc_now_iso()
        call_start = time.monotonic()
        _emit_broker_call_log(
            logs=logs,
            log_callback=log_callback,
            audit_event=None,
            event="BROKER_CALL_ENTER",
            op="get_saved_search_metadata",
            slice_label="pre-dispatch",
            started_utc=call_started_utc,
        )
        try:
            get_fn = getattr(client, "_get")
            get_kwargs: dict[str, Any] = {}
            if _dispatch_call_supports_keyword(get_fn, "timeout"):
                get_kwargs["timeout"] = METADATA_HTTP_READ_TIMEOUT_SECONDS
            if _dispatch_call_supports_keyword(get_fn, "connect_timeout_seconds"):
                get_kwargs["connect_timeout_seconds"] = METADATA_HTTP_CONNECT_TIMEOUT_SECONDS
            meta = get_fn(path, **get_kwargs)
            entries = meta.get("entry", [])
            _emit_broker_call_log(
                logs=logs,
                log_callback=log_callback,
                audit_event=None,
                event="BROKER_CALL_EXIT",
                op="get_saved_search_metadata",
                slice_label="pre-dispatch",
                started_utc=call_started_utc,
                ended_utc=_utc_now_iso(),
                elapsed_ms=int((time.monotonic() - call_start) * 1000),
                outcome="returned" if entries else "returned_empty",
            )
            _record_recent_metadata_activity(
                client,
                outcome="returned" if entries else "returned_empty",
                elapsed_ms=int((time.monotonic() - call_start) * 1000),
                path=path,
            )
            if not entries:
                continue
            content = entries[0].get("content", {})
            recipients.extend(_extract_recipients_from_content(content))
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - call_start) * 1000)
            metadata_outcome = "timeout_metadata_fetch" if _error_looks_like_timeout(str(exc) or repr(exc)) else "failed_metadata_fetch"
            _emit_broker_call_log(
                logs=logs,
                log_callback=log_callback,
                audit_event=None,
                event="BROKER_CALL_EXIT",
                op="get_saved_search_metadata",
                slice_label="pre-dispatch",
                started_utc=call_started_utc,
                ended_utc=_utc_now_iso(),
                elapsed_ms=elapsed_ms,
                outcome="timeout" if _error_looks_like_timeout(str(exc) or repr(exc)) else "exception",
                error_detail=str(exc) or repr(exc),
            )
            _record_recent_metadata_activity(
                client,
                outcome=metadata_outcome,
                elapsed_ms=elapsed_ms,
                path=path,
                error_detail=str(exc) or repr(exc),
            )
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


def _resolve_ack_on_pending(config: Optional[SplunkConfig]) -> bool:
    if config is None:
        return False
    return bool(getattr(config, "ack_on_pending", False) or getattr(config, "ack_on_unknown", False))


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
    default_from = "Splunk Notification <noreply@example.com>"
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
    overall_status = context.overall_status()
    status_prefix = f"{overall_status} | " if overall_status != "OK" else ""
    return (
        f"*** MANUALLY REGENERATED *** {status_prefix}{report_label} | "
        f"{context.earliest_configured} to {context.latest_configured} | "
        f"{format_sgt(run_time)}"
    )
def _build_ack_body(context: RegenContext) -> str:
    generated_at = context.end_time_sgt or context.start_time_sgt or get_sgt_now()
    ok_count, fail_count, pending_count = context.summary_counts()
    total = len(context.slices)
    slices_with_sid = [item for item in context.slices if item.sid]
    failed_slices = [
        item for item in context.slices if str(item.status or "").strip().upper() in {"FAILED", "EXPIRED"}
    ]
    pending_slices = [item for item in context.slices if _is_pending_status(item.status)]
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
        f"  - Overall status: {context.overall_status()}",
        f"  - Total slices: {total}",
        f"  - Succeeded: {ok_count}",
        f"  - Failed: {fail_count}",
        f"  - Pending: {pending_count}",
    ]
    if context.slicing_enabled and context.slices:
        body_lines.append("  - Per-slice ranges:")
        for item in context.slices:
            body_lines.append(f"    * {_format_slice_summary_line(item).strip()}")
    if failed_slices:
        body_lines.append("  - Failed slices:")
        for item in failed_slices:
            body_lines.append(
                f"    * {item.report_name} {item.slice_label}: {_short_error(item.error or 'Unknown error')}"
            )
    if pending_slices:
        body_lines.append("  - Pending / awaiting verification:")
        for item in pending_slices:
            body_lines.append(
                f"    * {item.report_name} {item.slice_label}: {_short_error(item.error or 'Final status not yet known')}"
            )
        body_lines.append("  - Splunk may still complete pending jobs asynchronously.")
    body_lines.append("")
    body_lines.append("SIDs issued by dispatch:")
    if slices_with_sid:
        for item in slices_with_sid:
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
    ack_on_pending = _resolve_ack_on_pending(config)
    recipients = _resolve_ack_recipients(context, config) if ack_enabled else []
    _, fail_count, pending_count = context.summary_counts()
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
            "ACK_EMAIL_SKIPPED_DISABLED",
            level="WARN",
            run_id=context.run_id,
            recipient_count=0,
            reason="ack_disabled",
            error_type="ack_disabled",
            error_phase="ack_decision",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            reason="ack_disabled",
        )
    if pending_count > 0 and not ack_on_pending:
        _audit_event(
            "ACK_EMAIL_SKIPPED_PENDING",
            level="WARN",
            run_id=context.run_id,
            recipient_count=len(recipients),
            pending_slices=pending_count,
            reason="pending_slices_present",
            error_type="pending_slices_present",
            error_phase="ack_decision",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            recipients=recipients,
            reason="pending_slices_present",
        )
    if not recipients:
        _audit_event(
            "EMAIL_SEND_FAILED",
            level="WARN",
            run_id=context.run_id,
            recipient_count=0,
            reason="no_recipients",
            error_type="no_recipients",
            error_phase="ack_decision",
        )
        return AckEmailResult(
            attempted=False,
            success=False,
            reason="no_recipients",
        )
    smtp_settings = _resolve_smtp_settings(config)
    subject = _build_ack_subject(context)
    body = _build_ack_body(context)
    if pending_count > 0:
        _audit_event(
            "ACK_EMAIL_SENT_PENDING",
            level="INFO",
            run_id=context.run_id,
            recipient_count=len(recipients),
            pending_slices=pending_count,
            failed_slices=fail_count,
        )
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
            reason="pending_verification" if pending_count > 0 else "",
        )
    except Exception as exc:
        _audit_event(
            "EMAIL_SEND_FAILED",
            level="ERROR",
            run_id=context.run_id,
            recipient_count=len(recipients),
            reason="smtp_send_failed",
            error_type=type(exc).__name__,
            error_phase="email_send",
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
    regen_context: Optional[RegenContext] = None
    logs: List[str] = []
    merge_report_settings = resolve_merge_report_runtime_settings(config)
    try:
        if not selected_indices:
            raise ValueError("No reports selected.")
        selected_report_names = [report_names[i] for i in selected_indices]
        selected_report_ids = [report_ids[i] for i in selected_indices]
        start_time_sgt = get_sgt_now()
        if no_change:
            slices_per_report = 1
            mode_description = "single run"
        else:
            starts, _ = build_slices(start, end, frequency)
            slices_per_report = len(starts)
            mode_description = f"{frequency.lower()} slices: {slices_per_report}"
        batch_id = f"batch-{start_time_sgt.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
        regen_context = RegenContext(
            run_id=f"regen-{start_time_sgt.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}",
            batch_id=batch_id,
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
            correlation_mode=CORRELATION_MODE_SPLUNK_UI_CONTEXT_BEST_EFFORT,
        )
        _append_log(logs, "Starting report generation...", log_callback)
        for line in _operator_reference_lines(batch_id):
            _append_log(logs, line, log_callback)
        regen_context.journal_path = batch_journal_path(batch_id)
        regen_context.lock_key = _compute_overlap_lock_key(
            report_ids=selected_report_ids,
            frequency=frequency,
            start=start,
            end=end,
            no_change=no_change,
        )
        unfinished = list_unfinished_journals()
        if unfinished:
            for payload in unfinished:
                lines = _recoverable_batch_lines(payload)
                regen_context.recovery_notices.extend(lines)
                for line in lines:
                    _append_log(logs, line, log_callback)
            _append_log(
                logs,
                "Recovery path: inspect the unfinished batch journal and reconcile or verify status before rerunning overlapping work.",
                log_callback,
            )
            _audit_event(
                "REPORT_RECOVERY_JOURNALS_FOUND",
                level="WARN",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                journal_count=len(unfinished),
            )
        lock_ok, lock_payload, lock_path = acquire_overlap_lock(
            regen_context.lock_key,
            regen_context.batch_id,
            {
                "journal_path": regen_context.journal_path,
                "report_names": list(selected_report_names),
                "app": app,
                "earliest": regen_context.earliest_configured,
                "latest": regen_context.latest_configured,
                "mode_description": mode_description,
                "started_utc": _utc_now_iso(),
            },
        )
        regen_context.lock_path = lock_path
        if lock_ok and isinstance(lock_payload, dict) and bool(lock_payload.get("_stale_lock_recovered")):
            stale_reason = str(lock_payload.get("_stale_lock_reason", "") or "").strip() or "unknown_reason"
            _append_log(
                logs,
                f"[Debug] STALE_OVERLAP_LOCK_RECOVERED batch_id={regen_context.batch_id} reason={stale_reason}",
                log_callback,
            )
            _audit_event(
                "REPORT_OVERLAP_LOCK_STALE_RECOVERED",
                level="WARN",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                stale_reason=stale_reason,
            )
        if not lock_ok:
            for line in _recoverable_batch_lines(lock_payload):
                _append_log(logs, line, log_callback)
            _append_log(
                logs,
                "Blocked by overlap lock. Another overlapping local batch is still active for this report/window.",
                log_callback,
            )
            raise RuntimeError(
                "Another overlapping local batch is still active. Inspect the existing journal and reconcile or wait before rerunning the same report/window."
            )
        _persist_batch_journal(regen_context, reason="batch_created")
        stale_dispatch_entries = _clear_pending_dispatch_attempts_for_run(clear_all=True)
        if stale_dispatch_entries > 0:
            _append_log(
                logs,
                f"[Debug] RUN_SCOPED_PENDING_DISPATCH_RESET cleared_entries={stale_dispatch_entries}",
                log_callback,
            )
        _append_log(
            logs,
            (
                f"[Debug] MERGEREPORT_CONFIG_NORMALIZED enabled={bool(merge_report_settings.get('enabled'))} "
                f"source_preference={merge_report_settings.get('source_preference', 'none')} "
                f"local_path={str(merge_report_settings.get('requested_log_path', '') or '(blank)')} "
                f"local_file_available={bool(merge_report_settings.get('local_file_available'))} "
                f"index={merge_report_settings.get('index', '_internal')} "
                f"source_contains={merge_report_settings.get('source_contains', 'mergeReport_alert.log')}"
            ),
            log_callback,
        )
        if bool(merge_report_settings.get("enabled")) and not bool(merge_report_settings.get("local_file_available")):
            _append_log(
                logs,
                (
                    f"[Debug] MERGEREPORT_FILE_UNAVAILABLE local_path="
                    f"{str(merge_report_settings.get('requested_log_path', '') or '(blank)')} "
                    f"reason={str(merge_report_settings.get('local_file_reason', '') or 'unknown')} "
                    "falling back to non-file verification"
                ),
                log_callback,
            )
        splunk_username = str(getattr(client, "username", "") or "").strip()
        _append_log(logs, "Preparing report...", log_callback)
        _set_batch_state(regen_context, "PREPARING", logs=logs, log_callback=log_callback, reason="batch_initializing")
        _prepare_batch_execution_definition(
            regen_context,
            report_ids=report_ids,
            report_names=report_names,
            selected_indices=selected_indices,
            frequency=frequency,
            start=start,
            end=end,
            no_change=no_change,
            app=app,
            owner=splunk_username,
            prefer_merge_report_verification=resolve_primary_slice_mergereport_enabled(config),
            merge_report_log_path=(
                str(getattr(config, "merge_report_log_path", "") or "")
                if config is not None
                else ""
            ),
        )
        _audit_event(
            "REPORT_DISPATCH_REQUESTED",
            level="INFO",
            run_id=regen_context.run_id,
            batch_id=regen_context.batch_id,
            app=app,
            report_names=selected_report_names,
            slicing_mode=mode_description,
            earliest=regen_context.earliest_configured,
            latest=regen_context.latest_configured,
            report_count=len(selected_indices),
        )
        _set_batch_state(
            regen_context,
            "DISPATCHING",
            logs=logs,
            log_callback=log_callback,
            reason="batch_definition_frozen",
        )

        collected: List[str] = []
        for i in selected_indices:
            discovery_report_name = report_names[i]
            discovery_start = time.monotonic()
            discovery_started_utc = _utc_now_iso()
            _append_log(
                logs,
                (
                    f"[Debug] RECIPIENT_DISCOVERY_START report_name={discovery_report_name} "
                    f"started_utc={discovery_started_utc}"
                ),
                log_callback,
            )
            _audit_event(
                "RECIPIENT_DISCOVERY_START",
                level="INFO",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                report_name=discovery_report_name,
                slice_label="pre-dispatch",
                started_utc=discovery_started_utc,
            )
            resolved = _collect_saved_search_recipients(
                client=client,
                report_id_url=report_ids[i],
                report_name=discovery_report_name,
                app=app,
                username=splunk_username,
                logs=logs,
                log_callback=log_callback,
            )
            collected.extend(resolved)
            discovery_elapsed_ms = int((time.monotonic() - discovery_start) * 1000)
            discovery_ended_utc = _utc_now_iso()
            _append_log(
                logs,
                (
                    f"[Debug] RECIPIENT_DISCOVERY_DONE report_name={discovery_report_name} "
                    f"ended_utc={discovery_ended_utc} elapsed_ms={discovery_elapsed_ms} "
                    f"recipient_count={len(resolved)} outcome=completed"
                ),
                log_callback,
            )
            _audit_event(
                "RECIPIENT_DISCOVERY_DONE",
                level="INFO",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                report_name=discovery_report_name,
                slice_label="pre-dispatch",
                started_utc=discovery_started_utc,
                ended_utc=discovery_ended_utc,
                elapsed_ms=discovery_elapsed_ms,
                recipient_count=len(resolved),
                outcome="completed",
            )
            report_definition = _find_report_definition(
                regen_context,
                report_id_url=report_ids[i],
                report_name=discovery_report_name,
            )
            if isinstance(report_definition, dict):
                report_definition["savedsearch_recipients"] = list(_dedupe_keep_order(resolved))
        regen_context.savedsearch_recipients = _dedupe_keep_order(collected)
        if isinstance(regen_context.frozen_definition, dict):
            regen_context.frozen_definition["savedsearch_recipients"] = list(regen_context.savedsearch_recipients)
        _persist_batch_journal(regen_context, reason="recipient_discovery_complete")
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
                continue_on_timeout=resolve_continue_on_timeout(config),
                timeout_status=resolve_timeout_result(config),
                dispatch_call_timeout_seconds=resolve_dispatch_call_timeout_seconds(config),
                prefer_merge_report_verification=bool(merge_report_settings.get("enabled")),
                merge_report_log_path=str(merge_report_settings.get("local_file_path", "") or ""),
                merge_report_timeout_seconds=int(
                    merge_report_settings.get("timeout_seconds", DEFAULT_MERGEREPORT_TIMEOUT_SECONDS)
                    or DEFAULT_MERGEREPORT_TIMEOUT_SECONDS
                ),
                merge_report_settings=merge_report_settings,
            )
            logs.extend(report_logs)
        pending_slices = _pending_slice_records(regen_context)
        if pending_slices:
            if not resolve_postdispatch_enabled(config):
                _append_log(
                    logs,
                    (
                        "Post-dispatch verification disabled by configuration; "
                        "deferring unresolved slices to the mandatory final end-of-batch reconciliation sweep."
                    ),
                    log_callback,
                )
                _audit_event(
                    "REPORT_POSTDISPATCH_SKIPPED_DISABLED",
                    level="INFO",
                    run_id=regen_context.run_id,
                    batch_id=regen_context.batch_id,
                    app=app,
                    pending_slices=len(pending_slices),
                )
            elif resolve_reconcile_pending(config):
                _set_batch_state(
                    regen_context,
                    "RECONCILING",
                    logs=logs,
                    log_callback=log_callback,
                    reason="end_of_batch_pending_sweep",
                )
                reconcile_logs = _reconcile_pending_slices(
                    client,
                    regen_context,
                    wait_seconds=resolve_reconcile_wait_seconds(config),
                    poll_interval=resolve_status_check_poll_seconds(config),
                    prefer_merge_report_verification=bool(merge_report_settings.get("enabled")),
                    merge_report_log_path=str(merge_report_settings.get("local_file_path", "") or ""),
                    merge_report_settings=merge_report_settings,
                    log_callback=log_callback,
                )
                logs.extend(reconcile_logs)
            else:
                _append_log(
                    logs,
                    (
                        "Background pending reconciliation is disabled by configuration; "
                        "unresolved slices will still receive the mandatory final end-of-batch sweep."
                    ),
                    log_callback,
                )
        final_pending_dispatch_logs = _finalize_pending_no_sid_dispatches(
            regen_context,
            log_callback=log_callback,
        )
        logs.extend(final_pending_dispatch_logs)
        final_unresolved = _unresolved_slice_records(regen_context)
        _append_log(logs, "Finalizing results...", log_callback)
        if final_unresolved:
            _append_log(
                logs,
                (
                    f"Final end-of-batch reconciliation sweep triggered for {len(final_unresolved)} unresolved slice(s)."
                ),
                log_callback,
            )
            _audit_event(
                "REPORT_END_OF_BATCH_RECONCILIATION_SWEEP",
                level="WARN",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                unresolved_slices=len(final_unresolved),
            )
            _set_batch_state(
                regen_context,
                "RECONCILING",
                logs=logs,
                log_callback=log_callback,
                reason="final_end_of_batch_reconcile",
            )
            reconcile_logs = _reconcile_pending_slices(
                client,
                regen_context,
                wait_seconds=resolve_reconcile_wait_seconds(config),
                poll_interval=resolve_status_check_poll_seconds(config),
                prefer_merge_report_verification=bool(merge_report_settings.get("enabled")),
                merge_report_log_path=str(merge_report_settings.get("local_file_path", "") or ""),
                merge_report_settings=merge_report_settings,
                log_callback=log_callback,
            )
            logs.extend(reconcile_logs)
        regen_context.end_time_sgt = get_sgt_now()
        regen_context.slice_count = len(regen_context.slices)
        ok_count, fail_count, pending_count = regen_context.summary_counts()
        total_count = len(regen_context.slices)
        any_expired = any(
            _normalize_slice_state(item.lifecycle_state) == SLICE_STATE_EXPIRED
            for item in regen_context.slices
        )
        _append_log(logs, "", log_callback)
        for line in _build_run_summary_lines(regen_context):
            _append_log(logs, line, log_callback)
        if pending_count > 0:
            _append_log(
                logs,
                "Splunk may still complete pending jobs asynchronously.",
                log_callback,
            )
        final_batch_state = "COMPLETED"
        if pending_count > 0:
            final_batch_state = "PENDING_RECONCILE"
        elif any_expired:
            final_batch_state = "EXPIRED"
        elif fail_count > 0:
            final_batch_state = "FAILED"
        _set_batch_state(
            regen_context,
            final_batch_state,
            logs=logs,
            log_callback=log_callback,
            reason="batch_complete",
        )
        if fail_count == 0 and pending_count == 0:
            _audit_event(
                "REPORT_DISPATCH_SUCCESS",
                level="INFO",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                app=app,
                report_count=len(selected_indices),
                total_slices=total_count,
            )
        elif fail_count == 0:
            _audit_event(
                "REPORT_DISPATCH_PENDING",
                level="WARN",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                app=app,
                report_count=len(selected_indices),
                total_slices=total_count,
                pending_slices=pending_count,
            )
        else:
            _audit_event(
                "REPORT_DISPATCH_FAILED",
                level="WARN",
                run_id=regen_context.run_id,
                batch_id=regen_context.batch_id,
                app=app,
                report_count=len(selected_indices),
                total_slices=total_count,
                failed_slices=fail_count,
                pending_slices=pending_count,
            )
        final_user_outcome = "success"
        if pending_count > 0:
            final_user_outcome = "pending_verification"
        elif fail_count > 0 or any_expired:
            final_user_outcome = "partial_success"
        elif _context_has_evidence_warning(regen_context):
            final_user_outcome = "evidence_warning"
        for line in _operator_final_message_lines(
            batch_id=regen_context.batch_id,
            outcome=final_user_outcome,
        ):
            _append_log(logs, line, log_callback)
        ack_result = send_ack_summary_email(regen_context, config=config)
        report_audit = ",".join(selected_report_names)
        recipient_count = len(ack_result.recipients)
        if ack_result.success:
            status = "sent"
        elif ack_result.attempted:
            status = "failed"
        else:
            status = "skipped"
        reason = ack_result.reason or "-"
        _append_log(
            logs,
            (
                f"ACK_EMAIL_SENT run_id={regen_context.run_id} report={report_audit} "
                f"recipient_count={recipient_count} status={status} reason={reason}"
            ),
            log_callback,
        )
        if ack_result.reason == "pending_slices_present":
            _append_log(
                logs,
                "Acknowledgement email skipped because one or more slices are still pending.",
                log_callback,
            )
        elif ack_result.reason == "pending_verification":
            _append_log(
                logs,
                "Acknowledgement email sent with PARTIAL / PENDING VERIFICATION status because pending slices remain.",
                log_callback,
            )
        elif ack_result.reason == "ack_disabled":
            _append_log(
                logs,
                "Acknowledgement email skipped because ack_enabled=false.",
                log_callback,
            )
        if ack_result.error:
            _append_log(
                logs,
                "ACK email failure details are available in security audit logs.",
                log_callback,
            )
        cleared_dispatch_entries = _clear_pending_dispatch_attempts_for_run(regen_context.run_id)
        if cleared_dispatch_entries > 0:
            _append_log(
                logs,
                (
                    f"[Debug] RUN_SCOPED_PENDING_DISPATCH_FINALIZE run_id={regen_context.run_id} "
                    f"cleared_entries={cleared_dispatch_entries}"
                ),
                log_callback,
            )
        client.dispatch_log.emit(logs)
        return logs
    except Exception as e:
        if regen_context is not None:
            _clear_pending_dispatch_attempts_for_run(regen_context.run_id)
            _set_batch_state(
                regen_context,
                "FAILED",
                logs=logs,
                log_callback=log_callback,
                reason="batch_exception",
            )
        error_classification = _classify_batch_exception(e, regen_context)
        logger.exception(
            "run_dispatch_multi failed classification=%s batch_id=%s",
            error_classification,
            regen_context.batch_id if regen_context is not None else "",
        )
        _append_log(
            logs,
            (
                f"[Debug] BATCH_EXCEPTION batch_id={(regen_context.batch_id if regen_context is not None else '')} "
                f"classification={error_classification} exception_type={type(e).__name__} "
                f"detail={redact_text(str(e) or repr(e))}"
            ),
            log_callback,
        )
        _audit_event(
            "REPORT_DISPATCH_FAILED",
            level="ERROR",
            run_id=(regen_context.run_id if regen_context is not None else ""),
            batch_id=(regen_context.batch_id if regen_context is not None else ""),
            app=app,
            report_count=len(selected_indices) if "selected_indices" in locals() else 0,
            reason=repr(e),
            error_classification=error_classification,
            error_type=type(e).__name__,
        )
        if regen_context is not None:
            outcome = "connectivity_prestart" if error_classification == "connectivity_prestart" else "could_not_start"
            if _context_started_processing(regen_context):
                outcome = "partial_success"
            for line in _operator_final_message_lines(
                batch_id=regen_context.batch_id,
                outcome=outcome,
            ):
                _append_log(logs, line, log_callback)
        return logs
    finally:
        if regen_context is not None and regen_context.lock_key:
            if str(regen_context.batch_state or "").strip().upper() in {"COMPLETED", "FAILED", "EXPIRED", "ABORTED"}:
                release_overlap_lock(regen_context.lock_key, regen_context.batch_id)
        client.finished.emit()
