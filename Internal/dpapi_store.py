from __future__ import annotations

import base64
import ctypes
import os
import re
import subprocess
from ctypes import wintypes
from typing import Callable, Optional

from Internal.security_policy import load_security_policy


CRYPTPROTECT_LOCAL_MACHINE = 0x4
DEFAULT_SECRET_FILE = "secret.dpapi"
APP_DIRNAME = "SplunkUtilityTool"
FIXED_PROGRAMDATA_ROOT = r"C:\ProgramData\SplunkUtilityTool"
_SAFE_SECRET_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_ACL_ACE_RE = re.compile(r"([^:\r\n]+):((?:\([^)]+\))+)")
_BROAD_PRINCIPALS = {
    "everyone",
    "authenticated users",
    "builtin\\users",
    "users",
    "nt authority\\authenticated users",
}
_READISH_PERMS = ("(f)", "(m)", "(w)", "(r)", "(rx)", "(read)")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32

_CryptProtectData = _crypt32.CryptProtectData
_CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),  # pDataIn
    wintypes.LPCWSTR,           # szDataDescr
    ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
    wintypes.LPVOID,            # pvReserved
    wintypes.LPVOID,            # pPromptStruct
    wintypes.DWORD,             # dwFlags
    ctypes.POINTER(DATA_BLOB),  # pDataOut
]
_CryptProtectData.restype = wintypes.BOOL

_CryptUnprotectData = _crypt32.CryptUnprotectData
_CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),   # pDataIn
    ctypes.POINTER(wintypes.LPWSTR),  # ppszDataDescr
    ctypes.POINTER(DATA_BLOB),   # pOptionalEntropy
    wintypes.LPVOID,             # pvReserved
    wintypes.LPVOID,             # pPromptStruct
    wintypes.DWORD,              # dwFlags
    ctypes.POINTER(DATA_BLOB),   # pDataOut
]
_CryptUnprotectData.restype = wintypes.BOOL

_LocalFree = _kernel32.LocalFree
_LocalFree.argtypes = [wintypes.HLOCAL]
_LocalFree.restype = wintypes.HLOCAL


def _bytes_to_blob(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    if data is None:
        raise ValueError("Input data cannot be None.")
    if len(data) == 0:
        raise ValueError("Input data cannot be empty.")

    buf = ctypes.create_string_buffer(data)
    blob = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    return blob, buf


def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
    if not blob.pbData or blob.cbData == 0:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def _audit_event(logger, event: str, level: str = "INFO", **fields) -> None:
    if logger is None:
        return
    if hasattr(logger, "log_event"):
        logger.log_event(event, level=level, **fields)
        return
    message = f"{event} {fields}" if fields else event
    level_upper = (level or "INFO").upper()
    if level_upper == "ERROR" and hasattr(logger, "error"):
        logger.error(message)
    elif level_upper == "WARN" and hasattr(logger, "warning"):
        logger.warning(message)
    elif hasattr(logger, "info"):
        logger.info(message)


def _validate_secret_filename(secret_file: str) -> str:
    value = (secret_file or DEFAULT_SECRET_FILE).strip() or DEFAULT_SECRET_FILE
    basename = os.path.basename(value)
    has_sep = ("\\" in value) or ("/" in value)
    has_drive = bool(os.path.splitdrive(value)[0])
    has_colon = ":" in value
    has_control = any(ord(ch) < 32 for ch in value)
    ends_bad = value.endswith(" ") or value.endswith(".")
    if has_sep or has_drive or value != basename or value in (".", ".."):
        raise ValueError("secret_file must be basename-only and cannot include paths.")
    if has_colon:
        raise ValueError("secret_file cannot contain ':'.")
    if has_control:
        raise ValueError("secret_file cannot contain control characters.")
    if ends_bad:
        raise ValueError("secret_file cannot end with dot or space.")
    if not _SAFE_SECRET_FILENAME_RE.match(value):
        raise ValueError("secret_file contains unsupported characters.")
    if not value.lower().endswith(".dpapi"):
        raise ValueError("secret_file must use .dpapi suffix.")
    return value


def _windows_directory() -> str:
    buffer = ctypes.create_unicode_buffer(260)
    get_win_dir = _kernel32.GetWindowsDirectoryW
    get_win_dir.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_win_dir.restype = wintypes.UINT
    length = get_win_dir(buffer, len(buffer))
    if length <= 0:
        return r"C:\Windows"
    return buffer.value


def _icacls_path() -> str:
    return os.path.join(_windows_directory(), "System32", "icacls.exe")


def _is_broad_principal(principal: str) -> bool:
    raw = principal.strip().lower().lstrip("*")
    if raw in _BROAD_PRINCIPALS:
        return True
    if raw.endswith("\\users"):
        return True
    if raw.endswith("authenticated users"):
        return True
    return False


def _acl_text_is_weak(acl_text: str) -> bool:
    text = (acl_text or "").lower()
    parsed_any = False
    for match in _ACL_ACE_RE.finditer(text):
        parsed_any = True
        principal = match.group(1).strip()
        perms = match.group(2)
        if not _is_broad_principal(principal):
            continue
        if "(deny)" in perms:
            continue
        if any(token in perms for token in _READISH_PERMS):
            return True
    if not parsed_any:
        return True
    return False


def _path_acl_is_weak(path: str) -> bool:
    icacls_exe = _icacls_path()
    if not os.path.isfile(icacls_exe):
        return True
    try:
        proc = subprocess.run(
            [icacls_exe, path],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except Exception:
        return True
    if proc.returncode != 0:
        return True
    return _acl_text_is_weak(proc.stdout or "")


def dpapi_protect_machine(plaintext_bytes: bytes) -> bytes:
    in_blob, in_buf = _bytes_to_blob(plaintext_bytes)
    out_blob = DATA_BLOB()
    ok = _CryptProtectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_LOCAL_MACHINE,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()

    try:
        return _blob_to_bytes(out_blob)
    finally:
        if out_blob.pbData:
            _LocalFree(ctypes.cast(out_blob.pbData, wintypes.HLOCAL))
        # keep a reference to in_buf alive until function exit
        _ = in_buf


def dpapi_unprotect(protected_bytes: bytes) -> bytes:
    in_blob, in_buf = _bytes_to_blob(protected_bytes)
    out_blob = DATA_BLOB()
    description = wintypes.LPWSTR()

    ok = _CryptUnprotectData(
        ctypes.byref(in_blob),
        ctypes.byref(description),
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError()

    try:
        return _blob_to_bytes(out_blob)
    finally:
        if description:
            _LocalFree(ctypes.cast(description, wintypes.HLOCAL))
        if out_blob.pbData:
            _LocalFree(ctypes.cast(out_blob.pbData, wintypes.HLOCAL))
        _ = in_buf


def save_secret_b64(path: str, protected_bytes: bytes) -> None:
    if not path:
        raise ValueError("Secret path cannot be empty.")
    if not protected_bytes:
        raise ValueError("Protected secret bytes cannot be empty.")

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    encoded = base64.b64encode(protected_bytes).decode("ascii")
    with open(path, "w", encoding="ascii", newline="\n") as f:
        f.write(encoded)


def load_secret_b64(path: str) -> bytes:
    if not path:
        raise ValueError("Secret path cannot be empty.")
    with open(path, "r", encoding="ascii") as f:
        raw = f.read().strip()
    if not raw:
        raise ValueError("Secret file is empty.")
    return base64.b64decode(raw, validate=True)


def _is_production_mode(exe_dir: str) -> bool:
    try:
        policy = load_security_policy(exe_dir=exe_dir)
    except Exception:
        return True
    return policy.is_production


def resolve_secret_candidates(exe_dir: str, secret_file: str = DEFAULT_SECRET_FILE) -> list[str]:
    if not exe_dir:
        raise ValueError("exe_dir is required.")
    filename = _validate_secret_filename(secret_file)
    production_mode = _is_production_mode(exe_dir)
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip() if not production_mode else ""

    candidates = [
        os.path.join(exe_dir, filename),
        os.path.join(exe_dir, "Internal", filename),
        os.path.join(FIXED_PROGRAMDATA_ROOT, filename),
    ]
    if local_app_data:
        candidates.append(os.path.join(local_app_data, APP_DIRNAME, filename))
    return candidates


def find_existing_secret_path(exe_dir: str, secret_file: str = DEFAULT_SECRET_FILE) -> Optional[str]:
    for path in resolve_secret_candidates(exe_dir, secret_file=secret_file):
        if os.path.isfile(path):
            return path
    return None


def choose_writable_secret_path(exe_dir: str, secret_file: str = DEFAULT_SECRET_FILE) -> str:
    for path in resolve_secret_candidates(exe_dir, secret_file=secret_file):
        parent = os.path.dirname(path)
        try:
            if parent:
                os.makedirs(parent, exist_ok=True)
            if parent and _path_acl_is_weak(parent):
                continue
            existed_before = os.path.isfile(path)
            with open(path, "ab"):
                pass
            if _path_acl_is_weak(path):
                if not existed_before:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                continue
            return path
        except OSError:
            continue
    raise PermissionError("No writable secret path available with strong ACL.")


def load_or_enroll_password(
    prompt_fn: Callable[[], Optional[str]],
    exe_dir: str,
    logger,
    secret_file: str = DEFAULT_SECRET_FILE,
    allow_ephemeral_on_save_failure: bool = False,
) -> tuple[str, str]:
    try:
        secret_file = _validate_secret_filename(secret_file)
    except Exception as exc:
        _audit_event(
            logger,
            "SECRET_FILENAME_REJECTED",
            level="ERROR",
            reason=str(exc),
        )
        raise PermissionError("Invalid secret filename.") from exc
    had_existing_secret = False
    existing_paths = [p for p in resolve_secret_candidates(exe_dir, secret_file=secret_file) if os.path.isfile(p)]
    if existing_paths:
        had_existing_secret = True
        for existing_path in existing_paths:
            if _path_acl_is_weak(existing_path):
                _audit_event(
                    logger,
                    "SECRET_FILE_WEAK_ACL_BLOCKED",
                    level="ERROR",
                    secret_path_used=existing_path,
                )
                continue
            try:
                protected = load_secret_b64(existing_path)
                plaintext = dpapi_unprotect(protected)
                password = plaintext.decode("utf-8")
                if not password:
                    raise ValueError("Decrypted password is empty.")
                _audit_event(logger, "CRED_SECRET_PATH_SELECTED", level="DEBUG", secret_path_used=existing_path)
                return password, existing_path
            except Exception as exc:
                _audit_event(
                    logger,
                    "CRED_DECRYPT_FAILED",
                    level="WARN",
                    secret_path_used=existing_path,
                    reason=str(exc),
                )
    else:
        _audit_event(logger, "SECRET_FILE_MISSING", level="WARN", secret_file=secret_file)

    if prompt_fn is None:
        raise RuntimeError("Password prompt callback is required for enrollment.")

    entered = prompt_fn()
    password = (entered or "").strip()
    if not password:
        raise RuntimeError("Password entry canceled or empty.")

    try:
        target_path = choose_writable_secret_path(exe_dir, secret_file=secret_file)
    except Exception as exc:
        _audit_event(
            logger,
            "SECURITY_ARTIFACT_PATH_UNAVAILABLE",
            level="ERROR",
            reason=str(exc),
        )
        if allow_ephemeral_on_save_failure:
            return password, ""
        raise
    if os.path.normcase(target_path).startswith(os.path.normcase(os.path.expandvars(r"%LOCALAPPDATA%"))):
        _audit_event(
            logger,
            "SECURITY_ARTIFACT_DEV_FALLBACK",
            level="WARN",
            secret_path_used=target_path,
        )
    target_parent = os.path.dirname(target_path)
    if target_parent and _path_acl_is_weak(target_parent):
        _audit_event(
            logger,
            "SECRET_FILE_WEAK_ACL_BLOCKED",
            level="ERROR",
            secret_path_used=target_parent,
        )
        if allow_ephemeral_on_save_failure:
            return password, ""
        raise PermissionError("Secret directory ACL is too permissive.")
    try:
        protected = dpapi_protect_machine(password.encode("utf-8"))
        save_secret_b64(target_path, protected)
        if _path_acl_is_weak(target_path):
            _audit_event(
                logger,
                "SECRET_FILE_WEAK_ACL_BLOCKED",
                level="ERROR",
                secret_path_used=target_path,
            )
            if allow_ephemeral_on_save_failure:
                return password, ""
            raise PermissionError("Secret file ACL is too permissive.")
    except Exception as exc:
        _audit_event(
            logger,
            "SECRET_FILE_WRITE_FAILED",
            level="ERROR",
            secret_path_used=target_path,
            reason=str(exc),
        )
        if allow_ephemeral_on_save_failure:
            return password, ""
        raise

    if had_existing_secret:
        _audit_event(logger, "CRED_REENROLL_OVERWRITE", level="INFO", secret_path_used=target_path)
    else:
        _audit_event(logger, "CRED_ENROLL_CREATE", level="INFO", secret_path_used=target_path)
    return password, target_path
