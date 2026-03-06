from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from Internal.security_policy import PolicyViolation


@dataclass
class AuthConfig:
    host: str = ""
    auth_mode: str = "password"
    token_storage: str = ""
    config_path: str = "config.ini"


def _legacy_disabled() -> PolicyViolation:
    return PolicyViolation(
        "LEGACY_FEATURE_DISABLED",
        "Legacy token/CLI authentication helpers are not supported in v4 production build.",
    )


def load_config(path: str = "config.ini") -> AuthConfig:
    _ = path
    raise _legacy_disabled()


def decrypt_splunk_secret(encrypted_value: str, splunk_cli_path: str = "") -> str:
    _ = (encrypted_value, splunk_cli_path)
    raise _legacy_disabled()


def get_splunk_token(path: str = "config.ini") -> str:
    _ = path
    raise _legacy_disabled()


def build_auth_header(token: str) -> Dict[str, str]:
    _ = token
    raise _legacy_disabled()
