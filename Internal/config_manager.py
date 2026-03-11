from __future__ import annotations

import configparser
import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import Optional


LOGGER = logging.getLogger(__name__)
CONFIG_FILENAME = "config.ini"
CONFIG_BACKUP_SUFFIX = ".bak"
EXAMPLE_FILENAMES = ("config.ini.example", "config.example.ini")
_SECTION_NAME_RE = r"[A-Za-z0-9_.-]+"
_KEY_NAME_RE = r"[A-Za-z0-9_.-]+"

_KNOWN_SECTION_ORDER = (
    "splunk",
    "credentials",
    "security",
    "logging",
    "mergereport",
    "dispatch",
    "email",
    "postdispatch",
)
_KNOWN_KEY_ORDER = {
    "splunk": (
        "host",
        "servers",
        "auth_mode",
        "verify_ssl",
        "password",
        "token_storage",
        "token",
        "token_ini",
        "token_encrypted",
        "splunk_cli_path",
    ),
    "credentials": ("username", "secret_file", "dpapi_scope"),
    "security": ("build_mode", "policy_mode", "allow_insecure_overrides"),
    "logging": ("level", "verbose", "max_bytes", "backup_count"),
    "mergereport": ("enabled", "log_path", "timeout_seconds"),
    "dispatch": ("per_slice_wait_seconds", "continue_on_timeout", "timeout_result"),
    "email": (
        "ack_enabled",
        "ack_on_pending",
        "ack_on_unknown",
        "ack_recipients",
        "ack_use_savedsearch_recipients",
        "ack_attach_manifest",
        "smtp_host",
        "smtp_port",
        "smtp_tls",
        "smtp_user",
        "smtp_pass",
        "from_addr",
        "from_address",
        "use_tls",
    ),
    "postdispatch": (
        "merge_report_enabled",
        "merge_report_log_path",
        "merge_report_index",
        "merge_report_source_contains",
        "merge_report_sourcetype",
        "merge_report_timeout_seconds",
        "native_email_enabled",
        "native_email_index",
        "native_email_source_contains",
        "native_email_sourcetype",
        "native_email_timeout_seconds",
        "broker_request_timeout_seconds",
        "reconcile_pending",
        "reconcile_wait_seconds",
        "native_email_strict_success",
        "poll_seconds",
        "lookback_seconds",
        "status_check_timeout_seconds",
        "status_check_poll_seconds",
    ),
}


def _canonical(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


@dataclass
class IniEntry:
    key: str
    value: str
    comments: list[str] = field(default_factory=list)
    order: int = 0


@dataclass
class IniSection:
    name: str
    comments: list[str] = field(default_factory=list)
    entries: dict[str, IniEntry] = field(default_factory=dict)
    order: int = 0


@dataclass
class IniDocument:
    leading_comments: list[str] = field(default_factory=list)
    sections: dict[str, IniSection] = field(default_factory=dict)
    trailing_comments: list[str] = field(default_factory=list)


@dataclass
class LoadedConfig:
    path: str
    parser: configparser.ConfigParser
    document: IniDocument
    canonical_text: str
    template_path: str = ""
    created_from_template: bool = False
    repaired: bool = False
    backup_path: str = ""
    changes: list[str] = field(default_factory=list)


class ConfigError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        path: str = "",
        line_number: Optional[int] = None,
        section: str = "",
        code: str = "config_error",
    ):
        super().__init__(message)
        self.message = message
        self.path = path
        self.line_number = line_number
        self.section = section
        self.code = code

    def __str__(self) -> str:
        parts = [self.message]
        if self.line_number is not None:
            parts.append(f"line {self.line_number}")
        if self.section:
            parts.append(f"section [{self.section}]")
        if self.path:
            parts.append(self.path)
        return " | ".join(parts)


class ConfigMissingError(ConfigError):
    pass


class ConfigFormatError(ConfigError):
    pass


class ConfigTemplateError(ConfigError):
    pass


def resolve_runtime_config_path(exe_dir: str) -> str:
    return _canonical(os.path.join(exe_dir, CONFIG_FILENAME))


def resolve_template_path(exe_dir: str) -> str:
    for filename in EXAMPLE_FILENAMES:
        candidate = os.path.join(exe_dir, filename)
        if os.path.isfile(candidate):
            return _canonical(candidate)
    return ""


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8-sig", errors="strict", newline="") as f:
            return f.read()
    except UnicodeDecodeError as exc:
        raise ConfigFormatError(
            "Configuration file is not valid UTF-8 text.",
            path=path,
            code="config_encoding_invalid",
        ) from exc


def _write_text(path: str, text: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _normalize_newlines(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def _parse_ini_document(text: str, *, path: str) -> IniDocument:
    import re

    header_re = re.compile(rf"^\[(?P<section>{_SECTION_NAME_RE})\]$")
    key_re = re.compile(rf"^(?P<key>{_KEY_NAME_RE})\s*=\s*(?P<value>.*)$")
    merged_key_re = re.compile(rf"\b{_KEY_NAME_RE}\s*=")
    merged_section_re = re.compile(rf"\[(?:{_SECTION_NAME_RE})\]")

    document = IniDocument()
    pending_comments: list[str] = []
    current_section: Optional[IniSection] = None
    saw_section = False

    normalized_lines = _normalize_newlines(text).split("\n")
    total_lines = len(normalized_lines)
    for line_number, raw_line in enumerate(normalized_lines, start=1):
        if line_number == 1 and raw_line.startswith("\ufeff"):
            raw_line = raw_line.lstrip("\ufeff")
        if line_number > 1 and raw_line == "" and line_number == total_lines:
            break

        stripped = raw_line.strip()
        if not stripped:
            pending_comments.append("")
            continue
        if stripped.startswith("#") or stripped.startswith(";"):
            pending_comments.append(raw_line.rstrip())
            continue

        header_match = header_re.match(stripped)
        if header_match:
            section_name = header_match.group("section")
            section_key = section_name.lower()
            if section_key in document.sections:
                raise ConfigFormatError(
                    f"Duplicate section [{section_name}] in configuration.",
                    path=path,
                    line_number=line_number,
                    section=section_name,
                    code="duplicate_section",
                )
            comments = _trim_comment_block(pending_comments)
            if not saw_section:
                document.leading_comments = comments
            current_section = IniSection(
                name=section_name,
                comments=[] if not saw_section else comments,
                order=len(document.sections),
            )
            document.sections[section_key] = current_section
            pending_comments = []
            saw_section = True
            continue

        key_match = key_re.match(stripped)
        if key_match:
            if current_section is None:
                raise ConfigFormatError(
                    "Found a key/value pair before any [section] header.",
                    path=path,
                    line_number=line_number,
                    code="key_before_section",
                )
            key_name = key_match.group("key")
            value = key_match.group("value")
            value_without_inline_comment = value.strip()
            if merged_section_re.search(value_without_inline_comment):
                raise ConfigFormatError(
                    f"Possible merged section header detected on line {line_number}.",
                    path=path,
                    line_number=line_number,
                    section=current_section.name,
                    code="merged_section_line",
                )
            extra_key_match = merged_key_re.search(value_without_inline_comment)
            if extra_key_match is not None and extra_key_match.start() > 0:
                raise ConfigFormatError(
                    f"Possible merged key/value content detected on line {line_number}.",
                    path=path,
                    line_number=line_number,
                    section=current_section.name,
                    code="merged_key_line",
                )
            entry_key = key_name.lower()
            if entry_key in current_section.entries:
                raise ConfigFormatError(
                    f"Duplicate key {key_name!r} in section [{current_section.name}].",
                    path=path,
                    line_number=line_number,
                    section=current_section.name,
                    code="duplicate_key",
                )
            current_section.entries[entry_key] = IniEntry(
                key=key_name,
                value=value,
                comments=_trim_comment_block(pending_comments),
                order=len(current_section.entries),
            )
            pending_comments = []
            continue

        if stripped.startswith("[") and ("]" in stripped):
            raise ConfigFormatError(
                f"Malformed section header on line {line_number}: {stripped}",
                path=path,
                line_number=line_number,
                code="malformed_header",
            )
        raise ConfigFormatError(
            f"Malformed configuration line {line_number}: {stripped}",
            path=path,
            line_number=line_number,
            section=current_section.name if current_section is not None else "",
            code="malformed_line",
        )

    document.trailing_comments = _trim_comment_block(pending_comments)
    return document


def _trim_comment_block(lines: list[str]) -> list[str]:
    trimmed = list(lines)
    while trimmed and trimmed[0] == "":
        trimmed.pop(0)
    while trimmed and trimmed[-1] == "":
        trimmed.pop()
    return trimmed


def _ordered_sections(current: IniDocument, template: Optional[IniDocument]) -> list[IniSection]:
    sections: list[IniSection] = []
    seen: set[str] = set()
    if template is not None:
        for section_key in template.sections:
            if section_key in current.sections:
                sections.append(current.sections[section_key])
                seen.add(section_key)
    for section_key, section in current.sections.items():
        if section_key not in seen:
            sections.append(section)
    def sort_key(section: IniSection) -> tuple[int, int, str]:
        known_idx = _KNOWN_SECTION_ORDER.index(section.name.lower()) if section.name.lower() in _KNOWN_SECTION_ORDER else len(_KNOWN_SECTION_ORDER)
        return (known_idx, section.order, section.name.lower())
    return sorted(sections, key=sort_key)


def _ordered_entries(current: IniSection, template: Optional[IniSection]) -> list[IniEntry]:
    entries: list[IniEntry] = []
    seen: set[str] = set()
    if template is not None:
        for entry_key in template.entries:
            if entry_key in current.entries:
                entries.append(current.entries[entry_key])
                seen.add(entry_key)
    for entry_key, entry in current.entries.items():
        if entry_key not in seen:
            entries.append(entry)
    known = _KNOWN_KEY_ORDER.get(current.name.lower(), ())
    def sort_key(entry: IniEntry) -> tuple[int, int, str]:
        known_idx = known.index(entry.key.lower()) if entry.key.lower() in known else len(known)
        return (known_idx, entry.order, entry.key.lower())
    return sorted(entries, key=sort_key)


def serialize_canonical_config(document: IniDocument, *, template: Optional[IniDocument] = None) -> str:
    lines: list[str] = []
    if document.leading_comments:
        lines.extend(document.leading_comments)
        lines.append("")

    ordered_sections = _ordered_sections(document, template)
    for section_index, section in enumerate(ordered_sections):
        template_section = None
        if template is not None:
            template_section = template.sections.get(section.name.lower())
        if section_index > 0 and lines and lines[-1] != "":
            lines.append("")
        if section.comments:
            lines.extend(section.comments)
        lines.append(f"[{template_section.name if template_section is not None else section.name}]")

        ordered_entries = _ordered_entries(section, template_section)
        for entry in ordered_entries:
            template_entry = None
            if template_section is not None:
                template_entry = template_section.entries.get(entry.key.lower())
            if entry.comments:
                lines.extend(entry.comments)
            key_name = template_entry.key if template_entry is not None else entry.key
            lines.append(f"{key_name} = {entry.value}")

    if document.trailing_comments:
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend(document.trailing_comments)
    while len(lines) >= 2 and lines[-1] == "" and lines[-2] == "":
        lines.pop()
    return "\n".join(lines).rstrip("\n") + "\n"


def write_canonical_config(
    path: str,
    document: IniDocument,
    *,
    template: Optional[IniDocument] = None,
    create_backup: bool = True,
) -> tuple[str, str]:
    canonical_text = serialize_canonical_config(document, template=template)
    backup_path = ""
    if create_backup and os.path.isfile(path):
        backup_path = f"{path}{CONFIG_BACKUP_SUFFIX}"
        shutil.copyfile(path, backup_path)
    _write_text(path, canonical_text)
    return canonical_text, backup_path


def _load_template_document(template_path: str) -> IniDocument:
    if not template_path:
        raise ConfigTemplateError(
            "Configuration template is missing. Expected config.ini.example or config.example.ini.",
            path=template_path,
            code="template_missing",
        )
    try:
        return _parse_ini_document(_read_text(template_path), path=template_path)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigTemplateError(
            f"Configuration template could not be read: {exc}",
            path=template_path,
            code="template_invalid",
        ) from exc


def _to_configparser(text: str, *, path: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(text, source=path)
    except configparser.DuplicateSectionError as exc:
        raise ConfigFormatError(
            f"Duplicate section [{exc.section}] in configuration.",
            path=path,
            line_number=getattr(exc, "lineno", None),
            section=exc.section,
            code="duplicate_section",
        ) from exc
    except configparser.DuplicateOptionError as exc:
        raise ConfigFormatError(
            f"Duplicate key {exc.option!r} in section [{exc.section}].",
            path=path,
            line_number=getattr(exc, "lineno", None),
            section=exc.section,
            code="duplicate_key",
        ) from exc
    except configparser.Error as exc:
        raise ConfigFormatError(
            f"Malformed configuration content: {exc}",
            path=path,
            line_number=getattr(exc, "lineno", None),
            code="parser_error",
        ) from exc
    return parser


def load_and_validate_config(
    *,
    exe_dir: str,
    auto_create_from_template: bool = True,
    auto_repair: bool = True,
) -> LoadedConfig:
    config_path = resolve_runtime_config_path(exe_dir)
    template_path = resolve_template_path(exe_dir)
    created_from_template = False
    repaired = False
    backup_path = ""
    changes: list[str] = []

    if not os.path.isfile(config_path):
        if not auto_create_from_template:
            raise ConfigMissingError(
                f"Config file not found: {config_path}",
                path=config_path,
                code="config_missing",
            )
        if not template_path:
            raise ConfigMissingError(
                "config.ini is missing and no config.ini.example/config.example.ini template was found.",
                path=config_path,
                code="config_missing_no_template",
            )
        template_document = _load_template_document(template_path)
        canonical_text, _ = write_canonical_config(
            config_path,
            template_document,
            template=template_document,
            create_backup=False,
        )
        created_from_template = True
        changes.append(f"Created {os.path.basename(config_path)} from {os.path.basename(template_path)}.")
        LOGGER.info("Created runtime config from template: %s <- %s", config_path, template_path)
    raw_text = _read_text(config_path)
    document = _parse_ini_document(raw_text, path=config_path)

    template_document = _load_template_document(template_path) if template_path else None
    canonical_text = serialize_canonical_config(document, template=template_document)
    parser = _to_configparser(canonical_text, path=config_path)

    normalized_input = _normalize_newlines(raw_text)
    if auto_repair and (normalized_input != canonical_text):
        canonical_text, backup_path = write_canonical_config(
            config_path,
            document,
            template=template_document,
            create_backup=True,
        )
        repaired = True
        details = "Normalized config.ini formatting into canonical INI layout."
        changes.append(details)
        if backup_path:
            changes.append(f"Saved backup to {os.path.basename(backup_path)}.")
        LOGGER.info("%s Path=%s Backup=%s", details, config_path, backup_path or "<none>")
        parser = _to_configparser(canonical_text, path=config_path)

    return LoadedConfig(
        path=config_path,
        parser=parser,
        document=document,
        canonical_text=canonical_text,
        template_path=template_path,
        created_from_template=created_from_template,
        repaired=repaired,
        backup_path=backup_path,
        changes=changes,
    )
