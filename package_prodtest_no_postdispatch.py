from __future__ import annotations

import argparse
import shutil
from pathlib import Path


PACKAGE_NAME = "SplunkUtilityTool_v4_prodtest_no_postdispatch"
DEFAULT_SOURCE_DIR = Path("dist") / "SplunkUtilityTool_v4"
DEFAULT_OUTPUT_DIR = Path("out") / PACKAGE_NAME
_POSTDISPATCH_SECTION = "[postdispatch]"


def _set_postdispatch_enabled(text: str, enabled: bool) -> str:
    lines = text.splitlines()
    result: list[str] = []
    in_postdispatch = False
    replaced = False
    value = "true" if enabled else "false"

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_postdispatch and not replaced:
                result.append(f"enabled = {value}")
                replaced = True
            in_postdispatch = stripped.lower() == _POSTDISPATCH_SECTION
        if in_postdispatch and stripped.lower().startswith("enabled ="):
            result.append(f"enabled = {value}")
            replaced = True
            continue
        result.append(line)

    if in_postdispatch and not replaced:
        result.append(f"enabled = {value}")
        replaced = True

    if not replaced:
        if result and result[-1].strip():
            result.append("")
        result.append(_POSTDISPATCH_SECTION)
        result.append(f"enabled = {value}")

    return "\n".join(result) + "\n"


def _rewrite_postdispatch_flag(path: Path, *, enabled: bool) -> None:
    text = path.read_text(encoding="utf-8-sig")
    path.write_text(_set_postdispatch_enabled(text, enabled), encoding="utf-8", newline="\n")


def _copy_if_present(source: Path, destination: Path) -> None:
    if source.is_file():
        shutil.copy2(source, destination)


def build_prodtest_package(
    *,
    source_dir: Path = DEFAULT_SOURCE_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Path:
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Package source folder not found: {source_dir}")

    if output_dir.exists():
        shutil.rmtree(output_dir)
    shutil.copytree(source_dir, output_dir)

    repo_root = Path(__file__).resolve().parent
    for name in ("config.ini.example", "config.example.ini"):
        _copy_if_present(repo_root / name, output_dir / name)

    config_targets = [
        output_dir / "config.ini",
        output_dir / "config.ini.example",
        output_dir / "config.example.ini",
    ]
    for target in config_targets:
        if target.is_file():
            _rewrite_postdispatch_flag(target, enabled=False)

    return output_dir


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a production-test package with post-dispatch verification disabled by default."
    )
    parser.add_argument("--source-dir", default=str(DEFAULT_SOURCE_DIR))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    output_dir = build_prodtest_package(
        source_dir=Path(args.source_dir),
        output_dir=Path(args.output_dir),
    )
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
