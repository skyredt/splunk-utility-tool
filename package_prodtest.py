from __future__ import annotations

import argparse
import shutil
from datetime import datetime
from pathlib import Path


PACKAGE_PREFIX = "SplunkUtilityTool_v4_prodtest"
DEFAULT_SOURCE_DIR = Path("dist") / "SplunkUtilityTool_v4"
DEFAULT_OUTPUT_ROOT = Path("out")
PLACEHOLDER_NAME = ".keep"


def _copy_if_present(source: Path, destination: Path) -> None:
    if source.is_file():
        shutil.copy2(source, destination)


def _ensure_placeholder_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    placeholder = path / PLACEHOLDER_NAME
    if not placeholder.exists():
        placeholder.write_text("", encoding="utf-8")


def _seed_runtime_config(package_dir: Path) -> None:
    primary = package_dir / "config.ini.example"
    secondary = package_dir / "config.example.ini"
    source = primary if primary.is_file() else secondary
    if not source.is_file():
        raise FileNotFoundError("No configuration template available to seed config.ini")
    shutil.copy2(source, package_dir / "config.ini")


def build_prodtest_package(
    *,
    source_dir: Path = DEFAULT_SOURCE_DIR,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    package_name: str = "",
) -> Path:
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Package source folder not found: {source_dir}")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    resolved_name = str(package_name or "").strip() or f"{PACKAGE_PREFIX}_{stamp}"
    output_dir = output_root / resolved_name

    if output_dir.exists():
        shutil.rmtree(output_dir)

    shutil.copytree(source_dir, output_dir)

    repo_root = Path(__file__).resolve().parent
    for name in ("config.ini.example", "config.example.ini"):
        _copy_if_present(repo_root / name, output_dir / name)

    _seed_runtime_config(output_dir)
    _ensure_placeholder_dir(output_dir / "Internal" / "logs")
    _ensure_placeholder_dir(output_dir / "Internal" / "baseline")

    return output_dir


def create_archive(package_dir: Path) -> Path:
    archive_path = Path(
        shutil.make_archive(
            str(package_dir),
            "zip",
            root_dir=str(package_dir.parent),
            base_dir=package_dir.name,
        )
    )
    return archive_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a production-test package from the hardened Tk build."
    )
    parser.add_argument("--source-dir", default=str(DEFAULT_SOURCE_DIR))
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--package-name", default="")
    parser.add_argument(
        "--no-zip",
        action="store_true",
        help="Build the package directory only and skip archive creation.",
    )
    args = parser.parse_args()

    output_dir = build_prodtest_package(
        source_dir=Path(args.source_dir),
        output_root=Path(args.output_root),
        package_name=str(args.package_name or ""),
    )
    print(output_dir)
    if not args.no_zip:
        print(create_archive(output_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
