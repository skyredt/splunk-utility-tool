# -*- mode: python ; coding: utf-8 -*-
# Qt/PySide6 build for lab use; not recommended for hardened servers.
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all


def _repo_root() -> Path:
    """
    Resolve repo root without __file__ (PyInstaller spec does not guarantee __file__ exists).

    Priority:
    1) PyInstaller-injected 'specpath' (directory containing the spec)
    2) GitHub Actions workspace
    3) Current working directory
    """
    sp = globals().get("specpath")
    if sp:
        try:
            return Path(sp).resolve()
        except Exception:
            pass

    ws = os.environ.get("GITHUB_WORKSPACE")
    if ws:
        return Path(ws).resolve()

    return Path.cwd().resolve()


def _find_vc_runtime_bins():
    """
    Minimal VC runtime bundle: include only the release DLLs we actually want.
    We intentionally do NOT scan System32/SysWOW64 here to avoid pulling in
    debug/CLR variants and duplicates.

    The workflow will populate vc_runtime/ from System32 at build time.
    """
    allow = [
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "msvcp140.dll",
        "msvcp140_1.dll",
        "concrt140.dll",
        "msvcp140_2.dll",
    ]

    repo_root = _repo_root()
    roots = [
        repo_root / "vc_runtime",
        Path(sys.base_prefix),
        Path(sys.base_prefix) / "DLLs",
        Path(sys.executable).resolve().parent,
    ]

    bins = []
    for dll in allow:
        picked = None
        for root in roots:
            candidate = root / dll
            if candidate.exists():
                picked = candidate
                break
        if picked is not None:
            bins.append((str(picked), "."))

    return bins


datas = []
top_level_datas = []
app_icon = _repo_root() / "assets" / "app_icon.ico"
if app_icon.exists():
    datas.append((str(app_icon), "assets"))
else:
    print("Warning: assets/app_icon.ico not found; build will use default icon.")
for config_template in ("config.ini.example", "config.example.ini"):
    template_path = _repo_root() / config_template
    if template_path.exists():
        top_level_datas.append((config_template, str(template_path), "PKG"))

binaries = _find_vc_runtime_bins()
if binaries:
    print("Bundling VC runtime DLLs (minimal):")
    for path, _ in binaries:
        print(" -", path)
else:
    print("Bundling VC runtime DLLs (minimal): none found")

hiddenimports = []

tmp_ret = collect_all("PySide6")
datas += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

tmp_ret = collect_all("PySide6_Essentials")
datas += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

tmp_ret = collect_all("PySide6_Addons")
datas += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

tmp_ret = collect_all("shiboken6")
datas += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]


a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SplunkUtilityTool_v4",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(app_icon),
)

coll = COLLECT(
    exe,
    top_level_datas,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="SplunkUtilityTool_v4",
)
