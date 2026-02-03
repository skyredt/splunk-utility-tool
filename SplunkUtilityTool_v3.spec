# -*- mode: python ; coding: utf-8 -*-
# Qt/PySide6 build for lab use; not recommended for hardened servers.
import os
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all


def _repo_root():
    """
    Resolve repo root without using module file variable.
    Prefer PyInstaller-injected `specpath` (directory containing the spec),
    then GITHUB_WORKSPACE (Actions), else current working directory.
    """
    sp = globals().get("specpath")
    if sp:
        return Path(sp).resolve()

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
            p = root / dll
            if p.exists():
                picked = p
                break
        if picked:
            bins.append((str(picked), "."))

    return bins


datas = []
app_icon = _repo_root() / "assets" / "app.ico"
if app_icon.exists():
    datas.append((str(app_icon), "assets"))
else:
    print("Warning: assets/app.ico not found; build will use default icon.")
binaries = _find_vc_runtime_bins()
if binaries:
    print("Bundling VC runtime DLLs (minimal):")
    for p, _ in binaries:
        print(" -", p)
else:
    print("Bundling VC runtime DLLs (minimal): none found")

hiddenimports = []

tmp_ret = collect_all("PySide6")
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all("PySide6_Essentials")
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all("PySide6_Addons")
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

tmp_ret = collect_all("shiboken6")
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


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
    name="SplunkUtilityTool_v3",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(app_icon),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="SplunkUtilityTool_v3",
)
