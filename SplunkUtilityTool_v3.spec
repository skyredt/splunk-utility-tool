# -*- mode: python ; coding: utf-8 -*-
# Qt/PySide6 build for lab use; not recommended for hardened servers.
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all


def _find_vc_runtime():
    patterns = ("vcruntime140*.dll", "msvcp140*.dll")
    repo_root = Path(__file__).resolve().parent
    roots = [
        repo_root / "vc_runtime",
        Path(sys.base_prefix),
        Path(sys.base_prefix) / "DLLs",
        Path(sys.executable).resolve().parent,
        Path("C:/Windows/System32"),
        Path("C:/Windows/SysWOW64"),
    ]
    found = []
    for root in roots:
        if not root.exists():
            continue
        for pattern in patterns:
            found.extend(root.glob(pattern))
    unique = []
    seen = set()
    for p in found:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    return unique

datas = []
vc_runtime_bins = [(str(p), ".") for p in _find_vc_runtime()]
if vc_runtime_bins:
    print("Bundling VC runtime DLLs:")
    for p, _ in vc_runtime_bins:
        print(" -", p)
else:
    print("Bundling VC runtime DLLs: none found")
binaries = vc_runtime_bins
hiddenimports = []
tmp_ret = collect_all('PySide6')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('PySide6_Essentials')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('PySide6_Addons')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('shiboken6')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['main.py'],
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
    name='SplunkUtilityTool_v3',
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
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SplunkUtilityTool_v3',
)
