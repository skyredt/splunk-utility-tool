# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for CIO Splunk Utility Tool 4.0 (Tkinter version).

Recommended for hardened production environments:
- Tk-only (no PySide6/Qt)
- onedir layout (no temp extraction)
- UPX disabled
"""

import os
import sys

spec_path = globals().get("__file__")
PROJECT_ROOT = os.path.abspath(os.path.dirname(spec_path)) if spec_path else os.getcwd()

# Bundle VC runtime to avoid external redistributable installs.
VC_RUNTIME_DIR = os.path.join(PROJECT_ROOT, "vc_runtime")
binaries = []
for dll_name in (
    "concrt140.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
):
    dll_path = os.path.join(VC_RUNTIME_DIR, dll_name)
    if os.path.isfile(dll_path):
        binaries.append((dll_path, "."))

# Bundle Tcl/Tk so Tkinter does not rely on system installs.
datas = []
tcl_root = os.path.join(sys.base_prefix, "tcl")
if os.path.isdir(tcl_root):
    datas.append((tcl_root, "tcl"))
app_icon = os.path.join(PROJECT_ROOT, "assets", "app_icon.ico")
if os.path.isfile(app_icon):
    datas.append((app_icon, "assets"))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=['tkinter', 'tkcalendar'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludedimports=['PySide6', 'shiboken6'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],
    name='SplunkUtilityTool_v4',
    exclude_binaries=True,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    console=False,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=app_icon if os.path.isfile(app_icon) else None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='SplunkUtilityTool_v4',
)
