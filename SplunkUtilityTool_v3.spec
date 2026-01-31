# -*- mode: python ; coding: utf-8 -*-
# Qt/PySide6 build for lab use; not recommended for hardened servers.
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = [('C:\\SplunkTool3.0\\SplunkUtilityTool_v3.0_base\\vc_runtime\\vcruntime140.dll', '.'), ('C:\\SplunkTool3.0\\SplunkUtilityTool_v3.0_base\\vc_runtime\\vcruntime140_1.dll', '.'), ('C:\\SplunkTool3.0\\SplunkUtilityTool_v3.0_base\\vc_runtime\\msvcp140.dll', '.')]
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
