# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec — builds a SINGLE standalone ForensicDiskImager.exe that runs
# on a bare Windows 10/11 machine with no Python, MSYS2, or libewf installed.
#
# Build order (see README "Packaging"):
#   1. ./build.bat                 (MSYS2 UCRT64)  -> backend/imager.exe
#   2. bash tools/bundle_dlls.sh   (MSYS2 UCRT64)  -> backend/*.dll (libewf chain)
#   3. pyinstaller ForensicDiskImager.spec         -> dist/ForensicDiskImager.exe
#
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

# Bundle the C engine + its libewf DLL chain under "backend/" inside the app.
backend = [(os.path.join('backend', f), 'backend')
           for f in os.listdir('backend')
           if f.lower().endswith(('.exe', '.dll'))]

datas = collect_data_files('customtkinter') + backend
hiddenimports = ['darkdetect'] + collect_submodules('pycdlib')

a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ForensicDiskImager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # windowed app — no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='app.ico',         # drop an .ico here to brand the executable
)
