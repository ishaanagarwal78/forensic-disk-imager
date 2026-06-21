@echo off
setlocal EnableDelayedExpansion
echo =====================================================
echo  Forensic Disk Imager  --  Standalone Packager
echo =====================================================
echo.

rem -- 1. The C engine must be built first --------------------------------------
if not exist "backend\imager.exe" (
    echo [ERROR] backend\imager.exe is missing.
    echo         Build it first in the MSYS2 UCRT64 shell:   ./build.bat
    pause & exit /b 1
)

rem -- 2. The libewf DLL chain must be bundled next to it -----------------------
if not exist "backend\libewf-2.dll" (
    echo [ERROR] libewf DLLs are missing in backend\.
    echo         Bundle them in the MSYS2 UCRT64 shell:   bash tools/bundle_dlls.sh
    pause & exit /b 1
)

rem -- 3. PyInstaller -----------------------------------------------------------
where pyinstaller >nul 2>&1
if !errorlevel! neq 0 (
    echo [INFO] Installing PyInstaller...
    python -m pip install pyinstaller || (echo [ERROR] pip install failed & pause & exit /b 1)
)

echo [INFO] Building standalone executable (this takes a minute)...
echo.
pyinstaller --noconfirm ForensicDiskImager.spec
if !errorlevel! neq 0 (
    echo [FAIL] PyInstaller build failed — see errors above.
    pause & exit /b 1
)

echo.
echo [OK] Standalone application:  dist\ForensicDiskImager.exe
echo.
echo      Copy that ONE .exe to any Windows 10/11 machine and run it.
echo      No Python, MSYS2, or libewf required on the target.
echo      (Run as Administrator for raw physical-drive access.)
echo.
pause
