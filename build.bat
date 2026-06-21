@echo off
setlocal EnableDelayedExpansion

echo =====================================================
echo  Forensic Disk Imager  --  Windows Backend Builder
echo =====================================================
echo.

rem  IMPORTANT: run this from the MSYS2 UCRT64 shell (or with the UCRT64
rem  bin directory on PATH) so that gcc resolves to the UCRT64 toolchain
rem  where libewf and its headers are installed.

rem -- Check for gcc (MSYS2 UCRT64) -------------------------------------------
where gcc >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] gcc not found in PATH.
    echo         Open the "MSYS2 UCRT64" shell, or add its bin directory to PATH.
    echo         Install the toolchain + libewf with:
    echo             pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-libewf
    pause
    exit /b 1
)

rem -- Compile + link backend ------------------------------------------------
rem  SHA-256 comes from the bundled sha256.c (pure C99, no dependencies).
rem  E01 output is produced by the system libewf (EnCase EWF) -- linked via
rem  -lewf.  The custom vendored zlib container has been removed; the
rem  backend/third_party/zlib directory is now unused and may be deleted.
rem
rem  -D__USE_MINGW_ANSI_STDIO=1  enables POSIX %%lld support in MinGW printf
echo [INFO] Compiling backend modules (linking system libewf)...
echo.

gcc -O2 -Wall -Wextra ^
    -D__USE_MINGW_ANSI_STDIO=1 ^
    -o backend\imager.exe ^
    backend\main.c backend\scanner.c backend\imager.c backend\sha256.c ^
    backend\sha1.c backend\md5.c ^
    -lewf

if !errorlevel! equ 0 (
    echo.
    echo [OK]  Build successful: backend\imager.exe
    echo.
    echo       NOTE: imager.exe depends on libewf-2.dll plus its own DLL
    echo             chain from MSYS2 UCRT64 ^(zlib1, libbz2-1, libcrypto-*,
    echo             libgcc_s_seh-1, libwinpthread-1, ...^).  Get the full
    echo             list with:  objdump -p ucrt64\bin\libewf-2.dll ^| findstr DLL
    echo             Bundle those DLLs next to the exe ^(or via PyInstaller
    echo             --add-binary^).  The api-ms-win-crt-*.dll imports are the
    echo             OS Universal CRT and do NOT need bundling on Win10/11.
    echo.
    echo       Quick scan test ^(run as Administrator for full drive access^):
    echo         backend\imager.exe scan
    echo.
    echo       Launch the GUI:
    echo         python app.py
) else (
    echo.
    echo [FAIL] Compilation failed. Review the errors above.
    echo        If libewf was built statically, you may also need its
    echo        dependencies, e.g.:  -lewf -lz -lcrypto -lbz2
)

echo.
pause
