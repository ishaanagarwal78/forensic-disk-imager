#!/usr/bin/env bash
# ── Bundle the libewf DLL chain next to imager.exe ────────────────────────────
# Run in the MSYS2 UCRT64 shell AFTER ./build.bat.  Walks imager.exe's *recursive*
# DLL dependency tree with objdump and copies every toolchain (UCRT64) DLL into
# backend/.  Windows system DLLs (KERNEL32, api-ms-win-crt-*) are skipped — they
# exist on every Win10/11 target.  This makes the PyInstaller bundle fully
# self-contained.  (ldd is intentionally NOT used — it chokes on native PE exes.)
set -uo pipefail
cd "$(dirname "$0")/.."

if [ ! -f backend/imager.exe ]; then
    echo "[ERROR] backend/imager.exe not found — run ./build.bat first."
    exit 1
fi

# DLL source = the toolchain bin that built imager.exe (where gcc/objdump live).
BIN="$(dirname "$(command -v gcc 2>/dev/null || echo /ucrt64/bin/gcc)")"
OBJDUMP="$BIN/objdump"
command -v "$OBJDUMP" >/dev/null 2>&1 || OBJDUMP="objdump"
echo "[INFO] Toolchain bin: $BIN"

declare -A seen
queue=("backend/imager.exe")
copied=0
while [ "${#queue[@]}" -gt 0 ]; do
    f="${queue[0]}"
    queue=("${queue[@]:1}")
    while read -r dep; do
        dep="$(echo "$dep" | tr -d '\r')"
        [ -z "$dep" ] && continue
        [ -n "${seen[$dep]:-}" ] && continue
        seen[$dep]=1
        if [ -f "$BIN/$dep" ]; then        # ships with the toolchain → bundle
            cp -f "$BIN/$dep" backend/
            echo "  + $dep"
            copied=$((copied + 1))
            queue+=("$BIN/$dep")           # recurse into its own dependencies
        fi
    done < <("$OBJDUMP" -p "$f" 2>/dev/null \
             | grep -iE "DLL Name:" | sed -E 's/.*DLL Name:[[:space:]]*//')
done

if [ "$copied" -eq 0 ]; then
    echo "[WARN] No toolchain DLLs resolved."
    echo "       Make sure you are in the MSYS2 UCRT64 shell and libewf is installed."
    exit 1
fi
echo "[OK] Bundled $copied DLL(s) into backend/:"
ls -1 backend/*.dll
