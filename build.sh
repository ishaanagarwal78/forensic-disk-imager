#!/usr/bin/env bash
# ── Forensic Disk Imager — Linux Backend Builder ──────────────────────────────
set -euo pipefail

echo "====================================================="
echo " Forensic Disk Imager  --  Linux Backend Builder"
echo "====================================================="
echo

# ── Dependency checks ─────────────────────────────────────────────────────────
if ! command -v gcc &>/dev/null; then
    echo "[ERROR] gcc not found.  Install with:  sudo apt install build-essential"
    exit 1
fi
if ! pkg-config --exists libewf 2>/dev/null && [ ! -e /usr/include/libewf.h ]; then
    echo "[WARN] libewf headers not found."
    echo "       Install with:  sudo apt install libewf-dev   (Debian/Ubuntu)"
    echo "       E01 output requires libewf; the build will fail without it."
fi

# ── Compile + link ────────────────────────────────────────────────────────────
#  MD5/SHA-1/SHA-256 come from the bundled pure-C md5.c / sha1.c / sha256.c.
#  E01 output is produced by the system libewf (linked via -lewf).
#  -D_FILE_OFFSET_BITS=64  → 64-bit off_t on 32-bit Linux builds.
echo "[INFO] Compiling backend (linking system libewf)..."
echo

gcc -O2 -Wall -Wextra \
    -D_FILE_OFFSET_BITS=64 \
    -o backend/imager \
    backend/main.c backend/scanner.c backend/imager.c \
    backend/sha256.c backend/sha1.c backend/md5.c \
    -lewf

echo
echo "[OK]  Build successful: backend/imager"
echo
echo "      Quick scan test (sudo required for raw device access):"
echo "        sudo ./backend/imager scan"
echo
echo "      Launch the GUI:"
echo "        python3 app.py"
echo
