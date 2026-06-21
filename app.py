"""
Forensic Disk Imager — Enterprise Forensic Suite
Python / CustomTkinter Frontend — Phase 5
UI: Telemetry Dashboard  ·  Hardware Interrogation  ·  Live Sector Map
"""
from __future__ import annotations

import csv
import ctypes
import glob
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import zipfile
import tkinter as tk
from collections import deque

# pycdlib builds the UDF volume image used for "logical E01" output.  Optional:
# only the logical-E01 path needs it, so a missing install degrades gracefully.
try:
    import pycdlib
except Exception:
    pycdlib = None
from datetime import datetime
from tkinter import filedialog, messagebox
from typing import Optional

# ctypes.wintypes only exists on Windows; guard the import so the module still
# loads on Linux/macOS (where the kernel32 creation-time path is never taken).
if sys.platform == "win32":
    import ctypes.wintypes

import customtkinter as ctk

# ── Platform constants ────────────────────────────────────────────────────────
# On Windows, CREATE_NO_WINDOW prevents subprocess calls from spawning a
# visible black CMD console.  On Linux/macOS, subprocess.CREATE_NO_WINDOW
# does not exist, so getattr returns 0 — a no-op creationflags value.
CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

# ── Appearance ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Colour palette (GitHub-Dark-inspired) ─────────────────────────────────────
_BG       = "#0d1117"
_PANEL    = "#161b22"
_SIDE     = "#0f1419"      # sidebar background
_BORDER   = "#30363d"
_TEXT     = "#e6edf3"
_MUTED    = "#8b949e"
_ACCENT   = "#58a6ff"
_GREEN    = "#3fb950"
_RED      = "#f85149"
_AMBER    = "#d97706"
_ENTRY_BG = "#1c2129"
_CARD_BG  = "#1a2030"

# Sector map
_MAP_BG      = "#090d12"
_MAP_IDLE    = "#1c2736"
_MAP_WRITTEN = "#3fb950"
_MAP_BAD     = "#f85149"

# ── Typography ────────────────────────────────────────────────────────────────
_F_TITLE = ("Segoe UI",  18, "bold")
_F_H2    = ("Segoe UI",   9, "bold")
_F_BODY  = ("Segoe UI",  11)
_F_MONO  = ("Consolas",  10)
_F_TVAL  = ("Consolas",  14, "bold")   # telemetry large value
_F_TLBL  = ("Consolas",   8)           # telemetry sub-label
_F_BTN   = ("Segoe UI",  13, "bold")


# ── Module-level helpers ──────────────────────────────────────────────────────

def get_backend_path() -> str:
    """Return the absolute path to the C backend executable.

    Handles two distinct runtime environments:

    1. Plain Python script (development / direct execution):
           <script_dir>/backend/imager[.exe]

    2. PyInstaller --onefile frozen binary:
       PyInstaller sets ``sys.frozen = True`` and extracts all bundled
       data into a temporary directory whose path is ``sys._MEIPASS``.
       Bundle the backend with:
           pyinstaller app.py --onefile \\
               --add-data "backend/imager.exe;backend"   # Windows
               --add-data "backend/imager:backend"       # Linux
       The backend will then live at:
           sys._MEIPASS/backend/imager[.exe]
    """
    name = "imager.exe" if sys.platform == "win32" else "imager"
    if getattr(sys, "frozen", False):
        # Frozen mode — resources are extracted to sys._MEIPASS at startup
        base: str = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        # Development mode — backend/ is a sibling directory of this script
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "backend", name)


def _fmt_hms(seconds: float) -> str:
    """Format a duration in seconds as HH:MM:SS."""
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, s   = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


# Win32 constants for the kernel-level SetFileTime path
_GENERIC_WRITE          = 0x40000000   # (unused — kept for reference)
_FILE_WRITE_ATTRIBUTES  = 0x0100
_OPEN_EXISTING          = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000   # required to open directory handles
_INVALID_HANDLE_VALUE   = ctypes.c_void_p(-1).value
# 100-ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01 (Unix epoch)
_EPOCH_DELTA_100NS      = 116444736000000000


def _unix_to_filetime(epoch: float):
    """Convert a UNIX epoch timestamp to a Win32 FILETIME structure.

    FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC:
        filetime = unix_epoch * 10_000_000 + 116444736000000000
    The 64-bit value is split across the FILETIME high/low DWORD pair.
    """
    ft = int(epoch * 10_000_000) + _EPOCH_DELTA_100NS
    if ft < 0:
        ft = 0
    return ctypes.wintypes.FILETIME(ft & 0xFFFFFFFF, (ft >> 32) & 0xFFFFFFFF)


def _set_windows_creation_time(filepath: str, ctime_epoch: float,
                               mtime_epoch: float, atime_epoch: float) -> bool:
    """Apply full MAC times — including the Creation time that os.utime cannot
    set — to ``filepath`` via the Win32 kernel (CreateFileW + SetFileTime).

    On non-Windows platforms (or any failure) returns False and the caller
    falls back to os.utime, which still covers Modified + Accessed.
    """
    if sys.platform != "win32":
        return False

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype  = ctypes.c_void_p

    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(filepath),
        _FILE_WRITE_ATTRIBUTES,
        0,                       # no sharing needed for an attribute write
        None,                    # default security
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if not handle or handle == _INVALID_HANDLE_VALUE:
        return False

    try:
        ctime_ft = _unix_to_filetime(ctime_epoch)   # Creation
        atime_ft = _unix_to_filetime(atime_epoch)   # LastAccess
        mtime_ft = _unix_to_filetime(mtime_epoch)   # LastWrite
        # SetFileTime(hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
        ok = kernel32.SetFileTime(
            ctypes.c_void_p(handle),
            ctypes.byref(ctime_ft),
            ctypes.byref(atime_ft),
            ctypes.byref(mtime_ft),
        )
        return bool(ok)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


# ─────────────────────────────────────────────────────────────────────────────
class ForensicImagerApp(ctk.CTk):
    """Enterprise Forensic Suite — main application window."""

    # Sector-map grid: 50 × 20 = 1 000 blocks; 1 block ≡ 0.1 % of the drive
    GRID_COLS    = 50
    GRID_ROWS    = 20
    TOTAL_BLOCKS = GRID_COLS * GRID_ROWS

    _PLACEHOLDER = "— click Scan Drives —"

    # Output-format menus are mode-aware: physical acquisitions produce a disk
    # image (raw DD or true EnCase E01); logical acquisitions produce either a
    # browsable tree-copy or a single zip archive — both carrying the per-file
    # SHA-256 audit manifest.
    _PHYSICAL_FORMATS = ("Raw (DD)", "E01 (EnCase)")
    _LOGICAL_FORMATS  = ("Folder (Tree + CSV)", "Zip Archive", "E01 (EnCase)")
    # Formats whose output supports a compression level (enables the dropdown).
    _COMPRESSIBLE_FORMATS = ("E01 (EnCase)", "Zip Archive")

    # ── Init ──────────────────────────────────────────────────────────────────
    def __init__(self) -> None:
        super().__init__()

        # Application state
        self._is_scanning:     bool  = False
        self._is_imaging:      bool  = False
        self._last_logged_pct: int   = -1
        # Live backend process — set in _imaging_worker, cleared in finally
        self._proc:    Optional[subprocess.Popen] = None
        self._aborted: bool = False

        # Acquisition mode — "Physical" (drive imaging via C backend) or
        # "Logical" (folder tree-copy + per-file hashing, pure Python)
        self._current_mode: str = "Physical"
        # Logical-scan results (populated by the logical scan, used for progress)
        self._logical_total_bytes: int = 0
        self._logical_total_files: int = 0
        # Output location of the most recent successful acquisition — surfaced
        # in the post-completion panel and opened by the "Open Output" button.
        self._last_output_path: str = ""
        # Chain-of-custody case metadata (entered via the Case Info dialog),
        # embedded in every manifest/report and logged at acquisition start.
        self._case_meta: dict = {
            "case": "", "evidence": "", "examiner": "", "notes": "",
        }

        # Telemetry — reset before each acquisition
        self._acq_start:   float = 0.0
        # Worker-side post throttle: the acquisition thread only does the heavy
        # telemetry work ~25 Hz, so a folder of thousands of tiny files can't
        # hammer Python (and starve the Tk main loop → "skipping seconds").
        self._last_post_t: float = 0.0
        # Stable speed/ETA: throughput sampled once per second with a slow EMA,
        # so the ETA can't bounce on bursty (E01) or small-file workloads.
        self._speed_t:        float = 0.0
        self._speed_b:        int   = 0
        self._ema_speed_bps:  float = 0.0
        # Pump-driven wall-clock for the ELAPSED display (decoupled from worker).
        self._last_clock_push: float = 0.0
        # Live bad-sector tally (shown in the details panel).
        self._bad_count: int = 0
        # Live throughput sparkline + E01 segment counter.
        self._spark: deque = deque(maxlen=80)
        self._last_spark_t: float = 0.0
        self._seg_base: str = ""        # E01 segment glob base while imaging
        self._last_seg_t: float = 0.0
        # EMA of the ETA (seconds) — damps the displayed value for the
        # multi-phase logical-E01 path (see _overall_eta).
        self._ema_eta_s: float = 0.0
        # Telemetry text (speed/ETA/transferred/elapsed) refreshes slower
        # (~2 Hz) so the numbers stay readable instead of flickering.
        self._last_telem_push: float = 0.0

        # ── Single-threaded UI pump ───────────────────────────────────────────
        # Worker threads NEVER touch Tk directly during an acquisition (calling
        # self.after() from a background thread floods Tcl's event queue and was
        # making the whole window lag).  Instead a worker drops its latest
        # numbers into self._ui_pending (a plain dict — atomic to assign under
        # the GIL), and ONE main-thread pump (_ui_pump, ~30 Hz) drains it and
        # repaints every widget, easing the progress bar so bursty E01 progress
        # glides instead of lurching.  Imaging/IPC are unaffected — display only.
        self._ui_pending: Optional[dict] = None  # latest telemetry from worker
        self._pump_text:  Optional[dict] = None  # last dict whose text is shown
        self._live_hash:        str = ""         # rolling/per-file hash to show
        self._live_hash_status: str = ""
        self._progress_target:        float = 0.0   # where the bar should be
        self._progress_display:       float = 0.0   # where the bar is drawn
        self._progress_indeterminate: bool  = False  # scan = marquee, no easing
        self._progress_anim_job: Optional[str] = None

        # ── Persistent log ────────────────────────────────────────────────────
        # Every _log() line is mirrored to a session log file so there is a
        # durable record of each acquisition (console output is ephemeral).
        # Best-effort: failure to open never blocks the app.
        self._log_fp = None
        try:
            _logdir = (os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
                       else os.path.dirname(os.path.abspath(__file__)))
            self._log_fp = open(os.path.join(_logdir, "forensic_imager.log"),
                                "a", encoding="utf-8")
            self._log_fp.write(
                f"\n===== Session started {datetime.now():%Y-%m-%d %H:%M:%S} "
                f"=====\n")
            self._log_fp.flush()
        except Exception:
            self._log_fp = None

        # Sector map
        self._sector_states: list = ["idle"] * self.TOTAL_BLOCKS
        self._sector_items:  list = []    # canvas rectangle IDs
        self._last_filled:   int  = -1
        self._resize_job:    Optional[str] = None

        # Window
        self.title("Forensic Disk Imager")
        self.geometry("1360x860")
        self.minsize(1080, 700)
        self.configure(fg_color=_BG)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Intercept the window close button to ensure clean subprocess teardown
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self._build_header()
        self._build_body()

        # Kick off the single main-thread UI pump (runs for the life of the
        # window; cheap no-op while idle / already at target).
        self._progress_anim_job = self.after(33, self._ui_pump)

    # ── Header ────────────────────────────────────────────────────────────────
    def _build_header(self) -> None:
        hdr = ctk.CTkFrame(self, fg_color=_PANEL, corner_radius=0, height=58)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            hdr, text="⬡",
            font=("Segoe UI", 26, "bold"), text_color=_ACCENT,
        ).grid(row=0, column=0, rowspan=2, padx=(18, 10), pady=4)

        ctk.CTkLabel(
            hdr, text="FORENSIC DISK IMAGER",
            font=_F_TITLE, text_color=_TEXT, anchor="w",
        ).grid(row=0, column=1, sticky="sw", pady=(10, 0))

        ctk.CTkLabel(
            hdr,
            text=(
                "Evidence Acquisition"
            ),
            font=("Segoe UI", 9), text_color=_MUTED, anchor="w",
        ).grid(row=1, column=1, sticky="nw", pady=(0, 7))

        self.case_info_btn = ctk.CTkButton(
            hdr, text="📋  Case Info",
            width=130, height=32, font=("Segoe UI", 11, "bold"),
            fg_color=_ENTRY_BG, hover_color=_BORDER, text_color=_TEXT,
            command=self._open_case_info,
        )
        self.case_info_btn.grid(row=0, column=2, rowspan=2, padx=(0, 8),
                                sticky="e")

        plat = "Windows" if sys.platform == "win32" else "Linux"
        ctk.CTkLabel(
            hdr, text=f"  {plat}  ",
            fg_color=_BORDER, corner_radius=4,
            font=("Segoe UI", 9, "bold"), text_color=_MUTED,
        ).grid(row=0, column=3, rowspan=2, padx=(0, 18), sticky="e")

    # ── Body (sidebar + main content) ─────────────────────────────────────────
    def _build_body(self) -> None:
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        self._build_sidebar(body)
        self._build_main(body)

    # ─────────────────────────────────────────────────────────────────────────
    # LEFT SIDEBAR
    # ─────────────────────────────────────────────────────────────────────────
    def _build_sidebar(self, parent: ctk.CTkFrame) -> None:
        sb = ctk.CTkFrame(parent, fg_color=_SIDE, width=285, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)
        # Row 15 (hardware textbox) expands to fill remaining vertical space,
        # which naturally pushes the START IMAGING button to the bottom.
        sb.grid_rowconfigure(15, weight=1)

        # ── Acquisition Parameters ────────────────────────────────────────
        ctk.CTkLabel(
            sb, text="ACQUISITION PARAMETERS",
            font=_F_H2, text_color=_MUTED, anchor="w",
        ).grid(row=0, column=0, padx=14, pady=(14, 6), sticky="w")

        # Acquisition-mode toggle (Physical drive imaging vs Logical folder copy).
        # Switches the target widgets below between the two acquisition paths.
        self.mode_selector = ctk.CTkSegmentedButton(
            sb,
            values=["Physical Imaging", "Logical Imaging"],
            font=_F_BODY,
            fg_color=_ENTRY_BG,
            selected_color=_ACCENT, selected_hover_color="#1f6feb",
            unselected_color=_ENTRY_BG, unselected_hover_color=_BORDER,
            text_color=_TEXT,
            command=self._on_mode_changed,
        )
        self.mode_selector.set("Physical Imaging")
        self.mode_selector.grid(row=1, column=0, sticky="ew",
                                padx=14, pady=(0, 10))

        # ── Physical-mode target widgets (rows 2–4) ───────────────────────
        # Target Drive label
        self._drive_label = ctk.CTkLabel(
            sb, text="Target Drive",
            font=("Segoe UI", 9), text_color=_MUTED, anchor="w",
        )

        self.drive_var = ctk.StringVar(value=self._PLACEHOLDER)
        self.drive_dropdown = ctk.CTkOptionMenu(
            sb,
            variable=self.drive_var,
            values=[self._PLACEHOLDER],
            height=34, font=_F_MONO,
            fg_color=_ENTRY_BG, button_color=_ACCENT,
            button_hover_color="#1f6feb",
            text_color=_TEXT,
            dropdown_fg_color=_PANEL,
            dropdown_text_color=_TEXT,
            dropdown_hover_color=_BORDER,
            command=self._on_drive_selected,
        )

        self.scan_btn = ctk.CTkButton(
            sb, text="Scan Drives", height=32, font=_F_BODY,
            fg_color=_ACCENT, hover_color="#1f6feb",
            command=self.scan_drives,
        )

        # ── Logical-mode target widgets (rows 2–4, mutually exclusive) ─────
        # Target Directory label
        self._dir_label = ctk.CTkLabel(
            sb, text="Target Directory",
            font=("Segoe UI", 9), text_color=_MUTED, anchor="w",
        )

        self.dir_var = ctk.StringVar(value="")
        self.dir_entry = ctk.CTkEntry(
            sb, textvariable=self.dir_var,
            placeholder_text="Source folder to acquire…",
            height=34, font=_F_MONO,
            fg_color=_ENTRY_BG, border_color=_BORDER, text_color=_TEXT,
        )

        self.dir_browse_btn = ctk.CTkButton(
            sb, text="Browse…", height=32, font=_F_BODY,
            fg_color="#21262d", hover_color=_BORDER,
            border_width=1, border_color=_BORDER,
            command=self.browse_directory,
        )

        # Output Image
        ctk.CTkLabel(
            sb, text="Output Image",
            font=("Segoe UI", 9), text_color=_MUTED, anchor="w",
        ).grid(row=5, column=0, padx=14, sticky="w")

        self.output_entry = ctk.CTkEntry(
            sb, placeholder_text="Destination  (.dd / .img)…",
            height=34, font=_F_MONO,
            fg_color=_ENTRY_BG, border_color=_BORDER, text_color=_TEXT,
        )
        self.output_entry.grid(row=6, column=0, sticky="ew",
                               padx=14, pady=(3, 5))

        ctk.CTkButton(
            sb, text="Browse…", height=32, font=_F_BODY,
            fg_color="#21262d", hover_color=_BORDER,
            border_width=1, border_color=_BORDER,
            command=self.browse_output,
        ).grid(row=7, column=0, sticky="ew", padx=14, pady=(0, 10))

        # ── Output Format (Raw DD vs E01) ─────────────────────────────────
        ctk.CTkLabel(
            sb, text="Output Format",
            font=("Segoe UI", 9), text_color=_MUTED, anchor="w",
        ).grid(row=8, column=0, padx=14, sticky="w")

        self.output_format_var = ctk.StringVar(value="Raw (DD)")
        self.format_dropdown = ctk.CTkOptionMenu(
            sb,
            variable=self.output_format_var,
            values=["Raw (DD)", "E01 (EnCase)"],
            height=34, font=_F_MONO,
            fg_color=_ENTRY_BG, button_color=_ACCENT,
            button_hover_color="#1f6feb",
            text_color=_TEXT,
            dropdown_fg_color=_PANEL,
            dropdown_text_color=_TEXT,
            dropdown_hover_color=_BORDER,
            command=self._on_format_changed,
        )
        self.format_dropdown.grid(row=9, column=0, sticky="ew",
                                  padx=14, pady=(3, 5))

        # ── Compression (E01 only) ────────────────────────────────────────
        self._compression_label = ctk.CTkLabel(
            sb, text="Compression",
            font=("Segoe UI", 9), text_color=_MUTED, anchor="w",
        )
        self._compression_label.grid(row=10, column=0, padx=14, sticky="w")

        self.compression_var = ctk.StringVar(value="None")
        self.compression_dropdown = ctk.CTkOptionMenu(
            sb,
            variable=self.compression_var,
            values=["None", "Fast", "Best"],
            height=34, font=_F_MONO,
            fg_color=_ENTRY_BG, button_color=_ACCENT,
            button_hover_color="#1f6feb",
            text_color=_TEXT,
            dropdown_fg_color=_PANEL,
            dropdown_text_color=_TEXT,
            dropdown_hover_color=_BORDER,
        )
        self.compression_dropdown.grid(row=11, column=0, sticky="ew",
                                       padx=14, pady=(3, 8))

        # Verify-after-acquisition toggle (forensic standard; default ON).
        self.verify_var = ctk.BooleanVar(value=True)
        self.verify_check = ctk.CTkCheckBox(
            sb, text="Verify after acquisition",
            variable=self.verify_var, onvalue=True, offvalue=False,
            font=("Segoe UI", 11), text_color=_TEXT,
            fg_color=_ACCENT, hover_color="#1f6feb",
            checkbox_width=18, checkbox_height=18,
        )
        self.verify_check.grid(row=12, column=0, sticky="w",
                               padx=14, pady=(0, 10))

        # Separator
        sep = ctk.CTkFrame(sb, fg_color=_BORDER, height=1, corner_radius=0)
        sep.grid(row=13, column=0, sticky="ew", padx=14)
        sep.grid_propagate(False)

        # ── Hardware Details ──────────────────────────────────────────────
        ctk.CTkLabel(
            sb, text="HARDWARE DETAILS",
            font=_F_H2, text_color=_MUTED, anchor="w",
        ).grid(row=14, column=0, padx=14, pady=(8, 4), sticky="w")

        self.hw_details = ctk.CTkTextbox(
            sb, font=_F_MONO,
            fg_color=_ENTRY_BG, text_color=_TEXT,
            border_color=_BORDER, border_width=1,
            state="disabled", wrap="none",
        )
        self.hw_details.grid(row=15, column=0, sticky="nsew",
                             padx=14, pady=(0, 10))
        self._set_hw_details("Select a drive and\nclick Scan Drives.")

        # ── START IMAGING ─────────────────────────────────────────────────
        self.image_btn = ctk.CTkButton(
            sb, text="▶  START IMAGING",
            height=50, font=_F_BTN,
            fg_color=_GREEN, hover_color="#2ea043",
            text_color="#ffffff", corner_radius=6,
            command=self.start_imaging,
        )
        self.image_btn.grid(row=16, column=0, sticky="ew",
                            padx=14, pady=(0, 14))

        # Apply the default acquisition mode (Physical) — grids the correct
        # target widgets and hides the inactive set.
        self._apply_mode()
        # Apply the default output format (Raw DD) — disables the compression
        # control, which is only meaningful for E01.
        self._on_format_changed(self.output_format_var.get())

    # ─────────────────────────────────────────────────────────────────────────
    # MAIN CONTENT AREA
    # ─────────────────────────────────────────────────────────────────────────
    def _build_main(self, parent: ctk.CTkFrame) -> None:
        main = ctk.CTkFrame(parent, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        self._build_top_panel(main)
        self._build_dashboard(main)

    def _build_top_panel(self, parent: ctk.CTkFrame) -> None:
        panel = ctk.CTkFrame(parent, fg_color=_PANEL, corner_radius=8)
        panel.grid(row=0, column=0, sticky="ew", padx=(6, 14), pady=(8, 4))
        # Column 0: telemetry (fixed width). Column 1: sector map (expands).
        panel.grid_columnconfigure(1, weight=1)
        self._build_telemetry(panel)
        self._build_sector_map(panel)

    # ── Telemetry Dashboard ───────────────────────────────────────────────────
    def _build_telemetry(self, parent: ctk.CTkFrame) -> None:
        frame = ctk.CTkFrame(parent, fg_color="transparent", width=372)
        frame.grid(row=0, column=0, sticky="nsew", padx=(10, 4), pady=10)
        frame.grid_propagate(False)
        frame.grid_columnconfigure((0, 1), weight=1)
        frame.grid_rowconfigure((0, 1), weight=1)

        self._telem: dict[str, ctk.CTkLabel] = {}
        _cards = [
            ("speed",       "SPEED",       "--   MB/s"),
            ("eta",         "ETA",         "--:--:--"),
            ("transferred", "TRANSFERRED", "0.000 GiB"),
            ("elapsed",     "ELAPSED",     "00:00:00"),
        ]

        for i, (key, label, init) in enumerate(_cards):
            row, col = divmod(i, 2)
            card = ctk.CTkFrame(frame, fg_color=_CARD_BG, corner_radius=6)
            card.grid(
                row=row, column=col, sticky="nsew",
                padx=(0, 3) if col == 0 else (3, 0),
                pady=(0, 3) if row == 0 else (3, 0),
            )
            card.grid_columnconfigure(0, weight=1)

            val_lbl = ctk.CTkLabel(
                card, text=init, font=_F_TVAL,
                text_color=_TEXT, anchor="center",
            )
            val_lbl.grid(row=0, column=0, padx=8, pady=(10, 2), sticky="ew")

            ctk.CTkLabel(
                card, text=label, font=_F_TLBL,
                text_color=_MUTED, anchor="center",
            ).grid(row=1, column=0, padx=8, pady=(0, 8), sticky="ew")

            self._telem[key] = val_lbl

        # Progress bar below the 4 cards
        pb_row = ctk.CTkFrame(frame, fg_color="transparent")
        pb_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        pb_row.grid_columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(
            pb_row, height=10,
            progress_color=_ACCENT, fg_color=_BORDER,
        )
        self.progress_bar.set(0.0)
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.progress_lbl = ctk.CTkLabel(
            pb_row, text="Idle",
            font=_F_MONO, text_color=_MUTED, width=62, anchor="e",
        )
        self.progress_lbl.grid(row=0, column=1)

    # ── Live Sector Map ───────────────────────────────────────────────────────
    def _build_sector_map(self, parent: ctk.CTkFrame) -> None:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Header row with legend
        hdr = ctk.CTkFrame(frame, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="LIVE SECTOR MAP",
            font=_F_H2, text_color=_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hdr,
            text="written  ■   bad sector  ■   unread",
            font=("Consolas", 8), text_color=_MUTED, anchor="e",
        ).grid(row=0, column=1, sticky="e")

        # The canvas — height=140 sets a natural minimum; it fills the panel
        self.sector_canvas = tk.Canvas(
            frame, bg=_MAP_BG,
            highlightthickness=1, highlightbackground=_BORDER,
            height=140,
        )
        self.sector_canvas.grid(row=1, column=0, sticky="nsew", pady=(4, 0))
        self.sector_canvas.bind("<Configure>", self._on_map_configure)

    # ── Live Hash Dashboard ─────────────────────────────────────────────────
    _HASH_PLACEHOLDER = "0" * 64

    def _build_dashboard(self, parent: ctk.CTkFrame) -> None:
        """Replaces the old text Operation Log with a clean dashboard whose
        centrepiece is the live SHA-256 hash of the acquisition."""
        card = ctk.CTkFrame(parent, fg_color=_PANEL, corner_radius=8)
        card.grid(row=1, column=0, sticky="nsew", padx=(6, 14), pady=(4, 8))
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(6, weight=1)

        # Section title row: title · live sparkline · phase chip
        trow = ctk.CTkFrame(card, fg_color="transparent")
        trow.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 4))
        trow.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            trow, text="LIVE SHA-256 HASH",
            font=_F_H2, text_color=_MUTED, anchor="w").grid(
            row=0, column=0, sticky="w")

        # Live throughput sparkline (drawn by the pump from recent speeds).
        self.spark_canvas = tk.Canvas(
            trow, width=160, height=22, bg=_PANEL,
            highlightthickness=0, bd=0)
        self.spark_canvas.grid(row=0, column=1, sticky="e", padx=(0, 10))

        # Phase chip — colour-coded pill: IDLE → ACQUIRING → … → DONE.
        self.phase_chip = ctk.CTkLabel(
            trow, text="  IDLE  ", font=("Segoe UI", 10, "bold"),
            fg_color=_BORDER, text_color=_MUTED, corner_radius=10)
        self.phase_chip.grid(row=0, column=2, sticky="e")

        # Prominent read-only hash field, spanning the full width
        self.hash_var = ctk.StringVar(value=self._HASH_PLACEHOLDER)
        self.hash_entry = ctk.CTkEntry(
            card, textvariable=self.hash_var,
            font=("Consolas", 13), justify="center",
            height=44,
            fg_color=_BG, text_color=_GREEN,
            border_color=_BORDER, border_width=1,
        )
        self.hash_entry.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 6))
        self.hash_entry.configure(state="readonly")

        # Status / verification caption — larger and colour-coded so the result
        # is easy to spot at a glance.
        self.hash_status = ctk.CTkLabel(
            card, text="Awaiting acquisition…",
            font=("Segoe UI", 14, "bold"), text_color=_MUTED,
            anchor="w", justify="left", wraplength=940,
        )
        self.hash_status.grid(row=2, column=0, sticky="w", padx=14, pady=(2, 6))

        # MD5 / SHA-1 — always visible right under the verification line so they
        # never get clipped by the details panel / output bar.
        hf = ctk.CTkFrame(card, fg_color="transparent")
        hf.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 8))
        hf.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(hf, text="MD5", font=("Segoe UI", 10), text_color=_MUTED,
                     width=56, anchor="w").grid(row=0, column=0, sticky="w")
        self.md5_lbl = ctk.CTkLabel(hf, text="—", font=("Consolas", 12),
                                    text_color=_TEXT, anchor="w")
        self.md5_lbl.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(hf, text="SHA-1", font=("Segoe UI", 10), text_color=_MUTED,
                     width=56, anchor="w").grid(row=1, column=0, sticky="w")
        self.sha1_lbl = ctk.CTkLabel(hf, text="—", font=("Consolas", 12),
                                     text_color=_TEXT, anchor="w")
        self.sha1_lbl.grid(row=1, column=1, sticky="w")

        # Separator
        _dsep = ctk.CTkFrame(card, fg_color=_BORDER, height=1, corner_radius=0)
        _dsep.grid(row=4, column=0, sticky="ew", padx=14, pady=(0, 8))

        # ── Acquisition details — styled properties panel (not a terminal) ────
        ctk.CTkLabel(
            card, text="◆  ACQUISITION DETAILS",
            font=_F_H2, text_color=_MUTED, anchor="w",
        ).grid(row=5, column=0, sticky="w", padx=14, pady=(0, 4))

        det = ctk.CTkFrame(card, fg_color=_BG, corner_radius=8,
                           border_color=_BORDER, border_width=1)
        det.grid(row=6, column=0, sticky="nsew", padx=14, pady=(0, 12))
        det.grid_columnconfigure(0, weight=1)

        # Static rows live here (rebuilt on each START); dynamic rows persist.
        self._details_static = ctk.CTkFrame(det, fg_color="transparent")
        self._details_static.grid(row=0, column=0, sticky="ew",
                                  padx=4, pady=(10, 2))
        self._details_static.grid_columnconfigure(1, weight=1)

        _hsep = ctk.CTkFrame(det, fg_color=_BORDER, height=1, corner_radius=0)
        _hsep.grid(row=1, column=0, sticky="ew", padx=14, pady=4)

        dyn = ctk.CTkFrame(det, fg_color="transparent")
        dyn.grid(row=2, column=0, sticky="ew", padx=4, pady=(2, 10))
        dyn.grid_columnconfigure(1, weight=1)
        self._dv = {}
        for i, (key, label, col) in enumerate([
            ("segments", "Segments",    _ACCENT),
            ("bad",      "Bad sectors", _GREEN),
        ]):
            ctk.CTkLabel(dyn, text=label, font=("Segoe UI", 10),
                         text_color=_MUTED, anchor="w", width=92).grid(
                row=i, column=0, sticky="w", padx=(12, 10), pady=2)
            v = ctk.CTkLabel(dyn, text="—", font=("Consolas", 12),
                             text_color=col, anchor="w",
                             justify="left", wraplength=660)
            v.grid(row=i, column=1, sticky="w", pady=2)
            self._dv[key] = v

        self._set_acq_details(None)

        # ── Output location (revealed only after a successful acquisition) ─────
        self.output_panel = ctk.CTkFrame(
            card, fg_color=_BG, corner_radius=6,
            border_color=_GREEN, border_width=1,
        )
        self.output_panel.grid(row=7, column=0, sticky="ew", padx=14, pady=(0, 12))
        self.output_panel.grid_columnconfigure(0, weight=1)
        self.output_panel.grid_remove()   # hidden until an acquisition completes

        self._output_caption = ctk.CTkLabel(
            self.output_panel, text="",
            font=_F_MONO, text_color=_TEXT,
            anchor="w", justify="left", wraplength=620,
        )
        self._output_caption.grid(row=0, column=0, sticky="w",
                                  padx=12, pady=10)

        self._open_output_btn = ctk.CTkButton(
            self.output_panel, text="📂  Open Output Location",
            width=210, height=38, font=_F_BTN,
            fg_color=_ACCENT, hover_color="#1f6feb", text_color="#ffffff",
            command=self._open_output_location,
        )
        self._open_output_btn.grid(row=0, column=1, sticky="e",
                                   padx=(8, 12), pady=10)

    def _open_output_location(self) -> None:
        """Open the most recent acquisition's output in the system file manager.

        Files are revealed-and-selected; directories are opened directly.  If
        the exact path is gone (e.g. an E01 set whose typed name differs from
        the real .E01), fall back to opening the containing folder.
        """
        path = self._last_output_path
        if not path:
            return
        try:
            if sys.platform == "win32":
                norm = os.path.normpath(path)
                if os.path.isdir(norm):
                    os.startfile(norm)                      # noqa: S606
                elif os.path.exists(norm):
                    # explorer selects the file within its folder
                    subprocess.Popen(f'explorer /select,"{norm}"')
                else:
                    parent = os.path.dirname(norm)
                    if os.path.isdir(parent):
                        os.startfile(parent)                # noqa: S606
                    else:
                        self._log(
                            f"Output path no longer exists: {norm}", "WARN")
            else:
                opener = "open" if sys.platform == "darwin" else "xdg-open"
                target = path if os.path.isdir(path) else os.path.dirname(path)
                subprocess.Popen([opener, target])
        except Exception as exc:
            self._log(f"Could not open output location: {exc}", "ERROR")

    @staticmethod
    def _parse_size_to_bytes(text: str) -> int:
        """Extract a byte count from a drive label like '… (7 GiB)'.  Returns 0
        if no size can be parsed (size check is then skipped)."""
        m = re.search(r"\(([\d.]+)\s*(B|KiB|MiB|GiB|TiB)\)", text or "")
        if not m:
            return 0
        val   = float(m.group(1))
        units = {"B": 1, "KiB": 1024, "MiB": 1024**2,
                 "GiB": 1024**3, "TiB": 1024**4}
        return int(val * units.get(m.group(2), 1))

    def _preflight(self, summary: str, dst_path: str, est_bytes: int) -> bool:
        """Pre-acquisition safety gate (runs on the main thread).

        Checks free space at the destination and shows a confirmation dialog
        summarising the operation.  Returns True to proceed, False to cancel.
        """
        free = None
        try:
            check_dir = (dst_path if os.path.isdir(dst_path)
                         else os.path.dirname(os.path.abspath(dst_path)) or ".")
            free = shutil.disk_usage(check_dir).free
        except Exception:
            free = None

        warn = ""
        if free is not None and est_bytes > 0 and free < est_bytes:
            warn = (
                f"\n\n⚠  WARNING: destination free space "
                f"({free / 1024**3:.2f} GiB) is LESS than the estimated "
                f"size ({est_bytes / 1024**3:.2f} GiB).\n"
                "The acquisition may run out of space and fail."
            )

        msg = summary
        if free is not None:
            msg += f"\n\nDestination free space: {free / 1024**3:.2f} GiB"
        if est_bytes > 0:
            msg += f"\nEstimated acquisition size: {est_bytes / 1024**3:.2f} GiB"
        msg += warn + "\n\nProceed with acquisition?"

        return messagebox.askyesno(
            "Confirm Acquisition", msg,
            icon="warning" if warn else "question",
        )

    # ── Case / examiner metadata (chain of custody) ───────────────────────────
    def _open_case_info(self) -> None:
        """Modal dialog to capture Case #, Evidence #, Examiner and Notes."""
        dlg = ctk.CTkToplevel(self)
        dlg.title("Case Information")
        dlg.geometry("480x420")
        dlg.configure(fg_color=_BG)
        dlg.transient(self)
        dlg.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(dlg, text="CASE INFORMATION", font=_F_H2,
                     text_color=_MUTED, anchor="w").grid(
            row=0, column=0, sticky="w", padx=18, pady=(16, 8))

        entries = {}
        fields = [("Case Number", "case"), ("Evidence Number", "evidence"),
                  ("Examiner", "examiner")]
        r = 1
        for label, key in fields:
            ctk.CTkLabel(dlg, text=label, font=("Segoe UI", 10),
                         text_color=_MUTED, anchor="w").grid(
                row=r, column=0, sticky="w", padx=18)
            e = ctk.CTkEntry(dlg, height=34, font=_F_MONO,
                             fg_color=_ENTRY_BG, text_color=_TEXT,
                             border_color=_BORDER, border_width=1)
            e.insert(0, self._case_meta.get(key, ""))
            e.grid(row=r + 1, column=0, sticky="ew", padx=18, pady=(2, 8))
            entries[key] = e
            r += 2

        ctk.CTkLabel(dlg, text="Description / Notes", font=("Segoe UI", 10),
                     text_color=_MUTED, anchor="w").grid(
            row=r, column=0, sticky="w", padx=18)
        notes = ctk.CTkTextbox(dlg, height=80, font=_F_MONO,
                               fg_color=_ENTRY_BG, text_color=_TEXT,
                               border_color=_BORDER, border_width=1)
        notes.insert("1.0", self._case_meta.get("notes", ""))
        notes.grid(row=r + 1, column=0, sticky="ew", padx=18, pady=(2, 12))

        btns = ctk.CTkFrame(dlg, fg_color="transparent")
        btns.grid(row=r + 2, column=0, sticky="e", padx=18, pady=(0, 14))

        def _save() -> None:
            for k, e in entries.items():
                self._case_meta[k] = e.get().strip()
            self._case_meta["notes"] = notes.get("1.0", "end").strip()
            self._update_case_btn()
            self._log("Case metadata updated.", "INFO")
            dlg.destroy()

        ctk.CTkButton(btns, text="Cancel", width=90, height=34,
                      fg_color=_ENTRY_BG, hover_color=_BORDER,
                      text_color=_TEXT, command=dlg.destroy).grid(
            row=0, column=0, padx=(0, 8))
        ctk.CTkButton(btns, text="Save", width=110, height=34,
                      fg_color=_GREEN, hover_color="#2ea043",
                      text_color="#ffffff", command=_save).grid(
            row=0, column=1)

        dlg.after(120, dlg.grab_set)   # grab after the window is mapped

    def _update_case_btn(self) -> None:
        c = self._case_meta.get("case", "")
        self.case_info_btn.configure(text=f"📋  {c}" if c else "📋  Case Info")

    def _metadata_rows(self) -> list:
        """Chain-of-custody header rows prepended to every manifest."""
        m  = self._case_meta
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return [
            ["# Forensic Acquisition Manifest"],
            ["# Case Number",     m.get("case", "")],
            ["# Evidence Number", m.get("evidence", "")],
            ["# Examiner",        m.get("examiner", "")],
            ["# Description",     (m.get("notes", "") or "").replace("\n", " ")],
            ["# Acquired (local)", ts],
            ["# Tool",            "Forensic Disk Imager"],
            [],
        ]

    def _log_case_meta(self) -> None:
        """Record the active case metadata in the session log."""
        m = self._case_meta
        if any(m.values()):
            self._log(
                f"Case: {m.get('case') or '—'}  |  "
                f"Evidence: {m.get('evidence') or '—'}  |  "
                f"Examiner: {m.get('examiner') or '—'}", "INFO")
            if m.get("notes"):
                self._log(f"Notes: {m['notes']}", "INFO")

    @staticmethod
    def _status_color(text: str) -> str:
        """Colour for the status caption, inferred from its wording so the
        verification result pops (green = ok, red = failed, blue = working)."""
        t = (text or "").lower()
        if "failed" in t or "does not match" in t or "✗" in t:
            return _RED
        if "verified ✓" in t or "verification passed" in t or "match" in t:
            return _GREEN
        if "verifying" in t or "finaliz" in t or "hashing" in t:
            return _ACCENT
        if "could not" in t or "skipped" in t or "warning" in t:
            return _AMBER
        return _MUTED

    def _set_phase(self, label: str, fg: str, fgtext: str = "#ffffff") -> None:
        """Update the colour-coded phase chip (main thread)."""
        self.phase_chip.configure(text=f"  {label}  ",
                                  fg_color=fg, text_color=fgtext)

    def _set_status(self, text: str) -> None:
        """Set the big status caption (coloured) and the phase chip from the
        wording of the status (main thread)."""
        self.hash_status.configure(text=text,
                                   text_color=self._status_color(text))
        t = (text or "").lower()
        if "failed" in t or "does not match" in t:
            self._set_phase("FAILED", _RED)
        elif "verified ✓" in t or "written ✓" in t:
            self._set_phase("DONE", _GREEN)
        elif "verifying" in t:
            self._set_phase("VERIFYING", _ACCENT)
        elif "finaliz" in t:
            self._set_phase("FINALIZING", _AMBER, "#000000")
        elif "creating e01" in t or "compress" in t:
            self._set_phase("COMPRESSING", _ACCENT)
        elif any(k in t for k in ("reading", "hashing", "building",
                                  "copying", "preparing", "opening")):
            self._set_phase("ACQUIRING", _ACCENT)
        elif "could not" in t or "skipped" in t:
            self._set_phase("WARNING", _AMBER, "#000000")

    def _draw_spark(self) -> None:
        """Render the live throughput sparkline from recent speed samples."""
        c = self.spark_canvas
        try:
            c.delete("all")
            data = list(self._spark)
            if len(data) < 2:
                return
            w = c.winfo_width() or 160
            h = c.winfo_height() or 22
            mx = max(data) or 1.0
            n = len(data)
            flat = []
            for i, v in enumerate(data):
                flat.append(1 + i * (w - 2) / (n - 1))
                flat.append(h - 1 - (v / mx) * (h - 3))
            c.create_line(*flat, fill=_GREEN, width=1, smooth=True)
        except Exception:
            pass

    def _set_hash(self, value: str, status: str = "") -> None:
        """Thread-safe update of the live hash field and its caption."""
        def _do() -> None:
            self.hash_entry.configure(state="normal")
            self.hash_var.set(value if value else self._HASH_PLACEHOLDER)
            self.hash_entry.configure(state="readonly")
            if status:
                self._set_status(status)

        self.after(0, _do)

    def _set_detail(self, key: str, value: str, color: str = None) -> None:
        """Update one dynamic detail value (bad/sha256/md5/sha1).  Thread-safe."""
        def _do() -> None:
            lbl = self._dv.get(key)
            if lbl is not None:
                lbl.configure(text=value if value else "—")
                if color:
                    lbl.configure(text_color=color)
        self.after(0, _do)

    def _set_acq_details(self, info) -> None:
        """(Re)build the static rows of the ACQUISITION DETAILS panel.  `info`
        is a list of (label, value) pairs, or None for the idle placeholder.
        Runs on the main thread (called from START)."""
        for w in self._details_static.winfo_children():
            w.destroy()
        if not info:
            ctk.CTkLabel(
                self._details_static,
                text="No acquisition in progress — configure on the left, set "
                     "Case Info, then press  ▶ START IMAGING.",
                font=("Segoe UI", 11), text_color=_MUTED,
                anchor="w", justify="left", wraplength=660).grid(
                row=0, column=0, columnspan=2, sticky="w", padx=12, pady=6)
        else:
            for i, (label, value) in enumerate(info):
                ctk.CTkLabel(
                    self._details_static, text=label, font=("Segoe UI", 10),
                    text_color=_MUTED, anchor="w", width=92).grid(
                    row=i, column=0, sticky="w", padx=(12, 10), pady=2)
                ctk.CTkLabel(
                    self._details_static, text=str(value),
                    font=("Consolas", 12), text_color=_TEXT,
                    anchor="w", justify="left", wraplength=660).grid(
                    row=i, column=1, sticky="w", pady=2)
        # Reset the dynamic rows + integrity-hash lines for the new run.
        self._set_detail("segments", "—", _ACCENT)
        self._set_detail("bad", "—", _GREEN)
        self.md5_lbl.configure(text="—")
        self.sha1_lbl.configure(text="—")
        if not info:
            self._set_phase("IDLE", _BORDER, _MUTED)

    def _append_acq_hashes(self, sha256: str = "", md5: str = "",
                           sha1: str = "", note: str = "") -> None:
        """Fill the always-visible MD5 / SHA-1 lines (SHA-256 is the big hash
        field).  Thread-safe."""
        def _do() -> None:
            self.md5_lbl.configure(text=(md5 or note or "—"))
            self.sha1_lbl.configure(text=(sha1 or note or "—"))
        self.after(0, _do)

    def _append_hashes_to_report(self, report_path: str, md5: str, sha1: str,
                                 sha256: str) -> None:
        """Append the MD5 / SHA-1 / SHA-256 block to the existing chain-of-
        custody report so everything stays in one file."""
        if not report_path or not os.path.isfile(report_path):
            return
        try:
            with open(report_path, "a", encoding="utf-8") as f:
                f.write("\n")
                f.write("-" * 70 + "\n")
                f.write("  INTEGRITY HASHES (verification re-read)\n")
                f.write("-" * 70 + "\n")
                f.write(f"  MD5      : {md5 or '(not available)'}\n")
                f.write(f"  SHA-1    : {sha1 or '(not available)'}\n")
                f.write(f"  SHA-256  : {sha256 or '(not available)'}\n")
            self._log(f"Hashes appended to report:  {report_path}", "SUCCESS")
        except Exception as exc:
            self._log(f"Could not append hashes to report: {exc}", "WARN")

    # ─────────────────────────────────────────────────────────────────────────
    # SECTOR MAP LOGIC
    # ─────────────────────────────────────────────────────────────────────────

    def _on_map_configure(self, _event: tk.Event) -> None:
        """Debounce canvas resize: rebuild grid after 80 ms of silence."""
        if self._resize_job:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(80, self._build_sector_grid)

    def _build_sector_grid(self) -> None:
        """(Re)create all 1 000 rectangles on the sector-map canvas.
        Re-applies current state colours so the map survives window resize."""
        canvas = self.sector_canvas
        cw = canvas.winfo_width()
        ch = canvas.winfo_height()
        if cw < 30 or ch < 20:
            return

        canvas.delete("all")
        self._sector_items.clear()

        pad = 4
        gap = 1
        bw  = (cw - 2 * pad - (self.GRID_COLS - 1) * gap) / self.GRID_COLS
        bh  = (ch - 2 * pad - (self.GRID_ROWS - 1) * gap) / self.GRID_ROWS

        for row in range(self.GRID_ROWS):
            for col in range(self.GRID_COLS):
                idx   = row * self.GRID_COLS + col
                x0    = pad + col * (bw + gap)
                y0    = pad + row * (bh + gap)
                state = (self._sector_states[idx]
                         if idx < len(self._sector_states) else "idle")
                color = (_MAP_WRITTEN if state == "written" else
                         _MAP_BAD     if state == "bad"     else _MAP_IDLE)
                item  = canvas.create_rectangle(
                    x0, y0, x0 + bw, y0 + bh,
                    fill=color, outline="",
                )
                self._sector_items.append(item)

    def _reset_sector_map(self) -> None:
        """Reset all blocks to idle (unread).  Must run on main thread."""
        self._sector_states = ["idle"] * self.TOTAL_BLOCKS
        self._last_filled   = -1
        for item in self._sector_items:
            self.sector_canvas.itemconfig(item, fill=_MAP_IDLE)

    def _advance_sector_map(self, pct: float) -> None:
        """Colour all blocks up to `pct` green.  Must run on main thread.
        Skips blocks already marked as bad sectors."""
        if not self._sector_items:
            return
        target = (self.TOTAL_BLOCKS - 1 if pct >= 1.0
                  else int(pct * self.TOTAL_BLOCKS))
        target = max(0, min(target, self.TOTAL_BLOCKS - 1))

        for i in range(self._last_filled + 1, target + 1):
            if self._sector_states[i] != "bad":
                self._sector_states[i] = "written"
                self.sector_canvas.itemconfig(
                    self._sector_items[i], fill=_MAP_WRITTEN)

        if target > self._last_filled:
            self._last_filled = target

    def _mark_bad_block(self) -> None:
        """Mark the leading edge block red on a bad-sector warning.
        Must run on main thread."""
        if not self._sector_items:
            return
        block = max(0, min(self._last_filled + 1, self.TOTAL_BLOCKS - 1))
        self._sector_states[block] = "bad"
        self.sector_canvas.itemconfig(self._sector_items[block], fill=_MAP_BAD)
        # Include the bad block in the processed range so _advance_sector_map
        # starts from block+1 and never overwrites it.
        self._last_filled = max(self._last_filled, block)

    # ─────────────────────────────────────────────────────────────────────────
    # UTILITIES
    # ─────────────────────────────────────────────────────────────────────────

    def _get_backend_exe(self) -> str:
        """Delegate to the module-level get_backend_path() so both
        development and PyInstaller --onefile runtimes work correctly."""
        return get_backend_path()

    def _log(self, message: str, level: str = "INFO") -> None:
        """Emit a diagnostic line to the console.

        The on-screen Operation Log was removed in V2.0, but worker threads
        still call _log heavily for progress/diagnostics.  Routing to stdout
        keeps every existing call site working and is inherently thread-safe
        (no Tk widget access), so no after(0, ...) marshalling is needed.
        """
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level:<7}] {message}"
        # NEVER let a logging call crash a worker thread.  When the app runs
        # windowed (pythonw / PyInstaller --windowed) sys.stdout is None and a
        # bare print() raises, which previously killed the acquisition thread
        # before it could reset the UI.  Swallow any such failure.
        try:
            print(line)
        except Exception:
            pass
        # Mirror to the durable session log (best-effort).
        fp = self._log_fp
        if fp is not None:
            try:
                fp.write(line + "\n")
                fp.flush()
            except Exception:
                pass

    def _set_hw_details(self, text: str) -> None:
        """Replace hardware details textbox content.  Main-thread safe."""
        self.hw_details.configure(state="normal")
        self.hw_details.delete("1.0", "end")
        self.hw_details.insert("1.0", text)
        self.hw_details.configure(state="disabled")

    def _set_progress(self, value: Optional[float], label: str = "") -> None:
        """Thread-safe progress bar update (schedules via after(0, ...)).

        A determinate ``value`` SNAPS the bar to that position immediately —
        use this for resets and the final 100 %.  Live progress ticks go through
        _post_progress()/_ui_pump() instead so the bar eases smoothly.
        ``value=None`` switches the bar to indeterminate marquee (scanning).
        """
        def _do() -> None:
            if value is None:
                self._progress_indeterminate = True
                self.progress_bar.configure(mode="indeterminate")
                self.progress_bar.start()
            else:
                self._progress_indeterminate = False
                self.progress_bar.stop()
                self.progress_bar.configure(mode="determinate")
                v = max(0.0, min(1.0, value))
                self._progress_target  = v
                self._progress_display = v          # snap (no easing)
                self.progress_bar.set(v)
            if label:
                self.progress_lbl.configure(text=label)

        self.after(0, _do)

    def _post_progress(self, pct: float, pct_str: str,
                       speed: str, eta: str, xfer: str, elapsed: str,
                       hash_val: Optional[str] = None,
                       hash_status: Optional[str] = None,
                       finalize: bool = False) -> None:
        """Called FROM A WORKER THREAD on every progress tick.

        Does NOT touch Tk — it only stores the latest snapshot (overwriting any
        previous unconsumed one, so fast producers naturally coalesce).  The
        main-thread _ui_pump consumes it.  A plain attribute assignment is
        atomic under the GIL, so no lock is needed.

        ``finalize=True`` flags a no-measurable-progress phase (E01 flush, zip
        close, verification spin-up) — the pump shows an animated marquee.
        """
        self._ui_pending = {
            "pct": max(0.0, min(1.0, pct)), "pct_str": pct_str,
            "speed": speed, "eta": eta, "xfer": xfer, "elapsed": elapsed,
            "hash": hash_val, "hash_status": hash_status, "finalize": finalize,
        }

    def _post_busy(self, label: str, caption: str) -> None:
        """Worker-thread helper: enter the animated 'busy' (marquee) state for a
        phase that produces no measurable progress (e.g. flushing/closing)."""
        self._ui_pending = {
            "pct": 1.0, "pct_str": label,
            "speed": None, "eta": None, "xfer": None, "elapsed": None,
            "hash": None, "hash_status": caption, "finalize": True,
        }

    def _ui_pump(self) -> None:
        """Single main-thread repaint loop (~30 Hz).  Drains the latest worker
        snapshot, updates the dashboard, and eases the progress bar toward its
        target so motion stays smooth even when progress arrives in bursts.

        Runs for the whole window lifetime; a no-op while idle.
        """
        try:
            now = time.monotonic()

            # 1) Consume the latest worker snapshot (only while imaging, so a
            #    stale post can't disturb a scan marquee or a finished run).
            data = self._ui_pending
            if data is not None and self._is_imaging:
                self._ui_pending = None
                if data.get("finalize"):
                    # Enter the animated marquee for a no-progress phase.
                    if not self._progress_indeterminate:
                        self._progress_indeterminate = True
                        self.progress_bar.configure(mode="indeterminate")
                        self.progress_bar.start()
                else:
                    if self._progress_indeterminate:
                        # Leaving marquee → back to determinate easing.
                        self.progress_bar.stop()
                        self.progress_bar.configure(mode="determinate")
                        self._progress_indeterminate = False
                    self._progress_target = data["pct"]
                self._pump_text = data            # shown by the throttled block

            # 2) Ease the bar + advance the sector map (only when moving and not
            #    in the animated marquee state).
            if not self._progress_indeterminate:
                if self._progress_target > 0.0:
                    self._advance_sector_map(self._progress_target)
                diff = self._progress_target - self._progress_display
                if abs(diff) >= 0.0008:
                    self._progress_display += diff * 0.25       # ease-out
                    self.progress_bar.set(
                        max(0.0, min(1.0, self._progress_display)))
                elif self._progress_display != self._progress_target:
                    self._progress_display = self._progress_target
                    self.progress_bar.set(self._progress_display)

            # 2b) Drive the ELAPSED clock on the pump's own wall-clock, NOT on
            #     worker posts.  At 1 MB/s a 4 MiB chunk takes ~4 s, so the
            #     worker only posts every ~4 s — driving the clock here keeps it
            #     ticking smoothly instead of freezing then jumping.
            if self._is_imaging and self._acq_start > 0.0:
                if (now - self._last_clock_push) >= 0.2:
                    self._last_clock_push = now
                    self._telem["elapsed"].configure(
                        text=_fmt_hms(now - self._acq_start))

            # 2c) Live throughput sparkline (~2 Hz) + E01 segment count (~1 Hz).
            if self._is_imaging:
                if (now - self._last_spark_t) >= 0.5:
                    self._last_spark_t = now
                    self._spark.append(self._ema_speed_bps / (1024 ** 2))
                    self._draw_spark()
                if self._seg_base and (now - self._last_seg_t) >= 1.0:
                    self._last_seg_t = now
                    n = len(glob.glob(self._seg_base + ".E*"))
                    self._set_detail("segments", str(max(n, 1)), _ACCENT)

            # 3) Text (speed/ETA/transferred/%/hash) at ~5 Hz so the numbers stay
            #    readable.  Fields may be None in the busy state — only update
            #    those provided.  (Elapsed is handled above on wall-clock time.)
            d = self._pump_text
            if d is not None and (now - self._last_telem_push) >= 0.2:
                self._last_telem_push = now
                self._pump_text = None
                if d.get("pct_str"):
                    self.progress_lbl.configure(text=d["pct_str"])
                if d.get("speed") is not None:
                    self._telem["speed"].configure(text=d["speed"])
                if d.get("eta") is not None:
                    self._telem["eta"].configure(text=d["eta"])
                if d.get("xfer") is not None:
                    self._telem["transferred"].configure(text=d["xfer"])
                if d.get("hash"):
                    self.hash_entry.configure(state="normal")
                    self.hash_var.set(d["hash"])
                    self.hash_entry.configure(state="readonly")
                if d.get("hash_status"):
                    self._set_status(d["hash_status"])
        except Exception:
            pass
        try:
            self._progress_anim_job = self.after(33, self._ui_pump)
        except Exception:
            self._progress_anim_job = None

    def _update_telem(self, speed: str, eta: str,
                      xfer: str, elapsed: str) -> None:
        """Thread-safe telemetry label update."""
        def _do() -> None:
            self._telem["speed"].configure(text=speed)
            self._telem["eta"].configure(text=eta)
            self._telem["transferred"].configure(text=xfer)
            self._telem["elapsed"].configure(text=elapsed)

        self.after(0, _do)

    def _reset_telem(self) -> None:
        """Reset all telemetry displays.  Called via after(0, ...) so it runs
        on the main thread directly — no inner after() needed."""
        self._telem["speed"].configure(text="--   MB/s")
        self._telem["eta"].configure(text="--:--:--")
        self._telem["transferred"].configure(text="0.000 GiB")
        self._telem["elapsed"].configure(text="00:00:00")
        self._progress_indeterminate = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self._progress_target  = 0.0
        self._progress_display = 0.0
        self.progress_bar.set(0.0)
        self.progress_lbl.configure(text="0 %")

    # ─────────────────────────────────────────────────────────────────────────
    # HARDWARE INTERROGATION
    # ─────────────────────────────────────────────────────────────────────────

    def _on_drive_selected(self, choice: str) -> None:
        """CTkOptionMenu command callback — runs on main thread."""
        if choice == self._PLACEHOLDER:
            return
        self._set_hw_details("Querying hardware…")
        threading.Thread(
            target=self._hw_interrogate_worker,
            args=(choice,), daemon=True,
        ).start()

    def _hw_interrogate_worker(self, drive_label: str) -> None:
        if sys.platform == "win32":
            self._hw_win(drive_label)
        else:
            self._hw_linux(drive_label)

    def _hw_win(self, drive_label: str) -> None:
        """Query hardware details via PowerShell Get-PhysicalDisk."""
        m = re.search(r"PhysicalDrive(\d+)", drive_label)
        if not m:
            self.after(0, lambda: self._set_hw_details(
                "Cannot parse device ID\nfrom drive label."))
            return

        dev_id = m.group(1)
        ps = (
            f"$d = Get-PhysicalDisk | Where-Object {{ $_.DeviceId -eq {dev_id} }}; "
            "if ($d) { $d | Select-Object FriendlyName, MediaType, Size, "
            "SerialNumber, BusType, FirmwareVersion "
            "| ConvertTo-Json -Depth 1 } else { Write-Output 'NOT_FOUND' }"
        )
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=12,
                creationflags=CREATE_NO_WINDOW,
            )
            raw = r.stdout.strip()
            if not raw or raw == "NOT_FOUND":
                self.after(0, lambda: self._set_hw_details(
                    f"No data for PhysicalDrive{dev_id}.\n"
                    "Run as Administrator\nfor full hardware access."))
                return

            info = json.loads(raw)
            if isinstance(info, list):
                info = info[0] if info else {}

            model  = info.get("FriendlyName", "Unknown")
            media  = info.get("MediaType",    "Unknown")
            sz_b   = info.get("Size", 0) or 0
            sz_gib = sz_b / (1024 ** 3)
            serial = (str(info.get("SerialNumber", "")).strip() or "—")
            bus    = (str(info.get("BusType", "")).strip() or "—")
            fw     = (str(info.get("FirmwareVersion", "")).strip() or "—")

            text = (
                f"Model  : {model}\n"
                f"Type   : {media}  ({bus})\n"
                f"Size   : {sz_gib:.2f} GiB\n"
                f"Serial : {serial}\n"
                f"Firmwre: {fw}\n"
                f"Device : \\\\.\\PhysicalDrive{dev_id}"
            )
            self.after(0, lambda t=text: self._set_hw_details(t))

        except subprocess.TimeoutExpired:
            self.after(0, lambda: self._set_hw_details(
                "Hardware query timed out."))
        except json.JSONDecodeError as exc:
            self.after(0, lambda e=str(exc): self._set_hw_details(
                f"JSON parse error:\n{e}"))
        except Exception as exc:
            self.after(0, lambda e=str(exc): self._set_hw_details(
                f"Error:\n{e}"))

    def _hw_linux(self, drive_label: str) -> None:
        """Query hardware details via lsblk on Linux."""
        dev   = drive_label.split(" (")[0].strip()
        lines = [f"Device : {dev}"]
        try:
            out = subprocess.check_output(
                ["lsblk", "-d", "-n", "-o", "MODEL,ROTA,SIZE", dev],
                stderr=subprocess.DEVNULL, text=True, timeout=6,
            ).strip()
            if out:
                parts = out.split(None, 2)
                lines = [
                    f"Model  : {parts[0] if parts else 'Unknown'}",
                    "Type   : " + (
                        "HDD (Rotational)"
                        if len(parts) > 1 and parts[1].strip() == "1"
                        else "SSD / NVMe"
                    ),
                    f"Size   : {parts[2].strip() if len(parts) > 2 else '?'}",
                    f"Device : {dev}",
                ]
        except Exception:
            pass
        self.after(0, lambda t="\n".join(lines): self._set_hw_details(t))

    # ─────────────────────────────────────────────────────────────────────────
    # SCAN DRIVES
    # ─────────────────────────────────────────────────────────────────────────

    def scan_drives(self) -> None:
        if self._is_scanning:
            return
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        # Logical mode performs a pure-Python directory tally instead of the
        # C-backend physical-drive enumeration.
        if self._current_mode == "Logical":
            self._logical_scan_worker()
            return

        self._is_scanning = True
        self.after(0, lambda: self.scan_btn.configure(
            state="disabled", text="Scanning…"))
        self._set_progress(None, "Scanning…")
        self._log("Enumerating physical drives…", "INFO")

        backend = self._get_backend_exe()
        if not os.path.isfile(backend):
            self._log(f"Backend not found: {backend}", "ERROR")
            self._log(
                "Run  build.bat  (Windows) or  build.sh  (Linux).", "WARN")
            self._finish_scan([])
            return

        try:
            proc = subprocess.Popen(
                [backend, "scan"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                creationflags=CREATE_NO_WINDOW,
            )
            stdout, stderr = proc.communicate(timeout=15)

            for line in stderr.strip().splitlines():
                self._log(f"[backend] {line}", "WARN")

            raw = stdout.strip()
            if not raw:
                self._log("Backend returned no output.", "ERROR")
                self._finish_scan([])
                return

            data: dict = json.loads(raw)
            if data.get("type") != "scan_result":
                self._log(
                    f"Unexpected backend response: {data.get('type')!r}",
                    "ERROR",
                )
                self._finish_scan([])
                return

            drives: list = data.get("drives", [])
            if drives:
                self._log(f"Found {len(drives)} physical drive(s):", "SUCCESS")
                for d in drives:
                    self._log(f"  {d}", "INFO")
            else:
                self._log("No physical drives detected.", "WARN")

            self._finish_scan(drives)

        except json.JSONDecodeError as exc:
            self._log(f"JSON parse error: {exc}", "ERROR")
            self._finish_scan([])
        except subprocess.TimeoutExpired:
            proc.kill()
            self._log("Backend scan timed out (>15 s).", "ERROR")
            self._finish_scan([])
        except Exception as exc:
            self._log(f"Unexpected scan error: {exc}", "ERROR")
            self._finish_scan([])

    def _finish_scan(self, drives: list) -> None:
        self._is_scanning = False

        def _update() -> None:
            self.scan_btn.configure(state="normal", text="Scan Drives")
            self._set_progress(0.0, "Idle")
            if drives:
                self.drive_dropdown.configure(values=drives)
                self.drive_var.set(drives[0])
                # Auto-interrogate the first discovered drive
                threading.Thread(
                    target=self._hw_interrogate_worker,
                    args=(drives[0],), daemon=True,
                ).start()
            else:
                self.drive_dropdown.configure(values=[self._PLACEHOLDER])
                self.drive_var.set(self._PLACEHOLDER)

        self.after(0, _update)

    # ── Logical scan (pure-Python directory tally) ─────────────────────────
    def _logical_scan_worker(self) -> None:
        """Walk the target directory to tally total files and bytes.
        Runs in a background thread; updates telemetry via after(0, ...)."""
        self._is_scanning = True
        self._set_progress(None, "Scanning…")

        src = self.dir_var.get().strip()
        if not src or not os.path.isdir(src):
            self._log("Logical scan: no valid target directory selected.", "WARN")
            self._finish_logical_scan(0, 0, valid=False)
            return

        self._log(f"Scanning logical target: {src}", "INFO")
        total_bytes = 0
        total_files = 0
        for root, _dirs, files in os.walk(src):
            for fname in files:
                try:
                    total_bytes += os.path.getsize(os.path.join(root, fname))
                    total_files += 1
                except OSError:
                    continue   # unreadable/locked file — skip in the tally

        self._logical_total_bytes = total_bytes
        self._logical_total_files = total_files
        self._log(
            f"Logical scan complete: {total_files} file(s), "
            f"{total_bytes / (1024 ** 3):.3f} GiB",
            "SUCCESS",
        )
        self._finish_logical_scan(total_bytes, total_files, valid=True)

    def _finish_logical_scan(self, total_bytes: int, total_files: int,
                             valid: bool) -> None:
        self._is_scanning = False

        def _update() -> None:
            self.scan_btn.configure(state="normal", text="Scan Drives")
            self._set_progress(0.0, "Idle")
            if valid:
                gib = total_bytes / (1024 ** 3)
                # Surface the tally on the TRANSFERRED card and details panel
                self._telem["transferred"].configure(text=f"{gib:.3f} GiB")
                self._set_hw_details(
                    "LOGICAL TARGET\n"
                    f"Files : {total_files}\n"
                    f"Size  : {gib:.3f} GiB"
                )
            else:
                self._set_hw_details("No valid directory\nselected.")

        self.after(0, _update)

    # ─────────────────────────────────────────────────────────────────────────
    # OUTPUT FILE BROWSER
    # ─────────────────────────────────────────────────────────────────────────

    def browse_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save Forensic Image As",
            defaultextension=".dd",
            filetypes=[
                ("Raw Disk Image", "*.dd *.img *.raw"),
                ("EnCase / EWF",   "*.E01 *.e01"),
                ("All Files",      "*.*"),
            ],
        )
        if path:
            self.output_entry.delete(0, "end")
            self.output_entry.insert(0, path)

    def browse_directory(self) -> None:
        """Logical-mode source picker — choose a folder to acquire.

        The Scan Drives button is hidden in Logical mode, so picking a folder
        also kicks off the logical scan (file/byte tally) automatically.
        """
        path = filedialog.askdirectory(title="Select Target Directory")
        if path:
            self.dir_var.set(path)
            self.scan_drives()

    # ─────────────────────────────────────────────────────────────────────────
    # ACQUISITION MODE (Physical drive  vs  Logical folder)
    # ─────────────────────────────────────────────────────────────────────────

    def _on_mode_changed(self, value: str) -> None:
        """Segmented-button callback — switch acquisition mode and relayout."""
        self._current_mode = "Logical" if value == "Logical Imaging" else "Physical"
        self._apply_mode()

    def _apply_mode(self) -> None:
        """Show the target widgets for the active mode, hide the other set.

        Both widget sets share grid rows 2–4 of the sidebar; only one set is
        gridded at a time so they never overlap.
        """
        if self._current_mode == "Physical":
            # Hide logical widgets
            self._dir_label.grid_remove()
            self.dir_entry.grid_remove()
            self.dir_browse_btn.grid_remove()
            # Show physical widgets
            self._drive_label.grid(row=2, column=0, padx=14, sticky="w")
            self.drive_dropdown.grid(row=3, column=0, sticky="ew",
                                     padx=14, pady=(3, 5))
            self.scan_btn.grid(row=4, column=0, sticky="ew",
                               padx=14, pady=(0, 10))
            # Physical output formats: raw sector image or true EnCase E01.
            self.format_dropdown.configure(values=list(self._PHYSICAL_FORMATS))
            if self.output_format_var.get() not in self._PHYSICAL_FORMATS:
                self.output_format_var.set(self._PHYSICAL_FORMATS[0])
        else:  # Logical
            # Hide physical widgets (incl. the Scan Drives button)
            self._drive_label.grid_remove()
            self.drive_dropdown.grid_remove()
            self.scan_btn.grid_remove()
            # Show logical widgets
            self._dir_label.grid(row=2, column=0, padx=14, sticky="w")
            self.dir_entry.grid(row=3, column=0, sticky="ew",
                                padx=14, pady=(3, 5))
            self.dir_browse_btn.grid(row=4, column=0, sticky="ew",
                                     padx=14, pady=(0, 10))
            # Logical output formats: browsable tree-copy or a single zip
            # archive (both carry the per-file SHA-256 audit manifest).
            self.format_dropdown.configure(values=list(self._LOGICAL_FORMATS))
            if self.output_format_var.get() not in self._LOGICAL_FORMATS:
                self.output_format_var.set(self._LOGICAL_FORMATS[0])

        # Re-apply compression-control enablement for the now-current format.
        self._on_format_changed(self.output_format_var.get())

    def _on_format_changed(self, value: str) -> None:
        """Output-format callback — enable compression only where it applies.

        Compressible formats:
          • E01 (EnCase)  — libewf zlib chunk compression (physical mode)
          • Zip Archive   — DEFLATE compression of the file set (logical mode)

        Uncompressed formats (Raw DD byte stream, plain folder tree-copy) grey
        the compression control out since it has no effect.
        """
        if value in self._COMPRESSIBLE_FORMATS:
            self.compression_dropdown.configure(state="normal")
            self._compression_label.configure(text_color=_MUTED)
        else:  # Raw (DD)  ·  Folder (Tree + CSV)
            self.compression_dropdown.configure(state="disabled")
            self._compression_label.configure(text_color=_BORDER)

    # ─────────────────────────────────────────────────────────────────────────
    # START IMAGING
    # ─────────────────────────────────────────────────────────────────────────

    def start_imaging(self) -> None:
        if self._is_imaging:
            return

        # Route to the pure-Python logical engine when in Logical mode.
        if self._current_mode == "Logical":
            self._start_logical_imaging()
            return

        target = self.drive_var.get()
        output = self.output_entry.get().strip()

        if target == self._PLACEHOLDER:
            self._log("No target drive selected — run Scan Drives first.", "WARN")
            return
        if not output:
            self._log("No output path specified — click Browse…", "WARN")
            return

        # Strip display size suffix: "\\.\PhysicalDrive0 (931 GiB)" → raw path
        drive_path = target.split(" (")[0].strip()
        backend    = self._get_backend_exe()

        if not os.path.isfile(backend):
            self._log(f"Backend not found: {backend}", "ERROR")
            self._log("Run  build.bat  (Windows) or  build.sh  (Linux).", "WARN")
            return

        # ── Pre-flight safety gate ────────────────────────────────────────────
        fmt_disp  = self.output_format_var.get()
        comp_disp = self.compression_var.get()
        summary = (
            f"Source:  {drive_path}\n"
            f"Output:  {output}\n"
            f"Format:  {fmt_disp}"
            + (f"  (compression: {comp_disp})"
               if fmt_disp == "E01 (EnCase)" else "")
        )
        if not self._preflight(summary, output,
                               self._parse_size_to_bytes(target)):
            self._log("Acquisition cancelled at pre-flight.", "WARN")
            return

        self._log("─" * 60, "INFO")
        self._log(f"Source :  {drive_path}", "INFO")
        self._log(f"Output :  {output}", "INFO")
        self._log_case_meta()
        self._log("Starting acquisition…", "INFO")

        # Reset all session state
        self._is_imaging       = True
        self._last_logged_pct  = -1
        self._acq_start        = 0.0
        self._ema_eta_s        = 0.0
        self._ema_speed_bps    = 0.0
        self._last_post_t      = 0.0
        self._speed_t          = 0.0
        self._speed_b          = 0
        self._last_clock_push  = 0.0
        self._last_telem_push  = 0.0
        self._ui_pending       = None
        self._pump_text        = None
        self._live_hash        = ""
        self._live_hash_status = ""
        self._aborted          = False
        self._proc             = None

        self.after(0, self._lock_ui_for_imaging)
        self.after(0, self._reset_telem)
        self.after(0, self._reset_sector_map)
        self.after(0, lambda: self.progress_bar.configure(
            progress_color=_ACCENT))
        # Reset the live-hash dashboard for the new acquisition
        self._set_hash(
            self._HASH_PLACEHOLDER,
            "Opening source device & initializing image — please wait…")

        # Map the UI controls to C-backend CLI args (read on the main thread).
        #   format       Raw (DD) → "DD"   ·  E01 (EnCase) → "E01"
        #   compression  None → "0"  ·  Fast → "1"  ·  Best → "9"
        fmt_arg = "E01" if self.output_format_var.get() == "E01 (EnCase)" else "DD"
        comp_arg = {"None": "0", "Fast": "1", "Best": "9"}.get(
            self.compression_var.get(), "0")
        if fmt_arg == "E01":
            self._log(f"Output format: E01 (zlib level {comp_arg})", "INFO")

        m = self._case_meta
        self._set_acq_details([
            ("Source",     drive_path),
            ("Output",     output),
            ("Format",     fmt_disp + (f"   ·   Compression: {comp_disp}"
                                       if fmt_disp == "E01 (EnCase)" else "")),
            ("Case #",     m.get("case") or "—"),
            ("Evidence #", m.get("evidence") or "—"),
            ("Examiner",   m.get("examiner") or "—"),
            ("Started",    datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ])
        self._bad_count = 0
        self._set_detail("bad", "0", _GREEN)
        self._seg_base = (os.path.splitext(self._e01_target_name(output))[0]
                          if fmt_arg == "E01" else "")
        self._spark.clear()
        self._last_spark_t = self._last_seg_t = 0.0
        self._set_detail("segments", "1" if fmt_arg == "E01" else "—", _ACCENT)
        self._set_phase("ACQUIRING", _ACCENT)

        threading.Thread(
            target=self._imaging_worker,
            args=(backend, drive_path, output, fmt_arg, comp_arg),
            daemon=True,
        ).start()

    # ─────────────────────────────────────────────────────────────────────────
    # LOGICAL IMAGING (pure-Python folder acquisition)
    # ─────────────────────────────────────────────────────────────────────────

    def _start_logical_imaging(self) -> None:
        """Validate inputs and launch the logical acquisition worker."""
        src    = self.dir_var.get().strip()
        output = self.output_entry.get().strip()

        if not src or not os.path.isdir(src):
            self._log("No valid target directory selected — click Browse…", "WARN")
            return
        if not output:
            self._log("No output destination specified — click Browse…", "WARN")
            return

        # Guard: destination must not live inside the source, or os.walk would
        # recurse into the growing copy forever (folder) / re-read its own
        # output (zip).
        src_abs = os.path.abspath(src)
        dst_abs = os.path.abspath(output)
        if dst_abs == src_abs or dst_abs.startswith(src_abs + os.sep):
            self._log(
                "Output cannot be inside the source directory.",
                "ERROR",
            )
            return

        # Resolve the logical output format and its compression mapping.
        #   Folder (Tree + CSV) → "folder"  (uncompressed tree-copy)
        #   Zip Archive         → "zip"     (None=STORED · Fast=L1 · Best=L9)
        #   E01 (EnCase)        → "e01"     (UDF volume image → libewf E01)
        fmt_sel = self.output_format_var.get()
        out_format = ("zip" if fmt_sel == "Zip Archive"
                      else "e01" if fmt_sel == "E01 (EnCase)"
                      else "folder")
        comp_choice = self.compression_var.get()
        comp_type, comp_level, comp_arg = None, None, "0"
        if out_format == "zip":
            comp_type  = (zipfile.ZIP_STORED if comp_choice == "None"
                          else zipfile.ZIP_DEFLATED)
            comp_level = {"None": None, "Fast": 1, "Best": 9}.get(
                comp_choice, None)
        elif out_format == "e01":
            comp_arg = {"None": "0", "Fast": "1", "Best": "9"}.get(
                comp_choice, "0")
            if pycdlib is None:
                self._log("Logical E01 needs pycdlib — run: "
                          "pip install pycdlib", "ERROR")
                messagebox.showerror(
                    "Missing dependency",
                    "Logical E01 output requires the 'pycdlib' package.\n\n"
                    "Install it with:\n    pip install pycdlib\n\n"
                    "then restart the app.")
                return

        # E01 needs temporary space for the UDF image *and* the E01 (~2×).
        est_bytes = self._logical_total_bytes * (2 if out_format == "e01" else 1)

        # ── Pre-flight safety gate ────────────────────────────────────────────
        summary = (
            f"Source:  {src}  (logical)\n"
            f"Output:  {output}\n"
            f"Format:  {fmt_sel}"
            + (f"  (compression: {comp_choice})"
               if out_format in ("zip", "e01") else "")
        )
        if not self._preflight(summary, output, est_bytes):
            self._log("Logical acquisition cancelled at pre-flight.", "WARN")
            return
        self._log_case_meta()

        self._log("─" * 60, "INFO")
        self._log(f"Source :  {src}  (logical)", "INFO")
        self._log(f"Output :  {output}", "INFO")
        self._log(
            f"Format :  {self.output_format_var.get()}"
            + (f"  (compression: {comp_choice})" if out_format == "zip" else ""),
            "INFO",
        )
        self._log("Starting logical acquisition…", "INFO")

        # Reset all session state (mirror of the physical path)
        self._is_imaging       = True
        self._last_logged_pct  = -1
        self._acq_start        = 0.0
        self._ema_eta_s        = 0.0
        self._ema_speed_bps    = 0.0
        self._last_post_t      = 0.0
        self._speed_t          = 0.0
        self._speed_b          = 0
        self._last_clock_push  = 0.0
        self._last_telem_push  = 0.0
        self._ui_pending       = None
        self._pump_text        = None
        self._live_hash        = ""
        self._live_hash_status = ""
        self._aborted          = False
        self._proc             = None   # no subprocess in logical mode

        self.after(0, self._lock_ui_for_imaging)
        self.after(0, self._reset_telem)
        self.after(0, self._reset_sector_map)
        self.after(0, lambda: self.progress_bar.configure(progress_color=_ACCENT))
        self._set_hash(self._HASH_PLACEHOLDER,
                       "Preparing — copying & hashing files…")

        self._seg_base = ""        # set by the E01 worker if applicable
        self._spark.clear()
        self._last_spark_t = self._last_seg_t = 0.0
        self._set_phase("ACQUIRING", _ACCENT)
        m = self._case_meta
        self._set_acq_details([
            ("Source",     f"{src}  (logical)"),
            ("Output",     output),
            ("Format",     fmt_sel + (f"   ·   Compression: {comp_choice}"
                                      if out_format in ("zip", "e01") else "")),
            ("Files",      f"{self._logical_total_files}"),
            ("Size",       f"{self._logical_total_bytes / 1024**3:.3f} GiB"),
            ("Case #",     m.get("case") or "—"),
            ("Evidence #", m.get("evidence") or "—"),
            ("Examiner",   m.get("examiner") or "—"),
            ("Started",    datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ])

        threading.Thread(
            target=self._logical_worker,
            args=(src, output, out_format, comp_type, comp_level, comp_arg),
            daemon=True,
        ).start()

    def _stable_eta(self, copied: int, total: int, now: float):
        """Sample throughput once per second with a slow EMA → a stable SPEED
        and ETA that don't bounce on bursty (E01) or small-file workloads.
        Returns (speed_mb_s, eta_seconds); eta is 0 until ~2 s of data exist."""
        if self._speed_t == 0.0:
            self._speed_t = now
            self._speed_b = copied
        elif now - self._speed_t >= 1.0:
            inst = (copied - self._speed_b) / (now - self._speed_t)   # bytes/s
            self._speed_t = now
            self._speed_b = copied
            if inst > 0:
                self._ema_speed_bps = (
                    inst if self._ema_speed_bps <= 0.0
                    else 0.25 * inst + 0.75 * self._ema_speed_bps)
        speed_mbs = self._ema_speed_bps / (1024 ** 2)
        remaining = max(0, total - copied)
        eta = (remaining / self._ema_speed_bps
               if (self._ema_speed_bps > 1.0
                   and (now - self._acq_start) > 2.0) else 0.0)
        return speed_mbs, eta

    def _logical_progress_update(self, bytes_copied: int, total_bytes: int,
                                 files_done: int = 0,
                                 total_files: int = 0) -> None:
        """Telemetry for the logical worker — runs on the acquisition thread.

        THROTTLED to ~25 Hz: without this, a folder of thousands of tiny files
        runs all the formatting below per file on the worker thread, holding the
        GIL and starving the Tk main loop (the UI "skips seconds" / jitters).
        """
        now = time.monotonic()
        if self._acq_start == 0.0:
            self._acq_start = now
        done_now = (total_bytes > 0 and bytes_copied >= total_bytes)
        if (not done_now) and (now - self._last_post_t) < 0.04:
            return                          # cheap exit — frees the GIL
        self._last_post_t = now
        elapsed_s = now - self._acq_start

        speed_mbs, eta_s = self._stable_eta(bytes_copied, total_bytes, now)

        # Blended pct: half by bytes, half by file count (smooth in both
        # many-tiny-files and few-huge-files regimes).
        byte_frac = (bytes_copied / total_bytes) if total_bytes > 0 else 0.0
        file_frac = (files_done / total_files) if total_files > 0 else 0.0
        if total_files > 0 and total_bytes > 0:
            pct = 0.5 * byte_frac + 0.5 * file_frac
        else:
            pct = byte_frac or file_frac
        pct = max(0.0, min(1.0, pct))

        speed_str   = f"{speed_mbs:6.2f} MB/s" if speed_mbs > 0 else "--   MB/s"
        eta_str     = _fmt_hms(eta_s) if eta_s > 0 else "--:--:--"
        xfer_str    = f"{bytes_copied / (1024 ** 3):.3f} GiB"
        elapsed_str = _fmt_hms(elapsed_s)
        pct_str     = f"{int(pct * 100):3d} %"

        self._post_progress(
            pct, pct_str, speed_str, eta_str, xfer_str, elapsed_str,
            hash_val=self._live_hash or None,
            hash_status=self._live_hash_status or None,
        )

    def _logical_worker(self, src_dir: str, dst: str,
                        out_format: str = "folder",
                        comp_type=None, comp_level=None,
                        comp_arg: str = "0") -> None:
        """Dispatch the logical acquisition to the selected output format.

        folder/zip are pure-Python; e01 packages the files into a UDF volume
        image (pycdlib) and runs it through the C-backend libewf E01 engine.
        All paths share the same per-file MD5/SHA-1/SHA-256 hashing and CSV
        audit manifest; they differ only in how the evidence is packaged.
        """
        if out_format == "zip":
            self._logical_worker_zip(src_dir, dst, comp_type, comp_level)
        elif out_format == "e01":
            self._logical_worker_e01(src_dir, dst, comp_arg)
        else:
            self._logical_worker_folder(src_dir, dst)

    def _logical_worker_folder(self, src_dir: str, dst_dir: str) -> None:
        """Pure-Python logical acquisition: recursively copy src_dir into
        dst_dir, hashing every file (SHA-256, 4 MiB chunks), preserving MAC
        times, and recording a forensic CSV manifest.  No C backend involved.
        """
        CHUNK = 4 * 1024 * 1024
        audit_path  = os.path.join(dst_dir, "logical_audit.csv")
        total_bytes = self._logical_total_bytes
        bytes_copied = 0
        files_done   = 0
        bad_files    = 0
        success      = False
        csv_file     = None
        verify_items = []   # (dst_path, sha256) for the verification pass

        def _fmt_ts(ts: float) -> str:
            try:
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (OverflowError, OSError, ValueError):
                return ""

        try:
            os.makedirs(dst_dir, exist_ok=True)
            csv_file = open(audit_path, "w", newline="", encoding="utf-8")
            writer = csv.writer(csv_file)
            writer.writerows(self._metadata_rows())
            writer.writerow([
                "Original Path", "Destination Path",
                "MD5", "SHA-1", "SHA-256",
                "Size (Bytes)", "Modified", "Accessed", "Created",
            ])

            for root, _dirs, files in os.walk(src_dir):
                if self._aborted:
                    break

                # Recreate the directory structure under dst_dir
                rel      = os.path.relpath(root, src_dir)
                dst_root = dst_dir if rel == "." else os.path.join(dst_dir, rel)
                os.makedirs(dst_root, exist_ok=True)

                for fname in files:
                    if self._aborted:
                        break

                    src_path = os.path.join(root, fname)
                    dst_path = os.path.join(dst_root, fname)

                    try:
                        h_md5  = hashlib.md5()
                        h_sha1 = hashlib.sha1()
                        h      = hashlib.sha256()
                        with open(src_path, "rb") as fin, \
                             open(dst_path, "wb") as fout:
                            while True:
                                if self._aborted:
                                    break
                                chunk = fin.read(CHUNK)
                                if not chunk:
                                    break
                                h_md5.update(chunk)
                                h_sha1.update(chunk)
                                h.update(chunk)
                                fout.write(chunk)
                                bytes_copied += len(chunk)
                                self._logical_progress_update(
                                    bytes_copied, total_bytes,
                                    files_done, self._logical_total_files)

                        if self._aborted:
                            break

                        # Preserve MAC times.  os.utime restores Modified +
                        # Accessed on every platform; on Windows we additionally
                        # restore the Creation time via the kernel (SetFileTime),
                        # which os.utime cannot touch.
                        st = os.stat(src_path)
                        os.utime(dst_path, (st.st_atime, st.st_mtime))
                        if sys.platform == "win32":
                            if not _set_windows_creation_time(
                                dst_path, st.st_ctime,
                                st.st_mtime, st.st_atime,
                            ):
                                self._log(
                                    f"Could not set creation time on {dst_path}",
                                    "WARN",
                                )

                        digest = h.hexdigest()
                        writer.writerow([
                            src_path, dst_path,
                            h_md5.hexdigest(), h_sha1.hexdigest(), digest,
                            st.st_size,
                            _fmt_ts(st.st_mtime), _fmt_ts(st.st_atime),
                            _fmt_ts(st.st_ctime),
                        ])
                        files_done += 1
                        verify_items.append((dst_path, digest))
                        # Stash for the UI pump (no per-file Tk call).
                        self._live_hash = digest
                        self._live_hash_status = (
                            f"Hashed {files_done}/{self._logical_total_files}: "
                            f"{fname}")

                    except OSError as exc:
                        bad_files += 1
                        self._log(f"Failed to acquire {src_path}: {exc}", "WARN")
                        continue

            success = not self._aborted

        except Exception as exc:
            self._log(f"Logical acquisition error: {exc}", "ERROR")
            success = False

        finally:
            if csv_file is not None:
                try:
                    csv_file.close()
                except Exception:
                    pass

        # Reporting + UI restore.  Everything here is wrapped so that no logging
        # or hash-display error can prevent the UI from being reset — the
        # _finish_imaging() call in the finally always runs.
        if self._aborted:
            self._log("─" * 56, "INFO")
            self._log("Logical acquisition ABORTED by user.", "ERROR")
            self._log("─" * 56, "INFO")
            # abort_imaging() already restored the UI — don't double-finish.
            return

        # ── Verification pass: re-read & compare to the manifest ──────────────
        verify_enabled = self.verify_var.get()
        passed = True   # default when verification is disabled
        v_ok = v_bad = v_miss = 0
        if success and verify_enabled:
            v_ok, v_bad, v_miss = self._verify_logical(verify_items, "folder")
            if self._aborted:
                self._log("Verification ABORTED by user.", "ERROR")
                return
            passed = (v_bad == 0 and v_miss == 0)

        try:
            if success and verify_enabled and passed:
                gib = bytes_copied / (1024 ** 3)
                self._log("─" * 56, "INFO")
                self._log(
                    f"Logical acquisition complete — {files_done} file(s), "
                    f"{gib:.3f} GiB", "SUCCESS")
                if bad_files > 0:
                    self._log(
                        f"WARNING: {bad_files} file(s) could not be acquired "
                        "(locked/unreadable) — see log.", "WARN")
                self._log(f"Audit Manifest :  {audit_path}", "SUCCESS")
                self._log(
                    f"VERIFICATION PASSED — {v_ok}/{len(verify_items)} "
                    "file(s) match the manifest", "SUCCESS")
                self._log("─" * 56, "INFO")
                self._set_hash(
                    self._HASH_PLACEHOLDER,
                    f"Verified ✓ — {v_ok}/{len(verify_items)} files match "
                    "manifest")
                self._append_acq_hashes(
                    note="Per-file MD5 / SHA-1 / SHA-256 recorded in "
                         "logical_audit.csv.")
            elif success and verify_enabled and not passed:
                self._log("─" * 56, "INFO")
                self._log(
                    f"VERIFICATION FAILED — {v_bad} mismatch, "
                    f"{v_miss} missing/unreadable", "ERROR")
                self._log("Evidence integrity NOT confirmed — do not rely on "
                          "this copy.", "ERROR")
                self._log("─" * 56, "INFO")
                self._set_hash(
                    self._HASH_PLACEHOLDER,
                    f"⚠ VERIFICATION FAILED — {v_bad} mismatch / "
                    f"{v_miss} missing")
            elif success:   # verification disabled
                gib = bytes_copied / (1024 ** 3)
                self._log("─" * 56, "INFO")
                self._log(
                    f"Logical acquisition complete — {files_done} file(s), "
                    f"{gib:.3f} GiB", "SUCCESS")
                if bad_files > 0:
                    self._log(
                        f"WARNING: {bad_files} file(s) could not be acquired "
                        "(locked/unreadable) — see log.", "WARN")
                self._log(f"Audit Manifest :  {audit_path}", "SUCCESS")
                self._log("Verification skipped (disabled).", "WARN")
                self._log("─" * 56, "INFO")
                self._set_hash(
                    self._HASH_PLACEHOLDER,
                    f"{files_done} file(s) hashed (verification skipped)")
            else:
                self._log("Logical acquisition failed.", "ERROR")
                self._set_hash(self._HASH_PLACEHOLDER, "Acquisition failed.")
        finally:
            ok_final = success and passed
            self._finish_imaging(
                ok_final, "verified" if (ok_final and verify_enabled) else "",
                bad_files, dst_dir if ok_final else "")

    def _logical_worker_zip(self, src_dir: str, zip_path: str,
                            comp_type, comp_level) -> None:
        """Pure-Python logical acquisition into a single zip archive.

        Streams every file through SHA-256 (4 MiB chunks) straight into the
        archive, records the per-file Modified time on each zip entry, and
        embeds the full forensic manifest (logical_audit.csv) inside the
        archive so the evidence and its integrity record travel as one file.
        No C backend involved.

        comp_type   zipfile.ZIP_STORED (no compression) or ZIP_DEFLATED.
        comp_level  DEFLATE level (1=Fast … 9=Best) or None for STORED.
        """
        CHUNK        = 4 * 1024 * 1024
        total_bytes  = self._logical_total_bytes
        bytes_copied = 0
        files_done   = 0
        bad_files    = 0
        success      = False
        zf           = None
        verify_items = []   # (arcname, sha256) for the verification pass

        # Normalise the output name — a zip archive must end in .zip.
        if not zip_path.lower().endswith(".zip"):
            zip_path += ".zip"

        def _fmt_ts(ts: float) -> str:
            try:
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (OverflowError, OSError, ValueError):
                return ""

        def _zip_time(ts: float):
            # Zip stores local time as a 6-tuple; the format cannot represent
            # years before 1980, so clamp defensively.
            try:
                lt = time.localtime(ts)
                if lt.tm_year < 1980:
                    return (1980, 1, 1, 0, 0, 0)
                return lt[:6]
            except (OverflowError, OSError, ValueError):
                return (1980, 1, 1, 0, 0, 0)

        # Manifest header — identical schema to the folder-mode CSV.
        manifest_rows = self._metadata_rows() + [[
            "Original Path", "Destination Path",
            "MD5", "SHA-1", "SHA-256",
            "Size (Bytes)", "Modified", "Accessed", "Created",
        ]]

        try:
            parent = os.path.dirname(os.path.abspath(zip_path))
            if parent:
                os.makedirs(parent, exist_ok=True)

            zf = zipfile.ZipFile(
                zip_path, "w",
                compression=comp_type,
                compresslevel=comp_level,
                allowZip64=True,    # evidence sets routinely exceed 4 GiB
            )

            for root, _dirs, files in os.walk(src_dir):
                if self._aborted:
                    break

                for fname in files:
                    if self._aborted:
                        break

                    src_path = os.path.join(root, fname)
                    # Archive path: source-relative, forward-slashed (zip spec).
                    arcname = os.path.relpath(src_path, src_dir).replace(
                        os.sep, "/")

                    try:
                        st = os.stat(src_path)
                        h_md5  = hashlib.md5()
                        h_sha1 = hashlib.sha1()
                        h      = hashlib.sha256()

                        zinfo = zipfile.ZipInfo(arcname,
                                                date_time=_zip_time(st.st_mtime))
                        zinfo.compress_type = comp_type
                        zinfo._compresslevel = comp_level
                        # Preserve the host file mode bits in the archive.
                        zinfo.external_attr = (st.st_mode & 0xFFFF) << 16

                        with open(src_path, "rb") as fin, \
                             zf.open(zinfo, "w") as zout:
                            while True:
                                if self._aborted:
                                    break
                                chunk = fin.read(CHUNK)
                                if not chunk:
                                    break
                                h_md5.update(chunk)
                                h_sha1.update(chunk)
                                h.update(chunk)
                                zout.write(chunk)
                                bytes_copied += len(chunk)
                                self._logical_progress_update(
                                    bytes_copied, total_bytes,
                                    files_done, self._logical_total_files)

                        if self._aborted:
                            break

                        digest = h.hexdigest()
                        manifest_rows.append([
                            src_path, arcname,
                            h_md5.hexdigest(), h_sha1.hexdigest(), digest,
                            st.st_size,
                            _fmt_ts(st.st_mtime), _fmt_ts(st.st_atime),
                            _fmt_ts(st.st_ctime),
                        ])
                        files_done += 1
                        verify_items.append((arcname, digest))
                        # Stash for the UI pump (no per-file Tk call).
                        self._live_hash = digest
                        self._live_hash_status = (
                            f"Hashed {files_done}/{self._logical_total_files}: "
                            f"{fname}")

                    except OSError as exc:
                        bad_files += 1
                        self._log(f"Failed to acquire {src_path}: {exc}", "WARN")
                        continue

            if not self._aborted:
                # Writing the manifest + closing the archive flushes any buffered
                # compressed data to disk, which can lag on slow media — show the
                # animated busy state instead of a frozen-looking 100 % bar.
                self._post_busy(
                    "Finalizing…",
                    "Writing manifest & flushing archive to disk…")
                # Embed the manifest inside the archive as the final entry.
                buf = io.StringIO()
                csv.writer(buf).writerows(manifest_rows)
                zf.writestr("logical_audit.csv", buf.getvalue())
                success = True

        except Exception as exc:
            self._log(f"Logical acquisition error: {exc}", "ERROR")
            success = False

        finally:
            if zf is not None:
                try:
                    zf.close()
                except Exception:
                    pass

        # On abort, delete the partial archive — it is not valid evidence.
        if self._aborted:
            try:
                os.remove(zip_path)
            except OSError:
                pass
            self._log("─" * 56, "INFO")
            self._log("Logical acquisition ABORTED by user.", "ERROR")
            self._log("─" * 56, "INFO")
            # abort_imaging() already restored the UI — don't double-finish.
            return

        # ── Verification pass: re-read archive members & compare to manifest ──
        verify_enabled = self.verify_var.get()
        passed = True   # default when verification is disabled
        v_ok = v_bad = v_miss = 0
        if success and verify_enabled:
            v_ok, v_bad, v_miss = self._verify_logical(
                verify_items, "zip", container=zip_path)
            if self._aborted:
                self._log("Verification ABORTED by user.", "ERROR")
                return
            passed = (v_bad == 0 and v_miss == 0)

        try:
            if success and verify_enabled and passed:
                gib = bytes_copied / (1024 ** 3)
                self._log("─" * 56, "INFO")
                self._log(
                    f"Logical acquisition complete — {files_done} file(s), "
                    f"{gib:.3f} GiB", "SUCCESS")
                if bad_files > 0:
                    self._log(
                        f"WARNING: {bad_files} file(s) could not be acquired "
                        "(locked/unreadable) — see log.", "WARN")
                self._log(f"Archive        :  {zip_path}", "SUCCESS")
                self._log(
                    "Audit Manifest :  logical_audit.csv (inside archive)",
                    "SUCCESS")
                self._log(
                    f"VERIFICATION PASSED — {v_ok}/{len(verify_items)} "
                    "file(s) match the manifest", "SUCCESS")
                self._log("─" * 56, "INFO")
                self._set_hash(
                    self._HASH_PLACEHOLDER,
                    f"Verified ✓ — {v_ok}/{len(verify_items)} files match "
                    "manifest")
                self._append_acq_hashes(
                    note="Per-file MD5 / SHA-1 / SHA-256 recorded in "
                         "logical_audit.csv.")
            elif success and verify_enabled and not passed:
                self._log("─" * 56, "INFO")
                self._log(
                    f"VERIFICATION FAILED — {v_bad} mismatch, "
                    f"{v_miss} missing/unreadable", "ERROR")
                self._log("Evidence integrity NOT confirmed — do not rely on "
                          "this archive.", "ERROR")
                self._log("─" * 56, "INFO")
                self._set_hash(
                    self._HASH_PLACEHOLDER,
                    f"⚠ VERIFICATION FAILED — {v_bad} mismatch / "
                    f"{v_miss} missing")
            elif success:   # verification disabled
                gib = bytes_copied / (1024 ** 3)
                self._log("─" * 56, "INFO")
                self._log(
                    f"Logical acquisition complete — {files_done} file(s), "
                    f"{gib:.3f} GiB", "SUCCESS")
                if bad_files > 0:
                    self._log(
                        f"WARNING: {bad_files} file(s) could not be acquired "
                        "(locked/unreadable) — see log.", "WARN")
                self._log(f"Archive        :  {zip_path}", "SUCCESS")
                self._log(
                    "Audit Manifest :  logical_audit.csv (inside archive)",
                    "SUCCESS")
                self._log("Verification skipped (disabled).", "WARN")
                self._log("─" * 56, "INFO")
                self._set_hash(
                    self._HASH_PLACEHOLDER,
                    f"{files_done} file(s) hashed (verification skipped)")
            else:
                self._log("Logical acquisition failed.", "ERROR")
                self._set_hash(self._HASH_PLACEHOLDER, "Acquisition failed.")
        finally:
            ok_final = success and passed
            self._finish_imaging(
                ok_final, "verified" if (ok_final and verify_enabled) else "",
                bad_files, zip_path if ok_final else "")

    @staticmethod
    def _e01_target_name(output: str) -> str:
        """The real .E01 path libewf creates from `output` (strip a trailing
        image extension, append .E01)."""
        base = output
        for ext in (".e01", ".dd", ".img", ".raw"):
            if base.lower().endswith(ext):
                base = base[:-len(ext)]
                break
        return base + ".E01"

    def _cleanup_temp(self, path: str) -> None:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    def _overall_eta(self, bar_pct: float) -> str:
        """EMA-smoothed whole-operation ETA derived from the overall bar
        fraction (covers the build + write + E01 phases as one).  Used by the
        multi-phase logical-E01 path."""
        el = time.monotonic() - self._acq_start
        raw = (el * (1.0 - bar_pct) / bar_pct
               if (bar_pct > 0.02 and el > 1.0) else 0.0)
        if raw > 0:
            self._ema_eta_s = (raw if self._ema_eta_s <= 0.0
                               else 0.1 * raw + 0.9 * self._ema_eta_s)
        return _fmt_hms(self._ema_eta_s) if self._ema_eta_s > 0 else "--:--:--"

    def _verify_logical(self, items, kind: str, container: str = None):
        """Post-acquisition verification: re-read every acquired file and
        compare its SHA-256 to what was recorded at acquisition time.

        ``items`` is a list of (key, expected_sha256) — key is a destination
        path (folder) or an archive member name (zip).  Returns
        (matched, mismatched, missing).  Drives its own progress sweep.
        """
        total = len(items)
        self._log(f"Verification — re-reading {total} file(s) to confirm they "
                  "match the manifest…", "INFO")
        ok = bad = missing = 0
        zf = None
        vstart = time.monotonic()
        try:
            if kind == "zip":
                zf = zipfile.ZipFile(container, "r")
            for i, (key, expected) in enumerate(items, 1):
                if self._aborted:
                    break
                try:
                    h  = hashlib.sha256()
                    fh = zf.open(key) if kind == "zip" else open(key, "rb")
                    with fh:
                        while True:
                            if self._aborted:
                                break
                            chunk = fh.read(4 * 1024 * 1024)
                            if not chunk:
                                break
                            h.update(chunk)
                    if h.hexdigest().lower() == (expected or "").lower():
                        ok += 1
                    else:
                        bad += 1
                        self._log(f"VERIFY MISMATCH: {key}", "ERROR")
                except (OSError, KeyError) as exc:
                    missing += 1
                    self._log(f"VERIFY MISSING/UNREADABLE: {key} — {exc}", "WARN")
                pct = i / total if total else 1.0
                self._post_progress(
                    pct, f"Verifying {int(pct * 100)} %",
                    None, None, None, _fmt_hms(time.monotonic() - vstart),
                    hash_status=(f"Verifying integrity — {i}/{total}: "
                                 f"{os.path.basename(key)}"))
        finally:
            if zf is not None:
                try:
                    zf.close()
                except Exception:
                    pass
        return ok, bad, missing

    def _verify_dd_reread(self, path: str, expected_sha: str):
        """Re-read a raw (DD) image, computing MD5/SHA-1/SHA-256.  Compares the
        SHA-256 to the acquisition hash.  Returns (passed, md5, sha1, sha256)."""
        md5  = hashlib.md5()
        sha1 = hashlib.sha1()
        sha  = hashlib.sha256()
        try:
            total = os.path.getsize(path)
        except OSError:
            total = 0
        done   = 0
        vstart = time.monotonic()
        with open(path, "rb") as f:
            while True:
                if self._aborted:
                    break
                chunk = f.read(4 * 1024 * 1024)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha.update(chunk)
                done += len(chunk)
                pct = done / total if total else 1.0
                el  = time.monotonic() - vstart
                spd = (done / el) / (1024 ** 2) if el > 0.5 else 0.0
                self._post_progress(
                    pct, f"Verifying {int(pct * 100)} %",
                    f"{spd:6.2f} MB/s" if spd > 0 else "--   MB/s",
                    None, f"{done / 1024**3:.3f} GiB", _fmt_hms(el),
                    hash_status=("Verifying image — re-reading & hashing… "
                                 f"{int(pct * 100)} %"))
        computed = sha.hexdigest()
        passed   = (computed.lower() == (expected_sha or "").lower())
        return passed, md5.hexdigest(), sha1.hexdigest(), computed

    @staticmethod
    def _win_native_path(path: str) -> str:
        """Convert a path to native backslashes + 8.3 short form so libewf can
        open/glob it.  Forward slashes and spaces (e.g. 'imager test') break
        libewf on Windows — the same reason the *write* path is normalised."""
        if sys.platform != "win32":
            return path
        native = os.path.normpath(path)            # '/' → '\'
        try:
            get_short = ctypes.windll.kernel32.GetShortPathNameW
            get_short.restype = ctypes.c_uint
            buf = ctypes.create_unicode_buffer(4096)
            n = get_short(native, buf, 4096)
            if 0 < n < 4096 and buf.value:
                return buf.value                   # e.g. E:\IMAGER~1\test4.E01
        except Exception:
            pass
        return native

    def _verify_e01_backend(self, e01_path: str, expected_sha: str):
        """Run the backend 'verify' command (libewf read-back of the E01) and
        stream its progress.  Returns (passed, computed_sha256)."""
        backend = self._get_backend_exe()
        if not os.path.isfile(backend):
            self._log(f"Backend not found: {backend}", "ERROR")
            return (False, "")
        # libewf can't glob a forward-slash / spaced path — give it a native one.
        e01_path = self._win_native_path(e01_path)
        verified, computed, e_md5, e_sha1 = False, "", "", ""
        proc = None
        vstart = time.monotonic()
        try:
            proc = subprocess.Popen(
                [backend, "verify", e01_path, expected_sha or ""],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, creationflags=CREATE_NO_WINDOW)
            self._proc = proc

            def _drain() -> None:
                for ln in proc.stderr:
                    s = ln.rstrip("\r\n")
                    if s:
                        self._log(f"[backend] {s}", "WARN")
            threading.Thread(target=_drain, daemon=True).start()

            while True:
                raw = proc.stdout.readline()
                if not raw:
                    break
                line = raw.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if data.get("type") == "progress":
                    copied = data.get("bytes_copied", 0)
                    total  = data.get("total_bytes", 1)
                    bp     = copied / total if total > 0 else 0.0
                    el     = time.monotonic() - vstart
                    spd    = (copied / el) / (1024 ** 2) if el > 0.5 else 0.0
                    self._post_progress(
                        bp, f"Verifying {int(bp * 100)} %",
                        f"{spd:6.2f} MB/s" if spd > 0 else "--   MB/s",
                        None, f"{copied / 1024**3:.3f} GiB", _fmt_hms(el),
                        hash_val=data.get("sha256") or None,
                        hash_status=("Verifying E01 — decoding & re-hashing via "
                                     f"libewf… {int(bp * 100)} %"))
                elif data.get("type") == "complete":
                    verified = bool(data.get("verified"))
                    computed = data.get("computed_sha256", "")
                    e_md5    = data.get("md5", "")
                    e_sha1   = data.get("sha1", "")
                    break
            if proc.poll() is None:
                proc.wait()
        except Exception as exc:
            self._log(f"E01 verify error: {exc}", "ERROR")
        finally:
            self._proc = None
        return (verified, computed, e_md5, e_sha1)

    def _logical_worker_e01(self, src_dir: str, output: str,
                            comp_arg: str) -> None:
        """Logical acquisition into a true EnCase E01.

        Files are packaged into a UDF volume image (pycdlib) — preserving the
        directory tree and long names — and that image is run through the same
        libewf E01 engine used for physical acquisitions.  The result is a real,
        ewfverify-able .E01 that forensic tools mount and browse as a volume.
        Per-file MD5/SHA-1/SHA-256 are recorded in logical_audit.csv (embedded
        in the volume and written beside the .E01).
        """
        CHUNK       = 4 * 1024 * 1024
        total_files = self._logical_total_files
        bytes_done  = 0
        bad_files   = 0
        success     = False
        sha256      = ""
        e01_md5 = e01_sha1 = e01_report = ""
        out_dir     = os.path.dirname(os.path.abspath(output)) or "."
        temp_udf    = os.path.join(out_dir, ".__fdimager_logical.udf")
        audit_path  = os.path.join(out_dir, "logical_audit.csv")
        e01_path    = self._e01_target_name(output)
        self._acq_start = time.monotonic()

        def _fmt_ts(ts: float) -> str:
            try:
                return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (OverflowError, OSError, ValueError):
                return ""

        def _elapsed() -> str:
            return _fmt_hms(time.monotonic() - self._acq_start)

        manifest_rows = self._metadata_rows() + [[
            "Original Path", "Volume Path",
            "MD5", "SHA-1", "SHA-256",
            "Size (Bytes)", "Modified", "Accessed", "Created",
        ]]

        try:
            os.makedirs(out_dir, exist_ok=True)
            iso = pycdlib.PyCdlib()
            iso.new(udf="2.60")

            files_done = 0
            for root, dirs, files in os.walk(src_dir):
                if self._aborted:
                    break
                for d in sorted(dirs):
                    drel = os.path.relpath(os.path.join(root, d),
                                           src_dir).replace(os.sep, "/")
                    try:
                        iso.add_directory(udf_path="/" + drel)
                    except Exception as exc:
                        self._log(f"UDF dir failed '/{drel}': {exc}", "WARN")

                for fname in sorted(files):
                    if self._aborted:
                        break
                    sp    = os.path.join(root, fname)
                    upath = "/" + os.path.relpath(sp, src_dir).replace(
                        os.sep, "/")
                    try:
                        st     = os.stat(sp)
                        h_md5  = hashlib.md5()
                        h_sha1 = hashlib.sha1()
                        h      = hashlib.sha256()
                        with open(sp, "rb") as fin:
                            while True:
                                if self._aborted:
                                    break
                                chunk = fin.read(CHUNK)
                                if not chunk:
                                    break
                                h_md5.update(chunk)
                                h_sha1.update(chunk)
                                h.update(chunk)
                                bytes_done += len(chunk)
                        if self._aborted:
                            break
                        iso.add_file(sp, udf_path=upath)
                        digest = h.hexdigest()
                        manifest_rows.append([
                            sp, upath,
                            h_md5.hexdigest(), h_sha1.hexdigest(), digest,
                            st.st_size,
                            _fmt_ts(st.st_mtime), _fmt_ts(st.st_atime),
                            _fmt_ts(st.st_ctime),
                        ])
                        files_done += 1
                        # Throttle UI work to ~25 Hz so thousands of files don't
                        # starve the GUI thread.
                        _now = time.monotonic()
                        if (files_done >= total_files
                                or (_now - self._last_post_t) >= 0.04):
                            self._last_post_t = _now
                            pct = (0.40 * files_done / total_files
                                   if total_files else 0.0)
                            _el = _now - self._acq_start
                            _spd = ((bytes_done / _el) / (1024 ** 2)
                                    if _el > 0.5 else 0.0)
                            self._post_progress(
                                pct, f"{int(pct * 100):3d} %",
                                f"{_spd:6.2f} MB/s" if _spd > 0 else "--   MB/s",
                                self._overall_eta(pct),
                                f"{bytes_done / 1024**3:.3f} GiB", _elapsed(),
                                hash_val=digest,
                                hash_status=(f"Building UDF volume & hashing — "
                                             f"{files_done}/{total_files}: "
                                             f"{fname}"))
                    except Exception as exc:
                        bad_files += 1
                        self._log(f"Failed to add '{sp}': {exc}", "WARN")
                        continue

            if self._aborted:
                try:
                    iso.close()
                except Exception:
                    pass
                self._cleanup_temp(temp_udf)
                self._log("Logical E01 ABORTED by user.", "ERROR")
                return

            # Embed the manifest inside the volume.
            try:
                sbuf = io.StringIO()
                csv.writer(sbuf).writerows(manifest_rows)
                blob = sbuf.getvalue().encode("utf-8")
                iso.add_fp(io.BytesIO(blob), len(blob),
                           udf_path="/logical_audit.csv")
            except Exception as exc:
                self._log(f"Could not embed manifest in volume: {exc}", "WARN")

            # Write the UDF image (single blocking call → animated busy state).
            self._post_busy("Writing volume…",
                            "Writing UDF volume image to disk…")
            iso.write(temp_udf)
            iso.close()

            if self._aborted:
                self._cleanup_temp(temp_udf)
                self._log("Logical E01 ABORTED by user.", "ERROR")
                return

            # Run the proven libewf E01 engine over the volume image.
            success, sha256, e01_report = self._stream_e01_from_image(
                temp_udf, output, comp_arg)

            # Post-acquisition verification (libewf read-back of the E01).
            if (success and sha256 and self.verify_var.get()
                    and not self._aborted):
                self._log("Verifying E01 — re-reading via libewf…", "INFO")
                v_ok, vcomp, e01_md5, e01_sha1 = self._verify_e01_backend(
                    e01_path, sha256)
                if not self._aborted:
                    if v_ok:
                        self._log("VERIFICATION PASSED — E01 re-read matches "
                                  "acquisition hash ✓", "SUCCESS")
                    elif not vcomp:
                        # Re-read failed (tooling), not a real mismatch — keep
                        # the image, just flag that verification didn't complete.
                        self._log("VERIFICATION COULD NOT COMPLETE — E01 written "
                                  "OK but the re-read failed; image is kept.",
                                  "WARN")
                    else:
                        self._log(f"VERIFICATION FAILED — re-read {vcomp} != "
                                  f"acquisition {sha256}", "ERROR")
                        success = False

        except Exception as exc:
            self._log(f"Logical E01 error: {exc}", "ERROR")
            success = False
        finally:
            self._cleanup_temp(temp_udf)

        if self._aborted:
            self._log("Logical E01 ABORTED by user.", "ERROR")
            return

        if success:
            try:
                with open(audit_path, "w", newline="", encoding="utf-8") as cf:
                    csv.writer(cf).writerows(manifest_rows)
            except Exception as exc:
                self._log(f"Could not write {audit_path}: {exc}", "WARN")

        try:
            if success:
                self._log("─" * 56, "INFO")
                self._log(f"Logical E01 complete — {files_done} file(s)",
                          "SUCCESS")
                if bad_files > 0:
                    self._log(f"WARNING: {bad_files} file(s) skipped "
                              "(locked/unreadable).", "WARN")
                self._log(f"Evidence  :  {e01_path}", "SUCCESS")
                self._log(f"Image SHA-256  {sha256}", "SUCCESS")
                self._log(f"Audit Manifest :  {audit_path}", "SUCCESS")
                self._log("─" * 56, "INFO")
                self._set_hash(
                    sha256 or self._HASH_PLACEHOLDER,
                    f"Logical E01 written → {os.path.basename(e01_path)}  "
                    "(image SHA-256)")
                if e01_md5 or e01_sha1:
                    self._append_acq_hashes(
                        sha256=sha256, md5=e01_md5, sha1=e01_sha1)
                    self._append_hashes_to_report(
                        e01_report, e01_md5, e01_sha1, sha256)
                else:
                    self._append_acq_hashes(
                        sha256=sha256,
                        note="Per-file hashes in logical_audit.csv.")
            else:
                self._log("Logical E01 failed.", "ERROR")
                self._set_hash(self._HASH_PLACEHOLDER, "Logical E01 failed.")
        finally:
            self._finish_imaging(success, sha256, 0,
                                 e01_path if success else "")

    def _stream_e01_from_image(self, image_path: str, output: str,
                               comp_arg: str):
        """Run the C backend to turn a volume image into an E01, streaming its
        progress (mapped to the back ~57 % of the bar).  Returns (ok, sha256)."""
        backend = self._get_backend_exe()
        if not os.path.isfile(backend):
            self._log(f"Backend not found: {backend}", "ERROR")
            return (False, "")

        ok, sha, rep = False, "", ""
        proc = None
        e01_start = time.monotonic()
        # Segments now start appearing — let the pump count them.
        self._seg_base = os.path.splitext(self._e01_target_name(output))[0]
        try:
            m = self._case_meta
            notes = (m.get("notes", "") or "").replace("\n", " ").replace(
                "\r", " ")
            proc = subprocess.Popen(
                [backend, "image", image_path, output, "E01", comp_arg,
                 m.get("case", ""), m.get("evidence", ""),
                 m.get("examiner", ""), notes],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, creationflags=CREATE_NO_WINDOW,
            )
            self._proc = proc

            def _drain_stderr() -> None:
                for ln in proc.stderr:
                    s = ln.rstrip("\r\n")
                    if s:
                        self._log(f"[backend] {s}", "WARN")
            threading.Thread(target=_drain_stderr, daemon=True).start()

            while True:
                raw = proc.stdout.readline()
                if not raw:
                    break
                line = raw.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                t = data.get("type")
                if t == "progress":
                    copied  = data.get("bytes_copied", 0)
                    total   = data.get("total_bytes", 1)
                    bp      = copied / total if total > 0 else 0.0
                    xfer    = f"{copied / 1024**3:.3f} GiB"
                    running = data.get("sha256")
                    el      = _fmt_hms(time.monotonic() - self._acq_start)
                    _e     = time.monotonic() - e01_start
                    _spd   = ((copied / _e) / (1024 ** 2)) if _e > 0.5 else 0.0
                    spd_str = (f"{_spd:6.2f} MB/s" if _spd > 0 else "--   MB/s")
                    if bp >= 1.0:
                        self._post_progress(
                            0.97, "Finalizing…", spd_str, "--:--:--", xfer, el,
                            hash_val=running or None,
                            hash_status=("Read complete — finalizing E01 "
                                         "(flushing to disk)…"),
                            finalize=True,
                        )
                    else:
                        mapped = 0.40 + 0.57 * bp
                        self._post_progress(
                            mapped, f"{int(mapped * 100):3d} %",
                            spd_str, self._overall_eta(mapped), xfer, el,
                            hash_val=running or None,
                            hash_status=(f"Creating E01 — {int(bp * 100)} %  "
                                         "(compressing & writing volume)"),
                        )
                elif t == "complete":
                    ok  = data.get("status") == "success"
                    sha = data.get("sha256", "")
                    rep = data.get("report", "")
                    break
            if proc.poll() is None:
                proc.wait()
        except Exception as exc:
            self._log(f"E01 engine error: {exc}", "ERROR")
            ok = False
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
        finally:
            self._proc = None
        return (ok, sha, rep)

    def _lock_ui_for_imaging(self) -> None:
        # Transform the START button into a live red ABORT button
        self.image_btn.configure(
            state="normal",
            text="⬛  ABORT",
            fg_color=_RED,
            hover_color="#b91c1c",
            command=self.abort_imaging,
        )
        self.scan_btn.configure(state="disabled")
        self.drive_dropdown.configure(state="disabled")
        # Hide any output panel from a previous run for the duration of this one
        self.output_panel.grid_remove()

    # ─────────────────────────────────────────────────────────────────────────
    # IMAGING WORKER
    # ─────────────────────────────────────────────────────────────────────────

    def _imaging_worker(self, backend: str, src: str, dst: str,
                        fmt_arg: str = "DD", comp_arg: str = "0") -> None:
        """
        Background thread: launches the C backend, reads its stdout line by
        line, and dispatches JSON messages back to the GUI via self.after(0, ...)
        or methods that do so internally.

        ``fmt_arg`` ("DD"/"E01") and ``comp_arg`` ("0"/"1"/"9") are appended to
        the backend command line; the legacy DD defaults keep the Golden Master
        invocation unchanged.

        A separate daemon thread drains stderr concurrently to prevent OS
        pipe-buffer deadlock during lengthy acquisitions.
        """
        proc: Optional[subprocess.Popen] = None

        try:
            m = self._case_meta
            notes = (m.get("notes", "") or "").replace("\n", " ").replace(
                "\r", " ")
            proc = subprocess.Popen(
                [backend, "image", src, dst, fmt_arg, comp_arg,
                 m.get("case", ""), m.get("evidence", ""),
                 m.get("examiner", ""), notes],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
                creationflags=CREATE_NO_WINDOW,
            )
            self._proc = proc   # expose for abort_imaging / on_closing

            def _drain_stderr() -> None:
                assert proc is not None
                for line in proc.stderr:
                    stripped = line.rstrip("\r\n")
                    if stripped:
                        self._log(f"[backend] {stripped}", "WARN")

            threading.Thread(target=_drain_stderr, daemon=True).start()

            while True:
                raw = proc.stdout.readline()
                if not raw:
                    break
                line = raw.strip()
                if not line:
                    continue

                try:
                    data: dict = json.loads(line)
                except json.JSONDecodeError:
                    self._log(f"Non-JSON backend output: {line!r}", "WARN")
                    continue

                msg_type = data.get("type")

                # ── Progress tick ─────────────────────────────────────────
                if msg_type == "progress":
                    copied: int = data.get("bytes_copied", 0)
                    total:  int = data.get("total_bytes", 1)
                    pct = copied / total if total > 0 else 0.0

                    # Telemetry computation — safe in background thread.
                    now = time.monotonic()
                    if self._acq_start == 0.0:
                        self._acq_start = now
                    # Worker-side throttle (~25 Hz); always render the 100 % tick.
                    if pct < 1.0 and (now - self._last_post_t) < 0.04:
                        continue
                    self._last_post_t = now
                    elapsed_s = now - self._acq_start

                    # Stable speed + ETA (1 Hz-sampled, slow EMA — won't bounce).
                    speed_mbs, eta_s = self._stable_eta(copied, total, now)

                    speed_str   = (f"{speed_mbs:6.2f} MB/s"
                                   if speed_mbs > 0 else "--   MB/s")
                    eta_str     = _fmt_hms(eta_s) if eta_s > 0 else "--:--:--"
                    xfer_str    = f"{copied / (1024 ** 3):.3f} GiB"
                    elapsed_str = _fmt_hms(elapsed_s)
                    pct_str     = f"{int(pct * 100):3d} %"

                    # Hand the snapshot to the main-thread pump — no Tk calls
                    # from this worker thread (that flooding was the lag source).
                    running = data.get("sha256")
                    if pct >= 1.0:
                        # All source bytes are read, but for E01 the backend is
                        # now in libewf write_finalize + flushing buffered writes
                        # to disk — this emits NO further progress and can take
                        # several minutes on slow destination media.  Surface a
                        # clear "finalizing" state so it doesn't look frozen.
                        self._post_progress(
                            1.0, "Finalizing…", speed_str, "--:--:--",
                            xfer_str, elapsed_str,
                            hash_val=running or None,
                            hash_status=("Read complete — finalizing image "
                                         "(flushing to disk; may take several "
                                         "minutes on slow media)…"),
                            finalize=True,
                        )
                    else:
                        total_gib = total / (1024 ** 3)
                        self._post_progress(
                            pct, pct_str, speed_str, eta_str, xfer_str,
                            elapsed_str,
                            hash_val=running or None,
                            hash_status=(
                                f"Reading & hashing sectors — {int(pct*100)} %"
                                f"   ·   {xfer_str} of {total_gib:.3f} GiB"
                                f"   ·   {speed_str.strip()}"),
                        )

                    # Log at 10 % milestones only to keep the log readable
                    pct_int   = int(pct * 100)
                    milestone = (pct_int // 10) * 10
                    if milestone > self._last_logged_pct:
                        self._last_logged_pct = milestone
                        total_gib = total / (1024 ** 3)
                        self._log(
                            f"Progress: {xfer_str} / {total_gib:.3f} GiB"
                            f"  [{pct_int:3d} %]  {speed_str}",
                            "INFO",
                        )

                # ── Bad-sector warning ────────────────────────────────────
                elif msg_type == "warning":
                    self._log(
                        data.get("message", "Unknown backend warning"), "WARN")
                    self.after(0, self._mark_bad_block)
                    self._bad_count += 1
                    self._set_detail("bad", str(self._bad_count), _RED)

                # ── Completion ────────────────────────────────────────────
                elif msg_type == "complete":
                    status      = data.get("status",        "error")
                    bytes_done  = data.get("bytes_copied",  0)
                    sha256      = data.get("sha256",         "")
                    bad_sectors = int(data.get("bad_sectors", 0))
                    report      = data.get("report",         "")
                    success     = (status == "success")

                    if success:
                        gib = bytes_done / (1024 ** 3)
                        self._log("─" * 56, "INFO")
                        self._log(
                            f"Acquisition complete — {gib:.3f} GiB written",
                            "SUCCESS",
                        )
                        if sha256:
                            self._log(f"SHA-256  {sha256}", "SUCCESS")
                            self._set_hash(
                                sha256,
                                ("SHA-256 verified ✓" if bad_sectors == 0
                                 else f"Hash covers {bad_sectors} zero-padded "
                                      "sector(s)"),
                            )
                        if bad_sectors > 0:
                            self._log(
                                f"WARNING: {bad_sectors} unreadable sector(s) "
                                "(Zero-Padded).  Hash covers padded data.",
                                "WARN",
                            )
                        elif sha256:
                            self._log(
                                "Cryptographic integrity verified ✓", "SUCCESS")
                        if report:
                            self._log(f"Audit Log  :  {report}", "SUCCESS")
                        else:
                            self._log(
                                "Audit Log could not be written — "
                                "check stderr for details.",
                                "WARN",
                            )
                        self._log("─" * 56, "INFO")
                    else:
                        self._log(
                            "Acquisition failed.  Check backend errors above.",
                            "ERROR",
                        )
                        self._set_hash(self._HASH_PLACEHOLDER,
                                       "Acquisition failed — no hash.")

                    # ── Post-acquisition verification (forensic re-read) ──────
                    v_ok = True
                    v_inconclusive = False
                    vmd5 = vsha1 = vcomp = ""
                    if success and sha256 and self.verify_var.get():
                        self._log("Verifying written image — this re-reads the "
                                  "evidence and re-hashes it…", "INFO")
                        if fmt_arg == "E01":
                            e01p = self._e01_target_name(dst)
                            v_ok, vcomp, vmd5, vsha1 = self._verify_e01_backend(
                                e01p, sha256)
                        else:
                            v_ok, vmd5, vsha1, vcomp = self._verify_dd_reread(
                                dst, sha256)
                        if self._aborted:
                            return
                        # No computed hash → the re-read itself failed (a tooling
                        # error), which is NOT a real hash mismatch.
                        v_inconclusive = (not v_ok) and (not vcomp)
                        self._log("─" * 56, "INFO")
                        if v_ok:
                            self._log("VERIFICATION PASSED — re-read hash "
                                      "matches the acquisition hash ✓", "SUCCESS")
                            if fmt_arg != "E01":
                                self._log(f"MD5    {vmd5}", "SUCCESS")
                                self._log(f"SHA-1  {vsha1}", "SUCCESS")
                            self._set_hash(
                                sha256,
                                "Verified ✓ — image re-read matches "
                                "acquisition hash")
                        elif v_inconclusive:
                            self._log("VERIFICATION COULD NOT COMPLETE — the "
                                      "image was written and hashed OK, but the "
                                      "re-read failed (see backend errors "
                                      "above).  The image is kept.", "WARN")
                            self._set_hash(
                                sha256,
                                "Image written ✓ — verification could not "
                                "complete (re-read error)")
                        else:
                            self._log(
                                f"VERIFICATION FAILED — re-read {vcomp} != "
                                f"acquisition {sha256}", "ERROR")
                            self._log("Evidence integrity NOT confirmed — do "
                                      "not rely on this image.", "ERROR")
                            self._set_hash(
                                sha256,
                                "⚠ VERIFICATION FAILED — image does not match")
                        self._log("─" * 56, "INFO")

                    # Surface every computed digest in the details panel + a
                    # plain-text <image>.hashes.txt next to the evidence.
                    if success and sha256:
                        eff_sha = vcomp or sha256
                        if vmd5 or vsha1:
                            self._append_acq_hashes(
                                sha256=eff_sha, md5=vmd5, sha1=vsha1)
                            self._append_hashes_to_report(
                                report, vmd5, vsha1, eff_sha)
                        elif fmt_arg == "E01":
                            self._append_acq_hashes(
                                sha256=sha256,
                                note="Enable 'Verify after acquisition' to "
                                     "extract MD5 / SHA-1.")
                        else:
                            self._append_acq_hashes(sha256=eff_sha)
                            self._append_hashes_to_report(
                                report, "", "", eff_sha)

                    final_ok = success and (v_ok or v_inconclusive)
                    final_sha = sha256 if (final_ok and v_ok) else ""
                    self._finish_imaging(
                        final_ok, final_sha, bad_sectors,
                        dst if final_ok else "")
                    return

            # Loop ended without a "complete" message.
            # If the user triggered an abort this is expected — stay silent.
            if not self._aborted:
                proc.wait()
                self._log(
                    f"Backend exited unexpectedly (code {proc.returncode}).",
                    "ERROR",
                )
                self._finish_imaging(False)

        except Exception as exc:
            self._log(f"Imaging thread error: {exc}", "ERROR")
            if proc:
                proc.kill()
            if not self._aborted:
                self._finish_imaging(False)

        finally:
            self._proc = None   # always clear the reference when the thread exits

    # ─────────────────────────────────────────────────────────────────────────
    # FINISH IMAGING
    # ─────────────────────────────────────────────────────────────────────────

    def _finish_imaging(
        self,
        success:     bool,
        sha256:      str = "",
        bad_sectors: int = 0,
        output_path: str = "",
    ) -> None:
        """Re-enable the UI and set final progress-bar colour.

        On a successful acquisition, ``output_path`` (the image file, archive
        or folder that was written) is surfaced in the post-completion panel
        with an Open-in-Explorer button.
        """
        self._is_imaging = False
        self._seg_base   = ""        # stop the pump polling for segments
        # Stop the pump from consuming any in-flight worker snapshot — done
        # synchronously here (we may be on the worker thread) so it can't clobber
        # the final hash/telemetry the completion handler is about to set.
        self._ui_pending = None
        self._pump_text  = None

        def _restore() -> None:
            self.image_btn.configure(
                state="normal", text="▶  START IMAGING",
                fg_color=_GREEN, hover_color="#2ea043",
                command=self.start_imaging,   # restore from ABORT state
            )
            self.scan_btn.configure(state="normal")
            self.drive_dropdown.configure(state="normal")

            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")

            # Reveal the output location only for a successful acquisition.
            if success and output_path:
                self._last_output_path = output_path
                self._output_caption.configure(
                    text=f"Output written to:\n{output_path}")
                self.output_panel.grid()
            else:
                self.output_panel.grid_remove()

            # Snap the easing state to the final position so the pump doesn't
            # keep gliding after completion, and drop any stale snapshot.
            self._ui_pending = None
            self._pump_text  = None
            self._progress_indeterminate = False
            final_pos = 0.0 if not success else 1.0
            self._progress_target  = final_pos
            self._progress_display = final_pos

            # Phase chip final state (success states are set by _set_status).
            if not success:
                if self._aborted:
                    self._set_phase("ABORTED", _AMBER, "#000000")
                else:
                    self._set_phase("FAILED", _RED)

            if success and bad_sectors > 0:
                # Partial integrity — image written but with zero-padded gaps
                self.progress_bar.configure(progress_color=_AMBER)
                self.progress_bar.set(1.0)
                self.progress_lbl.configure(text=f"⚠ {bad_sectors} bad")
            elif success and sha256:
                # Clean, cryptographically verified acquisition
                self.progress_bar.configure(progress_color=_GREEN)
                self.progress_bar.set(1.0)
                self.progress_lbl.configure(text="Verified ✓")
            elif success:
                self.progress_bar.configure(progress_color=_ACCENT)
                self.progress_bar.set(1.0)
                self.progress_lbl.configure(text="Done")
            else:
                self.progress_bar.configure(progress_color=_RED)
                self.progress_bar.set(0.0)
                self.progress_lbl.configure(text="Failed")

        self.after(0, _restore)


    # ─────────────────────────────────────────────────────────────────────────
    # ABORT & CLOSE
    # ─────────────────────────────────────────────────────────────────────────

    def abort_imaging(self) -> None:
        """Kill-switch: terminate the backend and reset the UI.
        Called from the main thread (ABORT button command)."""
        if not self._is_imaging:
            return

        self._aborted = True
        self._log("─" * 60, "INFO")
        self._log("Acquisition ABORTED by user.", "ERROR")
        self._log("─" * 60, "INFO")

        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            # After 1 s, force-kill if the backend is still alive
            def _force_kill(p: subprocess.Popen = proc) -> None:
                if p.poll() is None:
                    p.kill()
                    self._log("Backend force-killed after timeout.", "WARN")
            self.after(1000, _force_kill)

        # Reset UI immediately — _imaging_worker will see _aborted=True and
        # skip its own _finish_imaging call.
        self._finish_imaging(False)

    def on_closing(self) -> None:
        """Handle the window close button — no zombie backend processes.
        Kills the backend immediately (no grace period) before destroying."""
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
        if self._log_fp is not None:
            try:
                self._log_fp.close()
            except Exception:
                pass
        self.destroy()


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    app = ForensicImagerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
