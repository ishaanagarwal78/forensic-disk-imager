# Forensic Disk Imager

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)

A forensic disk-imaging suite for creating court-admissible evidence images. It
performs **physical acquisitions** — a complete, sector-by-sector copy of an
entire drive — and **logical acquisitions** that capture only selected files and
folders. Every acquisition is hashed in real time, automatically verified, and
documented with embedded chain-of-custody metadata.

> ⚠️ **Authorized use only.** This tool performs raw block-device access and is
> intended for legitimate digital-forensics, incident-response, and data-recovery
> work on media you own or are authorized to examine.

---

## Features

- **Two acquisition modes** — physical (whole disk, sector by sector) and
  logical (chosen files and folders).
- **Multiple evidence formats** — raw **DD** and **EnCase E01** (single or
  multi-segment).
- **Triple-hash integrity** — **MD5 + SHA-1 + SHA-256**, computed live during
  imaging.
- **Automatic verification** — re-reads the written image and confirms it matches
  the original acquisition hash.
- **Chain of custody** — case number, evidence number, examiner, and notes
  embedded in the evidence and a plain-text audit report.
- **Per-file manifest** — individual hashes and timestamps for logical
  acquisitions.
- **Resilient acquisition** — graceful bad-sector handling with zero-padding and
  reporting.
- **Live dashboard** — speed, ETA, throughput graph, sector map, segment counter,
  and device details (model, serial, firmware).
- **Safety guards** — destination free-space check and a pre-flight confirmation
  before any acquisition begins.

---

## Usage

Launch the application (run **as Administrator / root** for raw physical-drive
access):

1. Choose **Physical** or **Logical** imaging.
2. Select the source (a drive, or a folder) and an output location.
3. Pick the **output format** and **compression**, and optionally enter the
   **case information**.
4. Press **START IMAGING** and watch the live dashboard. The evidence is verified
   automatically when imaging completes.

---

## Output

| File | Contents |
|------|----------|
| `<name>.E01` / `<name>.dd` | the evidence image (E01 may span multiple segments) |
| `<name>.img.txt` | chain-of-custody audit report (case info + MD5/SHA-1/SHA-256) |
| `logical_audit.csv` | per-file MD5/SHA-1/SHA-256 + timestamps (logical modes) |

---

## License

**Proprietary — All Rights Reserved.** Copyright (c) 2026 Ishaan Agarwal.
See [LICENSE](LICENSE). No permission is granted to copy, modify, distribute, or
use this software without express written permission.
