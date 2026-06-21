/*
 * imager.c — Bare-metal forensic image acquisition engine with bad-sector armor
 *
 * Normal path:   reads CHUNK_SIZE (4 MiB) at a time — fast sequential I/O.
 * Recovery path: when a chunk read fails, the engine steps down to
 *                SECTOR_SIZE (512 B) granularity across that exact range.
 *                  • Readable sectors  → hash + write as normal.
 *                  • Unreadable sectors → inject 512 zero bytes, hash the
 *                    zeros, write zeros.  Byte alignment is preserved.
 *                One aggregated warning JSON is emitted per recovered chunk
 *                (never per-sector) to prevent IPC flooding on severely
 *                damaged drives.
 *
 * Output formats:
 *   DD   raw byte-for-byte image (Golden Master path — untouched).
 *   E01  true EnCase Expert Witness Format via libewf.  The raw 4 MiB buffer
 *        is handed straight to libewf_handle_write_buffer(); libewf performs
 *        the 32 KiB chunking, Adler-32 chunk checksums, offset tables and the
 *        MD5/SHA-1 hash sections internally.
 *
 * The streamed SHA-256 is always computed over the SOURCE bytes (uncompressed)
 * in both formats, so it verifies against the original drive regardless of the
 * on-disk container.
 *
 * IPC contract (stdout, one JSON per line, flushed immediately):
 *
 *   {"type": "progress",  "bytes_copied": N,   "total_bytes": T}
 *   {"type": "warning",   "message": "Recovered chunk at offset N: X unreadable sector(s)"}
 *   {"type": "complete",  "status": "success", "bytes_copied": N,
 *                         "sha256": "…64 hex chars…", "bad_sectors": K,
 *                         "report": "/path/to/audit.txt"}
 *   {"type": "complete",  "status": "error",   "bad_sectors": K}
 *
 * All OS-level diagnostics go exclusively to stderr.
 */

#include "imager.h"
#include "sha256.h"
#include "sha1.h"
#include "md5.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <libewf.h>    /* true EnCase E01 output (link with -lewf) */

#define CHUNK_SIZE       (4 * 1024 * 1024)  /* bulk read unit — 4 MiB      */
#define SECTOR_SIZE      512                 /* atomic recovery unit        */
#define REPORT_INTERVAL  1                   /* progress JSON every chunk (~4 MiB) for smooth UI */
#define REPORT_PATH_MAX  4096                /* max chars for report path   */

/* ── Common helpers ──────────────────────────────────────────────────────── */

static void bytes_to_hex(const unsigned char *bytes, int len, char *out)
{
    int i;
    for (i = 0; i < len; i++)
        snprintf(out + i * 2, 3, "%02x", (unsigned int)bytes[i]);
    out[len * 2] = '\0';
}

/*
 * emit_progress — write a progress JSON line, including a LIVE SHA-256 of all
 * bytes hashed so far.  We snapshot the running context by value and finalize
 * the COPY, so the real acquisition hash is never disturbed.  Each emitted
 * digest is a valid SHA-256 of the data acquired up to `copied` bytes, and the
 * final tick equals the digest reported in the completion message.
 */
static void emit_progress(const sha256_ctx *ctx,
                          long long copied, long long total)
{
    sha256_ctx snap = *ctx;                       /* independent snapshot */
    uint8_t    digest[SHA256_DIGEST_SIZE];
    char       hex[SHA256_DIGEST_SIZE * 2 + 1];

    sha256_final(&snap, digest);
    bytes_to_hex(digest, SHA256_DIGEST_SIZE, hex);

    printf("{\"type\": \"progress\", \"bytes_copied\": %lld, "
           "\"total_bytes\": %lld, \"sha256\": \"%s\"}\n",
           copied, total, hex);
    fflush(stdout);
}

/* "E01" (case-insensitive) selects the EnCase container; anything else
 * (including NULL) is the raw DD Golden Master path. */
static int fmt_is_e01(const char *fmt)
{
    return fmt && (strcmp(fmt, "E01") == 0 || strcmp(fmt, "e01") == 0);
}

/* True if `ext` (no dot) is one of our recognised image extensions (CI). */
static int ext_is_image(const char *ext)
{
    char low[8];
    size_t i;
    for (i = 0; i + 1 < sizeof(low) && ext[i]; i++)
        low[i] = (char)tolower((unsigned char)ext[i]);
    low[i] = '\0';
    if (ext[i] != '\0')          /* longer than any extension we strip */
        return 0;
    return strcmp(low, "e01") == 0 || strcmp(low, "dd")  == 0
        || strcmp(low, "img") == 0 || strcmp(low, "raw") == 0;
}

/*
 * ewf_basename — libewf APPENDS ".E01" to the base name it is given, so passing
 * "evidence.E01" yields "evidence.E01.E01".  Copy `dst` into `out` and strip a
 * trailing image extension (only when it appears after the last path separator)
 * so libewf re-adds exactly one ".E01".
 */
static void ewf_basename(const char *dst, char *out, size_t outlen)
{
    const char *p, *sep = NULL, *dot = NULL;

    snprintf(out, outlen, "%s", dst);

    for (p = out; *p; p++)
        if (*p == '/' || *p == '\\')
            sep = p;
    for (p = (sep ? sep + 1 : out); *p; p++)
        if (*p == '.')
            dot = p;

    if (dot != NULL && ext_is_image(dot + 1))
        out[dot - out] = '\0';   /* truncate the extension */
}

/* Map the UI compression string ("0"/"1"/"9") to a libewf compression level.
 * libewf_handle_set_compression_values() takes a raw int8_t level, NOT the
 * LIBEWF_COMPRESSION_LEVEL_* string macros.  The valid values are the discrete
 * EWF levels: 0 = NONE, 1 = FAST, 2 = BEST (libewf has no 0..9 scale). */
static int8_t ewf_compression_level(const char *compression)
{
    int lvl = compression ? atoi(compression) : 0;
    if (lvl >= 9) return 2;   /* Best  (LIBEWF_COMPRESSION_BEST) */
    if (lvl >= 1) return 1;   /* Fast  (LIBEWF_COMPRESSION_FAST) */
    return 0;                 /* None  (LIBEWF_COMPRESSION_NONE) */
}

/* ── libewf glue (platform-agnostic — libewf is cross-platform) ───────────── */

/* Print a libewf error to stderr and release it, so failures are never silent. */
static void ewf_report_error(libewf_error_t **error, const char *what)
{
    fprintf(stderr, "libewf: %s failed\n", what);
    if (error != NULL && *error != NULL) {
        libewf_error_fprint(*error, stderr);
        libewf_error_free(error);
    }
}

/*
 * ewf_open_for_write — initialize a libewf handle, open `dst` for writing and
 * configure media size, EnCase6 format and compression.  Returns 0 on success;
 * on failure reports the error, frees the handle and returns -1.
 */
/* Set a single EWF header value (case_number, examiner_name, …).  Skips empty
 * values; a libewf failure is non-fatal (logged, acquisition continues). */
static void ewf_set_header(libewf_handle_t *handle,
                           const char *identifier, const char *value)
{
    libewf_error_t *error = NULL;
    if (value == NULL || value[0] == '\0')
        return;
    if (libewf_handle_set_header_value(
            handle,
            (const uint8_t *)identifier, strlen(identifier),
            (const uint8_t *)value,      strlen(value),
            &error) != 1) {
        ewf_report_error(&error, "libewf_handle_set_header_value");
    }
}

static int ewf_open_for_write(libewf_handle_t **handle, const char *dst,
                              long long total_bytes, int8_t comp_level,
                              const char *case_no, const char *evidence_no,
                              const char *examiner, const char *notes)
{
    libewf_error_t *error = NULL;
    char           *filenames[1];

    filenames[0] = (char *)dst;

    if (libewf_handle_initialize(handle, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_initialize");
        return -1;
    }
    if (libewf_handle_open(*handle, filenames, 1,
                           LIBEWF_OPEN_WRITE, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_open");
        return -1;
    }
    if (libewf_handle_set_media_size(*handle,
                                     (size64_t)total_bytes, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_set_media_size");
        return -1;
    }
    if (libewf_handle_set_format(*handle,
                                 LIBEWF_FORMAT_ENCASE6, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_set_format");
        return -1;
    }
    if (libewf_handle_set_compression_values(*handle,
                                             comp_level, 0, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_set_compression_values");
        return -1;
    }
    /* Chain-of-custody metadata embedded in the EWF header (shown by
     * EnCase / X-Ways in evidence properties).  All non-fatal. */
    ewf_set_header(*handle, "case_number",     case_no);
    ewf_set_header(*handle, "evidence_number", evidence_no);
    ewf_set_header(*handle, "examiner_name",   examiner);
    ewf_set_header(*handle, "notes",           notes);
    ewf_set_header(*handle, "acquiry_software_version", "FDImager 2.0");
    return 0;
}

/* Write `len` bytes through libewf; returns 0 on success, -1 on failure. */
static int ewf_write(libewf_handle_t *handle,
                     const unsigned char *data, size_t len)
{
    libewf_error_t *error   = NULL;
    ssize_t         written = libewf_handle_write_buffer(
                                  handle, (void *)data, len, &error);
    if (written != (ssize_t)len) {
        ewf_report_error(&error, "libewf_handle_write_buffer");
        return -1;
    }
    return 0;
}

/* Flush libewf's trailing sections (table/table2/hash).  MANDATORY — without
 * this the E01 is incomplete and unreadable.  Returns 0 on success. */
static int ewf_finalize(libewf_handle_t *handle)
{
    libewf_error_t *error = NULL;
    if (libewf_handle_write_finalize(handle, &error) < 0) {
        ewf_report_error(&error, "libewf_handle_write_finalize");
        return -1;
    }
    return 0;
}

/* Close + free a libewf handle, swallowing (but reporting) any close errors. */
static void ewf_close_free(libewf_handle_t **handle)
{
    libewf_error_t *error = NULL;
    if (handle == NULL || *handle == NULL)
        return;
    if (libewf_handle_close(*handle, &error) != 0) {
        ewf_report_error(&error, "libewf_handle_close");
    }
    if (libewf_handle_free(handle, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_free");
    }
}

/*
 * verify_e01 — re-read an E01 evidence set via libewf, recompute the SHA-256 of
 * the *decoded* media stream and compare it to `expected_sha`.  This proves the
 * E01 decompresses to exactly the bytes that were acquired
 * (acquisition hash == verification hash).  Progress is streamed; a completion
 * JSON reports the verdict.  Returns 0 = verified, 1 = mismatch, 2 = error.
 */
int verify_e01(const char *e01_path, const char *expected_sha)
{
    libewf_error_t  *error      = NULL;
    libewf_handle_t *handle     = NULL;
    char           **filenames  = NULL;
    int              num_files  = 0;
    size64_t         media_size = 0;
    long long        total = 0, done = 0;
    sha256_ctx       sha;
    sha1_ctx         s1;
    md5_ctx          m5;
    uint8_t          hash[SHA256_DIGEST_SIZE];
    uint8_t          sha1_raw[SHA1_DIGEST_SIZE];
    uint8_t          md5_raw[MD5_DIGEST_SIZE];
    char             hex[SHA256_DIGEST_SIZE * 2 + 1];
    unsigned char   *buf = NULL;
    const size_t     BUFSZ = 4 * 1024 * 1024;
    int              verified = 0;

    if (libewf_glob(e01_path, strlen(e01_path), LIBEWF_FORMAT_UNKNOWN,
                    &filenames, &num_files, &error) != 1) {
        ewf_report_error(&error, "libewf_glob");
        goto fail;
    }
    if (libewf_handle_initialize(&handle, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_initialize");
        goto fail;
    }
    if (libewf_handle_open(handle, filenames, num_files,
                           LIBEWF_OPEN_READ, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_open(read)");
        goto fail;
    }
    if (libewf_handle_get_media_size(handle, &media_size, &error) != 1) {
        ewf_report_error(&error, "libewf_handle_get_media_size");
        goto fail;
    }
    total = (long long)media_size;
    buf   = (unsigned char *)malloc(BUFSZ);
    if (buf == NULL) {
        fprintf(stderr, "verify: out of memory\n");
        goto fail;
    }

    sha256_init(&sha);
    sha1_init(&s1);
    md5_init(&m5);
    while (done < total) {
        long long remaining = total - done;
        size_t    want = (remaining < (long long)BUFSZ)
                         ? (size_t)remaining : BUFSZ;
        ssize_t   got  = libewf_handle_read_buffer(handle, buf, want, &error);
        if (got <= 0) {
            ewf_report_error(&error, "libewf_handle_read_buffer");
            goto fail;
        }
        sha256_update(&sha, buf, (size_t)got);
        sha1_update(&s1, buf, (size_t)got);
        md5_update(&m5, buf, (size_t)got);
        done += got;
        emit_progress(&sha, done, total);
    }
    sha256_final(&sha, hash);
    sha1_final(&s1, sha1_raw);
    md5_final(&m5, md5_raw);
    bytes_to_hex(hash, SHA256_DIGEST_SIZE, hex);
    verified = (expected_sha != NULL && expected_sha[0] != '\0'
                && strcmp(hex, expected_sha) == 0);

    /* Pull libewf's stored MD5 / SHA-1 so the GUI/report can show them without
     * the ewfinfo command.  Either may be absent → reported as empty. */
    {
        char  md5_hex[MD5_DIGEST_SIZE * 2 + 1];
        char  sha1_hex[SHA1_DIGEST_SIZE * 2 + 1];

        /* MD5 + SHA-1 are computed by us over the decoded stream (libewf does
         * not reliably expose them), so both are always available. */
        bytes_to_hex(md5_raw, MD5_DIGEST_SIZE, md5_hex);
        bytes_to_hex(sha1_raw, SHA1_DIGEST_SIZE, sha1_hex);

        printf("{\"type\": \"complete\", \"status\": \"success\", "
               "\"verified\": %s, \"computed_sha256\": \"%s\", "
               "\"expected_sha256\": \"%s\", \"md5\": \"%s\", "
               "\"sha1\": \"%s\", \"bytes_copied\": %lld}\n",
               verified ? "true" : "false", hex,
               expected_sha ? expected_sha : "", md5_hex, sha1_hex, done);
        fflush(stdout);
    }

    free(buf);
    ewf_close_free(&handle);
    if (filenames)
        libewf_glob_free(filenames, num_files, &error);
    return verified ? 0 : 1;

fail:
    if (buf)
        free(buf);
    if (handle)
        ewf_close_free(&handle);
    if (filenames)
        libewf_glob_free(filenames, num_files, &error);
    printf("{\"type\": \"complete\", \"status\": \"error\", "
           "\"verified\": false}\n");
    fflush(stdout);
    return 2;
}

/*
 * json_escape_path — copy `src` into `dst_buf`, doubling every backslash
 * and backslash-escaping every double-quote so the result is safe to embed
 * as a JSON string value (without surrounding quotes).
 */
static void json_escape_path(const char *src, char *dst_buf, size_t dstlen)
{
    size_t j = 0;
    const char *p;
    for (p = src; *p && j + 3 < dstlen; p++) {
        if      (*p == '\\') { dst_buf[j++] = '\\'; dst_buf[j++] = '\\'; }
        else if (*p == '"')  { dst_buf[j++] = '\\'; dst_buf[j++] = '"';  }
        else                 { dst_buf[j++] = *p; }
    }
    dst_buf[j] = '\0';
}

/*
 * write_report — produce a plain-text chain-of-custody audit log.
 *
 * The file is opened in text mode so line endings are platform-appropriate
 * (CRLF on Windows, LF on Linux).  All errors are reported to stderr only.
 *
 * Returns 0 on success, -1 if the file could not be created or written.
 */
static int write_report(
    const char *report_path,
    const char *src_drive,
    const char *dst_image,
    long long   bytes_copied,
    const char *sha_hex,
    long long   bad_sectors,
    const char *case_no,
    const char *evidence_no,
    const char *examiner,
    const char *notes)
{
    #define RPT_OR_DASH(s) (((s) && (s)[0]) ? (s) : "(not provided)")
    FILE       *f;
    time_t      now;
    struct tm  *gmt;
    char        timebuf[64];
    const char *status_str;

    f = fopen(report_path, "w");
    if (!f) {
        fprintf(stderr, "Cannot create audit log '%s': %s\n",
                report_path, strerror(errno));
        return -1;
    }

    time(&now);
    gmt = gmtime(&now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC", gmt);

    status_str = (bad_sectors == 0) ? "SUCCESS - Clean image"
                                    : "SUCCESS - Image contains zero-padded sectors";

    fprintf(f,
        "======================================================================\n"
        "          FORENSIC DISK ACQUISITION - CHAIN OF CUSTODY LOG\n"
        "======================================================================\n"
        "\n"
        "  Generated  : %s\n"
        "  Tool       : Forensic Disk Imager\n"
        "\n"
        "----------------------------------------------------------------------\n"
        "  CASE INFORMATION\n"
        "----------------------------------------------------------------------\n"
        "  Case Number     : %s\n"
        "  Evidence Number : %s\n"
        "  Examiner        : %s\n"
        "  Description     : %s\n"
        "\n"
        "----------------------------------------------------------------------\n"
        "  SOURCE\n"
        "----------------------------------------------------------------------\n"
        "  Drive Path : %s\n"
        "\n"
        "----------------------------------------------------------------------\n"
        "  DESTINATION\n"
        "----------------------------------------------------------------------\n"
        "  Image File : %s\n"
        "  Audit Log  : %s\n"
        "\n"
        "----------------------------------------------------------------------\n"
        "  ACQUISITION SUMMARY\n"
        "----------------------------------------------------------------------\n"
        "  Bytes Copied : %lld\n"
        "  Bad Sectors  : %lld%s\n"
        "  Status       : %s\n"
        "\n"
        "----------------------------------------------------------------------\n"
        "  CRYPTOGRAPHIC VERIFICATION\n"
        "----------------------------------------------------------------------\n"
        "  Algorithm    : SHA-256 (FIPS 180-4, pure-C implementation)\n"
        "  Hash         : %s\n"
        "\n"
        "======================================================================\n"
        "  This document constitutes a chain-of-custody record for the\n"
        "  evidence image described above.  Any modification to the image\n"
        "  file will produce a different SHA-256 hash.\n"
        "======================================================================\n",
        timebuf,
        RPT_OR_DASH(case_no),
        RPT_OR_DASH(evidence_no),
        RPT_OR_DASH(examiner),
        RPT_OR_DASH(notes),
        src_drive,
        dst_image,
        report_path,
        bytes_copied,
        bad_sectors,
        (bad_sectors > 0) ? " (unreadable sectors replaced with 0x00 padding)" : "",
        status_str,
        sha_hex
    );
    #undef RPT_OR_DASH

    if (ferror(f)) {
        fprintf(stderr, "Write error on audit log '%s'\n", report_path);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Windows Implementation
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifdef _WIN32

#ifndef WINVER
#  define WINVER       0x0601
#endif
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>

static long long win_drive_size(HANDLE hDev)
{
    DISK_GEOMETRY_EX   geo;
    GET_LENGTH_INFORMATION len;
    LARGE_INTEGER      fileSize;
    DWORD              ret = 0;

    memset(&geo, 0, sizeof(geo));
    if (DeviceIoControl(hDev, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                        NULL, 0, &geo, sizeof(geo), &ret, NULL))
        return (long long)geo.DiskSize.QuadPart;

    if (DeviceIoControl(hDev, IOCTL_DISK_GET_LENGTH_INFO,
                        NULL, 0, &len, sizeof(len), &ret, NULL))
        return (long long)len.Length.QuadPart;

    /* Fallback for regular files (useful for testing / logical volumes) */
    if (GetFileSizeEx(hDev, &fileSize))
        return (long long)fileSize.QuadPart;

    return -1LL;
}

/*
 * win_native_target — make a path libewf can actually create on Windows.
 *
 * The GUI (tkinter) supplies forward-slash paths, and paths under the user
 * profile contain spaces (e.g. "Ishaan agarwal").  libewf's segment-file
 * creation fails on those ("unable to write new chunk" at offset 0).  We:
 *   1. convert '/' -> '\'
 *   2. replace the (existing) directory with its 8.3 short form to drop spaces
 * The filename component is left as-is (the caller's chosen base name).
 */
static void win_native_target(const char *in, char *out, size_t outlen)
{
    char  tmp[REPORT_PATH_MAX];
    char *q, *slash;

    snprintf(tmp, sizeof(tmp), "%s", in);
    for (q = tmp; *q; q++)
        if (*q == '/')
            *q = '\\';

    slash = strrchr(tmp, '\\');
    if (slash != NULL) {
        char   dir[REPORT_PATH_MAX];
        char   shortdir[REPORT_PATH_MAX];
        size_t dirlen = (size_t)(slash - tmp);
        memcpy(dir, tmp, dirlen);
        dir[dirlen] = '\0';
        /* GetShortPathNameA needs the directory to exist; if 8.3 names are
         * disabled or the call fails, fall back to the long directory. */
        if (dirlen == 0 ||
            GetShortPathNameA(dir, shortdir, sizeof(shortdir)) == 0)
            snprintf(shortdir, sizeof(shortdir), "%s", dir);
        snprintf(out, outlen, "%s\\%s", shortdir, slash + 1);
    } else {
        snprintf(out, outlen, "%s", tmp);
    }
}

/* Unified destination write: raw DD (WriteFile) or E01 (libewf).
 * Returns 0 on success, -1 on failure. */
static int dst_put_win(HANDLE hDst, libewf_handle_t *handle, int use_e01,
                       const unsigned char *data, DWORD len)
{
    DWORD bw;
    if (use_e01)
        return ewf_write(handle, data, (size_t)len);
    return (WriteFile(hDst, data, len, &bw, NULL) && bw == len) ? 0 : -1;
}

int image_drive(const char *src, const char *dst,
                const char *fmt, const char *compression,
                const char *case_no, const char *evidence_no,
                const char *examiner, const char *notes)
{
    HANDLE          hSrc        = INVALID_HANDLE_VALUE;
    HANDLE          hDst        = INVALID_HANDLE_VALUE;   /* DD only */
    libewf_handle_t *handle     = NULL;                   /* E01 only */
    unsigned char  *buf         = NULL;
    int             use_e01     = fmt_is_e01(fmt);
    int8_t          comp_level  = ewf_compression_level(compression);
    long long       totalBytes  = 0;
    long long       bytesCopied = 0;
    long long       chunkIndex  = 0;
    long long       bad_sectors = 0;
    int             result      = 1;

    /* Per-sector buffers — stack-allocated (512 B each, trivial overhead) */
    unsigned char sec_buf[SECTOR_SIZE];
    unsigned char zero_sec[SECTOR_SIZE];

    sha256_ctx sha_ctx;
    uint8_t    sha_hash[SHA256_DIGEST_SIZE];
    char       sha_hex[SHA256_DIGEST_SIZE * 2 + 1];

    /* Audit log path and its JSON-escaped copy */
    char report_path[REPORT_PATH_MAX];
    char report_esc [REPORT_PATH_MAX * 2];

    memset(zero_sec, 0x00, SECTOR_SIZE);
    snprintf(report_path, sizeof(report_path), "%s.txt", dst);

    /* ── Open source drive ──────────────────────────────────────────────── */
    hSrc = CreateFileA(
        src, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, NULL
    );
    if (hSrc == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot open source '%s': Win32 error %lu\n",
                src, (unsigned long)GetLastError());
        fprintf(stderr, "Re-run as Administrator for raw drive access.\n");
        goto cleanup;
    }

    totalBytes = win_drive_size(hSrc);
    if (totalBytes <= 0) {
        fprintf(stderr, "Cannot determine size of '%s'\n", src);
        goto cleanup;
    }

    /* ── Open / create destination ──────────────────────────────────────── */
    if (use_e01) {
        /* libewf owns the destination file(s) and appends ".E01" itself, so
         * strip any extension the caller supplied to avoid "name.E01.E01",
         * then normalise to a native backslash / space-free path libewf can
         * create. */
        char stripped[REPORT_PATH_MAX];
        char ewf_target[REPORT_PATH_MAX];
        ewf_basename(dst, stripped, sizeof(stripped));
        win_native_target(stripped, ewf_target, sizeof(ewf_target));
        if (ewf_open_for_write(&handle, ewf_target, totalBytes, comp_level,
                               case_no, evidence_no, examiner, notes) != 0)
            goto cleanup;
        fprintf(stderr,
                "E01 mode (libewf EnCase6): compression level %d -> %s.E01\n",
                (int)comp_level, ewf_target);
    } else {
        hDst = CreateFileA(
            dst, GENERIC_WRITE, 0,
            NULL, CREATE_ALWAYS,
            FILE_FLAG_SEQUENTIAL_SCAN, NULL
        );
        if (hDst == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "Cannot create destination '%s': Win32 error %lu\n",
                    dst, (unsigned long)GetLastError());
            goto cleanup;
        }
    }

    /* ── Allocate bulk read buffer ──────────────────────────────────────── */
    buf = (unsigned char *)malloc(CHUNK_SIZE);
    if (!buf) {
        fprintf(stderr, "malloc(%d) failed\n", CHUNK_SIZE);
        goto cleanup;
    }

    sha256_init(&sha_ctx);

    printf("{\"type\": \"progress\", \"bytes_copied\": 0, \"total_bytes\": %lld}\n",
           totalBytes);
    fflush(stdout);

    /* ════════════════════════════════════════════════════════════════════
     * Copy loop
     * ════════════════════════════════════════════════════════════════════ */
    while (bytesCopied < totalBytes) {
        long long remaining = totalBytes - bytesCopied;
        DWORD toRead = (remaining >= (long long)CHUNK_SIZE)
                           ? (DWORD)CHUNK_SIZE
                           : (DWORD)remaining;
        DWORD bytesRead = 0, bytesWritten = 0;
        BOOL  ok;

        ok = ReadFile(hSrc, buf, toRead, &bytesRead, NULL);

        if (ok && bytesRead > 0) {
            /* ── Fast path: hash then write ─────────────────────────── */
            /* SHA-256 always covers the SOURCE bytes (uncompressed), so the
             * hash verifies against the original drive in either format. */
            sha256_update(&sha_ctx, buf, bytesRead);
            if (use_e01) {
                /* Hand the raw 4 MiB buffer to libewf — it does the 32 KiB
                 * chunking, Adler-32 and CRC math internally. */
                if (ewf_write(handle, buf, bytesRead) != 0) {
                    fprintf(stderr, "E01 write failed at offset %lld\n",
                            bytesCopied);
                    goto cleanup;
                }
            } else {
                /* Golden Master DD path — byte-for-byte, untouched */
                ok = WriteFile(hDst, buf, bytesRead, &bytesWritten, NULL);
                if (!ok || bytesWritten != bytesRead) {
                    fprintf(stderr, "WriteFile failed at offset %lld: error %lu\n",
                            bytesCopied, (unsigned long)GetLastError());
                    goto cleanup;
                }
            }
            bytesCopied += (long long)bytesRead;

        } else if (!ok) {
            /* ── Recovery path: sector-by-sector across failed range ── */
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF) break;

            fprintf(stderr,
                    "Read error at offset %lld (Win32 error %lu), "
                    "entering sector recovery\n",
                    bytesCopied, (unsigned long)err);

            /* chunk_bad counts unreadable sectors within this 4 MiB chunk.
             * We emit ONE aggregated warning after the loop, not one per
             * sector, to prevent IPC flooding on badly damaged drives.      */
            DWORD chunk_bad = 0;
            DWORD recovered = 0;
            while (recovered < toRead) {
                DWORD secToRead = ((DWORD)SECTOR_SIZE <= toRead - recovered)
                                      ? (DWORD)SECTOR_SIZE
                                      : (toRead - recovered);
                LARGE_INTEGER seekPos;
                seekPos.QuadPart = bytesCopied + (long long)recovered;

                if (!SetFilePointerEx(hSrc, seekPos, NULL, FILE_BEGIN)) {
                    /*
                     * Seek itself failed — declare every remaining byte in
                     * this chunk as bad and break out of the inner loop.
                     */
                    fprintf(stderr, "SetFilePointerEx failed at offset %lld\n",
                            seekPos.QuadPart);
                    while (recovered < toRead) {
                        DWORD sub = ((DWORD)SECTOR_SIZE <= toRead - recovered)
                                        ? (DWORD)SECTOR_SIZE
                                        : (toRead - recovered);
                        sha256_update(&sha_ctx, zero_sec, sub);
                        if (dst_put_win(hDst, handle, use_e01,
                                        zero_sec, sub) != 0)
                            goto cleanup;
                        bad_sectors++;
                        chunk_bad++;
                        recovered += sub;
                    }
                    break;
                }

                DWORD secRead = 0;
                BOOL  secOk   = ReadFile(hSrc, sec_buf, secToRead, &secRead, NULL);

                if (secOk && secRead == secToRead) {
                    /* Readable sector */
                    sha256_update(&sha_ctx, sec_buf, secRead);
                    if (dst_put_win(hDst, handle, use_e01,
                                    sec_buf, secRead) != 0)
                        goto cleanup;
                } else {
                    /* Unreadable sector — inject zeros to preserve geometry */
                    sha256_update(&sha_ctx, zero_sec, secToRead);
                    if (dst_put_win(hDst, handle, use_e01,
                                    zero_sec, secToRead) != 0)
                        goto cleanup;
                    bad_sectors++;
                    chunk_bad++;
                }
                recovered += secToRead;
            }
            /* One aggregated warning per recovered chunk */
            if (chunk_bad > 0) {
                printf("{\"type\": \"warning\", \"message\": "
                       "\"Recovered chunk at offset %lld: "
                       "%lu unreadable sector(s)\"}\n",
                       bytesCopied, (unsigned long)chunk_bad);
                fflush(stdout);
            }

            bytesCopied += (long long)toRead;

            /*
             * After recovery the file pointer is at an undefined position.
             * Seek explicitly so the next normal-path ReadFile starts at
             * the correct offset.
             */
            {
                LARGE_INTEGER nextPos;
                nextPos.QuadPart = bytesCopied;
                SetFilePointerEx(hSrc, nextPos, NULL, FILE_BEGIN);
            }

        } else {
            break;  /* ReadFile returned TRUE with 0 bytes: clean EOF */
        }

        chunkIndex++;

        if (chunkIndex % REPORT_INTERVAL == 0) {
            /* progress tick with a live rolling SHA-256 of bytes-so-far */
            emit_progress(&sha_ctx, bytesCopied, totalBytes);
        }
    }

    /* ── Finalise the E01 container (writes tables + hash sections) ──────── */
    if (use_e01) {
        if (ewf_finalize(handle) != 0)
            goto cleanup;
    }

    /* ── Finalise SHA-256 ────────────────────────────────────────────────── */
    sha256_final(&sha_ctx, sha_hash);
    bytes_to_hex(sha_hash, SHA256_DIGEST_SIZE, sha_hex);

    printf("{\"type\": \"progress\", "
           "\"bytes_copied\": %lld, \"total_bytes\": %lld}\n",
           bytesCopied, totalBytes);
    fflush(stdout);

    /* ── Write chain-of-custody audit log ───────────────────────────────── */
    if (write_report(report_path, src, dst, bytesCopied, sha_hex, bad_sectors,
                     case_no, evidence_no, examiner, notes) == 0) {
        json_escape_path(report_path, report_esc, sizeof(report_esc));
        printf("{\"type\": \"complete\", \"status\": \"success\", "
               "\"bytes_copied\": %lld, \"sha256\": \"%s\", "
               "\"bad_sectors\": %lld, \"report\": \"%s\"}\n",
               bytesCopied, sha_hex, bad_sectors, report_esc);
    } else {
        /* Report write failed — still send complete, just without report path */
        printf("{\"type\": \"complete\", \"status\": \"success\", "
               "\"bytes_copied\": %lld, \"sha256\": \"%s\", "
               "\"bad_sectors\": %lld}\n",
               bytesCopied, sha_hex, bad_sectors);
    }
    fflush(stdout);

    result = 0;

cleanup:
    free(buf);
    ewf_close_free(&handle);
    if (hSrc != INVALID_HANDLE_VALUE) CloseHandle(hSrc);
    if (hDst != INVALID_HANDLE_VALUE) CloseHandle(hDst);
    if (result != 0) {
        printf("{\"type\": \"complete\", \"status\": \"error\", "
               "\"bad_sectors\": %lld}\n", bad_sectors);
        fflush(stdout);
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Linux Implementation
 * ═══════════════════════════════════════════════════════════════════════════ */
#elif defined(__linux__)

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

static long long linux_drive_size(int fd)
{
    unsigned long long sz = 0;
    if (ioctl(fd, BLKGETSIZE64, &sz) == 0)
        return (long long)sz;
    off_t end = lseek(fd, 0, SEEK_END);
    if (end != (off_t)-1) {
        lseek(fd, 0, SEEK_SET);
        return (long long)end;
    }
    return -1LL;
}

/* Unified destination write: raw DD (write) or E01 (libewf).
 * Returns 0 on success, -1 on failure. */
static int dst_put_lnx(int fd, libewf_handle_t *handle, int use_e01,
                       const unsigned char *data, size_t len)
{
    if (use_e01)
        return ewf_write(handle, data, len);
    return (write(fd, data, len) == (ssize_t)len) ? 0 : -1;
}

int image_drive(const char *src, const char *dst,
                const char *fmt, const char *compression,
                const char *case_no, const char *evidence_no,
                const char *examiner, const char *notes)
{
    int             fdSrc       = -1, fdDst = -1;   /* fdDst: DD only */
    libewf_handle_t *handle     = NULL;             /* E01 only */
    unsigned char  *buf         = NULL;
    int             use_e01     = fmt_is_e01(fmt);
    int8_t          comp_level  = ewf_compression_level(compression);
    long long       totalBytes  = 0;
    long long       bytesCopied = 0;
    long long       chunkIndex  = 0;
    long long       bad_sectors = 0;
    int             result      = 1;

    unsigned char sec_buf[SECTOR_SIZE];
    unsigned char zero_sec[SECTOR_SIZE];

    sha256_ctx sha_ctx;
    uint8_t    sha_hash[SHA256_DIGEST_SIZE];
    char       sha_hex[SHA256_DIGEST_SIZE * 2 + 1];

    char report_path[REPORT_PATH_MAX];
    char report_esc [REPORT_PATH_MAX * 2];

    memset(zero_sec, 0x00, SECTOR_SIZE);
    snprintf(report_path, sizeof(report_path), "%s.txt", dst);

    /* ── Open source ────────────────────────────────────────────────────── */
    fdSrc = open(src, O_RDONLY | O_LARGEFILE);
    if (fdSrc < 0) {
        fprintf(stderr, "Cannot open source '%s': %s\n", src, strerror(errno));
        fprintf(stderr, "Re-run as root (sudo) for raw device access.\n");
        goto cleanup;
    }

    totalBytes = linux_drive_size(fdSrc);
    if (totalBytes <= 0) {
        fprintf(stderr, "Cannot determine size of '%s'\n", src);
        goto cleanup;
    }

    /* ── Open / create destination ──────────────────────────────────────── */
    if (use_e01) {
        /* libewf owns the destination file(s) and appends ".E01" itself, so
         * strip any extension the caller supplied to avoid "name.E01.E01". */
        char ewf_target[REPORT_PATH_MAX];
        ewf_basename(dst, ewf_target, sizeof(ewf_target));
        if (ewf_open_for_write(&handle, ewf_target, totalBytes, comp_level,
                               case_no, evidence_no, examiner, notes) != 0)
            goto cleanup;
        fprintf(stderr,
                "E01 mode (libewf EnCase6): compression level %d -> %s.E01\n",
                (int)comp_level, ewf_target);
    } else {
        fdDst = open(dst,
                     O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
                     (mode_t)0644);
        if (fdDst < 0) {
            fprintf(stderr, "Cannot create destination '%s': %s\n",
                    dst, strerror(errno));
            goto cleanup;
        }
    }

    buf = (unsigned char *)malloc(CHUNK_SIZE);
    if (!buf) {
        fprintf(stderr, "malloc(%d) failed\n", CHUNK_SIZE);
        goto cleanup;
    }

    sha256_init(&sha_ctx);

    printf("{\"type\": \"progress\", \"bytes_copied\": 0, \"total_bytes\": %lld}\n",
           totalBytes);
    fflush(stdout);

    /* ════════════════════════════════════════════════════════════════════
     * Copy loop
     * ════════════════════════════════════════════════════════════════════ */
    while (bytesCopied < totalBytes) {
        long long remaining = totalBytes - bytesCopied;
        size_t  toRead = (remaining >= (long long)CHUNK_SIZE)
                             ? (size_t)CHUNK_SIZE
                             : (size_t)remaining;

        ssize_t bytesRead    = read(fdSrc, buf, toRead);
        ssize_t bytesWritten = 0;

        if (bytesRead > 0) {
            /* ── Fast path ──────────────────────────────────────────── */
            /* SHA-256 always covers the SOURCE bytes (uncompressed). */
            sha256_update(&sha_ctx, buf, (size_t)bytesRead);
            if (use_e01) {
                /* libewf handles 32 KiB chunking, Adler-32 and CRC math. */
                if (ewf_write(handle, buf, (size_t)bytesRead) != 0) {
                    fprintf(stderr, "E01 write failed at offset %lld\n",
                            bytesCopied);
                    goto cleanup;
                }
            } else {
                /* Golden Master DD path — byte-for-byte, untouched */
                bytesWritten = write(fdDst, buf, (size_t)bytesRead);
                if (bytesWritten != bytesRead) {
                    fprintf(stderr, "write() failed at offset %lld: %s\n",
                            bytesCopied, strerror(errno));
                    goto cleanup;
                }
            }
            bytesCopied += bytesRead;

        } else if (bytesRead == 0) {
            break;  /* EOF */

        } else {
            /* ── Recovery path: sector-by-sector ───────────────────── */
            fprintf(stderr,
                    "read() error at offset %lld (%s), "
                    "entering sector recovery\n",
                    bytesCopied, strerror(errno));

            /* One aggregated warning per recovered chunk — not per sector. */
            size_t chunk_bad = 0;
            size_t recovered = 0;
            while (recovered < toRead) {
                size_t secToRead = (SECTOR_SIZE <= toRead - recovered)
                                       ? (size_t)SECTOR_SIZE
                                       : (toRead - recovered);
                off_t  seekOff   = (off_t)(bytesCopied + (long long)recovered);

                if (lseek(fdSrc, seekOff, SEEK_SET) == (off_t)-1) {
                    /*
                     * Seek failed — declare remaining sectors in this chunk
                     * as bad and break out of inner loop.
                     */
                    fprintf(stderr, "lseek failed at offset %lld: %s\n",
                            (long long)seekOff, strerror(errno));
                    while (recovered < toRead) {
                        size_t sub = (SECTOR_SIZE <= toRead - recovered)
                                         ? (size_t)SECTOR_SIZE
                                         : (toRead - recovered);
                        sha256_update(&sha_ctx, zero_sec, sub);
                        if (dst_put_lnx(fdDst, handle, use_e01,
                                        zero_sec, sub) != 0)
                            goto cleanup;
                        bad_sectors++;
                        chunk_bad++;
                        recovered += sub;
                    }
                    break;
                }

                ssize_t secRead = read(fdSrc, sec_buf, secToRead);

                if (secRead == (ssize_t)secToRead) {
                    sha256_update(&sha_ctx, sec_buf, (size_t)secRead);
                    if (dst_put_lnx(fdDst, handle, use_e01,
                                    sec_buf, (size_t)secRead) != 0)
                        goto cleanup;
                } else {
                    sha256_update(&sha_ctx, zero_sec, secToRead);
                    if (dst_put_lnx(fdDst, handle, use_e01,
                                    zero_sec, secToRead) != 0)
                        goto cleanup;
                    bad_sectors++;
                    chunk_bad++;
                }
                recovered += secToRead;
            }
            /* One aggregated warning per recovered chunk */
            if (chunk_bad > 0) {
                printf("{\"type\": \"warning\", \"message\": "
                       "\"Recovered chunk at offset %lld: "
                       "%zu unreadable sector(s)\"}\n",
                       bytesCopied, chunk_bad);
                fflush(stdout);
            }

            bytesCopied += (long long)toRead;

            /* Reset file offset for the next main-loop chunk */
            lseek(fdSrc, (off_t)bytesCopied, SEEK_SET);
        }

        chunkIndex++;

        if (chunkIndex % REPORT_INTERVAL == 0) {
            /* progress tick with a live rolling SHA-256 of bytes-so-far */
            emit_progress(&sha_ctx, bytesCopied, totalBytes);
        }
    }

    /* ── Finalise the E01 container (writes tables + hash sections) ──────── */
    if (use_e01) {
        if (ewf_finalize(handle) != 0)
            goto cleanup;
    }

    /* ── Finalise SHA-256 ────────────────────────────────────────────────── */
    sha256_final(&sha_ctx, sha_hash);
    bytes_to_hex(sha_hash, SHA256_DIGEST_SIZE, sha_hex);

    printf("{\"type\": \"progress\", "
           "\"bytes_copied\": %lld, \"total_bytes\": %lld}\n",
           bytesCopied, totalBytes);
    fflush(stdout);

    /* ── Write chain-of-custody audit log ───────────────────────────────── */
    if (write_report(report_path, src, dst, bytesCopied, sha_hex, bad_sectors,
                     case_no, evidence_no, examiner, notes) == 0) {
        json_escape_path(report_path, report_esc, sizeof(report_esc));
        printf("{\"type\": \"complete\", \"status\": \"success\", "
               "\"bytes_copied\": %lld, \"sha256\": \"%s\", "
               "\"bad_sectors\": %lld, \"report\": \"%s\"}\n",
               bytesCopied, sha_hex, bad_sectors, report_esc);
    } else {
        printf("{\"type\": \"complete\", \"status\": \"success\", "
               "\"bytes_copied\": %lld, \"sha256\": \"%s\", "
               "\"bad_sectors\": %lld}\n",
               bytesCopied, sha_hex, bad_sectors);
    }
    fflush(stdout);

    result = 0;

cleanup:
    free(buf);
    ewf_close_free(&handle);
    if (fdSrc >= 0) close(fdSrc);
    if (fdDst >= 0) close(fdDst);
    if (result != 0) {
        printf("{\"type\": \"complete\", \"status\": \"error\", "
               "\"bad_sectors\": %lld}\n", bad_sectors);
        fflush(stdout);
    }
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Unsupported Platform
 * ═══════════════════════════════════════════════════════════════════════════ */
#else
#  error "imager.c supports Windows (_WIN32) and Linux (__linux__) only."
#endif
