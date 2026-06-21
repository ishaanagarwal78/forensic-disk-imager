#ifndef IMAGER_H
#define IMAGER_H

/*
 * image_drive(src, dst, fmt, compression)
 *
 * Reads every byte of the block device / physical drive at `src` and writes
 * an image to the regular file `dst`.
 *
 *   fmt          "DD"  → raw byte-for-byte image (Golden Master path, default)
 *                "E01" → true EnCase Expert Witness Format via libewf
 *   compression  "0"|"1".."9" — mapped to libewf levels for E01
 *                (0 → NONE, 1 → FAST, 9 → BEST).  Ignored for DD.
 *                Either argument may be NULL → defaults ("DD","0").
 *
 * IMPORTANT: in BOTH formats the streamed SHA-256 is computed over the
 * *source* bytes (uncompressed), so the hash always verifies against the
 * original drive regardless of on-disk compression.  (This is independent of
 * the MD5/SHA-1 that libewf stores inside the E01 container itself.)
 *
 * The "E01" output is a real, spec-compliant EnCase EWF file produced by
 * libewf (format LIBEWF_FORMAT_ENCASE6): libewf owns the volume header,
 * 32 KiB chunking, Adler-32 chunk checksums, offset table/table2 and the
 * hash sections.  Requires linking against libewf (-lewf).
 *
 * Progress is streamed to stdout as newline-terminated JSON objects:
 *
 *   {"type": "progress",  "bytes_copied": N,  "total_bytes": T}
 *   {"type": "complete",  "status": "success", "bytes_copied": N, ...}
 *   {"type": "complete",  "status": "error"}
 *
 * stdout is flushed after every JSON write so the Python frontend sees
 * each message immediately without waiting for the buffer to fill.
 *
 * All human-readable diagnostics (OS error codes, advisory text) are
 * sent exclusively to stderr.
 *
 * case_no / evidence_no / examiner / notes are chain-of-custody metadata
 * embedded in the EWF header for E01 output (ignored for DD).  Any may be
 * NULL or "" to skip that field.
 *
 * Returns 0 on success, non-zero on failure.
 */
int image_drive(const char *src, const char *dst,
                const char *fmt, const char *compression,
                const char *case_no, const char *evidence_no,
                const char *examiner, const char *notes);

/*
 * verify_e01(e01_path, expected_sha256)
 *
 * Re-reads an E01 evidence set through libewf, recomputes the SHA-256 of the
 * decoded media stream and compares it to expected_sha256 (the acquisition
 * hash).  Streams {"type":"progress",...} lines and a final
 * {"type":"complete","verified":bool,"computed_sha256":...} message.
 * Returns 0 if verified, 1 on mismatch, 2 on error.
 */
int verify_e01(const char *e01_path, const char *expected_sha256);

#endif /* IMAGER_H */
