/*
 * md5.h — Portable, dependency-free MD5 (RFC 1321)
 *
 * Streaming API mirroring sha256.h / sha1.h.  Used only as a secondary
 * compatibility integrity hash alongside SHA-256.  No security claim is made.
 */
#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

#define MD5_DIGEST_SIZE 16
#define MD5_BLOCK_SIZE  64

typedef struct {
    uint32_t a, b, c, d;
    uint64_t bit_count;
    uint8_t  buf[MD5_BLOCK_SIZE];
    size_t   buf_len;
} md5_ctx;

void md5_init  (md5_ctx *ctx);
void md5_update(md5_ctx *ctx, const void *data, size_t len);
void md5_final (md5_ctx *ctx, uint8_t digest[MD5_DIGEST_SIZE]);

#endif /* MD5_H */
