/*
 * sha1.h — Portable, dependency-free SHA-1 (FIPS 180-4)
 *
 * Streaming API mirroring sha256.h:
 *   sha1_ctx ctx; sha1_init(&ctx);
 *   sha1_update(&ctx, data, len);   // any number of times
 *   sha1_final(&ctx, digest);       // digest is uint8_t[SHA1_DIGEST_SIZE]
 *
 * NOTE: SHA-1 is used here only as a secondary/compatibility integrity hash
 * alongside SHA-256 (which remains the primary).  No security claim is made.
 */
#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64

typedef struct {
    uint32_t state[5];
    uint64_t bit_count;
    uint8_t  buf[SHA1_BLOCK_SIZE];
    size_t   buf_len;
} sha1_ctx;

void sha1_init  (sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const void *data, size_t len);
void sha1_final (sha1_ctx *ctx, uint8_t digest[SHA1_DIGEST_SIZE]);

#endif /* SHA1_H */
