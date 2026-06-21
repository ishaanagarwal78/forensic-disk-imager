/*
 * sha256.h — Portable, dependency-free SHA-256 (FIPS 180-4)
 *
 * A single-file, pure-C implementation that works on any platform with
 * a C99-conformant compiler and <stdint.h>.  No OpenSSL, no CryptoAPI,
 * no system library required.
 *
 * Usage:
 *   sha256_ctx ctx;
 *   sha256_init(&ctx);
 *   sha256_update(&ctx, data, len);   // call any number of times
 *   sha256_final(&ctx, hash);         // hash is uint8_t[SHA256_DIGEST_SIZE]
 */

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE  32   /* 256 bits → 32 bytes                  */
#define SHA256_BLOCK_SIZE   64   /* 512-bit message schedule blocks       */

typedef struct {
    uint32_t state[8];              /* running hash state (H0..H7)        */
    uint64_t bit_count;             /* total bits hashed so far           */
    uint8_t  buf[SHA256_BLOCK_SIZE];/* partial block buffer               */
    size_t   buf_len;               /* bytes currently in buf             */
} sha256_ctx;

void sha256_init  (sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final (sha256_ctx *ctx, uint8_t hash[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */
