/*
 * sha256.c — Portable, dependency-free SHA-256 (FIPS 180-4)
 *
 * Implements the SHA-256 cryptographic hash function exactly as specified
 * in NIST FIPS 180-4.  No external libraries, no OS-specific APIs.
 *
 * Verified against the NIST test vectors:
 *   SHA256("")         = e3b0c44298fc1c14...
 *   SHA256("abc")      = ba7816bf8f01cfea...
 *   SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
 *                      = 248d6a61d20638b8...
 */

#include "sha256.h"
#include <string.h>

/* ── Round constants K[0..63] ────────────────────────────────────────────────
 * First 32 bits of the fractional parts of the cube roots of the first
 * 64 prime numbers (FIPS 180-4, §4.2.2).                                    */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ── Bit-operation macros (FIPS 180-4, §4.1.2) ──────────────────────────── */
#define ROTR(x, n)   (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x)      (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))   /* Σ0 */
#define SIG1(x)      (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))   /* Σ1 */
#define sig0(x)      (ROTR(x,  7) ^ ROTR(x, 18) ^ ((x) >>  3))   /* σ0 */
#define sig1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))   /* σ1 */

/* ── Core compression function (processes one 512-bit / 64-byte block) ───── */
static void sha256_compress(sha256_ctx *ctx, const uint8_t block[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    int i;

    /* Message schedule: first 16 words from block (big-endian) */
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4    ] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] <<  8)
             | ((uint32_t)block[i * 4 + 3]);
    }
    /* Remaining 48 words extended from the first 16 */
    for (; i < 64; i++)
        w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16];

    /* Initialise working variables from current state */
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    /* 64 rounds */
    for (i = 0; i < 64; i++) {
        t1 = h + SIG1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = SIG0(a) + MAJ(a, b, c);
        h = g;  g = f;  f = e;  e = d + t1;
        d = c;  c = b;  b = a;  a = t1 + t2;
    }

    /* Add compressed chunk to current hash state */
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void sha256_init(sha256_ctx *ctx)
{
    /* Initial hash values H0..H7 — first 32 bits of the fractional parts
     * of the square roots of the first 8 primes (FIPS 180-4, §5.3.3).  */
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bit_count = 0;
    ctx->buf_len   = 0;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *in = (const uint8_t *)data;
    size_t i;

    for (i = 0; i < len; i++) {
        ctx->buf[ctx->buf_len++] = in[i];
        if (ctx->buf_len == SHA256_BLOCK_SIZE) {
            sha256_compress(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
    ctx->bit_count += (uint64_t)len * 8;
}

void sha256_final(sha256_ctx *ctx, uint8_t hash[SHA256_DIGEST_SIZE])
{
    uint64_t bc = ctx->bit_count;   /* capture BEFORE padding modifies anything */
    int i;

    /* Append mandatory 0x80 padding byte */
    ctx->buf[ctx->buf_len++] = 0x80;

    /* If the 0x80 byte just completed a full block, compress it now */
    if (ctx->buf_len == SHA256_BLOCK_SIZE) {
        sha256_compress(ctx, ctx->buf);
        ctx->buf_len = 0;
    }

    /*
     * We need 8 bytes at the end of the final block for the 64-bit length.
     * If there is not enough room (buf_len > 56), pad this block out, compress
     * it, and then start a fresh zero-padded block for the length field.
     */
    if (ctx->buf_len > 56) {
        while (ctx->buf_len < SHA256_BLOCK_SIZE)
            ctx->buf[ctx->buf_len++] = 0x00;
        sha256_compress(ctx, ctx->buf);
        ctx->buf_len = 0;
    }

    /* Zero-pad to the 56-byte mark */
    while (ctx->buf_len < 56)
        ctx->buf[ctx->buf_len++] = 0x00;

    /* Append the original message bit-count as a 64-bit big-endian integer */
    for (i = 0; i < 8; i++)
        ctx->buf[56 + i] = (uint8_t)(bc >> (56 - i * 8));

    sha256_compress(ctx, ctx->buf);

    /* Serialise state to output hash (big-endian 32-bit words) */
    for (i = 0; i < 8; i++) {
        hash[i * 4    ] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]      );
    }
}
