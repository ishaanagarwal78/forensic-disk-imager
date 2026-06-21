/*
 * sha1.c — Portable, dependency-free SHA-1 (FIPS 180-4).
 * Public-domain style streaming implementation.
 */
#include "sha1.h"
#include <string.h>

#define ROL32(v, b) (((v) << (b)) | ((v) >> (32 - (b))))

static void sha1_transform(uint32_t state[5], const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, tmp;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4]     << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] <<  8)
             | ((uint32_t)block[i * 4 + 3]);
    for (i = 16; i < 80; i++)
        w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & c) | ((~b) & d);        k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                    k = 0xCA62C1D6; }
        tmp = ROL32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL32(b, 30); b = a; a = tmp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void sha1_init(sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->bit_count = 0;
    ctx->buf_len   = 0;
}

void sha1_update(sha1_ctx *ctx, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    ctx->bit_count += (uint64_t)len * 8;
    while (len > 0) {
        size_t n = SHA1_BLOCK_SIZE - ctx->buf_len;
        if (n > len) n = len;
        memcpy(ctx->buf + ctx->buf_len, p, n);
        ctx->buf_len += n;
        p += n;
        len -= n;
        if (ctx->buf_len == SHA1_BLOCK_SIZE) {
            sha1_transform(ctx->state, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void sha1_final(sha1_ctx *ctx, uint8_t digest[SHA1_DIGEST_SIZE])
{
    uint64_t bits = ctx->bit_count;     /* captured before padding */
    uint8_t  pad  = 0x80;
    uint8_t  zero = 0x00;
    uint8_t  lenb[8];
    int      i;

    sha1_update(ctx, &pad, 1);
    while (ctx->buf_len != 56)
        sha1_update(ctx, &zero, 1);
    for (i = 0; i < 8; i++)
        lenb[i] = (uint8_t)(bits >> (56 - i * 8));
    sha1_update(ctx, lenb, 8);

    for (i = 0; i < 5; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}
