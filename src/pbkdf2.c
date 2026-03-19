#include <stdlib.h>
#include <string.h>

#include "pbkdf2.h"

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define SHA1_HASH_SIZE   20
#define SHA256_HASH_SIZE  32

static void sha1_transform(struct sha1_ctx *ctx) {
  uint32_t a, b, c, d, e, m[80], j;

  for (j = 0; j < 16; j++) {
    m[j] = (ctx->buffer[j*4] << 24) | (ctx->buffer[j*4+1] << 16) |
           (ctx->buffer[j*4+2] << 8) | ctx->buffer[j*4+3];
  }
  for ( ; j < 80; j++) {
    m[j] = (m[j-3] ^ m[j-8] ^ m[j-14] ^ m[j-16]);
    m[j] = (m[j] << 1) | (m[j] >> 31);
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  for (j = 0; j < 20; j++) {
    uint32_t t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + 0x5a827999 + m[j];
    e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
  }
  for ( ; j < 40; j++) {
    uint32_t t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + 0x6ed9eba1 + m[j];
    e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
  }
  for ( ; j < 60; j++) {
    uint32_t t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + 0x8f1bbcdc + m[j];
    e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
  }
  for ( ; j < 80; j++) {
    uint32_t t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + 0xca62c1d6 + m[j];
    e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
}

void sha1_init(struct sha1_ctx *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xEFCDAB89;
  ctx->state[2] = 0x98BADCFE;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xC3D2E1F0;
}

void sha1_update(struct sha1_ctx *ctx, const uint8_t *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    ctx->buffer[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha1_transform(ctx);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

void sha1_final(struct sha1_ctx *ctx, uint8_t *hash) {
  size_t i = ctx->datalen;

  ctx->buffer[i++] = 0x80;
  if (i > 56) {
    while (i < 64) ctx->buffer[i++] = 0;
    sha1_transform(ctx);
    memset(ctx->buffer, 0, 56);
  } else {
    while (i < 56) ctx->buffer[i++] = 0;
  }

  ctx->bitlen += ctx->datalen * 8;
  ctx->buffer[63] = (uint8_t)(ctx->bitlen);
  ctx->buffer[62] = (uint8_t)(ctx->bitlen >> 8);
  ctx->buffer[61] = (uint8_t)(ctx->bitlen >> 16);
  ctx->buffer[60] = (uint8_t)(ctx->bitlen >> 24);
  ctx->buffer[59] = (uint8_t)(ctx->bitlen >> 32);
  ctx->buffer[58] = (uint8_t)(ctx->bitlen >> 40);
  ctx->buffer[57] = (uint8_t)(ctx->bitlen >> 48);
  ctx->buffer[56] = (uint8_t)(ctx->bitlen >> 56);
  sha1_transform(ctx);

  for (i = 0; i < 4; i++) {
    hash[i]     = (ctx->state[0] >> (24 - i * 8)) & 0xff;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
  }
}

#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define SHA256_EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SHA256_SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t sha256_k[64] = {
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

static void sha256_transform(struct sha256_ctx *ctx) {
  uint32_t a, b, c, d, e, f, g, h, j, t1, t2, m[64];

  for (j = 0; j < 16; j++) {
    m[j] = (ctx->buffer[j*4] << 24) | (ctx->buffer[j*4+1] << 16) |
           (ctx->buffer[j*4+2] << 8) | ctx->buffer[j*4+3];
  }
  for ( ; j < 64; j++) {
    m[j] = SHA256_SIG1(m[j-2]) + m[j-7] + SHA256_SIG0(m[j-15]) + m[j-16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (j = 0; j < 64; j++) {
    t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g) + sha256_k[j] + m[j];
    t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void sha256_init(struct sha256_ctx *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    ctx->buffer[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256_transform(ctx);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

void sha256_final(struct sha256_ctx *ctx, uint8_t *hash) {
  size_t i = ctx->datalen;

  ctx->buffer[i++] = 0x80;
  if (i > 56) {
    while (i < 64) ctx->buffer[i++] = 0;
    sha256_transform(ctx);
    memset(ctx->buffer, 0, 56);
  } else {
    while (i < 56) ctx->buffer[i++] = 0;
  }

  ctx->bitlen += ctx->datalen * 8;
  ctx->buffer[63] = (uint8_t)(ctx->bitlen);
  ctx->buffer[62] = (uint8_t)(ctx->bitlen >> 8);
  ctx->buffer[61] = (uint8_t)(ctx->bitlen >> 16);
  ctx->buffer[60] = (uint8_t)(ctx->bitlen >> 24);
  ctx->buffer[59] = (uint8_t)(ctx->bitlen >> 32);
  ctx->buffer[58] = (uint8_t)(ctx->bitlen >> 40);
  ctx->buffer[57] = (uint8_t)(ctx->bitlen >> 48);
  ctx->buffer[56] = (uint8_t)(ctx->bitlen >> 56);
  sha256_transform(ctx);

  for (i = 0; i < 4; i++) {
    hash[i]     = (ctx->state[0] >> (24 - i * 8)) & 0xff;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
  }
}

void hmac_sha1(
  const uint8_t *key, size_t key_len,
  const uint8_t *data, size_t data_len,
  uint8_t *output
) {
  uint8_t k_ipad[64], k_opad[64], tk[20];
  struct sha1_ctx ctx;
  size_t i;

  if (key_len > 64) {
    sha1_init(&ctx);
    sha1_update(&ctx, key, key_len);
    sha1_final(&ctx, tk);
    key = tk;
    key_len = 20;
  }

  memset(k_ipad, 0x36, 64);
  memset(k_opad, 0x5c, 64);
  for (i = 0; i < key_len; i++) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }

  sha1_init(&ctx);
  sha1_update(&ctx, k_ipad, 64);
  sha1_update(&ctx, data, data_len);
  sha1_final(&ctx, output);

  sha1_init(&ctx);
  sha1_update(&ctx, k_opad, 64);
  sha1_update(&ctx, output, 20);
  sha1_final(&ctx, output);
}

void hmac_sha256(
  const uint8_t *key, size_t key_len,
  const uint8_t *data, size_t data_len,
  uint8_t *output
) {
  uint8_t k_ipad[64], k_opad[64], tk[32];
  struct sha256_ctx ctx;
  size_t i;

  if (key_len > 64) {
    sha256_init(&ctx);
    sha256_update(&ctx, key, key_len);
    sha256_final(&ctx, tk);
    key = tk;
    key_len = 32;
  }

  memset(k_ipad, 0x36, 64);
  memset(k_opad, 0x5c, 64);
  for (i = 0; i < key_len; i++) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }

  sha256_init(&ctx);
  sha256_update(&ctx, k_ipad, 64);
  sha256_update(&ctx, data, data_len);
  sha256_final(&ctx, output);

  sha256_init(&ctx);
  sha256_update(&ctx, k_opad, 64);
  sha256_update(&ctx, output, 32);
  sha256_final(&ctx, output);
}

void pbkdf2(
  const uint8_t *password, size_t password_len,
  const uint8_t *salt,     size_t salt_len,
  uint64_t iterations,
  enum pbkdf2_hash hash,
  uint8_t *output, size_t output_len
) {
  size_t hash_len = (hash == PBKDF2_SHA1) ? SHA1_HASH_SIZE : SHA256_HASH_SIZE;
  size_t l = (output_len + hash_len - 1) / hash_len;
  size_t r = output_len - (l - 1) * hash_len;

  uint8_t *salt_block = (uint8_t *)malloc(salt_len + 4);
  uint8_t *u = (uint8_t *)malloc(hash_len);
  uint8_t *t = (uint8_t *)malloc(hash_len);
  uint8_t *result = output;
  size_t i, j;

  for (i = 1; i <= l; i++) {
    memcpy(salt_block, salt, salt_len);
    salt_block[salt_len]     = (uint8_t)(i >> 24);
    salt_block[salt_len + 1] = (uint8_t)(i >> 16);
    salt_block[salt_len + 2] = (uint8_t)(i >> 8);
    salt_block[salt_len + 3] = (uint8_t)i;

    if (hash == PBKDF2_SHA1) {
      hmac_sha1(password, password_len, salt_block, salt_len + 4, t);
    } else {
      hmac_sha256(password, password_len, salt_block, salt_len + 4, t);
    }
    memcpy(u, t, hash_len);

    for (j = 1; j < iterations; j++) {
      if (hash == PBKDF2_SHA1) {
        hmac_sha1(password, password_len, u, hash_len, u);
      } else {
        hmac_sha256(password, password_len, u, hash_len, u);
      }
      for (size_t k = 0; k < hash_len; k++) {
        t[k] ^= u[k];
      }
    }

    size_t copy_len = (i == l) ? r : hash_len;
    memcpy(result, t, copy_len);
    result += copy_len;
  }

  free(salt_block);
  free(u);
  free(t);
}
