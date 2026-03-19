#ifndef __FINWO_PBKDF2_H__
#define __FINWO_PBKDF2_H__

#include <stddef.h>
#include <stdint.h>

enum pbkdf2_hash {
  PBKDF2_SHA1,
  PBKDF2_SHA256
};

struct sha1_ctx {
  uint32_t state[5];
  size_t datalen;
  uint64_t bitlen;
  uint8_t buffer[64];
};

struct sha256_ctx {
  uint32_t state[8];
  size_t datalen;
  uint64_t bitlen;
  uint8_t buffer[64];
};

void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const uint8_t *data, size_t len);
void sha1_final(struct sha1_ctx *ctx, uint8_t *hash);

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, uint8_t *hash);

void hmac_sha1(
  const uint8_t *key, size_t key_len,
  const uint8_t *data, size_t data_len,
  uint8_t *output
);

void hmac_sha256(
  const uint8_t *key, size_t key_len,
  const uint8_t *data, size_t data_len,
  uint8_t *output
);

void pbkdf2(
  const uint8_t *password, size_t password_len,
  const uint8_t *salt,     size_t salt_len,
  uint64_t iterations,
  enum pbkdf2_hash hash,
  uint8_t *output, size_t output_len
);

#endif
