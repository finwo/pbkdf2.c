# pbkdf2

Pure C implementation of PBKDF2-HMAC with SHA-1 and SHA-256 support.

## Installation

```sh
dep add finwo/pbkdf2
dep install
```

After that, simply add `include lib/.dep/config.mk` in your makefile and include
the header file by adding `#include "finwo/pbkdf2.h"`.

## Usage

```c
#include "finwo/pbkdf2.h"

uint8_t output[32];
pbkdf2(
  (uint8_t *)"password", 8,      // password
  (uint8_t *)"salt", 4,          // salt
  4096,                          // iterations
  PBKDF2_SHA256,                 // hash algorithm
  output, 32                     // output buffer & length
);
```

## API

### Functions

#### `pbkdf2`

```c
void pbkdf2(
  const uint8_t *password, size_t password_len,
  const uint8_t *salt,     size_t salt_len,
  uint64_t iterations,
  enum pbkdf2_hash hash,
  uint8_t *output, size_t output_len
);
```

Derives a key using PBKDF2-HMAC.

| Parameter | Description |
|-----------|-------------|
| `password` | Password bytes |
| `password_len` | Length of password |
| `salt` | Salt bytes |
| `salt_len` | Length of salt |
| `iterations` | Number of iterations |
| `hash` | Hash algorithm (`PBKDF2_SHA1` or `PBKDF2_SHA256`) |
| `output` | Output buffer |
| `output_len` | Desired output length |

#### `hmac_sha1` / `hmac_sha256`

```c
void hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output);
void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output);
```

Standalone HMAC functions for testing.

#### `sha1_*` / `sha256_*`

```c
void sha1_init(struct sha1_ctx *ctx);
void sha1_update(struct sha1_ctx *ctx, const uint8_t *data, size_t len);
void sha1_final(struct sha1_ctx *ctx, uint8_t *hash);

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(struct sha256_ctx *ctx, uint8_t *hash);
```

Standalone hash functions for testing.

## Testing

```sh
make test
./test
```

## License

This project is licensed under [FPGL](LICENSE.md)
