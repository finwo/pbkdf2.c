#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "src/pbkdf2.h"

int passed = 0;
int failed = 0;

static void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

static int compare_hex(const uint8_t *data, const char *expected, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned int val;
    if (sscanf(expected + i * 2, "%2x", &val) != 1) return 0;
    if (data[i] != val) return 0;
  }
  return 1;
}

void test_sha1(void) {
  struct sha1_ctx ctx;
  uint8_t hash[20];

  printf("SHA-1 Tests\n");
  printf("-----------\n");

  sha1_init(&ctx);
  sha1_update(&ctx, (uint8_t *)"abc", 3);
  sha1_final(&ctx, hash);
  printf("  SHA1(abc): ");
  if (compare_hex(hash, "a9993e364706816aba3e25717850c26c9cd0d89d", 20)) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n    Expected: a9993e364706816aba3e25717850c26c9cd0d89d\n    Got:      ");
    print_hex(hash, 20);
    printf("\n");
    failed++;
  }

  sha1_init(&ctx);
  sha1_final(&ctx, hash);
  printf("  SHA1(empty): ");
  if (compare_hex(hash, "da39a3ee5e6b4b0d3255bfef95601890afd80709", 20)) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n");
    failed++;
  }

  sha1_init(&ctx);
  sha1_update(&ctx, (uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
  sha1_final(&ctx, hash);
  printf("  SHA1(long): ");
  if (compare_hex(hash, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", 20)) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n");
    failed++;
  }
}

void test_sha256(void) {
  struct sha256_ctx ctx;
  uint8_t hash[32];

  printf("\nSHA-256 Tests\n");
  printf("-------------\n");

  sha256_init(&ctx);
  sha256_update(&ctx, (uint8_t *)"abc", 3);
  sha256_final(&ctx, hash);
  printf("  SHA256(abc): ");
  if (compare_hex(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32)) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n");
    failed++;
  }

  sha256_init(&ctx);
  sha256_final(&ctx, hash);
  printf("  SHA256(empty): ");
  if (compare_hex(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32)) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n");
    failed++;
  }
}

void test_hmac_sha1(void) {
  uint8_t hash[20];
  uint8_t openssl_hash[20];
  unsigned int len;

  printf("\nHMAC-SHA1 Tests\n");
  printf("---------------\n");

  const uint8_t key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b
  };
  const uint8_t data[] = "Hi There";

  HMAC(EVP_sha1(), key, 20, data, 8, openssl_hash, &len);
  hmac_sha1(key, 20, data, 8, hash);

  printf("  HMAC-SHA1 (vs OpenSSL): ");
  if (memcmp(hash, openssl_hash, 20) == 0) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n    OpenSSL: ");
    print_hex(openssl_hash, 20);
    printf("\n    Ours:   ");
    print_hex(hash, 20);
    printf("\n");
    failed++;
  }

  const uint8_t key2[] = "key";
  const uint8_t data2[] = "The quick brown fox jumps over the lazy dog";

  HMAC(EVP_sha1(), key2, 3, data2, 43, openssl_hash, &len);
  hmac_sha1(key2, 3, data2, 43, hash);

  printf("  HMAC-SHA1 (short key): ");
  if (memcmp(hash, openssl_hash, 20) == 0) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n");
    failed++;
  }
}

void test_hmac_sha256(void) {
  uint8_t hash[32];
  uint8_t openssl_hash[32];
  unsigned int len;

  printf("\nHMAC-SHA256 Tests\n");
  printf("-----------------\n");

  const uint8_t key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b
  };
  const uint8_t data[] = "Hi There";

  HMAC(EVP_sha256(), key, 20, data, 8, openssl_hash, &len);
  hmac_sha256(key, 20, data, 8, hash);

  printf("  HMAC-SHA256 (vs OpenSSL): ");
  if (memcmp(hash, openssl_hash, 32) == 0) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n    OpenSSL: ");
    print_hex(openssl_hash, 32);
    printf("\n    Ours:   ");
    print_hex(hash, 32);
    printf("\n");
    failed++;
  }
}

void test_pbkdf2(void) {
  uint8_t output[128];
  uint8_t openssl_output[128];

  printf("\nPBKDF2 Tests (vs OpenSSL)\n");
  printf("-------------------------\n");

  const char *password = "password";
  const char *salt = "salt";
  uint64_t iterations = 4096;

  /* PBKDF2-SHA1 */
  PKCS5_PBKDF2_HMAC(password, 8, (unsigned char *)salt, 4, iterations, EVP_sha1(), 20, openssl_output);
  pbkdf2((uint8_t *)password, 8, (uint8_t *)salt, 4, iterations, PBKDF2_SHA1, output, 20);

  printf("  PBKDF2-SHA1 (c=4096, dkLen=20): ");
  if (memcmp(output, openssl_output, 20) == 0) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n    OpenSSL: ");
    print_hex(openssl_output, 20);
    printf("\n    Ours:   ");
    print_hex(output, 20);
    printf("\n");
    failed++;
  }

  /* PBKDF2-SHA256 */
  PKCS5_PBKDF2_HMAC(password, 8, (unsigned char *)salt, 4, iterations, EVP_sha256(), 32, openssl_output);
  pbkdf2((uint8_t *)password, 8, (uint8_t *)salt, 4, iterations, PBKDF2_SHA256, output, 32);

  printf("  PBKDF2-SHA256 (c=4096, dkLen=32): ");
  if (memcmp(output, openssl_output, 32) == 0) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n    OpenSSL: ");
    print_hex(openssl_output, 32);
    printf("\n    Ours:   ");
    print_hex(output, 32);
    printf("\n");
    failed++;
  }

  /* Longer output (block chaining) */
  const char *password2 = "passwordPASSWORD";
  const char *salt2 = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
  size_t dk_len = 25;

  PKCS5_PBKDF2_HMAC(password2, 16, (unsigned char *)salt2, 36, iterations, EVP_sha1(), dk_len, openssl_output);
  pbkdf2((uint8_t *)password2, 16, (uint8_t *)salt2, 36, iterations, PBKDF2_SHA1, output, dk_len);

  printf("  PBKDF2-SHA1 (dkLen=25, chaining): ");
  if (memcmp(output, openssl_output, dk_len) == 0) {
    printf("PASSED\n");
    passed++;
  } else {
    printf("FAILED\n    OpenSSL: ");
    print_hex(openssl_output, dk_len);
    printf("\n    Ours:   ");
    print_hex(output, dk_len);
    printf("\n");
    failed++;
  }
}

int main() {
  printf("\n========================================\n");
  printf("    PBKDF2 Library Test Suite\n");
  printf("========================================\n\n");

  test_sha1();
  test_sha256();
  test_hmac_sha1();
  test_hmac_sha256();
  test_pbkdf2();

  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", passed, failed);
  printf("========================================\n");

  return failed > 0 ? 1 : 0;
}
