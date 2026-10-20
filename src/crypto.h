#ifndef HUB_SERVICE_C_CRYPTO_H
#define HUB_SERVICE_C_CRYPTO_H

/*
 * Internal crypto and file helpers shared by the keychain and the device key
 * (Docs/Devices/protocol.md section 1).
 *
 * Key file: base64 text of 92 bytes, the 48-byte PKCS8 DER ed25519 private
 * key followed by the 44-byte SPKI DER public key.
 */

#include <stddef.h>
#include <sys/types.h>

#define HS_PRIVATE_DER_LENGTH 48
#define HS_PUBLIC_DER_LENGTH 44
#define HS_KEY_BYTES (HS_PRIVATE_DER_LENGTH + HS_PUBLIC_DER_LENGTH)
/* base64 of the 44-byte SPKI (60 chars) plus NUL */
#define HS_SPKI_B64_SIZE 61
/* base64 of a 64-byte signature (88 chars) plus NUL */
#define HS_SIG_B64_SIZE 89

int hs_b64_encode(const unsigned char *data, size_t len, char *out, size_t out_size);
int hs_b64_decode(const char *in, unsigned char *out, size_t out_size, size_t *decoded);
/* RFC 4648 section 5, no padding. malloc'd. */
char *hs_b64url_encode(const unsigned char *data, size_t len);

/* Parse key file text (trailing whitespace ignored) into 92 bytes. */
int hs_key_parse(const char *text, unsigned char key[HS_KEY_BYTES]);
/* Base64 key file text of 92 bytes (124 chars) into out. */
int hs_key_encode(const unsigned char key[HS_KEY_BYTES], char *out, size_t out_size);
int hs_key_generate(unsigned char key[HS_KEY_BYTES]);
/* base64 SPKI of the key. */
int hs_key_public(const unsigned char key[HS_KEY_BYTES], char out[HS_SPKI_B64_SIZE]);
/* base64 ed25519 signature over data. */
int hs_key_sign(const unsigned char key[HS_KEY_BYTES], const char *data, size_t len, char out[HS_SIG_B64_SIZE]);

/*
 * Load the key file at path. When it is missing and create is set, generate
 * one and write it atomically with the given mode (parent directories are
 * created with mode 0700 when private_dirs is set).
 */
int hs_key_file_load(const char *path, int create, mode_t mode, int private_dirs, unsigned char key[HS_KEY_BYTES]);

/* Lowercase hex of SHA-256(data); out needs 65 bytes. */
int hs_sha256_hex(const unsigned char *data, size_t len, char out[65]);

/* Write data to path through a temp file and rename. */
int hs_write_atomic(const char *path, const char *data, size_t len, mode_t mode);
/* Read a whole file (malloc'd, NUL-terminated); NULL when missing. */
char *hs_read_file(const char *path);
/* Directory part of path ("." when there is none) into out. */
void hs_dirname(const char *path, char *out, size_t out_size);

#endif /* HUB_SERVICE_C_CRYPTO_H */
