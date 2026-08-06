#ifndef HUB_SERVICE_C_KEYCHAIN_H
#define HUB_SERVICE_C_KEYCHAIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * hub-pro auth keychain (TS hub-service/keychain.ts parity).
 *
 * The key file ("auth" in the working directory, or $HUBKEY) is the base64
 * encoding of the 48-byte PKCS8 DER ed25519 private key followed by the
 * 44-byte SPKI DER public key (92 bytes, 124 base64 chars).
 *
 * A signed token has the shape  key.<pub>.<sig>.<expiry>  where
 *   pub     = base64 of the 44-byte SPKI public key (bytes 48..92)
 *   sig     = base64 ed25519 signature over the expiry string
 *   expiry  = DECIMAL epoch-seconds string of now + 10 (TS parity)
 *
 * Return 0 on success, -1 on error. Out buffers are always NUL-terminated
 * on success and set to "" on failure.
 */

/* Write a fresh auth token ("key.<pub>.<sig>.<expiry>") into out. */
int hub_service_keychain_sign(char *out, size_t out_size);

/* Write the service's public key (base64 of the 44-byte SPKI DER). */
int hub_service_keychain_public_key(char *out, size_t out_size);

/*
 * Write "?auth=<urlencoded token>&v=0" into out — for appending to the
 * ws:// URL when the channel client cannot send real headers (channel-c
 * takes a URL; the hub reads query params as headers and decodes them).
 */
int hub_service_keychain_auth_query(char *out, size_t out_size);

/* Override the key file path (default "auth", or $HUBKEY). */
void hub_service_keychain_set_path(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SERVICE_C_KEYCHAIN_H */
