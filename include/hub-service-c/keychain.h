#ifndef HUB_SERVICE_C_KEYCHAIN_H
#define HUB_SERVICE_C_KEYCHAIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * hub-pro auth keychain (TS hub-service/keychain.ts parity,
 * Docs/Devices/protocol.md section 2).
 *
 * The key file ("auth" in the working directory, or $HUBKEY) is the base64
 * encoding of the 48-byte PKCS8 DER ed25519 private key followed by the
 * 44-byte SPKI DER public key (92 bytes, 124 base64 chars).
 *
 * A signed token has the shape  key.<pub>.<sig>.<expiry>  where
 *   pub     = base64 of the 44-byte SPKI public key (bytes 48..92)
 *   sig     = base64 ed25519 signature over
 *               v0: "<expiry>"
 *               v1: "hub1:<hub SPKI>:<expiry>" (only valid on that hub)
 *   expiry  = DECIMAL epoch-seconds string of now + 60; hub-pro rejects it
 *             once 30 s past or more than 330 s ahead
 *
 * Hub key pins live in "hubs.json" beside the key file:
 * {"<address>": "<hub SPKI>"}.
 *
 * Return 0 on success, -1 on error. Out buffers are always NUL-terminated
 * on success and set to "" on failure.
 */

/* Seconds a fresh token stays valid. */
#define HUB_SERVICE_AUTH_EXPIRY 60

/* Write a fresh v0 auth token ("key.<pub>.<sig>.<expiry>") into out. */
int hub_service_keychain_sign(char *out, size_t out_size);

/* Write a fresh token bound to hub_key (v1); hub_key NULL signs v0. */
int hub_service_keychain_sign_for_hub(const char *hub_key, char *out, size_t out_size);

/*
 * Token for an explicit key file text and expiry (for tests and tools).
 * hub_key NULL signs v0, otherwise v1.
 */
int hub_service_auth_token(const char *key_file, const char *hub_key, long long expiry, char *out, size_t out_size);

/* Write the base64 signature of the service key over data (the hub-net
 * agent's challenge nonce, for example). */
int hub_service_keychain_sign_data(const char *data, char *out, size_t out_size);

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

/* The hub key pinned for address; -1 (and "") when none is pinned. */
int hub_service_keychain_hub_key(const char *address, char *out, size_t out_size);

/* Pin hub_key for address (replaces an earlier pin). */
int hub_service_keychain_pin_hub_key(const char *address, const char *hub_key);

/* Remove the pin for address (connects use v0 again until hub/info re-pins). */
int hub_service_keychain_forget_hub_key(const char *address);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SERVICE_C_KEYCHAIN_H */
