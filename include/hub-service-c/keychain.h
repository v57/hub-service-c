#ifndef HUB_SERVICE_C_KEYCHAIN_H
#define HUB_SERVICE_C_KEYCHAIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * hub-server auth keychain (TS hub-service/keychain.ts parity,
 * Docs/Devices/protocol.md section 2).
 *
 * The key file ("auth" in the working directory, or $HUBKEY) is the base64
 * encoding of the 48-byte PKCS8 DER ed25519 private key followed by the
 * 44-byte SPKI DER public key (92 bytes, 124 base64 chars).
 *
 * A signed token has the shape  key.<pub>.<sig>.<expiry>.<nonce>  where
 *   pub     = base64 of the 44-byte SPKI public key (bytes 48..92)
 *   nonce   = the challenge the hub answered in hub/info
 *   sig     = base64 ed25519 signature over
 *               "hub1:<hub SPKI>:<nonce>:<expiry>" (one connection to one hub)
 *   expiry  = DECIMAL epoch-seconds string of now + 30; hub-server rejects it
 *             once 30 s past or more than 90 s ahead
 *
 * Hub key pins live in "hubs.json" beside the key file:
 * {"<address>": "<hub SPKI>"}.
 *
 * Return 0 on success, -1 on error. Out buffers are always NUL-terminated
 * on success and set to "" on failure.
 */

/* Seconds a fresh token stays valid: a token is for one connect, and hubs
 * accept at most 60 s. */
#define HUB_SERVICE_AUTH_EXPIRY 30

/* Write a fresh token for one connection to the hub with key hub_key, over the
 * challenge it answered in hub/info, into out. */
int hub_service_keychain_sign_for_hub(const char *hub_key, const char *nonce, char *out, size_t out_size);

/* Token for an explicit key file text, hub challenge and expiry (for tests and
 * tools). */
int hub_service_auth_token(const char *key_file, const char *hub_key, const char *nonce, long long expiry, char *out,
                           size_t out_size);

/* Write the base64 signature of the service key over data (the hub-net
 * agent's challenge nonce, for example). */
int hub_service_keychain_sign_data(const char *data, char *out, size_t out_size);

/* Write the service's public key (base64 of the 44-byte SPKI DER). */
int hub_service_keychain_public_key(char *out, size_t out_size);

/* Override the key file path (default "auth", or $HUBKEY). */
void hub_service_keychain_set_path(const char *path);

/* The hub key pinned for address; -1 (and "") when none is pinned. */
int hub_service_keychain_hub_key(const char *address, char *out, size_t out_size);

/* Pin hub_key for address (replaces an earlier pin). */
int hub_service_keychain_pin_hub_key(const char *address, const char *hub_key);

/* Remove the pin for address: the next connect pins what the hub proves. */
int hub_service_keychain_forget_hub_key(const char *address);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SERVICE_C_KEYCHAIN_H */
