#ifndef HUB_SERVICE_C_DEVICE_H
#define HUB_SERVICE_C_DEVICE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Device key and service certificates (Docs/Devices/protocol.md sections 1
 * and 3).
 *
 * The device key is one ed25519 key per OS instance, in the same file format
 * as the `auth` key. It lives in ~/.hub/device.key (directory 0700, file
 * 0600), /var/lib/hub/device.key for root, or $HUB_DEVICE_KEY, and is
 * created atomically on first use.
 *
 * The device signs a certificate for each service key it runs, sent in the
 * `device` handshake header as  <payload>.<signature>  where payload is the
 * base64url (no padding) of the certificate JSON and the signature is the
 * device key's base64 ed25519 signature over the payload characters.
 *
 * Strings returned as char * are malloc'd; free them with free().
 */

/* Default certificate lifetime (7 days) and the renewal margin (1 day). */
#define HUB_SERVICE_CERTIFICATE_LIFETIME 604800
#define HUB_SERVICE_CERTIFICATE_RENEW 86400

/* Certificate fields, emitted in this order. NULL optional fields are left out. */
typedef struct {
  const char *device;      /* device SPKI; NULL -> taken from the signing key */
  const char *service;     /* service SPKI, the key in `auth` */
  const char *instance;    /* 1-128 bytes, unique per device by convention */
  const char *device_name; /* suggested device name, <= 64 bytes (optional) */
  const char *platform;    /* macos, ios, linux, windows, android, other... (optional) */
  const char *parent;      /* declared parent device name (optional) */
  const char *hub;         /* reserved: hub SPKI for per-hub device keys (optional) */
  long long iat;
  long long exp;
} hub_service_certificate_t;

/* The certificate JSON with no whitespace. */
char *hub_service_certificate_json(const hub_service_certificate_t *certificate);

/* The `device` header value, signed with the key file text device_key_file. */
char *hub_service_certificate_encode(const char *device_key_file, const hub_service_certificate_t *certificate);

/* Override the device key path (NULL restores $HUB_DEVICE_KEY / the default). */
void hub_service_device_set_path(const char *path);

/* The device key path in use. */
int hub_service_device_key_path(char *out, size_t out_size);

/* The device public key (SPKI base64), creating the key file when missing. */
int hub_service_device_public_key(char *out, size_t out_size);

/* Device id: the first 32 lowercase hex characters of SHA-256(SPKI DER). */
int hub_service_device_id(const char *spki, char *out, size_t out_size);

/* Safety code shown when approving a device: "ddd ddd". */
int hub_service_device_safety_code(const char *spki, char *out, size_t out_size);

/* This OS as a certificate platform: macos, ios, linux, windows, android or other. */
const char *hub_service_device_platform(void);

/* The host name without a trailing ".local" (the default device name). */
int hub_service_device_host_name(char *out, size_t out_size);

/*
 * A certificate for service_key signed by the device key file (created when
 * missing), issued at now for HUB_SERVICE_CERTIFICATE_LIFETIME. device_name
 * NULL -> host name; parent may be NULL.
 */
char *hub_service_device_certificate(const char *service_key, const char *instance, const char *device_name,
                                     const char *parent, long long now);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SERVICE_C_DEVICE_H */
