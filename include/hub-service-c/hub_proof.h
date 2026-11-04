#ifndef HUB_SERVICE_C_HUB_PROOF_H
#define HUB_SERVICE_C_HUB_PROOF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Auth v2's client side (Docs/Devices/protocol.md section 2): before every
 * connect the SDK asks hub/info on an anonymous connection with a fresh nonce,
 * and sends its token only if the hub proved the key it claims, over that nonce.
 */

/* How a connection to an address travels. */
typedef enum {
  HUB_SERVICE_TRANSPORT_ENCRYPTED,
  HUB_SERVICE_TRANSPORT_LOOPBACK,
  HUB_SERVICE_TRANSPORT_OVERLAY,
  HUB_SERVICE_TRANSPORT_LOCAL_NETWORK,
  /* Plain ws:// beyond loopback, the overlay and the LAN: it isn't dialed
   * unless allow_plaintext says so. */
  HUB_SERVICE_TRANSPORT_REFUSED
} hub_service_transport_t;

/* Classifies an address before anything is dialed. A bare port is loopback,
 * and a host:port without a scheme reads as ws://. */
hub_service_transport_t hub_service_transport_of(const char *address);

/* The protocol's name of a class ("localNetwork", ...). */
const char *hub_service_transport_name(hub_service_transport_t transport);

/* The nonce for one hub/info: 32 fresh random bytes in base64url. malloc'd. */
char *hub_service_make_client_nonce(void);

/* The string a hub/info proof signs: "hubinfo1:<hub key>:<nonce>". malloc'd. */
char *hub_service_hub_info_signed_data(const char *hub_key, const char *nonce);

/* An answer to hub/info with a nonce. */
typedef struct {
  char key[128];
  char proof[128];
  char challenge[129];
} hub_service_hub_info_t;

/* Reads key, proof and challenge from a hub/info answer. 0 when all three are
 * strings and the challenge is what the protocol allows (base64url characters,
 * at most 128: it goes into a header). */
int hub_service_hub_info_parse(const char *json, hub_service_hub_info_t *out);

/* 1 when the answer proves its key over nonce. A relayed answer passes too, so
 * it never decides which credentials a hub gets. */
int hub_service_hub_info_proves(const hub_service_hub_info_t *info, const char *nonce);

/* Asks the hub at address for its key and a challenge on a short anonymous
 * connection, with a channel of its own, so it serves none of the service's
 * handlers. 0 only with a valid proof; otherwise -1 with *out_error set when
 * out_error is non-NULL (free with channel_c_free). */
int hub_service_ask_hub(const char *address, hub_service_hub_info_t *out, char **out_error);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SERVICE_C_HUB_PROOF_H */
