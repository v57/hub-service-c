#ifndef HUB_SERVICE_C_NETWORK_H
#define HUB_SERVICE_C_NETWORK_H

#include "hub-service-c/hub_service_c.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hub Network share publishing (TS hub-service/network.ts parity): make a
 * local TCP/UDP port reachable through Hub Network.
 *
 * For each share the service asks the local hub-net agent (HTTP over its Unix
 * socket) for a challenge, signs the nonce with the service key, gets an
 * attestation of the local target, and sends the whole declared set to the hub
 * with network/shares/replace. The hub answers with one publication per share
 * (resource id, authority, overlay address and port). Declared shares are
 * published again on every (re)connect.
 */

typedef struct {
  const char *name;        /* stable share name, at most 255 characters */
  const char *protocol;    /* "tcp" or "udp" */
  const char *host;        /* local host, usually "127.0.0.1" or "localhost" */
  int port;                /* local port, 1-65535 */
  const char *policy_json; /* {"mode":"hub"|"private"|"disabled"} or
                            * {"mode":"group","group":...} or {"mode":"keys","keys":[...]};
                            * NULL -> {"mode":"private"} */
} hub_service_share_t;

/* Declare a share before hub_service_start: it is published on connect and
 * on every reconnect. Replaces a share with the same name. */
int hub_service_share(hub_service_t *service, const hub_service_share_t *share, char **out_error);

/* Publish (or update) a share now through the hub. On failure the declared
 * set is left as it was. Errors if the service is not connected. */
int hub_service_publish_share(hub_service_t *service, const hub_service_share_t *share, char **out_error);

/* Remove a published share and publish the remaining set. */
int hub_service_remove_share(hub_service_t *service, const char *name, char **out_error);

/* The current publications as a JSON array of
 * {version, resourceId, authority, providerId, protocol, overlayAddress, port}
 * in share-name order ("[]" before the first publish). malloc'd. */
char *hub_service_share_publications(const hub_service_t *service);

/* The hub-net agent socket (default /var/run/hub-net/agent.sock on macOS,
 * /run/hub-net/agent.sock elsewhere) and its timeout in milliseconds (default 5000). */
void hub_service_set_agent_socket(hub_service_t *service, const char *path, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SERVICE_C_NETWORK_H */
