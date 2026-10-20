#ifndef HUB_SERVICE_C_NETWORK_INTERNAL_H
#define HUB_SERVICE_C_NETWORK_INTERNAL_H

#include "hub-service-c/network.h"

/* A service's declared shares and their publications (network.c). */
typedef struct hs_network hs_network_t;

hs_network_t *hs_network_new(void);
void hs_network_free(hs_network_t *network);
void hs_network_set_socket(hs_network_t *network, const char *path, int timeout_ms);
int hs_network_has_shares(const hs_network_t *network);
char *hs_network_publications(const hs_network_t *network);
int hs_network_declare(hs_network_t *network, const hub_service_share_t *share, char **out_error);
/* Attest every declared share and send them with network/shares/replace. */
int hs_network_republish(hs_network_t *network, channel_c_sender_t *sender, char **out_error);
int hs_network_publish(hs_network_t *network, channel_c_sender_t *sender, const hub_service_share_t *share,
                       char **out_error);
int hs_network_remove(hs_network_t *network, channel_c_sender_t *sender, const char *name, char **out_error);

/* ISO 8601 / RFC 3339 time to Unix milliseconds; -1 when invalid. */
long long hs_parse_iso_ms(const char *text);

#endif /* HUB_SERVICE_C_NETWORK_INTERNAL_H */
