#ifndef HUB_SERVICE_C_INTERNAL_H
#define HUB_SERVICE_C_INTERNAL_H

#include "hub-service-c/hub_service_c.h"

/*
 * Internal JSON builders, exposed for unit tests (exact-wire assertions).
 * All return malloc'd strings (free with channel_c_free()).
 */

/* hub/service/update payload: services sorted by path, apps in registration order. */
char *hub_service_build_update_json(const hub_service_t *service);

/* hub/profile/update payload; NULL when neither name nor icon is set. */
char *hub_service_build_profile_json(const hub_service_t *service);

/* AppInterface JSON: {"header":{...},"body":[...],"top":null,"bottom":null,"data":{}} */
char *hub_service_build_app_interface_json(const hub_service_app_t *app);

/* Handshake headers for a connect to the hub with key hub_key, over the
 * challenge it answered: auth, v and, unless device mode is off, device. items
 * point into the struct and the service. */
typedef struct {
  char auth[512];
  char v[2];
  channel_c_header_t items[3];
  size_t count;
} hub_service_connect_headers_t;

int hub_service_build_connect_headers(hub_service_t *service, const char *hub_key, const char *challenge,
                                      hub_service_connect_headers_t *out);
void hub_service_connect_headers_free(hub_service_connect_headers_t *headers);

/* Runs before every connection attempt (protocol.md section 2): asks the hub for
 * its proof, pins a first key, refuses another than the pinned one, and builds
 * the headers for that answer alone. -1 with *out_error set means nothing goes
 * out. */
int hub_service_handshake(hub_service_t *service, hub_service_connect_headers_t *out, char **out_error);

/* The `device` header for a connect at now: the cached certificate, or a new
 * one when there is none or less than HUB_SERVICE_CERTIFICATE_RENEW is left.
 * NULL when device mode is off or the device key is unavailable. */
const char *hub_service_current_certificate(hub_service_t *service, long long now);

#endif /* HUB_SERVICE_C_INTERNAL_H */
