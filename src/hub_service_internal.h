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

#endif /* HUB_SERVICE_C_INTERNAL_H */
