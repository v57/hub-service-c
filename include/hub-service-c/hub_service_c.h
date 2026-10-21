#ifndef HUB_SERVICE_C_HUB_SERVICE_C_H
#define HUB_SERVICE_C_HUB_SERVICE_C_H

#include <stddef.h>

#include "channel-c/channel_c.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * hub_service_c: lite C port of hub-service (TS reference).
 * Registers post/stream API endpoints and hub apps on a hub (hub-lite/hub-server)
 * and calls API through the hub. Authenticates with the keychain `auth` key
 * (see keychain.h): v0 until hub/info pins the hub key, then v1. Unless
 * disabled, every connect also sends a certificate for the service key signed
 * by the device key (see device.h), renewed when less than a day is left.
 */

typedef struct hub_service hub_service_t;

/* Service options. Zero-initialize; NULL fields are optional. */
typedef struct {
  /* ws:// URL. NULL -> $HUB env, else ws://127.0.0.1:1997. */
  const char *address;
  /* Profile name shown in the hub (optional). */
  const char *name;
  /* Profile icon as a JSON fragment (optional): "{"symbol":..,"text":..}" or "\"symbol\"". */
  const char *icon;
  /* Instance name in the device certificate, unique per device
   * ("s3-local/Backup Disk"). NULL -> $HUB_INSTANCE, else name, else the
   * basename of the working directory, else "service". */
  const char *instance;
  /* Suggested device name in the certificate. NULL -> $HUB_DEVICE_NAME, else
   * the macOS computer name, else the host name. */
  const char *device_name;
  /* Declared parent device name, for containers and VMs. NULL -> $HUB_DEVICE_PARENT. */
  const char *parent;
  /* Non-zero: no device key and no `device` header (a plain key connection).
   * $HUB_DEVICE=0 (or off, false, no) does the same. */
  int disable_device;
  /* A caller-provided device key (key file text) used instead of the device
   * key file, for apps that keep it in their own store. NULL -> the file. */
  const char *device_key;
} hub_service_options_t;

/* Per-path settings for the hub/service/update payload (pro-only wire parity;
 * hub-lite ignores them). Zero-initialize. */
typedef struct {
  /* Emit "permissions". */
  int permissions_set;
  /* Permission group. NULL -> auto-filled with the first path segment. */
  const char *permissions_group;
  /* Permission name. */
  const char *permissions_name;
  /* Emit "allows". */
  int permissions_allows_set;
  int permissions_allows;
  /* Emit "limit". */
  int limit_set;
  int limit;
} hub_service_settings_t;

/* Hub app header (apps always have type "app"). */
typedef struct {
  const char *type; /* "app" */
  const char *name;
  const char *path;
} hub_service_app_header_t;

/* Hub app: header plus a UI body. body is a NULL-terminated array of element
 * JSON strings (plain strings are shorthand text; see hub_service_elem_*).
 * top/bottom/data are optional JSON fragments (NULL -> null / {}). */
typedef struct {
  hub_service_app_header_t header;
  const char **body;
  const char *top;
  const char *bottom;
  const char *data;
} hub_service_app_t;

/* UI action: {path, body?, output?} with body/output as JSON fragments. */
typedef struct {
  const char *path;
  const char *body;
  const char *output;
} hub_service_action_t;

/*
 * Who is calling (Docs/Devices/protocol.md section 4). The hub replaces any
 * client-supplied context.hub, so handlers can trust it. All strings owned.
 */
typedef struct {
  char *key;          /* caller SPKI; NULL for anonymous callers */
  char *device_id;    /* caller's device; NULL unless the connection is device-attached */
  char *device_name;
  char **groups;      /* groups of the key or its device */
  size_t group_count;
  int owner;          /* member of the owners group */
  char *via;          /* merged hub SPKI when the call came through a merged hub, else NULL */
  char *claimed_json; /* the merged hub's own caller (unverified) as JSON, else NULL */
  char *hub_key;      /* the forwarding hub's key (context.hub.hubKey), or NULL */
} hub_service_caller_t;

/*
 * The caller of a request from its context JSON (request->context_json in
 * post and stream handlers). NULL when the context has no hub caller (hub-lite,
 * or a call that didn't come through a hub). Free with hub_service_caller_free.
 */
hub_service_caller_t *hub_service_caller(const char *context_json);
void hub_service_caller_free(hub_service_caller_t *caller);

/*
 * Create a service. options may be NULL.
 * Returns NULL (with *out_error set when non-NULL) on failure.
 */
hub_service_t *hub_service_new(const hub_service_options_t *options, char **out_error);

/* Free a service and all its resources. */
void hub_service_free(hub_service_t *service);

/* The ws:// URL the service dials. */
const char *hub_service_address(const hub_service_t *service);

/* The key of this service's hub key pin: the configured address normalized
 * (see hub_service_normalize_address). */
const char *hub_service_pin_address(const hub_service_t *service);

/*
 * A hub address normalized for hub key pins (protocol.md section 2): a bare
 * port "1997" becomes "ws://localhost:1997"; otherwise the URL as given with
 * the scheme and host lowercased and no trailing slash. malloc'd.
 */
char *hub_service_normalize_address(const char *address);

/* Update the profile (applied on the next connect/reconnect). */
int hub_service_set_name(hub_service_t *service, const char *name);
int hub_service_set_icon(hub_service_t *service, const char *icon_json);

/*
 * Register a request/response API endpoint. handler receives the request and
 * returns the response JSON via *out_body_json. settings may be NULL.
 * Returns the service for chaining.
 */
hub_service_t *hub_service_post(hub_service_t *service, const char *path,
                                channel_c_post_handler_fn handler,
                                const hub_service_settings_t *settings);

/*
 * Register a streaming API endpoint. The handler emits values via
 * request->emitter (channel_c_stream_emit_json). settings may be NULL.
 * Returns the service for chaining.
 */
hub_service_t *hub_service_stream(hub_service_t *service, const char *path,
                                  channel_c_stream_handler_fn handler,
                                  const hub_service_settings_t *settings);

/*
 * Register a hub app: appends the header to the apps list and registers a
 * stream at header.path yielding the AppInterface JSON (all 5 keys).
 * Returns the service for chaining.
 */
hub_service_t *hub_service_app(hub_service_t *service, const hub_service_app_t *app);

/*
 * Connect to the hub. Blocks until connected (or fails; channel-c connect has
 * a ~10s timeout). Returns 0 on success, -1 on failure.
 * On every 0->1 is_connected transition hub_service_poll sends
 * hub/profile/update (if a profile is set) then hub/service/update.
 */
int hub_service_start(hub_service_t *service, char **out_error);

/*
 * Drive the client: polls the websocket, detects connect/disconnect
 * transitions, re-sends profile+service updates on every (re)connect, and
 * redials when the connection drops. Call in a loop (see example/echo.c).
 * On the first connection to a hub with no pinned key it calls hub/info,
 * pins the key and reconnects with a hub-bound (v1) token.
 * Returns -1 when a redial failed (the next poll tries again).
 */
int hub_service_poll(hub_service_t *service);

/* Stop and release the current client connection (poll stays idle until
 * hub_service_start is called again). */
void hub_service_stop(hub_service_t *service);

/*
 * Forget the hub key pinned for this service's address. Use it when a v1
 * connect keeps failing with "invalid signature" because the hub's key
 * changed on purpose; the next connect learns it again.
 */
int hub_service_forget_hub_key(hub_service_t *service);

/* Call an API through the hub. Errors if the service is not started. */
int hub_service_send(hub_service_t *service, const char *path, const char *body_json,
                     char **out_body_json, char **out_error);

/* Open a stream call through the hub. Errors if the service is not started. */
int hub_service_values(hub_service_t *service, const char *path, const char *body_json,
                       channel_c_values_t **out_values, char **out_error);

/*
 * App element helpers (TS app.ts wire shapes). Each returns a malloc'd JSON
 * string; free with channel_c_free(). Optional params may be NULL.
 */

/* Action: {"path":...,"body":...,"output":...} (body/output omitted when NULL). */
char *hub_service_action(const hub_service_action_t *action);

char *hub_service_elem_text(const char *value, const char *secondary);
char *hub_service_elem_progress(const char *value, const char *min, const char *max);
char *hub_service_elem_text_field(const char *value, const char *placeholder, const char *action_json);
char *hub_service_elem_button(const char *title, const char *action_json);
char *hub_service_elem_slider(const char *value, const char *default_value,
                              const char *min, const char *max, const char *step,
                              const char *action_json);
char *hub_service_elem_list(const char *data, const char *content_json);
char *hub_service_elem_picker(const char **options, const char *selected);
char *hub_service_elem_cell(const char *title, const char *subtitle);
char *hub_service_elem_files(const char *value, const char *title, const char *action_json);
char *hub_service_elem_file_operation(const char *format, const char *title, const char *action_json);
char *hub_service_elem_hstack(const char **content, const char *spacing);
char *hub_service_elem_vstack(const char **content, const char *spacing);
char *hub_service_elem_zstack(const char **content);
char *hub_service_elem_spacer(void);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SERVICE_C_HUB_SERVICE_C_H */
