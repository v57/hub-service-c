/*
 * hub_service_c: lite C port of hub-service (TS reference).
 *
 * Registers post/stream API endpoints and hub apps on a hub (hub-lite/hub-pro)
 * and calls API through the hub. No crypto, no auth, no keychain.
 *
 * The channel-c client runs on a poll loop: call hub_service_start once, then
 * hub_service_poll in a loop. On every 0->1 is_connected transition the
 * service re-sends hub/profile/update (if a profile is set) and
 * hub/service/update (hub-lite drops services on disconnect).
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yyjson.h>

#include "hub-service-c/hub_service_c.h"
#include "hub-service-c/keychain.h"

/* ------------------------------------------------------------------ */
/* dynamic string buffer for JSON building                             */
/* ------------------------------------------------------------------ */

typedef struct {
  char *data;
  size_t length;
  size_t capacity;
} strbuf_t;

static void strbuf_init(strbuf_t *buffer) {
  buffer->data = NULL;
  buffer->length = 0;
  buffer->capacity = 0;
}

static int strbuf_reserve(strbuf_t *buffer, size_t extra) {
  size_t required;
  size_t capacity;
  char *resized;

  if (!buffer) return -1;
  required = buffer->length + extra + 1;
  if (required <= buffer->capacity) return 0;

  capacity = buffer->capacity ? buffer->capacity : 64;
  while (capacity < required) capacity *= 2;

  resized = (char *)realloc(buffer->data, capacity);
  if (!resized) return -1;
  buffer->data = resized;
  buffer->capacity = capacity;
  return 0;
}

static int strbuf_append(strbuf_t *buffer, const char *text) {
  size_t length;

  if (!buffer || !text) return -1;
  length = strlen(text);
  if (strbuf_reserve(buffer, length) != 0) return -1;
  memcpy(buffer->data + buffer->length, text, length);
  buffer->length += length;
  buffer->data[buffer->length] = '\0';
  return 0;
}

static int strbuf_appendf(strbuf_t *buffer, const char *format, ...) {
  va_list args;
  va_list copy;
  int written;

  if (!buffer || !format) return -1;

  va_start(args, format);
  va_copy(copy, args);
  written = vsnprintf(NULL, 0, format, copy);
  va_end(copy);
  if (written < 0) {
    va_end(args);
    return -1;
  }
  if (strbuf_reserve(buffer, (size_t)written) != 0) {
    va_end(args);
    return -1;
  }
  (void)vsnprintf(buffer->data + buffer->length, (size_t)written + 1, format, args);
  va_end(args);
  buffer->length += (size_t)written;
  return 0;
}

static char *strbuf_detach(strbuf_t *buffer) {
  char *result;

  if (!buffer) return NULL;
  if (!buffer->data) {
    result = (char *)malloc(1);
    if (result) result[0] = '\0';
    return result;
  }
  result = buffer->data;
  buffer->data = NULL;
  buffer->length = 0;
  buffer->capacity = 0;
  return result;
}

static void strbuf_free(strbuf_t *buffer) {
  if (!buffer) return;
  free(buffer->data);
  buffer->data = NULL;
  buffer->length = 0;
  buffer->capacity = 0;
}

/* ------------------------------------------------------------------ */
/* JSON string escaping                                                */
/* ------------------------------------------------------------------ */

static char *json_escape(const char *text) {
  strbuf_t buffer;
  const unsigned char *p;

  if (!text) return channel_c_strdup("");
  strbuf_init(&buffer);
  for (p = (const unsigned char *)text; *p; p += 1) {
    switch (*p) {
      case '"':
        strbuf_append(&buffer, "\\\"");
        break;
      case '\\':
        strbuf_append(&buffer, "\\\\");
        break;
      case '\b':
        strbuf_append(&buffer, "\\b");
        break;
      case '\f':
        strbuf_append(&buffer, "\\f");
        break;
      case '\n':
        strbuf_append(&buffer, "\\n");
        break;
      case '\r':
        strbuf_append(&buffer, "\\r");
        break;
      case '\t':
        strbuf_append(&buffer, "\\t");
        break;
      default:
        if (*p < 0x20) {
          strbuf_appendf(&buffer, "\\u%04x", (unsigned int)*p);
        } else {
          strbuf_appendf(&buffer, "%c", *p);
        }
        break;
    }
  }
  return strbuf_detach(&buffer);
}

/* ------------------------------------------------------------------ */
/* service state                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
  char *path;
  hub_service_settings_t settings;
} service_path_t;

struct hub_service {
  channel_c_channel_t *channel;
  channel_c_client_t *client;
  char *address; /* ws:// URL */
  char *name;    /* profile name or NULL */
  char *icon;    /* icon JSON fragment or NULL */

  service_path_t *paths;
  size_t paths_count;
  size_t paths_capacity;

  hub_service_app_t *apps; /* array of app copies (header strings owned) */
  size_t apps_count;
  size_t apps_capacity;
  char **app_interfaces; /* prebuilt AppInterface JSON per app (parallel) */

  int was_connected;
};

static int service_add_path(hub_service_t *service, const char *path, const hub_service_settings_t *settings);

/* ------------------------------------------------------------------ */
/* JSON builders (internal, exercised by unit tests)                   */
/* ------------------------------------------------------------------ */

/* Build the hub/service/update payload:
 * {"services":[{path, permissions?, limit?}...],"apps":[{type,name,path}...]}
 * services sorted by path. Returns malloc'd JSON (free with channel_c_free). */
char *hub_service_build_update_json(const hub_service_t *service) {
  strbuf_t buffer;
  const char **sorted;
  size_t index;

  if (!service) return NULL;
  strbuf_init(&buffer);

  sorted = (const char **)calloc(service->paths_count ? service->paths_count : 1, sizeof(const char *));
  if (!sorted) {
    strbuf_free(&buffer);
    return NULL;
  }
  for (index = 0; index < service->paths_count; index += 1) {
    sorted[index] = service->paths[index].path;
  }
  /* insertion sort (small N) */
  for (index = 1; index < service->paths_count; index += 1) {
    const char *key = sorted[index];
    size_t j = index;
    while (j > 0 && strcmp(sorted[j - 1], key) > 0) {
      sorted[j] = sorted[j - 1];
      j -= 1;
    }
    sorted[j] = key;
  }

  strbuf_append(&buffer, "{\"services\":[");
  for (index = 0; index < service->paths_count; index += 1) {
    const char *path = sorted[index];
    const hub_service_settings_t *settings = NULL;
    size_t path_index;
    char *escaped;

    for (path_index = 0; path_index < service->paths_count; path_index += 1) {
      if (strcmp(service->paths[path_index].path, path) == 0) {
        settings = &service->paths[path_index].settings;
        break;
      }
    }

    if (index > 0) strbuf_append(&buffer, ",");
    strbuf_append(&buffer, "{\"path\":");
    escaped = json_escape(path);
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);

    if (settings && settings->permissions_set) {
      const char *group = settings->permissions_group;
      if (!group || !group[0]) {
        /* auto-fill: first path segment */
        const char *slash = strchr(path, '/');
        if (slash) {
          char *segment = (char *)malloc((size_t)(slash - path) + 1);
          if (segment) {
            memcpy(segment, path, (size_t)(slash - path));
            segment[slash - path] = '\0';
            group = segment;
          }
        }
        if (!group || !group[0]) group = path;
      }
      strbuf_append(&buffer, ",\"permissions\":{");
      escaped = json_escape(group);
      strbuf_appendf(&buffer, "\"group\":\"%s\"", escaped ? escaped : "");
      free(escaped);
      if (settings->permissions_name) {
        escaped = json_escape(settings->permissions_name);
        strbuf_appendf(&buffer, ",\"name\":\"%s\"", escaped ? escaped : "");
        free(escaped);
      }
      if (settings->permissions_allows_set) {
        strbuf_appendf(&buffer, ",\"allows\":%s", settings->permissions_allows ? "true" : "false");
      }
      strbuf_append(&buffer, "}");
      if (group != settings->permissions_group && group != path) free((void *)group);
    }
    if (settings && settings->limit_set) {
      strbuf_appendf(&buffer, ",\"limit\":%d", settings->limit);
    }
    strbuf_append(&buffer, "}");
  }
  strbuf_append(&buffer, "],\"apps\":[");
  for (index = 0; index < service->apps_count; index += 1) {
    const hub_service_app_header_t *header = &service->apps[index].header;
    char *escaped;

    if (index > 0) strbuf_append(&buffer, ",");
    strbuf_append(&buffer, "{\"type\":");
    escaped = json_escape(header->type ? header->type : "app");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
    escaped = json_escape(header->name ? header->name : "");
    strbuf_appendf(&buffer, ",\"name\":\"%s\"", escaped ? escaped : "");
    free(escaped);
    escaped = json_escape(header->path ? header->path : "");
    strbuf_appendf(&buffer, ",\"path\":\"%s\"", escaped ? escaped : "");
    free(escaped);
    strbuf_append(&buffer, "}");
  }
  strbuf_append(&buffer, "]}");

  free(sorted);
  return strbuf_detach(&buffer);
}

/* Build the hub/profile/update payload: {"name":...,"icon":...}
 * Returns NULL when neither name nor icon is set. malloc'd otherwise. */
char *hub_service_build_profile_json(const hub_service_t *service) {
  strbuf_t buffer;
  char *escaped;

  if (!service) return NULL;
  if (!service->name && !service->icon) return NULL;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{");
  if (service->name) {
    escaped = json_escape(service->name);
    strbuf_appendf(&buffer, "\"name\":\"%s\"", escaped ? escaped : "");
    free(escaped);
    if (service->icon) strbuf_append(&buffer, ",");
  }
  if (service->icon) {
    strbuf_appendf(&buffer, "\"icon\":%s", service->icon);
  }
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

/* Build the AppInterface JSON for an app (all 5 keys always present):
 * {"header":{type,name,path},"body":[...],"top":null,"bottom":null,"data":{}}
 * body is an array of element JSON strings (plain strings = shorthand text). */
char *hub_service_build_app_interface_json(const hub_service_app_t *app) {
  strbuf_t buffer;
  size_t index;

  if (!app) return NULL;
  strbuf_init(&buffer);

  strbuf_append(&buffer, "{\"header\":{");
  {
    const hub_service_app_header_t *header = &app->header;
    char *escaped = json_escape(header->type ? header->type : "app");
    strbuf_appendf(&buffer, "\"type\":\"%s\"", escaped ? escaped : "");
    free(escaped);
    escaped = json_escape(header->name ? header->name : "");
    strbuf_appendf(&buffer, ",\"name\":\"%s\"", escaped ? escaped : "");
    free(escaped);
    escaped = json_escape(header->path ? header->path : "");
    strbuf_appendf(&buffer, ",\"path\":\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append(&buffer, "},\"body\":[");
  if (app->body) {
    for (index = 0; app->body[index]; index += 1) {
      if (index > 0) strbuf_append(&buffer, ",");
      strbuf_append(&buffer, app->body[index]);
    }
  }
  strbuf_append(&buffer, "],\"top\":");
  if (app->top) strbuf_append(&buffer, app->top);
  else strbuf_append(&buffer, "null");
  strbuf_append(&buffer, ",\"bottom\":");
  if (app->bottom) strbuf_append(&buffer, app->bottom);
  else strbuf_append(&buffer, "null");
  strbuf_append(&buffer, ",\"data\":");
  if (app->data) strbuf_append(&buffer, app->data);
  else strbuf_append(&buffer, "{}");
  strbuf_append(&buffer, "}");

  return strbuf_detach(&buffer);
}

/* ------------------------------------------------------------------ */
/* app stream handler (emits the prebuilt AppInterface once)           */
/* ------------------------------------------------------------------ */

static void app_interface_stream_handler(const channel_c_stream_request_t *request) {
  const char *interface_json;

  if (!request) return;
  interface_json = (const char *)request->user_data;
  if (interface_json && request->emitter) {
    (void)channel_c_stream_emit_json(request->emitter, interface_json);
  }
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */
/* ------------------------------------------------------------------ */

hub_service_t *hub_service_new(const hub_service_options_t *options, char **out_error) {
  hub_service_t *service;
  const char *address = NULL;
  char hub_url[64];

  if (out_error) *out_error = NULL;

  service = (hub_service_t *)calloc(1, sizeof(hub_service_t));
  if (!service) {
    if (out_error) *out_error = channel_c_strdup("internal error");
    return NULL;
  }

  if (options && options->address) {
    address = options->address;
  } else if (getenv("HUB") && getenv("HUB")[0]) {
    /* Accept a bare port number from $HUB (e.g. "1998") and normalize it to a
       ws:// URL — the channel-c client requires a full websocket URL. */
    const char *hub = getenv("HUB");
    bool numeric = hub[0] != '\0';
    for (const char *p = hub; *p; p++) {
      if (*p < '0' || *p > '9') { numeric = false; break; }
    }
    if (numeric) {
      snprintf(hub_url, sizeof(hub_url), "ws://127.0.0.1:%s", hub);
      address = hub_url;
    } else {
      address = hub;
    }
  } else {
    address = "ws://127.0.0.1:1997";
  }
  service->address = channel_c_strdup(address);
  if (!service->address) {
    hub_service_free(service);
    if (out_error) *out_error = channel_c_strdup("internal error");
    return NULL;
  }
  if (options && options->name) service->name = channel_c_strdup(options->name);
  if (options && options->icon) service->icon = channel_c_strdup(options->icon);

  service->channel = channel_c_channel_new();
  if (!service->channel) {
    hub_service_free(service);
    if (out_error) *out_error = channel_c_strdup("internal error");
    return NULL;
  }
  return service;
}

void hub_service_free(hub_service_t *service) {
  size_t index;

  if (!service) return;
  if (service->client) channel_c_client_free(service->client);
  if (service->channel) channel_c_channel_free(service->channel);

  free(service->address);
  free(service->name);
  free(service->icon);

  for (index = 0; index < service->paths_count; index += 1) {
    free(service->paths[index].path);
    free((void *)service->paths[index].settings.permissions_group);
    free((void *)service->paths[index].settings.permissions_name);
  }
  free(service->paths);

  for (index = 0; index < service->apps_count; index += 1) {
    free((void *)service->apps[index].header.type);
    free((void *)service->apps[index].header.name);
    free((void *)service->apps[index].header.path);
    if (service->app_interfaces) channel_c_free(service->app_interfaces[index]);
  }
  free(service->apps);
  free(service->app_interfaces);

  free(service);
}

int hub_service_set_name(hub_service_t *service, const char *name) {
  char *copy;

  if (!service) return -1;
  copy = name ? channel_c_strdup(name) : NULL;
  free(service->name);
  service->name = copy;
  return 0;
}

int hub_service_set_icon(hub_service_t *service, const char *icon_json) {
  char *copy;

  if (!service) return -1;
  copy = icon_json ? channel_c_strdup(icon_json) : NULL;
  free(service->icon);
  service->icon = copy;
  return 0;
}

/* ------------------------------------------------------------------ */
/* registration                                                        */
/* ------------------------------------------------------------------ */

static int service_add_path(hub_service_t *service, const char *path, const hub_service_settings_t *settings) {
  service_path_t *resized;
  size_t capacity;
  size_t index;

  if (!service || !path) return -1;

  for (index = 0; index < service->paths_count; index += 1) {
    if (strcmp(service->paths[index].path, path) == 0) return 0; /* already registered */
  }

  if (service->paths_count == service->paths_capacity) {
    capacity = service->paths_capacity ? service->paths_capacity * 2 : 8;
    resized = (service_path_t *)realloc(service->paths, capacity * sizeof(service_path_t));
    if (!resized) return -1;
    service->paths = resized;
    service->paths_capacity = capacity;
  }

  memset(&service->paths[service->paths_count], 0, sizeof(service_path_t));
  service->paths[service->paths_count].path = channel_c_strdup(path);
  if (!service->paths[service->paths_count].path) return -1;

  if (settings) {
    service->paths[service->paths_count].settings = *settings;
    /* copy owned strings */
    if (settings->permissions_group) {
      service->paths[service->paths_count].settings.permissions_group = channel_c_strdup(settings->permissions_group);
    }
    if (settings->permissions_name) {
      service->paths[service->paths_count].settings.permissions_name = channel_c_strdup(settings->permissions_name);
    }
    /* settings rule: if permissions set and group missing, auto-fill the
     * first path segment (TS/Go parity). */
    if (settings->permissions_set &&
        (!service->paths[service->paths_count].settings.permissions_group ||
         !service->paths[service->paths_count].settings.permissions_group[0])) {
      const char *slash = strchr(path, '/');
      char *segment;
      if (slash) {
        segment = (char *)malloc((size_t)(slash - path) + 1);
        if (segment) {
          memcpy(segment, path, (size_t)(slash - path));
          segment[slash - path] = '\0';
        }
      } else {
        segment = channel_c_strdup(path);
      }
      if (segment) {
        free((void *)service->paths[service->paths_count].settings.permissions_group);
        service->paths[service->paths_count].settings.permissions_group = segment;
      }
    }
  }

  service->paths_count += 1;
  return 0;
}

hub_service_t *hub_service_post(hub_service_t *service, const char *path,
                                channel_c_post_handler_fn handler,
                                const hub_service_settings_t *settings) {
  if (!service || !path || !handler) return service;
  if (service_add_path(service, path, settings) != 0) return service;
  (void)channel_c_channel_post(service->channel, path, handler, NULL, 0);
  return service;
}

hub_service_t *hub_service_stream(hub_service_t *service, const char *path,
                                  channel_c_stream_handler_fn handler,
                                  const hub_service_settings_t *settings) {
  if (!service || !path || !handler) return service;
  if (service_add_path(service, path, settings) != 0) return service;
  (void)channel_c_channel_stream(service->channel, path, handler, NULL);
  return service;
}

hub_service_t *hub_service_app(hub_service_t *service, const hub_service_app_t *app) {
  hub_service_app_t *resized;
  char **interfaces_resized;
  size_t capacity;
  char *interface_json;

  if (!service || !app) return service;

  /* build the AppInterface JSON once; the stream handler emits it */
  interface_json = hub_service_build_app_interface_json(app);
  if (!interface_json) return service;

  if (service->apps_count == service->apps_capacity) {
    capacity = service->apps_capacity ? service->apps_capacity * 2 : 4;
    resized = (hub_service_app_t *)realloc(service->apps, capacity * sizeof(hub_service_app_t));
    if (!resized) {
      channel_c_free(interface_json);
      return service;
    }
    service->apps = resized;
    interfaces_resized = (char **)realloc(service->app_interfaces, capacity * sizeof(char *));
    if (!interfaces_resized) {
      channel_c_free(interface_json);
      return service;
    }
    service->app_interfaces = interfaces_resized;
    service->apps_capacity = capacity;
  }

  memset(&service->apps[service->apps_count], 0, sizeof(hub_service_app_t));
  service->apps[service->apps_count].header.type = channel_c_strdup(app->header.type ? app->header.type : "app");
  service->apps[service->apps_count].header.name = channel_c_strdup(app->header.name ? app->header.name : "");
  service->apps[service->apps_count].header.path = channel_c_strdup(app->header.path ? app->header.path : "");
  service->app_interfaces[service->apps_count] = interface_json;

  /* TS/Go parity: the app path is also callable, so it appears in the
   * services list too. */
  (void)service_add_path(service, service->apps[service->apps_count].header.path, NULL);

  (void)channel_c_channel_stream(
    service->channel,
    service->apps[service->apps_count].header.path,
    app_interface_stream_handler,
    (void *)interface_json
  );

  service->apps_count += 1;
  return service;
}

/* ------------------------------------------------------------------ */
/* start / poll / updates                                              */
/* ------------------------------------------------------------------ */

static void service_send_updates(hub_service_t *service) {
  channel_c_sender_t *sender;
  char *profile_json;
  char *update_json;
  char *response = NULL;
  char *error = NULL;

  if (!service || !service->client) return;
  sender = channel_c_client_sender(service->client);
  if (!sender) return;

  profile_json = hub_service_build_profile_json(service);
  if (profile_json) {
    (void)channel_c_sender_send(sender, "hub/profile/update", profile_json, NULL, &response, &error);
    channel_c_free(response);
    channel_c_free(error);
    response = NULL;
    error = NULL;
    channel_c_free(profile_json);
  }

  update_json = hub_service_build_update_json(service);
  if (update_json) {
    (void)channel_c_sender_send(sender, "hub/service/update", update_json, NULL, &response, &error);
    channel_c_free(response);
    channel_c_free(error);
    channel_c_free(update_json);
  }
}

int hub_service_start(hub_service_t *service, char **out_error) {
  if (out_error) *out_error = NULL;
  if (!service) {
    if (out_error) *out_error = channel_c_strdup("invalid service");
    return -1;
  }
  if (service->client) return 0; /* already started */

  /* hub-pro auth: send a freshly signed token as handshake headers (as TS does), not as URL query
     params, so it never ends up in proxy or access logs. */
  {
    char token[512];
    channel_c_header_t headers[2];
    channel_c_client_options_t client_options;

    if (hub_service_keychain_sign(token, sizeof(token)) != 0) {
      if (out_error) *out_error = channel_c_strdup("keychain failed");
      return -1;
    }
    headers[0].name = "auth";
    headers[0].value = token;
    headers[1].name = "v";
    headers[1].value = "0";
    memset(&client_options, 0, sizeof(client_options));
    client_options.headers = headers;
    client_options.header_count = 2;
    service->client = channel_c_client_connect_with_options(service->channel, service->address, &client_options, out_error);
  }
  if (!service->client) return -1;

  service->was_connected = 0; /* first poll sees 0->1 and sends updates */
  return 0;
}

int hub_service_poll(hub_service_t *service) {
  int connected;

  if (!service) return -1;
  if (!service->client) return 0; /* stopped */

  (void)channel_c_client_poll(service->client);
  connected = channel_c_client_is_connected(service->client);

  if (connected && !service->was_connected) {
    /* 0->1 transition (initial connect or reconnect): re-register with the hub */
    service_send_updates(service);
  } else if (!connected && service->was_connected) {
    /* 1->0 transition: the channel-c client does not auto-reconnect, so
     * release it; the next poll redials a fresh client (handlers live on the
     * channel, so registration survives). */
    channel_c_client_free(service->client);
    service->client = NULL;
  }

  service->was_connected = connected ? 1 : 0;
  return 0;
}

void hub_service_stop(hub_service_t *service) {
  if (!service) return;
  if (service->client) {
    channel_c_client_free(service->client);
    service->client = NULL;
  }
  service->was_connected = 0;
}

/* ------------------------------------------------------------------ */
/* client calls through the hub                                        */
/* ------------------------------------------------------------------ */

int hub_service_send(hub_service_t *service, const char *path, const char *body_json,
                     char **out_body_json, char **out_error) {
  if (out_error) *out_error = NULL;
  if (!service || !service->client) {
    if (out_error) *out_error = channel_c_strdup("Service not started");
    return -1;
  }
  return channel_c_sender_send(channel_c_client_sender(service->client), path, body_json, NULL, out_body_json, out_error);
}

int hub_service_values(hub_service_t *service, const char *path, const char *body_json,
                       channel_c_values_t **out_values, char **out_error) {
  if (out_error) *out_error = NULL;
  if (!service || !service->client) {
    if (out_error) *out_error = channel_c_strdup("Service not started");
    return -1;
  }
  *out_values = channel_c_sender_values(channel_c_client_sender(service->client), path, body_json, NULL, out_error);
  return *out_values ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* app element helpers (TS app.ts wire shapes)                         */
/* ------------------------------------------------------------------ */

char *hub_service_action(const hub_service_action_t *action) {
  strbuf_t buffer;
  char *escaped;

  if (!action) return NULL;
  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"path\":");
  escaped = json_escape(action->path ? action->path : "");
  strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
  free(escaped);
  if (action->body) {
    strbuf_appendf(&buffer, ",\"body\":%s", action->body);
  }
  if (action->output) {
    strbuf_appendf(&buffer, ",\"output\":%s", action->output);
  }
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

static char *elem_json(const char *type, const char *fields) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_appendf(&buffer, "{\"type\":\"%s\"", type ? type : "");
  if (fields && fields[0]) strbuf_append(&buffer, fields);
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

static char *elem_string_field(const char *name, const char *value) {
  strbuf_t buffer;
  char *escaped;

  if (!value) return NULL;
  strbuf_init(&buffer);
  escaped = json_escape(value);
  strbuf_appendf(&buffer, ",\"%s\":\"%s\"", name, escaped ? escaped : "");
  free(escaped);
  return strbuf_detach(&buffer);
}

static char *elem_raw_field(const char *name, const char *value) {
  strbuf_t buffer;

  if (!value) return NULL;
  strbuf_init(&buffer);
  strbuf_appendf(&buffer, ",\"%s\":%s", name, value);
  return strbuf_detach(&buffer);
}

static void strbuf_append_owned(strbuf_t *buffer, char *owned) {
  if (!owned) return;
  strbuf_append(buffer, owned);
  free(owned);
}

char *hub_service_elem_text(const char *value, const char *secondary) {
  strbuf_t buffer;
  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"text\",\"value\":");
  {
    char *escaped = json_escape(value ? value : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  if (secondary) strbuf_append_owned(&buffer, elem_string_field("secondary", secondary));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_progress(const char *value, const char *min, const char *max) {
  strbuf_t buffer;
  char *field;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"progress\",\"value\":");
  {
    char *escaped = json_escape(value ? value : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append_owned(&buffer, elem_raw_field("min", min));
  strbuf_append_owned(&buffer, elem_raw_field("max", max));
  strbuf_append(&buffer, "}");
  (void)field;
  return strbuf_detach(&buffer);
}

char *hub_service_elem_text_field(const char *value, const char *placeholder, const char *action_json) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"textField\",\"value\":");
  {
    char *escaped = json_escape(value ? value : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append_owned(&buffer, elem_string_field("placeholder", placeholder));
  strbuf_append_owned(&buffer, elem_raw_field("action", action_json));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_button(const char *title, const char *action_json) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"button\",\"title\":");
  {
    char *escaped = json_escape(title ? title : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append_owned(&buffer, elem_raw_field("action", action_json));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_slider(const char *value, const char *default_value,
                              const char *min, const char *max, const char *step,
                              const char *action_json) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"slider\",\"value\":");
  {
    char *escaped = json_escape(value ? value : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append_owned(&buffer, elem_raw_field("defaultValue", default_value));
  strbuf_append_owned(&buffer, elem_raw_field("min", min));
  strbuf_append_owned(&buffer, elem_raw_field("max", max));
  strbuf_append_owned(&buffer, elem_raw_field("step", step));
  strbuf_append_owned(&buffer, elem_raw_field("action", action_json));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_list(const char *data, const char *content_json) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"list\",\"data\":");
  {
    char *escaped = json_escape(data ? data : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append_owned(&buffer, elem_raw_field("content", content_json));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_picker(const char **options, const char *selected) {
  strbuf_t buffer;
  size_t index;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"picker\",\"options\":[");
  if (options) {
    for (index = 0; options[index]; index += 1) {
      char *escaped = json_escape(options[index]);
      if (index > 0) strbuf_append(&buffer, ",");
      strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
      free(escaped);
    }
  }
  strbuf_append(&buffer, "],\"selected\":");
  {
    char *escaped = json_escape(selected ? selected : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_cell(const char *title, const char *subtitle) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"cell\"");
  strbuf_append_owned(&buffer, elem_string_field("title", title));
  strbuf_append_owned(&buffer, elem_string_field("subtitle", subtitle));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_files(const char *value, const char *title, const char *action_json) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"files\",\"value\":");
  {
    char *escaped = json_escape(value ? value : "");
    strbuf_appendf(&buffer, "\"%s\"", escaped ? escaped : "");
    free(escaped);
  }
  strbuf_append_owned(&buffer, elem_string_field("title", title));
  strbuf_append_owned(&buffer, elem_raw_field("action", action_json));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_file_operation(const char *format, const char *title, const char *action_json) {
  strbuf_t buffer;

  strbuf_init(&buffer);
  strbuf_append(&buffer, "{\"type\":\"fileOperation\"");
  strbuf_append_owned(&buffer, elem_string_field("format", format));
  strbuf_append_owned(&buffer, elem_string_field("title", title));
  strbuf_append_owned(&buffer, elem_raw_field("action", action_json));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

static char *stack_json(const char *type, const char **content, const char *spacing) {
  strbuf_t buffer;
  size_t index;

  strbuf_init(&buffer);
  strbuf_appendf(&buffer, "{\"type\":\"%s\",\"content\":[", type ? type : "");
  if (content) {
    for (index = 0; content[index]; index += 1) {
      if (index > 0) strbuf_append(&buffer, ",");
      strbuf_append(&buffer, content[index]);
    }
  }
  strbuf_append(&buffer, "]");
  strbuf_append_owned(&buffer, elem_raw_field("spacing", spacing));
  strbuf_append(&buffer, "}");
  return strbuf_detach(&buffer);
}

char *hub_service_elem_hstack(const char **content, const char *spacing) {
  return stack_json("hstack", content, spacing);
}

char *hub_service_elem_vstack(const char **content, const char *spacing) {
  return stack_json("vstack", content, spacing);
}

char *hub_service_elem_zstack(const char **content) {
  return stack_json("zstack", content, NULL);
}

char *hub_service_elem_spacer(void) {
  return channel_c_strdup("{\"type\":\"spacer\"}");
}
