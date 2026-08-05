/*
 * Echo service example (hub-service-c).
 *
 * Registers post "echo", post "echo/upper", and app "echo/ui" on the hub,
 * then runs the client poll loop. Start the hub first (hub-lite on :1997):
 *
 *   ./build/echo
 *
 * Then call through the hub:
 *   bun hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
 *   bun hub-service/tests/appcheck.ts echo/ui Echo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <yyjson.h>

#include "hub-service-c/hub_service_c.h"

/* echo: return the request body unchanged */
static int echo_handler(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  (void)out_error;
  *out_body_json = channel_c_strdup(request->body_json ? request->body_json : "null");
  return *out_body_json ? 0 : -1;
}

/* echo/upper: uppercase a JSON string body */
static int upper_handler(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  yyjson_doc *doc;
  yyjson_val *root;
  const char *text;
  size_t length;
  char *upper;
  char *escaped;
  size_t index;

  (void)out_error;

  if (!request->body_json) {
    *out_body_json = channel_c_strdup("null");
    return *out_body_json ? 0 : -1;
  }

  doc = yyjson_read(request->body_json, strlen(request->body_json), 0);
  if (!doc) {
    *out_body_json = channel_c_strdup("null");
    return *out_body_json ? 0 : -1;
  }
  root = yyjson_doc_get_root(doc);
  if (!yyjson_is_str(root)) {
    yyjson_doc_free(doc);
    *out_body_json = channel_c_strdup(request->body_json);
    return *out_body_json ? 0 : -1;
  }

  text = yyjson_get_str(root);
  length = yyjson_get_len(root);
  upper = (char *)malloc(length + 1);
  if (!upper) {
    yyjson_doc_free(doc);
    *out_error = channel_c_strdup("internal error");
    return -1;
  }
  for (index = 0; index < length; index += 1) {
    char c = text[index];
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    upper[index] = c;
  }
  upper[length] = '\0';
  yyjson_doc_free(doc);

  /* build a JSON string out of the uppercased text */
  {
    size_t needed = 3; /* quotes + NUL */
    const char *p;
    for (p = upper; *p; p += 1) {
      if (*p == '"' || *p == '\\') needed += 2;
      else needed += 1;
    }
    escaped = (char *)malloc(needed);
    if (!escaped) {
      free(upper);
      *out_error = channel_c_strdup("internal error");
      return -1;
    }
    {
      size_t offset = 0;
      escaped[offset++] = '"';
      for (p = upper; *p; p += 1) {
        if (*p == '"' || *p == '\\') escaped[offset++] = '\\';
        escaped[offset++] = *p;
      }
      escaped[offset++] = '"';
      escaped[offset] = '\0';
    }
  }
  free(upper);
  *out_body_json = escaped;
  return 0;
}

int main(void) {
  hub_service_options_t options;
  hub_service_t *service;
  hub_service_action_t action;
  char *action_json;
  char *text_field;
  char *cell;
  char *button;
  const char *body[5];
  hub_service_app_t app;
  char *error = NULL;
  char *body_json;
  char *response;

  memset(&options, 0, sizeof(options));
  options.name = "Echo";
  options.icon = "{\"symbol\":\"speaker.wave.2\",\"text\":\"E\"}";

  service = hub_service_new(&options, &error);
  if (!service) {
    fprintf(stderr, "hub_service_new failed: %s\n", error ? error : "unknown");
    free(error);
    return 1;
  }

  hub_service_post(service, "echo", echo_handler, NULL);
  hub_service_post(service, "echo/upper", upper_handler, NULL);

  /* app: echo/ui */
  memset(&action, 0, sizeof(action));
  action.path = "echo/upper";
  action.body = "\"value\"";
  action.output = "\"value\"";
  action_json = hub_service_action(&action);
  text_field = hub_service_elem_text_field("echo", "Text to echo", action_json);
  cell = hub_service_elem_cell("$Echo", "value");
  button = hub_service_elem_button("Upper", action_json);

  body[0] = "\"Hello from C\"";
  body[1] = text_field;
  body[2] = cell;
  body[3] = button;
  body[4] = NULL;

  memset(&app, 0, sizeof(app));
  app.header.type = "app";
  app.header.name = "Echo";
  app.header.path = "echo/ui";
  app.body = body;
  app.data = "{\"hello\":\"world\"}";
  hub_service_app(service, &app);

  if (hub_service_start(service, &error) != 0) {
    fprintf(stderr, "hub_service_start failed: %s\n", error ? error : "unknown");
    channel_c_free(error);
    hub_service_free(service);
    return 1;
  }

  printf("echo service started (hub-lite :1997)\n");
  fflush(stdout);

  /* self-check: call echo/upper through the hub */
  body_json = "\"hello\"";
  if (hub_service_send(service, "echo/upper", body_json, &response, &error) == 0) {
    printf("self-check echo/upper -> %s\n", response ? response : "null");
    channel_c_free(response);
  } else {
    fprintf(stderr, "self-check failed: %s\n", error ? error : "unknown");
  }
  channel_c_free(error);

  for (;;) {
    (void)hub_service_poll(service);
    usleep(1000);
  }

  hub_service_free(service);
  return 0;
}
