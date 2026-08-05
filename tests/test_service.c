/*
 * hub_service_c unit tests (cmocka).
 *
 * Asserts the exact hub wire payloads (hub/service/update, hub/profile/update,
 * AppInterface) plus registration and error behavior.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "hub-service-c/hub_service_c.h"
#include "hub_service_internal.h"

static int noop_post(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  (void)request;
  (void)out_error;
  *out_body_json = channel_c_strdup("null");
  return *out_body_json ? 0 : -1;
}

static void noop_stream(const channel_c_stream_request_t *request) {
  (void)request;
}

static hub_service_t *make_service(void) {
  return hub_service_new(NULL, NULL);
}

/* services list includes every registered path (post + stream + app path),
 * sorted; apps list carries the app header. */
static void test_services_list_includes_registered_paths(void **state) {
  hub_service_t *service = make_service();
  hub_service_app_t app;
  const char *body[] = {"\"hi\"", NULL};
  char *update;

  assert_non_null(service);

  hub_service_post(service, "echo", noop_post, NULL);
  hub_service_stream(service, "echo/values", noop_stream, NULL);

  memset(&app, 0, sizeof(app));
  app.header.type = "app";
  app.header.name = "Echo";
  app.header.path = "echo/ui";
  app.body = body;
  hub_service_app(service, &app);

  update = hub_service_build_update_json(service);
  assert_non_null(update);
  assert_string_equal(
    update,
    "{\"services\":[{\"path\":\"echo\"},{\"path\":\"echo/ui\"},{\"path\":\"echo/values\"}],"
    "\"apps\":[{\"type\":\"app\",\"name\":\"Echo\",\"path\":\"echo/ui\"}]}"
  );
  channel_c_free(update);

  hub_service_free(service);
}

/* settings apply to the update payload: permissions group auto-fill uses the
 * first path segment; limit is emitted. */
static void test_settings_apply_to_update_payload(void **state) {
  hub_service_t *service = make_service();
  hub_service_settings_t settings;
  char *update;

  assert_non_null(service);

  memset(&settings, 0, sizeof(settings));
  settings.permissions_set = 1;
  settings.permissions_name = "Echo";
  settings.permissions_allows_set = 1;
  settings.permissions_allows = 1;
  settings.limit_set = 1;
  settings.limit = 5;
  hub_service_post(service, "echo", noop_post, &settings);

  update = hub_service_build_update_json(service);
  assert_non_null(update);
  assert_string_equal(
    update,
    "{\"services\":[{\"path\":\"echo\",\"permissions\":{\"group\":\"echo\",\"name\":\"Echo\",\"allows\":true},\"limit\":5}],\"apps\":[]}"
  );
  channel_c_free(update);

  hub_service_free(service);
}

/* profile update is only sent when a name or icon is set. */
static void test_profile_only_when_set(void **state) {
  hub_service_t *plain = hub_service_new(NULL, NULL);
  hub_service_options_t named_options;
  hub_service_t *named;
  char *profile;

  assert_non_null(plain);
  profile = hub_service_build_profile_json(plain);
  assert_null(profile);

  memset(&named_options, 0, sizeof(named_options));
  named_options.name = "Echo";
  named = hub_service_new(&named_options, NULL);
  assert_non_null(named);
  profile = hub_service_build_profile_json(named);
  assert_non_null(profile);
  assert_string_equal(profile, "{\"name\":\"Echo\"}");
  channel_c_free(profile);

  hub_service_free(named);
  hub_service_free(plain);
}

/* update payload matches the exact wire contract string. */
static void test_update_json_matches_wire_contract(void **state) {
  hub_service_t *service = make_service();
  hub_service_settings_t settings;
  char *update;

  assert_non_null(service);

  memset(&settings, 0, sizeof(settings));
  settings.permissions_set = 1;
  settings.permissions_name = "Echo";
  settings.permissions_allows_set = 1;
  settings.permissions_allows = 1;
  settings.limit_set = 1;
  settings.limit = 5;
  hub_service_post(service, "echo", noop_post, &settings);

  update = hub_service_build_update_json(service);
  assert_non_null(update);
  assert_string_equal(
    update,
    "{\"services\":[{\"path\":\"echo\",\"permissions\":{\"group\":\"echo\",\"name\":\"Echo\",\"allows\":true},\"limit\":5}],\"apps\":[]}"
  );
  channel_c_free(update);

  hub_service_free(service);
}

/* send/values before start return "Service not started". */
static void test_send_before_start_errors(void **state) {
  hub_service_t *service = make_service();
  channel_c_values_t *values = NULL;
  char *body = NULL;
  char *error = NULL;

  assert_non_null(service);

  assert_int_equal(hub_service_send(service, "echo", "42", &body, &error), -1);
  assert_null(body);
  assert_non_null(error);
  assert_string_equal(error, "Service not started");
  channel_c_free(error);
  error = NULL;

  assert_int_equal(hub_service_values(service, "echo", NULL, &values, &error), -1);
  assert_null(values);
  assert_non_null(error);
  assert_string_equal(error, "Service not started");
  channel_c_free(error);

  hub_service_free(service);
}

/* app interface stream value carries all 5 keys with the right header. */
static void test_app_interface_shape(void **state) {
  hub_service_app_t app;
  const char *body[] = {"\"Hello from C\"", NULL};
  char *interface_json;

  memset(&app, 0, sizeof(app));
  app.header.type = "app";
  app.header.name = "Echo";
  app.header.path = "echo/ui";
  app.body = body;

  interface_json = hub_service_build_app_interface_json(&app);
  assert_non_null(interface_json);
  assert_string_equal(
    interface_json,
    "{\"header\":{\"type\":\"app\",\"name\":\"Echo\",\"path\":\"echo/ui\"},"
    "\"body\":[\"Hello from C\"],\"top\":null,\"bottom\":null,\"data\":{}}"
  );
  channel_c_free(interface_json);
}

int main(void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_services_list_includes_registered_paths),
    cmocka_unit_test(test_settings_apply_to_update_payload),
    cmocka_unit_test(test_profile_only_when_set),
    cmocka_unit_test(test_update_json_matches_wire_contract),
    cmocka_unit_test(test_send_before_start_errors),
    cmocka_unit_test(test_app_interface_shape),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
