/*
 * Connect flow against an in-process fake hub (a channel-c server):
 * v0 connect, hub/info, hub key pin, v1 reconnect; hub-lite stays on v0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <setjmp.h>
#include <cmocka.h>

#include "hub-service-c/hub_service_c.h"
#include "hub-service-c/device.h"
#include "hub-service-c/keychain.h"
#include "hub_service_internal.h"

#define HUB_KEY "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="

static int connect_count;
static char test_dir[256];
static char test_auth_path[320];

/* channel-c's server garbles custom handshake headers (libwebsockets keeps
 * only the first one, name and value merged), so the fake hub only counts
 * connections; the headers are checked through
 * hub_service_build_connect_headers. */
static void *count_connect(const channel_c_headers_t *headers, void *user_data) {
  (void)headers;
  (void)user_data;
  connect_count += 1;
  return NULL;
}

static char *read_key_file(void) {
  static char key_file[256];
  FILE *f = fopen(test_auth_path, "rb");
  size_t n;
  assert_non_null(f);
  n = fread(key_file, 1, sizeof(key_file) - 1, f);
  fclose(f);
  key_file[n] = '\0';
  return key_file;
}

static int reply_null(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  (void)request;
  (void)out_error;
  *out_body_json = channel_c_strdup("null");
  return 0;
}

static int reply_info(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  (void)request;
  (void)out_error;
  *out_body_json = channel_c_strdup("{\"key\":\"" HUB_KEY "\",\"protocol\":1,\"pro\":true,\"mode\":\"default-allow\"}");
  return 0;
}

typedef struct {
  channel_c_channel_t *channel;
  channel_c_server_t *server;
  hub_service_t *service;
} fixture_t;

static int setup(void **state) {
  fixture_t *fixture = calloc(1, sizeof(fixture_t));
  snprintf(test_dir, sizeof(test_dir), "/tmp/hub_service_c_flow_%ld", (long)getpid());
  mkdir(test_dir, 0700);
  snprintf(test_auth_path, sizeof(test_auth_path), "%s/auth", test_dir);
  hub_service_keychain_set_path(test_auth_path);
  {
    char device_path[320];
    snprintf(device_path, sizeof(device_path), "%s/device.key", test_dir);
    hub_service_device_set_path(device_path);
  }
  connect_count = 0;
  *state = fixture;
  return 0;
}

static int teardown(void **state) {
  fixture_t *fixture = *state;
  char cmd[512];
  hub_service_free(fixture->service);
  channel_c_server_free(fixture->server);
  channel_c_channel_free(fixture->channel);
  free(fixture);
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  system(cmd);
  hub_service_keychain_set_path(NULL);
  hub_service_device_set_path(NULL);
  return 0;
}

static void start_hub(fixture_t *fixture, int answers_info) {
  channel_c_state_factory_t factory;
  char *error = NULL;
  char url[64];
  hub_service_options_t options;

  fixture->channel = channel_c_channel_new();
  channel_c_channel_post(fixture->channel, "hub/service/update", reply_null, NULL, 0);
  channel_c_channel_post(fixture->channel, "hub/profile/update", reply_null, NULL, 0);
  if (answers_info) channel_c_channel_post(fixture->channel, "hub/info", reply_info, NULL, 0);
  memset(&factory, 0, sizeof(factory));
  factory.create_with_headers = count_connect;
  fixture->server = channel_c_server_listen(fixture->channel, "127.0.0.1", 0, factory, &error);
  assert_non_null(fixture->server);

  snprintf(url, sizeof(url), "ws://127.0.0.1:%d", channel_c_server_port(fixture->server));
  memset(&options, 0, sizeof(options));
  options.address = url;
  options.name = "flow";
  fixture->service = hub_service_new(&options, &error);
  assert_non_null(fixture->service);
}

static void pump(fixture_t *fixture, int until_connects, int ms) {
  int elapsed;
  for (elapsed = 0; elapsed < ms && connect_count < until_connects; elapsed++) {
    (void)hub_service_poll(fixture->service);
    (void)channel_c_server_poll(fixture->server);
    usleep(1000);
  }
  /* settle: let the service finish the updates on its latest connection */
  for (elapsed = 0; elapsed < 200; elapsed++) {
    (void)hub_service_poll(fixture->service);
    (void)channel_c_server_poll(fixture->server);
    usleep(1000);
  }
}

static void test_learns_and_pins_the_hub_key(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;
  char key[128];

  start_hub(fixture, 1);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 2, 5000);

  /* v0 connect, hub/info, pin, reconnect */
  assert_int_equal(connect_count, 2);
  assert_int_equal(hub_service_keychain_hub_key(hub_service_address(fixture->service), key, sizeof(key)), 0);
  assert_string_equal(key, HUB_KEY);
}

static void test_headers_follow_the_pin(void **state) {
  fixture_t *fixture = *state;
  hub_service_connect_headers_t headers;
  char expected[512];
  long long expiry;

  start_hub(fixture, 1);

  /* no pin: v0 */
  assert_int_equal(hub_service_build_connect_headers(fixture->service, &headers), 0);
  assert_int_equal(headers.count, 3); /* auth, v, device */
  assert_string_equal(headers.items[0].name, "auth");
  assert_string_equal(headers.items[1].name, "v");
  assert_string_equal(headers.items[1].value, "0");
  expiry = atoll(strrchr(headers.auth, '.') + 1);
  assert_int_equal(hub_service_auth_token(read_key_file(), NULL, expiry, expected, sizeof(expected)), 0);
  assert_string_equal(headers.auth, expected);
  hub_service_connect_headers_free(&headers);

  /* pinned: v1 bound to the hub key */
  assert_int_equal(hub_service_keychain_pin_hub_key(hub_service_address(fixture->service), HUB_KEY), 0);
  assert_int_equal(hub_service_build_connect_headers(fixture->service, &headers), 0);
  assert_string_equal(headers.items[1].value, "1");
  expiry = atoll(strrchr(headers.auth, '.') + 1);
  assert_int_equal(hub_service_auth_token(read_key_file(), HUB_KEY, expiry, expected, sizeof(expected)), 0);
  assert_string_equal(headers.auth, expected);
  hub_service_connect_headers_free(&headers);

  /* forgetting the pin goes back to v0 */
  assert_int_equal(hub_service_forget_hub_key(fixture->service), 0);
  assert_int_equal(hub_service_build_connect_headers(fixture->service, &headers), 0);
  assert_string_equal(headers.items[1].value, "0");
  hub_service_connect_headers_free(&headers);
}

static void test_pinned_hub_connects_once(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;

  start_hub(fixture, 1);
  assert_int_equal(hub_service_keychain_pin_hub_key(hub_service_address(fixture->service), HUB_KEY), 0);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 2, 300);

  assert_int_equal(connect_count, 1);
}

static void test_hub_lite_stays_on_v0(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;
  char key[128];

  start_hub(fixture, 0);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 2, 300);

  assert_int_equal(connect_count, 1);
  assert_int_equal(hub_service_keychain_hub_key(hub_service_address(fixture->service), key, sizeof(key)), -1);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_learns_and_pins_the_hub_key, setup, teardown),
      cmocka_unit_test_setup_teardown(test_headers_follow_the_pin, setup, teardown),
      cmocka_unit_test_setup_teardown(test_pinned_hub_connects_once, setup, teardown),
      cmocka_unit_test_setup_teardown(test_hub_lite_stays_on_v0, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
