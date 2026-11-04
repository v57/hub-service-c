/*
 * Connect flow against an in-process fake hub (a channel-c server): the proof of
 * the hub's key, the pin, a token for that answer's challenge alone, and nothing
 * at all for a hub that doesn't prove its key.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <setjmp.h>
#include <cmocka.h>

#include "hub-service-c/hub_service_c.h"
#include "hub-service-c/device.h"
#include "hub-service-c/keychain.h"
#include "hub_service_internal.h"
#include "fake_hub.h"

typedef enum {
  INFO_PROVING,
  INFO_PROVING_OTHER, /* proves its own key */
  INFO_NO_PROOF,      /* the real key, with no proof */
  INFO_FORGED_PROOF,  /* claims the real key, signs with its own */
  INFO_NO_CHALLENGE,
  INFO_BAD_CHALLENGE  /* would add a header line */
} info_mode_t;

#define MAX_CONNECTS 16

static info_mode_t info_mode;
static int connect_count;
static int credential_connects; /* connections with auth, v or device */
static int update_count;
static int info_count;
static char nonces[MAX_CONNECTS][64];
static char tokens[MAX_CONNECTS][512];
static int token_count;
static char test_dir[256];
static char test_auth_path[320];

/* The auth header a connection sent. channel-c's server garbles the first custom
 * handshake header (libwebsockets merges name and value up to the next header's
 * name and lowercases them), so it comes as a name "auth: key....\r\nv" and
 * compares only without case; the exact bytes are checked through
 * hub_service_handshake and against the vectors. */
static const char *auth_header(const channel_c_headers_t *headers) {
  size_t index;
  for (index = 0; index < headers->count; index++) {
    const char *name = headers->items[index].name;
    if (strncasecmp(name, "auth: ", 6) == 0) return name + 6;
    if (strcasecmp(name, "auth") == 0) return headers->items[index].value;
  }
  return NULL;
}

/* Records each connection's handshake headers. */
static void *record_connect(const channel_c_headers_t *headers, void *user_data) {
  const char *auth = auth_header(headers);
  (void)user_data;
  connect_count += 1;
  if (auth || channel_c_headers_get(headers, "device") || channel_c_headers_get(headers, "v")) {
    credential_connects += 1;
  }
  if (auth && token_count < MAX_CONNECTS) {
    snprintf(tokens[token_count], sizeof(tokens[token_count]), "%.*s", (int)strcspn(auth, "\r"), auth);
    token_count += 1;
  }
  return NULL;
}

static channel_c_sender_t *hub_sender;

static void remember_sender(void *state, channel_c_sender_t *sender, void *user_data) {
  (void)state;
  (void)user_data;
  hub_sender = sender;
}

/* who: replies with the caller's key, device name and owner flag */
static int who_handler(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  hub_service_caller_t *caller = hub_service_caller(request->context_json);
  char reply[512];
  (void)out_error;
  if (!caller) {
    *out_body_json = channel_c_strdup("null");
    return 0;
  }
  snprintf(reply, sizeof(reply), "\"%s|%s|%d\"", caller->key ? caller->key : "-",
           caller->device_name ? caller->device_name : "-", caller->owner);
  hub_service_caller_free(caller);
  *out_body_json = channel_c_strdup(reply);
  return 0;
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

static int reply_update(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  update_count += 1;
  return reply_null(request, out_body_json, out_error);
}

static int reply_info(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  char challenge[32];
  char reply[512];
  char nonce[64];
  (void)out_error;
  fake_hub_nonce(request->body_json, nonce, sizeof(nonce));
  if (info_count < MAX_CONNECTS) snprintf(nonces[info_count], sizeof(nonces[info_count]), "%s", nonce);
  info_count += 1;
  snprintf(challenge, sizeof(challenge), "challenge-%d", info_count);
  switch (info_mode) {
    case INFO_PROVING:
      *out_body_json = fake_hub_info(FAKE_HUB_KEY_FILE, FAKE_HUB_KEY, request->body_json, challenge);
      break;
    case INFO_PROVING_OTHER:
      *out_body_json = fake_hub_info(FAKE_OTHER_KEY_FILE, FAKE_OTHER_KEY, request->body_json, challenge);
      break;
    case INFO_NO_PROOF:
      snprintf(reply, sizeof(reply), "{\"key\":\"" FAKE_HUB_KEY "\",\"protocol\":2,\"challenge\":\"%s\"}", challenge);
      *out_body_json = channel_c_strdup(reply);
      break;
    case INFO_FORGED_PROOF:
      *out_body_json = fake_hub_info(FAKE_OTHER_KEY_FILE, FAKE_HUB_KEY, request->body_json, challenge);
      break;
    case INFO_NO_CHALLENGE:
      /* a real proof, with the challenge's name changed */
      {
        char *full = fake_hub_info(FAKE_HUB_KEY_FILE, FAKE_HUB_KEY, request->body_json, challenge);
        char *field = strstr(full, "\"challenge\"");
        memcpy(field, "\"xhallenge\"", 11);
        *out_body_json = full;
      }
      break;
    case INFO_BAD_CHALLENGE:
      *out_body_json = fake_hub_info(FAKE_HUB_KEY_FILE, FAKE_HUB_KEY, request->body_json, "c\\r\\nx: y");
      break;
  }
  return 0;
}

typedef struct {
  channel_c_channel_t *channel;
  channel_c_server_t *server;
  hub_service_t *service;
  hub_service_t *second;
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
  credential_connects = 0;
  update_count = 0;
  info_count = 0;
  token_count = 0;
  *state = fixture;
  return 0;
}

static int teardown(void **state) {
  fixture_t *fixture = *state;
  char cmd[512];
  hub_service_free(fixture->service);
  hub_service_free(fixture->second);
  channel_c_server_free(fixture->server);
  channel_c_channel_free(fixture->channel);
  free(fixture);
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  system(cmd);
  hub_service_keychain_set_path(NULL);
  hub_service_device_set_path(NULL);
  return 0;
}

static hub_service_t *new_service(fixture_t *fixture) {
  char url[64];
  char *error = NULL;
  hub_service_options_t options;
  hub_service_t *service;
  snprintf(url, sizeof(url), "ws://127.0.0.1:%d", channel_c_server_port(fixture->server));
  memset(&options, 0, sizeof(options));
  options.address = url;
  options.name = "flow";
  service = hub_service_new(&options, &error);
  assert_non_null(service);
  return service;
}

static void start_hub(fixture_t *fixture, info_mode_t mode) {
  channel_c_state_factory_t factory;
  char *error = NULL;

  info_mode = mode;
  fixture->channel = channel_c_channel_new();
  channel_c_channel_post(fixture->channel, "hub/service/update", reply_update, NULL, 0);
  channel_c_channel_post(fixture->channel, "hub/profile/update", reply_null, NULL, 0);
  channel_c_channel_post(fixture->channel, "hub/info", reply_info, NULL, 0);
  memset(&factory, 0, sizeof(factory));
  factory.create_with_headers = record_connect;
  factory.on_connect = remember_sender;
  hub_sender = NULL;
  fixture->server = channel_c_server_listen(fixture->channel, "127.0.0.1", 0, factory, &error);
  assert_non_null(fixture->server);
  fixture->service = new_service(fixture);
}

static void pump_service(fixture_t *fixture, hub_service_t *service, int until_connects, int ms) {
  int elapsed;
  for (elapsed = 0; elapsed < ms && connect_count < until_connects; elapsed++) {
    (void)hub_service_poll(service);
    (void)channel_c_server_poll(fixture->server);
    usleep(1000);
  }
  /* settle: let the service finish the updates on its latest connection */
  for (elapsed = 0; elapsed < 200; elapsed++) {
    (void)hub_service_poll(service);
    (void)channel_c_server_poll(fixture->server);
    usleep(1000);
  }
}

static void pump(fixture_t *fixture, int until_connects, int ms) {
  pump_service(fixture, fixture->service, until_connects, ms);
}

/* The nth dot-separated part of a token, in a static buffer. */
static const char *token_part(const char *token, int index) {
  static char part[256];
  const char *p = token;
  while (index-- > 0) {
    p = strchr(p, '.');
    assert_non_null(p);
    p += 1;
  }
  snprintf(part, sizeof(part), "%.*s", (int)strcspn(p, "."), p);
  return part;
}

static void test_sends_a_token_only_after_the_proof(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;
  char key[128];
  char expected[512];

  start_hub(fixture, INFO_PROVING);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 2, 5000);

  /* the anonymous question, then the connect */
  assert_int_equal(connect_count, 2);
  assert_int_equal(credential_connects, 1);
  assert_int_equal(info_count, 1);
  assert_int_equal(update_count, 1);
  assert_int_equal(strlen(nonces[0]), 43); /* 32 bytes in base64url, no padding */
  assert_int_equal(hub_service_keychain_hub_key(hub_service_pin_address(fixture->service), key, sizeof(key)), 0);
  assert_string_equal(key, FAKE_HUB_KEY);

  /* signs hub1:<hub key>:<challenge>:<expiry> with the service key */
  assert_int_equal(token_count, 1);
  assert_string_equal(token_part(tokens[0], 4), "challenge-1");
  assert_int_equal(hub_service_auth_token(read_key_file(), FAKE_HUB_KEY, "challenge-1", atoll(token_part(tokens[0], 3)),
                                          expected, sizeof(expected)),
                   0);
  assert_int_equal(strcasecmp(tokens[0], expected), 0);
}

static void test_handshake_builds_the_headers(void **state) {
  fixture_t *fixture = *state;
  hub_service_connect_headers_t headers;
  char *error = NULL;
  char first[512];

  start_hub(fixture, INFO_PROVING);
  assert_int_equal(hub_service_handshake(fixture->service, &headers, &error), 0);
  assert_int_equal(headers.count, 3); /* auth, v, device */
  assert_string_equal(headers.items[0].name, "auth");
  assert_string_equal(headers.items[1].name, "v");
  assert_string_equal(headers.items[1].value, "1");
  assert_string_equal(headers.items[2].name, "device");
  snprintf(first, sizeof(first), "%s", headers.auth);
  assert_string_equal(token_part(first, 4), "challenge-1");

  /* Two connects, two nonces, two challenges. */
  assert_int_equal(hub_service_handshake(fixture->service, &headers, &error), 0);
  assert_string_equal(token_part(headers.auth, 4), "challenge-2");
  assert_int_equal(info_count, 2);
  assert_string_not_equal(nonces[0], nonces[1]);
}

static void test_every_connect_asks_again(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;

  start_hub(fixture, INFO_PROVING);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 2, 5000);
  /* The same pin, a new connect: it asks again. */
  fixture->second = new_service(fixture);
  assert_int_equal(hub_service_start(fixture->second, &error), 0);
  pump_service(fixture, fixture->second, 4, 5000);

  assert_int_equal(connect_count, 4);
  assert_int_equal(info_count, 2);
  assert_int_equal(token_count, 2);
  {
    char first[64];
    snprintf(first, sizeof(first), "%s", token_part(tokens[0], 4));
    assert_string_not_equal(first, token_part(tokens[1], 4));
  }
}

static void check_gets_nothing(fixture_t *fixture, info_mode_t mode) {
  char *error = NULL;
  char *body = NULL;
  char key[128];
  char path[400];

  start_hub(fixture, mode);
  assert_int_equal(hub_service_start(fixture->service, &error), -1);
  assert_non_null(error);
  channel_c_free(error);
  error = NULL;
  /* Long enough for a retry: the first one comes after a second. */
  pump(fixture, 2, 2500);

  assert_true(info_count >= 2);
  assert_int_equal(credential_connects, 0);
  assert_int_equal(update_count, 0);
  assert_int_equal(hub_service_keychain_hub_key(hub_service_pin_address(fixture->service), key, sizeof(key)), -1);
  snprintf(path, sizeof(path), "%s/hubs.json", test_dir);
  assert_int_equal(access(path, F_OK), -1);

  /* A call says why instead of going out. */
  assert_int_equal(hub_service_send(fixture->service, "x", "1", &body, &error), -1);
  assert_non_null(strstr(error, "sending it nothing"));
  channel_c_free(error);
}

static void test_no_proof_gets_nothing(void **state) {
  check_gets_nothing(*state, INFO_NO_PROOF);
}

static void test_forged_proof_gets_nothing(void **state) {
  check_gets_nothing(*state, INFO_FORGED_PROOF);
}

static void test_no_challenge_gets_nothing(void **state) {
  check_gets_nothing(*state, INFO_NO_CHALLENGE);
}

static void test_bad_challenge_gets_nothing(void **state) {
  check_gets_nothing(*state, INFO_BAD_CHALLENGE);
}

static void test_stop_ends_the_retrying(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;
  int asked;

  start_hub(fixture, INFO_NO_PROOF);
  assert_int_equal(hub_service_start(fixture->service, &error), -1);
  channel_c_free(error);
  hub_service_stop(fixture->service);
  asked = info_count;
  pump(fixture, 100, 1200);
  assert_int_equal(info_count, asked);
}

static void test_another_proven_key_gets_nothing(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;
  char key[128];

  start_hub(fixture, INFO_PROVING_OTHER);
  assert_int_equal(hub_service_keychain_pin_hub_key(hub_service_pin_address(fixture->service), FAKE_HUB_KEY), 0);
  assert_int_equal(hub_service_start(fixture->service, &error), -1);
  assert_non_null(strstr(error, "pinned"));
  channel_c_free(error);
  pump(fixture, 2, 1500);

  assert_int_equal(credential_connects, 0);
  assert_int_equal(update_count, 0);
  assert_int_equal(hub_service_keychain_hub_key(hub_service_pin_address(fixture->service), key, sizeof(key)), 0);
  assert_string_equal(key, FAKE_HUB_KEY);
}

static void test_refused_address_is_not_dialed(void **state) {
  hub_service_options_t options;
  hub_service_t *service;
  channel_c_values_t *values = NULL;
  char *error = NULL;
  char *body = NULL;
  (void)state;

  memset(&options, 0, sizeof(options));
  options.address = "ws://hub.example.com:1997";
  service = hub_service_new(&options, &error);
  assert_non_null(service);
  assert_int_equal(hub_service_start(service, &error), -1);
  assert_non_null(strstr(error, "unencrypted"));
  channel_c_free(error);
  error = NULL;
  assert_int_equal(hub_service_poll(service), 0); /* idle */
  assert_int_equal(hub_service_send(service, "x", "1", &body, &error), -1);
  assert_non_null(strstr(error, "unencrypted"));
  channel_c_free(error);
  error = NULL;
  assert_int_equal(hub_service_values(service, "x", "1", &values, &error), -1);
  assert_non_null(strstr(error, "unencrypted"));
  channel_c_free(error);
  assert_int_equal(access(test_auth_path, F_OK), -1); /* signed nothing */
  hub_service_free(service);
}

static void test_handlers_see_the_caller(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;
  char *reply = NULL;

  start_hub(fixture, INFO_PROVING);
  hub_service_post(fixture->service, "who", who_handler, NULL);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 2, 2000);
  assert_non_null(hub_sender);

  assert_int_equal(channel_c_sender_send(hub_sender, "who", NULL,
                                         "{\"hub\":{\"caller\":{\"key\":\"K\",\"device\":{\"id\":\"d\",\"name\":\"Mac "
                                         "Studio\"},\"groups\":[\"owners\"],\"owner\":true},\"hubKey\":\"" FAKE_HUB_KEY "\"}}",
                                         &reply, &error),
                   0);
  assert_string_equal(reply, "\"K|Mac Studio|1\"");
  channel_c_free(reply);

  /* a call without hub context has no caller */
  assert_int_equal(channel_c_sender_send(hub_sender, "who", NULL, NULL, &reply, &error), 0);
  assert_string_equal(reply, "null");
  channel_c_free(reply);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_sends_a_token_only_after_the_proof, setup, teardown),
      cmocka_unit_test_setup_teardown(test_handshake_builds_the_headers, setup, teardown),
      cmocka_unit_test_setup_teardown(test_every_connect_asks_again, setup, teardown),
      cmocka_unit_test_setup_teardown(test_no_proof_gets_nothing, setup, teardown),
      cmocka_unit_test_setup_teardown(test_forged_proof_gets_nothing, setup, teardown),
      cmocka_unit_test_setup_teardown(test_no_challenge_gets_nothing, setup, teardown),
      cmocka_unit_test_setup_teardown(test_bad_challenge_gets_nothing, setup, teardown),
      cmocka_unit_test_setup_teardown(test_stop_ends_the_retrying, setup, teardown),
      cmocka_unit_test_setup_teardown(test_another_proven_key_gets_nothing, setup, teardown),
      cmocka_unit_test_setup_teardown(test_refused_address_is_not_dialed, setup, teardown),
      cmocka_unit_test_setup_teardown(test_handlers_see_the_caller, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
