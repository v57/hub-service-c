/* Keychain unit tests: token shape, public key round-trip, auth query. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <setjmp.h>
#include <cmocka.h>

#include "hub-service-c/keychain.h"

/* TS-generated test key (hub-pro-support contract) and its public key. */
#define TS_TEST_AUTH                                                          \
  "MC4CAQAwBQYDK2VwBCIEINguo0cc0FACJ0oRV3V/+ZqIyj04ON5wdMJGH4a/do8CM"       \
  "CowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ="
#define TS_TEST_PUB                                                           \
  "MCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ="

static char test_dir[256];
static char test_auth_path[320];

static int setup_test(void **state) {
  (void)state;
  snprintf(test_dir, sizeof(test_dir), "/tmp/hub_service_c_test_%ld", (long)getpid());
  mkdir(test_dir, 0700);
  snprintf(test_auth_path, sizeof(test_auth_path), "%s/auth", test_dir);
  hub_service_keychain_set_path(test_auth_path);
  return 0;
}

static int teardown_test(void **state) {
  (void)state;
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  system(cmd);
  hub_service_keychain_set_path(NULL);
  return 0;
}

static void test_sign_token_shape(void **state) {
  (void)state;
  char token[512];
  assert_int_equal(hub_service_keychain_sign(token, sizeof(token)), 0);

  /* key.<pub>.<sig>.<decimal-expiry> — 4 dot-separated parts. */
  char *parts[4];
  int count = 0;
  char *copy = strdup(token);
  char *save = NULL;
  for (char *p = strtok_r(copy, ".", &save); p && count < 4; p = strtok_r(NULL, ".", &save)) {
    parts[count++] = p;
  }
  assert_int_equal(count, 4);
  assert_string_equal(parts[0], "key");
  assert_int_equal(strlen(parts[1]), 60); /* base64 of 44-byte SPKI */
  assert_int_equal(strlen(parts[2]), 88); /* base64 of 64-byte sig */
  /* expiry is decimal digits */
  for (const char *p = parts[3]; *p; p++) {
    assert_true(*p >= '0' && *p <= '9');
  }
  free(copy);
}

static void test_public_key_round_trip(void **state) {
  (void)state;
  char pub1[128], pub2[128];
  assert_int_equal(hub_service_keychain_public_key(pub1, sizeof(pub1)), 0);
  /* file exists now */
  FILE *f = fopen(test_auth_path, "rb");
  assert_non_null(f);
  char buf[256];
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = '\0';
  assert_int_equal(n, 124); /* 92 bytes -> 124 base64 chars */
  /* reload gives the same public key */
  assert_int_equal(hub_service_keychain_public_key(pub2, sizeof(pub2)), 0);
  assert_string_equal(pub1, pub2);
  /* token pub matches public_key() */
  char token[512];
  assert_int_equal(hub_service_keychain_sign(token, sizeof(token)), 0);
  assert_memory_equal(token + 4, pub1, strlen(pub1)); /* "key." prefix */
}

static void test_ts_generated_key_reproduces_public_key(void **state) {
  (void)state;
  FILE *f = fopen(test_auth_path, "wb");
  assert_non_null(f);
  fputs(TS_TEST_AUTH, f);
  fclose(f);

  char pub[128];
  assert_int_equal(hub_service_keychain_public_key(pub, sizeof(pub)), 0);
  assert_string_equal(pub, TS_TEST_PUB);

  char token[512];
  assert_int_equal(hub_service_keychain_sign(token, sizeof(token)), 0);
  assert_memory_equal(token + 4, TS_TEST_PUB, strlen(TS_TEST_PUB));
}

static void test_auth_query_shape(void **state) {
  (void)state;
  char query[1024];
  assert_int_equal(hub_service_keychain_auth_query(query, sizeof(query)), 0);
  assert_memory_equal(query, "?auth=key.", 9);
  /* has the &v=0 suffix and no raw '+' '/' '=' (percent-encoded) */
  assert_true(strstr(query, "&v=0") != NULL);
  assert_true(strstr(query, "+") == NULL);
  assert_true(strstr(query, "=") == NULL || strstr(query, "%3D") != NULL);
}

static void test_hub_key_pins(void **state) {
  (void)state;
  char key[128];
  char path[400];
  assert_int_equal(hub_service_keychain_hub_key("ws://127.0.0.1:1997", key, sizeof(key)), -1);
  assert_string_equal(key, "");

  assert_int_equal(hub_service_keychain_pin_hub_key("ws://127.0.0.1:1997", "HUBKEY1"), 0);
  assert_int_equal(hub_service_keychain_pin_hub_key("ws://example:1997", "HUBKEY2"), 0);
  assert_int_equal(hub_service_keychain_hub_key("ws://127.0.0.1:1997", key, sizeof(key)), 0);
  assert_string_equal(key, "HUBKEY1");

  /* stored beside the key file */
  snprintf(path, sizeof(path), "%s/hubs.json", test_dir);
  assert_int_equal(access(path, F_OK), 0);

  assert_int_equal(hub_service_keychain_forget_hub_key("ws://127.0.0.1:1997"), 0);
  assert_int_equal(hub_service_keychain_hub_key("ws://127.0.0.1:1997", key, sizeof(key)), -1);
  assert_int_equal(hub_service_keychain_hub_key("ws://example:1997", key, sizeof(key)), 0);
  assert_string_equal(key, "HUBKEY2");
}

static void test_sign_for_hub_binds_the_hub_key(void **state) {
  (void)state;
  FILE *f = fopen(test_auth_path, "wb");
  assert_non_null(f);
  fputs(TS_TEST_AUTH, f);
  fclose(f);

  char token[512];
  char expected[512];
  assert_int_equal(hub_service_keychain_sign_for_hub("HUBKEY", token, sizeof(token)), 0);
  const char *expiry = strrchr(token, '.') + 1;
  long long value = atoll(expiry);
  long long now = (long long)time(NULL);
  assert_true(value >= now + HUB_SERVICE_AUTH_EXPIRY - 2 && value <= now + HUB_SERVICE_AUTH_EXPIRY);
  assert_int_equal(hub_service_auth_token(TS_TEST_AUTH, "HUBKEY", value, expected, sizeof(expected)), 0);
  assert_string_equal(token, expected);
  /* a v0 token for the same expiry has another signature */
  assert_int_equal(hub_service_auth_token(TS_TEST_AUTH, NULL, value, expected, sizeof(expected)), 0);
  assert_string_not_equal(token, expected);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_sign_token_shape, setup_test, teardown_test),
      cmocka_unit_test_setup_teardown(test_public_key_round_trip, setup_test, teardown_test),
      cmocka_unit_test_setup_teardown(test_ts_generated_key_reproduces_public_key, setup_test,
                                      teardown_test),
      cmocka_unit_test_setup_teardown(test_auth_query_shape, setup_test, teardown_test),
      cmocka_unit_test_setup_teardown(test_hub_key_pins, setup_test, teardown_test),
      cmocka_unit_test_setup_teardown(test_sign_for_hub_binds_the_hub_key, setup_test, teardown_test),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
