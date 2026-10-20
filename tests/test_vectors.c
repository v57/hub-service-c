/* Device layer test vectors (Docs/Devices/vectors.json): exact auth tokens. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>
#include <yyjson.h>

#include "hub-service-c/keychain.h"

#ifndef HUB_DEVICE_VECTORS
#error "HUB_DEVICE_VECTORS must point at Docs/Devices/vectors.json"
#endif

static yyjson_doc *vectors;

static const char *vector(const char *pointer) {
  yyjson_val *value = yyjson_ptr_get(yyjson_doc_get_root(vectors), pointer);
  if (!yyjson_is_str(value)) fail_msg("missing vector %s", pointer);
  return yyjson_get_str(value);
}

static long long vector_int(const char *pointer) {
  yyjson_val *value = yyjson_ptr_get(yyjson_doc_get_root(vectors), pointer);
  if (!yyjson_is_int(value)) fail_msg("missing vector %s", pointer);
  return (long long)yyjson_get_sint(value);
}

static int load_vectors(void **state) {
  (void)state;
  vectors = yyjson_read_file(HUB_DEVICE_VECTORS, 0, NULL, NULL);
  return vectors ? 0 : -1;
}

static int free_vectors(void **state) {
  (void)state;
  yyjson_doc_free(vectors);
  return 0;
}

static void test_auth_v0(void **state) {
  (void)state;
  char token[512];
  assert_int_equal(hub_service_auth_token(vector("/keys/service/keyFile"), NULL, vector_int("/auth/expiry"), token,
                                          sizeof(token)),
                   0);
  assert_string_equal(token, vector("/auth/v0/header"));
}

static void test_auth_v1(void **state) {
  (void)state;
  char token[512];
  assert_int_equal(hub_service_auth_token(vector("/keys/service/keyFile"), vector("/keys/hub/publicKey"),
                                          vector_int("/auth/expiry"), token, sizeof(token)),
                   0);
  assert_string_equal(token, vector("/auth/v1/header"));
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_auth_v0),
      cmocka_unit_test(test_auth_v1),
  };
  return cmocka_run_group_tests(tests, load_vectors, free_vectors);
}
