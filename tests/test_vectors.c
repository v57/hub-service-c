/* Device layer test vectors (Docs/Devices/vectors.json): exact auth tokens. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>
#include <yyjson.h>

#include "hub-service-c/device.h"
#include "hub-service-c/hub_service_c.h"
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

static void check_certificate(const char *name, const char *instance, const char *device_name, const char *platform,
                              const char *parent) {
  char pointer[128];
  hub_service_certificate_t certificate;
  char *json;
  char *header;

  memset(&certificate, 0, sizeof(certificate));
  certificate.service = vector("/keys/service/publicKey");
  certificate.instance = instance;
  certificate.device_name = device_name;
  certificate.platform = platform;
  certificate.parent = parent;
  certificate.iat = 1792500000;
  certificate.exp = 1793104800;

  /* device NULL: taken from the signing key */
  header = hub_service_certificate_encode(vector("/keys/device/keyFile"), &certificate);
  assert_non_null(header);
  snprintf(pointer, sizeof(pointer), "/%s/header", name);
  assert_string_equal(header, vector(pointer));
  free(header);

  certificate.device = vector("/keys/device/publicKey");
  json = hub_service_certificate_json(&certificate);
  snprintf(pointer, sizeof(pointer), "/%s/json", name);
  assert_string_equal(json, vector(pointer));
  free(json);
}

static void test_certificate(void **state) {
  (void)state;
  check_certificate("certificate", "s3-local/Backup Disk", "Mac Studio", "macos", NULL);
}

static void test_child_certificate(void **state) {
  (void)state;
  check_certificate("childCertificate", "builder", "builder", "linux", "Mac Studio");
}

static void test_device_id_and_safety_code(void **state) {
  (void)state;
  char id[64];
  char code[16];
  assert_int_equal(hub_service_device_id(vector("/keys/device/publicKey"), id, sizeof(id)), 0);
  assert_string_equal(id, vector("/keys/device/deviceId"));
  assert_int_equal(hub_service_device_safety_code(vector("/keys/device/publicKey"), code, sizeof(code)), 0);
  assert_string_equal(code, vector("/keys/device/safetyCode"));
}

static void test_caller(void **state) {
  (void)state;
  char *context = yyjson_val_write(yyjson_ptr_get(yyjson_doc_get_root(vectors), "/caller/context"), 0, NULL);
  hub_service_caller_t *caller = hub_service_caller(context);
  assert_non_null(caller);
  assert_string_equal(caller->key, vector("/keys/service/publicKey"));
  assert_string_equal(caller->device_id, vector("/keys/device/deviceId"));
  assert_string_equal(caller->device_name, "Mac Studio");
  assert_int_equal(caller->group_count, 1);
  assert_string_equal(caller->groups[0], "owners");
  assert_true(caller->owner);
  assert_null(caller->via);
  assert_null(caller->claimed_json);
  assert_string_equal(caller->hub_key, vector("/keys/hub/publicKey"));
  hub_service_caller_free(caller);
  free(context);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_auth_v0),
      cmocka_unit_test(test_auth_v1),
      cmocka_unit_test(test_certificate),
      cmocka_unit_test(test_child_certificate),
      cmocka_unit_test(test_device_id_and_safety_code),
      cmocka_unit_test(test_caller),
  };
  return cmocka_run_group_tests(tests, load_vectors, free_vectors);
}
