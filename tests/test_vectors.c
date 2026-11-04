/* Device layer test vectors (Docs/Devices/vectors.json): exact auth tokens. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>
#include <yyjson.h>

#include "hub-service-c/device.h"
#include "hub-service-c/hub_proof.h"
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

static void test_auth_v1(void **state) {
  (void)state;
  char token[512];
  assert_int_equal(hub_service_auth_token(vector("/keys/service/keyFile"), vector("/keys/hub/publicKey"),
                                          vector("/auth/nonce"), vector_int("/auth/expiry"), token, sizeof(token)),
                   0);
  assert_string_equal(token, vector("/auth/v1/header"));
}

static void test_hub_info_proof(void **state) {
  (void)state;
  hub_service_hub_info_t info;
  char *data = hub_service_hub_info_signed_data(vector("/keys/hub/publicKey"), vector("/hubInfo/nonce"));
  assert_string_equal(data, vector("/hubInfo/signedData"));
  free(data);

  memset(&info, 0, sizeof(info));
  snprintf(info.key, sizeof(info.key), "%s", vector("/keys/hub/publicKey"));
  snprintf(info.proof, sizeof(info.proof), "%s", vector("/hubInfo/proof"));
  snprintf(info.challenge, sizeof(info.challenge), "c");
  assert_true(hub_service_hub_info_proves(&info, vector("/hubInfo/nonce")));
  assert_false(hub_service_hub_info_proves(&info, "another-nonce-another-nonce"));
  snprintf(info.key, sizeof(info.key), "%s", vector("/keys/service/publicKey"));
  assert_false(hub_service_hub_info_proves(&info, vector("/hubInfo/nonce")));
  snprintf(info.key, sizeof(info.key), "not base64!");
  assert_false(hub_service_hub_info_proves(&info, vector("/hubInfo/nonce")));
}

static void test_transport(void **state) {
  (void)state;
  yyjson_val *cases = yyjson_ptr_get(yyjson_doc_get_root(vectors), "/transport");
  yyjson_val *entry;
  size_t index;
  size_t max;
  assert_true(yyjson_arr_size(cases) > 0);
  yyjson_arr_foreach(cases, index, max, entry) {
    const char *url = yyjson_get_str(yyjson_obj_get(entry, "url"));
    const char *expected = yyjson_get_str(yyjson_obj_get(entry, "transport"));
    const char *got = hub_service_transport_name(hub_service_transport_of(url));
    if (strcmp(got, expected) != 0) fail_msg("%s: %s, want %s", url, got, expected);
  }
  assert_int_equal(hub_service_transport_of("1997"), HUB_SERVICE_TRANSPORT_LOOPBACK);
  assert_int_equal(hub_service_transport_of("hub:1997"), HUB_SERVICE_TRANSPORT_REFUSED);
  assert_int_equal(hub_service_transport_of("WS://LOCALHOST.:1997"), HUB_SERVICE_TRANSPORT_LOOPBACK);
  assert_int_equal(hub_service_transport_of("ws://me@10.0.0.2:1997/x"), HUB_SERVICE_TRANSPORT_LOCAL_NETWORK);
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
  for (int index = 0; index < 5; index++) {
    char pointer[64];
    char hub_key[128], device_key[128], code_value[128];
    snprintf(pointer, sizeof(pointer), "/safetyCode/cases/%d/hubKey", index);
    snprintf(hub_key, sizeof(hub_key), "%s", vector(pointer));
    snprintf(pointer, sizeof(pointer), "/safetyCode/cases/%d/deviceKey", index);
    snprintf(device_key, sizeof(device_key), "%s", vector(pointer));
    snprintf(pointer, sizeof(pointer), "/safetyCode/cases/%d/codeValue", index);
    snprintf(code_value, sizeof(code_value), "%s", vector(pointer));
    assert_int_equal(hub_service_device_safety_code(hub_key, device_key, code_value, code, sizeof(code)), 0);
    snprintf(pointer, sizeof(pointer), "/safetyCode/cases/%d/code", index);
    assert_string_equal(code, vector(pointer));
  }
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
      cmocka_unit_test(test_auth_v1),
      cmocka_unit_test(test_hub_info_proof),
      cmocka_unit_test(test_transport),
      cmocka_unit_test(test_certificate),
      cmocka_unit_test(test_child_certificate),
      cmocka_unit_test(test_device_id_and_safety_code),
      cmocka_unit_test(test_caller),
  };
  return cmocka_run_group_tests(tests, load_vectors, free_vectors);
}
