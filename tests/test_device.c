/* Device key file, certificate renewal and the `device` connect header. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <setjmp.h>
#include <cmocka.h>
#include <yyjson.h>

#include "hub-service-c/device.h"
#include "hub-service-c/keychain.h"
#include "hub_service_internal.h"

static char test_dir[256];
static char device_path[320];
static char auth_path[320];

static int setup(void **state) {
  (void)state;
  snprintf(test_dir, sizeof(test_dir), "/tmp/hub_service_c_device_%ld", (long)getpid());
  mkdir(test_dir, 0700);
  /* a directory that doesn't exist yet: the key file creates it 0700 */
  snprintf(device_path, sizeof(device_path), "%s/hub/device.key", test_dir);
  snprintf(auth_path, sizeof(auth_path), "%s/auth", test_dir);
  hub_service_device_set_path(device_path);
  hub_service_keychain_set_path(auth_path);
  return 0;
}

static int teardown(void **state) {
  char cmd[512];
  (void)state;
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  system(cmd);
  hub_service_device_set_path(NULL);
  hub_service_keychain_set_path(NULL);
  return 0;
}

/* Decode the certificate payload JSON of a `device` header. */
static yyjson_doc *certificate_payload(const char *header) {
  char b64[2048];
  unsigned char raw[2048];
  size_t n = (size_t)(strchr(header, '.') - header);
  size_t i;
  int decoded;
  memcpy(b64, header, n);
  for (i = 0; i < n; i++) {
    if (b64[i] == '-') b64[i] = '+';
    if (b64[i] == '_') b64[i] = '/';
  }
  while (n % 4) b64[n++] = '=';
  b64[n] = '\0';
  decoded = EVP_DecodeBlock(raw, (const unsigned char *)b64, (int)n);
  assert_true(decoded > 0);
  while (decoded > 0 && raw[decoded - 1] == '\0') decoded--;
  return yyjson_read((const char *)raw, (size_t)decoded, 0);
}

static void test_key_file_is_created_private(void **state) {
  (void)state;
  char pub1[128];
  char pub2[128];
  char dir[400];
  struct stat st;

  assert_int_equal(hub_service_device_public_key(pub1, sizeof(pub1)), 0);
  assert_int_equal(stat(device_path, &st), 0);
  assert_int_equal(st.st_mode & 0777, 0600);
  snprintf(dir, sizeof(dir), "%s/hub", test_dir);
  assert_int_equal(stat(dir, &st), 0);
  assert_int_equal(st.st_mode & 0777, 0700);

  assert_int_equal(hub_service_device_public_key(pub2, sizeof(pub2)), 0);
  assert_string_equal(pub1, pub2);
}

static void test_environment_override(void **state) {
  (void)state;
  char path[1024];
  char expected[400];
  hub_service_device_set_path(NULL);
  snprintf(expected, sizeof(expected), "%s/env.key", test_dir);
  setenv("HUB_DEVICE_KEY", expected, 1);
  assert_int_equal(hub_service_device_key_path(path, sizeof(path)), 0);
  assert_string_equal(path, expected);
  unsetenv("HUB_DEVICE_KEY");
  if (getuid() != 0) {
    snprintf(expected, sizeof(expected), "%s/.hub/device.key", getenv("HOME"));
    assert_int_equal(hub_service_device_key_path(path, sizeof(path)), 0);
    assert_string_equal(path, expected);
  }
}

static void test_certificate_renews_with_a_day_left(void **state) {
  (void)state;
  hub_service_options_t options;
  hub_service_t *service;
  char *first;
  long long now = 1792500000;
  yyjson_doc *doc;

  memset(&options, 0, sizeof(options));
  options.instance = "s3-local/Backup Disk";
  options.device_name = "Mac Studio";
  options.parent = "Host";
  service = hub_service_new(&options, NULL);

  first = strdup(hub_service_current_certificate(service, now));
  /* 2 days left: kept */
  assert_string_equal(hub_service_current_certificate(service, now + 5 * 86400), first);
  /* 12 hours left: renewed, issued at the new time */
  assert_string_not_equal(hub_service_current_certificate(service, now + 6 * 86400 + 43200), first);
  doc = certificate_payload(hub_service_current_certificate(service, now + 6 * 86400 + 43200));
  assert_int_equal(yyjson_get_sint(yyjson_obj_get(yyjson_doc_get_root(doc), "iat")), now + 6 * 86400 + 43200);
  yyjson_doc_free(doc);

  doc = certificate_payload(first);
  {
    yyjson_val *root = yyjson_doc_get_root(doc);
    char service_key[128];
    char device_key[128];
    assert_int_equal(hub_service_keychain_public_key(service_key, sizeof(service_key)), 0);
    assert_int_equal(hub_service_device_public_key(device_key, sizeof(device_key)), 0);
    assert_int_equal(yyjson_get_sint(yyjson_obj_get(root, "v")), 1);
    assert_string_equal(yyjson_get_str(yyjson_obj_get(root, "service")), service_key);
    assert_string_equal(yyjson_get_str(yyjson_obj_get(root, "device")), device_key);
    assert_string_equal(yyjson_get_str(yyjson_obj_get(root, "instance")), "s3-local/Backup Disk");
    assert_string_equal(yyjson_get_str(yyjson_obj_get(root, "deviceName")), "Mac Studio");
    assert_string_equal(yyjson_get_str(yyjson_obj_get(root, "platform")), hub_service_device_platform());
    assert_string_equal(yyjson_get_str(yyjson_obj_get(root, "parent")), "Host");
    assert_int_equal(yyjson_get_sint(yyjson_obj_get(root, "exp")), now + HUB_SERVICE_CERTIFICATE_LIFETIME);
  }
  yyjson_doc_free(doc);
  free(first);
  hub_service_free(service);
}

static int noop_handler(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  (void)request;
  (void)out_error;
  *out_body_json = NULL;
  return 0;
}

static const char *instance_of(hub_service_t *service) {
  static char instance[256];
  yyjson_doc *doc = certificate_payload(hub_service_current_certificate(service, 1792500000));
  snprintf(instance, sizeof(instance), "%s", yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "instance")));
  yyjson_doc_free(doc);
  return instance;
}

static void test_instance_defaults(void **state) {
  (void)state;
  hub_service_options_t options;
  hub_service_t *service;
  char cwd[1024];
  char saved[1024];

  /* the basename of the working directory */
  assert_non_null(getcwd(saved, sizeof(saved)));
  snprintf(cwd, sizeof(cwd), "%s/s3-local", test_dir);
  mkdir(cwd, 0700);
  assert_int_equal(chdir(cwd), 0);
  service = hub_service_new(NULL, NULL);
  hub_service_post(service, "s3/read", noop_handler, NULL);
  assert_string_equal(instance_of(service), "s3-local");
  hub_service_free(service);
  assert_int_equal(chdir(saved), 0);

  /* the profile name */
  memset(&options, 0, sizeof(options));
  options.name = "Backup Disk";
  service = hub_service_new(&options, NULL);
  assert_string_equal(instance_of(service), "Backup Disk");
  hub_service_free(service);

  /* $HUB_INSTANCE (the launcher's app name) wins over the name */
  setenv("HUB_INSTANCE", "launcher-app", 1);
  service = hub_service_new(&options, NULL);
  assert_string_equal(instance_of(service), "launcher-app");
  hub_service_free(service);

  /* the option wins over everything */
  options.instance = "s3-local/Backup Disk";
  service = hub_service_new(&options, NULL);
  assert_string_equal(instance_of(service), "s3-local/Backup Disk");
  hub_service_free(service);
  unsetenv("HUB_INSTANCE");
}

static void test_environment_defaults(void **state) {
  (void)state;
  hub_service_options_t options;
  hub_service_t *service;
  hub_service_connect_headers_t headers;
  yyjson_doc *doc;

  setenv("HUB_DEVICE_NAME", "Named", 1);
  setenv("HUB_DEVICE_PARENT", "Host", 1);
  service = hub_service_new(NULL, NULL);
  doc = certificate_payload(hub_service_current_certificate(service, 1792500000));
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "deviceName")), "Named");
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "parent")), "Host");
  yyjson_doc_free(doc);
  hub_service_free(service);
  unsetenv("HUB_DEVICE_NAME");
  unsetenv("HUB_DEVICE_PARENT");

  /* HUB_DEVICE=off turns device mode off */
  setenv("HUB_DEVICE", "off", 1);
  service = hub_service_new(NULL, NULL);
  assert_int_equal(hub_service_build_connect_headers(service, &headers), 0);
  assert_int_equal(headers.count, 2);
  hub_service_free(service);
  unsetenv("HUB_DEVICE");

  /* a caller-provided device key: no key file is read or created */
  unlink(device_path);
  memset(&options, 0, sizeof(options));
  options.device_key = "MC4CAQAwBQYDK2VwBCIEIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDMCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";
  service = hub_service_new(&options, NULL);
  doc = certificate_payload(hub_service_current_certificate(service, 1792500000));
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "device")),
                      "MCowBQYDK2VwAyEA7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=");
  yyjson_doc_free(doc);
  hub_service_free(service);
  assert_int_equal(access(device_path, F_OK), -1);
}

static void test_pin_addresses_are_normalized(void **state) {
  (void)state;
  char *address;
  hub_service_options_t options;
  hub_service_t *service;

  address = hub_service_normalize_address("1997");
  assert_string_equal(address, "ws://localhost:1997");
  free(address);
  address = hub_service_normalize_address("WSS://Hub.Example.COM/");
  assert_string_equal(address, "wss://hub.example.com");
  free(address);
  address = hub_service_normalize_address("ws://Host:80/Path/");
  assert_string_equal(address, "ws://host:80/Path");
  free(address);

  /* the default hub: dialed at 127.0.0.1, pinned as ws://localhost:1997 */
  unsetenv("HUB");
  service = hub_service_new(NULL, NULL);
  assert_string_equal(hub_service_address(service), "ws://127.0.0.1:1997");
  assert_string_equal(hub_service_pin_address(service), "ws://localhost:1997");
  hub_service_free(service);

  setenv("HUB", "1998", 1);
  service = hub_service_new(NULL, NULL);
  assert_string_equal(hub_service_pin_address(service), "ws://localhost:1998");
  hub_service_free(service);
  unsetenv("HUB");

  memset(&options, 0, sizeof(options));
  options.address = "ws://Example:2000/";
  service = hub_service_new(&options, NULL);
  assert_string_equal(hub_service_pin_address(service), "ws://example:2000");
  hub_service_free(service);
}

static void test_connect_headers_carry_the_certificate(void **state) {
  (void)state;
  hub_service_options_t options;
  hub_service_t *service;
  hub_service_connect_headers_t headers;

  service = hub_service_new(NULL, NULL);
  assert_int_equal(hub_service_build_connect_headers(service, &headers), 0);
  assert_int_equal(headers.count, 3);
  assert_string_equal(headers.items[2].name, "device");
  assert_non_null(strchr(headers.items[2].value, '.'));
  hub_service_connect_headers_free(&headers);
  hub_service_free(service);

  memset(&options, 0, sizeof(options));
  options.disable_device = 1;
  service = hub_service_new(&options, NULL);
  assert_int_equal(hub_service_build_connect_headers(service, &headers), 0);
  assert_int_equal(headers.count, 2);
  hub_service_connect_headers_free(&headers);
  hub_service_free(service);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_key_file_is_created_private, setup, teardown),
      cmocka_unit_test_setup_teardown(test_environment_override, setup, teardown),
      cmocka_unit_test_setup_teardown(test_certificate_renews_with_a_day_left, setup, teardown),
      cmocka_unit_test_setup_teardown(test_instance_defaults, setup, teardown),
      cmocka_unit_test_setup_teardown(test_environment_defaults, setup, teardown),
      cmocka_unit_test_setup_teardown(test_pin_addresses_are_normalized, setup, teardown),
      cmocka_unit_test_setup_teardown(test_connect_headers_carry_the_certificate, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
