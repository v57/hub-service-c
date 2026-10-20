/*
 * Device key and service certificates (Docs/Devices/protocol.md sections 1
 * and 3).
 */

#include "hub-service-c/device.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <yyjson.h>

#include "crypto.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

static char device_path_override[1024] = {0};

void hub_service_device_set_path(const char *path) {
  if (path) {
    snprintf(device_path_override, sizeof(device_path_override), "%s", path);
  } else {
    device_path_override[0] = '\0';
  }
}

int hub_service_device_key_path(char *out, size_t out_size) {
  const char *env = getenv("HUB_DEVICE_KEY");
  const char *home = getenv("HOME");
  int n;
  if (device_path_override[0]) {
    n = snprintf(out, out_size, "%s", device_path_override);
  } else if (env && env[0]) {
    n = snprintf(out, out_size, "%s", env);
  } else if (getuid() == 0) {
    n = snprintf(out, out_size, "/var/lib/hub/device.key");
  } else if (home && home[0]) {
    n = snprintf(out, out_size, "%s/.hub/device.key", home);
  } else {
    out[0] = '\0';
    return -1;
  }
  return n < (int)out_size ? 0 : -1;
}

static int load_device_key(unsigned char key[HS_KEY_BYTES]) {
  char path[1024];
  if (hub_service_device_key_path(path, sizeof(path)) != 0) return -1;
  return hs_key_file_load(path, 1, 0600, 1, key);
}

int hub_service_device_public_key(char *out, size_t out_size) {
  unsigned char key[HS_KEY_BYTES];
  char pub[HS_SPKI_B64_SIZE];
  if (load_device_key(key) != 0 || hs_key_public(key, pub) != 0 ||
      snprintf(out, out_size, "%s", pub) >= (int)out_size) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

static int spki_digest(const char *spki, char hex[65]) {
  unsigned char der[HS_PUBLIC_DER_LENGTH + 4];
  size_t len = 0;
  if (!spki || hs_b64_decode(spki, der, sizeof(der), &len) != 0) return -1;
  return hs_sha256_hex(der, len, hex);
}

int hub_service_device_id(const char *spki, char *out, size_t out_size) {
  char hex[65];
  if (out_size < 33 || spki_digest(spki, hex) != 0) {
    if (out_size) out[0] = '\0';
    return -1;
  }
  memcpy(out, hex, 32);
  out[32] = '\0';
  return 0;
}

int hub_service_device_safety_code(const char *spki, char *out, size_t out_size) {
  char hex[65];
  char prefix[9];
  unsigned long n;
  if (out_size < 8 || spki_digest(spki, hex) != 0) {
    if (out_size) out[0] = '\0';
    return -1;
  }
  memcpy(prefix, hex, 8);
  prefix[8] = '\0';
  n = strtoul(prefix, NULL, 16) % 1000000UL;
  snprintf(out, out_size, "%03lu %03lu", n / 1000, n % 1000);
  return 0;
}

const char *hub_service_device_platform(void) {
#if defined(__APPLE__)
#if TARGET_OS_VISION
  return "visionos";
#elif TARGET_OS_WATCH
  return "watchos";
#elif TARGET_OS_TV
  return "tvos";
#elif TARGET_OS_IPHONE
  return "ios";
#else
  return "macos";
#endif
#elif defined(__ANDROID__)
  return "android";
#elif defined(__linux__)
  return "linux";
#elif defined(_WIN32)
  return "windows";
#else
  return "other";
#endif
}

int hub_service_device_mode_enabled(void) {
  const char *value = getenv("HUB_DEVICE");
  if (!value) return 1;
  return !(strcasecmp(value, "0") == 0 || strcasecmp(value, "off") == 0 || strcasecmp(value, "false") == 0 ||
           strcasecmp(value, "no") == 0);
}

/* macOS computer name (scutil --get ComputerName), cached; "" elsewhere. */
static const char *computer_name(void) {
  static int loaded = 0;
  static char name[256];
  if (!loaded) {
    loaded = 1;
    name[0] = '\0';
#if defined(__APPLE__) && !TARGET_OS_IPHONE
    {
      FILE *pipe = popen("scutil --get ComputerName 2>/dev/null", "r");
      if (pipe) {
        size_t n = fread(name, 1, sizeof(name) - 1, pipe);
        name[n] = '\0';
        while (n > 0 && (name[n - 1] == '\n' || name[n - 1] == '\r' || name[n - 1] == ' ')) name[--n] = '\0';
        if (pclose(pipe) != 0) name[0] = '\0';
      }
    }
#endif
  }
  return name;
}

int hub_service_device_default_name(char *out, size_t out_size) {
  const char *env = getenv("HUB_DEVICE_NAME");
  if (env && env[0]) {
    snprintf(out, out_size, "%s", env);
    return 0;
  }
  if (computer_name()[0]) {
    snprintf(out, out_size, "%s", computer_name());
    return 0;
  }
  return hub_service_device_host_name(out, out_size);
}

int hub_service_device_host_name(char *out, size_t out_size) {
  size_t n;
  if (gethostname(out, out_size) != 0) {
    out[0] = '\0';
    return -1;
  }
  out[out_size - 1] = '\0';
  n = strlen(out);
  if (n > 6 && strcmp(out + n - 6, ".local") == 0) out[n - 6] = '\0';
  return 0;
}

char *hub_service_certificate_json(const hub_service_certificate_t *certificate) {
  yyjson_mut_doc *doc;
  yyjson_mut_val *root;
  char *json;

  if (!certificate || !certificate->device || !certificate->service || !certificate->instance) return NULL;
  doc = yyjson_mut_doc_new(NULL);
  if (!doc) return NULL;
  root = yyjson_mut_obj(doc);
  yyjson_mut_doc_set_root(doc, root);
  yyjson_mut_obj_add_int(doc, root, "v", 1);
  yyjson_mut_obj_add_str(doc, root, "device", certificate->device);
  yyjson_mut_obj_add_str(doc, root, "service", certificate->service);
  yyjson_mut_obj_add_str(doc, root, "instance", certificate->instance);
  if (certificate->device_name) yyjson_mut_obj_add_str(doc, root, "deviceName", certificate->device_name);
  if (certificate->platform) yyjson_mut_obj_add_str(doc, root, "platform", certificate->platform);
  if (certificate->parent) yyjson_mut_obj_add_str(doc, root, "parent", certificate->parent);
  if (certificate->hub) yyjson_mut_obj_add_str(doc, root, "hub", certificate->hub);
  yyjson_mut_obj_add_sint(doc, root, "iat", certificate->iat);
  yyjson_mut_obj_add_sint(doc, root, "exp", certificate->exp);
  json = yyjson_mut_write(doc, 0, NULL);
  yyjson_mut_doc_free(doc);
  return json;
}

static char *encode_with_key(const unsigned char key[HS_KEY_BYTES], const hub_service_certificate_t *certificate) {
  hub_service_certificate_t filled = *certificate;
  char device[HS_SPKI_B64_SIZE];
  char sig[HS_SIG_B64_SIZE];
  char *json;
  char *payload;
  char *header = NULL;
  size_t size;

  if (!filled.device) {
    if (hs_key_public(key, device) != 0) return NULL;
    filled.device = device;
  }
  json = hub_service_certificate_json(&filled);
  if (!json) return NULL;
  payload = hs_b64url_encode((const unsigned char *)json, strlen(json));
  free(json);
  if (!payload) return NULL;
  if (hs_key_sign(key, payload, strlen(payload), sig) == 0) {
    size = strlen(payload) + 1 + strlen(sig) + 1;
    header = (char *)malloc(size);
    if (header) snprintf(header, size, "%s.%s", payload, sig);
  }
  free(payload);
  return header;
}

char *hub_service_certificate_encode(const char *device_key_file, const hub_service_certificate_t *certificate) {
  unsigned char key[HS_KEY_BYTES];
  if (!device_key_file || !certificate || hs_key_parse(device_key_file, key) != 0) return NULL;
  return encode_with_key(key, certificate);
}

/* Cut text to at most max bytes without splitting a UTF-8 sequence. */
static void truncate_utf8(char *text, size_t max) {
  size_t n = strlen(text);
  if (n <= max) return;
  n = max;
  while (n > 0 && ((unsigned char)text[n] & 0xC0) == 0x80) n--;
  text[n] = '\0';
}

static char *issue_certificate(const unsigned char key[HS_KEY_BYTES], const char *service_key, const char *instance,
                               const char *device_name, const char *parent, long long now) {
  hub_service_certificate_t certificate;
  char instance_buf[129];
  char name_buf[256];
  char parent_buf[65];

  if (!service_key || !instance || !instance[0]) return NULL;
  if (!parent) parent = getenv("HUB_DEVICE_PARENT");
  snprintf(instance_buf, sizeof(instance_buf), "%s", instance);
  truncate_utf8(instance_buf, 128);
  if (device_name) {
    snprintf(name_buf, sizeof(name_buf), "%s", device_name);
  } else if (hub_service_device_default_name(name_buf, sizeof(name_buf)) != 0) {
    name_buf[0] = '\0';
  }
  truncate_utf8(name_buf, 64);

  memset(&certificate, 0, sizeof(certificate));
  certificate.service = service_key;
  certificate.instance = instance_buf;
  certificate.device_name = name_buf[0] ? name_buf : NULL;
  certificate.platform = hub_service_device_platform();
  if (parent && parent[0]) {
    snprintf(parent_buf, sizeof(parent_buf), "%s", parent);
    truncate_utf8(parent_buf, 64);
    certificate.parent = parent_buf;
  }
  certificate.iat = now;
  certificate.exp = now + HUB_SERVICE_CERTIFICATE_LIFETIME;
  return encode_with_key(key, &certificate);
}

char *hub_service_device_certificate(const char *service_key, const char *instance, const char *device_name,
                                     const char *parent, long long now) {
  unsigned char key[HS_KEY_BYTES];
  if (load_device_key(key) != 0) return NULL;
  return issue_certificate(key, service_key, instance, device_name, parent, now);
}

char *hub_service_device_certificate_with_key(const char *device_key_file, const char *service_key,
                                              const char *instance, const char *device_name, const char *parent,
                                              long long now) {
  unsigned char key[HS_KEY_BYTES];
  if (!device_key_file || hs_key_parse(device_key_file, key) != 0) return NULL;
  return issue_certificate(key, service_key, instance, device_name, parent, now);
}
