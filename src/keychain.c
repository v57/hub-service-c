/*
 * hub-pro auth keychain: ed25519 load-or-generate, token signing and hub key
 * pins (Docs/Devices/protocol.md section 2).
 *
 * Key file layout (TS hub-service/keychain.ts parity):
 *   base64( 48-byte PKCS8 DER private key || 44-byte SPKI DER public key )
 * = 92 raw bytes, 124 base64 chars. Public key in tokens = bytes 48..92.
 */

#include "hub-service-c/keychain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <yyjson.h>

#include "crypto.h"

static char key_path_override[1024] = {0};

void hub_service_keychain_set_path(const char *path) {
  if (path) {
    snprintf(key_path_override, sizeof(key_path_override), "%s", path);
  } else {
    key_path_override[0] = '\0';
  }
}

static const char *key_path(void) {
  const char *env;
  if (key_path_override[0]) return key_path_override;
  env = getenv("HUBKEY");
  if (env && env[0]) return env;
  return "auth";
}

static int load_or_generate(unsigned char *key_bytes) {
  return hs_key_file_load(key_path(), 1, 0600, 0, key_bytes);
}

int hub_service_keychain_public_key(char *out, size_t out_size) {
  unsigned char key_bytes[HS_KEY_BYTES];
  char pub[HS_SPKI_B64_SIZE];
  if (load_or_generate(key_bytes) != 0 || hs_key_public(key_bytes, pub) != 0 ||
      snprintf(out, out_size, "%s", pub) >= (int)out_size) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

static int token_from_key(const unsigned char *key_bytes, const char *hub_key, long long expiry,
                          char *out, size_t out_size) {
  char data[256];
  char pub[HS_SPKI_B64_SIZE];
  char sig[HS_SIG_B64_SIZE];

  if (hub_key) {
    if (snprintf(data, sizeof(data), "hub1:%s:%lld", hub_key, expiry) >= (int)sizeof(data)) return -1;
  } else {
    snprintf(data, sizeof(data), "%lld", expiry);
  }
  if (hs_key_sign(key_bytes, data, strlen(data), sig) != 0) return -1;
  if (hs_key_public(key_bytes, pub) != 0) return -1;
  if (snprintf(out, out_size, "key.%s.%s.%lld", pub, sig, expiry) >= (int)out_size) return -1;
  return 0;
}

int hub_service_auth_token(const char *key_file, const char *hub_key, long long expiry, char *out, size_t out_size) {
  unsigned char key_bytes[HS_KEY_BYTES];
  if (!key_file || hs_key_parse(key_file, key_bytes) != 0 ||
      token_from_key(key_bytes, hub_key, expiry, out, out_size) != 0) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

int hub_service_keychain_sign_for_hub(const char *hub_key, char *out, size_t out_size) {
  unsigned char key_bytes[HS_KEY_BYTES];
  long long expiry = (long long)time(NULL) + HUB_SERVICE_AUTH_EXPIRY;
  if (load_or_generate(key_bytes) != 0 || token_from_key(key_bytes, hub_key, expiry, out, out_size) != 0) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

int hub_service_keychain_sign(char *out, size_t out_size) {
  return hub_service_keychain_sign_for_hub(NULL, out, out_size);
}

/* Percent-encode base64 for a query parameter: '+' -> %2B, '/' -> %2F, '=' -> %3D. */
static void url_encode(const char *in, char *out, size_t out_size) {
  size_t o = 0;
  for (const char *p = in; *p && o + 4 < out_size; p++) {
    char c = *p;
    if (c == '+' || c == '/' || c == '=') {
      out[o++] = '%';
      out[o++] = c == '+' ? '2' : (c == '/' ? '2' : '3');
      out[o++] = c == '+' ? 'B' : (c == '/' ? 'F' : 'D');
    } else {
      out[o++] = c;
    }
  }
  out[o] = '\0';
}

int hub_service_keychain_auth_query(char *out, size_t out_size) {
  char token[512];
  char encoded[1024];
  if (hub_service_keychain_sign(token, sizeof(token)) != 0) {
    out[0] = '\0';
    return -1;
  }
  url_encode(token, encoded, sizeof(encoded));
  if (snprintf(out, out_size, "?auth=%s&v=0", encoded) >= (int)out_size) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* hub key pins: hubs.json beside the key file                         */
/* ------------------------------------------------------------------ */

static void hubs_path(char *out, size_t out_size) {
  char dir[1024];
  hs_dirname(key_path(), dir, sizeof(dir));
  snprintf(out, out_size, "%s/hubs.json", dir);
}

/* The pins as a mutable object (empty when the file is missing or corrupt). */
static yyjson_mut_doc *read_pins(void) {
  char path[1100];
  char *text;
  yyjson_doc *doc = NULL;
  yyjson_mut_doc *mut;

  hubs_path(path, sizeof(path));
  text = hs_read_file(path);
  if (text) {
    doc = yyjson_read(text, strlen(text), 0);
    free(text);
  }
  if (doc && yyjson_is_obj(yyjson_doc_get_root(doc))) {
    mut = yyjson_doc_mut_copy(doc, NULL);
  } else {
    mut = yyjson_mut_doc_new(NULL);
    if (mut) yyjson_mut_doc_set_root(mut, yyjson_mut_obj(mut));
  }
  yyjson_doc_free(doc);
  return mut;
}

static int write_pins(yyjson_mut_doc *doc) {
  char path[1100];
  size_t len = 0;
  char *json = yyjson_mut_write(doc, 0, &len);
  int result;
  if (!json) return -1;
  hubs_path(path, sizeof(path));
  result = hs_write_atomic(path, json, len, 0600);
  free(json);
  return result;
}

int hub_service_keychain_hub_key(const char *address, char *out, size_t out_size) {
  yyjson_mut_doc *doc;
  yyjson_mut_val *value;
  int result = -1;

  out[0] = '\0';
  if (!address) return -1;
  doc = read_pins();
  if (!doc) return -1;
  value = yyjson_mut_obj_get(yyjson_mut_doc_get_root(doc), address);
  if (yyjson_mut_is_str(value) && snprintf(out, out_size, "%s", yyjson_mut_get_str(value)) < (int)out_size) {
    result = 0;
  } else {
    out[0] = '\0';
  }
  yyjson_mut_doc_free(doc);
  return result;
}

int hub_service_keychain_pin_hub_key(const char *address, const char *hub_key) {
  yyjson_mut_doc *doc;
  yyjson_mut_val *root;
  int result;

  if (!address || !hub_key) return -1;
  doc = read_pins();
  if (!doc) return -1;
  root = yyjson_mut_doc_get_root(doc);
  yyjson_mut_obj_remove_key(root, address);
  yyjson_mut_obj_add_strcpy(doc, root, address, hub_key);
  result = write_pins(doc);
  yyjson_mut_doc_free(doc);
  return result;
}

int hub_service_keychain_forget_hub_key(const char *address) {
  yyjson_mut_doc *doc;
  int result;

  if (!address) return -1;
  doc = read_pins();
  if (!doc) return -1;
  yyjson_mut_obj_remove_key(yyjson_mut_doc_get_root(doc), address);
  result = write_pins(doc);
  yyjson_mut_doc_free(doc);
  return result;
}
