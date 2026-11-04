/*
 * Auth v2's client side (Docs/Devices/protocol.md section 2): the transport
 * check, and the question a service asks a hub before every connect.
 */

#include "hub-service-c/hub_proof.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <yyjson.h>

#include "channel-c/channel_c.h"
#include "crypto.h"

static char lower(char c) {
  return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static int ends_with(const char *text, const char *suffix) {
  size_t n = strlen(text);
  size_t m = strlen(suffix);
  return n >= m && strcmp(text + n - m, suffix) == 0;
}

static int starts_with(const char *text, const char *prefix) {
  return strncmp(text, prefix, strlen(prefix)) == 0;
}

/* Four decimal bytes, each one to three digits. */
static int parse_ipv4(const char *host, int *a, int *b) {
  int bytes[4];
  int index;
  const char *p = host;
  for (index = 0; index < 4; index++) {
    int digits = 0;
    int value = 0;
    while (*p >= '0' && *p <= '9') {
      value = value * 10 + (*p - '0');
      digits++;
      p++;
      if (digits > 3) return 0;
    }
    if (digits == 0 || value > 255) return 0;
    bytes[index] = value;
    if (index < 3) {
      if (*p != '.') return 0;
      p++;
    }
  }
  if (*p != '\0') return 0;
  *a = bytes[0];
  *b = bytes[1];
  return 1;
}

hub_service_transport_t hub_service_transport_of(const char *address) {
  char scheme[16];
  char host[256];
  const char *p;
  const char *rest;
  size_t n;
  size_t i;
  int a;
  int b;

  if (!address) return HUB_SERVICE_TRANSPORT_REFUSED;
  for (p = address; *p >= '0' && *p <= '9'; p++) {
  }
  if (p != address && *p == '\0') return HUB_SERVICE_TRANSPORT_LOOPBACK;

  rest = strstr(address, "://");
  if (rest) {
    n = (size_t)(rest - address);
    if (n >= sizeof(scheme)) return HUB_SERVICE_TRANSPORT_REFUSED;
    for (i = 0; i < n; i++) scheme[i] = lower(address[i]);
    scheme[n] = '\0';
    rest += 3;
  } else {
    snprintf(scheme, sizeof(scheme), "ws");
    rest = address;
  }
  if (strcmp(scheme, "wss") == 0 || strcmp(scheme, "https") == 0 || strcmp(scheme, "quic") == 0) {
    return HUB_SERVICE_TRANSPORT_ENCRYPTED;
  }
  if (strcmp(scheme, "ws") != 0 && strcmp(scheme, "http") != 0) return HUB_SERVICE_TRANSPORT_REFUSED;

  /* authority without user info */
  n = strcspn(rest, "/?#");
  p = memchr(rest, '@', n);
  if (p) {
    n -= (size_t)(p + 1 - rest);
    rest = p + 1;
  }
  if (n > 0 && rest[0] == '[') {
    const char *close = memchr(rest, ']', n);
    n = close ? (size_t)(close - rest - 1) : n - 1;
    rest += 1;
    if (n >= sizeof(host)) return HUB_SERVICE_TRANSPORT_REFUSED;
    for (i = 0; i < n; i++) host[i] = lower(rest[i]);
    host[n] = '\0';
    if (strcmp(host, "::1") == 0) return HUB_SERVICE_TRANSPORT_LOOPBACK;
    if (starts_with(host, "fc") || starts_with(host, "fd") || starts_with(host, "fe8") || starts_with(host, "fe9") ||
        starts_with(host, "fea") || starts_with(host, "feb")) {
      return HUB_SERVICE_TRANSPORT_LOCAL_NETWORK;
    }
    return HUB_SERVICE_TRANSPORT_REFUSED;
  }
  p = memchr(rest, ':', n);
  if (p) n = (size_t)(p - rest);
  if (n >= sizeof(host)) return HUB_SERVICE_TRANSPORT_REFUSED;
  for (i = 0; i < n; i++) host[i] = lower(rest[i]);
  if (n > 0 && host[n - 1] == '.') n--;
  host[n] = '\0';

  if (parse_ipv4(host, &a, &b)) {
    if (a == 127) return HUB_SERVICE_TRANSPORT_LOOPBACK;
    if (a == 100 && b >= 64 && b <= 127) return HUB_SERVICE_TRANSPORT_OVERLAY;
    if (a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 169 && b == 254)) {
      return HUB_SERVICE_TRANSPORT_LOCAL_NETWORK;
    }
    return HUB_SERVICE_TRANSPORT_REFUSED;
  }
  if (strcmp(host, "localhost") == 0 || ends_with(host, ".localhost")) return HUB_SERVICE_TRANSPORT_LOOPBACK;
  if (ends_with(host, ".hub.invalid")) return HUB_SERVICE_TRANSPORT_OVERLAY;
  if (ends_with(host, ".local")) return HUB_SERVICE_TRANSPORT_LOCAL_NETWORK;
  return HUB_SERVICE_TRANSPORT_REFUSED;
}

const char *hub_service_transport_name(hub_service_transport_t transport) {
  switch (transport) {
    case HUB_SERVICE_TRANSPORT_ENCRYPTED: return "encrypted";
    case HUB_SERVICE_TRANSPORT_LOOPBACK: return "loopback";
    case HUB_SERVICE_TRANSPORT_OVERLAY: return "overlay";
    case HUB_SERVICE_TRANSPORT_LOCAL_NETWORK: return "localNetwork";
    case HUB_SERVICE_TRANSPORT_REFUSED: return "refused";
  }
  return "refused";
}

char *hub_service_make_client_nonce(void) {
  unsigned char bytes[32];
  if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1) return NULL;
  return hs_b64url_encode(bytes, sizeof(bytes));
}

char *hub_service_hub_info_signed_data(const char *hub_key, const char *nonce) {
  size_t size;
  char *out;
  if (!hub_key || !nonce) return NULL;
  size = strlen(hub_key) + strlen(nonce) + sizeof("hubinfo1::");
  out = (char *)malloc(size);
  if (out) snprintf(out, size, "hubinfo1:%s:%s", hub_key, nonce);
  return out;
}

static int copy_field(yyjson_val *root, const char *name, char *out, size_t size) {
  yyjson_val *value = yyjson_obj_get(root, name);
  if (!yyjson_is_str(value) || yyjson_get_len(value) == 0 || yyjson_get_len(value) >= size) return -1;
  memcpy(out, yyjson_get_str(value), yyjson_get_len(value) + 1);
  return 0;
}

int hub_service_hub_info_parse(const char *json, hub_service_hub_info_t *out) {
  yyjson_doc *doc;
  yyjson_val *root;
  const char *p;
  int result = -1;

  memset(out, 0, sizeof(*out));
  if (!json) return -1;
  doc = yyjson_read(json, strlen(json), 0);
  root = yyjson_doc_get_root(doc);
  if (yyjson_is_obj(root) && copy_field(root, "key", out->key, sizeof(out->key)) == 0 &&
      copy_field(root, "proof", out->proof, sizeof(out->proof)) == 0 &&
      copy_field(root, "challenge", out->challenge, sizeof(out->challenge)) == 0) {
    result = 0;
    for (p = out->challenge; *p; p++) {
      if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) {
        result = -1;
      }
    }
  }
  yyjson_doc_free(doc);
  return result;
}

int hub_service_hub_info_proves(const hub_service_hub_info_t *info, const char *nonce) {
  char *data;
  int proved;
  if (!info || !nonce) return 0;
  data = hub_service_hub_info_signed_data(info->key, nonce);
  if (!data) return 0;
  proved = hs_key_verify(info->key, data, strlen(data), info->proof) == 0;
  free(data);
  return proved;
}

int hub_service_ask_hub(const char *address, hub_service_hub_info_t *out, char **out_error) {
  channel_c_channel_t *channel;
  channel_c_client_t *client;
  char *nonce = NULL;
  char *response = NULL;
  char *error = NULL;
  char body[128];
  int result = -1;

  if (out_error) *out_error = NULL;
  memset(out, 0, sizeof(*out));
  channel = channel_c_channel_new();
  nonce = hub_service_make_client_nonce();
  if (!channel || !nonce) {
    if (out_error) *out_error = channel_c_strdup("internal error");
    channel_c_channel_free(channel);
    free(nonce);
    return -1;
  }
  client = channel_c_client_connect_with_options(channel, address, NULL, &error);
  if (client) {
    snprintf(body, sizeof(body), "{\"nonce\":\"%s\"}", nonce);
    if (channel_c_sender_send(channel_c_client_sender(client), "hub/info", body, NULL, &response, &error) == 0) {
      if (hub_service_hub_info_parse(response, out) == 0 && hub_service_hub_info_proves(out, nonce)) {
        result = 0;
      } else {
        channel_c_free(error);
        error = channel_c_strdup("hub didn't prove its key");
      }
    }
    channel_c_client_free(client);
  }
  channel_c_channel_free(channel);
  channel_c_free(response);
  free(nonce);
  if (result != 0) {
    /* An error answer, like no hub/info at all, proves nothing either. */
    if (out_error) *out_error = error ? error : channel_c_strdup("hub didn't prove its key");
    else channel_c_free(error);
    memset(out, 0, sizeof(*out));
  } else {
    channel_c_free(error);
  }
  return result;
}
