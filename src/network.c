/*
 * Hub Network share publishing (TS hub-service/network.ts parity).
 *
 * Per share: POST /challenge to the hub-net agent over its Unix socket, sign
 * the nonce with the service key, POST /attest, check the attestation, then
 * send every declared share with its attestation (forwarded verbatim) in one
 * network/shares/replace call. The hub answers with publications in request
 * order; each is checked against its share before it is kept.
 */

#include "network_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <yyjson.h>

#include "hub-service-c/keychain.h"

#define MAX_SHARE_NAME_LENGTH 255
#define WIRE_VERSION 1

typedef struct {
  char *name;
  char *protocol;
  char *host;
  int port;
  char *policy_json;
} share_t;

struct hs_network {
  share_t *shares; /* sorted by name */
  size_t count;
  char *publications; /* JSON array */
  char *socket_path;
  int timeout_ms;
};

static void set_error(char **out_error, const char *format, ...) __attribute__((format(printf, 2, 3)));

static void set_error(char **out_error, const char *format, ...) {
  char text[512];
  va_list args;
  if (!out_error) return;
  va_start(args, format);
  vsnprintf(text, sizeof(text), format, args);
  va_end(args);
  free(*out_error);
  *out_error = strdup(text);
}

hs_network_t *hs_network_new(void) {
  hs_network_t *network = (hs_network_t *)calloc(1, sizeof(hs_network_t));
  if (!network) return NULL;
#if defined(__APPLE__)
  network->socket_path = strdup("/var/run/hub-net/agent.sock");
#else
  network->socket_path = strdup("/run/hub-net/agent.sock");
#endif
  network->timeout_ms = 5000;
  network->publications = strdup("[]");
  return network;
}

static void share_free(share_t *share) {
  free(share->name);
  free(share->protocol);
  free(share->host);
  free(share->policy_json);
}

void hs_network_free(hs_network_t *network) {
  size_t index;
  if (!network) return;
  for (index = 0; index < network->count; index++) share_free(&network->shares[index]);
  free(network->shares);
  free(network->publications);
  free(network->socket_path);
  free(network);
}

void hs_network_set_socket(hs_network_t *network, const char *path, int timeout_ms) {
  if (path) {
    free(network->socket_path);
    network->socket_path = strdup(path);
  }
  if (timeout_ms > 0) network->timeout_ms = timeout_ms;
}

int hs_network_has_shares(const hs_network_t *network) {
  return network && network->count > 0;
}

char *hs_network_publications(const hs_network_t *network) {
  return strdup(network && network->publications ? network->publications : "[]");
}

/* ------------------------------------------------------------------ */
/* validation                                                          */
/* ------------------------------------------------------------------ */

/* Non-empty after trimming, no control characters, at most max chars (0: no limit). */
static int valid_text(const char *text, size_t max) {
  const unsigned char *p;
  int non_space = 0;
  if (!text) return 0;
  for (p = (const unsigned char *)text; *p; p++) {
    if (*p < 0x20 || *p == 0x7f) return 0;
    if (*p != ' ' && *p != '\t') non_space = 1;
  }
  if (max && strlen(text) > max) return 0;
  return non_space;
}

static int valid_policy(yyjson_val *policy) {
  const char *mode;
  yyjson_val *keys;
  yyjson_val *key;
  size_t index;
  size_t max;
  if (!yyjson_is_obj(policy)) return 0;
  mode = yyjson_get_str(yyjson_obj_get(policy, "mode"));
  if (!mode) return 0;
  if (strcmp(mode, "hub") == 0 || strcmp(mode, "private") == 0 || strcmp(mode, "disabled") == 0) return 1;
  if (strcmp(mode, "group") == 0) return valid_text(yyjson_get_str(yyjson_obj_get(policy, "group")), 0);
  if (strcmp(mode, "keys") == 0) {
    keys = yyjson_obj_get(policy, "keys");
    if (!yyjson_is_arr(keys) || yyjson_arr_size(keys) == 0) return 0;
    yyjson_arr_foreach(keys, index, max, key) {
      if (!valid_text(yyjson_get_str(key), 0)) return 0;
    }
    return 1;
  }
  return 0;
}

static int validate_share(const hub_service_share_t *share, char **out_error) {
  yyjson_doc *policy;
  int ok;
  if (!share || !valid_text(share->name, MAX_SHARE_NAME_LENGTH)) {
    set_error(out_error, "Invalid Hub Network share name");
    return -1;
  }
  if (!share->protocol || (strcmp(share->protocol, "tcp") != 0 && strcmp(share->protocol, "udp") != 0)) {
    set_error(out_error, "Invalid Hub Network protocol");
    return -1;
  }
  if (!valid_text(share->host, 0)) {
    set_error(out_error, "Invalid Hub Network target host");
    return -1;
  }
  if (share->port < 1 || share->port > 65535) {
    set_error(out_error, "Invalid Hub Network target port");
    return -1;
  }
  if (share->policy_json) {
    policy = yyjson_read(share->policy_json, strlen(share->policy_json), 0);
    ok = valid_policy(yyjson_doc_get_root(policy));
    yyjson_doc_free(policy);
    if (!ok) {
      set_error(out_error, "Invalid Hub Network policy");
      return -1;
    }
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* declared shares                                                     */
/* ------------------------------------------------------------------ */

static int share_copy(share_t *out, const hub_service_share_t *share) {
  yyjson_doc *policy = NULL;
  memset(out, 0, sizeof(*out));
  out->name = strdup(share->name);
  out->protocol = strdup(share->protocol);
  out->host = strdup(share->host);
  out->port = share->port;
  if (share->policy_json) {
    /* store it compact, as it goes on the wire */
    policy = yyjson_read(share->policy_json, strlen(share->policy_json), 0);
    out->policy_json = yyjson_write(policy, 0, NULL);
    yyjson_doc_free(policy);
  } else {
    out->policy_json = strdup("{\"mode\":\"private\"}");
  }
  if (!out->name || !out->protocol || !out->host || !out->policy_json) {
    share_free(out);
    return -1;
  }
  return 0;
}

static ssize_t find_share(const hs_network_t *network, const char *name) {
  size_t index;
  for (index = 0; index < network->count; index++) {
    if (strcmp(network->shares[index].name, name) == 0) return (ssize_t)index;
  }
  return -1;
}

static int compare_shares(const void *a, const void *b) {
  return strcmp(((const share_t *)a)->name, ((const share_t *)b)->name);
}

/* Insert or replace; *out_previous gets the replaced share (or a zeroed one). */
static int put_share(hs_network_t *network, const hub_service_share_t *share, share_t *out_previous) {
  share_t copy;
  ssize_t index;
  share_t *resized;

  if (share_copy(&copy, share) != 0) return -1;
  memset(out_previous, 0, sizeof(*out_previous));
  index = find_share(network, share->name);
  if (index >= 0) {
    *out_previous = network->shares[index];
    network->shares[index] = copy;
  } else {
    resized = (share_t *)realloc(network->shares, (network->count + 1) * sizeof(share_t));
    if (!resized) {
      share_free(&copy);
      return -1;
    }
    network->shares = resized;
    network->shares[network->count++] = copy;
  }
  qsort(network->shares, network->count, sizeof(share_t), compare_shares);
  return 0;
}

/* Undo put_share: restore the previous share, or drop the new one. */
static void restore_share(hs_network_t *network, const char *name, share_t *previous) {
  ssize_t index = find_share(network, name);
  if (index < 0) return;
  share_free(&network->shares[index]);
  if (previous->name) {
    network->shares[index] = *previous;
  } else {
    memmove(&network->shares[index], &network->shares[index + 1],
            (network->count - (size_t)index - 1) * sizeof(share_t));
    network->count -= 1;
  }
  qsort(network->shares, network->count, sizeof(share_t), compare_shares);
}

int hs_network_declare(hs_network_t *network, const hub_service_share_t *share, char **out_error) {
  share_t previous;
  if (validate_share(share, out_error) != 0) return -1;
  if (put_share(network, share, &previous) != 0) {
    set_error(out_error, "internal error");
    return -1;
  }
  share_free(&previous);
  return 0;
}

/* ------------------------------------------------------------------ */
/* local agent: HTTP/1.1 over a Unix socket                            */
/* ------------------------------------------------------------------ */

/* Decode a chunked body in place; returns the decoded length. */
static size_t dechunk(char *body, size_t length) {
  size_t in = 0;
  size_t out = 0;
  while (in < length) {
    char *end;
    unsigned long size = strtoul(body + in, &end, 16);
    char *line_end = strstr(body + in, "\r\n");
    if (!line_end || end == body + in) break;
    in = (size_t)(line_end - body) + 2;
    if (size == 0 || in + size > length) break;
    memmove(body + out, body + in, size);
    out += size;
    in += size + 2;
  }
  body[out] = '\0';
  return out;
}

static int agent_post(const hs_network_t *network, const char *path, const char *body, int *out_status,
                      char **out_body, char **out_error) {
  struct sockaddr_un address;
  struct timeval timeout;
  char header[512];
  char *response = NULL;
  size_t length = 0;
  size_t capacity = 0;
  char *header_end;
  int fd;

  *out_body = NULL;
  if (strlen(network->socket_path) >= sizeof(address.sun_path)) {
    set_error(out_error, "Hub Network agent socket path is too long");
    return -1;
  }
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    set_error(out_error, "Hub Network agent is unavailable at %s", network->socket_path);
    return -1;
  }
  timeout.tv_sec = network->timeout_ms / 1000;
  timeout.tv_usec = (network->timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#ifdef SO_NOSIGPIPE
  {
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
  }
#endif
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, network->socket_path, strlen(network->socket_path));
  if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(fd);
    set_error(out_error, "Hub Network agent is unavailable at %s", network->socket_path);
    return -1;
  }

  snprintf(header, sizeof(header),
           "POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
           "Connection: close\r\n\r\n",
           path, strlen(body));
  if (send(fd, header, strlen(header), 0) < 0 || send(fd, body, strlen(body), 0) < 0) goto failed;

  for (;;) {
    ssize_t n;
    if (length + 4096 + 1 > capacity) {
      char *resized;
      capacity = capacity ? capacity * 2 : 8192;
      resized = (char *)realloc(response, capacity);
      if (!resized) goto failed;
      response = resized;
    }
    n = recv(fd, response + length, capacity - length - 1, 0);
    if (n == 0) break;
    if (n < 0) {
      if (errno == EINTR) continue;
      close(fd);
      free(response);
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        set_error(out_error, "Hub Network agent timed out after %d ms", network->timeout_ms);
      } else {
        set_error(out_error, "Hub Network agent is unavailable at %s", network->socket_path);
      }
      return -1;
    }
    length += (size_t)n;
  }
  close(fd);
  if (!response) goto invalid;
  response[length] = '\0';

  if (sscanf(response, "HTTP/1.%*d %d", out_status) != 1) goto invalid;
  header_end = strstr(response, "\r\n\r\n");
  if (!header_end) goto invalid;
  *header_end = '\0';
  {
    char *body_start = header_end + 4;
    size_t body_length = length - (size_t)(body_start - response);
    int chunked = 0;
    char *line;
    for (line = response; line; line = strstr(line, "\r\n") ? strstr(line, "\r\n") + 2 : NULL) {
      if (strncasecmp(line, "transfer-encoding:", 18) == 0 && strstr(line, "chunked")) chunked = 1;
    }
    if (chunked) body_length = dechunk(body_start, body_length);
    *out_body = (char *)malloc(body_length + 1);
    if (!*out_body) goto invalid_freed;
    memcpy(*out_body, body_start, body_length);
    (*out_body)[body_length] = '\0';
  }
  free(response);
  return 0;

invalid:
  free(response);
invalid_freed:
  set_error(out_error, "Hub Network agent returned an invalid response");
  return -1;

failed:
  close(fd);
  free(response);
  set_error(out_error, "Hub Network agent is unavailable at %s", network->socket_path);
  return -1;
}

/* POST and parse a JSON object reply; non-2xx is "rejected". */
static yyjson_doc *agent_json(const hs_network_t *network, const char *path, const char *body,
                              const char *operation, char **out_error) {
  int status = 0;
  char *reply = NULL;
  yyjson_doc *doc;

  if (agent_post(network, path, body, &status, &reply, out_error) != 0) return NULL;
  if (status < 200 || status > 299) {
    size_t n = strlen(reply);
    while (n > 0 && (reply[n - 1] == '\n' || reply[n - 1] == '\r' || reply[n - 1] == ' ')) reply[--n] = '\0';
    set_error(out_error, "Hub Network agent rejected %s (%d)%s%s", operation, status, n ? ": " : "", reply);
    free(reply);
    return NULL;
  }
  doc = yyjson_read(reply, strlen(reply), 0);
  free(reply);
  if (!yyjson_is_obj(yyjson_doc_get_root(doc))) {
    yyjson_doc_free(doc);
    set_error(out_error, "Hub Network agent returned invalid JSON");
    return NULL;
  }
  return doc;
}

/* ------------------------------------------------------------------ */
/* attestation                                                         */
/* ------------------------------------------------------------------ */

static long long days_from_civil(long long y, unsigned m, unsigned d) {
  long long era;
  unsigned yoe, doy, doe;
  y -= m <= 2;
  era = (y >= 0 ? y : y - 399) / 400;
  yoe = (unsigned)(y - era * 400);
  doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + (long long)doe - 719468;
}

/* ISO 8601 / RFC 3339 time to Unix milliseconds; -1 when invalid. */
long long hs_parse_iso_ms(const char *text) {
  int year, month, day, hour, minute, second, consumed = 0;
  long long ms = 0;
  const char *p;
  if (!text || sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d%n", &year, &month, &day, &hour, &minute, &second, &consumed) != 6) {
    return -1;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) return -1;
  p = text + consumed;
  if (*p == '.') {
    long long scale = 100;
    for (p++; *p >= '0' && *p <= '9'; p++) {
      ms += (*p - '0') * scale;
      scale /= 10;
    }
  }
  ms += (days_from_civil(year, (unsigned)month, (unsigned)day) * 86400LL + hour * 3600LL + minute * 60LL + second) *
        1000LL;
  if (*p == 'Z' || *p == 'z') {
    p++;
  } else if (*p == '+' || *p == '-') {
    int oh, om;
    if (sscanf(p + 1, "%2d:%2d", &oh, &om) != 2) return -1;
    ms -= (*p == '+' ? 1 : -1) * (oh * 3600LL + om * 60LL) * 1000LL;
    p += 6;
  } else {
    return -1;
  }
  return *p == '\0' ? ms : -1;
}

static int check_attestation(yyjson_val *attestation, const share_t *share, const char *service_key,
                             char **out_error) {
  yyjson_val *target = yyjson_obj_get(attestation, "target");
  const char *host = yyjson_get_str(yyjson_obj_get(target, "host"));
  yyjson_val *port = yyjson_obj_get(target, "port");
  const char *text;
  long long issued;
  long long expires;
  struct timeval now;
  long long now_ms;

  if (!yyjson_is_obj(attestation) || yyjson_get_sint(yyjson_obj_get(attestation, "version")) != WIRE_VERSION ||
      !yyjson_is_int(yyjson_obj_get(attestation, "version")) ||
      !(text = yyjson_get_str(yyjson_obj_get(attestation, "serviceKey"))) || strcmp(text, service_key) != 0 ||
      !(text = yyjson_get_str(yyjson_obj_get(attestation, "shareName"))) || strcmp(text, share->name) != 0 ||
      !(text = yyjson_get_str(yyjson_obj_get(attestation, "protocol"))) || strcmp(text, share->protocol) != 0 ||
      !host || strcmp(host, share->host) != 0 || !yyjson_is_int(port) || yyjson_get_sint(port) != share->port) {
    set_error(out_error, "Local-agent attestation does not match the share");
    return -1;
  }
  issued = hs_parse_iso_ms(yyjson_get_str(yyjson_obj_get(attestation, "issuedAt")));
  expires = hs_parse_iso_ms(yyjson_get_str(yyjson_obj_get(attestation, "expiresAt")));
  gettimeofday(&now, NULL);
  now_ms = (long long)now.tv_sec * 1000 + now.tv_usec / 1000;
  if (issued < 0 || expires < 0 || expires <= issued || issued > now_ms + 30000 || expires <= now_ms) {
    set_error(out_error, "Local-agent attestation is expired");
    return -1;
  }
  return 0;
}

/* Challenge, sign, attest: the agent's attestation for one share (doc owns it). */
static yyjson_doc *attest(const hs_network_t *network, const share_t *share, const char *service_key,
                          char **out_error) {
  yyjson_mut_doc *request = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(request);
  yyjson_mut_val *target = yyjson_mut_obj(request);
  yyjson_doc *challenge = NULL;
  yyjson_doc *attestation = NULL;
  const char *nonce;
  char signature[128];
  char *body = NULL;

  yyjson_mut_doc_set_root(request, root);
  yyjson_mut_obj_add_str(request, root, "serviceKey", service_key);
  yyjson_mut_obj_add_str(request, root, "shareName", share->name);
  yyjson_mut_obj_add_str(request, root, "protocol", share->protocol);
  yyjson_mut_obj_add_str(request, target, "host", share->host);
  yyjson_mut_obj_add_int(request, target, "port", share->port);
  yyjson_mut_obj_add_val(request, root, "target", target);

  body = yyjson_mut_write(request, 0, NULL);
  challenge = agent_json(network, "/challenge", body, "challenge", out_error);
  free(body);
  body = NULL;
  if (!challenge) goto done;
  nonce = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(challenge), "nonce"));
  if (!nonce || !nonce[0]) {
    set_error(out_error, "Hub Network agent returned an invalid challenge");
    goto done;
  }
  if (hub_service_keychain_sign_data(nonce, signature, sizeof(signature)) != 0) {
    set_error(out_error, "keychain failed");
    goto done;
  }
  yyjson_mut_obj_add_str(request, root, "signature", signature);
  body = yyjson_mut_write(request, 0, NULL);
  attestation = agent_json(network, "/attest", body, "attestation", out_error);
  if (attestation && check_attestation(yyjson_doc_get_root(attestation), share, service_key, out_error) != 0) {
    yyjson_doc_free(attestation);
    attestation = NULL;
  }

done:
  free(body);
  yyjson_doc_free(challenge);
  yyjson_mut_doc_free(request);
  return attestation;
}

/* ------------------------------------------------------------------ */
/* network/shares/replace                                              */
/* ------------------------------------------------------------------ */

static int check_publication(yyjson_val *publication, const share_t *share, size_t index, char **out_error) {
  const char *resource = yyjson_get_str(yyjson_obj_get(publication, "resourceId"));
  const char *protocol = yyjson_get_str(yyjson_obj_get(publication, "protocol"));
  yyjson_val *port = yyjson_obj_get(publication, "port");
  if (!yyjson_is_obj(publication) || !yyjson_is_int(yyjson_obj_get(publication, "version")) ||
      yyjson_get_sint(yyjson_obj_get(publication, "version")) != WIRE_VERSION) {
    set_error(out_error, "Invalid Hub publication version at share index %zu", index);
    return -1;
  }
  if (!resource || strncmp(resource, "hnr1_", 5) != 0 || strlen(resource) == 5) {
    set_error(out_error, "Invalid Hub publication resourceId at share index %zu", index);
    return -1;
  }
  if (!valid_text(yyjson_get_str(yyjson_obj_get(publication, "authority")), 0) ||
      !valid_text(yyjson_get_str(yyjson_obj_get(publication, "providerId")), 0) ||
      !valid_text(yyjson_get_str(yyjson_obj_get(publication, "overlayAddress")), 0)) {
    set_error(out_error, "Invalid Hub publication at share index %zu", index);
    return -1;
  }
  if (!protocol || strcmp(protocol, share->protocol) != 0) {
    set_error(out_error, "Hub publication protocol mismatch at share index %zu", index);
    return -1;
  }
  if (!yyjson_is_int(port) || yyjson_get_sint(port) < 1 || yyjson_get_sint(port) > 65535) {
    set_error(out_error, "Invalid Hub publication port at share index %zu", index);
    return -1;
  }
  return 0;
}

static int synchronize(hs_network_t *network, channel_c_sender_t *sender, char **out_error) {
  char service_key[128];
  yyjson_mut_doc *request = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(request);
  yyjson_mut_val *wire_shares = yyjson_mut_arr(request);
  yyjson_doc **attestations = NULL;
  yyjson_doc *reply_doc = NULL;
  char *body = NULL;
  char *reply = NULL;
  char *error = NULL;
  yyjson_val *publications;
  size_t index;
  int result = -1;

  if (!sender) {
    set_error(out_error, "Service not started");
    goto done;
  }
  if (hub_service_keychain_public_key(service_key, sizeof(service_key)) != 0) {
    set_error(out_error, "keychain failed");
    goto done;
  }
  attestations = (yyjson_doc **)calloc(network->count ? network->count : 1, sizeof(yyjson_doc *));
  if (!attestations) goto done;

  yyjson_mut_doc_set_root(request, root);
  for (index = 0; index < network->count; index++) {
    const share_t *share = &network->shares[index];
    yyjson_mut_val *wire = yyjson_mut_obj(request);
    yyjson_mut_val *target = yyjson_mut_obj(request);
    yyjson_doc *policy;

    attestations[index] = attest(network, share, service_key, out_error);
    if (!attestations[index]) goto done;
    yyjson_mut_obj_add_str(request, wire, "name", share->name);
    yyjson_mut_obj_add_str(request, wire, "protocol", share->protocol);
    yyjson_mut_obj_add_str(request, target, "host", share->host);
    yyjson_mut_obj_add_int(request, target, "port", share->port);
    yyjson_mut_obj_add_val(request, wire, "target", target);
    policy = yyjson_read(share->policy_json, strlen(share->policy_json), 0);
    yyjson_mut_obj_add_val(request, wire, "policy", yyjson_val_mut_copy(request, yyjson_doc_get_root(policy)));
    yyjson_doc_free(policy);
    yyjson_mut_obj_add_int(request, wire, "version", WIRE_VERSION);
    /* forwarded verbatim: the agent signed it */
    yyjson_mut_obj_add_val(request, wire, "attestation",
                           yyjson_val_mut_copy(request, yyjson_doc_get_root(attestations[index])));
    yyjson_mut_arr_append(wire_shares, wire);
  }
  yyjson_mut_obj_add_val(request, root, "shares", wire_shares);
  body = yyjson_mut_write(request, 0, NULL);

  if (channel_c_sender_send(sender, "network/shares/replace", body, NULL, &reply, &error) != 0) {
    set_error(out_error, "%s", error ? error : "network/shares/replace failed");
    goto done;
  }
  reply_doc = reply ? yyjson_read(reply, strlen(reply), 0) : NULL;
  publications = yyjson_obj_get(yyjson_doc_get_root(reply_doc), "shares");
  if (!yyjson_is_arr(publications)) {
    set_error(out_error, "Hub returned an invalid shares/replace response");
    goto done;
  }
  if (yyjson_arr_size(publications) != network->count) {
    set_error(out_error, "Hub returned %zu publications for %zu shares", yyjson_arr_size(publications),
              network->count);
    goto done;
  }
  /* v1 publications carry no share name: the hub keeps request order */
  for (index = 0; index < network->count; index++) {
    yyjson_val *publication = yyjson_arr_get(publications, index);
    size_t other;
    if (check_publication(publication, &network->shares[index], index, out_error) != 0) goto done;
    for (other = 0; other < index; other++) {
      if (strcmp(yyjson_get_str(yyjson_obj_get(yyjson_arr_get(publications, other), "resourceId")),
                 yyjson_get_str(yyjson_obj_get(publication, "resourceId"))) == 0) {
        set_error(out_error, "Hub returned duplicate resourceId at share index %zu", index);
        goto done;
      }
    }
  }
  free(network->publications);
  network->publications = yyjson_val_write(publications, 0, NULL);
  result = network->publications ? 0 : -1;

done:
  if (attestations) {
    for (index = 0; index < network->count; index++) yyjson_doc_free(attestations[index]);
    free(attestations);
  }
  yyjson_doc_free(reply_doc);
  yyjson_mut_doc_free(request);
  channel_c_free(reply);
  channel_c_free(error);
  free(body);
  return result;
}

int hs_network_republish(hs_network_t *network, channel_c_sender_t *sender, char **out_error) {
  return synchronize(network, sender, out_error);
}

int hs_network_publish(hs_network_t *network, channel_c_sender_t *sender, const hub_service_share_t *share,
                       char **out_error) {
  share_t previous;
  if (validate_share(share, out_error) != 0) return -1;
  if (!sender) {
    set_error(out_error, "Service not started");
    return -1;
  }
  if (put_share(network, share, &previous) != 0) {
    set_error(out_error, "internal error");
    return -1;
  }
  if (synchronize(network, sender, out_error) != 0) {
    restore_share(network, share->name, &previous);
    return -1;
  }
  share_free(&previous);
  return 0;
}

int hs_network_remove(hs_network_t *network, channel_c_sender_t *sender, const char *name, char **out_error) {
  ssize_t index;
  share_t removed;
  if (!name || !valid_text(name, MAX_SHARE_NAME_LENGTH)) {
    set_error(out_error, "Invalid Hub Network share name");
    return -1;
  }
  if (!sender) {
    set_error(out_error, "Service not started");
    return -1;
  }
  index = find_share(network, name);
  if (index < 0) {
    set_error(out_error, "Share '%s' not found", name);
    return -1;
  }
  removed = network->shares[index];
  memmove(&network->shares[index], &network->shares[index + 1], (network->count - (size_t)index - 1) * sizeof(share_t));
  network->count -= 1;
  if (synchronize(network, sender, out_error) != 0) {
    share_t *resized = (share_t *)realloc(network->shares, (network->count + 1) * sizeof(share_t));
    if (resized) {
      network->shares = resized;
      network->shares[network->count++] = removed;
      qsort(network->shares, network->count, sizeof(share_t), compare_shares);
    } else {
      share_free(&removed);
    }
    return -1;
  }
  share_free(&removed);
  return 0;
}
