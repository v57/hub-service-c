/*
 * Hub Network share publishing against a fake hub-net agent (HTTP on a Unix
 * socket, in a thread) and an in-process fake hub (a channel-c server).
 */

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <setjmp.h>
#include <cmocka.h>
#include <yyjson.h>

#include "hub-service-c/device.h"
#include "hub-service-c/keychain.h"
#include "hub-service-c/network.h"
#include "network_internal.h"

static char test_dir[256];
static char agent_path[320];

/* ------------------------------------------------------------------ */
/* fake agent                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
  int listen_fd;
  volatile int stop;
  int attest_status; /* 200, or an error status for /attest */
  int chunked;       /* answer with Transfer-Encoding: chunked */
  int attest_ttl;    /* seconds the attestation stays valid */
  int bad_signatures;
  int attests;
  pthread_t thread;
} agent_t;

static agent_t agent;

static int verify_signature(const char *spki_b64, const char *data, const char *signature_b64) {
  unsigned char spki[64];
  unsigned char signature[80];
  const unsigned char *p = spki;
  int spki_len = EVP_DecodeBlock(spki, (const unsigned char *)spki_b64, (int)strlen(spki_b64));
  int sig_len = EVP_DecodeBlock(signature, (const unsigned char *)signature_b64, (int)strlen(signature_b64));
  EVP_PKEY *key;
  EVP_MD_CTX *ctx;
  int ok;
  if (spki_len < 44 || sig_len < 64) return 0;
  key = d2i_PUBKEY(NULL, &p, 44);
  if (!key) return 0;
  ctx = EVP_MD_CTX_new();
  ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
       EVP_DigestVerify(ctx, signature, 64, (const unsigned char *)data, strlen(data)) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
}

static void iso_time(time_t t, char *out, size_t size) {
  struct tm tm;
  gmtime_r(&t, &tm);
  strftime(out, size, "%Y-%m-%dT%H:%M:%S.123456789Z", &tm);
}

static void reply(int fd, int status, const char *body) {
  char header[256];
  if (agent.chunked) {
    snprintf(header, sizeof(header), "HTTP/1.1 %d X\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n%zx\r\n",
             status, strlen(body));
    send(fd, header, strlen(header), 0);
    send(fd, body, strlen(body), 0);
    send(fd, "\r\n0\r\n\r\n", 7, 0);
  } else {
    snprintf(header, sizeof(header), "HTTP/1.1 %d X\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
             status, strlen(body));
    send(fd, header, strlen(header), 0);
    send(fd, body, strlen(body), 0);
  }
}

static void handle(int fd) {
  char request[8192];
  size_t length = 0;
  char *body = NULL;
  yyjson_doc *doc;
  yyjson_val *root;
  char out[2048];

  while (length < sizeof(request) - 1) {
    ssize_t n = recv(fd, request + length, sizeof(request) - 1 - length, 0);
    char *end;
    if (n <= 0) break;
    length += (size_t)n;
    request[length] = '\0';
    end = strstr(request, "\r\n\r\n");
    if (end) {
      const char *cl = strcasestr(request, "content-length:");
      size_t want = cl ? (size_t)atol(cl + 15) : 0;
      if (length >= (size_t)(end + 4 - request) + want) {
        body = end + 4;
        break;
      }
    }
  }
  if (!body) return;
  doc = yyjson_read(body, strlen(body), 0);
  root = yyjson_doc_get_root(doc);
  if (strncmp(request, "POST /challenge ", 16) == 0) {
    reply(fd, 200, "{\"version\":1,\"type\":\"attest.challenge\",\"nonce\":\"bm9uY2U\",\"key\":\"agent-key\"}");
  } else if (strncmp(request, "POST /attest ", 13) == 0) {
    const char *service_key = yyjson_get_str(yyjson_obj_get(root, "serviceKey"));
    const char *signature = yyjson_get_str(yyjson_obj_get(root, "signature"));
    yyjson_val *target = yyjson_obj_get(root, "target");
    char issued[64];
    char expires[64];
    agent.attests += 1;
    if (!service_key || !signature || !verify_signature(service_key, "bm9uY2U", signature)) {
      agent.bad_signatures += 1;
      reply(fd, 401, "{\"error\":\"bad signature\"}\n");
    } else if (agent.attest_status != 200) {
      reply(fd, agent.attest_status, "{\"error\":\"denied\"}\n");
    } else {
      iso_time(time(NULL) - 1, issued, sizeof(issued));
      iso_time(time(NULL) + agent.attest_ttl, expires, sizeof(expires));
      snprintf(out, sizeof(out),
               "{\"version\":1,\"attestationId\":\"att-%d\",\"serviceKey\":\"%s\",\"key\":\"agent-key\","
               "\"shareName\":\"%s\",\"protocol\":\"%s\",\"target\":{\"host\":\"%s\",\"port\":%lld},"
               "\"issuedAt\":\"%s\",\"expiresAt\":\"%s\",\"signature\":\"c2ln\",\"extra\":\"kept\"}\n",
               agent.attests, service_key, yyjson_get_str(yyjson_obj_get(root, "shareName")),
               yyjson_get_str(yyjson_obj_get(root, "protocol")), yyjson_get_str(yyjson_obj_get(target, "host")),
               (long long)yyjson_get_sint(yyjson_obj_get(target, "port")), issued, expires);
      reply(fd, 200, out);
    }
  } else {
    reply(fd, 404, "not found");
  }
  yyjson_doc_free(doc);
}

static void *agent_main(void *arg) {
  (void)arg;
  while (!agent.stop) {
    struct pollfd pfd = {agent.listen_fd, POLLIN, 0};
    if (poll(&pfd, 1, 20) > 0) {
      int fd = accept(agent.listen_fd, NULL, NULL);
      if (fd >= 0) {
        handle(fd);
        close(fd);
      }
    }
  }
  return NULL;
}

static void agent_start(void) {
  struct sockaddr_un address;
  memset(&agent, 0, sizeof(agent));
  agent.attest_status = 200;
  agent.attest_ttl = 300;
  agent.listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s", agent_path);
  unlink(agent_path);
  assert_int_equal(bind(agent.listen_fd, (struct sockaddr *)&address, sizeof(address)), 0);
  assert_int_equal(listen(agent.listen_fd, 8), 0);
  pthread_create(&agent.thread, NULL, agent_main, NULL);
}

static void agent_stop(void) {
  if (!agent.listen_fd) return;
  agent.stop = 1;
  pthread_join(agent.thread, NULL);
  close(agent.listen_fd);
  agent.listen_fd = 0;
  unlink(agent_path);
}

/* ------------------------------------------------------------------ */
/* fake hub                                                            */
/* ------------------------------------------------------------------ */

static char *last_replace;
static int replace_count;

static int reply_null(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  (void)request;
  (void)out_error;
  *out_body_json = channel_c_strdup("null");
  return 0;
}

static int reply_replace(const channel_c_post_request_t *request, char **out_body_json, char **out_error) {
  yyjson_doc *doc = yyjson_read(request->body_json, strlen(request->body_json), 0);
  yyjson_val *shares = yyjson_obj_get(yyjson_doc_get_root(doc), "shares");
  yyjson_mut_doc *out = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(out);
  yyjson_mut_val *publications = yyjson_mut_arr(out);
  yyjson_val *share;
  size_t index;
  size_t max;
  (void)out_error;

  free(last_replace);
  last_replace = strdup(request->body_json);
  replace_count += 1;
  yyjson_mut_doc_set_root(out, root);
  yyjson_arr_foreach(shares, index, max, share) {
    yyjson_mut_val *publication = yyjson_mut_obj(out);
    const char *name = yyjson_get_str(yyjson_obj_get(share, "name"));
    yyjson_mut_obj_add_int(out, publication, "version", 1);
    yyjson_mut_obj_add_strcpy(out, publication, "resourceId", name);
    yyjson_mut_obj_add_str(out, publication, "authority", "share.hub.invalid");
    yyjson_mut_obj_add_str(out, publication, "providerId", "provider");
    yyjson_mut_obj_add_str(out, publication, "protocol", yyjson_get_str(yyjson_obj_get(share, "protocol")));
    yyjson_mut_obj_add_str(out, publication, "overlayAddress", "100.96.0.2");
    yyjson_mut_obj_add_int(out, publication, "port", 4000 + (int64_t)index);
    yyjson_mut_arr_append(publications, publication);
  }
  yyjson_mut_obj_add_val(out, root, "shares", publications);
  {
    /* resource ids are "hnr1_<name>" */
    char *json = yyjson_mut_write(out, 0, NULL);
    char *fixed = (char *)malloc(strlen(json) * 2 + 1);
    const char *p = json;
    char *o = fixed;
    while (*p) {
      if (strncmp(p, "\"resourceId\":\"", 14) == 0) {
        memcpy(o, p, 14);
        o += 14;
        p += 14;
        memcpy(o, "hnr1_", 5);
        o += 5;
      } else {
        *o++ = *p++;
      }
    }
    *o = '\0';
    free(json);
    *out_body_json = fixed;
  }
  yyjson_mut_doc_free(out);
  yyjson_doc_free(doc);
  return 0;
}

typedef struct {
  channel_c_channel_t *channel;
  channel_c_server_t *server;
  hub_service_t *service;
} fixture_t;

static int setup(void **state) {
  fixture_t *fixture = calloc(1, sizeof(fixture_t));
  char path[400];
  snprintf(test_dir, sizeof(test_dir), "/tmp/hsc_net_%ld", (long)getpid());
  mkdir(test_dir, 0700);
  snprintf(agent_path, sizeof(agent_path), "%s/agent.sock", test_dir);
  snprintf(path, sizeof(path), "%s/auth", test_dir);
  hub_service_keychain_set_path(path);
  snprintf(path, sizeof(path), "%s/device.key", test_dir);
  hub_service_device_set_path(path);
  free(last_replace);
  last_replace = NULL;
  replace_count = 0;
  *state = fixture;
  return 0;
}

static int teardown(void **state) {
  fixture_t *fixture = *state;
  char cmd[512];
  agent_stop();
  hub_service_free(fixture->service);
  channel_c_server_free(fixture->server);
  channel_c_channel_free(fixture->channel);
  free(fixture);
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  system(cmd);
  hub_service_keychain_set_path(NULL);
  hub_service_device_set_path(NULL);
  return 0;
}

static void start_hub(fixture_t *fixture) {
  channel_c_state_factory_t factory;
  char *error = NULL;
  char url[64];
  hub_service_options_t options;

  fixture->channel = channel_c_channel_new();
  channel_c_channel_post(fixture->channel, "hub/service/update", reply_null, NULL, 0);
  channel_c_channel_post(fixture->channel, "network/shares/replace", reply_replace, NULL, 0);
  memset(&factory, 0, sizeof(factory));
  fixture->server = channel_c_server_listen(fixture->channel, "127.0.0.1", 0, factory, &error);
  assert_non_null(fixture->server);
  snprintf(url, sizeof(url), "ws://127.0.0.1:%d", channel_c_server_port(fixture->server));
  memset(&options, 0, sizeof(options));
  options.address = url;
  fixture->service = hub_service_new(&options, &error);
  assert_non_null(fixture->service);
  hub_service_set_agent_socket(fixture->service, agent_path, 2000);
}

static void pump(fixture_t *fixture, int ms) {
  int elapsed;
  for (elapsed = 0; elapsed < ms; elapsed++) {
    (void)hub_service_poll(fixture->service);
    (void)channel_c_server_poll(fixture->server);
    usleep(1000);
  }
}

static yyjson_doc *replace_body(void) {
  assert_non_null(last_replace);
  return yyjson_read(last_replace, strlen(last_replace), 0);
}

static void test_declared_shares_are_published_on_connect(void **state) {
  fixture_t *fixture = *state;
  hub_service_share_t share = {"s3", "tcp", "127.0.0.1", 9001, "{ \"mode\": \"group\", \"group\": \"editors\" }"};
  char *error = NULL;
  char service_key[128];
  yyjson_doc *doc;
  yyjson_val *wire;
  yyjson_val *attestation;
  char *publications;

  agent_start();
  start_hub(fixture);
  assert_int_equal(hub_service_share(fixture->service, &share, &error), 0);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 300);

  assert_int_equal(replace_count, 1);
  assert_int_equal(agent.bad_signatures, 0);
  assert_int_equal(hub_service_keychain_public_key(service_key, sizeof(service_key)), 0);
  doc = replace_body();
  wire = yyjson_arr_get(yyjson_obj_get(yyjson_doc_get_root(doc), "shares"), 0);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(wire, "name")), "s3");
  assert_int_equal(yyjson_get_int(yyjson_obj_get(wire, "version")), 1);
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_obj_get(wire, "policy"), "group")), "editors");
  attestation = yyjson_obj_get(wire, "attestation");
  assert_string_equal(yyjson_get_str(yyjson_obj_get(attestation, "serviceKey")), service_key);
  /* forwarded verbatim, unknown fields included */
  assert_string_equal(yyjson_get_str(yyjson_obj_get(attestation, "extra")), "kept");
  yyjson_doc_free(doc);

  publications = hub_service_share_publications(fixture->service);
  assert_non_null(strstr(publications, "\"resourceId\":\"hnr1_s3\""));
  assert_non_null(strstr(publications, "\"overlayAddress\":\"100.96.0.2\""));
  free(publications);
}

static void test_publish_update_and_remove(void **state) {
  fixture_t *fixture = *state;
  hub_service_share_t web = {"web", "tcp", "localhost", 8080, "{\"mode\":\"hub\"}"};
  hub_service_share_t api = {"api", "udp", "localhost", 9090, NULL};
  char *error = NULL;
  yyjson_doc *doc;
  yyjson_val *shares;
  char *publications;

  agent_start();
  agent.chunked = 1;
  start_hub(fixture);
  /* not connected yet */
  assert_int_equal(hub_service_publish_share(fixture->service, &web, &error), -1);
  assert_string_equal(error, "Service not started");
  free(error);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 100);
  assert_int_equal(replace_count, 0); /* nothing declared */

  assert_int_equal(hub_service_publish_share(fixture->service, &web, &error), 0);
  assert_int_equal(hub_service_publish_share(fixture->service, &api, &error), 0);
  assert_int_equal(replace_count, 2);
  doc = replace_body();
  shares = yyjson_obj_get(yyjson_doc_get_root(doc), "shares");
  assert_int_equal(yyjson_arr_size(shares), 2);
  /* name order; the default policy is private */
  assert_string_equal(yyjson_get_str(yyjson_obj_get(yyjson_arr_get(shares, 0), "name")), "api");
  assert_string_equal(
      yyjson_get_str(yyjson_obj_get(yyjson_obj_get(yyjson_arr_get(shares, 0), "policy"), "mode")), "private");
  yyjson_doc_free(doc);

  /* update the port */
  web.port = 8081;
  assert_int_equal(hub_service_publish_share(fixture->service, &web, &error), 0);
  doc = replace_body();
  shares = yyjson_obj_get(yyjson_doc_get_root(doc), "shares");
  assert_int_equal(yyjson_arr_size(shares), 2);
  assert_int_equal(yyjson_get_int(yyjson_obj_get(yyjson_obj_get(yyjson_arr_get(shares, 1), "target"), "port")), 8081);
  yyjson_doc_free(doc);

  assert_int_equal(hub_service_remove_share(fixture->service, "web", &error), 0);
  doc = replace_body();
  assert_int_equal(yyjson_arr_size(yyjson_obj_get(yyjson_doc_get_root(doc), "shares")), 1);
  yyjson_doc_free(doc);
  publications = hub_service_share_publications(fixture->service);
  assert_non_null(strstr(publications, "hnr1_api"));
  assert_null(strstr(publications, "hnr1_web"));
  free(publications);

  assert_int_equal(hub_service_remove_share(fixture->service, "web", &error), -1);
  assert_string_equal(error, "Share 'web' not found");
  free(error);
}

static void test_agent_failures_roll_back(void **state) {
  fixture_t *fixture = *state;
  hub_service_share_t web = {"web", "tcp", "localhost", 8080, NULL};
  hub_service_share_t api = {"api", "tcp", "localhost", 9090, NULL};
  char *error = NULL;
  char *publications;

  start_hub(fixture);
  assert_int_equal(hub_service_start(fixture->service, &error), 0);
  pump(fixture, 100);

  /* no agent */
  assert_int_equal(hub_service_publish_share(fixture->service, &web, &error), -1);
  assert_non_null(strstr(error, "unavailable"));
  free(error);

  /* the agent refuses */
  agent_start();
  agent.attest_status = 403;
  assert_int_equal(hub_service_publish_share(fixture->service, &web, &error), -1);
  assert_string_equal(error, "Hub Network agent rejected attestation (403): {\"error\":\"denied\"}");
  free(error);

  /* an attestation that is already expired */
  agent.attest_status = 200;
  agent.attest_ttl = -5;
  assert_int_equal(hub_service_publish_share(fixture->service, &web, &error), -1);
  assert_string_equal(error, "Local-agent attestation is expired");
  free(error);
  assert_int_equal(replace_count, 0);

  /* nothing above stayed declared */
  agent.attest_ttl = 300;
  assert_int_equal(hub_service_publish_share(fixture->service, &api, &error), 0);
  publications = hub_service_share_publications(fixture->service);
  assert_non_null(strstr(publications, "hnr1_api"));
  assert_null(strstr(publications, "hnr1_web"));
  free(publications);
}

static void test_invalid_shares(void **state) {
  fixture_t *fixture = *state;
  char *error = NULL;
  hub_service_share_t bad_protocol = {"x", "sctp", "localhost", 1, NULL};
  hub_service_share_t bad_port = {"x", "tcp", "localhost", 70000, NULL};
  hub_service_share_t bad_name = {"a\nb", "tcp", "localhost", 1, NULL};
  hub_service_share_t bad_policy = {"x", "tcp", "localhost", 1, "{\"mode\":\"keys\",\"keys\":[]}"};

  start_hub(fixture);
  assert_int_equal(hub_service_share(fixture->service, &bad_protocol, &error), -1);
  assert_string_equal(error, "Invalid Hub Network protocol");
  free(error);
  assert_int_equal(hub_service_share(fixture->service, &bad_port, &error), -1);
  free(error);
  assert_int_equal(hub_service_share(fixture->service, &bad_name, &error), -1);
  free(error);
  assert_int_equal(hub_service_share(fixture->service, &bad_policy, &error), -1);
  assert_string_equal(error, "Invalid Hub Network policy");
  free(error);
}

static void test_iso_times(void **state) {
  (void)state;
  assert_true(hs_parse_iso_ms("1970-01-01T00:00:00Z") == 0);
  assert_true(hs_parse_iso_ms("2026-10-20T20:12:00.5Z") == 1792527120500LL);
  assert_true(hs_parse_iso_ms("2026-10-20T23:12:00.500123+03:00") == 1792527120500LL);
  assert_true(hs_parse_iso_ms("2026-10-20T20:12:00") == -1);
  assert_true(hs_parse_iso_ms("yesterday") == -1);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_setup_teardown(test_declared_shares_are_published_on_connect, setup, teardown),
      cmocka_unit_test_setup_teardown(test_publish_update_and_remove, setup, teardown),
      cmocka_unit_test_setup_teardown(test_agent_failures_roll_back, setup, teardown),
      cmocka_unit_test_setup_teardown(test_invalid_shares, setup, teardown),
      cmocka_unit_test(test_iso_times),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
