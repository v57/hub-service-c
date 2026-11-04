/* What the tests' fake hubs need to answer hub/info: the vectors' keys
 * (Docs/Devices/vectors.json) and their proofs. */

#ifndef HUB_SERVICE_C_TESTS_FAKE_HUB_H
#define HUB_SERVICE_C_TESTS_FAKE_HUB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <yyjson.h>

#include "channel-c/channel_c.h"
#include "crypto.h"
#include "hub-service-c/hub_proof.h"

#define FAKE_HUB_KEY "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
#define FAKE_HUB_KEY_FILE \
  "MC4CAQAwBQYDK2VwBCIEIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBMCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
#define FAKE_OTHER_KEY "MCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="
#define FAKE_OTHER_KEY_FILE \
  "MC4CAQAwBQYDK2VwBCIEIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICMCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="

/* The nonce in a hub/info body, into out ("" without one). */
static inline void fake_hub_nonce(const char *body_json, char *out, size_t size) {
  yyjson_doc *doc = body_json ? yyjson_read(body_json, strlen(body_json), 0) : NULL;
  const char *nonce = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "nonce"));
  snprintf(out, size, "%s", nonce ? nonce : "");
  yyjson_doc_free(doc);
}

/* A hub's answer: key_file signs for claimed_key. malloc'd JSON for a handler. */
static inline char *fake_hub_info(const char *key_file, const char *claimed_key, const char *body_json,
                                  const char *challenge) {
  unsigned char key[HS_KEY_BYTES];
  char nonce[256];
  char data[512];
  char signature[HS_SIG_B64_SIZE];
  char json[1024];
  fake_hub_nonce(body_json, nonce, sizeof(nonce));
  snprintf(data, sizeof(data), "hubinfo1:%s:%s", claimed_key, nonce);
  if (hs_key_parse(key_file, key) != 0 || hs_key_sign(key, data, strlen(data), signature) != 0) return NULL;
  snprintf(json, sizeof(json), "{\"key\":\"%s\",\"protocol\":2,\"pro\":true,\"proof\":\"%s\",\"challenge\":\"%s\"}", claimed_key,
           signature, challenge);
  return channel_c_strdup(json);
}

#endif
