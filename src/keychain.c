/*
 * hub-pro auth keychain — ed25519 load-or-generate + token signing.
 *
 * Key file layout (TS hub-service/keychain.ts parity):
 *   base64( 48-byte PKCS8 DER private key || 44-byte SPKI DER public key )
 * = 92 raw bytes, 124 base64 chars. Public key in tokens = bytes 48..92.
 */

#include "hub-service-c/keychain.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PRIVATE_DER_LENGTH 48
#define PUBLIC_DER_LENGTH 44
#define KEY_BYTES (PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH)

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

static int b64_encode(const unsigned char *data, size_t len, char *out, size_t out_size) {
  size_t n = 4 * ((len + 2) / 3);
  unsigned char *tmp;
  if (n + 1 > out_size) return -1;
  tmp = (unsigned char *)out;
  if (!EVP_EncodeBlock(tmp, data, (int)len)) return -1;
  out[n] = '\0';
  return 0;
}

static int b64_decode(const char *in, unsigned char *out, size_t out_size, size_t *decoded) {
  size_t in_len = strlen(in);
  size_t max = (in_len / 4) * 3 + 3; /* EVP_DecodeBlock ignores padding */
  unsigned char *tmp;
  int n;
  tmp = (unsigned char *)malloc(max);
  if (!tmp) return -1;
  n = EVP_DecodeBlock(tmp, (const unsigned char *)in, (int)in_len);
  if (n < 0) {
    free(tmp);
    return -1;
  }
  /* EVP_DecodeBlock ignores padding; compute the real length. */
  if (in_len > 0 && in[in_len - 1] == '=') n--;
  if (in_len > 1 && in[in_len - 2] == '=') n--;
  if ((size_t)n > out_size) {
    free(tmp);
    return -1;
  }
  memcpy(out, tmp, (size_t)n);
  *decoded = (size_t)n;
  free(tmp);
  return 0;
}

/* Load the key file into key_bytes (92 bytes); generate + write if missing. */
static int load_or_generate(unsigned char *key_bytes) {
  const char *path = key_path();
  FILE *f = fopen(path, "rb");
  char text[256];
  size_t n = 0;

  if (f) {
    n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[n] = '\0';
    /* trim trailing whitespace */
    while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r' || text[n - 1] == ' ')) {
      text[--n] = '\0';
    }
    size_t decoded = 0;
    if (b64_decode(text, key_bytes, KEY_BYTES, &decoded) != 0 || decoded != KEY_BYTES) {
      return -1;
    }
    return 0;
  }

  /* Generate a fresh ed25519 key pair. */
  EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  if (!pkey) return -1;

  unsigned char *priv_der = NULL;
  unsigned char *pub_der = NULL;
  int priv_len = i2d_PrivateKey(pkey, &priv_der); /* PKCS8 DER */
  int pub_len = i2d_PUBKEY(pkey, &pub_der);       /* SPKI DER */
  if (priv_len != PRIVATE_DER_LENGTH || pub_len != PUBLIC_DER_LENGTH || !priv_der || !pub_der) {
    OPENSSL_free(priv_der);
    OPENSSL_free(pub_der);
    EVP_PKEY_free(pkey);
    return -1;
  }

  unsigned char raw[KEY_BYTES];
  memcpy(raw, priv_der, PRIVATE_DER_LENGTH);
  memcpy(raw + PRIVATE_DER_LENGTH, pub_der, PUBLIC_DER_LENGTH);

  char encoded[256];
  if (b64_encode(raw, KEY_BYTES, encoded, sizeof(encoded)) != 0) {
    OPENSSL_free(priv_der);
    OPENSSL_free(pub_der);
    EVP_PKEY_free(pkey);
    return -1;
  }

  f = fopen(path, "wb");
  if (!f) {
    OPENSSL_free(priv_der);
    OPENSSL_free(pub_der);
    EVP_PKEY_free(pkey);
    return -1;
  }
  fwrite(encoded, 1, strlen(encoded), f);
  fclose(f);

  memcpy(key_bytes, raw, KEY_BYTES);
  OPENSSL_free(priv_der);
  OPENSSL_free(pub_der);
  EVP_PKEY_free(pkey);
  return 0;
}

static int load_private_key(EVP_PKEY **out_pkey, unsigned char *key_bytes) {
  const unsigned char *p = key_bytes;
  EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_ED25519, NULL, &p, PRIVATE_DER_LENGTH);
  if (!pkey) return -1;
  *out_pkey = pkey;
  return 0;
}

int hub_service_keychain_public_key(char *out, size_t out_size) {
  unsigned char key_bytes[KEY_BYTES];
  if (load_or_generate(key_bytes) != 0) {
    out[0] = '\0';
    return -1;
  }
  if (b64_encode(key_bytes + PRIVATE_DER_LENGTH, PUBLIC_DER_LENGTH, out, out_size) != 0) {
    out[0] = '\0';
    return -1;
  }
  return 0;
}

int hub_service_keychain_sign(char *out, size_t out_size) {
  unsigned char key_bytes[KEY_BYTES];
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *mdctx = NULL;
  unsigned char sig[64];
  size_t sig_len = sizeof(sig);
  char expiry[24];
  char pub_b64[128];
  char sig_b64[128];
  int ok = -1;

  if (load_or_generate(key_bytes) != 0) goto done;
  if (load_private_key(&pkey, key_bytes) != 0) goto done;

  long long now = (long long)time(NULL) + 10;
  snprintf(expiry, sizeof(expiry), "%lld", now);

  mdctx = EVP_MD_CTX_new();
  if (!mdctx) goto done;
  if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1) goto done;
  if (EVP_DigestSign(mdctx, sig, &sig_len, (const unsigned char *)expiry, strlen(expiry)) != 1) goto done;
  if (sig_len != 64) goto done;

  if (b64_encode(key_bytes + PRIVATE_DER_LENGTH, PUBLIC_DER_LENGTH, pub_b64, sizeof(pub_b64)) != 0) goto done;
  if (b64_encode(sig, sig_len, sig_b64, sizeof(sig_b64)) != 0) goto done;

  if (snprintf(out, out_size, "key.%s.%s.%s", pub_b64, sig_b64, expiry) >= (int)out_size) goto done;
  ok = 0;

done:
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  if (ok != 0) out[0] = '\0';
  return ok;
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
