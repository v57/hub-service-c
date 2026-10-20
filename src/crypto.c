/*
 * Internal crypto and file helpers: base64, ed25519 key files, SHA-256 and
 * atomic writes (Docs/Devices/protocol.md section 1).
 */

#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int hs_b64_encode(const unsigned char *data, size_t len, char *out, size_t out_size) {
  size_t n = 4 * ((len + 2) / 3);
  if (n + 1 > out_size) return -1;
  if (len > 0 && !EVP_EncodeBlock((unsigned char *)out, data, (int)len)) return -1;
  out[n] = '\0';
  return 0;
}

int hs_b64_decode(const char *in, unsigned char *out, size_t out_size, size_t *decoded) {
  size_t in_len = strlen(in);
  size_t max = (in_len / 4) * 3 + 3;
  unsigned char *tmp;
  int n;
  if (in_len % 4 != 0) return -1;
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

char *hs_b64url_encode(const unsigned char *data, size_t len) {
  size_t size = 4 * ((len + 2) / 3) + 1;
  char *out = (char *)malloc(size);
  size_t i;
  size_t n;
  if (!out) return NULL;
  if (hs_b64_encode(data, len, out, size) != 0) {
    free(out);
    return NULL;
  }
  n = strlen(out);
  while (n > 0 && out[n - 1] == '=') out[--n] = '\0';
  for (i = 0; i < n; i++) {
    if (out[i] == '+') out[i] = '-';
    else if (out[i] == '/') out[i] = '_';
  }
  return out;
}

int hs_key_parse(const char *text, unsigned char key[HS_KEY_BYTES]) {
  char trimmed[256];
  size_t n = strlen(text);
  size_t decoded = 0;
  while (n > 0 && (text[n - 1] == '\n' || text[n - 1] == '\r' || text[n - 1] == ' ' || text[n - 1] == '\t')) n--;
  if (n >= sizeof(trimmed)) return -1;
  memcpy(trimmed, text, n);
  trimmed[n] = '\0';
  if (hs_b64_decode(trimmed, key, HS_KEY_BYTES, &decoded) != 0 || decoded != HS_KEY_BYTES) return -1;
  return 0;
}

int hs_key_encode(const unsigned char key[HS_KEY_BYTES], char *out, size_t out_size) {
  return hs_b64_encode(key, HS_KEY_BYTES, out, out_size);
}

int hs_key_generate(unsigned char key[HS_KEY_BYTES]) {
  EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  unsigned char *priv_der = NULL;
  unsigned char *pub_der = NULL;
  int priv_len;
  int pub_len;
  int ok = -1;

  if (!pkey) return -1;
  priv_len = i2d_PrivateKey(pkey, &priv_der); /* PKCS8 DER */
  pub_len = i2d_PUBKEY(pkey, &pub_der);       /* SPKI DER */
  if (priv_len == HS_PRIVATE_DER_LENGTH && pub_len == HS_PUBLIC_DER_LENGTH && priv_der && pub_der) {
    memcpy(key, priv_der, HS_PRIVATE_DER_LENGTH);
    memcpy(key + HS_PRIVATE_DER_LENGTH, pub_der, HS_PUBLIC_DER_LENGTH);
    ok = 0;
  }
  OPENSSL_free(priv_der);
  OPENSSL_free(pub_der);
  EVP_PKEY_free(pkey);
  return ok;
}

int hs_key_public(const unsigned char key[HS_KEY_BYTES], char out[HS_SPKI_B64_SIZE]) {
  return hs_b64_encode(key + HS_PRIVATE_DER_LENGTH, HS_PUBLIC_DER_LENGTH, out, HS_SPKI_B64_SIZE);
}

int hs_key_sign(const unsigned char key[HS_KEY_BYTES], const char *data, size_t len, char out[HS_SIG_B64_SIZE]) {
  const unsigned char *p = key;
  EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_ED25519, NULL, &p, HS_PRIVATE_DER_LENGTH);
  EVP_MD_CTX *mdctx = NULL;
  unsigned char sig[64];
  size_t sig_len = sizeof(sig);
  int ok = -1;

  if (!pkey) return -1;
  mdctx = EVP_MD_CTX_new();
  if (!mdctx) goto done;
  if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1) goto done;
  if (EVP_DigestSign(mdctx, sig, &sig_len, (const unsigned char *)data, len) != 1) goto done;
  if (sig_len != 64) goto done;
  ok = hs_b64_encode(sig, sig_len, out, HS_SIG_B64_SIZE);

done:
  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return ok;
}

static int make_dirs(const char *dir, mode_t mode) {
  char path[1024];
  size_t i;
  size_t n = strlen(dir);
  if (n == 0 || n >= sizeof(path)) return n == 0 ? 0 : -1;
  memcpy(path, dir, n + 1);
  for (i = 1; i <= n; i++) {
    if (path[i] == '/' || path[i] == '\0') {
      char saved = path[i];
      path[i] = '\0';
      if (mkdir(path, mode) != 0 && errno != EEXIST) return -1;
      path[i] = saved;
    }
  }
  return 0;
}

int hs_key_file_load(const char *path, int create, mode_t mode, int private_dirs, unsigned char key[HS_KEY_BYTES]) {
  char *text = hs_read_file(path);
  char encoded[256];
  char dir[1024];

  if (text) {
    int result = hs_key_parse(text, key);
    free(text);
    return result;
  }
  if (!create) return -1;

  hs_dirname(path, dir, sizeof(dir));
  if (make_dirs(dir, private_dirs ? 0700 : 0755) != 0) return -1;
  if (hs_key_generate(key) != 0) return -1;
  if (hs_key_encode(key, encoded, sizeof(encoded)) != 0) return -1;
  return hs_write_atomic(path, encoded, strlen(encoded), mode);
}

int hs_sha256_hex(const unsigned char *data, size_t len, char out[65]) {
  unsigned char digest[32];
  unsigned int digest_len = 0;
  unsigned int i;
  if (EVP_Digest(data, len, digest, &digest_len, EVP_sha256(), NULL) != 1 || digest_len != 32) return -1;
  for (i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", digest[i]);
  out[64] = '\0';
  return 0;
}

int hs_write_atomic(const char *path, const char *data, size_t len, mode_t mode) {
  char tmp[1100];
  int fd;
  size_t written = 0;

  if (snprintf(tmp, sizeof(tmp), "%s.tmp-%ld", path, (long)getpid()) >= (int)sizeof(tmp)) return -1;
  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd < 0) return -1;
  (void)fchmod(fd, mode);
  while (written < len) {
    ssize_t n = write(fd, data + written, len - written);
    if (n <= 0) {
      close(fd);
      unlink(tmp);
      return -1;
    }
    written += (size_t)n;
  }
  if (close(fd) != 0 || rename(tmp, path) != 0) {
    unlink(tmp);
    return -1;
  }
  return 0;
}

char *hs_read_file(const char *path) {
  FILE *f = fopen(path, "rb");
  char *data;
  long size;
  size_t n;
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  data = (char *)malloc((size_t)size + 1);
  if (!data) {
    fclose(f);
    return NULL;
  }
  n = fread(data, 1, (size_t)size, f);
  fclose(f);
  data[n] = '\0';
  return data;
}

void hs_dirname(const char *path, char *out, size_t out_size) {
  const char *slash = strrchr(path, '/');
  size_t n;
  if (!slash) {
    snprintf(out, out_size, ".");
    return;
  }
  n = (size_t)(slash - path);
  if (n == 0) n = 1; /* "/file" -> "/" */
  if (n >= out_size) n = out_size - 1;
  memcpy(out, path, n);
  out[n] = '\0';
}
