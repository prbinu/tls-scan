#ifndef CERTPARSE_H
#define CERTPARSE_H

// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

#include <common.h>

#define FQDN_MAXLEN 256
#define SHA1LEN 20
#define CERT_CHAIN_MAXLEN 10
#define PUBKEY_ALGSTR_LEN 16
#define SIG_ALGSTR_LEN 64
#define TS_DATE_LEN 128
#define TS_SERIALNO_LEN 128
#define TS_ERRMSG_LEN 256

/* ssl2, ssl3, tls1, tls1_1, tls1_2 tls1_3*/
#define MAX_TLS_VERSION 6

enum TLSVersion {
    SSLv2 = 0,
    SSLv3 = 1,
    TLSv1 = 2,
    TLSv1_1 = 3,
    TLSv1_2 = 4,
    TLSv1_3 = 5
};

struct x509_cert {
  char sha1_fingerprint[3*SHA1LEN+1];
  char sig_alg[SIG_ALGSTR_LEN];
  char pubkey_alg[PUBKEY_ALGSTR_LEN];
  char pubkey_ec_curve[16];
  int pubkey_size;
  BIO *key_usage;
  int x509_ver;
  char issuer_serialno[TS_SERIALNO_LEN];
  BIO *issuer;
  char serialno[TS_SERIALNO_LEN];
  BIO *subject;
  BIO *subject_cname;
  char not_before[TS_DATE_LEN];
  char not_after[TS_DATE_LEN];
  BIO *ext_key_usage;
  bool is_ca;
  BIO *name_constr;
  BIO *basic_constr;
  BIO *subject_keyid;
  char authority_keyid[256];
  bool cert_expired;
  bool valid_cert;
};

struct tls_cert {
  char host[OPT_STRLEN];
  char ip[OPT_STRLEN];
  uint16_t port;
  char cipher[128];
  char tls_version[8];
  bool secure_renego;
  char compression[32];
  char expansion[32];
  char temp_pubkey_alg[PUBKEY_ALGSTR_LEN];
  int temp_pubkey_size;
  unsigned long session_lifetime_hint;
  bool session_reuse_supported;
  bool ocsp_stapling_response;
  bool verify_ocsp_basic;
  int x509_chain_depth;
  bool verify_cert;
  char verify_cert_errmsg[TS_ERRMSG_LEN];
  bool verify_host;
  char verify_host_errmsg[TS_ERRMSG_LEN];

  struct x509_cert x509[CERT_CHAIN_MAXLEN];
  BIO *san;
  bool tls_ver_support[MAX_TLS_VERSION];
  bool *cipher_suite_support;
  SSL_SESSION *session;
  //unsigned char *ssl_session;
  // to keep track of cipher enum scan
  int reference_count;
  // to measure elapsed time
  struct timeval start_time;
  // aggregate time per host
  int elapsed_time_ms;
};

void ts_tls_cert_BIO_free(struct tls_cert *tls_cert);

void ts_tls_cert_reset(struct tls_cert *tls_cert);

void ts_tls_cert_parse(SSL *ssl, struct tls_cert *tls_cert, FILE *fp, bool pretty);

void ts_tls_print_json(struct tls_cert *tls_cert, FILE *fp, bool pretty);

/* */
const SSL_METHOD *ts_tls_get_method(int index);

#endif
