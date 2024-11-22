// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <inttypes.h>
// openssl headers
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
// libevent
#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/util.h>
// tls-scan
#include <proto-adapters.h>
#include <common.h>
#include <cert-parser.h>

extern void gnutls13_init(struct options *op);
extern int gnutls13_session_init(client_t *cli, int sock_fd);
extern ts_status_t gnutls13_handshake(client_t *cli, int sock_fd);
extern void gnutls13_session_deinit(client_t *cli);
extern void gnutls13_deinit(struct options *op);
/*
 * openssl tutorial: http://www.linuxjournal.com/article/5487?page=0,1http://www.linuxjournal.com/article/5487?page=0,1s
 */

/* https://www.openssl.org/docs/manmaster/apps/ciphers.html */
static const char *default_ciphers = "ALL:aNULL:eNULL:NULL";

static const char *sslv2_ciphers =
    "RC4-MD5:EXP-RC4-MD5:RC2-MD5:EXP-RC2-MD5:IDEA-CBC-MD5:DES-CBC-MD5:DES-CBC3-MD5";
static const char *sslv3_ciphers =
    "NULL-MD5:NULL-SHA:EXP-RC4-MD5:RC4-MD5:RC4-SHA:EXP-RC2-CBC-MD5:IDEA-CBC-SHA:EXP-DES-CBC-SHA:DES-CBC-SHA:DES-CBC3-SHA:EXP-EDH-DSS-DES-CBC-SHA:EDH-DSS-CBC-SHA:EDH-DSS-DES-CBC3-SHA:EXP-EDH-RSA-DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EXP-ADH-RC4-MD5:ADH-RC4-MD5:EXP-ADH-DES-CBC-SHA:ADH-DES-CBC-SHA:ADH-DES-CBC3-SHA:EXP1024-DES-CBC-SHA:EXP1024-RC4-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EXP1024-DHE-DSS-RC4-SHA:DHE-DSS-RC4-SHA";
static const char *tlsv1_ciphers =
    "NULL-MD5:NULL-SHA:EXP-RC4-MD5:RC4-MD5:RC4-SHA:EXP-RC2-CBC-MD5:IDEA-CBC-SHA:EXP-DES-CBC-SHA:DES-CBC-SHA:DES-CBC3-SHA:EXP-DHE-DSS-DES-CBC-SHA:DHE-DSS-CBC-SHA:DHE-DSS-DES-CBC3-SHA:EXP-DHE-RSA-DES-CBC-SHA:DHE-RSA-DES-CBC-SHA:EXP-ADH-RC4-MD5:ADH-RC4-MD5:EXP-ADH-DES-CBC-SHA:ADH-DES-CBC-SHA:ADH-DES-CBC3-SHA:AES128-SHA:DH-DSS-AES128-SHA:DH-DSS-AES256-SHA:DH-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ADH-AES128-SHA:ADH-AES256-SHA:CAMELLIA128-SHA:CAMELLIA256-SHA:DH-DSS-CAMELLIA128-SHA:DH-DSS-CAMELLIA256-SHA:DH-RSA-CAMELLIA128-SHA:DH-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-CAMELLIA256-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-CAMELLIA256-SHA:ADH-CAMELLIA128-SHA:ADH-CAMELLIA256-SHA:SEED-SHA:DH-DSS-SEED-SHA:DH-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-SEED-SHA:ADH-SEED-SHA:GOST94-GOST89-GOST89:GOST2001-GOST89-GOST89:GOST94-NULL-GOST94:GOST2001-NULL-GOST94:EXP1024-DES-CBC-SHA:EXP1024-RC4-SHA:EXP1024-DHE-DSS-DES-CBC-SHA:EXP1024-DHE-DSS-RC4-SHA:DHE-DSS-RC4-SHA:ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA";
static const char *tlsv1_2_ciphers =
    "NULL-SHA256:AES128-SHA256:AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:DH-RSA-AES128-SHA256:DH-RSA-AES256-SHA256:DH-RSA-AES128-GCM-SHA256:DH-RSA-AES256-GCM-SHA384:DH-DSS-AES128-SHA256:DH-DSS-AES256-SHA256:DH-DSS-AES128-GCM-SHA256:DH-DSS-AES256-GCM-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES128-SHA256:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES256-GCM-SHA384:ECDH-RSA-AES128-SHA256:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-GCM-SHA256:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ADH-AES128-SHA256:ADH-AES256-SHA256:ADH-AES128-GCM-SHA256:ADH-AES256-GCM-SHA384:AES128-CCM:AES256-CCM:DHE-RSA-AES128-CCM:DHE-RSA-AES256-CCM:AES128-CCM8:AES256-CCM8:DHE-RSA-AES128-CCM8:DHE-RSA-AES256-CCM8:ECDHE-ECDSA-AES128-CCM:ECDHE-ECDSA-AES256-CCM:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDH-ECDSA-CAMELLIA128-SHA256:ECDH-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA256-SHA384:ECDH-RSA-CAMELLIA128-SHA256:ECDH-RSA-CAMELLIA256-SHA384:PSK-NULL-SHA:DHE-PSK-NULL-SHA:RSA-PSK-NULL-SHA:PSK-RC4-SHA:PSK-3DES-EDE-CBC-SHA:PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:DHE-PSK-RC4-SHA:DHE-PSK-3DES-EDE-CBC-SHA:DHE-PSK-AES128-CBC-SHA:DHE-PSK-AES256-CBC-SHA:RSA-PSK-RC4-SHA:RSA-PSK-3DES-EDE-CBC-SHA:RSA-PSK-AES128-CBC-SHA:RSA-PSK-AES256-CBC-SHA:PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-AES128-GCM-SHA256:RSA-PSK-AES256-GCM-SHA384:PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384:PSK-NULL-SHA256:PSK-NULL-SHA384:DHE-PSK-AES128-CBC-SHA256:DHE-PSK-AES256-CBC-SHA384:DHE-PSK-NULL-SHA256:DHE-PSK-NULL-SHA384:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES256-CBC-SHA384:RSA-PSK-NULL-SHA256:RSA-PSK-NULL-SHA384:PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:ECDHE-PSK-RC4-SHA:ECDHE-PSK-3DES-EDE-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA:ECDHE-PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-NULL-SHA:ECDHE-PSK-NULL-SHA256:ECDHE-PSK-NULL-SHA384:PSK-CAMELLIA128-SHA256:PSK-CAMELLIA256-SHA384:DHE-PSK-CAMELLIA128-SHA256:DHE-PSK-CAMELLIA256-SHA384:RSA-PSK-CAMELLIA128-SHA256:RSA-PSK-CAMELLIA256-SHA384:ECDHE-PSK-CAMELLIA128-SHA256:ECDHE-PSK-CAMELLIA256-SHA384:PSK-AES128-CCM:PSK-AES256-CCM:DHE-PSK-AES128-CCM:DHE-PSK-AES256-CCM:PSK-AES128-CCM8:PSK-AES256-CCM8:DHE-PSK-AES128-CCM8:DHE-PSK-AES256-CCM8";

static const char *tlsv1_3_ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256";

/* mozilla */
static const char *modern_ciphers =
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256";
static const char *interm_ciphers =
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS";
static const char *old_ciphers =
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP";

/* options global object */
static options_t op;

/* stats global object */
static stats_t stats = { 0 };

/* not thread safe, but we are not using threads */
static int client_count = 0;

/* default connection timeout in sec */
const uint32_t DEFAULT_TIMEOUT = 10;

/* used for sleep - 1 millisecond = 1,000,000 Nanoseconds */
const long NANO_SECOND_MULTIPLIER = 1000000;

/* 1 sec = 1000 millisecond */
const int SECOND_MULTPLIER = 1000;

/* try upto 3 times, before we give on session reuse support test */
const int MAX_SESSION_REUSE_RETRY  = 3;

/* scan engine */
void ts_scan_start(client_t *client);

const options_t *ts_get_global_option_obj()
{
  return &op;
}

stats_t *ts_get_stats_obj()
{
  return &stats;
}

void global_init()
{

}

/* TODO
3. tls13 only scans
4. convert tls1.3 cipher name to openssl compliant name
5. implement ST_GNUTLS_CERT
6. fix port bug
7. GnuTLS cert verification
8. Review and fix client object variable init (create/init functions)
*/

/* returns current scan type/state */
scan_type_t ts_scan_type(const client_t *cli);

size_t alpn_wireformat(const char* alpn_str, unsigned char alpn[])
{
  char *c = NULL;
  char *c2 = strdup(alpn_str);
  char *tptr = c2;
  int index = 0;
  size_t len = 0;
  while ((c = strtok_r(tptr, ", ", &tptr))) {
    len = strlen(c);
    alpn[index++] = (unsigned char)len;
    memcpy(&alpn[index], c, len);
    index = index + len;
  }

  alpn[index+1] = 0;
  free(c2);
  return index;
}
// https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_ciphersuites.html
// seperate given ciphers into to TLS1.3 and pre-TLS1.3 cipher group
void get_ciphersuites_and_cipher_list(const char *ciphers,
                                   char o_ciphersuites[], char o_cipher_list[])
{
  char *c = NULL;
  char *c2 = strdup(ciphers);
  char *tptr = c2;
  size_t n = 0, m = 0;
  o_ciphersuites[0] = o_cipher_list[0] = 0;

  while ((c = strtok_r(tptr, ":", &tptr))) {
    if(strstr(tlsv1_3_ciphers, c) != NULL) {
      if (n == 0) {
        strcpy(o_ciphersuites, c);
      } else {
        strcat(o_ciphersuites, ":");
        strcat(o_ciphersuites, c);
      }

      n++;
    } else {
      if (m == 0) {
        strcpy(o_cipher_list, c);
      } else {
        strcat(o_cipher_list, ":");
        strcat(o_cipher_list, c);
      }

      m++;
    }
  }

  free(c2);
  return;
}

// https://www.openssl.org/docs/man1.1.0/ssl/SSL_CTX_set_info_callback.html
void apps_ssl_info_callback(SSL *s, int where, int ret)
{
  const char *str;
  int w;

  w = where & ~SSL_ST_MASK;

  if (w & SSL_ST_CONNECT) str = "SSL_connect";
  else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
  else str = "undefined";

  if (where & SSL_CB_LOOP) {
    printf("%s:%s\n", str, SSL_state_string_long(s));
  }
  else if (where & SSL_CB_ALERT) {
    str = (where & SSL_CB_READ) ? "read" : "write";
    printf("SSL3 alert %s:%s:%s\n",
                        str,
                        SSL_alert_type_string_long(ret),
                        SSL_alert_desc_string_long(ret));
  }
  else if (where & SSL_CB_EXIT) {
    if (ret == 0)
      printf("%s:failed in %s\n",
                                str, SSL_state_string_long(s));
    else if (ret < 0) {
      printf("%s:error in %s\n",
                                str, SSL_state_string_long(s));
    }
  }
}

/* create an SSL object, and initiaze it */
SSL *ts_ssl_create(SSL_CTX *ssl_ctx, client_t *cli)
{
  SSL *ssl = SSL_new(ssl_ctx);
  if (!ssl) {
    fprintf(stderr, "Could not create SSL/TLS session object: %s",
            ERR_error_string(ERR_get_error(), NULL));
  }

  const char *cipher = cli->op->ciphers;
  bool ssl2 = false;
  if (cli->cipher_index >= 0) {
    cipher = cli->op->cipher_enum_list[cli->cipher_index];
    if (strstr(sslv2_ciphers, cipher)) {
      ssl2 = true;
    }
  }

  scan_type_t st = ts_scan_type(cli);
  if (ST_SESSION_REUSE == st) {

    cipher = old_ciphers; // default_ciphers;  // default cipher list is too long
    if (!SSL_set_ssl_method(ssl, SSLv23_client_method())) {
      fprintf(stderr, "%s %d %s\n", "SSL_set_ssl_method failed, skipping..",
                                                   cli->tls_ver_index, cipher);
    }

    if (cli->tls_cert->session != NULL) {
      SSL_set_session(ssl, cli->tls_cert->session);
    }

  } else if (ST_TLS_VERSION == st) {
    // TODO set cipher to ciphers based on tls version
    cipher = default_ciphers;

    if (cli->tls_ver_index == 0) {
      cipher = sslv2_ciphers;
    }

    SSL_set_options(ssl, ts_tls_get_options(cli->tls_ver_index));

    if (!SSL_set_ssl_method(ssl, ts_tls_get_method(cli->tls_ver_index))) {
     fprintf(stderr, "%s %d %s\n", "SSL_set_ssl_method failed, skipping..",
                                                   cli->tls_ver_index, cipher);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  } else if (cli->op->ssl2) {

    if (!SSL_set_ssl_method(ssl, SSLv2_client_method())) {
      fprintf(stderr, "%s %d %s\n",
                                "SSL_set_ssl_method (SSL2) failed, skipping..",
                                                   cli->tls_ver_index, cipher);
    }
#endif
  } else {

    if (!SSL_set_ssl_method(ssl, (ssl2) ? SSLv2_client_method() :
                                                    SSLv23_client_method())) {
      fprintf(stderr, "%s %d %s\n", "SSL_set_ssl_method failed, skipping..",
                                                 cli->tls_ver_index, cipher);
    }
  }

  if (ST_CERT == st) {

    if (cli->op->session_in_fp) {
      cli->tls_cert->session = PEM_read_SSL_SESSION(cli->op->session_in_fp,
                                                            NULL, NULL, NULL);
      SSL_set_session(ssl, cli->tls_cert->session);
      PEM_write_SSL_SESSION(stderr, cli->tls_cert->session);
    }

    // check only for the first time
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
  }

  // a hack, to void additional local variables
  get_ciphersuites_and_cipher_list(cipher, op.ciphersuites, op.cipher_list);

  // https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_ciphersuites.html
  // if no ciphers, then set NULL
  if (!SSL_set_cipher_list(ssl,
                (strlen(op.cipher_list) == 0) ? "NO-CIPHER": op.cipher_list)) {
      fprintf(stderr, "%s %d %s\n", "SSL_set_cipher_list failed, skipping..",
                                                    cli->cipher_index, cipher);
      SSL_free(ssl);
      return NULL;
  }
#if OPENSSL_VERSION_NUMBER > 0x10101010L
  if (strlen(op.ciphersuites) > 0) {
    if (!SSL_set_ciphersuites(ssl, op.ciphersuites)) {
      fprintf(stderr, "%s %d %s\n", "SSL_set_ciphersuites failed, skipping..",
                                                    cli->cipher_index, cipher);
      SSL_free(ssl);
      return NULL;
    }
  }
#endif

  if (!cli->op->ssl2) {
    // Set hostname for SNI extension
    if (cli->op->sni[0] != 0) {
      SSL_set_tlsext_host_name(ssl, cli->op->sni);
    } else if (cli->host[0] != 0) {
      SSL_set_tlsext_host_name(ssl, cli->host);
    }

    // Set ALPN protocol ids
    if (cli->op->alpn_size != 0) {
      SSL_set_alpn_protos(ssl, cli->op->alpn, cli->op->alpn_size);
    }
  }

  return ssl;
}

SSL_CTX *ts_ssl_ctx_create(const char *ciphers, const char *cacert, bool ssl2)
{
  // Initialize SSL
  SSL_library_init();
  SSL_load_error_strings();

  SSL_CTX *ssl_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if (ssl2) {
    ssl_ctx = SSL_CTX_new(SSLv2_client_method());
  } else {
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  }
#else
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif

  //SSL_CTX_set_info_callback(ssl_ctx, apps_ssl_info_callback);

  if (!SSL_CTX_set_cipher_list(ssl_ctx,
                (strlen(op.cipher_list) == 0) ? "NO-CIPHER": op.cipher_list)) {
      fprintf(stderr, "%s\n", "SSL_CTX_set_cipher_list failed, exiting..");
      exit(EXIT_FAILURE);
  }
#if OPENSSL_VERSION_NUMBER > 0x10101010L
  if (strlen(op.ciphersuites) > 0) {
    if (!SSL_CTX_set_ciphersuites(ssl_ctx, op.ciphersuites)) {
      fprintf(stderr, "%s\n", "SSL_CTX_set_ciphersuites failed, exiting..");
      exit(EXIT_FAILURE);
    }
  }

#endif
  /*
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, dubug_ssl_verify_callback);
  SSL_CTX_set_info_callback(ssl_ctx, dubug_ssl_info_callback);
  SSL_CTX_set_msg_callback(ssl_ctx, dubug_ssl_msg_callback);
  */

  long res = SSL_CTX_load_verify_locations(ssl_ctx, cacert, NULL);
  if (1 != res) {
    fprintf(stderr, "%s\n", "Error: Root CA bundle with correct path required \
(--cacert flag); exiting..");
    exit(EXIT_FAILURE);
  }

  SSL_CTX_set_verify_depth(ssl_ctx, 5);

  SSL_COMP_add_compression_method(0, COMP_zlib());
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_COMP_add_compression_method(1, COMP_rle());
#endif
  return ssl_ctx;
}

void ts_ssl_destroy(SSL_CTX * ssl_ctx)
{
  SSL_CTX_free(ssl_ctx);
  ERR_free_strings();
  ERR_remove_thread_state(NULL);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  //sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
  SSL_COMP_free_compression_methods();
}

/* Initializes client object */
client_t *ts_client_create(struct event_base *evbase,
                               struct evdns_base *dnsbase,
                               SSL_CTX *ssl_ctx,
                               const options_t *options,
                               int id)
{
  client_count++;
  client_t *cli = (client_t*)malloc(sizeof(client_t));
  assert(cli != NULL);
  // memset(cli, 0, sizeof(client_t));
  cli->id = id;

  cli->session_reuse_supported = false;
  cli->reuse_test_count = -1;
  cli->cipher_index = -1;
  cli->cipher1_3_index = -1;
  cli->tls_ver_index = -1;
  cli->event_status = TS_SUCCESS;
  cli->tls_cert = NULL;
  cli->bev = NULL;
  cli->temp_bev = NULL;

  // life time is as same as client object.
  cli->dnsbase = dnsbase;
  cli->evbase = evbase;
  cli->port = options->port;
  cli->ssl_ctx = ssl_ctx;
  cli->timeout = options->timeout;
  cli->op = options;
  cli->adapter_index = op.protocol_adapter_index;
  cli->scan_engine = SE_OPENSSL;

  // call adapter create
  ts_adapter_create(cli);
  return cli;
}

/*
 Called for the first time scanning a remote server. Subsequent
 calls for cipher/tls-version enum scans do not call this.
*/
bool ts_client_init(client_t *cli)
{
  char *input =NULL;
  cli->host[0] = cli->ip[0] = 0;

  if (cli->op->ip_input) {
    input = cli->ip;
  } else {
    input = cli->host;
  }

  char line[DEFAULT_HOSTLEN+5];
  if (ts_get_line_input(&in_handle, line, DEFAULT_HOSTLEN) == -1) {
    return false;
  }

  ts_parse_connect_target(line, input, OPT_STRLEN, &cli->port);

  ts_tls_cert_reset(cli->op->cert_obj_pool[cli->id]);
  cli->tls_cert = cli->op->cert_obj_pool[cli->id];
  cli->session_reuse_supported = false;
  cli->reuse_test_count = -1;
  cli->cipher_index = -1;
  cli->cipher1_3_index = -1;
  cli->tls_ver_index = -1;
  cli->event_status = TS_SUCCESS;
  cli->state = ST_CERT;
  cli->scan_engine = SE_OPENSSL;

  gettimeofday(&cli->tls_cert->start_time, NULL);
  ts_adapter_init(cli);
  return true;
}

void ts_client_reset(client_t * cli)
{
  if (cli->bev) {
    bufferevent_disable(cli->bev, EV_READ | EV_WRITE);

    SSL *ssl = bufferevent_openssl_get_ssl(cli->bev);
    if (ssl) {
      SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
      SSL_shutdown(ssl);
    }

    bufferevent_free(cli->bev);
    cli->bev = NULL;
    cli->temp_bev = NULL;
    cli->event_status = TS_SUCCESS;
  }

  ts_adapter_reset(cli);
}

void ts_client_destroy(client_t * cli)
{
  if (cli) {
    struct event_base *base = cli->evbase;
    ts_adapter_destroy(cli);

    if (--client_count == 0) {
      event_base_loopexit(base, NULL);
    }

    free(cli);
  }

}

void print_tls_cert(client_t *cli)
{
  struct timeval t;
  gettimeofday(&t, NULL);

  cli->tls_cert->elapsed_time_ms =
                     (t.tv_sec - cli->tls_cert->start_time.tv_sec) * 1000 +
                     (t.tv_usec - cli->tls_cert->start_time.tv_usec)/1000;

  ts_tls_print_json(cli->tls_cert, cli->op->certlog_fp, cli->op->pretty);
}

/* returns the current scan type/state */
scan_type_t ts_scan_type(const client_t *cli)
{
  return cli->state;
}

void ts_scan_parallel_host_scan(client_t *cli);

/* Use to determine the next test. The test could be tls version,
   enum, cipher enum, session-reuse check or move over to next server.
   This also updates the current state to next state.
*/
scan_type_t ts_scan_next(client_t *cli)
{
  // default scan engine. overridden for TLS 1.3+ scans
  cli->scan_engine = SE_OPENSSL;
  if ((cli->op->session_reuse_test) && (!cli->session_reuse_supported) &&
      (cli->reuse_test_count+1 < MAX_SESSION_REUSE_RETRY)) {
    cli->reuse_test_count++;
    cli->state = ST_SESSION_REUSE;
    return ST_SESSION_REUSE;
  }

  // parallelize cipher and tls-version enumerations
  if (((cli->op->tls_vers_enum) || (cli->op->cipher_enum)) &&
       (cli->op->host[0] != 0) && (!op.no_parallel_enum)) {
    cli->state = ST_HOST_PARALLEL;
    return ST_HOST_PARALLEL;
  }

  // tls-version enum scans
  if (cli->op->tls_vers_enum) {
    if (cli->tls_ver_index+1 < MAX_OPENSSL_TLS_VERSION) {
      cli->tls_ver_index++;
      nanosleep(&cli->op->ts_sleep, NULL);
      cli->scan_engine = SE_OPENSSL;
      cli->state = ST_TLS_VERSION;
      return ST_TLS_VERSION;
    }

    // GnuTLS 1.3 scans
    if (cli->tls_ver_index+1 < MAX_TLS_VERSION) {
      cli->tls_ver_index++;
      nanosleep(&cli->op->ts_sleep, NULL);
      if ((!cli->op->ssl2) && (!cli->op->ssl3) && (!cli->op->tls1)) {
        cli->scan_engine = SE_GNUTLS;
        cli->state = ST_GNUTLS_VERSION;
        return ST_GNUTLS_VERSION;
      }
    }
  }

  // cipher enum scans
  if (cli->op->cipher_enum) {
    if (cli->cipher_index+1 < cli->op->cipher_enum_count) {
      cli->cipher_index++;

      // scan CHACHA ciphers using gnults
      if (strstr(cli->op->cipher_enum_list[cli->cipher_index], "CHACHA") != NULL) {
        nanosleep(&cli->op->ts_sleep, NULL);
        cli->scan_engine = SE_GNUTLS;
        cli->state = ST_GNUTLS_1_2CHACHA_CIPHER;
        return ST_GNUTLS_1_2CHACHA_CIPHER;
      }

      // continue with same host/ip, but different cipher
      nanosleep(&cli->op->ts_sleep, NULL);
      cli->scan_engine = SE_OPENSSL;
      cli->state = ST_CIPHER;
      return ST_CIPHER;
    }

    if (cli->cipher1_3_index+1 < cli->op->cipher1_3_enum_count) {
      cli->cipher1_3_index++;
      nanosleep(&cli->op->ts_sleep, NULL);
      cli->scan_engine = SE_GNUTLS;
      cli->state = ST_GNUTLS_CIPHER;
      return ST_GNUTLS_CIPHER;

    }
  }

  cli->state = ST_CERT_PRINT;
  return ST_CERT_PRINT;
}

void ts_scan_connect(client_t *cli, bool ip_input);

/* An endpoint scan is complete (include session-reuse, tls-version enum
   cipher enum).
*/
void ts_scan_end(client_t * cli, scan_type_t st)
{

  switch (st) {

  case ST_CERT:
    ts_tls_cert_BIO_free(cli->tls_cert);
    break;

  case ST_CERT_PRINT:
    print_tls_cert(cli);
    ts_tls_cert_BIO_free(cli->tls_cert);
    break;

  default:
    break;
  }

  if ((!cli->op->no_parallel_enum) && ((op.outfile[0] != 0) || (op.stats_outfile[0] != 0))) {
    uint64_t et = ts_elapsed_time(stats.start_time);

    ++stats.hcount;
    if (op.outfile[0] != 0) {
      fprintf(stdout, "\relapsed-time: %"PRIu64" secs | status: %d/%d | tls-handshake: %d | target: %s          ", et/1000000, stats.hcount, stats.connect_count, stats.gross_tls_handshake, cli->host);
      fflush(stdout);
    }

    if (op.stats_outfile[0] != 0) {
      fprintf(cli->op->statsfile_fp, "%"PRIu64" %d %d %d %d %d %d %d %d %d %d %s\n", et/1000000, stats.hcount, stats.connect_count, stats.network_err_count, stats.dns_errcount, stats.remote_close_count, stats.error_count, stats.connect_err_count, stats.timeout_count, stats.tls_handshake, stats.gross_tls_handshake, cli->host);
    }
  }

  ts_scan_start(cli);
  return;
}

/* connection close */
void ts_scan_disconnect(client_t * cli)
{
  if (cli) {

    // only for single scans + with no_parallel_scans
    if ((cli->op->no_parallel_enum) && ((op.outfile[0] != 0) || (op.stats_outfile[0] != 0))) {
      uint64_t et = ts_elapsed_time(stats.start_time);

      FILE *fp = stdout;
      char cr = '\r';
      if (op.stats_outfile[0] != 0) {
        fp = cli->op->statsfile_fp;
        cr = '\n';
      }

      if ((cli->tls_ver_index < 0) && (cli->cipher_index < 0)) {
        fprintf(fp, "%celapsed-time: %"PRIu64".%"PRIu64" secs | tls-handshake: %d | scan-type: cert         ", cr, et/1000000, et%1000000, stats.gross_tls_handshake);
      } else if (cli->state == ST_TLS_VERSION || cli->state == ST_GNUTLS_VERSION) {
        fprintf(fp, "%celapsed-time: %"PRIu64".%"PRIu64" secs | tls-handshake: %d | scan-type: tls-version-enum %s         ", cr, et/1000000, et%1000000, stats.gross_tls_handshake, get_ssl_version_str(cli->tls_ver_index));
      } else if (cli->state == ST_GNUTLS_CIPHER) {
        fprintf(fp, "%celapsed-time: %"PRIu64".%"PRIu64" secs | tls-handshake: %d | scan-type: cipher %d:%d %s         ", cr, et/1000000, et%1000000, stats.gross_tls_handshake, cli->cipher1_3_index+1 + cli->cipher_index+1, cli->op->cipher1_3_enum_count + cli->op->cipher_enum_count, cli->op->cipher1_3_enum_list[cli->cipher1_3_index]);
      } else if (cli->state == ST_CIPHER) {
        fprintf(fp, "%celapsed-time: %"PRIu64".%"PRIu64" secs | tls-handshake: %d | scan-type: cipher %d:%d %s         ", cr, et/1000000, et%1000000, stats.gross_tls_handshake, cli->cipher_index+1, cli->op->cipher_enum_count + cli->op->cipher1_3_enum_count, cli->op->cipher_enum_list[cli->cipher_index]);
      }

      if (cr == '\r') {
        fflush(stdout);
      }

    }

    ts_client_reset(cli);
    scan_type_t st =  ts_scan_next(cli);
    switch (st) {

    case ST_SESSION_REUSE:
      ts_scan_connect(cli, true);
      break;

    case ST_HOST_PARALLEL:
      ts_scan_parallel_host_scan(cli);
      //ts_scan_start(cli);
      break;

    case ST_TLS_VERSION:
      ts_scan_connect(cli, true);
      break;

    case ST_CIPHER:
      ts_scan_connect(cli, true);
      break;

    case ST_GNUTLS_VERSION:
    case ST_GNUTLS_CIPHER:
    case ST_GNUTLS_1_2CHACHA_CIPHER:
      ts_scan_connect(cli, true);
      break;

    case ST_CERT:
    case ST_CERT_PRINT:
    default:
      ts_scan_end(cli, st);
      break;
    }
  }
}

void ts_scan_error(client_t * cli)
{
  scan_type_t st = ST_CERT;
  if (cli) {

    // error, move to next remote server
    if ((cli->cipher_index == -1) && (cli->tls_ver_index == -1) &&
                                             (cli->reuse_test_count == -1)) {
      stats.connect_err_count++;
    } else if (cli->event_status == TS_HSHAKE_ERR) {
      //continue with next cipher/tls-version scan
      ts_scan_disconnect(cli);
      return;

    } else {
      st = ST_CERT_PRINT;
    }

    ts_client_reset(cli);
    ts_scan_end(cli, st);
    return;
  }

  // move on..
  ts_scan_start(cli);
  return;
}

static int set_linger(int fd, int onoff, int linger)
{
  struct linger lgr;
  lgr.l_linger = linger;
  lgr.l_onoff = onoff;

  int res = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lgr, sizeof(lgr));
  assert(res == 0);
  return res;
}

void tls_scan_connect_error_handler(struct bufferevent *bev, short events,
                                                                client_t *cli)
{
  cli->event_status = TS_HSHAKE_ERR;

  if (events & BEV_EVENT_ERROR) {
    int err;
    err = bufferevent_socket_get_dns_error(bev);
    if (err) {
      fprintf(stderr, "host: %s; ip: %s; error: DNS; errormsg: %s\n",
                               cli->host, cli->ip, evutil_gai_strerror(err));
      stats.dns_errcount++;
      return;
    }
  }

  if (events & BEV_EVENT_EOF) {
    stats.remote_close_count++;
    fprintf(stderr, "host: %s; ip: %s; error: Network; errormsg: \
                     Disconnected from the remote host\n", cli->host, cli->ip);

  } else if (events & BEV_EVENT_TIMEOUT) {
    cli->event_status = TS_TIMEOUT;
    stats.timeout_count++;
    fprintf(stderr, "host: %s; ip: %s; port: %d; error: Timeout\n", cli->host,
                                                           cli->ip, cli->port);

  } else if (events & BEV_EVENT_READING) {
    stats.network_err_count++;

    scan_type_t t = ts_scan_type(cli);

    // it is expected to fail version and cipher enumeration requests
    // so skip printing msgs to error console for those requests
    if ((ST_TLS_VERSION != t) && (ST_CIPHER != t)) {
      fprintf(stderr, "host: %s; ip: %s; error: Network; errormsg: \
                     Error encountered while reading\n", cli->host, cli->ip);
    }

  } else if (events & BEV_EVENT_WRITING) {
    stats.network_err_count++;
    fprintf(stderr, "host: %s; ip: %s; error: Network; errormsg: \
                     Error encountered while writing\n", cli->host, cli->ip);

  } else {
    stats.error_count++;
    fprintf(stderr, "host: %s; ip: %s; error: Unknown; errormsg: %s\n",
    cli->host, cli->ip, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
  }
}

/*
 * ts_scan_tls_connect callback is called after the successful completion
 * of TLS handshake
 */
void ts_scan_tls_connect_cb(struct bufferevent *bev, short events, void *ptr)
{
  client_t *cli = (client_t *) ptr;
  assert(cli != NULL);

  if (events & BEV_EVENT_CONNECTED) {
    stats.gross_tls_handshake++;

    switch (ts_scan_type(cli)) {
    case ST_CERT:
      stats.tls_handshake++;
      strcpy(cli->tls_cert->host, cli->host);
      cli->tls_cert->port = cli->port;

      int fd;
      if (cli->ip[0] == 0) {
        fd = bufferevent_getfd(bev);
        ts_get_ip(fd, cli->ip, sizeof(cli->ip));
      }

      strcpy(cli->tls_cert->ip, cli->ip);
      ts_tls_cert_parse(bufferevent_openssl_get_ssl(bev), cli->tls_cert,
                                       cli->op->certlog_fp, cli->op->pretty);

      if (cli->op->session_in_fp) {
        if (SSL_session_reused(bufferevent_openssl_get_ssl(bev))) {
          cli->session_reuse_supported = true;
          cli->tls_cert->session_reuse_supported = true;
        } else {
          //fprintf(stderr, "NEW SESSION\n");
        }
      }

      break;

    case ST_SESSION_REUSE:
      // Was the stored session reused?
      if (SSL_session_reused(bufferevent_openssl_get_ssl(bev))) {
        cli->session_reuse_supported = true;
        cli->tls_cert->session_reuse_supported = true;
      } else {
        //printf("NEW SESSION\n");
      }

      break;

    case ST_TLS_VERSION:
      cli->tls_cert->tls_ver_support[cli->tls_ver_index] = true;
      break;

    case ST_CIPHER:
      cli->tls_cert->cipher_suite_support[cli->cipher_index] = true;
      break;

    default:
      assert(0);
      break;
    }

    ts_scan_disconnect(cli);

  } else {
    tls_scan_connect_error_handler(bev, events, cli);
    ts_scan_error(cli);
  }

  return;
}

void ts_scan_do_tls1_3_handshake_cb(evutil_socket_t fd, short event, void *ptr)
{
  client_t *cli = (client_t *) ptr;
  assert(cli != NULL);

  if (event == EV_READ) {
    ts_status_t status = gnutls13_handshake(cli, fd);
    if (status == TS_EAGAIN_ERR) {
      const struct timeval timeout = { cli->timeout, 0 };
      assert(cli->handshake1_3_ev != NULL);
      event_add(cli->handshake1_3_ev, &timeout);
      return;
    }

    if (status == TS_SUCCESS) {
      stats.gross_tls_handshake++;
    }

    if (status == TS_HSHAKE_ERR) {
      stats.network_err_count++;
    }
  }

  if (event == EV_TIMEOUT) {
    stats.timeout_count++;
  }

  if (cli->handshake1_3_ev) {
    event_free(cli->handshake1_3_ev);
  }

  gnutls13_session_deinit(cli);
  ts_scan_disconnect(cli);
}

/* TLS handshake on existing TCP session, used by protocol adapters */
void ts_scan_do_tls1_3_handshake(client_t *cli)
{
  int fd;
  fd = bufferevent_getfd(cli->temp_bev);
  gnutls13_session_init(cli, fd);
  ts_status_t status = gnutls13_handshake(cli, fd);
  if (status == TS_EAGAIN_ERR) {
    const struct timeval timeout = { cli->timeout, 0 };
    cli->handshake1_3_ev = event_new(cli->evbase, fd, EV_TIMEOUT|EV_READ,
                        ts_scan_do_tls1_3_handshake_cb, cli);
    assert(cli->handshake1_3_ev != NULL);
    event_add(cli->handshake1_3_ev, &timeout);
    return;
  }

  if (status == TS_SUCCESS) {
    stats.gross_tls_handshake++;
  }

  if (status == TS_HSHAKE_ERR) {
    stats.network_err_count++;
  }

  gnutls13_session_deinit(cli);
  ts_scan_disconnect(cli);
}

/* TLS handshake on existing TCP session, used by protocol adapters */
void ts_scan_do_tls_handshake(client_t *cli)
{
  struct bufferevent *bev_ssl = NULL;
  SSL *ssl = NULL;
  ssl = ts_ssl_create(cli->ssl_ctx, cli);
  if (!ssl) {
    cli->event_status = TS_SSL_CREAT_ERR;
    ts_scan_error(cli);
    return;
  }

  bev_ssl = bufferevent_openssl_filter_new(cli->evbase,
                                           cli->temp_bev, ssl,
                                           BUFFEREVENT_SSL_CONNECTING,
                                           BEV_OPT_CLOSE_ON_FREE); // |
                                           //BEV_OPT_DEFER_CALLBACKS);

  if (!bev_ssl) {
    fprintf(stderr, "host: %s; ip: %s; error: Bufferevent_openssl_new\n",
                                                           cli->host, cli->ip);
    cli->event_status = TS_CONN_ERR;
    ts_scan_error(cli);
  } else {
    cli->bev = cli->temp_bev = bev_ssl;
    bufferevent_setcb(cli->bev, NULL, NULL, ts_scan_tls_connect_cb, cli);
  }
}

// called by adapter functions (proto-adapters.c)
void ts_scan_tcp_write(client_t *cli,
                                   const unsigned char *data, size_t data_len)
{
  if (cli->temp_bev) {
    bufferevent_write(cli->temp_bev, data, data_len);
  } else {
    bufferevent_write(cli->bev, data, data_len);
  }
}

void ts_scan_tcp_read_cb(struct bufferevent *bev, void *ptr)
{
  client_t *cli = (client_t *) ptr;
  assert(cli != NULL);

  struct evbuffer *input = bufferevent_get_input(bev);
  size_t nread = evbuffer_get_length(input);
  unsigned char *read_buf = malloc(nread+1);
  memcpy(read_buf, evbuffer_pullup(input, -1), nread);

  cli->temp_bev = bev;
  evbuffer_drain(input, nread);

  ts_adapter_read(cli, read_buf, nread);
  free (read_buf);
  return;
}

void ts_scan_tcp_write_cb(struct bufferevent *bev, void *ptr)
{
  client_t *cli = (client_t *) ptr;
  assert(cli != NULL);

  ts_adapter_write(cli);
  return;
}

void ts_scan_tcp_connect_cb(struct bufferevent *bev, short events, void *ptr)
{
  client_t *cli = (client_t *) ptr;
  assert(cli != NULL);

  if (events & BEV_EVENT_CONNECTED) {
    set_linger(bufferevent_getfd(cli->bev), 1, 0);

    int fd;
    fd = bufferevent_getfd(bev);
    ts_get_ip(fd, cli->ip, sizeof(cli->ip));

    // if tls >= 1.3
    if ((cli->scan_engine == SE_GNUTLS) && (cli->adapter_index == 0)) {
      gnutls13_session_init(cli, fd);
      ts_status_t status = gnutls13_handshake(cli, fd);
      if (status == TS_EAGAIN_ERR) {
        const struct timeval timeout = { cli->timeout, 0 };
        cli->handshake1_3_ev = event_new(cli->evbase, fd, EV_TIMEOUT|EV_READ,
                                          ts_scan_do_tls1_3_handshake_cb, cli);
        assert(cli->handshake1_3_ev != NULL);
        event_add(cli->handshake1_3_ev, &timeout);
        return;
      }

      if (status == TS_SUCCESS) {
        stats.gross_tls_handshake++;
      }

      if (status == TS_HSHAKE_ERR) {
        stats.network_err_count++;
      }

      gnutls13_session_deinit(cli);
      ts_scan_disconnect(cli);
    } else {
      // starttls and tls < 1.3 scans
      bufferevent_enable(cli->bev, EV_READ | EV_WRITE);
      ts_adapter_connect(cli);
    }
  } else {
    tls_scan_connect_error_handler(bev, events, cli);
    ts_scan_error(cli);
  }
}

/* Connecting to the remote peer using given hostname and port */
void ts_scan_tcp_connect_hostname(client_t * cli)
{
  int ret = 0;
  cli->bev = bufferevent_socket_new(cli->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
  assert(cli->bev != NULL);

  bufferevent_setcb(cli->bev, ts_scan_tcp_read_cb, ts_scan_tcp_write_cb,
                                                  ts_scan_tcp_connect_cb, cli);
  const struct timeval timeout = { cli->timeout, 0 };
  bufferevent_set_timeouts(cli->bev, &timeout, &timeout);

  ret = bufferevent_socket_connect_hostname(cli->bev, cli->dnsbase,
                                            AF_UNSPEC, cli->host, cli->port);

  if (ret != 0) {
    fprintf(stderr, "host: %s; ip: %s; error: Failed to connect remote host\n",
                                                           cli->host, cli->ip);
    cli->event_status = TS_CONN_ERR;
    ts_scan_error(cli);
  }
}

/* Connecting to the remote peer using given IP and port */
void ts_scan_tcp_connect(client_t * cli)
{
  int ret = 0;
  cli->bev = bufferevent_socket_new(cli->evbase, -1, BEV_OPT_CLOSE_ON_FREE);
  assert(cli->bev != NULL);

  bufferevent_setcb(cli->bev, ts_scan_tcp_read_cb, ts_scan_tcp_write_cb,
                                                  ts_scan_tcp_connect_cb, cli);
  const struct timeval timeout = { cli->timeout, 0 };
  bufferevent_set_timeouts(cli->bev, &timeout, &timeout);

  char ip_port[DEFAULT_HOSTLEN+8];
  if (strstr(cli->ip, ":") == NULL) {
    snprintf(ip_port, DEFAULT_HOSTLEN+8, "%s:%d", cli->ip, cli->port);
  } else {
    snprintf(ip_port, DEFAULT_HOSTLEN+8, "[%s]:%d", cli->ip, cli->port);
  }

  struct sockaddr_storage ss;
  int len = sizeof(ss);
  memset(&ss, 0, sizeof(ss));

  ret = evutil_parse_sockaddr_port(ip_port, (struct sockaddr *)&ss, &len);
  if (ret != 0) {
    fprintf(stderr, "error: Failed to parse remote ip:port: %s\n", ip_port);
    cli->event_status = TS_CONN_ERR;
    ts_scan_error(cli);
  }

  ret = bufferevent_socket_connect(cli->bev, (struct sockaddr *)&ss, len);
  if (ret != 0) {
    fprintf(stderr, "error: Failed to connect remote ip:port: %s\n", ip_port);
    cli->event_status = TS_CONN_ERR;
    ts_scan_error(cli);
  }
}

void tls_rw_dummy_cb(struct bufferevent *bev, void *ptr)
{
  return;
}


/* Connecting to the remote peer using given hostname and port.
 * this function does DNS lookup, which may incur time due to
 * the rate limits enforced by DNS resolvers
 */
void ts_scan_tls_connect_hostname(client_t * cli)
{
  int ret = 0;
  SSL *ssl = ts_ssl_create(cli->ssl_ctx, cli);
  if (!ssl) {
    cli->event_status = TS_SSL_CREAT_ERR;
    ts_scan_error(cli);
    return;
  }

  cli->bev =
      bufferevent_openssl_socket_new(cli->evbase, -1, ssl,
                                     BUFFEREVENT_SSL_CONNECTING,
                                     BEV_OPT_DEFER_CALLBACKS |
                                     BEV_OPT_CLOSE_ON_FREE);
  assert(cli->bev != NULL);
  bufferevent_setcb(cli->bev, tls_rw_dummy_cb, tls_rw_dummy_cb,
                                               ts_scan_tls_connect_cb, cli);

  const struct timeval timeout = { cli->timeout, 0 };
  bufferevent_set_timeouts(cli->bev, &timeout, &timeout);

  //set_linger(bufferevent_getfd(bev), 1, 0);

  ret = bufferevent_socket_connect_hostname(cli->bev, cli->dnsbase,
                                            AF_UNSPEC, cli->host, cli->port);

  if (ret != 0) {
    fprintf(stderr, "host: %s; ip: %s; error: Failed to connect remote host\n",
                                                           cli->host, cli->ip);
    cli->event_status = TS_CONN_ERR;
    ts_scan_error(cli);
  }
}

/* Connecting to the remote peer using given IP and port */
void ts_scan_tls_connect(client_t * cli)
{
  int ret = 0;
  SSL *ssl = ts_ssl_create(cli->ssl_ctx, cli);
  if (!ssl) {
    cli->event_status = TS_SSL_CREAT_ERR;
    ts_scan_error(cli);
    return;
  }

  cli->bev =
      bufferevent_openssl_socket_new(cli->evbase, -1, ssl,
                                     BUFFEREVENT_SSL_CONNECTING,
                                     BEV_OPT_DEFER_CALLBACKS |
                                     BEV_OPT_CLOSE_ON_FREE);
  assert(cli->bev != NULL);
  bufferevent_setcb(cli->bev, tls_rw_dummy_cb, tls_rw_dummy_cb,
                                                  ts_scan_tls_connect_cb, cli);

  const struct timeval timeout = { cli->timeout, 0 };
  bufferevent_set_timeouts(cli->bev, &timeout, &timeout);

  char ip_port[DEFAULT_HOSTLEN+8];
  if (strstr(cli->ip, ":") == NULL) {
    snprintf(ip_port, DEFAULT_HOSTLEN+8, "%s:%d", cli->ip, cli->port);
  } else {
    snprintf(ip_port, DEFAULT_HOSTLEN+8, "[%s]:%d", cli->ip, cli->port);
  }

  struct sockaddr_storage ss;
  int len = sizeof(ss);
  memset(&ss, 0, sizeof(ss));

  ret = evutil_parse_sockaddr_port(ip_port, (struct sockaddr *)&ss, &len);
  if (ret != 0) {
    fprintf(stderr, "error: Failed to parse remote ip:port: %s\n", ip_port);
    cli->event_status = TS_CONN_ERR;
    ts_scan_error(cli);
  }

  ret = bufferevent_socket_connect(cli->bev, (struct sockaddr *)&ss, len);
  if (ret != 0) {
    fprintf(stderr, "error: Failed to connect remote ip:port: %s\n", ip_port);
    cli->event_status = TS_CONN_ERR;
    ts_scan_error(cli);
  }
}

void ts_scan_connect(client_t *cli, bool ip_input)
{

  if (cli->scan_engine == SE_GNUTLS) {
    // gnutls both tls/starttls
    if (ip_input) {
      ts_scan_tcp_connect(cli);
    } else {
      ts_scan_tcp_connect_hostname(cli);
    }

    return;
  }

  if (cli->adapter_index == 0) {
    // tls
    if (ip_input) {
      ts_scan_tls_connect(cli);
    } else {
      ts_scan_tls_connect_hostname(cli);
    }

  } else {
     // starttls
    if (ip_input) {
      ts_scan_tcp_connect(cli);
    } else {
      ts_scan_tcp_connect_hostname(cli);
    }

  }
}

void ts_scan_parallel_host_scan(client_t *cli);

/* parallel cipher and tls-version enum scan is enabled
    only when --connect cmdline option is used
 */
void ts_scan_parallel_host_scan(client_t *cli)
{
  if ((cli->tls_ver_index == -1) && (cli->cipher_index == -1)) {
    int i = 0;

    if (cli->op->tls_vers_enum) {
      for (i = 0; i < MAX_TLS_VERSION; i++) {
        client_t *c = ts_client_create(cli->evbase, cli->dnsbase, cli->ssl_ctx,
                                                    cli->op, client_count + i);
        strcpy(c->host, cli->host);
        strcpy(c->ip, cli->ip);
        c->session_reuse_supported = cli->session_reuse_supported;
        c->reuse_test_count = cli->reuse_test_count;
        c->tls_ver_index = i;
        c->tls_cert = cli->tls_cert;
        c->tls_cert->reference_count++;
        if (i < MAX_OPENSSL_TLS_VERSION) {
          c->scan_engine = SE_OPENSSL;
          c->state = ST_TLS_VERSION;
        } else {
          c->scan_engine = SE_GNUTLS;
          c->state = ST_GNUTLS_VERSION;
        }
        ts_adapter_init(c);
        ts_scan_connect(c, true);
      }
    }

    if (cli->op->cipher_enum) {
      int j = 0;
      for (j = 0; j < cli->op->cipher_enum_count; j++, i++) {
        client_t *c = ts_client_create(cli->evbase, cli->dnsbase, cli->ssl_ctx,
                                                    cli->op, client_count + i);
        strcpy(c->host, cli->host);
        strcpy(c->ip, cli->ip);
        c->session_reuse_supported = cli->session_reuse_supported;
        c->reuse_test_count = cli->reuse_test_count;
        c->cipher_index = j;
        c->tls_ver_index = MAX_TLS_VERSION;
        c->tls_cert = cli->tls_cert;
        c->tls_cert->reference_count++;

        // scan CHACHA ciphers using gnutls
        if (strstr(cli->op->cipher_enum_list[c->cipher_index], "CHACHA") != NULL) {
          c->scan_engine = SE_GNUTLS;
          c->state = ST_GNUTLS_1_2CHACHA_CIPHER;
        } else {
          c->scan_engine = SE_OPENSSL;
          c->state = ST_CIPHER;
        }

        ts_adapter_init(c);
        ts_scan_connect(c, true);
      }

      // GnuTLS 1.3 cipher scans
      for (int k = 0; k < cli->op->cipher1_3_enum_count; k++, i++) {
        client_t *c = ts_client_create(cli->evbase, cli->dnsbase, cli->ssl_ctx,
                                                    cli->op, client_count + i);
        strcpy(c->host, cli->host);
        strcpy(c->ip, cli->ip);
        c->session_reuse_supported = cli->session_reuse_supported;
        c->reuse_test_count = cli->reuse_test_count;
        c->cipher_index = cli->op->cipher_enum_count;
        c->cipher1_3_index = k;
        c->tls_ver_index = MAX_TLS_VERSION;
        c->tls_cert = cli->tls_cert;
        c->tls_cert->reference_count++;
        c->scan_engine = SE_GNUTLS;
        c->state = ST_GNUTLS_CIPHER;
        ts_adapter_init(c);
        ts_scan_connect(c, true);
      }

    }

    ts_scan_end(cli, ST_HOST_PARALLEL);
    return;
  }

  cli->tls_cert->reference_count--;

  if (!cli->tls_cert->reference_count) {
    ts_scan_end(cli, ST_CERT_PRINT);
  } else {
    ts_scan_end(cli, ST_HOST_PARALLEL);
  }

  return;
}

void ts_scan_start(client_t * cli)
{

  if (!ts_client_init(cli)) {
    ts_client_destroy(cli);
    return;
  }

  ts_scan_connect(cli, cli->op->ip_input);
  stats.connect_count++;
  return;
}

typedef struct port_protocol_map {
  uint32_t port;
  char protocol[32];
} port_protocol_map_t;

static const port_protocol_map_t protocol_map[] = {
  { 25, "smtp" },           // smtp mta
  { 443, "tls" },           // https
  { 465, "tls" },           // smtps
  { 587, "smtp" },          // smtp submission
  { 993, "tls" },           // imaps
  { 995, "tls" },           // pops
  { 3306, "mysql" }         // mysql
};

const char *ts_supported_protocol(uint32_t port)
{
  size_t count = sizeof(protocol_map) / sizeof(protocol_map[0]);
  for (size_t i = 0; i < count; i++) {

    if (protocol_map[i].port == port) {
      return protocol_map[i].protocol;
    }
  }

  return NULL;
}

void print_usage()
{
  printf("%s\n", "Usage: tls-scan [OPTION]...");
  printf("Version: %s\n", TS_VERSION);
  printf("\n%s\n","With no options, program accepts hostnames from standard input, scans TLS");
  printf("%s\n","on port 443, and print results to standard output");
  printf("\n%s\n", "Options:");
  printf("  %s\n", "-c  --connect=<arg>      Target[:port] to connect. Target = {hostname, IPv4, [IPv6] }");
  printf("  %s\n", "                         IPv6 example: [::1]:443 (default port 443)");
  // deprecated, use --connect instead
  //printf("  %s\n", "-h  --host=<hostname>    Host to scan");
  //printf("  %s\n", "-p  --port=<port>        TCP port (default 443)");
  printf("  %s\n", "    --starttls=<proto>   Supported protocols: smtp, imap, pop3, ftp, sieve,");
  printf("  %s\n", "                         nntp, xmpp, ldap, rdp, postgres, mysql, tls (default)");
  printf("  %s\n", "    --cacert=<file>      Root CA file/bundle for certificate validation");
  printf("  %s\n", "-C  --ciphers=<arg>      Ciphers to use; try 'openssl ciphers' to see all.");
#if OPENSSL_VERSION_NUMBER > 0x10100000L
  printf("  %s\n", "                         NOTE: overwritten by --ssl3, --tls1");
  printf("  %s\n", "                         --tls1_1, --tls1_2, --tls1_3 options (if provided)");
#else
  printf("  %s\n", "                         NOTE: overwritten by --ssl2, --ssl3, --tls1");
  printf("  %s\n", "                         --tls1_1, --tls1_2, options (if provided)");
#endif
  printf("  %s\n", "                         https://www.openssl.org/docs/man1.0.1/apps/ciphers.html");
  printf("  %s\n", "-e  --cipher-enum        Enumerate supported ciphers");
  printf("  %s\n", "    --show-unsupported-ciphers");
  printf("  %s\n", "                         Show ciphers that are not supported in cipher list");
  printf("  %s\n", "-V  --version-enum       Enumerate supported TLS versions");
  printf("  %s\n", "-r  --session-reuse      Enable ssl session reuse");
  printf("  %s\n", "-u  --session-print      Print SSL session in PEM format to stderr");
  printf("  %s\n", "-T  --session-file=<file>");
  printf("  %s\n", "                         Pass file that contains SSL session in PEM format");
  printf("  %s\n", "-a  --all                Enable --version-enum and --cipher-enum");
  printf("  %s\n", "-A  --alpn=<proto-list>  Comma separated ALPN protocol id list passed in ClientHello");
  printf("  %s\n", "                         Example: -A \"spdy/3,h2,http/1.1\"");
  printf("  %s\n", "-s  --sni=<host>         Set TLS extension servername in ClientHello");
  printf("  %s\n", "                         Defaults to input hostname & Applied to TLSv1+ only");
  printf("  %s\n", "-b  --concurrency=<number>");
  printf("  %s\n", "                         Concurrent requests (default 1)");
  printf("  %s\n", "-t  --timeout=<number>   Timeout per connection (in seconds)");
  printf("  %s\n", "-S  --sleep=<number>     Add milliseconds delay between the connection.");
  printf("  %s\n", "                         Only for -e,-V options");
  printf("  %s\n", "-f  --infile=<file>      Input file with domains or IPs (default stdin)");
  printf("  %s\n", "-o  --outfile=<file>     Output file (default stdout)");
  printf("  %s\n", "-n  --pretty             Pretty print; add newline (\\n) between record fields");
  printf("  %s\n", "-v  --version            Print version and build information");
  printf("  %s\n", "-H  --help               help");
  printf("  %s\n", "-N  --nameserver=<ip>    DNS resolver IPs, (eg. -N <ip1> -N <ip2> -N <ip3>..)");
  printf("  %s\n", "    --ssl2               SSLv2 ciphers");
  printf("  %s\n", "    --ssl3               SSLv3 ciphers");
  printf("  %s\n", "    --tls1               TLSv1 ciphers");
  printf("  %s\n", "    --tls1_1             TLSv1_1 ciphers");
  printf("  %s\n", "    --tls1_2             TLSv1_2 ciphers");
#if OPENSSL_VERSION_NUMBER > 0x10100000L
  printf("  %s\n", "    --tls1_3             TLSv1_3 ciphers");
#endif
  printf("  %s\n", "    --tls-modern         Mozilla's modern cipher list. See:");
  printf("  %s\n", "                         https://wiki.mozilla.org/Security/Server_Side_TLS");
  printf("  %s\n", "    --tls-interm         Mozilla's intermediate cipher list");
  printf("  %s\n", "    --tls-old            Mozilla's old (backward compatible cipher list)");
  printf("  %s\n", "    --no-parallel-enum   Disable parallel cipher and tls version enumeration.");
  printf("  %s\n", "                         Parallel scan is performed only with -connect option");
  printf("  %s\n", "    --meta-info          Print program meta information and exit");
  printf("  %s\n", "    --stats-outfile=<file>");
  printf("  %s\n", "                         Enable run-time scan stats and save it to a file");

  printf("\n");
  printf("%s\n", "NOTE: If you pipe the output to another process, redirect stderr to /dev/null");
  printf("\n%s\n", "Examples:");
  printf("  %s\n", "% tls-scan -c smtp.mail.yahoo.com:587 \\");
  printf("  %s\n", "              --starttls=smtp  --cacert=ca-bundle.crt 2> /dev/null");
  printf("  %s\n", "% tls-scan --infile=domains.txt --cacert=ca-bundle.crt 2> /dev/null");
  printf("  %s\n", "% tls-scan -c [::1]:443 --cacert=ca-bundle.crt --pretty 2> /dev/null");
  printf("  %s\n", "% tls-scan -c 10.10.10.10 --cacert=ca-bundle.crt --pretty 2> /dev/null");
  printf("  %s\n", "% cat domains.txt | tls-scan --cacert=ca-bundle.crt 2> /dev/null");
  printf("\n");
}

void print_meta()
{
  printf("CIPHERS:\n");
  printf("default-cipher: %s\n\n", default_ciphers);
  printf("ssl2-cipher: %s\n\n", sslv2_ciphers);
  printf("ssl3-cipher: %s\n\n", sslv3_ciphers);
  printf("tls1-cipher: %s\n\n", tlsv1_ciphers);
  printf("tls1_2-cipher: %s\n\n", tlsv1_2_ciphers);
  printf("tls1_3-cipher: %s\n\n", tlsv1_3_ciphers);
  printf("modern-cipher: %s\n\n", modern_ciphers);
  printf("interm-cipher: %s\n\n", interm_ciphers);
  printf("old-cipher: %s\n\n", old_ciphers);
  printf("concurrency: %d\n", (int)op.batch_size);
  printf("timeout: %u\n", op.timeout);
}

int main(int argc, char **argv)
{
  struct event_base *evbase = event_base_new();
  struct evdns_base *dnsbase = evdns_base_new(evbase, 1);

  static struct option long_options[] = {
    {"starttls", required_argument, 0, 'P'},
    {"connect", required_argument, 0, 'c'},
    {"host", required_argument, 0, 'h'},
    {"port", required_argument, 0, 'p'},
    {"cacert", required_argument, 0, '1'},
    {"ciphers", required_argument, 0, 'C'},
    {"cipher-enum", no_argument, 0, 'e'},
    {"show-unsupported-ciphers", no_argument, 0, 'U'},
    {"session-reuse", no_argument, 0, 'r'},
    {"session-print", no_argument, 0, 'u'},
    {"session-file", required_argument, 0, 'T'},
    {"all", no_argument, 0, 'a'},
    {"alpn", required_argument, 0, 'A'},
    {"sni", required_argument, 0, 's'},
    {"ssl2", no_argument, 0, '2'},
    {"ssl3", no_argument, 0, '3'},
    {"tls1", no_argument, 0, '4'},
    {"tls1_1", no_argument, 0, '5'},
    {"tls1_2", no_argument, 0, '6'},
    {"tls1_3", no_argument, 0, 'Q'},
    {"tls-modern", no_argument, 0, '7'},
    {"tls-interm", no_argument, 0, '8'},
    {"tls-old", no_argument, 0, '9'},
    {"version-enum", no_argument, 0, 'V'},
    {"no-parallel-enum", no_argument, 0, 'X'},
    {"concurrency", required_argument, 0, 'b'},
    {"json", no_argument, 0, 'j'},
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'H'},
    {"infile", required_argument, 0, 'f'},
    {"timeout", required_argument, 0, 't'},
    {"sleep", required_argument, 0, 'S'},
    {"outfile", required_argument, 0, 'o'},
    {"stdout", no_argument, 0, 'O'},
    {"pretty", no_argument, 0, 'n'},
    {"nameserver", required_argument, 0, 'N'},
    {"meta-info", no_argument, 0, 'M'},
    {"stats-outfile", required_argument, 0, 'R'},
    {0, 0, 0, 0}
  };

  int opt = 0;

  memset(&op, 0, sizeof(op));
  op.port = 443;
  /* default ca bundlel; but use your own! */
  strcpy(op.cacert, "./ca-bundle.crt");
  strcpy(op.ciphers, default_ciphers);
  op.certlog_fp = stdout;
  op.ip_input = false;
  op.cipher_user_input = false;
  op.cipher_enum = false;
  op.cipher_enum_count = 0;
  op.show_unsupported_ciphers = false;
  op.tls_vers_enum = false;
  op.no_parallel_enum = false;
  op.batch_size = 1;
  op.json = false;
  op.verbose = 0;
  op.timeout = DEFAULT_TIMEOUT;
  op.pretty = false;
  op.stdout = false;
  int long_index = 0;
  int valid = 0;
  op.ssl2 = false;
  op.ssl3 = false;
  op.tls1 = false;
  op.tls1_1 = false;
  op.tls1_2 = false;
  op.protocol_adapter_index = -1;
  char alpn[DEFAULT_ALPNLEN];
  int tmsec = 0;
  int tsec = 0;
  while ((opt = getopt_long(argc,
                            argv,
                            "P:h:p:c:C:eUruT:aA:s:b:vt:S:o:N:R:f:123456Q789VXnOjMH",
                            long_options, &long_index)) != -1) {
    valid = 1;
    switch (opt) {
    case 'P':
      op.protocol_adapter_index = ts_adapter_index(optarg);
      if (op.protocol_adapter_index < 0) {
        fprintf(stderr, "Error: unknown --starttls option\n");
        exit(EXIT_FAILURE);
      }

      break;
    case 'h':
      snprintf(op.host, OPT_STRLEN, "%s", optarg);
      break;
    case 'p':
      op.port = strtol(optarg, NULL, 10);
      break;
    case 'c':
      snprintf(op.host, OPT_STRLEN, "%s", optarg);
      ts_address_family_t add = ts_address_family(optarg);
      if ((add == TS_IPV6) || (add == TS_IPV4)) {
        op.ip_input = true;
      }
      break;
    case 'C':
      op.cipher_user_input = true;
      snprintf(op.ciphers, OPT_CIPHER_STRLEN, "%s", optarg);
      break;
    case 'e':
      op.cipher_enum = true;
      break;
    case 'U':
      op.show_unsupported_ciphers = true;
      break;
    case 'r':
      op.session_reuse_test = true;
      break;
    case 'u':
      op.session_print = true;
      break;
    case 'T':
      snprintf(op.session_infile, OPT_STRLEN, "%s", optarg);
      break;
    case 'a':
      op.cipher_enum = true;
      op.tls_vers_enum = true;
      //op.session_reuse_test = true;
      break;
    case 'A':
      snprintf(alpn, DEFAULT_ALPNLEN, "%s", optarg);
      break;
    case 's':
      snprintf(op.sni, DEFAULT_HOSTLEN, "%s", optarg);
      break;
    case 'b':
      op.batch_size = strtol(optarg, NULL, 10);
      break;
    case 't':
      op.timeout = strtol(optarg, NULL, 10);
      break;
    case 'S':

      tmsec = strtol(optarg, NULL, 10);
      if ((tmsec <= 0) || (tmsec > 60000))  {
        fprintf(stderr,
        "Error: --sleep option invalid. It should be > 0 and <= 1 minute: %s\n",
        optarg);
        exit(EXIT_FAILURE);
      }

      tsec = (tmsec / SECOND_MULTPLIER);
      op.ts_sleep.tv_sec = tsec;
      op.ts_sleep.tv_nsec = (tmsec - (tsec * SECOND_MULTPLIER)) *
                                                        NANO_SECOND_MULTIPLIER;
      break;
    case 'j':
      op.json = true;
      break;
    case 'f':
      snprintf(op.infile, OPT_STRLEN, "%s", optarg);
      break;
    case 'o':
      snprintf(op.outfile, OPT_STRLEN, "%s", optarg);
      break;
    case 'R':
      snprintf(op.stats_outfile, OPT_STRLEN, "%s", optarg);
      break;
    case 'O':
      op.stdout = true;
      break;
    case 'N':
      evdns_base_nameserver_ip_add(dnsbase, optarg);
      break;
    case 'n':
      op.pretty = true;
      break;
    case 'V':
      op.tls_vers_enum = true;
      break;
    case 'X':
      op.no_parallel_enum = true;
      break;
    case '1':
      snprintf(op.cacert, OPT_STRLEN, "%s", optarg);
      break;
    case '2':
      op.ssl2 = true;
      strcpy(op.ciphers, sslv2_ciphers);
      break;
    case '3':
      op.ssl3 = true;
      strcpy(op.ciphers, sslv3_ciphers);
      break;
    case '4':
      op.tls1 = true;
      strcpy(op.ciphers, tlsv1_ciphers);
      break;
    case '5':
      op.tls1_1 = true;
      strcpy(op.ciphers, tlsv1_ciphers);
      break;
    case '6':
      op.tls1_2 = true;
      strcpy(op.ciphers, tlsv1_2_ciphers);
      break;
    case 'Q':
      op.tls1_3 = true;
      strcpy(op.ciphers, tlsv1_3_ciphers);
      break;
    case '7':
      strcpy(op.ciphers, modern_ciphers);
      break;
    case '8':
      strcpy(op.ciphers, interm_ciphers);
      break;
    case '9':
      strcpy(op.ciphers, old_ciphers);
      break;
    case 'v':
      printf("tls-scan %s %s %s %s\n", TS_VERSION, TS_OS, TS_ARCH, TS_BUILD_DATE);
      printf("Built with OpenSSL-%lx GnuTLS-%x\n",
                               OPENSSL_VERSION_NUMBER, GNUTLS_VERSION_NUMBER);
      exit(EXIT_SUCCESS);
      break;
    case 'M':
      print_meta();
      exit(EXIT_FAILURE);
      break;
    case 'H':
    default:
      print_usage();
      exit(EXIT_FAILURE);
    }
  }

  if (!valid) {
    print_usage();
    exit(EXIT_FAILURE);
  }

  if (op.protocol_adapter_index == -1) {
    const char *p = ts_supported_protocol(op.port);
    if (p) {
      op.protocol_adapter_index = ts_adapter_index(p);
    } else {
      fprintf(stderr, "Error: specify --starttls option\n");
      exit(EXIT_FAILURE);
    }
  }

  assert(op.protocol_adapter_index != -1);

  if (strlen(op.outfile) > 0) {
    op.certlog_fp = fopen(op.outfile, "w");
    assert(op.certlog_fp != NULL);
  }

  if (strlen(op.stats_outfile) > 0) {
    op.statsfile_fp = fopen(op.stats_outfile, "w");
    assert(op.statsfile_fp != NULL);
    if (!op.no_parallel_enum) {
      fprintf(op.statsfile_fp, "elapsed-time completed connect-count network-error dns-errcount remote-close-error unknown-error connect-error timeout-error tls-handshake gross-tls-handshake target\n");
    }
  }

  in_handle.eof = false;
  in_handle.fp = stdin;
  if (strlen(op.infile) > 0) {
    in_handle.fp = fopen(op.infile, "r");
    assert(in_handle.fp != NULL);
  }

  in_handle.host[0] = 0;
  if (strlen(op.host) > 0) {
    strcpy(in_handle.host, op.host);
  }

  if (strlen(op.session_infile) > 0) {
    op.session_in_fp = fopen(op.session_infile, "r");
    assert(in_handle.fp != NULL);
  }

  if (strlen(alpn) > 0) {
    op.alpn_size = alpn_wireformat(alpn, &op.alpn[0]);
  }

  signal(SIGPIPE, SIG_IGN);

  init_stats(&stats);

  // default cipher is too long, lets use old_ciphers. We can tune it later
  // commenting this code to fix https://github.com/prbinu/tls-scan/issues/3
 // if (strcmp(op.ciphers, default_ciphers) == 0) {
 //   strcpy(op.ciphers, old_ciphers);
 // }

  get_ciphersuites_and_cipher_list(op.ciphers, op.ciphersuites, op.cipher_list);
  SSL_CTX *ssl_ctx = ts_ssl_ctx_create(op.ciphers, op.cacert, op.ssl2);


  if (op.cipher_enum) {
    SSL *ssl_tmp = SSL_new(ssl_ctx);
    assert(ssl_tmp != NULL);

    const char *p = NULL;
    int i;
    for (i=0; ; i++) {
      p = SSL_get_cipher_list(ssl_tmp, i);
      if (p == NULL) break;
      // these ciphers are causing core dumps, skipping it for now
      if ((strncmp(p, "SRP", 3)) &&
    //      (strncmp(p, "IDEA", 4)) &&
    //      (strncmp(p, "RC2", 3)) &&
    //      (strncmp(p, "DES-CBC3-MD5", 12)) &&
    //      (strncmp(p, "RC4-64-MD5", 10)) &&
    //      (strncmp(p, "DES-CBC-MD5", 11)) &&
          (strncmp(p, "PSK", 3))) {

        // avoid duplicate ciphers
        int k = 0;
        while (k < op.cipher_enum_count) {
          if (strcmp(p, op.cipher_enum_list[k]) == 0) {
            break;
	  }
          k++;
        }

        if (k == op.cipher_enum_count) {
          strcpy(op.cipher_enum_list[op.cipher_enum_count++], p);
          //fprintf(stderr, "%s:", p);
        }
      }

      if (op.cipher_enum_count >= CIPHER_ENUM_SZ) {
        break;
      }
    }

    if (ssl_tmp != NULL) {
      SSL_free(ssl_tmp);
    }
  }

  op.cert_obj_pool = (struct tls_cert**)malloc(sizeof(struct tls_cert*) *
                                                              op.batch_size);

  size_t i = 0;
  for (i = 0; i < op.batch_size; i++) {
    op.cert_obj_pool[i] = (struct tls_cert*)calloc(1, sizeof(struct tls_cert));
    op.cert_obj_pool[i]->cipher_suite_support  = NULL;
    if (op.cipher_enum_count > 0) {
      op.cert_obj_pool[i]->cipher_suite_support =
                           (bool*)calloc(op.cipher_enum_count, sizeof(bool));
    }
  }

  gnutls13_init(&op);
  //event_enable_debug_logging(EVENT_DBG_ALL);
  for (i = 0; i < op.batch_size; i++) {
    client_t *c = ts_client_create(evbase, dnsbase, ssl_ctx, &op, i);
    ts_scan_start(c);
  }

  event_base_loop(evbase, 0);
  evdns_base_free(dnsbase, 0);
  event_base_free(evbase);
  ts_ssl_destroy(ssl_ctx);

  gnutls13_deinit(&op);

  for (i = 0; i < op.batch_size; i++) {
    free(op.cert_obj_pool[i]->cipher_suite_support);
    free(op.cert_obj_pool[i]);
  }

  free(op.cert_obj_pool);

  uint64_t et = ts_elapsed_time(stats.start_time);
  int pid = getpid();

  if (op.pretty) {
    fprintf(stderr, "\n<|---------Scan Summary---------|>\n");
    fprintf(stderr, " [%d] ciphers             : ", pid);

    int k = 0;
    while (k < op.cipher_enum_count) {
      fprintf(stderr, "%s:", op.cipher_enum_list[k]);
      k++;
    }

    fprintf(stderr, " (%d)\n", op.cipher_enum_count);
    fprintf(stderr, " [%d] host-count          : %d\n",
                                                          pid, stats.connect_count);
    fprintf(stderr, " [%d] network-error       : %d\n",
                                                 pid, stats.network_err_count);
    fprintf(stderr, " [%d] dns-errcount        : %d\n",
                                                 getpid(), stats.dns_errcount);
    fprintf(stderr, " [%d] remote-close-error  : %d\n",
                                           getpid(), stats.remote_close_count);
    fprintf(stderr, " [%d] unknown-error       : %d\n",
                                                  getpid(), stats.error_count);
    fprintf(stderr, " [%d] timeout-error       : %d\n",
                                                getpid(), stats.timeout_count);
    fprintf(stderr, " [%d] connect-error       : %d\n",
                                            getpid(), stats.connect_err_count);
    fprintf(stderr, " [%d] tls-handshake       : %d\n",
                                                getpid(), stats.tls_handshake);
    fprintf(stderr, " [%d] gross-tls-handshake : %d\n",
                                          getpid(), stats.gross_tls_handshake);

    if (stats.starttls_no_support_count) {
      fprintf(stderr, " [%d] starttls-no-support-count : %d\n",
                                    getpid(), stats.starttls_no_support_count);
    }

    fprintf(stderr, " [%d] elapsed-time        : %"PRIu64".%"PRIu64" secs\n",
                                            getpid(),  et/1000000, et%1000000);
    fprintf(stderr, "<|------------------------------|>\n");
  } else {
    fprintf(stderr, " pid: %d | ciphers:", pid);

    int k = 0;
    while (k < op.cipher_enum_count) {
      fprintf(stderr, "%s:", op.cipher_enum_list[k]);
      k++;
    }

    fprintf(stderr, " (%d) |", op.cipher_enum_count);
    fprintf(stderr, "host-count: %d |", stats.connect_count);
    fprintf(stderr, "network-error: %d |", stats.network_err_count);
    fprintf(stderr, "dns-errcount: %d |", stats.dns_errcount);
    fprintf(stderr, "remote-close-error: %d |", stats.remote_close_count);
    fprintf(stderr, "unknown-error: %d |", stats.error_count);
    fprintf(stderr, "connect-error: %d |", stats.connect_err_count);
    fprintf(stderr, "timeout-error: %d |", stats.timeout_count);
    fprintf(stderr, "tls-handshake: %d |", stats.tls_handshake);
    fprintf(stderr, "gross-tls-handshake: %d |", stats.gross_tls_handshake);
    if (stats.starttls_no_support_count) {
      fprintf(stderr, "starttls-no-support-count: %d |",
                                              stats.starttls_no_support_count);
    }
    fprintf(stderr, "elapsed-time: %"PRIu64".%"PRIu64" secs\n", et/1000000,
                                                                   et%1000000);
  }

  if (stats.timeout_count == stats.connect_count) {
    fprintf(stderr, "Warning: Are you talking the right protocol? \
 The timeout error could be because of wrong protocol option.\n");
  }

  fclose(op.certlog_fp);
  if (op.session_in_fp) {
    fclose(op.session_in_fp);
  }

  if (op.outfile[0] != 0) {
    fprintf(stdout, "\n");
  }

  return 0;
}
