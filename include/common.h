#ifndef COMMON_H
#define COMMON_H
// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
// openssl headers
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <gnutls/gnutls.h>

#define DEFAULT_HOSTLEN 256
#define OPT_STRLEN 256
#define OPT_CIPHER_STRLEN 4092
#define OPT_CIPHERSUITES_STRLEN 512
#define CIPHER_ENUM_SZ 256
#define SE_OPENSSL 0
#define SE_GNUTLS 1

typedef enum {
  TS_ERROR = 0,
  TS_HOSTNAME,
  TS_IPV4,
  TS_IPV6,
} ts_address_family_t;

struct tls_cert;

typedef struct stats {
  int hcount;
  int connect_count;
  int dns_errcount;
  int connect_err_count;
  int timeout_count;
  int tls_handshake;
  int gross_tls_handshake;
  int error_count;
  int completed_count;
  int network_err_count;
  int remote_close_count;
  int starttls_no_support_count;
  struct timeval start_time;
} stats_t;

void init_stats(stats_t *st);

typedef enum {
  TS_SUCCESS = 0,
  TS_TIMEOUT,
  TS_DNS_ERR,
  TS_HSHAKE_ERR,
  TS_CONN_ERR,
  TS_SSL_CREAT_ERR,
  TS_EAGAIN_ERR,
  TS_UNKNOWN_ERR
} ts_status_t;

typedef enum {
  ST_UNKNOWN_TYPE = 0,
  ST_CERT,
  ST_SESSION_REUSE,
  ST_TLS_VERSION,
  ST_CIPHER,
  ST_HOST_PARALLEL,
  ST_GNUTLS_CERT,
  ST_GNUTLS_VERSION,
  ST_GNUTLS_CIPHER,
  ST_GNUTLS_1_2CHACHA_CIPHER, // TLS1.2 with CHACHA cipher
  ST_CERT_PRINT
} scan_type_t;

/* command line options, and related global consts */
typedef struct options {
  int protocol_adapter_index;
  char host[OPT_STRLEN];
  uint16_t port;
  bool ssl2;
  bool ssl3;
  bool tls1;
  bool tls1_1;
  bool tls1_2;
  bool tls1_3;
  char cacert[OPT_STRLEN];
  char sni[DEFAULT_HOSTLEN];
  char ciphers[OPT_CIPHER_STRLEN];
  bool cipher_user_input; // user provided cipher flag
  bool cipher_enum;
  char cipher_enum_list[CIPHER_ENUM_SZ][64];
  int cipher_enum_count;
  char cipher_list[OPT_CIPHER_STRLEN]; // pre-TLS1.3 ciphers
  char ciphersuites[OPT_CIPHERSUITES_STRLEN]; // TLS1.3 ciphers
  char cipher1_3_enum_list[CIPHER_ENUM_SZ][64]; // gnutls tls 1.3 ciphers
  int cipher1_3_enum_count; // gnutls tls 1.3 scan cipher count
  bool show_unsupported_ciphers;
  bool tls_vers_enum;
  bool no_parallel_enum;
  bool session_reuse_test;
  bool session_print;
  char session_infile[OPT_STRLEN];
  FILE *session_in_fp;
  char infile[OPT_STRLEN];
  char outfile[OPT_STRLEN];
  FILE *certlog_fp;
  char stats_outfile[OPT_STRLEN];
  FILE *statsfile_fp;
  size_t batch_size;
  uint32_t timeout;
  struct timespec ts_sleep;
  bool json;
  bool pretty;
  bool stdout;
  int verbose;
  // if the input is IP
  bool ip_input;
  // GnuTLS
  gnutls_certificate_credentials_t xcred;
  // tls_cert objects
  struct tls_cert **cert_obj_pool;
} options_t;

/* connection object */
typedef struct client {
  int id;
  char host[OPT_STRLEN];
  char ip[OPT_STRLEN];
  uint16_t port;
  struct event_base *evbase;
  struct evdns_base *dnsbase;
  struct bufferevent *bev;
  struct bufferevent *temp_bev;
  //struct evutil_addrinfo *addr;
  // event status to determine error type
  ts_status_t event_status;
  SSL_CTX *ssl_ctx;
  // adapter index
  int adapter_index;
  // points to adaptor data structure
  void *adaptor_data_ptr;
  uint16_t timeout;
  // reference to global object
  const options_t *op;
  // reference to global object
  const stats_t *st;
  // tls session resuse test
  bool session_reuse_supported;
  // try few times to test session reuse
  int reuse_test_count;
  // current cipher index (for cipher enum)
  int cipher_index;
  // TLS version support test index
  int tls_ver_index;
  // tls 1.3+ cipher index
  int cipher1_3_index;
  // scan state
  scan_type_t state;
  // scan engine - openssl or gnutls
  uint8_t scan_engine;
  // GnuTLS 1.3 handshake event
  struct event *handshake1_3_ev;
  // GnuTLS 1.3 session
  gnutls_session_t session;
  struct tls_cert *tls_cert;
} client_t;

/* input file handle */
typedef struct input_handle {
  FILE *fp;
  char host[DEFAULT_HOSTLEN];
  bool eof;
} input_handle_t;

extern input_handle_t in_handle;

/* readline  */
ssize_t ts_get_line_input(input_handle_t *in_handle, char *line, size_t len);

/* elapsed time in seconds */
uint64_t ts_elapsed_time(struct timeval t1);

/* returns ip str from socket fd */
void ts_get_ip(int fd, char *ipstr, size_t ipstr_len);

/* stats struct object (implemented in main.c) */
extern stats_t *ts_get_stats_obj();

void ts_parse_connect_target(const char *target, char *host, size_t hlen, uint16_t *port);

/* sniff the input to determine the input is hostname, ipv4 or ipv6 */
ts_address_family_t ts_address_family(const char *target);

#endif
