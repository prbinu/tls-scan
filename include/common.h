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

#define DEFAULT_HOSTLEN 256
#define OPT_STRLEN 256
#define OPT_CIPHER_STRLEN 4092
#define CIPHER_ENUM_SZ 256

struct tls_cert;

typedef struct stats {
  int hcount;
  int dnscount;
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
  TS_NO_ERR = 0,
  TS_TIMEOUT,
  TS_DNS_ERR,
  TS_HSHAKE_ERR,
  TS_CONN_ERR,
  TS_SSL_CREAT_ERR,
  TS_UNKNOWN_ERR
} ts_error_t;

/* command line options, and related global consts */
typedef struct options {
  int protocol_adapter_index;
  char host[OPT_STRLEN];
  uint16_t port;
  bool ssl2;
  char cacert[OPT_STRLEN];
  char sni[DEFAULT_HOSTLEN];
  char ciphers[OPT_CIPHER_STRLEN];
  bool cipher_enum;
  char cipher_enum_list[CIPHER_ENUM_SZ][64];
  int cipher_enum_count;
  bool tls_vers_enum;
  bool no_parallel_enum;
  bool session_reuse_test;
  bool session_print;
  char session_infile[OPT_STRLEN];
  FILE *session_in_fp;
  char infile[OPT_STRLEN];
  char outfile[OPT_STRLEN];
  FILE *certlog_fp;
  size_t batch_size;
  uint32_t timeout;
  struct timespec ts_sleep;
  bool json;
  bool pretty;
  bool stdout;
  int verbose;
  // if the input is IP
  bool ip_input;
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
  ts_error_t event_error;
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
  struct tls_cert *tls_cert;
  // to measure elapsed time
  struct timeval start_time;
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
uint64_t elapsed_time(struct timeval t1);

/* returns ip str from socket fd */
void get_ip(int fd, char *ipstr, size_t ipstr_len);

/* stats struct object (implemented in main.c) */
extern stats_t *ts_get_stats_obj();

#endif
