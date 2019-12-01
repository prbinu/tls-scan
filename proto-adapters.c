// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

#include <string.h>
// openssl headers
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
// tls-scan
#include <common.h>
#include <cert-parser.h>
#include <proto-adapters.h>


/* Callback function definitions */
typedef void (*create_cb_fptr) (client_t *cli);
typedef void (*init_cb_fptr) (client_t *cli);

/* Required if client is the first party to send data after TCP connect. */
typedef void (*tcp_connect_cb_fptr) (client_t *cli);

/* Called when data is ready to read */
typedef void (*read_cb_fptr) (client_t *cli,
                               unsigned char *read_buf,
                               size_t nread);
/*
 * Called after a succuessful write, may not required in most cases
 */
typedef void (*write_cb_fptr) (client_t *cli);
typedef void (*reset_cb_fptr) (client_t *cli);
typedef void (*destroy_cb_fptr) (client_t *cli);

/* Follow STEPS 1-2 to add a new protocol adapters */

/* STEP 1: Declare your protocol's callback functions here */

// smtp
static void on_smtp_create(client_t *cli);
static void on_smtp_init(client_t *cli);
static void on_smtp_read(client_t *cli, unsigned char *read_buf, size_t nread);
static void on_smtp_reset(client_t *cli);
static void on_smtp_destroy(client_t *cli);

// mysql
static void on_mysql_create(client_t *cli);
static void on_mysql_read(client_t *cli, unsigned char *read_buf, size_t nread);

// add new protocols below


//


typedef struct adapter_table {
  char protocol[32];
  create_cb_fptr create_cb;
  init_cb_fptr init_cb;
  tcp_connect_cb_fptr connect_cb;
  read_cb_fptr read_cb;
  write_cb_fptr write_cb;
  reset_cb_fptr reset_cb;
  destroy_cb_fptr destroy_cb;
} adapter_table_t;

/* STEP 2
 * Add a new record to adapters struct below.
 * Format: { "protocol-name", create, init, connect, read, write, reset, destroy }
 * NULL if the callback is not implemented
 */
static const adapter_table_t adapters[] = {
//{ "protocol-name", create, init, connect, read, write, reset, destroy }
  { "tls", NULL, NULL, NULL, NULL, NULL, NULL, NULL }, // implemented in main.c
  { "smtp", on_smtp_create, on_smtp_init, NULL, on_smtp_read, NULL, on_smtp_reset, on_smtp_destroy },
  { "mysql", on_mysql_create, NULL, NULL, on_mysql_read, NULL, NULL, NULL }
};


/* functions that are available for adapters */
/* TODO make it as callbacks? */
extern void ts_scan_error(client_t * cli);
extern void ts_scan_do_tls_handshake(client_t * cli);
extern void ts_scan_tcp_write(client_t * cli, const unsigned char *data,
                                                              size_t data_len);

const char *ts_protocol_name(int adapter_index)
{
  size_t count = sizeof(adapters) / sizeof(adapters[0]);
  if ((adapter_index>= 0) && (adapter_index < count)) {
    return adapters[adapter_index].protocol;
  }

  return NULL;
}

int ts_adapter_index(const char *proto_name)
{

  if (!proto_name) return -1;

  size_t count = sizeof(adapters) / sizeof(adapters[0]);
  for (size_t i = 0; i < count; i++) {

    if (strncmp(adapters[i].protocol, proto_name, 32) == 0) {
      return i;
    }

  }

  return -1;
}

void ts_adapter_create(client_t *cli)
{
  if (adapters[cli->adapter_index].create_cb) {
     adapters[cli->adapter_index].create_cb(cli);
  }
}

void ts_adapter_init(client_t *cli)
{
  if (adapters[cli->adapter_index].init_cb) {
    adapters[cli->adapter_index].init_cb(cli);
  }
}

void ts_adapter_connect(client_t *cli)
{
  if (adapters[cli->adapter_index].connect_cb) {
    adapters[cli->adapter_index].connect_cb(cli);
  }
}

void ts_adapter_read(client_t *cli,
                               unsigned char *read_buf,
                               size_t nread)
{
  if (adapters[cli->adapter_index].read_cb) {
    adapters[cli->adapter_index].read_cb(cli, read_buf, nread);
  }
}

void ts_adapter_write(client_t *cli)
{
  if (adapters[cli->adapter_index].write_cb) {
    adapters[cli->adapter_index].write_cb(cli);
  }
}

void ts_adapter_reset(client_t *cli)
{
  if (adapters[cli->adapter_index].reset_cb) {
     adapters[cli->adapter_index].reset_cb(cli);
  }
}

void ts_adapter_destroy(client_t *cli)
{
  if (adapters[cli->adapter_index].destroy_cb) {
     adapters[cli->adapter_index].destroy_cb(cli);
  }
}

const char *starttls = "STARTTLS\r\n";
const char *smtpquit = "SMTP QUIT\r\n";
const char *ret = NULL;

static void on_smtp_create(client_t *cli)
{
  cli->adaptor_data_ptr = malloc(sizeof(int));
}

static void on_smtp_init(client_t *cli)
{
  *(int*)cli->adaptor_data_ptr = 0;
}

static void on_smtp_reset(client_t *cli)
{
  *(int*)cli->adaptor_data_ptr = 0;
}

static void on_smtp_destroy(client_t *cli)
{
  if (cli->adaptor_data_ptr) {
    free(cli->adaptor_data_ptr);
    cli->adaptor_data_ptr = 0;
  }
}

void on_smtp_read(client_t * cli, unsigned char *rbuffer, size_t rbuf_len)
{
  unsigned char *rbuf = rbuffer;
  int *resp_index = (int*)cli->adaptor_data_ptr;
  char ehlo[128];

  if (rbuf_len < 1) {
    goto error;
  }

 // printf("%.*s+  resp_index: %d\n", (int)rbuf_len, rbuffer, *resp_index);

  switch (*resp_index) {
  case 0:
    (*resp_index)++;

    if (strncmp((char*)rbuf, "220", 3) != 0) {
      fprintf(stderr, "host: %s; ip: %s; error: %s\n", cli->host, cli->ip,
                                                    "ERROR: NON 220 response");
      goto error;
    }

    snprintf(ehlo, 128, "EHLO %s\r\n", cli->host);
    ts_scan_tcp_write(cli, (unsigned char*)ehlo, strlen(ehlo));
    break;

  case 1:{
      (*resp_index)++;
      char *saveptr;
      char* line = NULL;
      bool found = false;
      line = strtok_r((char*)rbuf, "\r\n", &saveptr);

      do {
        if ((strncmp((char*)line, "250", 3) == 0) &&
                                                  (strstr(line, "STARTTLS"))) {
          found = true;
          break;
        }

      } while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL);

      if (found == false) {
        fprintf(stderr, "host: %s; ip: %s; error: %s\n",
                                 cli->host, cli->ip, "STARTTLS not supported");
        ts_get_stats_obj()->starttls_no_support_count++;
        goto error;
      }

      ts_scan_tcp_write(cli, (unsigned char*)starttls, strlen(starttls));
      break;
    }

  case 2:
    (*resp_index)++;
    ts_scan_do_tls_handshake(cli);
    break;

  case 3:
    //(*resp_index)++;
    //ts_scan_tcp_write(cli, (unsigned char*)smtpquit, strlen(smtpquit));
    break;

  default:
    break;
  }

  return;

error:
  ts_scan_error(cli);
  return;
}

// mysql
uint8_t ssl_handshake_response[] = {
                      0x20, 0x00, 0x00, 0x01, 0x05,
                      0xae, 0x0f, 0x00, 0x00, 0x00,
                      0x00, 0x01, 0x21, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void on_mysql_create(client_t *cli)
{
  //printf("on_mysql_init called\n");
}
/*

  MySQL Packet:
  https://dev.mysql.com/doc/internals/en/mysql-packet.html

  Protocol::HandshakeV10
  https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake

  Protocol::SSLRequest: (response from client before SSL Handshake)

  Payload

  4              capability flags, CLIENT_SSL always set
  4              max-packet size
  1              character set
  string[23]     reserved (all [0])

 */

#define MYSQL_PKT_HDR_SIZE 4
void on_mysql_read(client_t * cli, unsigned char *rbuffer, size_t rbuf_len)
{
  uint8_t *rbuf = (uint8_t*)rbuffer;

  if (rbuf_len < 1) {
    goto error;
  }

  /* debug?
  for (int i=0; i < rbuf_len; i++) {
    printf("%0x ", rbuf[i]);
  }*/

  int index = strlen((char*)&rbuf[MYSQL_PKT_HDR_SIZE+1])+6;
  index = index + sizeof(uint32_t);
  index = index + strlen((char*)&rbuf[index]+1);

  if (0x0008 & (int16_t)(rbuf[index+3])) {
    ts_scan_tcp_write(cli, ssl_handshake_response,
                                       sizeof(ssl_handshake_response));
    ts_scan_do_tls_handshake(cli);
  } else {
    fprintf(stderr, "host: %s; ip: %s; error: SSL NOT Supported\n",
                                                        cli->ip, cli->host);
    goto error;
  }

  return;

error:
  ts_scan_error(cli);
  return;
}
