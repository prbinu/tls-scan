#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "common.h"
#include "cert-parser.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

// GnuTLS equivalent of tls 1.3 ciphers
static const char *tlsv1_3_gnutls_ciphers_str = "NONE:+CTYPE-ALL:+COMP-ALL:+GROUP-ALL:+SIGN-ALL:+KX-ALL:+MAC-ALL:+VERS-TLS1.3:+AES-128-GCM:+AES-256-GCM:+AES-128-CCM:+AES-256-CCM:+CHACHA20-POLY1305:+AES-128-CCM-8:+AES-256-CCM-8";
// note - the following cipher is 1:1 equivalent.
// TLS1_3_MAX_CIPHER_COUNT defined in cert-parser.h
static const char *tlsv1_3_gnutls_ciphers[TLS1_3_MAX_CIPHER_COUNT] = { "AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305", "AES-128-CCM", "AES-128-CCM-8"};
static const char *tlsv1_3_openssl_ciphers[TLS1_3_MAX_CIPHER_COUNT] = { "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256" };

#define TLS1_2_MAX_CHACHA_CIPHER_COUNT 3

static const char *tlsv1_2_gnutls_chacha_ciphers[TLS1_2_MAX_CHACHA_CIPHER_COUNT] = {
  "NONE:+VERS-TLS1.2:-CIPHER-ALL:+CHACHA20-POLY1305:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ECDHE-ECDSA:+CURVE-ALL",
  "NONE:+VERS-TLS1.2:-CIPHER-ALL:+CHACHA20-POLY1305:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+ECDHE-RSA:+CURVE-ALL",
  "NONE:+VERS-TLS1.2:-CIPHER-ALL:+CHACHA20-POLY1305:+MAC-ALL:+SIGN-ALL:+COMP-ALL:+DHE-RSA:+CURVE-ALL",
};

static const char *tlsv1_2_openssl_chacha_ciphers[TLS1_2_MAX_CHACHA_CIPHER_COUNT] = { "ECDHE-RSA-CHACHA20-POLY1305-OLD", "ECDHE-ECDSA-CHACHA20-POLY1305-OLD", "DHE-RSA-CHACHA20-POLY1305-OLD" };

#define CHECK(x) assert((x)>=0)

// tls 1_2 chacha cipher index for gnutls
static const char*  gnutls1_2_chacha_priority_str(const char *openssl_cipher)
{
  for (int i=0; i < TLS1_2_MAX_CHACHA_CIPHER_COUNT; i++) {
    if (strcmp(tlsv1_2_openssl_chacha_ciphers[i], openssl_cipher) == 0) {
      return tlsv1_2_gnutls_chacha_ciphers[i];
    }
  }

  return NULL;
}

void gnutls13_init(struct options *op) {
  op->cipher1_3_enum_count = 0;

  if (op->cipher_enum) {
    // if cipher is provided by the user, select only the chosen tls1.3 ciphers
    if (op->cipher_user_input) {
      for (int i = 0; i < TLS1_3_MAX_CIPHER_COUNT; i++) {
        if (strstr(op->ciphers, tlsv1_3_openssl_ciphers[i]) != NULL) {
          strcpy(op->cipher1_3_enum_list[op->cipher1_3_enum_count],
                                                    tlsv1_3_gnutls_ciphers[i]);
          op->cipher1_3_enum_count++;
        }
      }
    } else if ((!op->ssl2) && (!op->ssl3) && (!op->tls1)) {
      // select all tls 1.3 ciphers that matches
      for (int i = 0; i < TLS1_3_MAX_CIPHER_COUNT; i++) {
        strcpy(op->cipher1_3_enum_list[op->cipher1_3_enum_count],
                                                    tlsv1_3_gnutls_ciphers[i]);
        op->cipher1_3_enum_count++;
      }
    }

  }

  if (gnutls_check_version("3.4.6") == NULL) {
    fprintf(stderr, "GnuTLS 3.4.6 or later is required for this program\n");
    exit(1);
  }

  CHECK(gnutls_global_init());

  // X509 stuff
  CHECK(gnutls_certificate_allocate_credentials(&op->xcred));

  // sets the system trusted CAs for Internet PKI
  CHECK(gnutls_certificate_set_x509_system_trust(op->xcred));

  /* If client holds a certificate it can be set using the following:
   *
   gnutls_certificate_set_x509_key_file (xcred, "cert.pem", "key.pem",
   GNUTLS_X509_FMT_PEM);
   */
}

void gnutls13_deinit(struct options *op)
{
  gnutls_certificate_free_credentials(op->xcred);
  gnutls_global_deinit();
  return;
}

bool _gnutls13_session_init(client_t *cli, int sd, const char *priority)
{

  // Initialize TLS session
  CHECK(gnutls_init(&cli->session, GNUTLS_CLIENT));
  CHECK(gnutls_priority_set_direct(cli->session, priority, NULL));

  // put the x509 credentials to the current session
  CHECK(gnutls_credentials_set(cli->session, GNUTLS_CRD_CERTIFICATE,
                                                              cli->op->xcred));

  if (cli->op->sni[0] != 0) {
    CHECK(gnutls_server_name_set(cli->session, GNUTLS_NAME_DNS, cli->op->sni,
                                                        strlen(cli->op->sni)));
  } else if (cli->host[0] != 0) {
    CHECK(gnutls_server_name_set(cli->session, GNUTLS_NAME_DNS, cli->host,
                                                           strlen(cli->host)));
  }
  /*  if (cli->host[0] != 0) {
    //  gnutls_session_set_verify_cert(session, cli->host, 0);
      CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, cli->host, strlen(cli->host)));
    } else {
      gnutls_session_set_verify_cert(session, NULL, 0);
    }*/
    /* connect to the peer
     */
  gnutls_transport_set_int(cli->session, sd);
  gnutls_handshake_set_timeout(cli->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
  return true;
}

int gnutls13_session_init(client_t *cli, int sd)
{

  if (cli->state == ST_GNUTLS_VERSION) {
    _gnutls13_session_init(cli, sd, tlsv1_3_gnutls_ciphers_str);
  } else if (cli->state == ST_GNUTLS_CIPHER) {
    char priority[512];
    if (cli->cipher1_3_index < cli->op->cipher1_3_enum_count) {
      snprintf(priority, 512, "NONE:+CTYPE-ALL:+COMP-ALL:+GROUP-ALL:+SIGN-ALL:+KX-ALL:+MAC-ALL:+VERS-TLS1.3:+%s", cli->op->cipher1_3_enum_list[cli->cipher1_3_index]);
      _gnutls13_session_init(cli, sd, priority);
    } else {
      assert(0);
    }
  } else if (cli->state == ST_GNUTLS_1_2CHACHA_CIPHER) {
    char priority[512];
    if (cli->cipher1_3_index < cli->op->cipher1_3_enum_count) {
      const char *p = gnutls1_2_chacha_priority_str(cli->op->cipher_enum_list[cli->cipher_index]);
      if (p) {
        snprintf(priority, 512, "%s", p);
        _gnutls13_session_init(cli, sd, priority);
      } else {
        assert(0);
      }
    } else {
      assert(0);
    }
  } else {
    assert(0);
  }

  return 0;
}

void gnutls13_session_deinit(client_t *cli)
{
  // TODO - check err status and log to stderr
  gnutls_deinit(cli->session);
}

ts_status_t gnutls13_handshake(client_t *cli, int sd)
{
  int ret;
  bool status = false;
  char *desc;
  gnutls_datum_t out;
  int type;

retry:
  ret = gnutls_handshake(cli->session);
  if  (ret < 0) {
    if (gnutls_error_is_fatal(ret) == 0) {
      if (gnutls_record_get_direction(cli->session) == 0) {
        return TS_EAGAIN_ERR; // read
      } else {
        goto retry; // write
      }
    } else if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
      // check certificate verification status
      type = gnutls_certificate_type_get(cli->session);
      status = gnutls_session_get_verify_cert_status(cli->session);
      CHECK(gnutls_certificate_verification_status_print(status, type, &out, 0));
      //printf("cert verify output: %s\n", out.data);
      gnutls_free(out.data);
    }

    fprintf(stderr, "host: %s; ip: %s; error: Network; errormsg: \
               Error encountered during GnuTLS handshake: %d \
               Unsupported TLS 1.3 version/cipher\n", cli->host, cli->ip, ret);
    return TS_HSHAKE_ERR;
  }

  desc = gnutls_session_get_desc(cli->session);
  //printf("- Session info: %s\n", desc);
  gnutls_free(desc);
  gnutls_bye(cli->session, GNUTLS_SHUT_RDWR);

  if (cli->state == ST_GNUTLS_VERSION) {
    cli->tls_cert->tls_ver_support[cli->tls_ver_index] = true;
  } else if (cli->state == ST_GNUTLS_CIPHER) {
    if (cli->cipher1_3_index < cli->op->cipher1_3_enum_count) {
      cli->tls_cert->cipher1_3_suite_support[cli->cipher1_3_index] = true;
    } else {
      assert(0);
    }
  } else if (cli->state == ST_GNUTLS_1_2CHACHA_CIPHER) {
    cli->tls_cert->cipher_suite_support[cli->cipher_index] = true;
  } else {
    assert(0);
  }

  return TS_SUCCESS;
}
