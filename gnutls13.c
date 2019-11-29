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

#define CHECK(x) assert((x)>=0)
#define LOOP_CHECK(rval, cmd) \
  do { \
    rval = cmd; \
  } while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED); \
  assert(rval >= 0)

static bool _gnutls13_scan(client_t *cli, const char *priority);

extern int tcp_connect(const char *target, uint16_t port)
{
  int err, sd;
  struct sockaddr_in sa;

  sd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  inet_pton(AF_INET, target, &sa.sin_addr);

  err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
  if (err < 0) {
    fprintf(stderr, "Connect error\n");
    exit(1);
  }

  return sd;
}

void tcp_close(int sd)
{
  shutdown(sd, SHUT_RDWR);
  close(sd);
}

// TODO move elsewhere?
gnutls_certificate_credentials_t xcred;

void gnutls13_init(struct options *op) {
  op->cipher1_3_enum_count = 0;

  if (op->cipher_enum) {
    // if cipher is provided by the user, select only the chosen tls1.3 ciphers
    if (op->cipher_user_input) {
      for (int i = 0; i < TLS1_3_MAX_CIPHER_COUNT; i++) {
        if (strstr(op->ciphers, tlsv1_3_openssl_ciphers[i]) != NULL) {
          strcpy(op->cipher1_3_enum_list[op->cipher1_3_enum_count], tlsv1_3_gnutls_ciphers[i]);
          op->cipher1_3_enum_count++;
        }
      }
    } else if ((!op->ssl2) && (!op->ssl3) && (!op->tls1)) {
      // select all tls 1.3 ciphers that matches
      for (int i = 0; i < TLS1_3_MAX_CIPHER_COUNT; i++) {
      //  for (int j = 0; j < opt->cipher_enum_count; j++) {
      //    if (strcmp(op.cipher_enum_list[j], tlsv1_3_openssl_ciphers[i]) == 0) {
            strcpy(op->cipher1_3_enum_list[op->cipher1_3_enum_count], tlsv1_3_gnutls_ciphers[i]);
            op->cipher1_3_enum_count++;
      //    }
      }
    }

  }

  if (gnutls_check_version("3.4.6") == NULL) {
          fprintf(stderr, "GnuTLS 3.4.6 or later is required for this google\n");
          exit(1);
  }

  CHECK(gnutls_global_init());

  /* X509 stuff */
  CHECK(gnutls_certificate_allocate_credentials(&xcred));

  /* sets the system trusted CAs for Internet PKI */
  CHECK(gnutls_certificate_set_x509_system_trust(xcred));

  /* If client holds a certificate it can be set using the following:
   *
   gnutls_certificate_set_x509_key_file (xcred, "cert.pem", "key.pem",
   GNUTLS_X509_FMT_PEM);
   */
}

int gnutls13_scan(client_t *cli) {
  if ((cli->op->tls_vers_enum) && (!cli->op->ssl2) && (!cli->op->ssl3) && (!cli->op->tls1)) {
    cli->tls_cert->tls1_3_ver_support = false;
    if (_gnutls13_scan(cli, tlsv1_3_gnutls_ciphers_str)) {
      cli->tls_cert->tls1_3_ver_support = true;
    }
  }

  // TODO - replace hardcoded index with safe+readable const var
  char priority[512];
  for (int i = 0; i < cli->op->cipher1_3_enum_count; i++) {
    snprintf(priority, 512, "NONE:+CTYPE-ALL:+COMP-ALL:+GROUP-ALL:+SIGN-ALL:+KX-ALL:+MAC-ALL:+VERS-TLS1.3:+%s", cli->op->cipher1_3_enum_list[i]);
    printf("%s\n", priority);
    if (_gnutls13_scan(cli, priority)) {
      cli->tls_cert->cipher1_3_suite_support[i] = true;
    }
  }

  return 0;
}

bool _gnutls13_scan(client_t *cli, const char *priority) {
  int ret, sd;
  bool status = false;
  char *desc;
  gnutls_datum_t out;
  int type;
  gnutls_session_t session;

  // Initialize TLS session
  CHECK(gnutls_init(&session, GNUTLS_CLIENT));
  CHECK(gnutls_priority_set_direct(session, priority, NULL));

  // put the x509 credentials to the current session
  CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred));
      /*  if (cli->host[0] != 0) {
        //  gnutls_session_set_verify_cert(session, cli->host, 0);
          CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, cli->host, strlen(cli->host)));
        } else {
          gnutls_session_set_verify_cert(session, NULL, 0);
        }*/
        /* connect to the peer
         */
  sd = tcp_connect(cli->ip, cli->port);
  gnutls_transport_set_int(session, sd);
  gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  // Perform the TLS handshake; TODO add non-blocking support
  do {
    ret = gnutls_handshake(session);
  }
  while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
  if (ret < 0) {
    if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
      /* check certificate verification status */
      type = gnutls_certificate_type_get(session);
      status = gnutls_session_get_verify_cert_status(session);
      CHECK(gnutls_certificate_verification_status_print(status, type, &out, 0));
      printf("cert verify output: %s\n", out.data);
      gnutls_free(out.data);
    }

    fprintf(stderr, "*** Handshake failed: %s\n", gnutls_strerror(ret));

  } else {
    desc = gnutls_session_get_desc(session);
    printf("- Session info: %s\n", desc);
    gnutls_free(desc);
    gnutls_bye(session, GNUTLS_SHUT_RDWR);
    status = true;
  }

  tcp_close(sd);
  gnutls_deinit(session);
  return status;
}

void gnutls13_deinit() {
        gnutls_certificate_free_credentials(xcred);
        gnutls_global_deinit();
        return;
}
