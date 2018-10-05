// Copyright (c) 2016 Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/asn1.h>
#include <openssl/ocsp.h>
#include <string.h>
#include <cert-parser.h>

// References
// https://github.com/openssl/openssl/blob/master/apps/s_client.c
// https://zakird.com/2013/10/13/certificate-parsing-with-openssl


static BIO *get_cname(X509_NAME *name)
{
  int idx = -1;
  if (!name) {
    return NULL;;
  }

  idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
  if (!(idx > -1)) {
    return NULL;
  }

  X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
  if (!entry) {
    return NULL;
  }

  ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
  if (!data) {
    return NULL;
  }

  BIO *bio = BIO_new(BIO_s_mem());
  //int l = ASN1_STRING_print_ex(bio, data, ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL);
  if (!ASN1_STRING_print(bio, data)) {
    BIO_free(bio);
    return NULL;
  }

  if (BIO_flush(bio)) {}

  return bio;
}


static BIO *get_x509v3_ext(X509 *cert, int nid)
{
  int loc = 0;

  loc = X509_get_ext_by_NID(cert, nid, -1);
  X509_EXTENSION *ex = X509_get_ext(cert, loc);

  if (!ex) {
    return NULL;
  }

  BIO *bio = BIO_new(BIO_s_mem());
  if (!X509V3_EXT_print(bio, ex, 0, 0)) {
    BIO_free(bio);
    return NULL;
  }

  BIO_printf(bio, "%s", X509_EXTENSION_get_critical(ex) ? " critical" : "");
  if (BIO_flush(bio)) {}

  return bio;
}

static char *get_serial_no(X509 *const cert, char *out)
{
  strcpy(out, "NULL");
  ASN1_INTEGER *serial = X509_get_serialNumber(cert);
  int t = 0;
  for (int i = 0; i < serial->length; i++) {

    if (t+2 >= TS_SERIALNO_LEN) break;

    if (i + 1 == serial->length) {
      sprintf(out + t, "%02X", serial->data[i]);
    } else {
      t += sprintf(out + t, "%02X:", serial->data[i]);
    }
  }

  return out;
}

static char *get_x509_fingerprint(const X509 *cert,
                                            const EVP_MD *digest, char *out)
{
  strcpy(out, "NULL");
  unsigned char buf[SHA1LEN];
  unsigned len;

  int rc = X509_digest(cert, digest, buf, &len);
  if (rc == 0 || len != SHA1LEN) {
    return out;
  }

  int t = 0;
  for (int i = 0; i < SHA1LEN; i++) {

    if (i + 1 == SHA1LEN) {
      sprintf(out + t, "%02X", buf[i]);
    } else {
      t += sprintf(out + t, "%02X:", buf[i]);
    }
  }

  return out;
}

static const char *get_signature_algorithm(const X509 *cert)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  int sig_nid = OBJ_obj2nid((cert)->sig_alg->algorithm);
#else
  int sig_nid = X509_get_signature_nid(cert);
#endif
  return OBJ_nid2ln(sig_nid);
}

static int convert_ASN1TIME(ASN1_TIME *t, char *out, size_t len)
{
  strcpy(out, "NULL");
  int rc;
  BIO *b = BIO_new(BIO_s_mem());

  rc = ASN1_TIME_print(b, t);
  if (rc <= 0) {
    BIO_free(b);
    return EXIT_FAILURE;
  }

  rc = BIO_gets(b, out, len);
  if (rc <= 0) {
    BIO_free(b);
    return EXIT_FAILURE;
  }

  BIO_free(b);
  return EXIT_SUCCESS;
}

static int get_public_keyalg_and_keylen(EVP_PKEY *key, char *out_alg, bool tmp_key)
{
  out_alg[0] = 0;
  int keylen = 0;

  switch (EVP_PKEY_id(key)) {
  case EVP_PKEY_RSA:
    strcpy(out_alg, "RSA");
    keylen = EVP_PKEY_bits(key);
    break;

  case EVP_PKEY_DSA:
    strcpy(out_alg, "DSA");
    keylen = EVP_PKEY_bits(key);
    break;

  case EVP_PKEY_DH:
    strcpy(out_alg, "DH");
    keylen = EVP_PKEY_bits(key);
    break;

  case EVP_PKEY_EC:
  {
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
    int nid = 0;
    const char *cname = NULL;

    nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
    EC_KEY_free(ec);
    //cname = EC_curve_nid2nist(nid);
    cname = OBJ_nid2sn(nid);

    if (tmp_key) {
      sprintf(out_alg, "ECDH %s", cname);
    } else {
      sprintf(out_alg, "ECC %s", cname);
    }

    keylen = EVP_PKEY_bits(key);
  }
  break;

  default:
    //strcpy(out_alg, OBJ_nid2sn(EVP_PKEY_id(key)));
    snprintf(out_alg, PUBKEY_ALGSTR_LEN, "%s", OBJ_nid2sn(EVP_PKEY_id(key)));
    keylen = EVP_PKEY_bits(key);
  }

  return keylen;
}

static BIO *get_X509_name(X509_NAME *name)
{
  BIO *bio = BIO_new(BIO_s_mem());
  X509_NAME_print_ex(bio, name, 0,  XN_FLAG_DN_REV | XN_FLAG_SEP_SPLUS_SPC |
                                           !XN_FLAG_SPC_EQ | XN_FLAG_FN_SN |
                           ASN1_STRFLGS_UTF8_CONVERT | ASN1_STRFLGS_ESC_CTRL);
  if (BIO_flush(bio)) {}
  return bio;
}

static void X509_parse(X509 *cert, struct x509_cert *x509_cert)
{
  /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */
  x509_cert->issuer = get_X509_name(X509_get_issuer_name(cert));

  x509_cert->subject = get_X509_name(X509_get_subject_name(cert));

  x509_cert->subject_cname = get_cname(X509_get_subject_name(cert));

  get_x509_fingerprint(cert, EVP_sha1(), x509_cert->sha1_fingerprint);

  x509_cert->x509_ver = X509_get_version(cert) + 1;

  get_serial_no(cert, x509_cert->serialno);

  snprintf(x509_cert->sig_alg, SIG_ALGSTR_LEN, "%s",
                                              get_signature_algorithm(cert));

  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if (pkey) {
    x509_cert->pubkey_size =
            get_public_keyalg_and_keylen(pkey, x509_cert->pubkey_alg, false);
    EVP_PKEY_free(pkey);
  }

  x509_cert->subject_keyid = get_x509v3_ext(cert, NID_subject_key_identifier);

  x509_cert->key_usage = get_x509v3_ext(cert, NID_key_usage);

  x509_cert->ext_key_usage = get_x509v3_ext(cert, NID_ext_key_usage);

  x509_cert->basic_constr = get_x509v3_ext(cert, NID_basic_constraints);

  x509_cert->name_constr = get_x509v3_ext(cert, NID_name_constraints);

  ASN1_TIME *not_before = X509_get_notBefore(cert);
  ASN1_TIME *not_after = X509_get_notAfter(cert);

  convert_ASN1TIME(not_after, x509_cert->not_after, TS_DATE_LEN);
  convert_ASN1TIME(not_before, x509_cert->not_before, TS_DATE_LEN);
  time_t ctime;
  ctime = time(&ctime);
  ASN1_TIME *curr_time = ASN1_TIME_set(NULL, ctime);

  int pday;
  int psec;
  ASN1_TIME_diff(&pday, &psec, curr_time, not_after);

  if (pday > 0 || psec > 0) {
    x509_cert->cert_expired = false;
  } else {
    x509_cert->cert_expired = true;
  }

  ASN1_STRING_free(curr_time);
  return;
}

options_t  *ts_get_global_option_obj();

static const char *bool_to_str(bool b)
{
  if (b) {
    return "true";
  } else {
    return "false";
  }
}

static const char *get_ssl_version_str(int index)
{
  switch (index) {
  case 0:
    return "SSLv2";
  case 1:
    return "SSLv3";
  case 2:
    return "TLSv1";
  case 3:
    return "TLSv1_1";
  case 4:
    return "TLSv1_2";
  default:
    return "UNKNOWN";
  }
}

static bool verify_ocsp(SSL *ssl, OCSP_RESPONSE *ocsp_resp,
                                                  STACK_OF(X509) *cert_stack)
{
  bool ret = false;
  OCSP_BASICRESP *bresp = NULL;
  int st = -1;

  bresp = OCSP_response_get1_basic(ocsp_resp);
  if (!bresp) {
    return false;
  }

  X509_STORE *x509_store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
  assert(x509_store != NULL);

  st = OCSP_basic_verify(bresp, cert_stack, x509_store, 0);
  if (st <= 0) {
    //ERR_print_errors_fp(stderr);
    ret = false;
  } else {
    ret = true;
  }

  OCSP_BASICRESP_free(bresp);
  return ret;
}

void ts_tls_cert_parse(SSL *ssl, struct tls_cert *tls_cert,
                                                      FILE * fp, bool pretty)
{
  STACK_OF(X509) * cert_stack;
  X509 *cert = NULL;
  int i;
  const COMP_METHOD *comp = NULL, *expansion = NULL;

  SSL_CIPHER_description(SSL_get_current_cipher(ssl), tls_cert->cipher, 128);
  // remove newline chars
  tls_cert->cipher[strlen(tls_cert->cipher) - 1] = '\0';

  EVP_PKEY *key = NULL;
  if (SSL_get_server_tmp_key(ssl, &key)) {
    tls_cert->temp_pubkey_size =
            get_public_keyalg_and_keylen(key, tls_cert->temp_pubkey_alg, true);
    EVP_PKEY_free(key);
  }

  tls_cert->secure_renego =
                      SSL_get_secure_renegotiation_support(ssl) ? true : false;

  comp = SSL_get_current_compression(ssl);
  snprintf(tls_cert->compression, sizeof(tls_cert->compression), "%s",
                                      comp ? SSL_COMP_get_name(comp) : "NONE");

  expansion = SSL_get_current_expansion(ssl);
  snprintf(tls_cert->expansion, sizeof(tls_cert->expansion), "%s",
                                 comp ? SSL_COMP_get_name(expansion) : "NONE");

  SSL_SESSION *session = SSL_get_session(ssl);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if (session) {
    tls_cert->session_lifetime_hint = session->tlsext_tick_lifetime_hint;
  }
#else
  if (session && SSL_SESSION_has_ticket(session)) {
    tls_cert->session_lifetime_hint = SSL_SESSION_get_ticket_lifetime_hint(session);
  }
#endif

  // https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_SSL_SESSION.html
  if (!tls_cert->session) {
    tls_cert->session = SSL_get1_session(ssl);
  }

  cert_stack = SSL_get_peer_cert_chain(ssl);
  tls_cert->x509_chain_depth = sk_X509_num(cert_stack);

  int res = SSL_get_verify_result(ssl);
  if (X509_V_OK == res) {
    tls_cert->verify_cert = true;
  } else {
    tls_cert->verify_cert = false;
  }

  snprintf(tls_cert->verify_cert_errmsg, sizeof(tls_cert->verify_cert_errmsg),
                                    "%s", X509_verify_cert_error_string(res));

  const unsigned char *resp;
  long ocsp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);

  if (ocsp_len == -1) {
    tls_cert->ocsp_stapling_response = false;
  } else {
    tls_cert->ocsp_stapling_response = true;

    OCSP_RESPONSE *ocsp_resp = d2i_OCSP_RESPONSE(NULL, &resp, ocsp_len);
    if (ocsp_resp) {
      tls_cert->verify_ocsp_basic = verify_ocsp(ssl, ocsp_resp, cert_stack);
      OCSP_RESPONSE_free(ocsp_resp);
    } else {
      tls_cert->verify_ocsp_basic = false;
    }
  }

  for (i = 0; i < tls_cert->x509_chain_depth; i++) {

    if (i == CERT_CHAIN_MAXLEN) {
      break;
    }

    cert = sk_X509_value(cert_stack, i);
    X509_parse(cert, &tls_cert->x509[i]);

    if (i == 0) {
      tls_cert->san = get_x509v3_ext(cert, NID_subject_alt_name);

      int ret = X509_check_host(cert, tls_cert->host, 0, 0, NULL);
      if (ret == 1) {
        tls_cert->verify_host = true;
      } else {
        tls_cert->verify_host = false;
      }
    }
  }
}

void ts_tls_cert_BIO_free(struct tls_cert *tls_cert)
{
  if (!tls_cert) return;

  if (tls_cert->session) {
    SSL_SESSION_free(tls_cert->session);
    tls_cert->session = NULL;
  }

  for (int i = 0; i < tls_cert->x509_chain_depth; i++) {

    if (i == CERT_CHAIN_MAXLEN) {
      break;
    }

    if (0 == i) {
      if (tls_cert->san) {
        BIO_free(tls_cert->san);
       tls_cert->san = NULL;
      }
    }

    if (tls_cert->x509[i].issuer) {
      BIO_free(tls_cert->x509[i].issuer);
      tls_cert->x509[i].issuer = NULL;
    }

    if (tls_cert->x509[i].subject) {
      BIO_free(tls_cert->x509[i].subject);
      tls_cert->x509[i].subject = NULL;
    }

    if (tls_cert->x509[i].subject_cname) {
      BIO_free(tls_cert->x509[i].subject_cname);
      tls_cert->x509[i].subject_cname = NULL;
    }

    if (tls_cert->x509[i].key_usage) {
      BIO_free(tls_cert->x509[i].key_usage);
      tls_cert->x509[i].key_usage = NULL;
    }

    if (tls_cert->x509[i].ext_key_usage) {
      BIO_free(tls_cert->x509[i].ext_key_usage);
      tls_cert->x509[i].ext_key_usage = NULL;
    }

    if (tls_cert->x509[i].basic_constr) {
      BIO_free(tls_cert->x509[i].basic_constr);
      tls_cert->x509[i].basic_constr = NULL;
    }

   if (tls_cert->x509[i].name_constr) {
      BIO_free(tls_cert->x509[i].name_constr);
      tls_cert->x509[i].name_constr = NULL;
    }

    if (tls_cert->x509[i].subject_keyid) {
      BIO_free(tls_cert->x509[i].subject_keyid);
      tls_cert->x509[i].subject_keyid = NULL;
    }
  }
}

void ts_tls_cert_reset(struct tls_cert* tls_cert)
{
  if (!tls_cert) return;

  bool *cipher_suite_support = tls_cert->cipher_suite_support;
  memset(tls_cert, 0, sizeof(struct tls_cert));

  const options_t *op = ts_get_global_option_obj();
  if ((cipher_suite_support) && (op->cipher_enum_count > 0)) {
    memset(cipher_suite_support, 0, op->cipher_enum_count);
    tls_cert->cipher_suite_support= cipher_suite_support;
  }

  tls_cert->cipher_suite_support= cipher_suite_support;
}

const SSL_METHOD *ts_tls_get_method(int index)
{
  switch (index) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    case 0:
      return SSLv2_client_method();
#endif
  case 1:
    return SSLv3_client_method();
  case 2:
    return TLSv1_client_method();
  case 3:
    return TLSv1_1_client_method();
  case 4:
    return TLSv1_2_client_method();
  default:
    return SSLv23_client_method();
  }
}

void ts_json_escape(char *data, size_t length, char espchar)
{
  int i;
  for (i = 0; i < length; i++) {
    if (data[i] == espchar) {
      data[i] = ' ';
    }
  }
}

#define FMT_INDENT(n) (n) * sp_flag, sp

void ts_tls_print_json(struct tls_cert *tls_cert, FILE *fp, bool pretty)
{
  BUF_MEM *bptr = NULL;
  char fmt = ' ';
  char sp[] = "                    "; // indent space
  char sp_flag = 0;

  if (pretty) {
    fmt = '\n';
    sp_flag = 1;
  }

  const options_t *op = ts_get_global_option_obj();

  fprintf(fp, "{%c", fmt);

  if (tls_cert->host[0] != 0) {
    fprintf(fp, "%.*s\"host\": \"%s\",%c", FMT_INDENT(2), tls_cert->host, fmt);
  }

  if (tls_cert->ip[0] != 0) {
    fprintf(fp, "%.*s\"ip\": \"%s\",%c", FMT_INDENT(2), tls_cert->ip, fmt);
  }

  fprintf(fp, "%.*s\"port\": %d,%c", FMT_INDENT(2), tls_cert->port, fmt);
  fprintf(fp, "%.*s\"cipher\": \"%s\",%c", FMT_INDENT(2), tls_cert->cipher, fmt);

  if (tls_cert->temp_pubkey_size > 0) {
    fprintf(fp, "%.*s\"tempPublicKeyAlg\": \"%s\",%c", FMT_INDENT(2),
                                               tls_cert->temp_pubkey_alg, fmt);

    fprintf(fp, "%.*s\"tempPublicKeySize\": %d,%c", FMT_INDENT(2),
                                              tls_cert->temp_pubkey_size, fmt);
  }

  fprintf(fp, "%.*s\"secureRenego\": %s,%c", FMT_INDENT(2),
                                    bool_to_str(tls_cert->secure_renego), fmt);
  fprintf(fp, "%.*s\"compression\": \"%s\",%c", FMT_INDENT(2),
                                                   tls_cert->compression, fmt);
  fprintf(fp, "%.*s\"expansion\": \"%s\",%c", FMT_INDENT(2),
                                                     tls_cert->expansion, fmt);

  if (op->session_reuse_test) {
     fprintf(fp, "%.*s\"sessionReuse\": %s,%c", FMT_INDENT(2),
                          bool_to_str(tls_cert->session_reuse_supported), fmt);
  }

  if (tls_cert->session_lifetime_hint > 0) {
    fprintf(fp, "%.*s\"sessionLifetimeHint\": %lu,%c", FMT_INDENT(2),
                                         tls_cert->session_lifetime_hint, fmt);
  }

  if (op->tls_vers_enum) {

    fprintf(fp, "%.*s\"tlsVersions\": [%c", FMT_INDENT(2), fmt);
    int i, j = 0;
    int vers[MAX_TLS_VERSION];

    for (i = 0; i < MAX_TLS_VERSION; i++) {
      if (tls_cert->tls_ver_support[i]) {
        vers[j++] = i;
      }
    }

// workaround to supress SSLv2 if openssl version > 1.1.x
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    fprintf(fp, "%.*s\"%s\", %c", FMT_INDENT(4),
                                            get_ssl_version_str(vers[0]), fmt);
#endif
    
    for (i = 1; i < j-1; i++) {
      fprintf(fp, "%.*s\"%s\", %c", FMT_INDENT(4),
                                            get_ssl_version_str(vers[i]), fmt);
    }

    fprintf(fp, "%.*s\"%s\"%c%.*s],%c", FMT_INDENT(4),
                        get_ssl_version_str(vers[i]), fmt, FMT_INDENT(2), fmt);
  }

  if (op->cipher_enum) {

    int supported[op->cipher_enum_count];
    int unsupported[op->cipher_enum_count];

    int i = 0, s = 0, u = 0;
    for (i = 0; i < op->cipher_enum_count; i++) {

      if (tls_cert->cipher_suite_support[i]) {
        supported[s++] = i;
      } else {
        unsupported[u++] = i;
      }

    }

    fprintf(fp, "%.*s\"cipherSuite\": {%c", FMT_INDENT(2), fmt);
    fprintf(fp, "%.*s\"supported\": [%c", FMT_INDENT(4), fmt);

    if (s > 0) {
      for (i = 0; i < s-1; i++) {
        fprintf(fp, "%.*s\"%s\",%c", FMT_INDENT(6),
                                      op->cipher_enum_list[supported[i]], fmt);
      }

      fprintf(fp, "%.*s\"%s\"%c", FMT_INDENT(6),
                                      op->cipher_enum_list[supported[i]], fmt);
    }

    if (op->show_unsupported_ciphers) {
      fprintf(fp, "%.*s],%c", FMT_INDENT(4), fmt);
      fprintf(fp, "%.*s\"notSupported\": [%c", FMT_INDENT(4), fmt);

      if (u > 0) {
        for (i = 0; i < u-1; i++) {
          fprintf(fp, "%.*s\"%s\",%c", FMT_INDENT(6),
                                    op->cipher_enum_list[unsupported[i]], fmt);
        }

        fprintf(fp, "%.*s\"%s\"%c", FMT_INDENT(6),
                                    op->cipher_enum_list[unsupported[i]], fmt);
      }
    }

    fprintf(fp, "%.*s]%c", FMT_INDENT(4), fmt);
    fprintf(fp, "%.*s},%c", FMT_INDENT(2), fmt);
  }

  fprintf(fp, "%.*s\"x509ChainDepth\": %d,%c", FMT_INDENT(2),
                                              tls_cert->x509_chain_depth, fmt);

  if (tls_cert->verify_cert) {
    fprintf(fp, "%.*s\"verifyCertResult\": true,%c", FMT_INDENT(2), fmt);
  } else {
    fprintf(fp, "%.*s\"verifyCertResult\": false,%c", FMT_INDENT(2), fmt);
    fprintf(fp, "%.*s\"verifyCertError\": \"%s\",%c",
                              FMT_INDENT(2), tls_cert->verify_cert_errmsg, fmt);
  }

  fprintf(fp, "%.*s\"verifyHostResult\": %s,%c",
                        FMT_INDENT(2), bool_to_str(tls_cert->verify_host), fmt);

  fprintf(fp, "%.*s\"ocspStapled\": %s,%c", FMT_INDENT(2),
                           bool_to_str(tls_cert->ocsp_stapling_response), fmt);

  if (tls_cert->ocsp_stapling_response) {
    fprintf(fp, "%.*s\"verifyOcspResult\": %s,%c", FMT_INDENT(2),
                           bool_to_str(tls_cert->verify_ocsp_basic), fmt);
  }

  if (tls_cert->x509_chain_depth > 0) {
    fprintf(fp, "%.*s\"certificateChain\": [%c", FMT_INDENT(2), fmt);
  }

  int i = 0;
  while (i < tls_cert->x509_chain_depth) {

    if (i == CERT_CHAIN_MAXLEN) {
      break;
    }

    fprintf(fp, "%.*s{%c", FMT_INDENT(2), fmt);
    fprintf(fp, "%.*s\"version\": %d,%c", FMT_INDENT(4),
                                              tls_cert->x509[i].x509_ver, fmt);

    if (tls_cert->x509[i].subject) {
      BIO_get_mem_ptr(tls_cert->x509[i].subject, &bptr);
      // TODO - temp fix
      ts_json_escape(bptr->data, bptr->length, '\"');
      ts_json_escape(bptr->data, bptr->length, '\\');
      fprintf(fp, "%.*s\"subject\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
    }

    if (tls_cert->x509[i].issuer) {
      BIO_get_mem_ptr(tls_cert->x509[i].issuer, &bptr);

      if (!tls_cert->verify_cert) {
        ts_json_escape(bptr->data, bptr->length, '\"');
        ts_json_escape(bptr->data, bptr->length, '\\');
      }

      fprintf(fp, "%.*s\"issuer\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
    }

    if (tls_cert->x509[i].subject_cname) {
      BIO_get_mem_ptr(tls_cert->x509[i].subject_cname, &bptr);
      fprintf(fp, "%.*s\"subjectCN\": \"%.*s\",%c", FMT_INDENT(4),
                                         (int)bptr->length, bptr->data, fmt);
    }

    if (0 == i) {
      if (tls_cert->san) {
        BIO_get_mem_ptr(tls_cert->san, &bptr);

        if (!tls_cert->verify_cert) {
          ts_json_escape(bptr->data, bptr->length, '\n');
        }

        ts_json_escape(bptr->data, bptr->length, '\\');
        fprintf(fp, "%.*s\"subjectAltName\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
      }
    }

    fprintf(fp, "%.*s\"signatureAlg\": \"%s\",%c", FMT_INDENT(4),
                                               tls_cert->x509[i].sig_alg, fmt);
    fprintf(fp, "%.*s\"notBefore\": \"%s\",%c", FMT_INDENT(4),
                                            tls_cert->x509[i].not_before, fmt);
    fprintf(fp, "%.*s\"notAfter\": \"%s\",%c", FMT_INDENT(4),
                                             tls_cert->x509[i].not_after, fmt);

    fprintf(fp, "%.*s\"expired\": %s,%c", FMT_INDENT(4),
                             bool_to_str(tls_cert->x509[i].cert_expired), fmt);

    fprintf(fp, "%.*s\"serialNo\": \"%s\",%c", FMT_INDENT(4),
                                              tls_cert->x509[i].serialno, fmt);

    if (tls_cert->x509[i].key_usage) {
      BIO_get_mem_ptr(tls_cert->x509[i].key_usage, &bptr);
      fprintf(fp, "%.*s\"keyUsage\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
    }

    if (tls_cert->x509[i].ext_key_usage) {
      BIO_get_mem_ptr(tls_cert->x509[i].ext_key_usage, &bptr);
      fprintf(fp, "%.*s\"extKeyUsage\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
    }

    fprintf(fp, "%.*s\"publicKeyAlg\": \"%s\",%c", FMT_INDENT(4),
                                            tls_cert->x509[i].pubkey_alg, fmt);

    fprintf(fp, "%.*s\"publicKeySize\": %d,%c", FMT_INDENT(4),
                                           tls_cert->x509[i].pubkey_size, fmt);

    if (tls_cert->x509[i].basic_constr) {
      BIO_get_mem_ptr(tls_cert->x509[i].basic_constr, &bptr);
      fprintf(fp, "%.*s\"basicConstraints\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
    }

    if (tls_cert->x509[i].name_constr) {
      BIO_get_mem_ptr(tls_cert->x509[i].name_constr, &bptr);
      ts_json_escape(bptr->data, bptr->length, '\n');
      fprintf(fp, "%.*s\"nameConstraints\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
    }

    if (tls_cert->x509[i].subject_keyid) {
      BIO_get_mem_ptr(tls_cert->x509[i].subject_keyid, &bptr);
      fprintf(fp, "%.*s\"subjectKeyIdentifier\": \"%.*s\",%c", FMT_INDENT(4),
                                           (int)bptr->length, bptr->data, fmt);
    }

    fprintf(fp, "%.*s\"sha1Fingerprint\": \"%s\"%c", FMT_INDENT(4),
                                      tls_cert->x509[i].sha1_fingerprint, fmt);
    //fprintf(fp, "authorityKeyIdentifier: %s; ", tls_cert->x509[i].authority_keyid);

    if ((i + 1 == tls_cert->x509_chain_depth) || (i + 1 == CERT_CHAIN_MAXLEN)){
      fprintf(fp, "%.*s} ]%c", FMT_INDENT(2), fmt);
    } else {
      fprintf(fp, "%.*s},", FMT_INDENT(2));
    }

    i++;
  }

  fprintf(fp, "}\n");
  fflush(fp);

  // print seperate, outside of json
  if (op->session_print) {
    fprintf(stderr, "host: %s; ip: %s; ssl_session:\n",
                                               tls_cert->host, tls_cert->ip);
    PEM_write_SSL_SESSION(stderr, tls_cert->session);
  }
}
