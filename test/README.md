## 

### TLS Certificates

```
# RSA certs
openssl req -new -newkey rsa:2048 -x509 -sha256 -days 3650 -nodes -out test.crt -keyout test.key

# ECDSA certs
openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) -keyout ecdsa-test.key -out ecdsa-test.crt

# DSS certs

```
