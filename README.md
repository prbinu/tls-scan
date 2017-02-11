[![Build Status](https://travis-ci.org/prbinu/tls-scan.svg?branch=master)](https://travis-ci.org/prbinu/tls-scan)


# tls-scan

A program to scan TLS based servers and collect x509 certificates, ciphers and related information. It produces results in JSON format. tls-scan is a single threaded asynchronous/event-based program (powered by libevent) capable of concurrently scan thousands of TLS servers. It can be combined with other tools such as GNU parallel to vertically scale in multi-core machines.

`tls-scan` helps developers and security engineers to track/test/debug certificates and TLS configurations of servers within their organization.

## Features

* Extract x509 certificate from the server and print it in JSON format
* Cipher and TLS version enumeration
* Session reuse tests
* Stapled OCSP response verification
* Can operate at scale with the ability to concurrently scan large number of servers 
* Support TLS, SMTP STARTTLS and MYSQL protocols
* Can be easily combined with other tools to analyze the scan results

This tool is primarly for collecting data. The scan output can be easily combined with related tools to identify TLS misconfigurations. 

## Installation

All you need is [`build-x86-64.sh`](https://github.com/prbinu/tls-scan/blob/master/build-x86-64.sh). This script pulls `tls-scan`, its  dependent packages - [`openssl`](https://github.com/PeterMosmans/openssl) and [`libevent`](https://github.com/libevent/libevent), and build those from the scratch. Since the openssl we use is different from stock openssl, it is linked staticlally to tls-scan program. The build can take approximately five minutes to complete.

*Pre-requisites*:
  * [autoconf](https://ftpmirror.gnu.org/autoconf)
  * [automake](https://ftpmirror.gnu.org/automake)
  * [libtool](http://ftpmirror.gnu.org/libtool)
  * [pkg-config](https://pkg-config.freedesktop.org/releases/?C=M;O=D)
  * [gcc](http://railsapps.github.io/xcode-command-line-tools.html)

### Linux

*Build*: 
```
% ./build-x86-64.sh
```
The newly built tls-scan binary can be found at `./ts-build-root/bin`

*Test*:
```
% cd ts-build-root/bin
% ./tls-scan --host=yahoo.com --cacert=../etc/tls-scan/ca-bundle.crt --pretty
```

### OSX
If you do not have the pre-requisite packages, you can easily install those packages by following the links below:
  * [xcode-command-line-tools](http://railsapps.github.io/xcode-command-line-tools.html)
  * [how-to-install-autoconf-automake-and-related-tools-on-mac-os-x-from-source](http://superuser.com/questions/383580/how-to-install-autoconf-automake-and-related-tools-on-mac-os-x-from-source)
  
*Build*: 
```
% ./build-x86-64.sh
```
The tls-scan binary can be found at `./ts-build-root/bin`. Another (easy) option is to use our Docker image to build and run `tls-scan` on OSX.

### Docker

*Pre-requisite*: [Docker](https://docs.docker.com/engine/installation/)

*Build*:
Copy the [Dockerfile](https://github.com/prbinu/tls-scan/blob/master/Dockerfile) to your machine, and run it:

```
% docker build -t tls-scan .
```
*Test*:
```
% docker run tls-scan --host=yahoo.com --port=443 --cacert=/usr/local/etc/tls-scan/ca-bundle.crt --pretty
```

## Example

```
% ./tls-scan --host=search.yahoo.com --port=443 --all --pretty
```

```json
{
  "host": "search.yahoo.com",
  "ip": "208.71.45.12",
  "port": 443,
  "cipher": "ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(128) Mac=AEAD",
  "tempPublicKeyAlg": "ECDH prime256v1",
  "tempPublicKeySize": 256,
  "secureRenego": true,
  "compression": "NONE",
  "expansion": "NONE",
  "sessionLifetimeHint": 100800,
  "tlsVersions": [
    "TLSv1", 
    "TLSv1_1", 
    "TLSv1_2"
  ],
  "x509ChainDepth": 2,
  "verifyCertResult": true,
  "verifyHostResult": true,
  "ocspStapled": true,
  "verifyOcspResult": true,
  "certificateChain": [
  {
    "version": 3,
    "subject": "CN=*.search.yahoo.com; O=Yahoo! Inc.; L=Sunnyvale; ST=CA; C=US",
    "issuer": "CN=DigiCert SHA2 High Assurance Server CA; OU=www.digicert.com; O=DigiCert Inc; C=US",
    "subjectCN": "*.search.yahoo.com",
    "subjectAltName": "DNS:*.search.yahoo.com, DNS:search.yahoo.com, DNS:search.yahoo.net, ...",
    "signatureAlg": "sha256WithRSAEncryption",
    "notBefore": "Dec  9 00:00:00 2016 GMT",
    "notAfter": "Apr 30 12:00:00 2017 GMT",
    "expired": false,
    "serialNo": "0F:45:73:E3:F5:7A:7D:5B:43:57:64:2A:6C:46:F2:1C",
    "keyUsage": "Digital Signature, Key Encipherment critical",
    "extKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
    "publicKeyAlg": "RSA",
    "publicKeySize": 2048,
    "basicConstraints": "CA:FALSE critical",
    "subjectKeyIdentifier": "63:0F:82:DB:F9:B0:64:78:90:C9:16:69:95:84:24:F1:4B:04:6F:E4",
    "sha1Fingerprint": "F7:35:E5:C9:A3:60:62:07:CB:55:74:7E:0F:09:AD:2A:F3:F3:53:F3"
  },  {
    "version": 3,
    "subject": "CN=DigiCert SHA2 High Assurance Server CA; OU=www.digicert.com; O=DigiCert Inc; C=US",
    "issuer": "CN=DigiCert High Assurance EV Root CA; OU=www.digicert.com; O=DigiCert Inc; C=US",
    "subjectCN": "DigiCert SHA2 High Assurance Server CA",
    "signatureAlg": "sha256WithRSAEncryption",
    "notBefore": "Oct 22 12:00:00 2013 GMT",
    "notAfter": "Oct 22 12:00:00 2028 GMT",
    "expired": false,
    "serialNo": "04:E1:E7:A4:DC:5C:F2:F3:6D:C0:2B:42:B8:5D:15:9F",
    "keyUsage": "Digital Signature, Certificate Sign, CRL Sign critical",
    "extKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication",
    "publicKeyAlg": "RSA",
    "publicKeySize": 2048,
    "basicConstraints": "CA:TRUE, pathlen:0 critical",
    "subjectKeyIdentifier": "51:68:FF:90:AF:02:07:75:3C:CC:D9:65:64:62:A2:12:B8:59:72:3B",
    "sha1Fingerprint": "A0:31:C4:67:82:E6:E6:C6:62:C2:C8:7C:76:DA:9A:A6:2C:CA:BD:8E"
  } ]
}

```
