[![Build Status](https://travis-ci.org/prbinu/tls-scan.svg?branch=master)](https://travis-ci.org/prbinu/tls-scan)
[![Release](https://img.shields.io/badge/release-latest-blue.svg?label=release)](https://github.com/prbinu/tls-scan/releases/latest)
# tls-scan

A program to scan TLS based servers and collect X.509 certificates, ciphers and related information. It produces results in JSON format. `tls-scan` is a single threaded asynchronous/event-based program (powered by libevent) capable of concurrently scan thousands of TLS servers. It can be combined with other tools such as GNU parallel to vertically scale in multi-core machines.

`tls-scan` helps developers and security engineers to track/test/debug certificates and TLS configurations of servers within their organization.

## Features

* Extract X.509 certificate from the server and print it in JSON format
* Certificate and host name verification checks
* Cipher and TLS version enumeration
* TLS compression checks
* Session reuse tests
* Certificate revocation checks with stapled OCSP response
* Support TLS, SMTP STARTTLS and MYSQL protocols
* Can operate at scale with the ability to concurrently scan large number of servers
* Can be easily combined with other tools to analyze the scan results

This tool is primarly for collecting data. The scan output can be easily combined with related tools to identify TLS misconfigurations.

## Installation

You may either use pre-built binary package or build from the source.

### Pre-built Binary

Linux and OSX: [https://github.com/prbinu/tls-scan/releases/latest](https://github.com/prbinu/tls-scan/releases/latest)

### Build From Source

All you need is [`build-x86-64.sh`](https://github.com/prbinu/tls-scan/blob/master/build-x86-64.sh). This script pulls `tls-scan`, its  dependent packages - PeterMosmans [`openssl`](https://github.com/PeterMosmans/openssl) and [`libevent`](https://github.com/libevent/libevent), and build those from the scratch. Since the openssl we use is different from stock openssl, it is linked statically to tls-scan program. The build can take approximately five minutes to complete.

*Build Pre-requisites* :

* [autoconf](https://ftpmirror.gnu.org/autoconf)
* [automake](https://ftpmirror.gnu.org/automake)
* [libtool](http://ftpmirror.gnu.org/libtool)
* [pkg-config](https://pkg-config.freedesktop.org/releases/?C=M;O=D)
* [gcc](http://railsapps.github.io/xcode-command-line-tools.html)

### Linux

*Build* :

```sh
% ./build-x86-64.sh
```

The newly built tls-scan binary can be found at `./ts-build-root/bin`

*Test* :

```sh
% cd ts-build-root/bin
% ./tls-scan --connect=yahoo.com --cacert=../etc/tls-scan/ca-bundle.crt --pretty
```

### OSX
If you do not have the pre-requisite packages, you can easily install those packages by following the links below:

* [xcode-command-line-tools](http://railsapps.github.io/xcode-command-line-tools.html)
* [how-to-install-autoconf-automake-and-related-tools-on-mac-os-x-from-source](http://superuser.com/questions/383580/how-to-install-autoconf-automake-and-related-tools-on-mac-os-x-from-source)

*Build* :

```sh
% ./build-x86-64.sh
```

The tls-scan binary can be found at `./ts-build-root/bin`. Another (easy) option is to use our Docker image to build and run `tls-scan` on OSX.

### Docker

*Pre-requisite* : [Docker](https://docs.docker.com/engine/installation/)

*Build* :
Copy the [Dockerfile](https://github.com/prbinu/tls-scan/blob/master/Dockerfile) to your machine, and run it:

```sh
% docker build -t tls-scan .
```

*Test* :

```sh
% docker run tls-scan --connect=yahoo.com:443 --cacert=/usr/local/etc/tls-scan/ca-bundle.crt --pretty
```

## Example

```sh
% ./tls-scan -c search.yahoo.com --all --pretty
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

## Usage

The scan output can be shoved into tools like [Splunk](http://www.splunk.com/) or [ELK](http://elastic.co/) for analysis.

### Command-line Query & Filter

By passing `tls-scan` output to JSON command-line parser like [`jq`](https://stedolan.github.io/jq), you can do realtime filtering on the scan results.

**Examples**:

*Command to filter out hosts that passed certificate and host name verifications*:

```sh
cat input.txt | tls-scan --port=443  2>/dev/null | \
jq-linux64 -r 'select(.verifyHostResult == true and .verifyCertResult == true) | [.host, .ip, .verifyHost, .verifyCert] | @tsv'

```

*Command to find hosts with expired certificates* :

```sh
cat input.txt | tls-scan --port=443 --concurrency=500 --timeout=5 2>/dev/null | \
jq-linux64 -r  'select(.certificateChain[].expired == true) | [.host, .ip] | @tsv'

```

*Command to find weak RSA keys* :

```sh
cat tlscerts.out | \
jq-linux64 -r  'select(.certificateChain[0].publicKeyAlg == "RSA" and .certificateChain[0].publicKeySize < 2048) | [.host, .ip]'

```

*Command to find hosts that support SSLv2 or SSLv3* :

```sh
tls-scan --infile=domains.txt --port=443 --version-enum --concurrency=250 --timeout=3 2>/dev/null | \
jq-linux64 -r 'if (.tlsVersions[] | contains("SSL")) == true then [.host, .ip, .tlsVersions[]] else empty end | @tsv'

```

**NOTE**: Avoid frequent scan + filter; instead save the scan output to a file and use it to run queries.

## Help

|     Option     | Description |
|----------------|-------------|
-H  --help | Print a usage message briefly summarizing these command-line options and the bug-reporting address, then exit.
-c  --connect=\<arg\> | `host[:port]` to scan. By passing an additional flag `--ip`, the host value will be interpreted as an IP address.
-p  --port=\<arg\> | Destination TCP port. Default: `443`
--starttls=\<protocol\> | Specify the starttls protocol. Current options: `smtp` and `mysql`. If the flag is not provided, program will choose the protocol based on the given port. Port `443`, `465`, `993` and `995` defaults to `tls`. Port `25` and `587` uses starttls `smtp` by default. Port `3306` use `mysql` SSL.
-c  --cacert=\<file\> | Root CA file for certificate validation. By default the program attempts to load `ca-bundle.crt` file from current directory.
-C  --ciphers=\<arg\> | Ciphers to use; try `openssl ciphers` to see all ciphers. Note that this option will be overwritten by `--ssl2`, `--ssl3`, `--tls1`, `--tls1_1`, `--tls1_2` options, if provided. Example: `"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384"`
-e  --cipher-enum | Enumerate supported ciphers. Currently use `--tls-old` ciphers. Try `--meta-info` to find predefined cipher suite options.
--show-unsupported-ciphers | Include unsupported ciphers in the cipher list to JSON output.
-V  --version-enum | Enumerate supported TLS versions.
-r  --session-reuse | Enable ssl session reuse.
-u  --session-print | Print SSL session in PEM format to stderr. This is currently not included in the JSON output, but print seperately. This flag woould be useful if you wanted to pass SSL session to `--session-file` to test session reuse.
-T  --session-file=\<file\> | File that contains SSL session in PEM format.
-a  --all | Shortcut for `--version-enum`, `--cipher-enum` and `--session-reuse` options. This scan can take longer time to complete. Also note if the server employs some form of rate-limiting, your scan may fail.
-s  --sni=\<host\> | Set TLS extension servername in `ClientHello`. Defaults to input hostname and applied to TLSv1+ only.
-b  --concurrency=\<number\> | Number of concurrent requests. The default is 1. This option specify the number of worker objects. Concurrency should be set based on your system capacity (memory, cpu, network) etc. Default: 1.
-t  --timeout=\<number\> | Timeout per connection (in seconds). Note that is is per connection and for cipher scans, `tls-scan` makes several connections to the same server. Default: 10.
-S  --sleep=\<number\> | Add milliseconds delay between the connection. Only for `--cipher-enum` and `--version-enum` options. Useful to manage server rate-limits. The max sleep value is 60000 (1 minute). Default: 0.
-f  --infile=\<file\> | Input file with domains or IPs. This is optional and by default the program accepts input from standard input (`stdin`).
-o  --outfile=\<file\> | Output file where the result in JSON format is stored. The default is standard output (`stdout`).
-n  --pretty | Pretty print; add newline (`\n`) between record fields.
-i  --ip | Treat input as IP address. The default is hostname.
-N  --nameserver=\<ip\> | DNS resolver IPs to use and is an optional field. Multiple Namespace IP address can be passed. Format: `-N <ip1> -N <ip2> -N <ip3>..` In practice, DNS servers may have tight rate-limit in place.
--ssl2 | Use only SSLv2 ciphers.
--ssl3 | Use only SSLv3 ciphers.
--tls1 | Use only TLSv1 ciphers.
--tls1_1 | Use only TLSv1_1 ciphers.
--tls1_2 | Use only TLSv1_2 ciphers.
--tls-modern | Mozilla's modern cipher list. See: https://wiki.mozilla.org/Security/Server_Side_TLS.
--tls-interm | Mozilla's intermediate cipher list.
--tls-old | Mozilla's old (backward compatible cipher list).
--no-parallel-enum |Disable parallel cipher and tls version enumeration. Parallel scan is performed only with '--connect' option.
--meta-info | Print program meta information and exit. Useful if you wanted to see predefined cipher options.

## Caveats

* The openssl fork we use doesn't support new CHACHA ciphers (yet). Here is the tracking issue: https://github.com/PeterMosmans/openssl/issues/38
* The following ciphers are currently disabled: ```SRP:PSK:RC2:DES-CBC3-MD5:RC4-64-MD5:DES-CBC-MD5:IDEA```
* Instead of escaping JSON special chars (eg. double quotes), those characters are currently removed from the JSON output. (issue #2)

## CHACHA20_POLY1305 and  TLS-1.3 Support

```sh
% ./build-x86-64-openssl-1.1.1.sh
```

The `tls-scan` binary can be found at `./ts-build-root_v1_3/bin`.

`tls-scan` built with openssl-1.1.1 only supports latest ciphers. It cannot be used to enumerate SSLv2 or EXP ciphers. This is less than optimal solution, but as a workaround you may use tls-scan+openssl-1.1.1 for scanning latest ciphers and use tls-scan for scanning old ciphers and SSL versions. The results may combine using json tools.

## Contributions
Collaborators and pull requests are welcome!

