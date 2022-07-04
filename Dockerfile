FROM ubuntu:18.04 AS builder

RUN set -xeu; \
    apt-get update; \
    apt-get install -y \
        build-essential \
        autoconf \
        automake \
        pkg-config \
        curl \
        zip \
        libtool

COPY . /usr/local/src/tls-scan
RUN set -xeu; \
    cd /usr/local/src/tls-scan; \
    ./build-x86-64.sh


FROM ubuntu:18.04

RUN useradd -rU tls-scan
USER tls-scan

WORKDIR /usr/local/share/tls-scan/
COPY --from=builder /usr/local/src/tls-scan/build-root/bin/tls-scan /usr/local/bin/tls-scan
ADD --chown=tls-scan:tls-scan https://curl.haxx.se/ca/cacert.pem ./ca-bundle.crt

ENTRYPOINT ["tls-scan"]
CMD ["--help"]
