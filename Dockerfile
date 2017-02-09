FROM ubuntu:16.04

RUN apt-get update -y
RUN apt-get upgrade -y

RUN apt-get install build-essential -y
RUN apt-get install curl -y
RUN apt-get install zip -y
RUN apt-get install autoconf -y
RUN apt-get install libtool -y
RUN apt-get install automake -y
RUN apt-get install pkg-config -y
RUN apt-get install jq -y

ENV TS_INSTALLDIR /usr/local
ADD ./build-x86-64.sh build-x86-64.sh
RUN ./build-x86-64.sh

ENTRYPOINT ["tls-scan"]
CMD ["--help"]

