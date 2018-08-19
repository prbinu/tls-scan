#!/bin/bash
# Environment variables
#  TS_BUILDDIR : Build root directory. Default to current working directory
#  TS_INSTALLDIR : Installation directory. Default to ${TS_BUILDDIR}
#
echo " "
echo "  IMPORTANT NOTICE"
echo "  Build Pre-requisites :"
echo " "
echo "    gcc"
echo "    autoconf"
echo "    automake"
echo "    libtool"
echo "    pkg-config"
echo "Make sure you have these packages installed before you proceed with tls-scan build"
echo "continue in a moment ..."
sleep 10

set -e
CD=`pwd`
OS=`uname`

if [ "${OS}" != "Darwin" ] && [ "${OS}" != "Linux" ]; then
  echo "Error: ${OS} is not a currently supported platform."
  exit 1
fi

[[ -z "${TS_BUILDDIR}" ]] && BUILDDIR="${CD}" || BUILDDIR="${TS_BUILDDIR}"

echo ">>> Build DIR: ${BUILDDIR}"
BUILDDIR=${BUILDDIR}/ts-build-root

# remove build dirs
test -d ${BUILDDIR}/build && rm -rf ${BUILDDIR}/build/*


test -z ${BUILDDIR} || /bin/mkdir -p ${BUILDDIR}
test -z ${BUILDDIR}/downloads || /bin/mkdir -p ${BUILDDIR}/downloads
test -z ${BUILDDIR}/build || /bin/mkdir -p ${BUILDDIR}/build

[[ -z "${TS_INSTALLDIR}" ]] && OUTDIR="${BUILDDIR}" || OUTDIR="${TS_INSTALLDIR}"

echo ">>> Install DIR: ${OUTDIR}"
export PKG_CONFIG_PATH=${OUTDIR}/lib/pkgconfig

OPENSSL_VERSION="OpenSSL_1_1_0i"
LIBEVENT_VERSION="2.1.8-stable"
ZLIB_VERSION="zlib-1.2.11"

FILE="${BUILDDIR}/downloads/${OPENSSL_VERSION}.zip"
if [ ! -f $FILE ]; then
  echo "Downloading $FILE.."
  cd ${BUILDDIR}/downloads
  curl -OL https://github.com/openssl/openssl/archive/${OPENSSL_VERSION}.zip
fi

cd ${BUILDDIR}/build
unzip ${BUILDDIR}/downloads/${OPENSSL_VERSION}.zip
mv openssl-${OPENSSL_VERSION} openssl-x86_64

cd openssl-x86_64

if [ "${OS}" == "Darwin" ]; then
  ./Configure darwin64-x86_64-cc enable-static-engine enable-ec_nistp_64_gcc_128 enable-weak-ssl-ciphers enable-gost enable-idea enable-md2 enable-rc2 enable-rc5 enable-rfc3779 enable-ssl-trace enable-ssl2 enable-ssl3 enable-ssl3-method enable-zlib no-shared --prefix=${OUTDIR} --openssldir=${OUTDIR}/ssl

else
  cd ${BUILDDIR}/downloads
  curl -OL http://www.zlib.net/${ZLIB_VERSION}.tar.gz

  cd ${BUILDDIR}/build
  tar -zxvf ${BUILDDIR}/downloads/${ZLIB_VERSION}.tar.gz
  mv ${ZLIB_VERSION} zlib-x86_64
  cd zlib-x86_64

  ./configure  --prefix=${OUTDIR} --static -64
  make
  make install

  echo ">>> ZLIB complete"
  cd ${BUILDDIR}/build/openssl-x86_64
  ./config enable-static-engine enable-ec_nistp_64_gcc_128 enable-weak-ssl-ciphers enable-gost enable-idea enable-md2 enable-rc2 enable-rc5 enable-rfc3779 enable-ssl-trace enable-ssl2 enable-ssl3 enable-ssl3-method enable-zlib no-shared --prefix=${OUTDIR} --openssldir=${OUTDIR}/ssl -I${OUTDIR}/include -L${OUTDIR}/lib --with-zlib-lib=${OUTDIR}/lib --with-zlib-include=${OUTDIR}/include
fi

make
make install prefix=${OUTDIR}

FILE="${BUILDDIR}/downloads/libevent-${LIBEVENT_VERSION}.tar.gz"
if [ ! -f $FILE ]; then
  echo "Downloading $FILE.."
  cd ${BUILDDIR}/downloads
  curl -OL https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}/libevent-${LIBEVENT_VERSION}.tar.gz
fi

cd ${BUILDDIR}/build
tar -zxvf ${BUILDDIR}/downloads/libevent-${LIBEVENT_VERSION}.tar.gz
mv libevent-${LIBEVENT_VERSION} libevent-x86_64

cd libevent-x86_64
./autogen.sh

if [ "${OS}" == "Darwin" ]; then
  ./configure --enable-shared=no --enable-static CFLAGS="-I${OUTDIR}/include -arch x86_64" LIBS="-L${OUTDIR}/lib -lssl -L${OUTDIR}/lib -lcrypto -ldl -L${OUTDIR}/lib -lz"
else
  ./configure --enable-shared=no OPENSSL_CFLAGS=-I${OUTDIR}/include OPENSSL_LIBS="-L${OUTDIR}/lib -lssl -L${OUTDIR}/lib -lcrypto"  CFLAGS="-I${OUTDIR}/include" LIBS="-L${OUTDIR}/lib -ldl -lz"
fi

make
make install prefix=${OUTDIR}

FILE="${BUILDDIR}/downloads/master.zip"
if [ ! -f $FILE ]; then
  echo "Downloading $FILE.."
  cd ${BUILDDIR}/downloads
  curl -OL https://github.com/prbinu/tls-scan/archive/master.zip
fi

cd ${BUILDDIR}/build
unzip ${BUILDDIR}/downloads/master.zip
cd tls-scan-master
export TS_DEPDIR=${OUTDIR}
make
export PREFIX=${OUTDIR}
make install
echo '>>> Complete'

