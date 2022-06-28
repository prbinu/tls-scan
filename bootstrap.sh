#!/bin/bash
# Environment variables
#  TS_BUILDROOT : Build root directory. Default to current working directory
#  TS_INSTALLDIR : Installation directory. Default to ${TS_BUILDROOT}
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

[[ -z "${TS_BUILDROOT}" ]] && BUILDDIR="${CD}" || BUILDDIR="${TS_BUILDROOT}"

echo ">>> Build DIR: ${BUILDDIR}"
BUILDDIR=${BUILDDIR}/build-root

# remove build dirs
test -d ${BUILDDIR}/build && rm -rf ${BUILDDIR}/build/*


test -z ${BUILDDIR} || /bin/mkdir -p ${BUILDDIR}
test -z ${BUILDDIR}/downloads || /bin/mkdir -p ${BUILDDIR}/downloads
test -z ${BUILDDIR}/build || /bin/mkdir -p ${BUILDDIR}/build

[[ -z "${TS_INSTALLDIR}" ]] && OUTDIR="${BUILDDIR}" || OUTDIR="${TS_INSTALLDIR}"

echo ">>> Install DIR: ${OUTDIR}"
export PKG_CONFIG_PATH=${OUTDIR}/lib/pkgconfig

OPENSSL_VERSION="1.0.2-chacha"
LIBEVENT_VERSION="2.1.8-stable"
ZLIB_VERSION="zlib-1.2.12"

FILE="${BUILDDIR}/downloads/${OPENSSL_VERSION}.zip"
if [ ! -f $FILE ]; then
  echo "Downloading $FILE.."
  cd ${BUILDDIR}/downloads
  curl -OL https://github.com/PeterMosmans/openssl/archive/${OPENSSL_VERSION}.zip
fi

cd ${BUILDDIR}/build
unzip ${BUILDDIR}/downloads/${OPENSSL_VERSION}.zip
mv openssl-${OPENSSL_VERSION} openssl-x86_64

cd openssl-x86_64

if [ "${OS}" == "Darwin" ]; then
  ./Configure darwin64-x86_64-cc enable-static-engine enable-ec_nistp_64_gcc_128 enable-gost enable-idea enable-md2 enable-rc2 enable-rc5 enable-rfc3779 enable-ssl-trace enable-ssl2 enable-ssl3 enable-zlib experimental-jpake --prefix=${OUTDIR} --openssldir=${OUTDIR}/ssl
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
  ./config enable-static-engine enable-ec_nistp_64_gcc_128 enable-gost enable-idea enable-md2 enable-rc2 enable-rc5 enable-rfc3779 enable-ssl-trace enable-ssl2 enable-ssl3 enable-zlib experimental-jpake --prefix=${OUTDIR} --openssldir=${OUTDIR}/ssl -I${OUTDIR}/include -L${OUTDIR}/lib --with-zlib-lib=${OUTDIR}/lib --with-zlib-include=${OUTDIR}/include
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

echo "Downloading nettle_3.5.1."
cd ${BUILDDIR}/downloads
curl -OL https://ftp.gnu.org/gnu/nettle/nettle-3.5.1.tar.gz

cd ${BUILDDIR}/build
tar -zxvf ${BUILDDIR}/downloads/nettle-3.5.1.tar.gz
cd nettle-3.5.1

./.bootstrap
./configure --enable-static --enable-mini-gmp --disable-openssl --disable-shared --disable-documentation LDFLAGS="-L${OUTDIR}/lib"
make && make install prefix=${OUTDIR}

echo "Downloading gnutls_3.6.10."
cd ${BUILDDIR}/downloads
curl -OL https://www.gnupg.org/ftp/gcrypt/gnutls/v3.6/gnutls-3.6.10.tar.xz

cd ${BUILDDIR}/build
tar -xvf ${BUILDDIR}/downloads/gnutls-3.6.10.tar.xz
cd gnutls-3.6.10

if [ "${OS}" == "Darwin" ]; then
  ./configure --enable-static --disable-openssl-compatibility --disable-libdane --without-p11-kit --without-tpm  --without-idn --disable-tests --disable-doc --disable-full-test-suite  --disable-libdane --disable-nls --enable-shared=no --with-included-libtasn1 --with-included-unistring --with-nettle-mini --enable-guile=no --prefix=$OUTDIR PKG_CONFIG_PATH=${OUTDIR}/lib/pkgconfig LDFLAGS="-L${OUTDIR}/lib" NETTLE_CFLAGS="-I${OUTDIR}/include -arch x86_64" NETTLE_LIBS="-L${OUTDIR}/lib -lnettle" HOGWEED_CFLAGS="-I${OUTDIR}/include -arch x86_64 "  HOGWEED_LIBS="-L${OUTDIR}/lib -lhogweed"
else
  ./configure --enable-static --disable-openssl-compatibility --disable-libdane --without-p11-kit --without-tpm  --without-idn --disable-tests --disable-doc --disable-full-test-suite  --disable-libdane --disable-nls --enable-shared=no --with-included-libtasn1 --with-included-unistring --with-nettle-mini --enable-guile=no --prefix=$OUTDIR LDFLAGS="-L${OUTDIR}/lib" NETTLE_CFLAGS="-I${OUTDIR}/include" NETTLE_LIBS="-L${OUTDIR}/lib -lnettle" HOGWEED_CFLAGS="-I${OUTDIR}/include"  HOGWEED_LIBS="-L${OUTDIR}/lib -lhogweed" LIBS="${OUTDIR}/lib/libhogweed.a ${OUTDIR}/lib/libnettle.a"
fi

make && make install prefix=${OUTDIR}

echo ">>> Running autoreconf -i"
cd ${CD}
autoreconf -i

echo ">>> Bootstrap complete"
