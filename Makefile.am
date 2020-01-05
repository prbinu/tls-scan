# Build the library in the hand subdirectory first.

# Include hand's header when compiling this directory.
#AM_CPPFLAGS = -I$(srcdir)/third-party/zlib/include

# link with the hand library.
#arm_LDADD = hand/libhand.a

bin_PROGRAMS = tls-scan
tls_scan_SOURCES = main.c common.c cert-parser.c gnutls13.c proto-adapters.c

#SUBDIRS = $(subdirs) $(subdirs_extra) openssl-1.0.2-chacha


TS_VERSION = $(shell grep -m 1  Version $(top_srcdir)/CHANGELOG | awk '{print $$2}')
TS_BUILD_DATE = $(shell date '+%Y-%m-%d')
TS_OS = $(shell uname -s)
AM_CPPFLAGS = -I$(top_srcdir)/include -I build-root/include -I build-root/include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -D_GNU_SOURCE -DTS_VERSION=\"$(TS_VERSION)\" -DTS_BUILD_DATE=\"$(TS_BUILD_DATE)\" -DTS_OS=\"$(TS_OS)\"

LDADD =  build-root/lib/libssl.a build-root/lib/libcrypto.a build-root/lib/libevent.a build-root/lib/libevent_openssl.a build-root/lib/libgnutls.a build-root/lib/libhogweed.a build-root/lib/libnettle.a -ldl

if LINUX
LDADD += build-root/lib/libz.a -lrt
endif

if DARWIN
AM_LDFLAGS = -lz -framework Security -framework CoreFoundation
endif
#ifeq ($(TS_OS),Darwin)
#AM_LDFLAGS += -lz -framework Security -framework CoreFoundation
#end


myconfdir = $(sysconfdir)/tls-scan
myconf_DATA = ca-bundle.crt
man1_MANS = man/tls-scan.1
EXTRA_DIST = build-x86-64.sh


