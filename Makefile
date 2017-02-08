
ifndef TS_DEPDIR
  $(info ----------------------------------)
  $(warning Env variable TS_DEPDIR [install path of openssl and libevent] is not defined; setting it to '../')
  $(warning Refer: https://github.com/prbinu/tls-scan/blob/master/build-x86-64.sh)
  TS_DEPDIR=..
  $(warning TS_DEPDIR path set to: ${TS_DEPDIR})
  $(info ----------------------------------)

endif

$(info TS_DEPDIR path: ${TS_DEPDIR})

src = $(wildcard *.c)
obj = $(src:.c=.o)

CC = gcc
CFLAGS= -I./include -I ${TS_DEPDIR}/include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -Wl,-rpath,${TS_DEPDIR}/lib -D_GNU_SOURCE

LDFLAGS = -L ${TS_DEPDIR}/lib -L ${TS_DEPDIR}/lib -lssl -L ${TS_DEPDIR}/lib -lcrypto -L ${TS_DEPDIR}/lib -levent -L ${TS_DEPDIR}/lib -levent_openssl -ldl $(libdep_$(shell uname -s))

libdep_Linux = -L ${TS_DEPDIR}/lib -lz -lrt
libdep_Darwin = -lz 

tls-scan: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)


ifndef PREFIX
  PREFIX = ./
endif

.PHONY: install
install: tls-scan
	mkdir -p $(PREFIX)/bin
	cp $< $(PREFIX)/bin/tls-scan
	mkdir -p $(PREFIX)/etc/tls-scan
	cp $< $(PREFIX)/etc/tls-scan/ca-bundle.crt

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/bin/tls-scan
	rm -f $(PREFIX)/etc/tls-scan/ca-bundle.crt

.PHONY: clean
clean:
	rm -f $(obj) tls-scan
