
ifndef TS_DEP_PATH
    $(info Env variable TS_DEP_PATH [root dir for openssl and libevent] is not defined; setting it to '../')
    TS_DEP_PATH=..
endif

$(info ${TS_DEP_PATH} is undefined)

CC = gcc
CFLAGS= -I./include -I ${TS_DEP_PATH}/include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -Wl,-rpath,${TS_DEP_PATH}/lib -D_GNU_SOURCE

tls-scanner: common.o cert-parser.o proto-adapters.o main.o
	$(CC) $(CFLAGS) -o tls-scan common.o cert-parser.o proto-adapters.o main.o -L ${TS_DEP_PATH}/lib -L ${TS_DEP_PATH}/lib -lssl -L ${TS_DEP_PATH}/lib -lcrypto -L ${TS_DEP_PATH}/lib -levent -L ${TS_DEP_PATH}/lib -levent_openssl -ldl

main.o: main.c

proto-adapters.o: proto-adapters.c

certparse.o: cert-parser.c

common.o: common.c

clean:
	rm tls-scan *.o

