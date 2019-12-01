#ifndef PROTO_ts_adapterS_H
#define PROTO_ts_adapterS_H

// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

#include <common.h>

/* returns protocol name if found, else return NULL */
const char *ts_protocol_name(int adapter_index);
/*
 * returns ts_adapter table index for supported protocols
 * returns -1 if the proto_name is NOT found in the ts_adapters table
 */
int ts_adapter_index(const char *proto_name);

void ts_adapter_create(client_t *cli);

void ts_adapter_init(client_t *cli);


void ts_adapter_connect(client_t *cli);

void ts_adapter_read(client_t *cli, unsigned char *read_buf, size_t nread);

void ts_adapter_write(client_t *cli);

void ts_adapter_reset(client_t *cli);

void ts_adapter_destroy(client_t *cli);

#endif // PROTO_ts_adapterS_H
