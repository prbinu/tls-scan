// Copyright (c) 2016, Yahoo Inc.
// Copyrights licensed under the New BSD License. See the
// accompanying LICENSE.txt file for terms.

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <common.h>

input_handle_t in_handle;

void init_stats(stats_t *st)
{
  memset(st, 0, sizeof(stats_t));
  gettimeofday(&st->start_time, NULL);
}

ssize_t ts_get_line_input(input_handle_t *handle, char *line, size_t len)
{
  ssize_t read = 0;
  line[0] = 0;

  if ((handle->eof) || (handle->fp == NULL)) {
    return -1;
  }

  if (strlen(handle->host)) {
    strncpy(line, handle->host, len);
    line[len - 1] = '\0';

    handle->eof = true;
    return len; // TODO len?
  }

  while ((read = getline(&line, &len, handle->fp)) != -1) {
    // zero-terminate only new lines
    if (line[read - 1] == '\n') {
      line[read - 1] = 0;
    }

    // skip empty lines
    if (read > 0)
      break;
  }

  if ((read < 1) || (len == 0)) {
    handle->eof = true;
    fclose(handle->fp);
    handle->fp = NULL;
    return -1;
  }

  return read;
}

uint64_t ts_elapsed_time(struct timeval t1)
{
  struct timeval t2;
  gettimeofday(&t2, NULL);
  return ((t2.tv_sec - t1.tv_sec) * 1000000) + (t2.tv_usec - t1.tv_usec);
}

void ts_get_ip(int fd, char *ipstr, size_t ipstr_len)
{
  ipstr[0] = 0;
  socklen_t len;
  struct sockaddr_storage addr;
  len = sizeof(addr);

  getpeername(fd, (struct sockaddr *) &addr, &len);

  if (addr.ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *) &addr;
    inet_ntop(AF_INET, &s->sin_addr, ipstr, ipstr_len);
  } else {                    // AF_INET6
    struct sockaddr_in6 *s = (struct sockaddr_in6 *) &addr;
    inet_ntop(AF_INET6, &s->sin6_addr, ipstr, ipstr_len);
  }

}

ts_address_family_t ts_address_family(const char *target)
{
  if (target[0] == '[') {
    return TS_IPV6;
  }

  size_t len = strlen(target);
  if (len == strspn(target, "0123456789.:")) {
    return TS_IPV4;
  }

  return TS_HOSTNAME;
}

void ts_parse_connect_target(const char *target, char *host, size_t hlen, uint16_t *port)
{
  size_t len = strlen(target);
  // addr should be atleast 4 chars
  if (len < 5) {
    return;
  }

  ts_address_family_t addr = ts_address_family(target);
  switch (addr) {
    case TS_HOSTNAME:
    case TS_IPV4:
      for (int i=len-1; i>=0; i--) {
        if ((target[i] == ':') && (i+1 < len)) {
          *port = strtol(target + i + 1, NULL, 10);
          snprintf(host, hlen, "%.*s", i, target);
          return;
        }
      }

      snprintf(host, OPT_STRLEN, "%s", target);
      break;

    case TS_IPV6:
      for (int i=len-1; i>=0; i--) {
        if ((target[i] == ']') && (target[i+1] == ':') && (i+1 < len)) {
          *port = strtol(target + i + 2, NULL, 10);
          snprintf(host, hlen, "%.*s", i-1, target+1);
          return;
        }
      }

      snprintf(host, OPT_STRLEN, "%.*s", (int)len-2, target+1);
      break;
    default: break;
  }

  return;
}
