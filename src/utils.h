#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdbool.h>

#include "traceroute.h"

void print_message_with_metadata(const uint8_t *buffer, ssize_t length,
                                 const struct sockaddr_in *sender_addr);
void print_raw_packet_metadata(const unsigned char *buffer, ssize_t length);
bool check_ip_packet(uint8_t *buf, size_t len, sockaddr_any *dest);

#endif
