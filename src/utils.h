#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdbool.h>

void print_message_with_metadata(const uint8_t *buffer, ssize_t length,
                                 const struct sockaddr_in *sender_addr);
void print_raw_packet_metadata(const unsigned char *buffer, ssize_t length);
double diff_timeval(struct timeval start, struct timeval finish);

#endif
