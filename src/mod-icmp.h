#ifndef MOD_ICMP_H
#define MOD_ICMP_H

#include "traceroute.h"

int icmp_send_probe(sockaddr_any *dest);
int icmp_recv_probe(void);
void icmp_expire_probe(void);

#endif
