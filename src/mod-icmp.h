#ifndef MOD_ICMP_H
#define MOD_ICMP_H

#include "traceroute.h"

void icmp_send_probe(probe * p, int ttl);
void icmp_recv_probe(void);
void icmp_expire_probe(void);

#endif
