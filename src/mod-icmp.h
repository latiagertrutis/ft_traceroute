#ifndef MOD_ICMP_H
#define MOD_ICMP_H

#include "ip_utils.h"
#include "probe.h"

int icmp_init(sockaddr_any *dest, size_t data_len);
int icmp_send_probe(struct probes *ps, int ttl);
int icmp_recv_probe(struct probes *ps, int timeout, struct probe_range range);
void icmp_clean();

#endif
