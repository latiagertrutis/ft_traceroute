#ifndef MOD_DEFAULT_H
#define MOD_DEFAULT_H

#include "ip_utils.h"
#include "probe.h"

int def_init(sockaddr_any *dest, size_t data_len);
int def_send_probe(struct probes * ps, int ttl);
int def_recv_probe(struct probes *ps, int timeout, struct probe_range range);
void def_clean();

#endif
