#ifndef MOD_DEFAULT_H
#define MOD_DEFAULT_H

#include "traceroute.h"

int def_init(sockaddr_any *dest, size_t data_len, unsigned int n_probes);
int def_send_probe(int ttl);
int def_recv_probe(int timeout, unsigned int n_probes);
void def_expire_probe(void);

#endif
