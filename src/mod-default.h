#ifndef MOD_DEFAULT_H
#define MOD_DEFAULT_H

#include "traceroute.h"

int def_init(size_t data_len, unsigned int n_probes);
int def_send_probe(sockaddr_any *dest, int ttl);
int def_recv_probe(void);
void def_expire_probe(void);

#endif
