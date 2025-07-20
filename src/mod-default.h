#ifndef MOD_DEFAULT_H
#define MOD_DEFAULT_H

#include "traceroute.h"

int def_init(void);
int def_setup_probe(int ttl);
int def_send_probe(sockaddr_any *dest);
int def_recv_probe(void);
void def_expire_probe(void);

#endif
