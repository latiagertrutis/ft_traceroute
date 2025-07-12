#ifndef MOD_DEFAULT_H
#define MOD_DEFAULT_H

#include "traceroute.h"

int def_setup_probe(probe * p, int ttl);
void def_send_probe(probe * p, int ttl);
void def_recv_probe(void);
void def_expire_probe(void);

#endif
