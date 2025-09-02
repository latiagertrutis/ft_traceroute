#ifndef MOD_INTERNAL_H
#define MOD_INTERNAL_H

#include "probe.h"

int select_probes(int fd, struct probes *ps, int timeout, struct probe_range range,
                  int (*rcv_and_check_msg)(struct probes *, struct probe_range));

#endif
