#include <stdlib.h>

#include "probe.h"

/* If final probe is read matk probes as done, oterwise, return last pos. Pos can be greater than range.max since the last probe in the range can validate its hop which can contain more probes. If that is the case the next iteration should start from the next hop. */
int select_probes(int fd, struct probes *ps, int timeout, struct probe_range range,
                  int (*rcv_and_check_msg)(int, struct probes *, struct probe_range))
{
    int nfds, ready, ret;
    fd_set readfds;
    struct timeval tim;
    unsigned int pos;

    nfds = fd + 1;
    pos = range.min;
    while (pos < range.max) {
        /* This values are modified in select() so must be re-initialized in each call */
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);

        tim.tv_sec = timeout;
        tim.tv_usec = 0;

        ready = select(nfds, &readfds, NULL, NULL, &tim);
        if (ready < 0) {
            return -1;
        }

        if (ready == 0) {
            /* timeout */
            /* If timeout occured,  probes in this range will not have a recv_time, meaning they are expired. Return the max position reached. If this position is less than the max we know there are some timeouts */
            return pos;
        }

        /* only one fd set */
        ret = rcv_and_check_msg(fd, ps, range);
        if (ret < 0) {
            return -1;
        }

        pos += ret;

        if (ps->done) {
            return pos;
        }
    }

    return pos;
}
