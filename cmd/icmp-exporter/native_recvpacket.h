#ifndef PING_NATIVE_RECVPACKET_H
#define PING_NATIVE_RECVPACKET_H

#include <string.h>
#include <arpa/inet.h>
// #include <netinet/in.h>

#include <stdio.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "linux/net_tstamp.h"
#include <linux/ethtool.h>
#include <linux/sockios.h>

#ifndef SO_TIMESTAMPING
    # define SO_TIMESTAMPING         37
    # define SCM_TIMESTAMPING        SO_TIMESTAMPING
#endif

#ifndef SO_TIMESTAMPNS
    # define SO_TIMESTAMPNS 35
#endif

#ifndef SIOCGSTAMPNS
    # define SIOCGSTAMPNS 0x8907
#endif

#ifndef SIOCSHWTSTAMP
    # define SIOCSHWTSTAMP 0x89b0
#endif


int recvpacket_v4(int32_t sock, uint8_t* name, uint8_t* data, uint32_t data_len, int64_t* u_seconds, int32_t recvmsg_flags, int32_t timestamp_type);
int socket_set_ioctl(int sock, char* ifname, int so_timestamping_flags);

#endif /* PING_NATIVE_RECVPACKET_H */
