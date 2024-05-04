#include "native_recvpacket.h"

static int64_t get_timestamp(struct msghdr *msg, int32_t timestamp_type)
{
	if (timestamp_type >= 0 && timestamp_type < 3)
	{
		for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
		{
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING)
			{
				struct timespec* stamp = (struct timespec *)CMSG_DATA(cmsg);
				// printf("SO_TIMESTAMPING ");
				// printf("SW %ld.%09ld ",             (long)stamp[0].tv_sec, (long)stamp[0].tv_nsec);
				// printf("HW transformed %ld.%09ld ", (long)stamp[1].tv_sec, (long)stamp[1].tv_nsec);
				// printf("HW raw %ld.%09ld",          (long)stamp[2].tv_sec, (long)stamp[2].tv_nsec);
				// printf("\n");
				long u_seconds = (long)stamp[timestamp_type].tv_sec * 1000000 + (long)stamp[timestamp_type].tv_nsec / 1000;
				return u_seconds & 0x7FFFFFFFFFFFFFFF;
			}
		}
	}
	return -1;
}

int recvpacket_v4(int32_t sock, uint8_t* name, uint8_t* data, uint32_t data_len, int64_t* u_seconds, int32_t recvmsg_flags, int32_t timestamp_type)
{
	struct msghdr msg;
	struct iovec entry;
	struct {
		struct cmsghdr cm;
		char control[512];
	} control;
	int res;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = data_len;
	msg.msg_name = name;
	msg.msg_namelen = 32;
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	res = recvmsg(sock, &msg, recvmsg_flags);
	if (res < 0) {
		*u_seconds = 0;
	} else {
		*u_seconds = get_timestamp(&msg, timestamp_type);
	}
	return res;
}

int socket_set_ioctl(int sock, char* ifname, int so_timestamping_flags)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	// Binding is not strictly nessary but is to make sure we only send out the correct interface
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
		return -1;
	}

	struct ethtool_ts_info info;
	info.cmd = ETHTOOL_GET_TS_INFO;
	ifr.ifr_data = (void *)&info;
	if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
		printf("Could not get capabilities for network interface %.*s\n", (int)sizeof(ifr.ifr_name), ifr.ifr_name);
		return -3;
	} else if ((info.so_timestamping & so_timestamping_flags) != so_timestamping_flags) {
		printf("Network interface %.*s does not have required capabilities: %d != %d\n", (int)sizeof(ifr.ifr_name), ifr.ifr_name, info.so_timestamping, so_timestamping_flags);
		return -4;
	}

	struct hwtstamp_config hwconfig, hwconfig_requested;
	ifr.ifr_data = (void *)&hwconfig;
	memset(&hwconfig, 0, sizeof(hwconfig));
	hwconfig.tx_type   = (so_timestamping_flags & SOF_TIMESTAMPING_TX_HARDWARE) ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
	hwconfig.rx_filter = (so_timestamping_flags & SOF_TIMESTAMPING_RX_HARDWARE) ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;

	hwconfig_requested = hwconfig;

	if (ioctl(sock, SIOCSHWTSTAMP, &ifr) < 0)
	{
		if ((errno == EINVAL || errno == ENOTSUP) && hwconfig_requested.tx_type == HWTSTAMP_TX_OFF && hwconfig_requested.rx_filter == HWTSTAMP_FILTER_NONE)
		{
			printf("SIOCSHWTSTAMP: disabling hardware time stamping not possible\n");
		}
		else
		{
			return -2;
		}
	}

	printf("SIOCSHWTSTAMP: tx_type %d requested, got %d; rx_filter %d requested, got %d\n",
		hwconfig_requested.tx_type, hwconfig.tx_type,
		hwconfig_requested.rx_filter, hwconfig.rx_filter
	);

	return 1;
}
