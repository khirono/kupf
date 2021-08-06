#ifndef UPF_LINK_H__
#define UPF_LINK_H__

#include <net/rtnetlink.h>

enum {
	IFLA_UPF_UNSPEC,
	IFLA_UPF_FD1,
	IFLA_UPF_PDR_HASHSIZE,
	IFLA_UPF_ROLE,
	__IFLA_UPF_MAX,
};
#define IFLA_UPF_MAX (__IFLA_UPF_MAX - 1)

extern struct rtnl_link_ops upf_link_ops;

#endif
