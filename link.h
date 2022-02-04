#ifndef UPF_LINK_H__
#define UPF_LINK_H__

#include <linux/rculist.h>

#include <net/rtnetlink.h>

enum {
	IFLA_UPF_UNSPEC,
	IFLA_UPF_FD1,
	IFLA_UPF_PDR_HASHSIZE,
	IFLA_UPF_ROLE,
	__IFLA_UPF_MAX,
};
#define IFLA_UPF_MAX (__IFLA_UPF_MAX - 1)

/* role */
enum {
	UPF_ROLE_UPF,
	UPF_ROLE_RAN
};

extern struct rtnl_link_ops upf_link_ops;

extern void upf_link_all_del(struct list_head *);

#endif
