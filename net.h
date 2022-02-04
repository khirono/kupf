#ifndef UPF_NET_H__
#define UPF_NET_H__

#include <linux/rculist.h>

#include <net/net_namespace.h>

struct upf_net {
	struct list_head upf_dev_list;
};

extern struct pernet_operations upf_net_ops;

#define UPF_NET_ID() (*upf_net_ops.id)

#endif
