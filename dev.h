#ifndef UPF_DEV_H__
#define UPF_DEV_H__

#include <linux/netdevice.h>
#include <linux/rculist.h>

struct upf_dev {
	struct list_head list;
};

extern const struct net_device_ops upf_netdev_ops;

extern struct upf_dev *upf_find_dev(struct net *, int, int);

#endif
