#ifndef UPF_DEV_H__
#define UPF_DEV_H__

#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/rculist.h>

struct upf_dev {
	struct list_head list;
	struct sock *sk1u;
	struct net_device *dev;
	unsigned int role;
	unsigned int hash_size;
	struct hlist_head *pdr_id_hash;
	struct hlist_head *far_id_hash;
	struct hlist_head *qer_id_hash;
	struct hlist_head *bar_id_hash;
	struct hlist_head *urr_id_hash;
	struct hlist_head *i_teid_hash;
	struct hlist_head *addr_hash;
	struct hlist_head *related_far_hash;
	struct hlist_head *related_qer_hash;
	struct hlist_head *related_bar_hash;
	struct hlist_head *related_urr_hash;
};

extern const struct net_device_ops upf_netdev_ops;

extern struct upf_dev *find_upf_dev(struct net *, int, int);

extern int upf_dev_hashtable_new(struct upf_dev *, int);
extern void upf_dev_hashtable_free(struct upf_dev *);

#endif
