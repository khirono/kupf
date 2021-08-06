#include <net/rtnetlink.h>
#include <net/ip.h>
#include <net/udp.h>

#include "dev.h"
#include "link.h"

struct gtp1_header {
	__u8 flags;
	__u8 type;
	__be16 length;
	__be32 tid;
} __attribute__((packed));


static void upf_link_setup(struct net_device *dev)
{
	printk("<%s: %d> start\n", __func__, __LINE__);

	dev->netdev_ops = &upf_netdev_ops;
	dev->needs_free_netdev = true;

	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = ETH_DATA_LEN -
		(sizeof(struct iphdr) +
		 sizeof(struct udphdr) +
		 sizeof(struct gtp1_header));

	/* Zero header length. */
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

	dev->priv_flags |= IFF_NO_QUEUE;
	dev->features |= NETIF_F_LLTX;
	netif_keep_dst(dev);

	/* Assume largest header, ie. GTPv1. */
	dev->needed_headroom = LL_MAX_HEADER +
		sizeof(struct iphdr) +
		sizeof(struct udphdr) +
		sizeof(struct gtp1_header);
}

static int upf_validate(struct nlattr *tb[], struct nlattr *data[],
		struct netlink_ext_ack *extack)
{
	int i;

	printk("<%s: %d> start\n", __func__, __LINE__);
	printk("<%s: %d> tb: %p\n", __func__, __LINE__, tb);
	printk("<%s: %d> data: %p\n", __func__, __LINE__, data);

	if (!data)
		return -EINVAL;

	for (i = 0; tb[i] != NULL; i++) {
		printk("<%s: %d> tb[%d]: type: %u\n", __func__, __LINE__, 0,
				tb[i]->nla_type);
		printk("<%s: %d> tb[%d]: len: %u\n", __func__, __LINE__, 0,
				tb[i]->nla_len);
	}
	for (i = 0; data[i] != NULL; i++) {
		printk("<%s: %d> data[%d]: type: %u\n", __func__, __LINE__, 0,
				data[i]->nla_type);
		printk("<%s: %d> data[%d]: len: %u\n", __func__, __LINE__, 0,
				data[i]->nla_len);
	}

	printk("<%s: %d> end\n", __func__, __LINE__);
	return 0;
}

static int upf_newlink(struct net *net, struct net_device *dev,
		struct nlattr *tb[], struct nlattr *data[],
		struct netlink_ext_ack *extack)
{
	int err;

	printk("<%s: %d> start\n", __func__, __LINE__);

	err = register_netdevice(dev);
	if (err < 0) {
		netdev_dbg(dev, "failed to register new netdev %d\n", err);
		return err;
	}

	return 0;
}

static void upf_dellink(struct net_device *dev, struct list_head *head)
{
	//struct upf_dev *upf = netdev_priv(dev);

	printk("<%s: %d> start\n", __func__, __LINE__);

	//list_del_rcu(&upf->list);
	unregister_netdevice_queue(dev, head);
}

static size_t upf_get_size(const struct net_device *dev)
{
	printk("<%s: %d> start\n", __func__, __LINE__);

	return 0;
}

static int upf_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	printk("<%s: %d> start\n", __func__, __LINE__);

	return 0;
}

static const struct nla_policy upf_policy[] = {
	[IFLA_UPF_FD1]          = { .type = NLA_U32 },
	[IFLA_UPF_PDR_HASHSIZE] = { .type = NLA_U32 },
	[IFLA_UPF_ROLE]         = { .type = NLA_U32 },
};

struct rtnl_link_ops upf_link_ops __read_mostly = {
	.kind      = "gtp5g",
	.maxtype   = IFLA_UPF_MAX,
	.policy    = upf_policy,
	.priv_size = sizeof(struct upf_dev),
	.setup     = upf_link_setup,
	.validate  = upf_validate,
	.newlink   = upf_newlink,
	.dellink   = upf_dellink,
	.get_size  = upf_get_size,
	.fill_info = upf_fill_info,
};