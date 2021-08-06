#include <linux/netdevice.h>

#include "dev.h"
#include "genl.h"


struct upf_dev *upf_find_dev(struct net *src_net, int ifindex, int netnsfd)
{
	struct upf_dev *upf;
	struct net_device *dev;
	struct net *net;

	if (netnsfd == -1)
		net = get_net(src_net);
	else
		net = get_net_ns_by_fd(netnsfd);

	if (IS_ERR(net))
		return NULL;

	dev = dev_get_by_index_rcu(net, ifindex);
	if (dev && dev->netdev_ops == &upf_netdev_ops)
		upf = netdev_priv(dev);
	else
		upf = NULL;

	put_net(net);

	return upf;
}


static int upf_dev_init(struct net_device *dev)
{
	printk("<%s: %d> start\n", __func__, __LINE__);

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void upf_dev_uninit(struct net_device *dev)
{
	printk("<%s: %d> start\n", __func__, __LINE__);

	free_percpu(dev->tstats);
}

static netdev_tx_t upf_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	printk("<%s: %d> start\n", __func__, __LINE__);

	skb_dump("packet:", skb, 1);

	notify(3);

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static void upf_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *s)
{
	int cpu;

	printk("<%s: %d> start\n", __func__, __LINE__);

	netdev_stats_to_stats64(s, &dev->stats);

	for_each_possible_cpu(cpu) {
		const struct pcpu_sw_netstats *stats;
		struct pcpu_sw_netstats tmp;
		unsigned int start;

		stats = per_cpu_ptr(dev->tstats, cpu);
		do {
			start = u64_stats_fetch_begin_irq(&stats->syncp);
			tmp.rx_packets = stats->rx_packets;
			tmp.rx_bytes   = stats->rx_bytes;
			tmp.tx_packets = stats->tx_packets;
			tmp.tx_bytes   = stats->tx_bytes;
		} while (u64_stats_fetch_retry_irq(&stats->syncp, start));

		s->rx_packets += tmp.rx_packets;
		s->rx_bytes   += tmp.rx_bytes;
		s->tx_packets += tmp.tx_packets;
		s->tx_bytes   += tmp.tx_bytes;
	}
}

const struct net_device_ops upf_netdev_ops = {
	.ndo_init        = upf_dev_init,
	.ndo_uninit      = upf_dev_uninit,
	.ndo_start_xmit  = upf_dev_xmit,
	.ndo_get_stats64 = upf_get_stats64,
};
