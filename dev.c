#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/net.h>
#include <linux/socket.h>

#include "dev.h"
#include "genl.h"
#include "encap.h"
#include "pdr.h"
#include "far.h"
#include "qer.h"
#include "bar.h"
#include "urr.h"
#include "genl_far.h"
#include "pktinfo.h"


struct upf_dev *find_upf_dev(struct net *src_net, int ifindex, int netnsfd)
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

int upf_dev_hashtable_new(struct upf_dev *upf, int hsize)
{
	int i;

	upf->addr_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->addr_hash)
		goto err;

	upf->i_teid_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->i_teid_hash)
		goto err;

	upf->pdr_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->pdr_id_hash)
		goto err;

	upf->far_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->far_id_hash)
		goto err;

	upf->qer_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->qer_id_hash)
		goto err;

	upf->bar_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->bar_id_hash)
		goto err;

	upf->urr_id_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->urr_id_hash)
		goto err;

	upf->related_far_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->related_far_hash)
		goto err;

	upf->related_qer_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->related_qer_hash)
		goto err;

	upf->related_bar_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->related_bar_hash)
		goto err;

	upf->related_urr_hash = kmalloc_array(hsize, sizeof(struct hlist_head),
			GFP_KERNEL);
	if (!upf->related_urr_hash)
		goto err;

	upf->hash_size = hsize;

	for (i = 0; i < hsize; i++) {
		INIT_HLIST_HEAD(&upf->addr_hash[i]);
		INIT_HLIST_HEAD(&upf->i_teid_hash[i]);
		INIT_HLIST_HEAD(&upf->pdr_id_hash[i]);
		INIT_HLIST_HEAD(&upf->far_id_hash[i]);
		INIT_HLIST_HEAD(&upf->qer_id_hash[i]);
		INIT_HLIST_HEAD(&upf->bar_id_hash[i]);
		INIT_HLIST_HEAD(&upf->urr_id_hash[i]);
		INIT_HLIST_HEAD(&upf->related_far_hash[i]);
		INIT_HLIST_HEAD(&upf->related_qer_hash[i]);
		INIT_HLIST_HEAD(&upf->related_bar_hash[i]);
		INIT_HLIST_HEAD(&upf->related_urr_hash[i]);
	}

	return 0;
err:
	upf_dev_hashtable_free(upf);
	return -ENOMEM;
}

void upf_dev_hashtable_free(struct upf_dev *upf)
{
	struct pdr *pdr;
	struct far *far;
	struct qer *qer;
	struct bar *bar;
	struct urr *urr;
	int i;

	for (i = 0; i < upf->hash_size; i++) {
		hlist_for_each_entry_rcu(qer, &upf->qer_id_hash[i], hlist_id)
			qer_context_delete(qer);
		hlist_for_each_entry_rcu(far, &upf->far_id_hash[i], hlist_id)
			far_context_delete(far);
		hlist_for_each_entry_rcu(pdr, &upf->pdr_id_hash[i], hlist_id)
			pdr_context_delete(pdr);
		hlist_for_each_entry_rcu(bar, &upf->bar_id_hash[i], hlist_id)
			bar_context_delete(bar);
		hlist_for_each_entry_rcu(urr, &upf->urr_id_hash[i], hlist_id)
			urr_context_delete(urr);
	}

	synchronize_rcu();

	kfree(upf->addr_hash);
	kfree(upf->i_teid_hash);
	kfree(upf->pdr_id_hash);
	kfree(upf->far_id_hash);
	kfree(upf->qer_id_hash);
	kfree(upf->bar_id_hash);
	kfree(upf->urr_id_hash);
	kfree(upf->related_far_hash);
	kfree(upf->related_qer_hash);
	kfree(upf->related_bar_hash);
	kfree(upf->related_urr_hash);
}

static int upf_dev_init(struct net_device *dev)
{
	struct upf_dev *upf = netdev_priv(dev);

	printk("<%s: %d> start\n", __func__, __LINE__);

	upf->dev = dev;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void upf_dev_uninit(struct net_device *dev)
{
	struct upf_dev *upf = netdev_priv(dev);

	printk("<%s: %d> start\n", __func__, __LINE__);

	upf_encap_disable(upf->sk1u);
	free_percpu(dev->tstats);
}

static netdev_tx_t upf_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	unsigned int proto = ntohs(skb->protocol);
	struct upf_pktinfo pktinfo;
	int ret;

	printk("<%s: %d> start\n", __func__, __LINE__);

	/* Ensure there is sufficient headroom */
	if (skb_cow_head(skb, dev->needed_headroom)) {
		goto tx_err;
	}

	skb_reset_inner_headers(skb);

	/* PDR lookups in gtp5g_build_skb_*() need rcu read-side lock.
	 * */
	rcu_read_lock();
	switch (proto) {
	case ETH_P_IP:
		ret = upf_handle_skb_ipv4(skb, dev, &pktinfo);
		break;
	default:
		ret = -EOPNOTSUPP;
	}
	rcu_read_unlock();

	if (ret < 0)
		goto tx_err;

	if (ret == FAR_ACTION_FORW)
		upf_xmit_skb_ipv4(skb, &pktinfo);

	return NETDEV_TX_OK;
tx_err:
	dev->stats.tx_errors++;
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
