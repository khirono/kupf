#include <linux/udp.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/udp_tunnel.h>

#include "gtp.h"
#include "pktinfo.h"


static struct rtable *ip4_find_route_simple(struct sk_buff *skb,
		struct sock *sk, struct net_device *gtp_dev,
		__be32 saddr, __be32 daddr, struct flowi4 *fl4)
{
	struct rtable *rt;

	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = sk->sk_bound_dev_if;
	fl4->daddr = daddr;
	fl4->saddr = (saddr ? saddr : inet_sk(sk)->inet_saddr);
	fl4->flowi4_tos = RT_CONN_FLAGS(sk);
	fl4->flowi4_proto = sk->sk_protocol;

	rt = ip_route_output_key(dev_net(gtp_dev), fl4);
	if (IS_ERR(rt)) {
		gtp_dev->stats.tx_carrier_errors++;
		goto err;
	}

	if (rt->dst.dev == gtp_dev) {
		gtp_dev->stats.collisions++;
		goto err_rt;
	}

	skb_dst_drop(skb);

	return rt;

err_rt:
	ip_rt_put(rt);
err:
	return ERR_PTR(-ENOENT);
}


void upf_fwd_emark_skb_ipv4(struct sk_buff *skb,
		struct net_device *dev, struct upf_emark_pktinfo *epkt_info)
{
	struct rtable *rt;
	struct flowi4 fl4;
	struct gtpv1_hdr *gtp1;

	/* Reset all headers */
	skb_reset_transport_header(skb);
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);

	/* Fill GTP-U Header */
	gtp1 = skb_push(skb, sizeof(*gtp1));
	gtp1->flags = 0x30; /* v1, GTP-non-prime. */
	gtp1->type = GTP_EMARK;
	gtp1->tid = epkt_info->teid;

	rt = ip4_find_route_simple(skb, epkt_info->sk, dev,
			epkt_info->role_addr /* Src Addr */ ,
			epkt_info->peer_addr /* Dst Addr*/,
			&fl4);
	if (IS_ERR(rt)) {
		dev_kfree_skb(skb);
		return;
	}
	udp_tunnel_xmit_skb(rt,
			epkt_info->sk,
			skb,
			fl4.saddr,
			fl4.daddr,
			0,
			ip4_dst_hoplimit(&rt->dst),
			0,
			epkt_info->gtph_port,
			epkt_info->gtph_port,
			true,
			true);
}
