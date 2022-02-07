#include <linux/version.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/icmp.h>
#include <net/udp_tunnel.h>

#include "gtp.h"
#include "far.h"
#include "qer.h"
#include "pktinfo.h"


struct rtable *ip4_find_route(struct sk_buff *skb, struct iphdr *iph,
		struct sock *sk, struct net_device *gtp_dev,
		__be32 saddr, __be32 daddr, struct flowi4 *fl4)
{
	struct rtable *rt;
	__be16 df;
	int mtu;

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

	/* This is similar to tnl_update_pmtu(). */
	df = iph->frag_off;
	if (df) {
		mtu = dst_mtu(&rt->dst);
		mtu -= gtp_dev->hard_header_len;
	       	mtu -= sizeof(struct iphdr);
	       	mtu -= sizeof(struct udphdr);
		// GTPv1
		mtu -= sizeof(struct gtpv1_hdr);
	} else {
		mtu = dst_mtu(&rt->dst);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0) || defined(RHEL8)
	rt->dst.ops->update_pmtu(&rt->dst, NULL, skb, mtu, false);
#else
	rt->dst.ops->update_pmtu(&rt->dst, NULL, skb, mtu);
#endif

	if (!skb_is_gso(skb) && (iph->frag_off & htons(IP_DF)) &&
			mtu < ntohs(iph->tot_len)) {
		memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				htonl(mtu));
		goto err_rt;
	}

	return rt;
err_rt:
	ip_rt_put(rt);
err:
	return ERR_PTR(-ENOENT);
}

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

int ip_xmit(struct sk_buff *skb, struct sock *sk, struct net_device *upf_dev)
{
	struct iphdr *iph = ip_hdr(skb);
	struct flowi4 fl4;
	struct rtable *rt;

	rt = ip4_find_route_simple(skb, sk, upf_dev, 0, iph->daddr, &fl4);
	if (IS_ERR(rt)) {
		return -EBADMSG;
	}

	skb_dst_set(skb, &rt->dst);

	if (ip_local_out(dev_net(upf_dev), sk, skb) < 0) {
		return -1;
	}
	return 0;
}

void upf_xmit_skb_ipv4(struct sk_buff *skb, struct upf_pktinfo *pktinfo)
{
	udp_tunnel_xmit_skb(pktinfo->rt,
			pktinfo->sk,
			skb,
			pktinfo->fl4.saddr,
			pktinfo->fl4.daddr,
			pktinfo->iph->tos,
			ip4_dst_hoplimit(&pktinfo->rt->dst),
			0,
			pktinfo->gtph_port,
			pktinfo->gtph_port,
			true,
			true);
}

void upf_set_pktinfo_ipv4(struct upf_pktinfo *pktinfo,
		struct sock *sk, struct iphdr *iph,
	       	struct outer_header_creation *hdr_creation,
		struct qer *qer, struct rtable *rt, struct flowi4 *fl4,
		struct net_device *dev)
{
	pktinfo->sk = sk;
	pktinfo->iph = iph;
	pktinfo->hdr_creation = hdr_creation;
	pktinfo->qer = qer;
	pktinfo->rt = rt;
	pktinfo->fl4 = *fl4;
	pktinfo->dev = dev;
}

void upf_push_header(struct sk_buff *skb, struct upf_pktinfo *pktinfo)
{
	int payload_len = skb->len;
	struct gtpv1_hdr *gtp1;
	gtpv1_hdr_opt_t *gtp1opt;
	ext_pdu_sess_ctr_t *dl_pdu_sess;
	int ext_flag = 0;

	pktinfo->gtph_port = pktinfo->hdr_creation->port;

	/* Suppport for extension header, sequence number and N-PDU.
	 * Update the length field if any of them is available.
	 */
	if (pktinfo->qer) {
		ext_flag = 1;

		/* Push PDU Session container information */
		dl_pdu_sess = skb_push(skb, sizeof(*dl_pdu_sess));
		/* Multiple of 4 (TODO include PPI) */
		dl_pdu_sess->length = 1;
		dl_pdu_sess->pdu_sess_ctr.type_spare = 0; /* For DL */
		dl_pdu_sess->pdu_sess_ctr.u.dl.ppp_rqi_qfi = pktinfo->qer->qfi;
		//TODO: PPI
		dl_pdu_sess->next_ehdr_type = 0; /* No more extension Header */

		/* Push optional header information */
		gtp1opt = skb_push(skb, sizeof(*gtp1opt));
		gtp1opt->seq_number = 0;
		gtp1opt->NPDU = 0;
		gtp1opt->next_ehdr_type = 0x85; /* PDU Session Container */
		// Increment the GTP-U payload length by size of optional headers length
		payload_len += (sizeof(*gtp1opt) + sizeof(*dl_pdu_sess));
	}

	/* Bits 8  7  6  5  4  3  2  1
	 *    +--+--+--+--+--+--+--+--+
	 *    |version |PT| 0| E| S|PN|
	 *    +--+--+--+--+--+--+--+--+
	 *      0  0  1  1  0  0  0  0
	 */
	gtp1 = skb_push(skb, sizeof(*gtp1));
	gtp1->flags = 0x30; /* v1, GTP-non-prime. */
	if (ext_flag)
		gtp1->flags |= GTPV1_HDR_FLG_EXTHDR; /* v1, Extension header enabled */

	gtp1->type = GTP_TPDU;
	gtp1->tid = pktinfo->hdr_creation->teid;
	gtp1->length = htons(payload_len);       /* Excluded the header length of gtpv1 */
}
