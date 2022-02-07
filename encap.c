#include <linux/version.h>
#include <linux/socket.h>
#include <linux/rculist.h>
#include <linux/gtp.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/un.h>

#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>

#include "dev.h"
#include "encap.h"
#include "gtp.h"
#include "pdr.h"
#include "genl_far.h"
#include "far.h"
#include "qer.h"

static void upf_encap_disable_locked(struct sock *);
static int upf_encap_recv(struct sock *, struct sk_buff *);
static int gtp1u_udp_encap_recv(struct upf_dev *, struct sk_buff *);
static int upf_rx(struct pdr *, struct sk_buff *, unsigned int, unsigned int);
static int upf_fwd_skb_encap(struct sk_buff *, struct net_device *,
		unsigned int, struct pdr *);
static int unix_sock_send(struct pdr *, void *, u32);


struct sock *upf_encap_enable(int fd, int type, struct upf_dev *upf)
{
	struct udp_tunnel_sock_cfg tuncfg = {};
	struct socket *sock;
	struct sock *sk;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return NULL;

	if (sock->sk->sk_protocol != IPPROTO_UDP) {
		sockfd_put(sock);
		return ERR_PTR(-EINVAL);
	}

	lock_sock(sock->sk);
	if (sock->sk->sk_user_data) {
		release_sock(sock->sk);
		sockfd_put(sock);
		return ERR_PTR(-EBUSY);
	}

	sk = sock->sk;
	sock_hold(sk);

	tuncfg.sk_user_data = upf;
	tuncfg.encap_type = type;
	tuncfg.encap_rcv = upf_encap_recv;
	tuncfg.encap_destroy = upf_encap_disable_locked;

	setup_udp_tunnel_sock(sock_net(sock->sk), sock, &tuncfg);

	release_sock(sock->sk);
	sockfd_put(sock);
	return sk;
}

void upf_encap_disable(struct sock *sk)
{
	struct upf_dev *upf;

	if (!sk)
		return;

	lock_sock(sk);
	upf = sk->sk_user_data;
	if (upf) {
		upf->sk1u = NULL;
		udp_sk(sk)->encap_type = 0;
		rcu_assign_sk_user_data(sk, NULL);
		sock_put(sk);
	}
	release_sock(sk);
}

static void upf_encap_disable_locked(struct sock *sk)
{
	rtnl_lock();
	upf_encap_disable(sk);
	rtnl_unlock();
}

static int upf_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct upf_dev *upf;
	int r; 

	upf = rcu_dereference_sk_user_data(sk);
	if (!upf)
		return 1;

	if (udp_sk(sk)->encap_type != UDP_ENCAP_GTP1U) {
		kfree_skb(skb);
		return 0;
	}

	r = gtp1u_udp_encap_recv(upf, skb);
	if (r < 0) {
		// dropped
		kfree_skb(skb);
		return 0;
	}
	return r;
}

static int gtp1u_udp_encap_recv(struct upf_dev *upf, struct sk_buff *skb)
{
	unsigned int hdrlen = sizeof(struct udphdr) + sizeof(struct gtpv1_hdr);
	struct gtpv1_hdr *gtpv1;
	struct pdr *pdr;
	int gtpv1_hdr_len;

	if (!pskb_may_pull(skb, hdrlen)) {
		return -1;
	}

	gtpv1 = (struct gtpv1_hdr *)(skb->data + sizeof(struct udphdr));
	if ((gtpv1->flags >> 5) != GTP_V1) {
		return 1;
	}

	if (gtpv1->type != GTP_TPDU) {
		return 1;
	}

	gtpv1_hdr_len = get_gtpu_header_len(gtpv1, skb);
	if (gtpv1_hdr_len < 0) {
		return -1;
	}

	hdrlen = sizeof(struct udphdr) + gtpv1_hdr_len;
	if (!pskb_may_pull(skb, hdrlen)) {
		return -1;
	}

	pdr = pdr_find_by_gtp1u(upf, skb, hdrlen, gtpv1->tid);
	if (!pdr) {
		return -1;
	}

	return upf_rx(pdr, skb, hdrlen, upf->role);
}

static int upf_rx(struct pdr *pdr, struct sk_buff *skb,
		unsigned int hdrlen, unsigned int role)
{
	struct far *far = pdr->far;

	if (!far)
		return -1;

	if (!pdr->outer_header_removal)
		return -1;

	switch (far->action & FAR_ACTION_MASK) {
	case FAR_ACTION_DROP:
		pdr->ul_drop_cnt++;
		dev_kfree_skb(skb);
		return 0;
	case FAR_ACTION_BUFF:
		if (unix_sock_send(pdr, skb->data, skb_headlen(skb)) < 0)
			pdr->ul_drop_cnt++;
		dev_kfree_skb(skb);
		return 0;
	case FAR_ACTION_FORW:
		return upf_fwd_skb_encap(skb, pdr->dev, hdrlen, pdr);
	default:
		return -1;
	}
}

static int unix_sock_send(struct pdr *pdr, void *buf, u32 len)
{
	struct msghdr msg;
	struct iovec *iov;
	mm_segment_t oldfs;
	int msg_iovlen;
	int total_iov_len = 0;
	int i;
	int rt;
	u64 self_seid_hdr[1] = {pdr->seid};
	u16 self_hdr[2] = {pdr->id, pdr->far->action};

	if (!pdr->sock_for_buf) {
		return -EINVAL;
	}

#define MSG_SEID_IOV_LEN 3
#define MSG_NO_SEID_IOV_LEN 2

	memset(&msg, 0, sizeof(msg));
	if (pdr->seid) {
		msg_iovlen = MSG_SEID_IOV_LEN;
		iov = kmalloc_array(msg_iovlen, sizeof(struct iovec),
				GFP_KERNEL);

		memset(iov, 0, sizeof(struct iovec) * msg_iovlen);
		iov[0].iov_base = self_seid_hdr;
		iov[0].iov_len = sizeof(self_seid_hdr);
		iov[1].iov_base = self_hdr;
		iov[1].iov_len = sizeof(self_hdr);
		iov[2].iov_base = buf;
		iov[2].iov_len = len;
	} else {
		// for backward compatible
		msg_iovlen = MSG_NO_SEID_IOV_LEN;
		iov = kmalloc_array(msg_iovlen, sizeof(struct iovec),
				GFP_KERNEL);

		memset(iov, 0, sizeof(struct iovec) * msg_iovlen);
		iov[0].iov_base = self_hdr;
		iov[0].iov_len = sizeof(self_hdr);
		iov[1].iov_base = buf;
		iov[1].iov_len = len;
	}

	for (i = 0; i < msg_iovlen; i++)
		total_iov_len += iov[i].iov_len;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	iov_iter_init(&msg.msg_iter, WRITE, iov, msg_iovlen, total_iov_len);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = MSG_DONTWAIT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	oldfs = force_uaccess_begin();
#else
	oldfs = get_fs();
	set_fs(KERNEL_DS);
#endif

	rt = sock_sendmsg(pdr->sock_for_buf, &msg);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	force_uaccess_end(oldfs);
#else
	set_fs(oldfs);
#endif
	return rt;
}

static int upf_fwd_skb_encap(struct sk_buff *skb, struct net_device *dev,
		unsigned int hdrlen, struct pdr *pdr)
{
	struct far *far = pdr->far;
	struct forwarding_parameter *fwd_param = far->fwd_param;
	struct outer_header_creation *hdr_creation;
	struct forwarding_policy *fwd_policy;
	struct gtpv1_hdr *gtp1;
	struct iphdr *iph;
	struct udphdr *uh;
	struct pcpu_sw_netstats *stats;

	if (fwd_param) {
		fwd_policy = fwd_param->fwd_policy;
		if (fwd_policy)
			skb->mark = fwd_policy->mark;

		hdr_creation = fwd_param->hdr_creation;
		if (hdr_creation) {
			// Just modify the teid and packet dest ip
			gtp1 = (struct gtpv1_hdr *)(skb->data + sizeof(struct udphdr));
			gtp1->tid = hdr_creation->teid;

			skb_push(skb, 20); // L3 Header Length
			iph = ip_hdr(skb);

			if (!pdr->pdi->f_teid) {
				return -1;
			}

			iph->saddr = pdr->pdi->f_teid->gtpu_addr_ipv4.s_addr;
			iph->daddr = hdr_creation->peer_addr_ipv4.s_addr;
			iph->check = 0;

			uh = udp_hdr(skb);
			uh->check = 0;

			if (ip_xmit(skb, pdr->sk, dev) < 0) {
				return -1;
			}
			return 0;
		}
	}

	// Get rid of the GTP-U + UDP headers.
	if (iptunnel_pull_header(skb,
				hdrlen,
				skb->protocol,
				!net_eq(sock_net(pdr->sk), dev_net(dev)))) {
		return -1;
	}

	/* Now that the UDP and the GTP header have been removed, set up the
	 * new network header. This is required by the upper layer to
	 * calculate the transport header.
	 * */
	skb_reset_network_header(skb);

	skb->dev = dev;

	stats = this_cpu_ptr(skb->dev->tstats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	netif_rx(skb);
	return 0;
}
