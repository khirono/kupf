#ifndef PKTINFO_H__
#define PKTINFO_H__

#include <linux/skbuff.h>
#include <linux/net.h>

#include "qer.h"

struct upf_pktinfo {
	struct sock                   *sk;
	struct iphdr                  *iph;
	struct flowi4                 fl4;
	struct rtable                 *rt;
	struct outer_header_creation  *hdr_creation;
	struct qer                    *qer;
	struct net_device             *dev;
	__be16                        gtph_port;
};

struct upf_emark_pktinfo {
	u32 teid;
	u32 peer_addr;
	u32 local_addr;
	u32 role_addr;

	struct sock         *sk;
	struct flowi4       fl4;
	struct rtable       *rt;
	struct net_device   *dev;
	__be16              gtph_port;
};

extern struct rtable *ip4_find_route(struct sk_buff *, struct iphdr *,
		struct sock *, struct net_device *,
		__be32, __be32, struct flowi4 *);
extern void upf_fwd_emark_skb_ipv4(struct sk_buff *,
		struct net_device *, struct upf_emark_pktinfo *);
extern int ip_xmit(struct sk_buff *, struct sock *, struct net_device *);
extern void upf_xmit_skb_ipv4(struct sk_buff *, struct upf_pktinfo *);

extern void upf_set_pktinfo_ipv4(struct upf_pktinfo *,
		struct sock *, struct iphdr *,
	       	struct outer_header_creation *,
		struct qer *, struct rtable *, struct flowi4 *,
		struct net_device *);
extern void upf_push_header(struct sk_buff *, struct upf_pktinfo *);

#endif
