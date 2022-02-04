#ifndef FAR_H__
#define FAR_H__

#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/net.h>

#include <net/ip.h>

struct outer_header_creation {
	u16 description;
	u32 teid;
	struct in_addr peer_addr_ipv4;
	u16 port;
};

struct forwarding_policy {
	int len;
	char identifier[0xff + 1];
	/* Exact value to handle forwarding policy */
	u32 mark;
};

struct forwarding_parameter {
	struct outer_header_creation *hdr_creation;
	struct forwarding_policy *fwd_policy;
};

struct far {
	struct hlist_node hlist_id;
	u64 seid;
	u32 id;
	u8 action;
	struct forwarding_parameter *fwd_param;
	struct net_device *dev;
	struct rcu_head rcu_head;
};

extern void far_context_delete(struct far *);

#endif
