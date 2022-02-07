#ifndef ENCAP_H__
#define ENCAP_H__

#include <linux/socket.h>

#include "dev.h"
#include "pktinfo.h"

extern struct sock *upf_encap_enable(int, int, struct upf_dev *);
extern void upf_encap_disable(struct sock *);
extern int upf_handle_skb_ipv4(struct sk_buff *, struct net_device *,
		struct upf_pktinfo *);

#endif
