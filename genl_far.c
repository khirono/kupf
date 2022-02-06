#include <linux/module.h>
#include <net/genetlink.h>

#include "dev.h"
#include "genl.h"
#include "genl_far.h"
#include "far.h"
#include "pktinfo.h"


static int header_creation_fill(struct forwarding_parameter *,
	       	struct nlattr **, u8 *,
	       	struct upf_emark_pktinfo *);
static int forwarding_parameter_fill(struct forwarding_parameter *,
	       	struct nlattr **, u8 *,
	       	struct upf_emark_pktinfo *);
static int far_fill(struct far *, struct upf_dev *, struct genl_info *,
		u8 *, struct upf_emark_pktinfo *);


int upf_genl_add_far(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct far *far;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 far_id;
	int err;
	u8 flag;
	struct upf_emark_pktinfo epkt_info;

	printk("<%s:%d> start\n", __func__, __LINE__);

	if (!info->attrs[UPF_ATTR_LINK])
		return -EINVAL;
	ifindex = nla_get_u32(info->attrs[UPF_ATTR_LINK]);
	printk("ifindex: %d\n", ifindex);

	if (info->attrs[UPF_ATTR_NET_NS_FD])
		netnsfd = nla_get_u32(info->attrs[UPF_ATTR_NET_NS_FD]);
	else
		netnsfd = -1;
	printk("netnsfd: %d\n", netnsfd);

	rtnl_lock();
	rcu_read_lock();

	upf = find_upf_dev(sock_net(skb->sk), ifindex, netnsfd);
	if (!upf) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENODEV;
	}

	if (info->attrs[UPF_ATTR_FAR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_FAR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_FAR_ID]) {
		far_id = nla_get_u32(info->attrs[UPF_ATTR_FAR_ID]);
		printk("FAR ID: %u\n", far_id);
	} else {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENODEV;
	}

	far = find_far_by_id(upf, seid, far_id);
	if (far) {
		if (info->nlhdr->nlmsg_flags & NLM_F_EXCL) {
			rcu_read_unlock();
			rtnl_unlock();
			return -EEXIST;
		}
		if (!(info->nlhdr->nlmsg_flags & NLM_F_REPLACE)) {
			rcu_read_unlock();
			rtnl_unlock();
			return -EOPNOTSUPP;
		}

		flag = 0;
		err = far_fill(far, upf, info, &flag, &epkt_info);
		if (err) {
			far_context_delete(far);
			rcu_read_unlock();
			rtnl_unlock();
			return err;
		}

		// Send GTP-U End marker to gNB
		if (flag) {
			/* SKB size GTPU(8) + UDP(8) + IP(20) + Eth(14)
			 * + 2-Bytes align the IP header
			 * */
			struct sk_buff *skb = __netdev_alloc_skb(upf->dev, 52, GFP_KERNEL);
			if (!skb) {
				rcu_read_unlock();
				rtnl_unlock();
				return 0;
			}
			skb_reserve(skb, 2);
			skb->protocol = eth_type_trans(skb, upf->dev);
			upf_fwd_emark_skb_ipv4(skb, upf->dev, &epkt_info);
		}
		rcu_read_unlock();
		rtnl_unlock();
		return 0;
	}

	if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENOENT;
	}

	if (info->nlhdr->nlmsg_flags & NLM_F_APPEND) {
		rcu_read_unlock();
		rtnl_unlock();
		return -EOPNOTSUPP;
	}

	// Check only at the creation part
	if (!info->attrs[UPF_ATTR_FAR_APPLY_ACTION]) {
		rcu_read_unlock();
		rtnl_unlock();
		return -EINVAL;
	}

	far = kzalloc(sizeof(*far), GFP_ATOMIC);
	if (!far) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENOMEM;
	}
	far->dev = upf->dev;

	err = far_fill(far, upf, info, NULL, NULL);
	if (err) {
		far_context_delete(far);
		rcu_read_unlock();
		rtnl_unlock();
		return err;
	}

	far_append(seid, far_id, far, upf);
 
	rcu_read_unlock();
	rtnl_unlock();
	return 0;
}

int upf_genl_del_far(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct far *far;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 far_id;

	printk("<%s:%d> start\n", __func__, __LINE__);

	if (!info->attrs[UPF_ATTR_LINK])
		return -EINVAL;
	ifindex = nla_get_u32(info->attrs[UPF_ATTR_LINK]);
	printk("ifindex: %d\n", ifindex);

	if (info->attrs[UPF_ATTR_NET_NS_FD])
		netnsfd = nla_get_u32(info->attrs[UPF_ATTR_NET_NS_FD]);
	else
		netnsfd = -1;
	printk("netnsfd: %d\n", netnsfd);

	rcu_read_lock();

	upf = find_upf_dev(sock_net(skb->sk), ifindex, netnsfd);
	if (!upf) {
		rcu_read_unlock();
		return -ENODEV;
	}

	if (info->attrs[UPF_ATTR_FAR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_FAR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_FAR_ID]) {
		far_id = nla_get_u32(info->attrs[UPF_ATTR_FAR_ID]);
		printk("FAR ID: %u\n", far_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	far = find_far_by_id(upf, seid, far_id);
	if (!far) {
		rcu_read_unlock();
		return -ENOENT;
	}

	far_context_delete(far);
	rcu_read_unlock();

	return 0;
}

int upf_genl_get_far(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

int upf_genl_dump_far(struct sk_buff *skb, struct netlink_callback *cb)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

static int header_creation_fill(struct forwarding_parameter *param,
	       	struct nlattr **attrs, u8 *flag,
	       	struct upf_emark_pktinfo *epkt_info)
{
	struct outer_header_creation *hdr_creation;

	if (!attrs[UPF_ATTR_OUTER_HEADER_CREATION_DESCRIPTION] ||
			!attrs[UPF_ATTR_OUTER_HEADER_CREATION_O_TEID] ||
			!attrs[UPF_ATTR_OUTER_HEADER_CREATION_PEER_ADDR_IPV4] ||
			!attrs[UPF_ATTR_OUTER_HEADER_CREATION_PORT]) {
		return -EINVAL;
	}

	if (!param->hdr_creation) {
		param->hdr_creation = kzalloc(sizeof(*param->hdr_creation),
				GFP_ATOMIC);
		if (!param->hdr_creation)
			return -ENOMEM;
		hdr_creation = param->hdr_creation;
		hdr_creation->description = nla_get_u16(attrs[UPF_ATTR_OUTER_HEADER_CREATION_DESCRIPTION]);
		hdr_creation->teid = htonl(nla_get_u32(attrs[UPF_ATTR_OUTER_HEADER_CREATION_O_TEID]));
		hdr_creation->peer_addr_ipv4.s_addr = nla_get_be32(attrs[UPF_ATTR_OUTER_HEADER_CREATION_PEER_ADDR_IPV4]);
		hdr_creation->port = htons(nla_get_u16(attrs[UPF_ATTR_OUTER_HEADER_CREATION_PORT]));
	} else {
		u32 old_teid, old_peer_addr;
		u16 old_port;

		hdr_creation = param->hdr_creation;
		old_teid = hdr_creation->teid;
		old_peer_addr = hdr_creation->peer_addr_ipv4.s_addr;
		old_port = hdr_creation->port;
		hdr_creation->description = nla_get_u16(attrs[UPF_ATTR_OUTER_HEADER_CREATION_DESCRIPTION]);
		hdr_creation->teid = htonl(nla_get_u32(attrs[UPF_ATTR_OUTER_HEADER_CREATION_O_TEID]));
		hdr_creation->peer_addr_ipv4.s_addr = nla_get_be32(attrs[UPF_ATTR_OUTER_HEADER_CREATION_PEER_ADDR_IPV4]);
		hdr_creation->port = htons(nla_get_u16(attrs[UPF_ATTR_OUTER_HEADER_CREATION_PORT]));
		/* For Downlink traffic from UPF to gNB
		 * In some cases,
		 *  1) SMF will send PFCP Msg filled with FAR's TEID and gNB N3 addr as 0
		 *  2) Later time, SMF will send PFCP Msg filled with right value in 1)

		 *      2.a) We should send the GTP-U EndMarker to gNB
		 *      2.b) SHOULD not set the flag as 1
		 *  3) Xn Handover in b/w gNB then
		 *      3.a) SMF will send modification of PDR, FAR(TEID and GTP-U)
		 *      3.b) SHOULD set the flag as 1 and send GTP-U Marker for old gNB

		 * */
		/* R15.3 29.281
		 * 5.1 General format
		 * When setting up a GTP-U tunnel, the GTP-U entity shall not assign th
		 e value 'all zeros' to its own TEID.
		 * However, for backward compatibility, if a GTP-U entity receives (via
		 respective control plane message) a peer's
		 * TEID that is set to the value 'all zeros', the GTP-U entity shall ac
		 cept this value as valid and send the subsequent
		 * G-PDU with the TEID field in the header set to the value 'all zeros'
		 .
		 * */
		if ((flag != NULL && epkt_info != NULL)) {
			if (((old_peer_addr & hdr_creation->peer_addr_ipv4.s_addr) != 0) &&

					((old_teid != hdr_creation->teid ) ||
					 (old_peer_addr != hdr_creation->peer_addr_ipv4.s_addr))) {
				*flag = 1;
				epkt_info->teid = old_teid;
				epkt_info->peer_addr = old_peer_addr;
				epkt_info->gtph_port = old_port;
			}
		}
	}

	return 0;
}

static int forwarding_parameter_fill(struct forwarding_parameter *param,
	       	struct nlattr **attrs, u8 *flag,
	       	struct upf_emark_pktinfo *epkt_info)
{
	struct nlattr *hdr_creation_attrs[UPF_ATTR_OUTER_HEADER_CREATION_MAX + 1];
	struct forwarding_policy *fwd_policy;
	int err;

	if (attrs[UPF_ATTR_FORWARDING_PARAMETER_OUTER_HEADER_CREATION]) {
		err = nla_parse_nested(hdr_creation_attrs,
				UPF_ATTR_OUTER_HEADER_CREATION_MAX,
				attrs[UPF_ATTR_FORWARDING_PARAMETER_OUTER_HEADER_CREATION],
				NULL,
				NULL);
		if (err)
			return err;
		err = header_creation_fill(param, hdr_creation_attrs, flag, epkt_info);
		if (err)
			return err;
	}

	if (attrs[UPF_ATTR_FORWARDING_PARAMETER_FORWARDING_POLICY]) {
		if (!param->fwd_policy) {
			param->fwd_policy = kzalloc(sizeof(*param->fwd_policy), GFP_ATOMIC);
			if (!param->fwd_policy)
				return -ENOMEM;
		}
		fwd_policy = param->fwd_policy;
		fwd_policy->len = nla_len(attrs[UPF_ATTR_FORWARDING_PARAMETER_FORWARDING_POLICY]);
		if (fwd_policy->len >= sizeof(fwd_policy->identifier))
			return -EINVAL;
		strncpy(fwd_policy->identifier,
				nla_data(attrs[UPF_ATTR_FORWARDING_PARAMETER_FORWARDING_POLICY]), fwd_policy->len);

		/* Exact value to handle forwarding policy */
		if (!(fwd_policy->mark = simple_strtol(fwd_policy->identifier, NULL, 10))) {
			return -EINVAL;
		}
	}

	return 0;
}

static int far_fill(struct far *far, struct upf_dev *upf, struct genl_info *info,
		u8 *flag, struct upf_emark_pktinfo *epkt_info)
{
	struct nlattr *attrs[UPF_ATTR_FORWARDING_PARAMETER_MAX + 1];
	int err;

	if (!far)
		return -EINVAL;

	far->id = nla_get_u32(info->attrs[UPF_ATTR_FAR_ID]);

	if (info->attrs[UPF_ATTR_FAR_SEID])
		far->seid = nla_get_u64(info->attrs[UPF_ATTR_FAR_SEID]);
	else
		far->seid = 0;

	if (info->attrs[UPF_ATTR_FAR_APPLY_ACTION])
		far->action = nla_get_u8(info->attrs[UPF_ATTR_FAR_APPLY_ACTION]);

	if (info->attrs[UPF_ATTR_FAR_FORWARDING_PARAMETER]) {
		err = nla_parse_nested(attrs,
				UPF_ATTR_FORWARDING_PARAMETER_MAX,
				info->attrs[UPF_ATTR_FAR_FORWARDING_PARAMETER],
				NULL,
				NULL);
		if (err)
			return err;
		if (!far->fwd_param) {
			far->fwd_param = kzalloc(sizeof(*far->fwd_param), GFP_ATOMIC);
			if (!far->fwd_param)
				return -ENOMEM;
		}
		err = forwarding_parameter_fill(far->fwd_param, attrs, flag, epkt_info);
		if (err)
			return err;
	}

	/* Update PDRs which has not linked to this FAR */
	far_update(far, upf, flag, epkt_info);

	return 0;
}
