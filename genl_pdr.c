#include <linux/module.h>
#include <linux/socket.h>
#include <linux/net.h>

#include <net/ip.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

#include "dev.h"
#include "genl.h"
#include "genl_pdr.h"
#include "pdr.h"


static int pdr_fill(struct pdr *, struct upf_dev *, struct genl_info *);
static int parse_pdi(struct pdr *, struct nlattr *);
static int parse_f_teid(struct pdi *, struct nlattr *);
static int parse_sdf_filter(struct pdi *, struct nlattr *);
static int parse_ip_filter_rule(struct sdf_filter *, struct nlattr *);

static int upf_genl_fill_pdr(struct sk_buff *, u32, u32, u32, struct pdr *);
static int upf_genl_fill_rule(struct sk_buff *, struct ip_filter_rule *);
static int upf_genl_fill_sdf(struct sk_buff *, struct sdf_filter *);
static int upf_genl_fill_f_teid(struct sk_buff *, struct local_f_teid *);
static int upf_genl_fill_pdi(struct sk_buff *, struct pdi *);


int upf_genl_add_pdr(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct pdr *pdr;
	int ifindex;
	int netnsfd;
	u64 seid;
	u16 pdr_id;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	printk("info.net: %p\n", genl_info_net(info));
	printk("info.nlhdr: %p\n", info->nlhdr);
	printk("info.snd_portid: %u\n", info->snd_portid);

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

	if (info->attrs[UPF_ATTR_PDR_SEID]) {
		seid = nla_get_u32(info->attrs[UPF_ATTR_PDR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_PDR_ID]) {
		pdr_id = nla_get_u16(info->attrs[UPF_ATTR_PDR_ID]);
		printk("PDR ID: %u\n", pdr_id);
	} else {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENODEV;
	}

	pdr = find_pdr_by_id(upf, seid, pdr_id);
	if (pdr) {
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

		err = pdr_fill(pdr, upf, info);
		if (err) {
			pdr_context_delete(pdr);
			return err;
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
	if (!info->attrs[UPF_ATTR_PDR_PRECEDENCE]) {
		rcu_read_unlock();
		rtnl_unlock();
		return -EINVAL;
	}

	pdr = kzalloc(sizeof(*pdr), GFP_ATOMIC);
	if (!pdr) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENOMEM;
	}

	sock_hold(upf->sk1u);
	pdr->sk = upf->sk1u;
	pdr->dev = upf->dev;

	err = pdr_fill(pdr, upf, info);
	if (err) {
		pdr_context_delete(pdr);
		rcu_read_unlock();
		rtnl_unlock();
		return err;
	}

	pdr_append(seid, pdr_id, pdr, upf);

	rcu_read_unlock();
	rtnl_unlock();

	return 0;
}

int upf_genl_del_pdr(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct pdr *pdr;
	int ifindex;
	int netnsfd;
	u64 seid;
	u16 pdr_id;

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

	if (info->attrs[UPF_ATTR_PDR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_PDR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_PDR_ID]) {
		pdr_id = nla_get_u16(info->attrs[UPF_ATTR_PDR_ID]);
		printk("FAR ID: %u\n", pdr_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	pdr = find_pdr_by_id(upf, seid, pdr_id);
	if (!pdr) {
		rcu_read_unlock();
		return -ENOENT;
	}

	pdr_context_delete(pdr);
	rcu_read_unlock();

	return 0;
}

int upf_genl_get_pdr(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct pdr *pdr;
	int ifindex;
	int netnsfd;
	u64 seid;
	u16 pdr_id;
	struct sk_buff *skb_ack;
	int err;

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

	if (info->attrs[UPF_ATTR_PDR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_PDR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_PDR_ID]) {
		pdr_id = nla_get_u16(info->attrs[UPF_ATTR_PDR_ID]);
		printk("FAR ID: %u\n", pdr_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	pdr = find_pdr_by_id(upf, seid, pdr_id);
	if (!pdr) {
		rcu_read_unlock();
		return -ENOENT;
	}

	skb_ack = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!skb_ack) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	err = upf_genl_fill_pdr(skb_ack,
			NETLINK_CB(skb).portid,
			info->snd_seq,
			info->nlhdr->nlmsg_type,
			pdr);
	if (err) {
		kfree_skb(skb_ack);
		rcu_read_unlock();
		return err;
	}

	rcu_read_unlock();

	return genlmsg_unicast(genl_info_net(info), skb_ack, info->snd_portid);
}

#include <linux/rculist.h>
#include <net/netns/generic.h>
#include "net.h"

int upf_genl_dump_pdr(struct sk_buff *skb, struct netlink_callback *cb)
{
	/* netlink_callback->args
	 * args[0] : index of gtp5g dev id
	 * args[1] : index of gtp5g hash entry id in dev
	 * args[2] : index of gtp5g pdr id
	 * args[5] : set non-zero means it is finished
	 */
	struct upf_dev *upf;
	struct upf_dev *last_upf = (struct upf_dev *)cb->args[0];
	struct net *net = sock_net(skb->sk);
	struct upf_net *upf_net = net_generic(net, UPF_NET_ID());
	int i;
	int last_hash_entry_id = cb->args[1];
	int ret;
	u16 pdr_id = cb->args[2];
	struct pdr *pdr;

	printk("<%s:%d> start\n", __func__, __LINE__);

	if (cb->args[5])
		return 0;

	list_for_each_entry_rcu(upf, &upf_net->upf_dev_list, list) {
		if (last_upf && last_upf != upf)
			continue;
		else
			last_upf = NULL;

		for (i = last_hash_entry_id; i < upf->hash_size; i++) {
			hlist_for_each_entry_rcu(pdr, &upf->pdr_id_hash[i], hlist_id) {
				if (pdr_id && pdr_id != pdr->id)
					continue;
				else
					pdr_id = 0;

				ret = upf_genl_fill_pdr(skb,
						NETLINK_CB(cb->skb).portid,
						cb->nlh->nlmsg_seq,
						cb->nlh->nlmsg_type,
						pdr);
				if (ret) {
					cb->args[0] = (unsigned long)upf;
					cb->args[1] = i;
					cb->args[2] = pdr->id;
					goto out;
				}
			}
		}
	}
	cb->args[5] = 1;
out:
	return skb->len;
}


static int pdr_fill(struct pdr *pdr, struct upf_dev *upf, struct genl_info *info)
{
	char *str;
	int err;

	if (!pdr)
		return -EINVAL;

	pdr->af = AF_INET;
	pdr->id = nla_get_u16(info->attrs[UPF_ATTR_PDR_ID]);
	if (info->attrs[UPF_ATTR_PDR_SEID])
		pdr->seid = nla_get_u64(info->attrs[UPF_ATTR_PDR_SEID]);
	else
		pdr->seid = 0;

	if (info->attrs[UPF_ATTR_PDR_PRECEDENCE])
		pdr->precedence = nla_get_u32(info->attrs[UPF_ATTR_PDR_PRECEDENCE]);

	if (info->attrs[UPF_ATTR_OUTER_HEADER_REMOVAL]) {
		if (!pdr->outer_header_removal) {
			pdr->outer_header_removal = kzalloc(sizeof(*pdr->outer_header_removal), GFP_ATOMIC);
			if (!pdr->outer_header_removal)
				return -ENOMEM;
		}
		*pdr->outer_header_removal = nla_get_u8(info->attrs[UPF_ATTR_OUTER_HEADER_REMOVAL]);
	}

	/* Not in 3GPP spec, just used for routing */
	if (info->attrs[UPF_ATTR_PDR_ROLE_ADDR_IPV4]) {
		pdr->role_addr_ipv4.s_addr = nla_get_u32(info->attrs[UPF_ATTR_PDR_ROLE_ADDR_IPV4]);
	}

	/* Not in 3GPP spec, just used for buffering */
	if (info->attrs[UPF_ATTR_PDR_UNIX_SOCKET_PATH]) {
		str = nla_data(info->attrs[UPF_ATTR_PDR_UNIX_SOCKET_PATH]);
		pdr->addr_unix.sun_family = AF_UNIX;
		strncpy(pdr->addr_unix.sun_path, str, nla_len(info->attrs[UPF_ATTR_PDR_UNIX_SOCKET_PATH]));
	}

	if (info->attrs[UPF_ATTR_PDR_FAR_ID]) {
		if (!pdr->far_id) {
			pdr->far_id = kzalloc(sizeof(*pdr->far_id), GFP_ATOMIC);
			if (!pdr->far_id)
				return -ENOMEM;
		}
		*pdr->far_id = nla_get_u32(info->attrs[UPF_ATTR_PDR_FAR_ID]);
		pdr->far = find_far_by_id(upf, pdr->seid, *pdr->far_id);
		far_set_pdr(pdr->seid, *pdr->far_id, &pdr->hlist_related_far, upf);
	}

	if (info->attrs[UPF_ATTR_PDR_QER_ID]) {
		if (!pdr->qer_id) {
			pdr->qer_id = kzalloc(sizeof(*pdr->qer_id), GFP_ATOMIC);
			if (!pdr->qer_id)
				return -ENOMEM;
		}
		*pdr->qer_id = nla_get_u32(info->attrs[UPF_ATTR_PDR_QER_ID]);
		pdr->qer = find_qer_by_id(upf, pdr->seid, *pdr->qer_id);
		qer_set_pdr(pdr->seid, *pdr->qer_id, &pdr->hlist_related_qer, upf);
	}

	if (unix_sock_client_update(pdr) < 0)
		return -EINVAL;

	if (info->attrs[UPF_ATTR_PDR_PDI]) {
		err = parse_pdi(pdr, info->attrs[UPF_ATTR_PDR_PDI]);
		if (err)
			return err;
	}

	// Update hlist table
	pdr_update_hlist_table(pdr, upf);

	return 0;
}

static int parse_pdi(struct pdr *pdr, struct nlattr *a)
{
	struct nlattr *attrs[UPF_ATTR_PDI_MAX + 1];
	struct pdi *pdi;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_ATTR_PDI_MAX, a, NULL, NULL);
	if (err)
		return err;

	if (!pdr->pdi) {
		pdr->pdi = kzalloc(sizeof(*pdr->pdi), GFP_ATOMIC);
		if (!pdr->pdi)
			return -ENOMEM;
	}
	pdi = pdr->pdi;

	if (attrs[UPF_ATTR_PDI_UE_ADDR_IPV4]) {
		if (!pdi->ue_addr_ipv4) {
			pdi->ue_addr_ipv4 = kzalloc(sizeof(*pdi->ue_addr_ipv4), GFP_ATOMIC);
			if (!pdi->ue_addr_ipv4)
				return -ENOMEM;
		}
		pdi->ue_addr_ipv4->s_addr = nla_get_be32(attrs[UPF_ATTR_PDI_UE_ADDR_IPV4]);
		printk("UE Addr: %08x\n", pdi->ue_addr_ipv4->s_addr);
	}

	if (attrs[UPF_ATTR_PDI_F_TEID]) {
		err = parse_f_teid(pdi, attrs[UPF_ATTR_PDI_F_TEID]);
		if (err)
			return err;
	}

	if (attrs[UPF_ATTR_PDI_SDF_FILTER]) {
		err = parse_sdf_filter(pdi, attrs[UPF_ATTR_PDI_SDF_FILTER]);
		if (err)
			return err;
	}

	return 0;
}

static int parse_f_teid(struct pdi *pdi, struct nlattr *a)
{
	struct nlattr *attrs[UPF_ATTR_F_TEID_MAX + 1];
	struct local_f_teid *f_teid;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_ATTR_F_TEID_MAX, a, NULL, NULL);
	if (err)
		return err;

	if (!attrs[UPF_ATTR_F_TEID_I_TEID])
		return -EINVAL;

	if (!attrs[UPF_ATTR_F_TEID_GTPU_ADDR_IPV4])
		return -EINVAL;

	if (!pdi->f_teid) {
		 pdi->f_teid = kzalloc(sizeof(*pdi->f_teid), GFP_ATOMIC);
		 if (!pdi->f_teid)
			 return -ENOMEM;
	}
	f_teid = pdi->f_teid;

	f_teid->teid = htonl(nla_get_u32(attrs[UPF_ATTR_F_TEID_I_TEID]));
	printk("TEID: %u\n", f_teid->teid);

	f_teid->gtpu_addr_ipv4.s_addr = nla_get_be32(attrs[UPF_ATTR_F_TEID_GTPU_ADDR_IPV4]);
	printk("GTP-U Addr: %08x\n", f_teid->gtpu_addr_ipv4.s_addr);

	return 0;
}

static int parse_sdf_filter(struct pdi *pdi, struct nlattr *a)
{
	struct nlattr *attrs[UPF_ATTR_SDF_FILTER_MAX + 1];
	struct sdf_filter *sdf;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_ATTR_SDF_FILTER_MAX, a, NULL, NULL);
	if (err)
		return err;

	if (!pdi->sdf) {
		pdi->sdf = kzalloc(sizeof(*pdi->sdf), GFP_ATOMIC);
		if (!pdi->sdf)
			return -ENOMEM;
	}
	sdf = pdi->sdf;

	if (attrs[UPF_ATTR_SDF_FILTER_FLOW_DESCRIPTION]) {
		err = parse_ip_filter_rule(sdf, attrs[UPF_ATTR_SDF_FILTER_FLOW_DESCRIPTION]);
		if (err)
			return err;
	}

	if (attrs[UPF_ATTR_SDF_FILTER_TOS_TRAFFIC_CLASS]) {
		if (!sdf->tos_traffic_class) {
			sdf->tos_traffic_class = kzalloc(sizeof(*sdf->tos_traffic_class), GFP_ATOMIC);
			if (!sdf->tos_traffic_class)
				return -ENOMEM;
		}
		*sdf->tos_traffic_class = nla_get_u16(attrs[UPF_ATTR_SDF_FILTER_TOS_TRAFFIC_CLASS]);
	}

	if (attrs[UPF_ATTR_SDF_FILTER_SECURITY_PARAMETER_INDEX]) {
		if (!sdf->security_param_idx) {
			sdf->security_param_idx = kzalloc(sizeof(*sdf->security_param_idx), GFP_ATOMIC);
			if (!sdf->security_param_idx)
				return -ENOMEM;
                }
		*sdf->security_param_idx = nla_get_u32(attrs[UPF_ATTR_SDF_FILTER_SECURITY_PARAMETER_INDEX]);
	}

	if (attrs[UPF_ATTR_SDF_FILTER_FLOW_LABEL]) {
		if (!sdf->flow_label) {
			sdf->flow_label = kzalloc(sizeof(*sdf->flow_label), GFP_ATOMIC);
			if (!sdf->flow_label)
				return -ENOMEM;
                }
		*sdf->flow_label = nla_get_u32(attrs[UPF_ATTR_SDF_FILTER_FLOW_LABEL]);
	}

	if (attrs[UPF_ATTR_SDF_FILTER_SDF_FILTER_ID]) {
		if (!sdf->bi_id) {
			sdf->bi_id = kzalloc(sizeof(*sdf->bi_id), GFP_ATOMIC);
			if (!sdf->bi_id) {
				return -ENOMEM;
			}
		}
		*sdf->bi_id = nla_get_u32(attrs[UPF_ATTR_SDF_FILTER_SDF_FILTER_ID]);
	}

	return 0;
}

static int parse_ip_filter_rule(struct sdf_filter *sdf, struct nlattr *a)
{
	struct nlattr *attrs[UPF_ATTR_FLOW_DESCRIPTION_MAX + 1];
	struct ip_filter_rule *rule;
	int err;
	int i;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_ATTR_FLOW_DESCRIPTION_MAX, a, NULL, NULL);
	if (err)
		return err;

	if (!attrs[UPF_ATTR_FLOW_DESCRIPTION_ACTION])
		return -EINVAL;
	if (!attrs[UPF_ATTR_FLOW_DESCRIPTION_DIRECTION])
		return -EINVAL;
	if (!attrs[UPF_ATTR_FLOW_DESCRIPTION_PROTOCOL])
		return -EINVAL;
	if (!attrs[UPF_ATTR_FLOW_DESCRIPTION_SRC_IPV4])
		return -EINVAL;
	if (!attrs[UPF_ATTR_FLOW_DESCRIPTION_DEST_IPV4])
		return -EINVAL;

	if (!sdf->rule) {
		sdf->rule = kzalloc(sizeof(*sdf->rule), GFP_ATOMIC);
		if (!sdf->rule)
			return -ENOMEM;
	}
	rule = sdf->rule;

	rule->action = nla_get_u8(attrs[UPF_ATTR_FLOW_DESCRIPTION_ACTION]);
	rule->direction = nla_get_u8(attrs[UPF_ATTR_FLOW_DESCRIPTION_DIRECTION]);
	rule->proto = nla_get_u8(attrs[UPF_ATTR_FLOW_DESCRIPTION_PROTOCOL]);
	rule->src.s_addr = nla_get_be32(attrs[UPF_ATTR_FLOW_DESCRIPTION_SRC_IPV4]);
	rule->dest.s_addr = nla_get_be32(attrs[UPF_ATTR_FLOW_DESCRIPTION_DEST_IPV4]);
	if (attrs[UPF_ATTR_FLOW_DESCRIPTION_SRC_MASK])
		rule->smask.s_addr = nla_get_be32(attrs[UPF_ATTR_FLOW_DESCRIPTION_SRC_MASK]);
	else
		rule->smask.s_addr = -1;

	if (attrs[UPF_ATTR_FLOW_DESCRIPTION_DEST_MASK])
		rule->dmask.s_addr = nla_get_be32(attrs[UPF_ATTR_FLOW_DESCRIPTION_DEST_MASK]);
	else
		rule->dmask.s_addr = -1;

	if (attrs[UPF_ATTR_FLOW_DESCRIPTION_SRC_PORT]) {
		u32 *sport_encode = nla_data(attrs[UPF_ATTR_FLOW_DESCRIPTION_SRC_PORT]);
		rule->sport_num = nla_len(attrs[UPF_ATTR_FLOW_DESCRIPTION_SRC_PORT]) / sizeof(u32);
		if (rule->sport)
			kfree(rule->sport);
		rule->sport = kzalloc(rule->sport_num * sizeof(*rule->sport), GFP_ATOMIC);
		if (!rule->sport)
			return -ENOMEM;

		for (i = 0; i < rule->sport_num; i++) {
			if ((sport_encode[i] & 0xFFFF) <= (sport_encode[i] >> 16)) {
				rule->sport[i].start = (sport_encode[i] & 0xFFFF);
				rule->sport[i].end = (sport_encode[i] >> 16);
			} else {
				rule->sport[i].start = (sport_encode[i] >> 16);
				rule->sport[i].end = (sport_encode[i] & 0xFFFF);
			}
		}
	}

	if (attrs[UPF_ATTR_FLOW_DESCRIPTION_DEST_PORT]) {
		u32 *dport_encode = nla_data(attrs[UPF_ATTR_FLOW_DESCRIPTION_DEST_PORT]);
		rule->dport_num = nla_len(attrs[UPF_ATTR_FLOW_DESCRIPTION_DEST_PORT]) / sizeof(u32);

		if (rule->dport)
			kfree(rule->dport);

		rule->dport = kzalloc(rule->dport_num * sizeof(*rule->dport), GFP_ATOMIC);
		if (!rule->dport)
			return -ENOMEM;

		for (i = 0; i < rule->dport_num; i++) {
			if ((dport_encode[i] & 0xFFFF) <= (dport_encode[i] >> 16)) {
				rule->dport[i].start = (dport_encode[i] & 0xFFFF);
				rule->dport[i].end = (dport_encode[i] >> 16);
			} else {
				rule->dport[i].start = (dport_encode[i] >> 16);
				rule->dport[i].end = (dport_encode[i] & 0xFFFF);
			}
		}
	}

	return 0;
}

static int upf_genl_fill_rule(struct sk_buff *skb, struct ip_filter_rule *rule)
{
	struct nlattr *nest_rule;
	u32 *u32_buf;
	int i;

	u32_buf = kzalloc(0xff * sizeof(u32), GFP_KERNEL);
	if (!u32_buf)
		return -EMSGSIZE;

	nest_rule = nla_nest_start(skb, UPF_ATTR_SDF_FILTER_FLOW_DESCRIPTION);
	if (!nest_rule)
		goto genlmsg_fail;

	if (nla_put_u8(skb, UPF_ATTR_FLOW_DESCRIPTION_ACTION, rule->action))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_FLOW_DESCRIPTION_DIRECTION, rule->direction))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_FLOW_DESCRIPTION_PROTOCOL, rule->proto))
		goto genlmsg_fail;
	if (nla_put_be32(skb, UPF_ATTR_FLOW_DESCRIPTION_SRC_IPV4, rule->src.s_addr))
		goto genlmsg_fail;
	if (nla_put_be32(skb, UPF_ATTR_FLOW_DESCRIPTION_DEST_IPV4, rule->dest.s_addr))
		goto genlmsg_fail;

	if (rule->smask.s_addr != -1)
		if (nla_put_be32(skb, UPF_ATTR_FLOW_DESCRIPTION_SRC_MASK, rule->smask.s_addr))
			goto genlmsg_fail;

	if (rule->dmask.s_addr != -1)
		if (nla_put_be32(skb, UPF_ATTR_FLOW_DESCRIPTION_DEST_MASK, rule->dmask.s_addr))
			goto genlmsg_fail;

	if (rule->sport_num && rule->sport) {
		for (i = 0; i < rule->sport_num; i++)
			u32_buf[i] = rule->sport[i].start + (rule->sport[i].end << 16);
		if (nla_put(skb, UPF_ATTR_FLOW_DESCRIPTION_SRC_PORT,
					rule->sport_num * sizeof(u32), u32_buf))
			goto genlmsg_fail;
	}

	if (rule->dport_num && rule->dport) {
		for (i = 0; i < rule->dport_num; i++)
			u32_buf[i] = rule->dport[i].start + (rule->dport[i].end << 16);
		if (nla_put(skb, UPF_ATTR_FLOW_DESCRIPTION_DEST_PORT,
					rule->dport_num * sizeof(u32), u32_buf))
			goto genlmsg_fail;
	}

	nla_nest_end(skb, nest_rule);
	kfree(u32_buf);
	return 0;
genlmsg_fail:
	kfree(u32_buf);
	return -EMSGSIZE;
}

static int upf_genl_fill_sdf(struct sk_buff *skb, struct sdf_filter *sdf)
{
	struct nlattr *nest_sdf;

	nest_sdf = nla_nest_start(skb, UPF_ATTR_PDI_SDF_FILTER);
	if (!nest_sdf)
		return -EMSGSIZE;

	if (sdf->rule) {
		if (upf_genl_fill_rule(skb, sdf->rule))
			return -EMSGSIZE;
	}

	if (sdf->tos_traffic_class)
		if (nla_put_u16(skb, UPF_ATTR_SDF_FILTER_TOS_TRAFFIC_CLASS, *sdf->tos_traffic_class))
			return -EMSGSIZE;

	if (sdf->security_param_idx)
		if (nla_put_u32(skb, UPF_ATTR_SDF_FILTER_SECURITY_PARAMETER_INDEX, *sdf->security_param_idx))
			return -EMSGSIZE;

	if (sdf->flow_label)
		if (nla_put_u32(skb, UPF_ATTR_SDF_FILTER_FLOW_LABEL, *sdf->flow_label))
			return -EMSGSIZE;

	if (sdf->bi_id)
		if (nla_put_u32(skb, UPF_ATTR_SDF_FILTER_SDF_FILTER_ID, *sdf->bi_id))
			return -EMSGSIZE;

	nla_nest_end(skb, nest_sdf);
	return 0;
}

static int upf_genl_fill_f_teid(struct sk_buff *skb, struct local_f_teid *f_teid)
{
	struct nlattr *nest_f_teid;

	nest_f_teid = nla_nest_start(skb, UPF_ATTR_PDI_F_TEID);
	if (!nest_f_teid)
		return -EMSGSIZE;

	if (nla_put_u32(skb, UPF_ATTR_F_TEID_I_TEID, ntohl(f_teid->teid)))
		return -EMSGSIZE;
	if (nla_put_be32(skb, UPF_ATTR_F_TEID_GTPU_ADDR_IPV4, f_teid->gtpu_addr_ipv4.s_addr))
		return -EMSGSIZE;

	nla_nest_end(skb, nest_f_teid);
	return 0;
}

static int upf_genl_fill_pdi(struct sk_buff *skb, struct pdi *pdi)
{
	struct nlattr *nest_pdi;

	nest_pdi = nla_nest_start(skb, UPF_ATTR_PDR_PDI);
	if (!nest_pdi)
		return -EMSGSIZE;

	if (pdi->ue_addr_ipv4) {
		if (nla_put_be32(skb, UPF_ATTR_PDI_UE_ADDR_IPV4, pdi->ue_addr_ipv4->s_addr))
			return -EMSGSIZE;
	}

	if (pdi->f_teid) {
		if (upf_genl_fill_f_teid(skb, pdi->f_teid))
			return -EMSGSIZE;
	}

	if (pdi->sdf) {
		if (upf_genl_fill_sdf(skb, pdi->sdf))
			return -EMSGSIZE;
	}

	nla_nest_end(skb, nest_pdi);
	return 0;
}

static int upf_genl_fill_pdr(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
		u32 type, struct pdr *pdr)
{
	void *genlh;

	genlh = genlmsg_put(skb, snd_portid, snd_seq, &upf_genl_family, 0, type);
	if (!genlh)
		goto genlmsg_fail;

	if (nla_put_u16(skb, UPF_ATTR_PDR_ID, pdr->id))
		goto genlmsg_fail;

	if (nla_put_u32(skb, UPF_ATTR_PDR_PRECEDENCE, pdr->precedence))
		goto genlmsg_fail;

	if (pdr->seid) {
		if (nla_put_u64_64bit(skb, UPF_ATTR_PDR_SEID, pdr->seid, 0))
			goto genlmsg_fail;
	}

	if (pdr->outer_header_removal) {
		if (nla_put_u8(skb, UPF_ATTR_OUTER_HEADER_REMOVAL, *pdr->outer_header_removal))
			goto genlmsg_fail;
	}

	if (pdr->far_id) {
		if (nla_put_u32(skb, UPF_ATTR_PDR_FAR_ID, *pdr->far_id))
			goto genlmsg_fail;
	}

	if (pdr->qer_id) {
		if (nla_put_u32(skb, UPF_ATTR_PDR_QER_ID, *pdr->qer_id))
			goto genlmsg_fail;
	}

	if (pdr->role_addr_ipv4.s_addr) {
		if (nla_put_u32(skb, UPF_ATTR_PDR_ROLE_ADDR_IPV4, pdr->role_addr_ipv4.s_addr))
			goto genlmsg_fail;
	}

	if (pdr->pdi) {
		if (upf_genl_fill_pdi(skb, pdr->pdi))
			goto genlmsg_fail;
	}

	genlmsg_end(skb, genlh);
	return 0;
genlmsg_fail:
	genlmsg_cancel(skb, genlh);
	return -EMSGSIZE;
}
