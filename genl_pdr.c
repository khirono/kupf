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


static int parse_pdi(struct nlattr *);
static int parse_f_teid(struct nlattr *);
static int parse_sdf_filter(struct nlattr *);

static int upf_genl_fill_pdr(struct sk_buff *, u32, u32, u32, struct pdr *);
static int upf_genl_fill_rule(struct sk_buff *, struct ip_filter_rule *);
static int upf_genl_fill_sdf(struct sk_buff *, struct sdf_filter *);
static int upf_genl_fill_f_teid(struct sk_buff *, struct local_f_teid *);
static int upf_genl_fill_pdi(struct sk_buff *, struct pdi *);


int upf_genl_add_pdr(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	int ifindex;
	int netnsfd;
	u64 seid;
	u16 pdr_id;
	u32 precedence;
	u8 removal;
	u32 far_id;
	u32 qer_id;

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

	if (info->attrs[UPF_ATTR_PDR_PRECEDENCE]) {
		precedence = nla_get_u32(info->attrs[UPF_ATTR_PDR_PRECEDENCE]);
		printk("precedence: %u\n", precedence);
	}

	if (info->attrs[UPF_ATTR_PDR_PDI]) {
		parse_pdi(info->attrs[UPF_ATTR_PDR_PDI]);
	}

	if (info->attrs[UPF_ATTR_OUTER_HEADER_REMOVAL]) {
		removal = nla_get_u8(info->attrs[UPF_ATTR_OUTER_HEADER_REMOVAL]);
		printk("removal: %u\n", removal);
	}

	if (info->attrs[UPF_ATTR_PDR_FAR_ID]) {
		far_id = nla_get_u32(info->attrs[UPF_ATTR_PDR_FAR_ID]);
		printk("far_id: %u\n", far_id);
	}

	if (info->attrs[UPF_ATTR_PDR_QER_ID]) {
		qer_id = nla_get_u32(info->attrs[UPF_ATTR_PDR_QER_ID]);
		printk("qer_id: %u\n", qer_id);
	}

	notify(0x9876);

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


static int parse_pdi(struct nlattr *a)
{
	struct nlattr *attrs[UPF_ATTR_PDI_MAX + 1];
	u32 ue_addr;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_ATTR_PDI_MAX, a, NULL, NULL);
	if (err)
		return err;

	if (attrs[UPF_ATTR_PDI_UE_ADDR_IPV4]) {
		ue_addr = nla_get_be32(attrs[UPF_ATTR_PDI_UE_ADDR_IPV4]);
		printk("UE Addr: %08x\n", ue_addr);
	}

	if (attrs[UPF_ATTR_PDI_F_TEID]) {
		parse_f_teid(attrs[UPF_ATTR_PDI_F_TEID]);
	}

	if (attrs[UPF_ATTR_PDI_SDF_FILTER]) {
		parse_sdf_filter(attrs[UPF_ATTR_PDI_SDF_FILTER]);
	}

	return 0;
}

static int parse_f_teid(struct nlattr *a)
{
	struct nlattr *attrs[UPF_ATTR_F_TEID_MAX + 1];
	u32 teid;
	u32 gtpu_addr;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_ATTR_F_TEID_MAX, a, NULL, NULL);
	if (err)
		return err;

	if (attrs[UPF_ATTR_F_TEID_I_TEID]) {
		teid = htonl(nla_get_u32(attrs[UPF_ATTR_F_TEID_I_TEID]));
		printk("TEID: %u\n", teid);
	}

	if (attrs[UPF_ATTR_F_TEID_GTPU_ADDR_IPV4]) {
		gtpu_addr = nla_get_be32(attrs[UPF_ATTR_F_TEID_GTPU_ADDR_IPV4]);
		printk("GTP-U Addr: %08x\n", gtpu_addr);
	}

	return 0;
}

static int parse_sdf_filter(struct nlattr *a)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

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
