#include <net/genetlink.h>
#include <net/sock.h>

#include "dev.h"
#include "genl.h"
#include "genl_qer.h"
#include "qer.h"


static int qer_fill(struct qer *, struct upf_dev *, struct genl_info *);
static int upf_genl_fill_qer(struct sk_buff *, u32, u32, u32, struct qer *);


int upf_genl_add_qer(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct qer *qer;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 qer_id;
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

	rtnl_lock();
	rcu_read_lock();

	upf = find_upf_dev(sock_net(skb->sk), ifindex, netnsfd);
	if (!upf) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENODEV;
	}

	if (info->attrs[UPF_ATTR_QER_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_QER_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_QER_ID]) {
		qer_id = nla_get_u32(info->attrs[UPF_ATTR_QER_ID]);
		printk("QER ID: %u\n", qer_id);
	} else {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENODEV;
	}

	qer = find_qer_by_id(upf, seid, qer_id);
	if (qer) {
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
		err = qer_fill(qer, upf, info);
		if (err) {
			qer_context_delete(qer);
			return err;
		}
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

	qer = kzalloc(sizeof(*qer), GFP_ATOMIC);
	if (!qer) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENOMEM;
	}

	qer->dev = upf->dev;

	err = qer_fill(qer, upf, info);
	if (err) {
		qer_context_delete(qer);
		rcu_read_unlock();
		rtnl_unlock();
		return err;
	}

	qer_append(seid, qer_id, qer, upf);

	rcu_read_unlock();
	rtnl_unlock();
	return 0;
}

int upf_genl_del_qer(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct qer *qer;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 qer_id;

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

	if (info->attrs[UPF_ATTR_QER_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_QER_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_QER_ID]) {
		qer_id = nla_get_u32(info->attrs[UPF_ATTR_QER_ID]);
		printk("QER ID: %u\n", qer_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	qer = find_qer_by_id(upf, seid, qer_id);
	if (!qer) {
		rcu_read_unlock();
		return -ENOENT;
	}

	qer_context_delete(qer);
	rcu_read_unlock();

	return 0;
}

int upf_genl_get_qer(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct qer *qer;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 qer_id;
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

	if (info->attrs[UPF_ATTR_QER_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_QER_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_QER_ID]) {
		qer_id = nla_get_u32(info->attrs[UPF_ATTR_QER_ID]);
		printk("QER ID: %u\n", qer_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	qer = find_qer_by_id(upf, seid, qer_id);
	if (!qer) {
		rcu_read_unlock();
		return -ENOENT;
	}

	skb_ack = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!skb_ack) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	err = upf_genl_fill_qer(skb_ack,
			NETLINK_CB(skb).portid,
			info->snd_seq,
			info->nlhdr->nlmsg_type,
			qer);
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

int upf_genl_dump_qer(struct sk_buff *skb, struct netlink_callback *cb)
{
	/* netlink_callback->args
	 * args[0] : index of gtp5g dev id
	 * args[1] : index of gtp5g hash entry id in dev
	 * args[2] : index of gtp5g qer id
	 * args[5] : set non-zero means it is finished
	 */
	struct upf_dev *upf;
	struct upf_dev *last_upf = (struct upf_dev *)cb->args[0];
	struct net *net = sock_net(skb->sk);
	struct upf_net *upf_net = net_generic(net, UPF_NET_ID());
	int i;
	int last_hash_entry_id = cb->args[1];
	int ret;
	u32 qer_id = cb->args[2];
	struct qer *qer;

	printk("<%s:%d> start\n", __func__, __LINE__);

	if (cb->args[5])
		return 0;

	list_for_each_entry_rcu(upf, &upf_net->upf_dev_list, list) {
		if (last_upf && last_upf != upf)
			continue;
		else
			last_upf = NULL;

		for (i = last_hash_entry_id; i < upf->hash_size; i++) {
			hlist_for_each_entry_rcu(qer, &upf->qer_id_hash[i], hlist_id) {
				if (qer_id && qer_id != qer->id)
					continue;
				qer_id = 0;
				ret = upf_genl_fill_qer(skb,
						NETLINK_CB(cb->skb).portid,
						cb->nlh->nlmsg_seq,
						cb->nlh->nlmsg_type,
						qer);
				if (ret) {
					cb->args[0] = (unsigned long)upf;
					cb->args[1] = i;
					cb->args[2] = qer->id;
					goto out;
				}
			}
		}
	}

	cb->args[5] = 1;
out:
	return skb->len;
}


static int qer_fill(struct qer *qer, struct upf_dev *upf, struct genl_info *info)
{
	struct nlattr *mbr_param_attrs[UPF_ATTR_QER_MBR_MAX + 1];
	struct nlattr *gbr_param_attrs[UPF_ATTR_QER_GBR_MAX + 1];

	qer->id = nla_get_u32(info->attrs[UPF_ATTR_QER_ID]);

	if (info->attrs[UPF_ATTR_QER_SEID])
		qer->seid = nla_get_u64(info->attrs[UPF_ATTR_QER_SEID]);
	else
		qer->seid = 0;

	if (info->attrs[UPF_ATTR_QER_GATE])
		qer->ul_dl_gate = nla_get_u8(info->attrs[UPF_ATTR_QER_GATE]);

	/* MBR */
	if (info->attrs[UPF_ATTR_QER_MBR] &&
	    !nla_parse_nested(mbr_param_attrs, UPF_ATTR_QER_MBR_MAX, info->attrs[UPF_ATTR_QER_MBR], NULL, NULL)) {
		qer->mbr.ul_high = nla_get_u32(mbr_param_attrs[UPF_ATTR_QER_MBR_UL_HIGH32]);
		qer->mbr.ul_low  = nla_get_u8(mbr_param_attrs[UPF_ATTR_QER_MBR_UL_LOW8]);
		qer->mbr.dl_high = nla_get_u32(mbr_param_attrs[UPF_ATTR_QER_MBR_DL_HIGH32]);
		qer->mbr.dl_low  = nla_get_u8(mbr_param_attrs[UPF_ATTR_QER_MBR_DL_LOW8]);
	}

	/* GBR */
	if (info->attrs[UPF_ATTR_QER_GBR] &&
	    !nla_parse_nested(gbr_param_attrs, UPF_ATTR_QER_GBR_MAX, info->attrs[UPF_ATTR_QER_GBR], NULL, NULL)) {
		qer->gbr.ul_high = nla_get_u32(gbr_param_attrs[UPF_ATTR_QER_GBR_UL_HIGH32]);
		qer->gbr.ul_low  = nla_get_u8(gbr_param_attrs[UPF_ATTR_QER_GBR_UL_LOW8]);
		qer->gbr.dl_high = nla_get_u32(gbr_param_attrs[UPF_ATTR_QER_GBR_DL_HIGH32]);
		qer->gbr.dl_low  = nla_get_u8(gbr_param_attrs[UPF_ATTR_QER_GBR_DL_LOW8]);
	}

	if (info->attrs[UPF_ATTR_QER_CORR_ID])
		qer->qer_corr_id = nla_get_u32(info->attrs[UPF_ATTR_QER_CORR_ID]);

	if (info->attrs[UPF_ATTR_QER_RQI])
		qer->rqi = nla_get_u8(info->attrs[UPF_ATTR_QER_RQI]);

	if (info->attrs[UPF_ATTR_QER_QFI])
		qer->qfi = nla_get_u8(info->attrs[UPF_ATTR_QER_QFI]);

	if (info->attrs[UPF_ATTR_QER_PPI])
		qer->ppi = nla_get_u8(info->attrs[UPF_ATTR_QER_PPI]);

	if (info->attrs[UPF_ATTR_QER_RCSR])
		qer->rcsr = nla_get_u8(info->attrs[UPF_ATTR_QER_RCSR]);

	/* Update PDRs which has not linked to this QER */
	qer_update(qer, upf);
	return 0;
}

static int upf_genl_fill_qer(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
		u32 type, struct qer *qer)
{
	struct upf_dev *upf = netdev_priv(qer->dev);
	void *genlh;
	struct nlattr *nest_mbr_param;
	struct nlattr *nest_gbr_param;
	u16 *ids;
	int n;

	genlh = genlmsg_put(skb, snd_portid, snd_seq,
			&upf_genl_family, 0, type);
	if (!genlh)
		goto genlmsg_fail;

	if (nla_put_u32(skb, UPF_ATTR_QER_ID, qer->id))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_GATE, qer->ul_dl_gate))
		goto genlmsg_fail;
	if (qer->seid) {
		if (nla_put_u64_64bit(skb, UPF_ATTR_QER_SEID, qer->seid, 0))
			goto genlmsg_fail;
	}

	/* MBR */
	if (!(nest_mbr_param = nla_nest_start(skb, UPF_ATTR_QER_MBR)))
		goto genlmsg_fail;

	if (nla_put_u32(skb, UPF_ATTR_QER_MBR_UL_HIGH32, qer->mbr.ul_high))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_MBR_UL_LOW8, qer->mbr.ul_low))
		goto genlmsg_fail;
	if (nla_put_u32(skb, UPF_ATTR_QER_MBR_DL_HIGH32, qer->mbr.dl_high))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_MBR_DL_LOW8, qer->mbr.dl_low))
		goto genlmsg_fail;

	nla_nest_end(skb, nest_mbr_param);

	/* GBR */
	if (!(nest_gbr_param = nla_nest_start(skb, UPF_ATTR_QER_GBR)))
		goto genlmsg_fail;

	if (nla_put_u32(skb, UPF_ATTR_QER_GBR_UL_HIGH32, qer->gbr.ul_high))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_GBR_UL_LOW8, qer->gbr.ul_low))
		goto genlmsg_fail;
	if (nla_put_u32(skb, UPF_ATTR_QER_GBR_DL_HIGH32, qer->gbr.dl_high))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_GBR_DL_LOW8, qer->gbr.dl_low))
		goto genlmsg_fail;

	nla_nest_end(skb, nest_gbr_param);

	/* CORR_ID, RQI, QFI, PPI, RCSR */
	if (nla_put_u32(skb, UPF_ATTR_QER_CORR_ID, qer->qer_corr_id))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_RQI, qer->rqi))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_QFI, qer->qfi))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_PPI, qer->ppi))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_QER_RCSR, qer->rcsr))
		goto genlmsg_fail;

	ids = kzalloc(0xff * sizeof(u16), GFP_KERNEL);
	if (!ids)
		goto genlmsg_fail;
	n = qer_get_pdr_ids(ids, 0xff, qer, upf);
	if (n) {
		if (nla_put(skb, UPF_ATTR_QER_RELATED_TO_PDR, n * sizeof(u16), ids)) {
			kfree(ids);
			goto genlmsg_fail;
		}
	}
	kfree(ids);

	genlmsg_end(skb, genlh);
	return 0;
genlmsg_fail:
	genlmsg_cancel(skb, genlh);
	return -EMSGSIZE;
}
