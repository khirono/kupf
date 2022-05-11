#include <net/genetlink.h>
#include <net/sock.h>

#include "dev.h"
#include "genl.h"
#include "genl_urr.h"
#include "urr.h"


static int urr_fill(struct urr *, struct upf_dev *, struct genl_info *);
static int upf_genl_fill_urr(struct sk_buff *, u32, u32, u32, struct urr *);


int upf_genl_add_urr(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct urr *urr;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 urr_id;
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

	if (info->attrs[UPF_ATTR_URR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_URR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_URR_ID]) {
		urr_id = nla_get_u32(info->attrs[UPF_ATTR_URR_ID]);
		printk("URR ID: %u\n", urr_id);
	} else {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENODEV;
	}

	urr = find_urr_by_id(upf, seid, urr_id);
	if (urr) {
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
		err = urr_fill(urr, upf, info);
		if (err) {
			urr_context_delete(urr);
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

	urr = kzalloc(sizeof(*urr), GFP_ATOMIC);
	if (!urr) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENOMEM;
	}

	urr->dev = upf->dev;

	err = urr_fill(urr, upf, info);
	if (err) {
		urr_context_delete(urr);
		rcu_read_unlock();
		rtnl_unlock();
		return err;
	}

	urr_append(seid, urr_id, urr, upf);

	rcu_read_unlock();
	rtnl_unlock();
	return 0;
}

int upf_genl_del_urr(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct urr *urr;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 urr_id;

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

	if (info->attrs[UPF_ATTR_URR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_URR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_URR_ID]) {
		urr_id = nla_get_u32(info->attrs[UPF_ATTR_URR_ID]);
		printk("URR ID: %u\n", urr_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	urr = find_urr_by_id(upf, seid, urr_id);
	if (!urr) {
		rcu_read_unlock();
		return -ENOENT;
	}

	urr_context_delete(urr);
	rcu_read_unlock();

	return 0;
}

int upf_genl_get_urr(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct urr *urr;
	int ifindex;
	int netnsfd;
	u64 seid;
	u32 urr_id;
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

	if (info->attrs[UPF_ATTR_URR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_URR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_URR_ID]) {
		urr_id = nla_get_u32(info->attrs[UPF_ATTR_URR_ID]);
		printk("URR ID: %u\n", urr_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	urr = find_urr_by_id(upf, seid, urr_id);
	if (!urr) {
		rcu_read_unlock();
		return -ENOENT;
	}

	skb_ack = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!skb_ack) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	err = upf_genl_fill_urr(skb_ack,
			NETLINK_CB(skb).portid,
			info->snd_seq,
			info->nlhdr->nlmsg_type,
			urr);
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

int upf_genl_dump_urr(struct sk_buff *skb, struct netlink_callback *cb)
{
	/* netlink_callback->args
	 * args[0] : index of gtp5g dev id
	 * args[1] : index of gtp5g hash entry id in dev
	 * args[2] : index of gtp5g urr id
	 * args[5] : set non-zero means it is finished
	 */
	struct upf_dev *upf;
	struct upf_dev *last_upf = (struct upf_dev *)cb->args[0];
	struct net *net = sock_net(skb->sk);
	struct upf_net *upf_net = net_generic(net, UPF_NET_ID());
	int i;
	int last_hash_entry_id = cb->args[1];
	int ret;
	u32 urr_id = cb->args[2];
	struct urr *urr;

	printk("<%s:%d> start\n", __func__, __LINE__);

	if (cb->args[5])
		return 0;

	list_for_each_entry_rcu(upf, &upf_net->upf_dev_list, list) {
		if (last_upf && last_upf != upf)
			continue;
		else
			last_upf = NULL;

		for (i = last_hash_entry_id; i < upf->hash_size; i++) {
			hlist_for_each_entry_rcu(urr, &upf->urr_id_hash[i], hlist_id) {
				if (urr_id && urr_id != urr->id)
					continue;
				urr_id = 0;
				ret = upf_genl_fill_urr(skb,
						NETLINK_CB(cb->skb).portid,
						cb->nlh->nlmsg_seq,
						cb->nlh->nlmsg_type,
						urr);
				if (ret) {
					cb->args[0] = (unsigned long)upf;
					cb->args[1] = i;
					cb->args[2] = urr->id;
					goto out;
				}
			}
		}
	}

	cb->args[5] = 1;
out:
	return skb->len;
}


static int urr_fill(struct urr *urr, struct upf_dev *upf, struct genl_info *info)
{
	urr->id = nla_get_u32(info->attrs[UPF_ATTR_URR_ID]);

	if (info->attrs[UPF_ATTR_URR_SEID])
		urr->seid = nla_get_u64(info->attrs[UPF_ATTR_URR_SEID]);
	else
		urr->seid = 0;

	if (info->attrs[UPF_ATTR_URR_MEASUREMENT_METHOD])
		urr->method = nla_get_u64(info->attrs[UPF_ATTR_URR_MEASUREMENT_METHOD]);

	if (info->attrs[UPF_ATTR_URR_REPORTING_TRIGGER])
		urr->trigger = nla_get_u64(info->attrs[UPF_ATTR_URR_REPORTING_TRIGGER]);

	if (info->attrs[UPF_ATTR_URR_MEASUREMENT_PERIOD])
		urr->period = nla_get_u64(info->attrs[UPF_ATTR_URR_MEASUREMENT_PERIOD]);

	if (info->attrs[UPF_ATTR_URR_MEASUREMENT_INFO])
		urr->info = nla_get_u64(info->attrs[UPF_ATTR_URR_MEASUREMENT_INFO]);

	if (info->attrs[UPF_ATTR_URR_SEQ])
		urr->seq = nla_get_u64(info->attrs[UPF_ATTR_URR_SEQ]);

	/* Update PDRs which has not linked to this URR */
	urr_update(urr, upf);
	return 0;
}

static int upf_genl_fill_urr(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
		u32 type, struct urr *urr)
{
	void *genlh;

	genlh = genlmsg_put(skb, snd_portid, snd_seq,
			&upf_genl_family, 0, type);
	if (!genlh)
		goto genlmsg_fail;

	if (nla_put_u32(skb, UPF_ATTR_URR_ID, urr->id))
		goto genlmsg_fail;
	if (nla_put_u64_64bit(skb, UPF_ATTR_URR_MEASUREMENT_METHOD, urr->method, 0))
		goto genlmsg_fail;
	if (nla_put_u64_64bit(skb, UPF_ATTR_URR_REPORTING_TRIGGER, urr->trigger, 0))
		goto genlmsg_fail;
	if (nla_put_u64_64bit(skb, UPF_ATTR_URR_MEASUREMENT_PERIOD, urr->period, 0))
		goto genlmsg_fail;
	if (nla_put_u64_64bit(skb, UPF_ATTR_URR_MEASUREMENT_INFO, urr->info, 0))
		goto genlmsg_fail;
	if (nla_put_u64_64bit(skb, UPF_ATTR_URR_SEQ, urr->seq, 0))
		goto genlmsg_fail;
	if (urr->seid) {
		if (nla_put_u64_64bit(skb, UPF_ATTR_URR_SEID, urr->seid, 0))
			goto genlmsg_fail;
	}

	genlmsg_end(skb, genlh);
	return 0;
genlmsg_fail:
	genlmsg_cancel(skb, genlh);
	return -EMSGSIZE;
}
