#include <net/genetlink.h>
#include <net/sock.h>

#include "dev.h"
#include "genl.h"
#include "genl_bar.h"
#include "bar.h"


static int bar_fill(struct bar *, struct upf_dev *, struct genl_info *);
static int upf_genl_fill_bar(struct sk_buff *, u32, u32, u32, struct bar *);


int upf_genl_add_bar(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct bar *bar;
	int ifindex;
	int netnsfd;
	u64 seid;
	u8 bar_id;
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

	if (info->attrs[UPF_ATTR_BAR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_BAR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_BAR_ID]) {
		bar_id = nla_get_u8(info->attrs[UPF_ATTR_BAR_ID]);
		printk("BAR ID: %u\n", bar_id);
	} else {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENODEV;
	}

	bar = find_bar_by_id(upf, seid, bar_id);
	if (bar) {
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
		err = bar_fill(bar, upf, info);
		if (err) {
			bar_context_delete(bar);
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

	bar = kzalloc(sizeof(*bar), GFP_ATOMIC);
	if (!bar) {
		rcu_read_unlock();
		rtnl_unlock();
		return -ENOMEM;
	}

	bar->dev = upf->dev;

	err = bar_fill(bar, upf, info);
	if (err) {
		bar_context_delete(bar);
		rcu_read_unlock();
		rtnl_unlock();
		return err;
	}

	bar_append(seid, bar_id, bar, upf);

	rcu_read_unlock();
	rtnl_unlock();
	return 0;
}

int upf_genl_del_bar(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct bar *bar;
	int ifindex;
	int netnsfd;
	u64 seid;
	u8 bar_id;

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

	if (info->attrs[UPF_ATTR_BAR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_BAR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_BAR_ID]) {
		bar_id = nla_get_u8(info->attrs[UPF_ATTR_BAR_ID]);
		printk("BAR ID: %u\n", bar_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	bar = find_bar_by_id(upf, seid, bar_id);
	if (!bar) {
		rcu_read_unlock();
		return -ENOENT;
	}

	bar_context_delete(bar);
	rcu_read_unlock();

	return 0;
}

int upf_genl_get_bar(struct sk_buff *skb, struct genl_info *info)
{
	struct upf_dev *upf;
	struct bar *bar;
	int ifindex;
	int netnsfd;
	u64 seid;
	u8 bar_id;
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

	if (info->attrs[UPF_ATTR_BAR_SEID]) {
		seid = nla_get_u64(info->attrs[UPF_ATTR_BAR_SEID]);
		printk("SEID: %llu\n", seid);
	} else {
		seid = 0;
	}

	if (info->attrs[UPF_ATTR_BAR_ID]) {
		bar_id = nla_get_u8(info->attrs[UPF_ATTR_BAR_ID]);
		printk("BAR ID: %u\n", bar_id);
	} else {
		rcu_read_unlock();
		return -ENODEV;
	}

	bar = find_bar_by_id(upf, seid, bar_id);
	if (!bar) {
		rcu_read_unlock();
		return -ENOENT;
	}

	skb_ack = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!skb_ack) {
		rcu_read_unlock();
		return -ENOMEM;
	}

	err = upf_genl_fill_bar(skb_ack,
			NETLINK_CB(skb).portid,
			info->snd_seq,
			info->nlhdr->nlmsg_type,
			bar);
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

int upf_genl_dump_bar(struct sk_buff *skb, struct netlink_callback *cb)
{
	/* netlink_callback->args
	 * args[0] : index of gtp5g dev id
	 * args[1] : index of gtp5g hash entry id in dev
	 * args[2] : index of gtp5g bar id
	 * args[5] : set non-zero means it is finished
	 */
	struct upf_dev *upf;
	struct upf_dev *last_upf = (struct upf_dev *)cb->args[0];
	struct net *net = sock_net(skb->sk);
	struct upf_net *upf_net = net_generic(net, UPF_NET_ID());
	int i;
	int last_hash_entry_id = cb->args[1];
	int ret;
	u8 bar_id = cb->args[2];
	struct bar *bar;

	printk("<%s:%d> start\n", __func__, __LINE__);

	if (cb->args[5])
		return 0;

	list_for_each_entry_rcu(upf, &upf_net->upf_dev_list, list) {
		if (last_upf && last_upf != upf)
			continue;
		else
			last_upf = NULL;

		for (i = last_hash_entry_id; i < upf->hash_size; i++) {
			hlist_for_each_entry_rcu(bar, &upf->bar_id_hash[i], hlist_id) {
				if (bar_id && bar_id != bar->id)
					continue;
				bar_id = 0;
				ret = upf_genl_fill_bar(skb,
						NETLINK_CB(cb->skb).portid,
						cb->nlh->nlmsg_seq,
						cb->nlh->nlmsg_type,
						bar);
				if (ret) {
					cb->args[0] = (unsigned long)upf;
					cb->args[1] = i;
					cb->args[2] = bar->id;
					goto out;
				}
			}
		}
	}

	cb->args[5] = 1;
out:
	return skb->len;
}


static int bar_fill(struct bar *bar, struct upf_dev *upf, struct genl_info *info)
{
	bar->id = nla_get_u8(info->attrs[UPF_ATTR_BAR_ID]);

	if (info->attrs[UPF_ATTR_BAR_SEID])
		bar->seid = nla_get_u64(info->attrs[UPF_ATTR_BAR_SEID]);
	else
		bar->seid = 0;

	if (info->attrs[UPF_ATTR_BAR_DOWNLINK_DATA_NOTIFICATION_DELAY])
		bar->delay = nla_get_u8(info->attrs[UPF_ATTR_BAR_DOWNLINK_DATA_NOTIFICATION_DELAY]);
	else
		bar->delay = 0;

	if (info->attrs[UPF_ATTR_BAR_BUFFERING_PACKETS_COUNT])
		bar->count = nla_get_u16(info->attrs[UPF_ATTR_BAR_BUFFERING_PACKETS_COUNT]);
	else
		bar->count = 0;

	/* Update PDRs which has not linked to this BAR */
	bar_update(bar, upf);
	return 0;
}

static int upf_genl_fill_bar(struct sk_buff *skb, u32 snd_portid, u32 snd_seq,
		u32 type, struct bar *bar)
{
	void *genlh;

	genlh = genlmsg_put(skb, snd_portid, snd_seq,
			&upf_genl_family, 0, type);
	if (!genlh)
		goto genlmsg_fail;

	if (nla_put_u8(skb, UPF_ATTR_BAR_ID, bar->id))
		goto genlmsg_fail;
	if (nla_put_u8(skb, UPF_ATTR_BAR_DOWNLINK_DATA_NOTIFICATION_DELAY, bar->delay))
		goto genlmsg_fail;
	if (nla_put_u16(skb, UPF_ATTR_BAR_BUFFERING_PACKETS_COUNT, bar->count))
		goto genlmsg_fail;
	if (bar->seid) {
		if (nla_put_u64_64bit(skb, UPF_ATTR_BAR_SEID, bar->seid, 0))
			goto genlmsg_fail;
	}

	genlmsg_end(skb, genlh);
	return 0;
genlmsg_fail:
	genlmsg_cancel(skb, genlh);
	return -EMSGSIZE;
}
