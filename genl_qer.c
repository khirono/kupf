#include <net/genetlink.h>
#include <net/sock.h>

#include "dev.h"
#include "genl.h"
#include "genl_qer.h"
#include "qer.h"


int upf_genl_add_qer(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

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

	upf = upf_find_dev(sock_net(skb->sk), ifindex, netnsfd);
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
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

int upf_genl_dump_qer(struct sk_buff *skb, struct netlink_callback *cb)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}
