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

	if (info->attrs[UPF_ATTR_LINK]) {
		ifindex = nla_get_u32(info->attrs[UPF_ATTR_LINK]);
	} else {
		ifindex = -1;
		return -EINVAL;
	}
	printk("ifindex: %d\n", ifindex);

	if (info->attrs[UPF_ATTR_NET_NS_FD]) {
		netnsfd = nla_get_u32(info->attrs[UPF_ATTR_NET_NS_FD]);
	} else {
		netnsfd = -1;
	}
	printk("netnsfd: %d\n", netnsfd);

	rtnl_lock();
	rcu_read_lock();

	upf = upf_find_dev(sock_net(skb->sk), ifindex, netnsfd);
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

	if (!info->attrs[UPF_ATTR_LINK]) {
		return -EINVAL;
	}
	ifindex = nla_get_u32(info->attrs[UPF_ATTR_LINK]);
	printk("ifindex: %d\n", ifindex);

	if (info->attrs[UPF_ATTR_NET_NS_FD]) {
		netnsfd = nla_get_u32(info->attrs[UPF_ATTR_NET_NS_FD]);
	} else {
		netnsfd = -1;
	}
	printk("netnsfd: %d\n", netnsfd);

	rcu_read_lock();

	upf = upf_find_dev(sock_net(skb->sk), ifindex, netnsfd);
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
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

int upf_genl_dump_pdr(struct sk_buff *skb, struct netlink_callback *cb)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}


static int parse_pdi(struct nlattr *a)
{
	struct nlattr *attrs[UPF_ATTR_PDI_MAX + 1];
	u32 ue_addr;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_ATTR_PDI_MAX, a, NULL, NULL);
	if (err != 0) {
		return err;
	}

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
	if (err != 0) {
		return err;
	}

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
