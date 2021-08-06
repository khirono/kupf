#include <linux/module.h>
#include <net/genetlink.h>

#include "genl.h"


void notify(int pdr_id)
{
	struct sk_buff *skb;
	void *data;

	printk("<%s:%d> start\n", __func__, __LINE__);

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return;

	data = genlmsg_put(skb, 0, 0, &upf_genl_family, 0,
			UPF_CMD_IND_DL_DATA);
	if (!data) {
		nlmsg_free(skb);
		return;
	}
	nla_put_u32(skb, 8, pdr_id);

	genlmsg_end(skb, data);
	genlmsg_multicast(&upf_genl_family, skb, 0, UPF_MCGRP_DATA, GFP_KERNEL);
}

static int parse_f_teid(struct nlattr *a)
{
	struct nlattr *attrs[UPF_F_TEID_ATTR_MAX + 1];
	u32 teid;
	u32 gtpu_addr;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_F_TEID_ATTR_MAX, a, NULL, NULL);
	if (err != 0) {
		return err;
	}

	if (attrs[UPF_F_TEID_ATTR_I_TEID]) {
		teid = htonl(nla_get_u32(attrs[UPF_F_TEID_ATTR_I_TEID]));
		printk("TEID: %u\n", teid);
	}

	if (attrs[UPF_F_TEID_ATTR_GTPU_ADDR_IPV4]) {
		gtpu_addr = nla_get_be32(attrs[UPF_F_TEID_ATTR_GTPU_ADDR_IPV4]);
		printk("GTP-U Addr: %08x\n", gtpu_addr);
	}

	return 0;
}

static int parse_sdf_filter(struct nlattr *a)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

static int parse_pdi(struct nlattr *a)
{
	struct nlattr *attrs[UPF_PDI_ATTR_MAX + 1];
	u32 ue_addr;
	int err;

	printk("<%s:%d> start\n", __func__, __LINE__);

	err = nla_parse_nested(attrs, UPF_PDI_ATTR_MAX, a, NULL, NULL);
	if (err != 0) {
		return err;
	}

	if (attrs[UPF_PDI_ATTR_UE_ADDR_IPV4]) {
		ue_addr = nla_get_be32(attrs[UPF_PDI_ATTR_UE_ADDR_IPV4]);
		printk("UE Addr: %08x\n", ue_addr);
	}

	if (attrs[UPF_PDI_ATTR_F_TEID]) {
		parse_f_teid(attrs[UPF_PDI_ATTR_F_TEID]);
	}

	if (attrs[UPF_PDI_ATTR_SDF_FILTER]) {
		parse_sdf_filter(attrs[UPF_PDI_ATTR_SDF_FILTER]);
	}

	return 0;
}

static int upf_genl_add_pdr(struct sk_buff *skb, struct genl_info *info)
{
	int ifindex;
	int netnsfd;
	u32 pdr_id;
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
	}
	printk("ifindex: %d\n", ifindex);

	if (info->attrs[UPF_ATTR_NET_NS_FD]) {
		netnsfd = nla_get_u32(info->attrs[UPF_ATTR_NET_NS_FD]);
	} else {
		netnsfd = -1;
	}
	printk("netnsfd: %d\n", netnsfd);

	if (info->attrs[UPF_ATTR_PDR_ID]) {
		pdr_id = nla_get_u32(info->attrs[UPF_ATTR_PDR_ID]);
		printk("PDR ID: %u\n", pdr_id);
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

	return 0;
}

static int upf_genl_del_pdr(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

static int upf_genl_get_pdr(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}


static int upf_genl_add_far(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

static int upf_genl_del_far(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

static int upf_genl_get_far(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}


static int upf_genl_add_qer(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

static int upf_genl_del_qer(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

static int upf_genl_get_qer(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}



#if defined(FEATURE_GENL_POLICY)
static const struct nla_policy upf_genl_pdr_policy[] = {
	[UPF_ATTR_PDR_ID]               = { .type = NLA_U32, },
	[UPF_ATTR_PDR_PRECEDENCE]       = { .type = NLA_U32, },
	[UPF_ATTR_PDR_PDI]              = { .type = NLA_NESTED, },
	[UPF_ATTR_OUTER_HEADER_REMOVAL] = { .type = NLA_U8, },
	[UPF_ATTR_PDR_FAR_ID]           = { .type = NLA_U32, },
	[UPF_ATTR_PDR_QER_ID]           = { .type = NLA_U32, },
};

static const struct nla_policy upf_genl_far_policy[] = {
	[UPF_ATTR_FAR_ID]           = { .type = NLA_U32, },
	[UPF_ATTR_FAR_APPLY_ACTION] = { .type = NLA_U8, },
	[UPF_ATTR_PDR_FORW_PARAM]   = { .type = NLA_NESTED, },
};

static const struct nla_policy upf_genl_qer_policy[] = {
	[UPF_ATTR_QER_ID]           = { .type = NLA_U32, },
	[UPF_ATTR_QER_GATE]         = { .type = NLA_U8, },
	[UPF_ATTR_QER_MBR]          = { .type = NLA_NESTED, },
	[UPF_ATTR_QER_GBR]          = { .type = NLA_NESTED, },
	[UPF_ATTR_QER_CORR_ID]      = { .type = NLA_U32, },
	[UPF_ATTR_QER_RQI]          = { .type = NLA_U8, },
	[UPF_ATTR_QER_QFI]          = { .type = NLA_U8, },
	[UPF_ATTR_QER_PPI]          = { .type = NLA_U8, },
};
#endif

static const struct genl_ops upf_genl_ops[] = {
	{
		.cmd = UPF_CMD_ADD_PDR,
		.doit = upf_genl_add_pdr,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_pdr_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_DEL_PDR,
		.doit = upf_genl_del_pdr,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_pdr_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_GET_PDR,
		.doit = upf_genl_get_pdr,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_pdr_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_ADD_FAR,
		.doit = upf_genl_add_far,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_far_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_DEL_FAR,
		.doit = upf_genl_del_far,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_far_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_GET_FAR,
		.doit = upf_genl_get_far,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_far_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_ADD_QER,
		.doit = upf_genl_add_qer,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_qer_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_DEL_QER,
		.doit = upf_genl_del_qer,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_qer_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UPF_CMD_GET_QER,
		.doit = upf_genl_get_qer,
#if defined(FEATURE_GENL_POLICY)
		.policy = upf_genl_qer_policy,
#endif
		.flags = GENL_ADMIN_PERM,
	},
};

static const struct genl_multicast_group upf_genl_mcgrps[] = {
	[UPF_MCGRP_DATA] = { .name = "data" },
};

struct genl_family upf_genl_family __ro_after_init = {
	.name     = "gtp5g",
	.version  = 1,
	.hdrsize  = 0,
	.maxattr  = UPF_ATTR_MAX,
	.netnsok  = true,
	.module   = THIS_MODULE,
	.ops      = upf_genl_ops,
	.n_ops    = ARRAY_SIZE(upf_genl_ops),
	.mcgrps   = upf_genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(upf_genl_mcgrps),
};
