#include <linux/module.h>
#include <net/genetlink.h>

#include "genl.h"
#include "genl_pdr.h"
#include "genl_far.h"
#include "genl_qer.h"


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
		.dumpit = upf_genl_dump_pdr,
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
		.dumpit = upf_genl_dump_far,
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
		.dumpit = upf_genl_dump_qer,
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
