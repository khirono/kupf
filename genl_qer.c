#include <linux/module.h>
#include <net/genetlink.h>

#include "genl.h"
#include "genl_qer.h"


int upf_genl_add_qer(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

	return 0;
}

int upf_genl_del_qer(struct sk_buff *skb, struct genl_info *info)
{
	printk("<%s:%d> start\n", __func__, __LINE__);

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
