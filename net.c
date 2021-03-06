#include <linux/rculist.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "dev.h"
#include "net.h"
#include "link.h"


static unsigned int upf_net_id __read_mostly;


static int __net_init upf_net_init(struct net *net)
{
	struct upf_net *n = net_generic(net, upf_net_id);

	printk("<%s: %d> start\n", __func__, __LINE__);

	INIT_LIST_HEAD(&n->upf_dev_list);

	printk("upf_net_id: %u\n", upf_net_id);
	return 0;
}

static void __net_exit upf_net_exit(struct net *net)
{
	struct upf_net *n = net_generic(net, upf_net_id);

	printk("<%s: %d> start\n", __func__, __LINE__);

	upf_link_all_del(&n->upf_dev_list);
}

struct pernet_operations upf_net_ops = {
	.init = upf_net_init,
	.exit = upf_net_exit,
	.id   = &upf_net_id,
	.size = sizeof(struct upf_net),
};
