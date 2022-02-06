#include <linux/module.h>

#include "genl.h"
#include "link.h"
#include "net.h"

static int __init upf_init(void)
{
	int err;

	printk("<%s: %d> start\n", __func__, __LINE__);

	err = rtnl_link_register(&upf_link_ops);
	if (err) {
		printk("rtnl_link_register failed. %d\n", err);
		return err;
	}

	err = genl_register_family(&upf_genl_family);
	if (err) {
		printk("genl_register_family failed. %d\n", err);
		rtnl_link_unregister(&upf_link_ops);
		return err;
	}

	err = register_pernet_subsys(&upf_net_ops);
	if (err) {
		printk("register_parnet_subsys failed. %d\n", err);
		rtnl_link_unregister(&upf_link_ops);
		genl_unregister_family(&upf_genl_family);
		return err;
	}

	return 0;
}

static void __exit upf_exit(void)
{
	printk("<%s: %d> start\n", __func__, __LINE__);

	rtnl_link_unregister(&upf_link_ops);
	genl_unregister_family(&upf_genl_family);
	unregister_pernet_subsys(&upf_net_ops);
}

module_init(upf_init);
module_exit(upf_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Koji Hirono <koji.hirono.yh@apresiasystems.co.jp>");
MODULE_DESCRIPTION("UPF kernel module");
MODULE_ALIAS_GENL_FAMILY("gtp5g");
MODULE_ALIAS_RTNL_LINK("gtp5g");
