#ifndef GENL_BAR_H__
#define GENL_BAR_H__

#include "genl.h"

/* BAR attributes */
enum {
	UPF_ATTR_BAR_ID = __UPF_ATTR_COMMON_MAX,
	UPF_ATTR_BAR_DOWNLINK_DATA_NOTIFICATION_DELAY,
	UPF_ATTR_BAR_BUFFERING_PACKETS_COUNT,
	UPF_ATTR_BAR_SEID,
	__UPF_ATTR_BAR_MAX,
};
#define UPF_ATTR_BAR_MAX (__UPF_ATTR_BAR_MAX - 1)


/* for kernel */
extern int upf_genl_add_bar(struct sk_buff *, struct genl_info *);
extern int upf_genl_del_bar(struct sk_buff *, struct genl_info *);
extern int upf_genl_get_bar(struct sk_buff *, struct genl_info *);
extern int upf_genl_dump_bar(struct sk_buff *, struct netlink_callback *);

#endif
