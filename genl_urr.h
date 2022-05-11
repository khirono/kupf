#ifndef GENL_URR_H__
#define GENL_URR_H__

#include "genl.h"

/* URR attributes */
enum {
	UPF_ATTR_URR_ID = __UPF_ATTR_COMMON_MAX,
	UPF_ATTR_URR_MEASUREMENT_METHOD,
	UPF_ATTR_URR_REPORTING_TRIGGER,
	UPF_ATTR_URR_MEASUREMENT_PERIOD,
	UPF_ATTR_URR_MEASUREMENT_INFO,
	UPF_ATTR_URR_SEQ,
	UPF_ATTR_URR_SEID,
	__UPF_ATTR_URR_MAX,
};
#define UPF_ATTR_URR_MAX (__UPF_ATTR_URR_MAX - 1)


/* for kernel */
extern int upf_genl_add_urr(struct sk_buff *, struct genl_info *);
extern int upf_genl_del_urr(struct sk_buff *, struct genl_info *);
extern int upf_genl_get_urr(struct sk_buff *, struct genl_info *);
extern int upf_genl_dump_urr(struct sk_buff *, struct netlink_callback *);

#endif
