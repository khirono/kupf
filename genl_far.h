#ifndef GENL_FAR_H__
#define GENL_FAR_H__

#include "genl.h"

/* FAR attributes */
enum {
	UPF_ATTR_FAR_ID = __UPF_ATTR_COMMON_MAX,
	UPF_ATTR_FAR_APPLY_ACTION,
	UPF_ATTR_FAR_FORWARDING_PARAMETER,
	UPF_ATTR_FAR_RELATED_TO_PDR,
	UPF_ATTR_FAR_SEID,
	__UPF_ATTR_FAR_MAX,
};
#define UPF_ATTR_FAR_MAX (__UPF_ATTR_FAR_MAX - 1)

/* FAR.Forwarding Parameter attributes */
enum {
	UPF_ATTR_FORWARDING_PARAMETER_UNSPEC,
	UPF_ATTR_FORWARDING_PARAMETER_OUTER_HEADER_CREATION,
	UPF_ATTR_FORWARDING_PARAMETER_FORWARDING_POLICY,
	__UPF_ATTR_FORWARDING_PARAMETER_MAX,
};
#define UPF_ATTR_FORWARDING_PARAMETER_MAX (__UPF_ATTR_FORWARDING_PARAMETER_MAX - 1)

/* FAR.Forwarding Parameter.Outer Header Creation attributes */
enum {
	UPF_ATTR_OUTER_HEADER_CREATION_UNSPEC,
	UPF_ATTR_OUTER_HEADER_CREATION_DESCRIPTION,
	UPF_ATTR_OUTER_HEADER_CREATION_O_TEID,
	UPF_ATTR_OUTER_HEADER_CREATION_PEER_ADDR_IPV4,
	UPF_ATTR_OUTER_HEADER_CREATION_PORT,
	__UPF_ATTR_OUTER_HEADER_CREATION_MAX,
};
#define UPF_ATTR_OUTER_HEADER_CREATION_MAX (__UPF_ATTR_OUTER_HEADER_CREATION_MAX - 1)

/* for kernel */
extern int upf_genl_add_far(struct sk_buff *, struct genl_info *);
extern int upf_genl_del_far(struct sk_buff *, struct genl_info *);
extern int upf_genl_get_far(struct sk_buff *, struct genl_info *);
extern int upf_genl_dump_far(struct sk_buff *, struct netlink_callback *);

#endif
