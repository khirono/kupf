#ifndef GENL_QER_H__
#define GENL_QER_H__

#include "genl.h"

/* QER attributes */
enum {
	UPF_ATTR_QER_ID = __UPF_ATTR_COMMON_MAX,
	UPF_ATTR_QER_GATE,
	UPF_ATTR_QER_MBR,
	UPF_ATTR_QER_GBR,
	UPF_ATTR_QER_CORR_ID,
	UPF_ATTR_QER_RQI,
	UPF_ATTR_QER_QFI,
	UPF_ATTR_QER_PPI,
	UPF_ATTR_QER_RCSR,
	UPF_ATTR_QER_RELATED_TO_PDR,
	UPF_ATTR_QER_SEID,
	__UPF_ATTR_QER_MAX,
};
#define UPF_ATTR_QER_MAX (__UPF_ATTR_QER_MAX - 1)

/* QER.MBR attributes */
enum {
	UPF_ATTR_QER_MBR_UNSPEC,
	UPF_ATTR_QER_MBR_UL_HIGH32,
	UPF_ATTR_QER_MBR_UL_LOW8,
	UPF_ATTR_QER_MBR_DL_HIGH32,
	UPF_ATTR_QER_MBR_DL_LOW8,
	__UPF_ATTR_QER_MBR_MAX,
};
#define UPF_ATTR_QER_MBR_MAX (__UPF_ATTR_QER_MBR_MAX - 1)

/* QER.GBR attributes */
enum {
	UPF_ATTR_QER_GBR_UNSPEC,
	UPF_ATTR_QER_GBR_UL_HIGH32,
	UPF_ATTR_QER_GBR_UL_LOW8,
	UPF_ATTR_QER_GBR_DL_HIGH32,
	UPF_ATTR_QER_GBR_DL_LOW8,
	__UPF_ATTR_QER_GBR_MAX,
};
#define UPF_ATTR_QER_GBR_MAX (__UPF_ATTR_QER_GBR_MAX - 1)

/* for kernel */
extern int upf_genl_add_qer(struct sk_buff *, struct genl_info *);
extern int upf_genl_del_qer(struct sk_buff *, struct genl_info *);
extern int upf_genl_get_qer(struct sk_buff *, struct genl_info *);
extern int upf_genl_dump_qer(struct sk_buff *, struct netlink_callback *);

#endif
