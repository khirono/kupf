#ifndef GENL_PDR_H__
#define GENL_PDR_H__

#include "genl.h"

/* PDR attributes */
enum {
	UPF_ATTR_PDR_ID = __UPF_ATTR_COMMON_MAX,
	UPF_ATTR_PDR_PRECEDENCE,
	UPF_ATTR_PDR_PDI,
	UPF_ATTR_OUTER_HEADER_REMOVAL,
	UPF_ATTR_PDR_FAR_ID,
	UPF_ATTR_PDR_ROLE_ADDR_IPV4, /* deprecated */
	UPF_ATTR_PDR_UNIX_SOCKET_PATH, /* deprecated */
	UPF_ATTR_PDR_QER_ID,
	UPF_ATTR_PDR_SEID,
	__UPF_ATTR_PDR_MAX,
};
#define UPF_ATTR_PDR_MAX (__UPF_ATTR_PDR_MAX - 1)

/* PDR.PDI attributes */
enum {
	UPF_ATTR_PDI_UNSPEC,
	UPF_ATTR_PDI_UE_ADDR_IPV4,
	UPF_ATTR_PDI_F_TEID,
	UPF_ATTR_PDI_SDF_FILTER,
	__UPF_ATTR_PDI_MAX,
};
#define UPF_ATTR_PDI_MAX (__UPF_ATTR_PDI_MAX - 1)

/* PDR.PDI.F-TEID attributes */
enum {
	UPF_ATTR_F_TEID_UNSPEC,
	UPF_ATTR_F_TEID_I_TEID,
	UPF_ATTR_F_TEID_GTPU_ADDR_IPV4,
	__UPF_ATTR_F_TEID_MAX,
};
#define UPF_ATTR_F_TEID_MAX (__UPF_ATTR_F_TEID_MAX - 1)

/* PDR.PDI.SD Filer attributes */
enum {
	UPF_ATTR_SDF_FILTER_UNSPEC,
	UPF_ATTR_SDF_FILTER_FLOW_DESCRIPTION,
	UPF_ATTR_SDF_FILTER_TOS_TRAFFIC_CLASS,
	UPF_ATTR_SDF_FILTER_SECURITY_PARAMETER_INDEX,
	UPF_ATTR_SDF_FILTER_FLOW_LABEL,
	UPF_ATTR_SDF_FILTER_SDF_FILTER_ID,
	__UPF_ATTR_SDF_FILTER_MAX,
};
#define UPF_ATTR_SDF_FILTER_MAX (__UPF_ATTR_SDF_FILTER_MAX - 1)

/* PDR.PDI.SD Filter.Flow Description attributes */
enum {
	UPF_ATTR_FLOW_DESCRIPTION_UNSPEC,
	UPF_ATTR_FLOW_DESCRIPTION_ACTION,
	UPF_ATTR_FLOW_DESCRIPTION_DIRECTION,
	UPF_ATTR_FLOW_DESCRIPTION_PROTOCOL,
	UPF_ATTR_FLOW_DESCRIPTION_SRC_IPV4,
	UPF_ATTR_FLOW_DESCRIPTION_SRC_MASK,
	UPF_ATTR_FLOW_DESCRIPTION_DEST_IPV4,
	UPF_ATTR_FLOW_DESCRIPTION_DEST_MASK,
	UPF_ATTR_FLOW_DESCRIPTION_SRC_PORT,
	UPF_ATTR_FLOW_DESCRIPTION_DEST_PORT,
	__UPF_ATTR_FLOW_DESCRIPTION_MAX,
};
#define UPF_ATTR_FLOW_DESCRIPTION_MAX (__UPF_ATTR_FLOW_DESCRIPTION_MAX - 1)

/* for kernel */
extern int upf_genl_add_pdr(struct sk_buff *, struct genl_info *);
extern int upf_genl_del_pdr(struct sk_buff *, struct genl_info *);
extern int upf_genl_get_pdr(struct sk_buff *, struct genl_info *);
extern int upf_genl_dump_pdr(struct sk_buff *, struct netlink_callback *);

#endif
