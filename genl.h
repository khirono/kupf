#ifndef UPF_GENL_H__
#define UPF_GENL_H__

#include <net/genetlink.h>

enum {
	UPF_CMD_UNSPEC,
	UPF_CMD_ADD_PDR,
	UPF_CMD_ADD_FAR,
	UPF_CMD_ADD_QER,
	UPF_CMD_DEL_PDR,
	UPF_CMD_DEL_FAR,
	UPF_CMD_DEL_QER,
	UPF_CMD_GET_PDR,
	UPF_CMD_GET_FAR,
	UPF_CMD_GET_QER,
	UPF_CMD_IND_DL_DATA,
};

enum {
	UPF_MCGRP_DATA,
};

/* common attributes */
enum {
	UPF_ATTR_LINK = 1,
	UPF_ATTR_NET_NS_FD,
	__UPF_ATTR_COMMON_MAX,
};
#define UPF_ATTR_MAX 0x10

extern struct genl_family upf_genl_family;

extern void notify(int);

#endif
