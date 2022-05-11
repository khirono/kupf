#ifndef BAR_H__
#define BAR_H__

#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/net.h>

#include "dev.h"

struct bar {
	struct hlist_node hlist_id;
	u64 seid;
	u8 id;
	uint8_t delay;
	uint16_t count;
	struct net_device *dev;
	struct rcu_head rcu_head;
};

extern void bar_context_delete(struct bar *);
extern struct bar *find_bar_by_id(struct upf_dev *, u64, u32);
extern void bar_update(struct bar *, struct upf_dev *);
extern void bar_append(u64, u32, struct bar *, struct upf_dev *);
extern int bar_get_far_ids(u32 *, int, struct bar *, struct upf_dev *);
extern void bar_set_far(u64, u32, struct hlist_node *, struct upf_dev *);

#endif
