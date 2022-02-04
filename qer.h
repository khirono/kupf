#ifndef QER_H__
#define QER_H__

#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/net.h>

struct qer {
	struct hlist_node hlist_id;
	u64 seid;
	u32 id;
	uint8_t ul_dl_gate;
	struct {
		uint32_t ul_high;
		uint8_t ul_low;
		uint32_t dl_high;
		uint8_t dl_low;
	} mbr;
	struct {
		uint32_t ul_high;
		uint8_t ul_low;
		uint32_t dl_high;
		uint8_t dl_low;
	} gbr;
	uint32_t qer_corr_id;
	uint8_t rqi;
	uint8_t qfi;
	uint8_t ppi;
	uint8_t rcsr;
	struct net_device *dev;
	struct rcu_head rcu_head;
};

extern void qer_context_delete(struct qer *);

#endif