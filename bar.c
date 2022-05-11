#include <linux/rculist.h>

#include "dev.h"
#include "bar.h"
#include "far.h"
#include "seid.h"
#include "hash.h"

static char* seid_bar_id_to_hex_str(u64 seid_int, u32 bar_id)
{
	return seid_and_u32id_to_hex_str(seid_int, bar_id);
}

static void bar_context_free(struct rcu_head *head)
{
	struct bar *bar = container_of(head, struct bar, rcu_head);

	if (!bar)
		return;

	kfree(bar);
}

void bar_context_delete(struct bar *bar)
{
	struct upf_dev *upf = netdev_priv(bar->dev);
	struct hlist_head *head;
	struct far *far;
	char *seid_bar_id_hexstr;

	if (!bar)
		return;

	if (!hlist_unhashed(&bar->hlist_id))
		hlist_del_rcu(&bar->hlist_id);

	seid_bar_id_hexstr = seid_bar_id_to_hex_str(bar->seid, bar->id);
	head = &upf->related_bar_hash[str_hashfn(seid_bar_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(far, head, hlist_related_bar) {
		if (*far->bar_id == bar->id) {
			far->bar = NULL;
		}
	}

	call_rcu(&bar->rcu_head, bar_context_free);
}

struct bar *find_bar_by_id(struct upf_dev *upf, u64 seid, u32 bar_id)
{
	struct hlist_head *head;
	struct bar *bar;
	char *seid_bar_id_hexstr;

	seid_bar_id_hexstr = seid_bar_id_to_hex_str(seid, bar_id);
	head = &upf->bar_id_hash[str_hashfn(seid_bar_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(bar, head, hlist_id) {
		if (bar->seid == seid && bar->id == bar_id)
			return bar;
	}

	return NULL;
}

void bar_update(struct bar *bar, struct upf_dev *upf)
{
	struct far *far;
	struct hlist_head *head;
	char *seid_bar_id_hexstr;

	seid_bar_id_hexstr = seid_bar_id_to_hex_str(bar->seid, bar->id);
	head = &upf->related_bar_hash[str_hashfn(seid_bar_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(far, head, hlist_related_bar) {
		if (*far->bar_id == bar->id) {
			far->bar = bar;
		}
	}
}

void bar_append(u64 seid, u32 bar_id, struct bar *bar, struct upf_dev *upf)
{
	char *seid_bar_id_hexstr;
	u32 i;

	seid_bar_id_hexstr = seid_bar_id_to_hex_str(seid, bar_id);
	i = str_hashfn(seid_bar_id_hexstr) % upf->hash_size;
	hlist_add_head_rcu(&bar->hlist_id, &upf->bar_id_hash[i]);
}

int bar_get_far_ids(u32 *ids, int n, struct bar *bar, struct upf_dev *upf)
{
	struct hlist_head *head;
	struct far *far;
	char *seid_bar_id_hexstr;
	int i;

	seid_bar_id_hexstr = seid_bar_id_to_hex_str(bar->seid, bar->id);
	head = &upf->related_bar_hash[str_hashfn(seid_bar_id_hexstr) % upf->hash_size];
	i = 0;
	hlist_for_each_entry_rcu(far, head, hlist_related_bar) {
		if (i >= n)
			break;
		if (*far->bar_id == bar->id)
			ids[i++] = far->id;
	}
	return i;
}

void bar_set_far(u64 seid, u32 bar_id, struct hlist_node *node, struct upf_dev *upf)
{
	char *seid_bar_id_hexstr;
	u32 i;

	if (!hlist_unhashed(node))
		hlist_del_rcu(node);

	seid_bar_id_hexstr = seid_bar_id_to_hex_str(seid, bar_id);
	i = str_hashfn(seid_bar_id_hexstr) % upf->hash_size;
	hlist_add_head_rcu(node, &upf->related_bar_hash[i]);
}
