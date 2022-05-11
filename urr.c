#include <linux/rculist.h>

#include "dev.h"
#include "urr.h"
#include "pdr.h"
#include "seid.h"
#include "hash.h"

static char* seid_urr_id_to_hex_str(u64 seid_int, u32 urr_id)
{
	return seid_and_u32id_to_hex_str(seid_int, urr_id);
}

static void urr_context_free(struct rcu_head *head)
{
	struct urr *urr = container_of(head, struct urr, rcu_head);

	if (!urr)
		return;

	kfree(urr);
}

void urr_context_delete(struct urr *urr)
{
	struct upf_dev *upf = netdev_priv(urr->dev);
	struct hlist_head *head;
	struct pdr *pdr;
	char *seid_urr_id_hexstr;

	if (!urr)
		return;

	if (!hlist_unhashed(&urr->hlist_id))
		hlist_del_rcu(&urr->hlist_id);

	seid_urr_id_hexstr = seid_urr_id_to_hex_str(urr->seid, urr->id);
	head = &upf->related_urr_hash[str_hashfn(seid_urr_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(pdr, head, hlist_related_urr) {
		if (*pdr->urr_id == urr->id) {
			pdr->urr = NULL;
			unix_sock_client_delete(pdr);
		}
	}

	call_rcu(&urr->rcu_head, urr_context_free);
}

struct urr *find_urr_by_id(struct upf_dev *upf, u64 seid, u32 urr_id)
{
	struct hlist_head *head;
	struct urr *urr;
	char *seid_urr_id_hexstr;

	seid_urr_id_hexstr = seid_urr_id_to_hex_str(seid, urr_id);
	head = &upf->urr_id_hash[str_hashfn(seid_urr_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(urr, head, hlist_id) {
		if (urr->seid == seid && urr->id == urr_id)
			return urr;
	}

	return NULL;
}

void urr_update(struct urr *urr, struct upf_dev *upf)
{
	struct pdr *pdr;
	struct hlist_head *head;
	char *seid_urr_id_hexstr;

	seid_urr_id_hexstr = seid_urr_id_to_hex_str(urr->seid, urr->id);
	head = &upf->related_urr_hash[str_hashfn(seid_urr_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(pdr, head, hlist_related_urr) {
		if (*pdr->urr_id == urr->id) {
			pdr->urr = urr;
			unix_sock_client_update(pdr);
		}
	}
}

void urr_append(u64 seid, u32 urr_id, struct urr *urr, struct upf_dev *upf)
{
	char *seid_urr_id_hexstr;
	u32 i;

	seid_urr_id_hexstr = seid_urr_id_to_hex_str(seid, urr_id);
	i = str_hashfn(seid_urr_id_hexstr) % upf->hash_size;
	hlist_add_head_rcu(&urr->hlist_id, &upf->urr_id_hash[i]);
}

int urr_get_pdr_ids(u16 *ids, int n, struct urr *urr, struct upf_dev *upf)
{
	struct hlist_head *head;
	struct pdr *pdr;
	char *seid_urr_id_hexstr;
	int i;

	seid_urr_id_hexstr = seid_urr_id_to_hex_str(urr->seid, urr->id);
	head = &upf->related_urr_hash[str_hashfn(seid_urr_id_hexstr) % upf->hash_size];
	i = 0;
	hlist_for_each_entry_rcu(pdr, head, hlist_related_urr) {
		if (i >= n)
			break;
		if (*pdr->urr_id == urr->id)
			ids[i++] = pdr->id;
	}
	return i;
}

void urr_set_pdr(u64 seid, u32 urr_id, struct hlist_node *node, struct upf_dev *upf)
{
	char *seid_urr_id_hexstr;
	u32 i;

	if (!hlist_unhashed(node))
		hlist_del_rcu(node);

	seid_urr_id_hexstr = seid_urr_id_to_hex_str(seid, urr_id);
	i = str_hashfn(seid_urr_id_hexstr) % upf->hash_size;
	hlist_add_head_rcu(node, &upf->related_urr_hash[i]);
}
