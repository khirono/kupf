#include "dev.h"
#include "far.h"
#include "pdr.h"
#include "seid.h"
#include "hash.h"

static char *seid_far_id_to_hex_str(u64 seid_int, u32 far_id)
{
	return seid_and_u32id_to_hex_str(seid_int, far_id);
}

static void far_context_free(struct rcu_head *head)
{
	struct far *far = container_of(head, struct far, rcu_head);
	struct forwarding_parameter *fwd_param;

	if (!far)
		return;

	fwd_param = far->fwd_param;
	if (fwd_param) {
		if (fwd_param->hdr_creation)
			kfree(fwd_param->hdr_creation);
		if (fwd_param->fwd_policy)
			kfree(fwd_param->fwd_policy);
		kfree(fwd_param);
	}

	kfree(far);
}

void far_context_delete(struct far *far)
{
	struct upf_dev *upf = netdev_priv(far->dev);
	struct hlist_head *head;
	struct pdr *pdr;

	char *seid_far_id_hexstr;

	if (!far)
		return;

	if (!hlist_unhashed(&far->hlist_id))
		hlist_del_rcu(&far->hlist_id);

	seid_far_id_hexstr = seid_far_id_to_hex_str(far->seid, far->id);
	head = &upf->related_far_hash[str_hashfn(seid_far_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(pdr, head, hlist_related_far) {
		if (pdr->seid == far->seid && *pdr->far_id == far->id) {
			pdr->far = NULL;
			unix_sock_client_delete(pdr);
		}
	}

	call_rcu(&far->rcu_head, far_context_free);
}

struct far *find_far_by_id(struct upf_dev *upf, u64 seid, u32 far_id)
{
	struct hlist_head *head;
	struct far *far;
	char *seid_far_id_hexstr;

	seid_far_id_hexstr = seid_far_id_to_hex_str(seid, far_id);
	head = &upf->far_id_hash[str_hashfn(seid_far_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(far, head, hlist_id) {
		if (far->seid == seid && far->id == far_id)
			return far;
	}

	return NULL;
}
