#include "dev.h"
#include "pdr.h"
#include "seid.h"
#include "hash.h"

static char *seid_pdr_id_to_hex_str(u64 seid_int, u16 pdr_id)
{
	return seid_and_u32id_to_hex_str(seid_int, (u32)pdr_id);
}

static void pdr_context_free(struct rcu_head *head)
{
	struct pdr *pdr = container_of(head, struct pdr, rcu_head);
	struct pdi *pdi;
	struct sdf_filter *sdf;

	if (!pdr)
		return;

	sock_put(pdr->sk);

	if (pdr->outer_header_removal)
		kfree(pdr->outer_header_removal);

	pdi = pdr->pdi;
	if (pdi) {
		if (pdi->ue_addr_ipv4)
			kfree(pdi->ue_addr_ipv4);
		if (pdi->f_teid)
			kfree(pdi->f_teid);
		if (pdr->far_id)
			kfree(pdr->far_id);
		if (pdr->qer_id)
			kfree(pdr->qer_id);

		sdf = pdi->sdf;
		if (sdf) {
			if (sdf->rule) {
				if (sdf->rule->sport)
					kfree(sdf->rule->sport);
				if (sdf->rule->dport)
					kfree(sdf->rule->dport);
				kfree(sdf->rule);
			}
			if (sdf->tos_traffic_class)
				kfree(sdf->tos_traffic_class);
			if (sdf->security_param_idx)
				kfree(sdf->security_param_idx);
			if (sdf->flow_label)
				kfree(sdf->flow_label);
			if (sdf->bi_id)
				kfree(sdf->bi_id);

			kfree(sdf);
		}
		kfree(pdi);
	}

	unix_sock_client_delete(pdr);
	kfree(pdr);
}

void pdr_context_delete(struct pdr *pdr)
{
	if (!pdr)
		return;

	if (!hlist_unhashed(&pdr->hlist_id))
		hlist_del_rcu(&pdr->hlist_id);

	if (!hlist_unhashed(&pdr->hlist_i_teid))
		hlist_del_rcu(&pdr->hlist_i_teid);

	if (!hlist_unhashed(&pdr->hlist_addr))
		hlist_del_rcu(&pdr->hlist_addr);

	if (!hlist_unhashed(&pdr->hlist_related_far))
		hlist_del_rcu(&pdr->hlist_related_far);

	if (!hlist_unhashed(&pdr->hlist_related_qer))
		hlist_del_rcu(&pdr->hlist_related_qer);

	call_rcu(&pdr->rcu_head, pdr_context_free);
}

// Delete the AF_UNIX client
void unix_sock_client_delete(struct pdr *pdr)
{
	if (pdr->sock_for_buf)
		sock_release(pdr->sock_for_buf);

	pdr->sock_for_buf = NULL;
}

struct pdr *find_pdr_by_id(struct upf_dev *upf, u64 seid, u16 pdr_id)
{
	struct hlist_head *head;
	struct pdr *pdr;
	char *seid_pdr_id;

	seid_pdr_id = seid_pdr_id_to_hex_str(seid, pdr_id);
	head = &upf->pdr_id_hash[str_hashfn(seid_pdr_id) % upf->hash_size];
	hlist_for_each_entry_rcu(pdr, head, hlist_id) {
		if (pdr->seid == seid && pdr->id == pdr_id)
			return pdr;
	}

	return NULL;
}
