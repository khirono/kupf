#include "dev.h"
#include "qer.h"
#include "pdr.h"
#include "seid.h"
#include "hash.h"

static char* seid_qer_id_to_hex_str(u64 seid_int, u32 qer_id)
{
	return seid_and_u32id_to_hex_str(seid_int, qer_id);
}

static void qer_context_free(struct rcu_head *head)
{
	struct qer *qer = container_of(head, struct qer, rcu_head);

	if (!qer)
		return;

	kfree(qer);
}

void qer_context_delete(struct qer *qer)
{
	struct upf_dev *upf = netdev_priv(qer->dev);
	struct hlist_head *head;
	struct pdr *pdr;
	char *seid_qer_id_hexstr;

	if (!qer)
		return;

	if (!hlist_unhashed(&qer->hlist_id))
		hlist_del_rcu(&qer->hlist_id);

	seid_qer_id_hexstr = seid_qer_id_to_hex_str(qer->seid, qer->id);
	head = &upf->related_qer_hash[str_hashfn(seid_qer_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(pdr, head, hlist_related_qer) {
		if (*pdr->qer_id == qer->id) {
			pdr->qer = NULL;
			unix_sock_client_delete(pdr);
		}
	}

	call_rcu(&qer->rcu_head, qer_context_free);
}
