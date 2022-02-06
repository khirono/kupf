#include <linux/rculist.h>

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

struct qer *find_qer_by_id(struct upf_dev *upf, u64 seid, u32 qer_id)
{
	struct hlist_head *head;
	struct qer *qer;
	char *seid_qer_id_hexstr;

	seid_qer_id_hexstr = seid_qer_id_to_hex_str(seid, qer_id);
	head = &upf->qer_id_hash[str_hashfn(seid_qer_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(qer, head, hlist_id) {
		if (qer->seid == seid && qer->id == qer_id)
			return qer;
	}

	return NULL;
}

void qer_update(struct qer *qer, struct upf_dev *upf)
{
	struct pdr *pdr;
	struct hlist_head *head;
	char *seid_qer_id_hexstr;

	seid_qer_id_hexstr = seid_qer_id_to_hex_str(qer->seid, qer->id);
	head = &upf->related_qer_hash[str_hashfn(seid_qer_id_hexstr) % upf->hash_size];
	hlist_for_each_entry_rcu(pdr, head, hlist_related_qer) {
		if (*pdr->qer_id == qer->id) {
			pdr->qer = qer;
			unix_sock_client_update(pdr);
		}
	}
}

void qer_append(u64 seid, u32 qer_id, struct qer *qer, struct upf_dev *upf)
{
	char *seid_qer_id_hexstr;
	u32 i;

	seid_qer_id_hexstr = seid_qer_id_to_hex_str(seid, qer_id);
	i = str_hashfn(seid_qer_id_hexstr) % upf->hash_size;
	hlist_add_head_rcu(&qer->hlist_id, &upf->qer_id_hash[i]);
}

int qer_get_pdr_ids(u16 *ids, int n, struct qer *qer, struct upf_dev *upf)
{
	struct hlist_head *head;
	struct pdr *pdr;
	char *seid_qer_id_hexstr;
	int i;

	seid_qer_id_hexstr = seid_qer_id_to_hex_str(qer->seid, qer->id);
	head = &upf->related_qer_hash[str_hashfn(seid_qer_id_hexstr) % upf->hash_size];
	i = 0;
	hlist_for_each_entry_rcu(pdr, head, hlist_related_qer) {
		if (i >= n)
			break;
		if (*pdr->qer_id == qer->id)
			ids[i++] = pdr->id;
	}
	return i;
}
