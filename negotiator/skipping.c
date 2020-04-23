
		 * Find the existing entry and use it.


 * (because the entry for this commit had already been popped).
static const struct object_id *get_rev(struct data *data)
	 * The number of non-COMMON commits in rev_list.
}
{
	int non_common_revs;
		struct commit *commit;
 */
parent_found:
	if (!(mark & COMMON))
			/*
{
struct entry {
#include "../commit.h"
}
	data->rev_list.compare = compare;
	if (o && o->type == OBJ_COMMIT)
			to_send = commit;
/*
#include "skipping.h"
	struct data *data;
{
			? entry->original_ttl : entry->original_ttl * 3 / 2 + 1;
/*

		data->non_common_revs--;
		commit->object.flags |= POPPED;
	negotiator->add_tip = add_tip;

		for_each_ref(clear_marks, NULL);

			mark_common(data, p->item);
	return known_to_be_common;
		for (p = commit->parents; p; p = p->next)
	rev_list_push(n->data, c, ADVERTISED);
#define COMMON		(1U << 2)

static const struct object_id *next(struct fetch_negotiator *n)
	n->known_common = NULL;

	if (!c->object.parsed)
	entry = xcalloc(1, sizeof(*entry));
 */
 */
	const struct entry *b = b_;
}
			return NULL;
	prio_queue_put(&data->rev_list, entry);

			? entry->ttl - 1 : new_original_ttl;

		BUG("missing parent in priority queue");
			parent_entry->original_ttl = new_original_ttl;
void skipping_negotiator_init(struct fetch_negotiator *negotiator)
	return &to_send->object.oid;
	if (c->object.flags & SEEN)
		mark_common(data, to_push);
}
static void mark_common(struct data *data, struct commit *c)

		}
	const struct entry *a = a_;
 */
	/*


	return 0;
	FREE_AND_NULL(n->data);
	if (marked)
		commit = entry->commit;
		if (data->rev_list.nr == 0 || data->non_common_revs == 0)
struct data {
}
	clear_prio_queue(&((struct data *)n->data)->rev_list);
 * Both us and the server know that both parties have this object.
#define ADVERTISED	(1U << 3)

};
 * server that we have this object (or one of its descendants), but since we are
 */
	return entry;
		;
/*
{

/*
	commit->object.flags |= mark | SEEN;
	if (c->object.flags & COMMON)
	negotiator->ack = ack;


 * going to do that, we do not need to tell the server about its ancestors.
			data->non_common_revs--;
			return 0;
#include "cache.h"
		       int flag, void *cb_data)
	 */

static int ack(struct fetch_negotiator *n, struct commit *c)
	}
	if (!(c->object.flags & POPPED))
			parent_entry = data->rev_list.array[i].data;
	}
	while (to_send == NULL) {
 */
		uint16_t new_original_ttl = entry->ttl

		int parent_pushed = 0;
	/*

	} else {
	if (entry->commit->object.flags & (COMMON | ADVERTISED)) {
	n->add_tip = NULL;
	struct commit *commit;
 * This commit has left the priority queue.
{
#include "../prio-queue.h"

		data->non_common_revs++;

#define POPPED		(1U << 5)
			parent_entry->ttl = new_ttl;
/*
		struct commit_list *p;
	struct commit *to_send = NULL;
	if (!(c->object.flags & SEEN))
		if (p->item->object.flags & SEEN)
	for (p = c->parents; p; p = p->next) {
			 */
	struct commit_list *p;
	if (c->object.flags & SEEN)
}
			 * it anyway.
			parent_pushed |= push_parent(data, entry, p->item);
 * This function returns 1 if an entry was found or created, and 0 otherwise
{
/*
	return get_rev(n->data);
	return 1;
	rev_list_push(n->data, c, 0);
		if (!(commit->object.flags & COMMON) && !entry->ttl)
	struct prio_queue rev_list;
			to_send = commit;
static void add_tip(struct fetch_negotiator *n, struct commit *c)
	entry->commit = commit;
		parse_commit(commit);

		die("received ack for commit %s not sent as 'have'\n",
 * Mark this SEEN commit and all its SEEN ancestors as COMMON.

			 */
}

		return;
static void release(struct fetch_negotiator *n)
	marked = 1;
#include "../tag.h"
#define SEEN		(1U << 4)
		if (!(commit->object.flags & COMMON) && !parent_pushed)
{
			 * The entry for this commit has already been popped,
}
static void known_common(struct fetch_negotiator *n, struct commit *c)
	if (to_push->object.flags & SEEN) {
			 * This commit has no parents, or all of its parents
		if (!(commit->object.flags & COMMON))
	c->object.flags |= COMMON;
}
 * The server has told us that it has this object. We still need to tell the
{
		uint16_t new_ttl = entry->ttl
			 * have already been popped (due to clock skew), so send
static int marked;
		parent_entry = rev_list_push(data, to_push, 0);
		 */
	 * Used only if commit is not COMMON.
#include "../fetch-negotiator.h"
		return;
			/*
	negotiator->next = next;
	} else {

 * An entry in the priority queue.
		return;
	negotiator->known_common = known_common;

	struct entry *parent_entry;
}
	 */
		clear_commit_marks((struct commit *)o,
	uint16_t ttl;
		entry = prio_queue_get(&data->rev_list);
static struct entry *rev_list_push(struct data *data, struct commit *commit, int mark)
		/*
			 * exist.
static int compare(const void *a_, const void *b_, void *unused)
};
{
	int known_to_be_common = !!(c->object.flags & COMMON);
 * This commit has entered the priority queue.
static int clear_marks(const char *refname, const struct object_id *oid,
/* Remember to update object flag allocation in object.h */
	negotiator->release = release;
	negotiator->data = data = xcalloc(1, sizeof(*data));

 * Ensure that the priority queue has an entry for to_push, and ensure that the
#include "../refs.h"
		       struct commit *to_push)
		return;
		if (to_push->object.flags & POPPED)

				goto parent_found;


}
	uint16_t original_ttl;
 */

{
 *
	mark_common(n->data, c);
	struct entry *entry;

 * entry has the correct flags and ttl.

		struct entry *entry;
static int push_parent(struct data *data, struct entry *entry,
	struct object *o = deref_tag(the_repository, parse_object(the_repository, oid), refname, 0);
	return compare_commits_by_commit_date(a->commit, b->commit, NULL);
		if (parent_entry->original_ttl < new_original_ttl) {
		for (i = 0; i < data->rev_list.nr; i++) {
				   COMMON | ADVERTISED | SEEN | POPPED);
		int i;
/*
	n->known_common = NULL;
	}

		free(entry);
			 * due to clock skew. Pretend that this parent does not
		}
{
			if (parent_entry->commit == to_push)
		    oid_to_hex(&c->object.oid));
	}
{
}
