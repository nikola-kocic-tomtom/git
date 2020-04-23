	negotiator->next = next;
			/* do not send "have", and ignore ancestors */
void default_negotiator_init(struct fetch_negotiator *negotiator)
#include "cache.h"
					parents;
	return 0;
static void add_tip(struct fetch_negotiator *n, struct commit *c)
static void known_common(struct fetch_negotiator *n, struct commit *c)
					    dont_parse);
/* Remember to update object flag allocation in object.h */
		} else if (commit->object.flags & COMMON_REF)
			mark = COMMON | SEEN;
		commit->object.flags |= POPPED;

}
	n->add_tip = NULL;
		int ancestors_only, int dont_parse)
	int known_to_be_common = !!(c->object.flags & COMMON);
static int marked;
		if (!(commit->object.flags & COMMON))
	if (o && o->type == OBJ_COMMIT)
			ns->non_common_revs--;
		}
			for (parents = commit->parents;
		parse_commit(commit);

	if (!(c->object.flags & SEEN)) {
#include "../commit.h"
	struct prio_queue rev_list;
/*

		if (parse_commit(commit))
	return &commit->object.oid;
		parents = commit->parents;
static const struct object_id *get_rev(struct negotiation_state *ns)
struct negotiation_state {
		if (ns->rev_list.nr == 0 || ns->non_common_revs == 0)
}
				if (parse_commit(commit))
			commit = NULL;
			/* send "have", also for its ancestors */
}


{



			if (mark & COMMON)
				rev_list_push(ns, parents->item, mark);
	struct object *o = deref_tag(the_repository, parse_object(the_repository, oid), refname, 0);

static void rev_list_push(struct negotiation_state *ns,
	negotiator->known_common = known_common;
{
#define POPPED		(1U << 5)
#include "../refs.h"
{
	negotiator->release = release;
		else

	struct commit *commit = NULL;
 * This function marks a rev and its ancestors as common.
	}
	while (commit == NULL) {
		if (!(commit->object.flags & COMMON))
			return;
		mark_common(n->data, c, 1, 1);
static int clear_marks(const char *refname, const struct object_id *oid,
	negotiator->data = ns = xcalloc(1, sizeof(*ns));
	return known_to_be_common;
	struct negotiation_state *ns;
		if (!ancestors_only)


#define COMMON_REF	(1U << 3)
{


			struct commit_list *parents;
		if (!(o->flags & SEEN))

static int ack(struct fetch_negotiator *n, struct commit *c)
 */
 * In some cases, it is desirable to mark only the ancestors (for example
	n->known_common = NULL;
	negotiator->add_tip = add_tip;
	}
					return;
#include "../tag.h"
				ns->non_common_revs--;
				mark_common(ns, parents->item, 1, 0);
		while (parents) {
}
			rev_list_push(ns, commit, SEEN);
		commit->object.flags |= mark;
		struct commit_list *parents;

	if (commit != NULL && !(commit->object.flags & COMMON)) {
{

			ns->non_common_revs++;
		struct object *o = (struct object *)commit;

					parents = parents->next)
}
			mark = COMMON | SEEN;
			parents = parents->next;

	if (!(commit->object.flags & mark)) {
#define COMMON		(1U << 2)
		rev_list_push(n->data, c, COMMON_REF | SEEN);
				   COMMON | COMMON_REF | SEEN | POPPED);
			  struct commit *commit, int mark)

	marked = 1;
		prio_queue_put(&ns->rev_list, commit);
static void mark_common(struct negotiation_state *ns, struct commit *commit,
		unsigned int mark;
	FREE_AND_NULL(n->data);
			o->flags |= COMMON;
#define SEEN		(1U << 4)
	int non_common_revs;
	rev_list_push(n->data, c, SEEN);
{
static void release(struct fetch_negotiator *n)
	if (marked)
#include "../prio-queue.h"
{
			if (!ancestors_only && !(o->flags & POPPED))
	}
}
	mark_common(n->data, c, 0, 1);
			/* send "have", and ignore ancestors */
}
	n->known_common = NULL;
 */
			if (!(parents->item->object.flags & SEEN))
			if (!o->parsed && !dont_parse)
		else {

		commit = prio_queue_get(&ns->rev_list);
}
	clear_prio_queue(&((struct negotiation_state *)n->data)->rev_list);

	}
		for_each_ref(clear_marks, NULL);
	negotiator->ack = ack;
		clear_commit_marks((struct commit *)o,

};
			return NULL;
{
 * Get the next rev to send, ignoring the common.

/*
{
			mark = SEEN;
static const struct object_id *next(struct fetch_negotiator *n)
				mark_common(ns, parents->item, 0,
#include "../fetch-negotiator.h"
}


}
#include "default.h"
	return get_rev(n->data);
{

		if (commit->object.flags & COMMON) {
		}
 * when only the server does not yet know that they are common).


		       int flag, void *cb_data)
	ns->rev_list.compare = compare_commits_by_commit_date;
