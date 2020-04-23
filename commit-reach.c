	clear_commit_marks_many(nr_reference, reference, all_flags);
 */
	struct prio_queue queue = { compare_commits_by_gen_then_commit_date };

		if (oideq(&want->item->object.oid, &c->object.oid))
			/* Mark parents of a found merge stale */


				min_commit_date = to_iter->item->date;
			min_generation = reference[i]->generation;

		if (!parse_commit(to_iter->item)) {
	for (p = want; p; p = p->next) {

			redundant[i] = 1;
				continue;
	int i, j, filled;
			if (!(commit->object.flags & RESULT)) {
		 * If we just popped the stack, parents->item has been marked,


			if (p->object.flags & PARENT2)
int ref_newer(const struct object_id *new_oid, const struct object_id *old_oid)
		while (stack) {

			/*
	int ret = 0, i;
	free(filled_index);
	o = deref_tag(the_repository, parse_object(the_repository, new_oid),
	for (i = 0; i < cnt; i++)
		}
	struct commit **from_last = from + nr_from;
	uint32_t min_generation = GENERATION_NUMBER_INFINITY;

		clear_commit_marks(array[i], all_flags);
{
			parents = parents->next;
			break;
		case CONTAINS_YES:

			p->item->object.flags &= ~STALE;
	 * are independent from each other.
		int result;
		clear_commit_marks(from->item, PARENT1);
			parse_commit(p);
		from_one = deref_tag(the_repository, from_one,

	struct commit_list *result;
	}
					 struct commit *two)


	uint32_t cutoff = GENERATION_NUMBER_INFINITY;
				pop_commit(&stack);
	while (contains_stack.nr) {
			BUG("bad generation skip %8x > %8x at %s",
				pop_commit(&stack);

#include "tag.h"
			continue;
		       int cutoff_by_min_date)
			return result;

		if (flags == (PARENT1 | PARENT2)) {
					      struct commit **twos)
		}

		return 0;
				min_generation = from_iter->item->generation;
			return commit_list_insert(one, &result);
			if (in_merge_bases(other, commit))
	struct commit_list *result = reduce_heads(*heads);
#include "commit.h"
}

	for (p = heads, num_head = 0; p; p = p->next) {
	/* Now collect the result */
};
cleanup:
					 struct commit **to, int nr_to,
	while (from) {
		}
	}
				min_generation = to_iter->item->generation;


	}
	if (!with_commit)
			commit_list_insert(current, &found_commits);

	const struct commit_list *p;
					      work, min_generation);
			 */

	free(work);
	int nr_commits;
	cnt = commit_list_count(result);
		struct commit *commit = entry->commit;
		return ret;
		for (parents = current->parents; parents; parents = parents->next) {
	}
	return get_merge_bases_many_0(r, one, n, twos, 1);
{
	for (i = 0; i < n; i++) {
{
			else

}
}

	while (num_to_find && (current = prio_queue_get(&queue)) != NULL) {
		queue.compare = compare_commits_by_commit_date;
			prio_queue_put(&queue, p);
		if (!(commit->object.flags & STALE))
{
			if (p->generation < min_generation)
			 * this object anymore.
}
		ret = 1;
			 * looking at the ancestry chain alone, so
			continue;

	free(contains_stack.contains_stack);
	free(rslt);
	/* Otherwise, we don't know; prepare to recurse */
		from = from->next;
		}
static void push_to_contains_stack(struct commit *candidate, struct contains_stack *contains_stack)
	return result;
				redundant[filled_index[j]] = 1;
	time_t min_commit_date = cutoff_by_min_date ? from->item->date : 0;
	while (to) {
	result = contains_test(candidate, want, cache, cutoff);


	return 0;
	struct commit_list *from_iter = from, *to_iter = to;
{
int repo_in_merge_bases_many(struct repository *r, struct commit *commit,
		while (parents) {
	 */
	}
{

		if (one == twos[i])
	for (list = result, i = 0; list; list = list->next)
	struct commit **work;
				min_generation = array[j]->generation;
static const unsigned all_flags = (PARENT1 | PARENT2 | STALE | RESULT);

		to_iter = to_iter->next;
		from->objects[i].item->flags &= ~assign_flag;
		struct commit_list *common;
	int num_head, i;
	for (i = 0; i < n; i++) {
#include "commit-reach.h"
	result = can_all_from_reach_with_flag(&from_objs, PARENT2, PARENT1,
	commit_list_insert(old_commit, &old_commit_list);
		for (j = ret; j; j = j->next) {

static int queue_has_nonstale(struct prio_queue *queue)

			goto cleanup;
#include "revision.h"
	if (commit->object.flags & PARENT2)
	struct commit_list *i, *j, *k, *ret = NULL;
		struct commit *c = p->item;

			bases = get_merge_bases(i->item, j->item);
		if (repo_parse_commit(r, twos[i]))
	return get_merge_bases_many_0(r, one, 1, &two, 1);

			parse_commit(c);
	if (result != CONTAINS_UNKNOWN)
			if (to_iter->item->generation < min_generation)
int commit_contains(struct ref_filter *filter, struct commit *commit,
						int min_generation)
{
		if (one == twos[i])


			break;

	return get_merge_bases_many_0(r, one, n, twos, 0);
		struct commit_list *stack = NULL;
			struct commit *other;
				continue;
	}
	 * old_commit.  Otherwise we require --force.
					  const struct commit_list *want,
			continue;
			     int nr_reference, struct commit **reference)
						    struct commit **twos)
static int compare_commits_by_gen(const void *_a, const void *_b)
	struct commit_list *found_commits = NULL;
				}
		}
	}
{
	struct prio_queue queue = { compare_commits_by_gen_then_commit_date };
	one->object.flags |= PARENT1;
		if (!(c->object.flags & PARENT1)) {
	/*

		struct commit_list *parents;
		    list[nr_commits]->generation < min_generation) {
	return is_descendant_of(commit, list);

{
		if (reference[i]->generation < min_generation)
		return ret;
	/* Uniquify */

				return NULL;
				commit_list_insert_by_date(commit, &result);
	list = paint_down_to_common(r, one, n, twos, 0);
					  uint32_t cutoff)
	}
 */
	rslt = xcalloc(cnt, sizeof(*rslt));
		return -1;
				 unsigned int with_flag,
	clear_commit_marks_many(nr_commits, list, RESULT | assign_flag);
}
		nr_commits++;

				     nr_reference, reference,

			 * leave a note to ourselves not to worry about

		}
/* all input commits in one and twos[] must have been parsed! */
 */
		if (p->item->object.flags & STALE) {
			    commit->generation, last_gen,
	 * Some commit in the array may be an ancestor of

	return is_descendant_of(new_commit, old_commit_list);
	struct commit_list *list = NULL;
}
		parse_commit(c);
			return 1;
{
		}

		p->item->object.flags &= ~STALE;
	for (j = filled, i = 0; i < cnt; i++)
	}
}
			struct commit *reference)
				if (!(parent->item->object.flags & assign_flag)) {
		commit_list_insert_by_date(rslt[i], &result);
		while (with_commit) {

			min_generation = c->generation;
				return 1;
	struct commit *current;
					    struct commit **twos)
	return result;
				 uint32_t min_generation)
	prio_queue_put(&queue, one);
		if (c->generation < cutoff)

		add_object_array(&from_iter->item->object, NULL, &from_objs);

	free_commit_list(result);
	for (i = filled = 0; i < cnt; i++)
		if (c->generation < min_generation)
	uint32_t min_generation = GENERATION_NUMBER_INFINITY;
{
		return 0;
			if (i == j || redundant[j])
/*
			if (from_iter->item->date < min_commit_date)
		result = can_all_from_reach(from_list, with_commit, 0);

	/* There are more than one */
			struct commit *p = parents->item;
		 */

			    oid_to_hex(&commit->object.oid));
			num_to_find--;
				new_commits = bases;
			 * no way to tell if this is reachable by
		struct commit_list *parents = entry->parents;
	} *contains_stack;
	if (generation_numbers_enabled(the_repository)) {
	return found_commits;
		struct commit *c = *item;
	} else {
#include "commit-graph.h"
			array[j++] = work[i];
		}
	struct commit_list *list;
		load_commit_graph_info(the_repository, c);
{
		}

			from->objects[i].item->flags |= assign_flag;
			}
	parse_commit_or_die(candidate);
						  int cleanup)
	push_to_contains_stack(candidate, &contains_stack);

					 unsigned int reachable_flag)
{
					  struct contains_cache *cache,


	return result;
#include "tree.h"
		to = to->next;
}
		/*
			 */
				continue;


	struct commit **list = NULL;
	struct contains_stack contains_stack = { 0, 0, NULL };
	for (i = 0; i < queue->nr; i++) {
				     "a from object", 0);
#define STALE		(1u<<18)
			cutoff = c->generation;
	int i;

{
			c->object.flags |= PARENT2;
		return result;
	int result;
struct commit_list *get_octopus_merge_bases(struct commit_list *in)
#define RESULT		(1u<<19)

}
	uint32_t min_generation = GENERATION_NUMBER_INFINITY;
			work[filled++] = array[j];
						continue;
		if (current->object.flags & PARENT1) {
		case CONTAINS_NO:
	struct contains_stack_entry {
		if (redundant[i])

}

	/*
			c->object.flags |= PARENT1;
	return result;
		from_iter = from_iter->next;

					    parent->item->date < min_commit_date ||
			break;
	}
			}
	int i;
		free_commit_list(from_list);
int is_descendant_of(struct commit *commit, struct commit_list *with_commit)
}

	return repo_in_merge_bases_many(r, commit, 1, &reference);
			for (k = bases; k; k = k->next)
	for (p = heads, i = 0; p; p = p->next) {
		/* DFS from list[i] */
		struct commit *commit = queue->array[i].data;
	if (!o || o->type != OBJ_COMMIT)
		}
	while (queue_has_nonstale(&queue)) {
	}
			commit_list_insert_by_date(commit, &result);
int can_all_from_reach_with_flag(struct object_array *from,
 * ancestors are to be inspected.
	if (commit->generation > min_generation)

					      struct contains_cache *cache)



	bases = paint_down_to_common(r, commit,
	free(redundant);


	o = deref_tag(the_repository, parse_object(the_repository, old_oid),
		if (!redundant[i])
struct contains_stack {
 * Mimicking the real stack, this stack lives on the heap, avoiding stack
			entry->parents = parents->next;
			/*
	for (i = 0; i < nr_reference; i++) {
	int num_to_find = 0;
	clear_prio_queue(&queue);
		if (!(commit->object.flags & STALE))
}
	old_commit = (struct commit *) o;
	clear_commit_marks_many(n, twos, all_flags);

}
{
	return ret;
		if (redundant[i])
	COPY_ARRAY(work, array, cnt);
		struct commit *commit;
			}

					      struct commit *one,
struct commit_list *reduce_heads(struct commit_list *heads)
				continue;
{
int repo_in_merge_bases(struct repository *r,
					stack->item->object.flags |= RESULT;
	if (!in)
		clear_commit_marks(to->item, PARENT2);
	for (i = in->next; i; i = i->next) {
		twos[i]->object.flags |= PARENT2;
	nr_commits = 0;
				 unsigned int assign_flag,
	int result = 1;
				if (stack)
	}
	struct commit *old_commit, *new_commit;

}
	}
	return contains_test(candidate, want, cache, cutoff);
		if (!from_one || from_one->flags & assign_flag)
		free_commit_list(common);
		}
 * Test whether the candidate is contained in the list.
#include "decorate.h"
	}

				     commit->generation);
			contains_stack.nr--;
	return filled;
	struct commit **item;
 * Is "commit" an ancestor of one of the "references"?
	cnt = remove_redundant(r, rslt, cnt);

						  struct commit *one,
			if (stack->item->object.flags & (with_flag | RESULT)) {
			*contains_cache_at(cache, commit) = CONTAINS_NO;
	int nr, alloc;
	struct commit **rslt;
			push_to_contains_stack(parents->item, &contains_stack);
	struct commit_list *result = NULL;
	while (from_iter) {


		struct commit *commit = pop_commit(&list);
			if (repo_parse_commit(r, p))
			if (from_iter->item->generation < min_generation)
		}
		ret = new_commits;
				end->next = bases;
{
	if (a->generation > b->generation)
		repo_parse_commit(r, array[i]);
				end = k;
	 */


	enum contains_result *cached = contains_cache_at(cache, candidate);

	struct commit_list *old_commit_list = NULL;
	if (candidate->generation < cutoff)
		if (parse_commit(list[nr_commits]) ||
	if (!min_generation)
		return 0;

	if (*cached)

	for (; want; want = want->next)
		struct commit *c = *item;
	struct commit_list *result = NULL, **tail = &result;
/* Remember to update object flag allocation in object.h */
			current->object.flags &= ~PARENT1;
			prio_queue_put(&queue, *item);
		commit_list_append(one, &result);
		prio_queue_put(&queue, twos[i]);
 * Is "commit" an ancestor of (i.e. reachable from) the "reference"?
}
			 * have to clean it up.
		}
	}
		struct commit_list *new_commits = NULL, *end = NULL;

static struct commit_list *merge_bases_many(struct repository *r,
	if (!n) {
{

		struct commit_list *from_list = NULL;
		return result;
/*
			struct commit *p = parents->item;
		list[i]->object.flags |= assign_flag;


					      const struct commit_list *want,
	ALLOC_GROW(contains_stack->contains_stack, contains_stack->nr + 1, contains_stack->alloc);
		if (repo_parse_commit(r, reference[i]))
		if (!parse_commit(from_iter->item)) {


	struct commit_list *bases;
			struct commit_list *bases;
	 * Both new_commit and old_commit must be commit-ish and new_commit is descendant of
	if (in_commit_list(want, candidate)) {
}
	int i;
	contains_stack->contains_stack[contains_stack->nr++].parents = candidate->parents;
 */
					    struct commit *one, int n,
		*cached = CONTAINS_YES;
	const struct commit *b = *(const struct commit * const *)_b;
struct commit_list *repo_get_merge_bases_many(struct repository *r,
{
}
			break;
			return 1;
	return CONTAINS_UNKNOWN;
		if (!parents) {
		    struct commit_list *list, struct contains_cache *cache)
	if (a->generation < b->generation)
	array = xcalloc(num_head, sizeof(*array));
struct commit_list *repo_get_merge_bases_many_dirty(struct repository *r,
	int *filled_index;

	 * another commit.  Move such commit to the end of
		tail = &commit_list_insert(array[i], tail)->next;
			 * We do not mark this even with RESULT so we do not
		      NULL, 0);
			with_commit = with_commit->next;
		}
	}
	for (i = 0; i < nr_commits; i++) {

	if (filter->with_commit_tag_algo)

	object_array_clear(&from_objs);
}
	for (i = 0; i < cnt; i++) {
	if (!o || o->type != OBJ_COMMIT)
	for (i = 0; i < n; i++) {
#include "prio-queue.h"
						    struct commit *one,
	struct commit_list *p;
			for (parent = stack->item->parents; parent; parent = parent->next) {

			flags |= STALE;
	}
						struct commit **twos,
	result = merge_bases_many(r, one, n, twos);

	/* If we already have the answer cached, return that. */
		return ret;
	}
void reduce_heads_replace(struct commit_list **heads)



	new_commit = (struct commit *) o;
	free_commit_list(*heads);
}
#include "ref-filter.h"
					stack->item->object.flags |= RESULT;

static enum contains_result contains_test(struct commit *candidate,
	}
 * Is "commit" a descendant of one of the elements on the "with_commit" list?
		}
	ALLOC_ARRAY(list, from->nr);
	struct commit_list *result = NULL;
		last_gen = commit->generation;
					 struct commit *one,
		return CONTAINS_YES;

			goto cleanup;
	enum contains_result result;
		struct commit_list *parents;
				continue;
#define PARENT1		(1u<<16)
 * At each recursion step, the stack items points to the commits whose
		return NULL;
static struct commit_list *paint_down_to_common(struct repository *r,
					      min_commit_date, min_generation);
	}
	while (list) {
struct commit_list *repo_get_merge_bases(struct repository *r,
	}

			return NULL;
		flags = commit->object.flags & (PARENT1 | PARENT2 | STALE);

	clear_commit_marks_many(nr_to, to, PARENT1);
	if (!heads)
int can_all_from_reach(struct commit_list *from, struct commit_list *to,

}
	contains_stack->contains_stack[contains_stack->nr].commit = candidate;
	work = xcalloc(cnt, sizeof(*work));
{
}
			prio_queue_put(&queue, p);


		common = paint_down_to_common(r, array[i], filled,
	int i;
			p->object.flags |= PARENT2;
		parents = commit->parents;
		struct object *from_one = from->objects[i].item;
#define PARENT2		(1u<<17)
	}
	}
				if (parent->item->object.flags & (with_flag | RESULT))
		 * therefore contains_test will return a meaningful yes/no.
static enum contains_result contains_tag_algo(struct commit *candidate,
			filled_index[filled] = j;
			current->object.flags |= reachable_flag;
	clear_commit_marks(one, all_flags);
		}
	int cnt, i;
			contains_stack.nr--;
	return 0;
	for (item = to; item < to_last; item++) {
	if (repo_parse_commit(r, one))
	struct commit **to_last = to + nr_to;
/*
		if (p->item->object.flags & STALE)
	for (item = from; item < from_last; item++) {
/*
		rslt[i++] = list->item;
	free(array);
		return result;
	for (i = 0; i < from->nr; i++)
		p->item->object.flags |= STALE;
		for (j = 0; j < filled; j++)
	unsigned char *redundant;
	if (!result || !result->next) {
			continue;
 *
static int remove_redundant(struct repository *r, struct commit **array, int cnt)
			return ret;
		if (array[i]->object.flags & PARENT2)
static struct commit_list *get_merge_bases_many_0(struct repository *r,
struct commit_list *get_reachable_subset(struct commit **from, int nr_from,

		uint32_t min_generation = array[i]->generation;
			clear_commit_marks(one, all_flags);
		case CONTAINS_UNKNOWN:
	for (i = 0; i < num_head; i++)
		int flags;
	if (parse_commit(new_commit) < 0)
		return *cached;

			if (!new_commits)
		if (!from_one || from_one->type != OBJ_COMMIT) {
	for (i = 0; i < cnt; i++)
						    int n,
static int in_commit_list(const struct commit_list *want, struct commit *c)

	redundant = xcalloc(cnt, 1);
		struct commit *commit = prio_queue_get(&queue);
	clear_commit_marks(commit, all_flags);
	free(list);
			*contains_cache_at(cache, commit) = CONTAINS_YES;
			array[i++] = p->item;
	}
			array[filled++] = work[i];
					      int n,
 * Do not recurse to find out, though, but return -1 if inconclusive.
	struct object_array from_objs = OBJECT_ARRAY_INIT;
		if (commit->generation < min_generation)
}
	uint32_t last_gen = GENERATION_NUMBER_INFINITY;
}
			if (array[j]->generation < min_generation)
		return result;
		struct commit_list *parents;

		for (j = filled = 0; j < cnt; j++) {
		return CONTAINS_NO;
	result = NULL;

			clear_commit_marks_many(n, twos, all_flags);
	struct commit **array;
		return NULL;
		      NULL, 0);
	const struct commit *a = *(const struct commit * const *)_a;
		return 1;
	 * the array, and return the number of commits that
					parent->item->object.flags |= assign_flag;

		if (cleanup) {
	commit_list_insert(in->item, &ret);
				commit->object.flags |= RESULT;


#include "cache.h"




			p->object.flags |= flags;
				min_commit_date = from_iter->item->date;
	struct object *o;
						  int n,
		to_iter->item->object.flags |= PARENT2;
/*
		struct contains_stack_entry *entry = &contains_stack.contains_stack[contains_stack.nr - 1];
		commit_list_insert(list[i], &stack);
		return 0;
	for (i = 0; i < from->nr; i++) {
		if (!(list[i]->object.flags & (with_flag | RESULT))) {
			if (!parent)
		return contains_tag_algo(commit, list, cache) == CONTAINS_YES;
		commit_list_insert(commit, &from_list);
	}
		}
	num_head = remove_redundant(the_repository, array, num_head);
{
	while (to_iter) {
		if (!(c->object.flags & PARENT2)) {
}
	if (repo_parse_commit(r, commit))
			if (work[j]->object.flags & PARENT1)
	for (i = 0; i < n; i++) {
					commit_list_insert(parent->item, &stack);
			result = 0;
			if (to_iter->item->date < min_commit_date)
	clear_commit_marks_many(nr_from, from, PARENT2);
	}
		if (min_generation && commit->generation > last_gen)
	free_commit_list(bases);
					    parent->item->generation < min_generation)
		}



		clear_commit_marks_many(filled, work, all_flags);

			num_to_find++;
		list[nr_commits] = (struct commit *)from_one;
	}
	return ret;
					break;
						struct commit *one, int n,
			struct commit *commit,

						  struct commit **twos,
	return result;
			result = 0;
 * overflows.
					if (parse_commit(parent->item) ||
	*heads = result;

			if ((p->object.flags & flags) == flags)
	return result;

{
	ALLOC_ARRAY(filled_index, cnt - 1);
		return 1;
		num_head++;
	return 0;
		}
			struct commit_list *parent;
	/* or are we it? */
			other = with_commit->item;

				 time_t min_commit_date,
		else switch (contains_test(parents->item, want, cache, cutoff)) {
{
{
	QSORT(list, nr_commits, compare_commits_by_gen);
 */
	for (p = heads; p; p = p->next)
