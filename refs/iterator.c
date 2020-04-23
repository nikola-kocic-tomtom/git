
			ref_iterator_abort(ref_iterator);
	}
		if ((selection & ITER_CURRENT_SELECTION_MASK) == 0) {
}
{
#include "iterator.h"
				   struct object_id *peeled)

}
	return ref_iterator;
}
				    struct object_id *peeled)
#include "refs/refs-internal.h"
/*
}
 */
struct ref_iterator *current_ref_iter = NULL;

	 * them.
static int prefix_ref_iterator_peel(struct ref_iterator *ref_iterator,

	free(iter);

					       int trim)

	iter->iter0 = iter0;
			iter->base.refname = iter->iter0->refname;
			 * can stop the iteration as soon as we see a

	return ref_iterator->vtable == &empty_ref_iterator_vtable;

	merge_ref_iterator_abort
};
	return ITER_DONE;
	struct merge_ref_iterator *iter =
int ref_iterator_abort(struct ref_iterator *ref_iterator)
void base_ref_iterator_free(struct ref_iterator *iter)
	iter->refname = NULL;
	if (!iter->current) {
void base_ref_iterator_init(struct ref_iterator *iter,
				goto error;
		}
	ref_iterator_abort(ref_iterator);
			 */
			continue;
{

			return ITER_OK;
	struct ref_iterator *ref_iterator = &iter->base;
#include "refs.h"

	}

		ok = ref_iterator_abort(iter->iter0);
}
	if (!back)
		iter->base.oid = iter->iter0->oid;
out:
		return iter0; /* optimization: no need to wrap iterator */

}
		if (iter->trim) {
	}
	iter->iter0 = iter0;
	void *cb_data;

		ref_iterator_select_fn *select, void *cb_data)
{
	struct prefix_ref_iterator *iter =
		if ((ok = ref_iterator_advance(iter->iter1)) != ITER_OK) {
	/*
/*
static int compare_prefix(const char *refname, const char *prefix)
	base_ref_iterator_init(ref_iterator, &empty_ref_iterator_vtable, 1);
			ok = ITER_ERROR;

		(struct prefix_ref_iterator *)ref_iterator;
	current_ref_iter = iter;
		if (ref_iterator_abort(iter->iter1) != ITER_DONE)

	iter->ordered = !!ordered;
			goto out;
		(struct merge_ref_iterator *)ref_iterator;

			 * we ignore that error in deference to the
		if (selection & ITER_SKIP_SECONDARY) {
		/* Initialize: advance both iterators to their first entries */
	iter->iter0 = NULL;
		}
		if (selection & ITER_YIELD_CURRENT) {

		struct ref_iterator *iter0, struct ref_iterator *iter1,
error:

		/*
		if (cmp < 0)
{
		return ITER_ERROR;
		if (selection == ITER_SELECT_DONE) {
	return ref_iterator;
			}

};
	int ok = ITER_DONE;
	return ref_iterator->vtable->abort(ref_iterator);
{
	/* Loop until we find an entry that we can yield. */
	while (1) {

		}

	empty_ref_iterator_advance,
	iter->select = select;
	empty_ref_iterator_peel,
				   struct object_id *peeled)
			 */
			/*
	char *prefix;
}
			if (ok == ITER_ERROR)
static struct ref_iterator_vtable empty_ref_iterator_vtable = {
		(struct merge_ref_iterator *)ref_iterator;
struct ref_iterator *overlay_ref_iterator_begin(
	if (!iter->current) {
			if (iter->iter0->ordered) {
static int empty_ref_iterator_peel(struct ref_iterator *ref_iterator,
			    int ordered)
	/*
	return ref_iterator_peel(iter->iter0, peeled);
{
{
	if (cmp < 0)
/* Return -1, 0, 1 if refname is before, inside, or after the prefix. */


			 * If ref_iterator_abort() returns ITER_ERROR,
{
	iter->prefix = xstrdup(prefix);
			 * It is nonsense to trim off characters that
		refname++;
		 */
struct empty_ref_iterator {
			secondary = &iter->iter0;
	return 0;
	 */
		return front ? ITER_SELECT_0 : ITER_SELECT_DONE;
			 * `iter0`). So if there wouldn't be at least
int ref_iterator_peel(struct ref_iterator *ref_iterator,
	if (ok == ITER_ERROR)

	cmp = strcmp(front->refname, back->refname);
}
{
 * overlay_ref_iterator_begin().

		BUG("peel called before advance for merge iterator");


	struct ref_iterator base;

	if (ref_iterator_abort(ref_iterator) != ITER_DONE)

}
			if (strlen(iter->iter0->refname) <= iter->trim)
 * A ref_iterator_select_fn that overlays the items from front on top
		if (retval) {
			iter->base.refname = (*iter->current)->refname;

	if (is_empty_ref_iterator(front)) {
			iter->current = &iter->iter0;
	iter->vtable = NULL;
		return ITER_SELECT_1;
	iter->cb_data = cb_data;
		prefix++;
	iter->oid = NULL;
	return ok;
		if (cmp > 0) {
 * of those from back (like loose refs over packed refs). See
		enum iterator_selection selection =
	}
}
		return back;


			*iter->current = NULL;
{
	 * Optimization: if one of the iterators is empty, return the
}
static struct ref_iterator_vtable merge_ref_iterator_vtable = {

	base_ref_iterator_free(ref_iterator);
		}
 * documentation about the design and use of reference iterators.
		if (*refname != *prefix)

			 * callback function's return value.
			iter->base.flags = (*iter->current)->flags;
{
		return ITER_SELECT_1;
				break;
		void *cb_data)
int ref_iterator_advance(struct ref_iterator *ref_iterator)

			if ((ok = ref_iterator_advance(*secondary)) != ITER_OK) {
	 * references through only if they exist in both iterators.
}
	return ref_iterator->vtable->peel(ref_iterator, peeled);
	if (!*prefix && !trim)
				goto error;
			} else {

			/*
static int prefix_ref_iterator_abort(struct ref_iterator *ref_iterator)
	struct prefix_ref_iterator *iter =
	/* Help make use-after-free bugs fail quickly: */
	merge_ref_iterator_advance,

}
	int retval = 0, ok;

	return ref_iterator_abort(ref_iterator);

		(struct prefix_ref_iterator *)ref_iterator;
	struct ref_iterator *ref_iterator = &iter->base;
};
		if (ref_iterator_abort(iter->iter0) != ITER_DONE)
	return merge_ref_iterator_begin(1, front, back,
		(struct prefix_ref_iterator *)ref_iterator;
		return -1;
	struct merge_ref_iterator *iter =
			    struct ref_iterator_vtable *vtable,
		} else {
			iter->base.oid = (*iter->current)->oid;
	 */
			 * one character left in the refname after
{
	struct ref_iterator *old_ref_iter = current_ref_iter;
static int merge_ref_iterator_peel(struct ref_iterator *ref_iterator,
	}
		BUG("overlay_ref_iterator requires ordered inputs");
}
	base_ref_iterator_free(ref_iterator);
		if ((ok = ref_iterator_advance(iter->iter0)) != ITER_OK) {
{
		return ITER_SELECT_0_SKIP_1;

					overlay_iterator_select, NULL);
{
	struct prefix_ref_iterator *iter =

		return front;

}

		}
	else if (cmp > 0)
		if ((ok = ref_iterator_advance(*iter->current)) != ITER_OK) {
		}
{
	ref_iterator_select_fn *select;

	else if (!front)
};
			if (ok == ITER_ERROR)
		ref_iterator_abort(back);

			 * If the source iterator is ordered, then we
					       const char *prefix,
	prefix_ref_iterator_advance,
		ref_iterator_abort(front);
	struct ref_iterator **current;
	base_ref_iterator_init(ref_iterator, &merge_ref_iterator_vtable, ordered);
	while (*prefix) {
	struct merge_ref_iterator *iter = xcalloc(1, sizeof(*iter));
			ref_iterator_abort(iter);

		} else {
#include "cache.h"
static int empty_ref_iterator_advance(struct ref_iterator *ref_iterator)
static enum iterator_selection overlay_iterator_select(

	} else if (!front->ordered || !back->ordered) {
			 */
		(struct merge_ref_iterator *)ref_iterator;

	iter = xcalloc(1, sizeof(*iter));
	iter->trim = trim;
	prefix_ref_iterator_abort
int is_empty_ref_iterator(struct ref_iterator *ref_iterator)
			 * `prefix_ref_iterator` or upstream in
	else
			if (ok == ITER_ERROR)
		struct ref_iterator **secondary;
		retval = fn(r, iter->refname, iter->oid, iter->flags, cb_data);
	empty_ref_iterator_abort

	 */
	return ok;
	prefix_ref_iterator_peel,
				continue;

			iter->iter0 = NULL;
	if (iter->iter0)
		return ITER_SELECT_0;
		iter->base.flags = iter->iter0->flags;
	iter->current = NULL;
	while ((ok = ref_iterator_advance(iter->iter0)) == ITER_OK) {
	iter->flags = 0;

		int ordered,
	struct prefix_ref_iterator *iter;
	int ok = ITER_DONE;
		 * entry:
	base_ref_iterator_free(ref_iterator);

		}


	 * It might, for example, implement "intersect" by passing
	current_ref_iter = old_ref_iter;
		struct ref_iterator *front, struct ref_iterator *back,
	struct ref_iterator base;
	return ref_iterator_peel(*iter->current, peeled);
	 * because we don't know the semantics of the select function.

};
static int prefix_ref_iterator_advance(struct ref_iterator *ref_iterator)
}
			iter->select(iter->iter0, iter->iter1, iter->cb_data);
	}
	if (iter->iter1) {

struct ref_iterator *prefix_ref_iterator_begin(struct ref_iterator *iter0,

	iter->vtable = vtable;
		} else if (selection == ITER_SELECT_ERROR) {


	} else if (is_empty_ref_iterator(back)) {
	free(iter->prefix);
	}
	ref_iterator = &iter->base;
	while ((ok = ref_iterator_advance(iter)) == ITER_OK) {
		struct ref_iterator *front, struct ref_iterator *back)
	 * optimization here as overlay_ref_iterator_begin() does,
	}
{
		}
	BUG("peel called for empty iterator");
struct merge_ref_iterator {
};
	if (iter->iter0) {
			 * prefix check, whether via this

	struct ref_iterator *iter0, *iter1;
static struct ref_iterator_vtable prefix_ref_iterator_vtable = {
static int empty_ref_iterator_abort(struct ref_iterator *ref_iterator)
	 * We can't do the same kind of is_empty_ref_iterator()-style
		}
struct ref_iterator *merge_ref_iterator_begin(

	struct ref_iterator *iter0;
	 * current value), or NULL if advance has not yet been called.
{
static int merge_ref_iterator_abort(struct ref_iterator *ref_iterator)
	 * other one rather than incurring the overhead of wrapping
}
		int cmp = compare_prefix(iter->iter0->refname, iter->prefix);
 * Generic reference iterator infrastructure. See refs-internal.h for
			 * trimming, report it as a bug:
}
					goto error;
	struct empty_ref_iterator *iter = xcalloc(1, sizeof(*iter));
{
{

		return ITER_OK;
int do_for_each_repo_ref_iterator(struct repository *r, struct ref_iterator *iter,
}
struct prefix_ref_iterator {
			 * you haven't already checked for via a
{
			iter->current = &iter->iter1;
		 * Advance the current iterator past the just-used
	int ok;
		      struct object_id *peeled)
	struct merge_ref_iterator *iter =
	}

	} else {
			/*
 */
			 * refname that comes after the prefix:
				BUG("attempt to trim too many characters");
	int cmp;
				if (ok == ITER_ERROR)
				ok = ref_iterator_abort(iter->iter0);
	return ok;
	 * A pointer to iter0 or iter1 (whichever is supplying the
}
	return ref_iterator;
			return ((unsigned char)*refname < (unsigned char)*prefix) ? -1 : +1;

				goto error;
	merge_ref_iterator_peel,
	base_ref_iterator_init(ref_iterator, &prefix_ref_iterator_vtable, iter0->ordered);

	return retval;
	iter->iter1 = iter1;
			ok = ITER_ERROR;
{
}
			secondary = &iter->iter1;
	return ITER_ERROR;
			iter->base.refname = iter->iter0->refname + iter->trim;
	int trim;
	int ok;
			}
		}
				*secondary = NULL;
			return ITER_ERROR;
}
				  each_repo_ref_fn fn, void *cb_data)
			return ref_iterator_abort(ref_iterator);
	struct ref_iterator *ref_iterator;
			iter->iter1 = NULL;


	/*
{
	struct ref_iterator base;
static int merge_ref_iterator_advance(struct ref_iterator *ref_iterator)
	return ref_iterator->vtable->advance(ref_iterator);
struct ref_iterator *empty_ref_iterator_begin(void)
