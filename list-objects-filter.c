	void *filter_data)
	struct oidmap seen_at_depth;
	struct repository *r,
#include "dir.h"

	void *filter_data_)
	unsigned long object_length;
	d->sub = xcalloc(d->nr, sizeof(*d->sub));
		t = oid_object_info(r, &obj->oid, &object_length);
static enum list_objects_filter_result process_subfilter(

{
 * include blobs that a sparse checkout would populate.
	struct list_objects_filter_options *filter_options,

	filter->filter_data = d;
	filter->free_fn = free;

	filter_blobs_limit__init,
		 * If there are NO provisionally omitted child objects (ALL child
	const char *pathname,
	struct object_id sparse_oid;
void list_objects_filter__free(struct filter *filter)
	if (add_patterns_from_blob_to_list(&sparse_oid, "", 0, &d->pl) < 0)
	return combined_result;
		frame = &filter_data->array_frame[filter_data->nr - 1];
			filter_res = LOFR_SKIP_TREE;
		enum list_objects_filter_situation filter_situation,
/*
static enum list_objects_filter_result filter_blobs_limit(
#include "oidmap.h"
{
	struct filter *filter;
		/*


		    oideq(&obj->oid, &sub->skip_tree))
	default:
						filter->filter_data);
	/* If non-NULL, the filter collects a list of the omitted OIDs here. */
	struct object *obj,
	filter->filter_data = d;
	case LOFS_BLOB:
		d->sub[sub].filter = list_objects_filter__init(
{
		if (!(sub_result & LOFR_MARK_SEEN))
	else
	if (filter->finalize_omits_fn && filter->omits)
struct frame {

		}
	struct filter_sparse_data *d = filter_data;
		enum list_objects_filter_result sub_result = process_subfilter(
			match = filter_data->array_frame[filter_data->nr - 1].default_match;
	free(d->array_frame);
	 * default_match is the usual default include/exclude value that
	size_t sub;
		if (obj->flags & FILTER_SHOWN_BUT_REVISIT)
		oidset_insert(dest, src_oid);
	filter->finalize_omits_fn = filter_combine__finalize_omits;

		const char *pathname,
	struct repository *r,
/* A filter which only shows objects shown by all sub-filters. */
static void filter_trees_free(void *filter_data) {

};
	size_t sub;
		 *
		 * that will prevent process_tree() from revisiting this
		}
	ALLOC_GROW(d->array_frame, d->nr + 1, d->alloc);
		die(_("unable to access sparse blob in '%s'"),
			 * and force show it (and let the caller deal with

			oidmap_put(&filter_data->seen_at_depth, seen_info);
		 * So we cannot mark this directory as SEEN (yet), since
		frame->child_prov_omit = 1;
		const char *filename,
#include "list-objects-filter.h"
 * the non-de-dup usage in pack-bitmap.c
		BUG("unknown filter_situation: %d", filter_situation);
	assert((sizeof(s_filters) / sizeof(s_filters[0])) == LOFC__COUNT);
	enum list_objects_filter_result result;
#include "tree.h"
	filter->filter_object_fn = filter_combine;
	case LOFS_END_TREE:
			BUG("expected oidset to be cleared already");
	 * 0 if everything (recursively) contained in this directory
		 * Leave the LOFR_ bits unset so that if the blob appears
			already_seen = 0;
	const char *filename,
	filter->free_fn = free;
	struct repository *r,
		oidset_clear(&d->sub[sub].omits);

static filter_init_fn s_filters[] = {

		assert(obj->type == OBJ_TREE);
	enum list_objects_filter_result (*filter_object_fn)(
	if (filter && (obj->flags & NOT_USER_GIVEN))
	struct combine_filter_data *d = filter_data;
	oidset_iter_init(src, &iter);
}
	struct filter *filter)
			already_seen =
		filter_data->nr++;
}
 * server.

	 */
	 * Note that we do not use _MARK_SEEN in order to allow re-traversal in
	if (omits)
	enum object_type t;
	struct object *obj,
 * is subtly different from the "revision.h:SHOWN" and the

	}

		assert(obj->type == OBJ_TREE);

	struct oidmap_entry base;

			combined_result &= ~LOFR_SKIP_TREE;
	/*
	return LOFR_MARK_SEEN | LOFR_DO_SHOW;
		 * Remember that at least 1 blob in this tree was
			/*
		seen_info = oidmap_get(
	void *filter_data_)
		 * provisionally omitted.
/* Remember to update object flag allocation in object.h */
};
	struct object *obj,
{
		return LOFR_ZERO;
	}


		return filter->filter_object_fn(r, filter_situation, obj,
		 */
	 *
	 * Maps trees to the minimum depth at which they were seen. It is not
		 * cutting the tree in future iterations.

	}

#include "tree-walk.h"
						  filename, &dtype, &filter_data->pl,
		filter->finalize_omits_fn(filter->omits, filter->filter_data);
	enum list_objects_filter_situation filter_situation,

		return LOFR_MARK_SEEN | LOFR_DO_SHOW;
}
	 * necessary to re-traverse a tree at deeper or equal depths than it has
	enum list_objects_filter_situation filter_situation,
 * A filter for list-objects to omit large blobs.
#include "object-store.h"
	filter->filter_data = d;
static enum list_objects_filter_result filter_trees_depth(

struct seen_map_entry {
	struct combine_filter_data *d = xcalloc(1, sizeof(*d));
	struct repository *r,
	if (!filter)

			combined_result &= ~LOFR_MARK_SEEN;
 */
 */
struct filter_sparse_data {
	struct subfilter *sub)
	/*
}
/* Returns 1 if the oid was in the omits set before it was invoked. */
		assert(obj->type == OBJ_TREE);
{

			seen_info->depth = filter_data->current_depth;
#include "blob.h"
	enum list_objects_filter_result combined_result =
	struct object_id *src_oid;
}
		add_all(omits, &d->sub[sub].omits);
	size_t sub;
static void filter_combine__finalize_omits(
#include "oidset.h"
{

	case LOFS_BEGIN_TREE:
		assert(filter_data->nr > 1);
	 */
#define FILTER_SHOWN_BUT_REVISIT (1<<21)
			&filter_options->sub[sub]);
		dtype = DT_DIR;
	struct filter_sparse_data *d = xcalloc(1, sizeof(*d));
	struct oidset *omits,
		if (object_length < filter_data->max_bytes)
	switch (filter_situation) {
	free(d->sub);
	struct oidset_iter iter;
	for (sub = 0; sub < d->nr; sub++) {
{

		 * with no other changes, so the OID is the same, but the
		 * may want to attempt to narrow this.
struct filter {
}
	void *filter_data;
		assert((obj->flags & SEEN) == 0);
}
	struct combine_filter_data *d = filter_data;
		sub->is_skipping_tree = 1;
			return LOFR_MARK_SEEN;
		 * objects in this folder were INCLUDED), then we can mark the
		 * tree object with other pathname prefixes.
	if (include_it)
	enum list_objects_filter_situation filter_situation,
			&d->sub[sub]);
		return LOFR_ZERO;

		if (!frame->child_prov_omit)
	return result;
	if (result & LOFR_MARK_SEEN)
		obj->flags |= FILTER_SHOWN_BUT_REVISIT;
	while ((src_oid = oidset_iter_next(&iter)) != NULL)
	enum pattern_match_result match;
static enum list_objects_filter_result filter_sparse(
	unsigned long current_depth;
#include "list-objects-filter-options.h"
	default:
	struct oidset *omits,
	/*
			seen_info->depth = filter_data->current_depth;
			oidset_insert(omits, &obj->oid);
	}
static void add_all(struct oidset *dest, struct oidset *src) {

		assert(obj->type == OBJ_TREE);
		oidset_remove(omits, &obj->oid);
 * let us silently de-dup calls to show() in the caller.  This

 *
	 * As such, the omits sets must be separate sets, and can only
	struct filter* filter)
 */
 * Must match "enum list_objects_filter_choice".
		    filter_options->sparse_oid_name);
	if (get_oid_with_context(the_repository,
	struct combine_filter_data *d = filter_data;
	const char *pathname,
{
	case LOFS_END_TREE:
	d->nr = filter_options->sub_nr;
				 GET_OID_BLOB, &sparse_oid, &oc))


		/*
static void filter_combine__free(void *filter_data)
		return filter_res;
					    filename, &dtype, &filter_data->pl,
	 *   b. A combine filter's omit set is the union of all its
	struct oidset *omits,
		filter_trees_update_omits(obj, omits, include_it);
	struct oidset *omitted,
		return LOFR_MARK_SEEN; /* but not LOFR_DO_SHOW (hard omit) */
	 * Optional. If this function is supplied and the filter needs

	/*
	d->exclude_depth = filter_options->tree_exclude_depth;
	 *
		} else {

}
		return oidset_insert(omits, &obj->oid);
	 * No filter is active or user gave object explicitly. In this case,
	unsigned long exclude_depth;
	struct filter_trees_depth_data *filter_data = filter_data_;

	filter->omits = omitted;
		 */
		filter_data->array_frame[filter_data->nr].child_prov_omit = 0;
	 * ordering is only theoretically important. Be cautious if you
	if (sub->is_skipping_tree) {
	enum list_objects_filter_situation filter_situation,
}
	case LOFS_BLOB:

	 * the directory may be short-cut later in the traversal.
	 *
		if (!d->sub[sub].is_skipping_tree)
	d->current_depth = 0;
/*
		 * Only _DO_SHOW the tree object the first time we visit
#include "list-objects.h"

static void filter_combine__init(
	filter = xcalloc(1, sizeof(*filter));
	init_fn = s_filters[filter_options->choice];
	free(d);
static enum list_objects_filter_result filter_blobs_none(
	case LOFS_BLOB:
			match = frame->default_match;
		 * this tree object.
 * in the traversal (until we mark it SEEN).  This is a way to
 */
	int include_it = filter_data->current_depth <
	void (*free_fn)(void *filter_data);
				/*

	struct oidset seen;
				filter_data->current_depth >= seen_info->depth;
	struct filter *filter)
		assert(obj->type == OBJ_TREE);
/*
	 * that is_skipping_tree gets unset even when the object is

		/* always include all tree objects */
	filter->free_fn = filter_trees_free;
	free(d);
			goto include_it;
	 * already been traversed.
			 * apply the size filter criteria.  Be conservative
		 */
		oidset_clear(&d->sub[sub].seen);

	struct filter *filter)
				oidset_remove(omits, &obj->oid);
						pathname, filename,
	struct object *obj,
}
		return oidset_remove(omits, &obj->oid);
	int filter_res;
#include "commit.h"
	struct oidset *omits,

	default:

{
		/*
	}
};
	filter->filter_object_fn = filter_blobs_none;
	enum list_objects_filter_situation filter_situation,

	oidmap_init(&d->seen_at_depth, 0);

	if (!init_fn)
	int include_it)
	if (filter_options->choice >= LOFC__COUNT)
	void *filter_data)
		 * Provisionally omit it.  We've already established that
}
	filter->free_fn = filter_sparse_free;

		if (omits)
	case LOFS_BEGIN_TREE:
	if (!d)
typedef void (*filter_init_fn)(
}
		if (match == MATCHED) {
	 *   a. A tree filter can add and remove objects as an object
	for (sub = 0; sub < d->nr; sub++) {

	return filter;
	filter_init_fn init_fn;
};
#include "revision.h"
	 * upon pattern matching of the directory itself or of a


		 * places in the tree. (Think of a directory move or copy,
};
	const char *pathname,
		} else {
	if (result & LOFR_SKIP_TREE) {
	int dtype;
			seen_info = xcalloc(1, sizeof(*seen_info));
static void filter_blobs_none__init(


		 * provisionally omitted.  This prevents us from short
	if (oidset_contains(&sub->seen, &obj->oid))
struct subfilter {
	struct oidset *omits,
	struct filter *filter)
/*

		BUG("unknown filter_situation: %d", filter_situation);
	filter->free_fn = filter_combine__free;
	 */
	 * free_fn is called.
	struct filter_sparse_data *filter_data = filter_data_;
			combined_result &= ~LOFR_DO_SHOW;
	filter->filter_object_fn = filter_sparse;
		 *
			 */
		BUG("unknown filter_situation: %d", filter_situation);
	}

		assert(obj->type == OBJ_BLOB);
	 * had already been shown when LOFS_BEGIN_TREE).

	struct repository *r,

	 * change the order of the below checks and more filters have
#include "diff.h"
	const char *pathname,
		return 0;
struct combine_filter_data {

		r, filter_situation, obj, pathname, filename, sub->filter);

	struct list_objects_filter_options *filter_options,
		if (!(sub_result & LOFR_DO_SHOW))
 * the repo may be bare or we may be doing the filtering on the
				 filter_options->sparse_oid_name,
		/*
{
	const char *pathname,
	 */
 * A filter for list-objects to omit ALL trees and blobs from the traversal.

		match = path_matches_pattern_list(pathname, strlen(pathname),
				 * Must update omit information of children
	 *      graph is traversed.
{

	 * marked as seen.  As of this writing, no filter uses
		filter_data->array_frame[filter_data->nr].default_match = match;
		return LOFR_ZERO;
		/*


		 * However, a pathname elsewhere in the tree may also
	free(filter);
enum list_objects_filter_result list_objects_filter__filter_object(
		match = path_matches_pattern_list(pathname, strlen(pathname),
	struct filter *filter);
{
			&filter_data->seen_at_depth, &obj->oid);
struct filter_trees_depth_data {
	 * Check and update is_skipping_tree before oidset_contains so
	filter->filter_object_fn = filter_trees_depth;
			return LOFR_ZERO;

	 * to collect omits, then this function is called once before
		assert(obj->type == OBJ_TREE);
		void *filter_data);
		sub->skip_tree = obj->oid;
 * "sha1-name.c:ONELINE_SEEN" bits.  And also different from
}
				filter_res = LOFR_SKIP_TREE;
 * Can OPTIONALLY collect a list of the omitted OIDs.

	unsigned long max_bytes;
{
struct filter_blobs_limit_data {
		return LOFR_ZERO;
					    r->index);
	struct oidset *omits;
			oidset_insert(omits, &obj->oid);
		 * A directory with this tree OID may appear in multiple
		 * and may match is_excluded() patterns differently.)
		 * with the CURRENT pathname, so we *WANT* to omit this blob.
 * The sparse-checkout spec can be loaded from a blob with the

	struct object *obj,
		if (d->sub[sub].omits.set.size)


	struct repository *r,
/*
	 * 1 if the directory (recursively) contains any provisionally
		assert((obj->flags & SEEN) == 0);
	 */
	size_t depth;
		if (match == UNDECIDED)
			oidset_insert(omits, &obj->oid);
	struct frame *frame;
	d->nr++;
{
		filter_data->current_depth--;
		return LOFR_DO_SHOW;
	 * been added!
	case LOFS_BEGIN_TREE:

	void (*finalize_omits_fn)(struct oidset *omits, void *filter_data);
		 */
		assert((obj->flags & SEEN) == 0);
			return LOFR_MARK_SEEN | LOFR_DO_SHOW;
	const char *filename,
	if (filter_situation == LOFS_END_TREE)
	struct list_objects_filter_options *filter_options,
		 *
}

	/*

		struct oidset *omits,
			r, filter_situation, obj, pathname, filename,
				filter_res = LOFR_ZERO;

		 * this pathname is not in the sparse-checkout specification
#include "cache.h"
		struct repository *r,
	}
}
		    filter_options->choice);
		BUG("invalid list-objects filter choice: %d",
	unsigned child_prov_omit : 1;
			if (include_it)
	/*
	struct oidset omits;
		 * full pathnames of objects within this directory are new
	const char *pathname,
		list_objects_filter__free(d->sub[sub].filter);


		return 0;
}

		LOFR_DO_SHOW | LOFR_MARK_SEEN | LOFR_SKIP_TREE;
		return include_it ? LOFR_MARK_SEEN | LOFR_DO_SHOW : LOFR_ZERO;
	const char *filename,
 * And to OPTIONALLY collect a list of the omitted OIDs.
};
		 * folder as SEEN (so we will not have to revisit it again).
	 */

	filter_combine__init,
	struct object *obj,

	struct oidset *omits,
	filter->free_fn(filter->filter_data);
			goto include_it;
	struct object *obj,
	d->max_bytes = filter_options->blob_limit_value;
		if (omits)
		 * again in the traversal, we will be asked again.
	struct object_context oc;
	 * be unioned after the traversal is completed.
}
	struct filter_blobs_limit_data *d = xcalloc(1, sizeof(*d));
{
	filter->filter_data = d;

	void *filter_data_)
		if (t != OBJ_BLOB) { /* probably OBJ_NONE */
		return;
		return LOFR_MARK_SEEN; /* but not LOFR_DO_SHOW (hard omit) */

						filter->omits,
static void filter_sparse_oid__init(
	struct filter_trees_depth_data *d = xcalloc(1, sizeof(*d));
			else if (omits && !been_omitted)
			int been_omitted = filter_trees_update_omits(
	struct filter_trees_depth_data *d = filter_data;
	if (!omits)
		return LOFR_MARK_SEEN | LOFR_DO_SHOW;
		filter_data->exclude_depth;

	const char *filename,
	enum list_objects_filter_situation filter_situation,
		return LOFR_ZERO;
		struct object *obj,
		return NULL;
		assert(obj->type == OBJ_TREE);
	struct subfilter *sub;
		if (match == UNDECIDED)
		filter_data->array_frame[filter_data->nr - 1].child_prov_omit |=
	filter_blobs_none__init,
	struct object_id skip_tree;
		 * Tell our parent directory if any of our children were
}
		else
}
	struct filter *filter)
		dtype = DT_REG;
	const char *pathname,
	return LOFR_MARK_SEEN | LOFR_DO_SHOW;
	struct object *obj,
}
				obj, omits, include_it);

			else
	for (sub = 0; sub < d->nr; sub++)

	size_t nr, alloc;
				filter_res = LOFR_DO_SHOW;
	d->array_frame[d->nr].default_match = 0; /* default to include */
	struct repository *r,

 * A filter driven by a sparse-checkout specification to only
	}
			filter->omits ? &d->sub[sub].omits : NULL,
		assert(obj->type == OBJ_BLOB);
	 *


				 * recursively; they have not been omitted yet.
};
	 * containing directory.
		return LOFR_ZERO;
			   filter_data->alloc);

	struct filter_blobs_limit_data *filter_data = filter_data_;

		oidset_insert(&sub->seen, &obj->oid);
	size_t sub;
		if (omits)
	filter->filter_object_fn = filter_blobs_limit;

	enum pattern_match_result default_match;
	 */
	 * should be inherited as we recurse into directories based
	struct seen_map_entry *seen_info;
	filter_sparse_oid__init,
	const char *filename,
		/* always include all tree objects */
struct filter *list_objects_filter__init(
	filter_trees_depth__init,
	 * it from being traversed at shallower depths.
	int already_seen;
	result = list_objects_filter__filter_object(
	switch (filter_situation) {
	 * We can't use LOFR_MARK_SEEN for tree objects since this will prevent
		return;
			sub->is_skipping_tree = 0;
	struct frame *array_frame;
static void filter_trees_depth__init(
	struct list_objects_filter_options *filter_options,
	const char *filename,
		if (already_seen) {
	 *
	void *filter_data_)
				 */
			 * We DO NOT have the blob locally, so we cannot
include_it:
};
		if (!seen_info) {
	case LOFS_BLOB:
#include "tag.h"
	/*
	case LOFS_END_TREE:
		if (filter_situation == LOFS_END_TREE &&
	switch (filter_situation) {
	struct pattern_list pl;
		 * We always show all tree objects.  A future optimization
	oidmap_free(&d->seen_at_depth, 1);
		ALLOC_GROW(filter_data->array_frame, filter_data->nr + 1,
 * FILTER_SHOWN_BUT_REVISIT -- we set this bit on tree objects
	default:
static void filter_blobs_limit__init(
	struct list_objects_filter_options *filter_options)
	init_fn(filter_options, filter);
	case LOFS_BEGIN_TREE:
			return LOFR_ZERO;
	d->array_frame[d->nr].child_prov_omit = 0;
		 */
{
	unsigned is_skipping_tree : 1;
	switch (filter_situation) {
		}

	for (sub = 0; sub < d->nr; sub++) {
		frame = &filter_data->array_frame[--filter_data->nr];
	 * omitted objects.
static void filter_sparse_free(void *filter_data)
static int filter_trees_update_omits(
		    oid_to_hex(&sparse_oid));


		filter_data->current_depth++;
		 * reference this same blob, so we cannot reject it yet.
static enum list_objects_filter_result filter_combine(
	 * case we encounter a tree or blob again at a shallower depth.
		assert(obj->type == OBJ_BLOB);
	struct oidset *omits,
{
						  r->index);
		die(_("unable to parse sparse filter data in %s"),
	 *      subfilters, which may include tree: filters.

		BUG("unknown filter_situation: %d", filter_situation);
	NULL,
	struct filter *filter;
};
	 * This is required because the following two conditions hold:

 * that have been shown, but should be revisited if they appear
 */
	struct list_objects_filter_options *filter_options,
			if (omits)
	size_t nr;
			 * the ambiguity).
			oidcpy(&seen_info->base.oid, &obj->oid);
	enum list_objects_filter_situation filter_situation,


			frame->child_prov_omit;
	 * has been explicitly included (SHOWN) in the result and
	 * LOFR_MARK_SEEN on trees that also uses LOFR_SKIP_TREE, so the
	const char *filename,
	case LOFS_END_TREE:
{
	}
		}
	struct list_objects_filter_options *filter_options,

	 * always show the object (except when LOFS_END_TREE, since this tree
 * given OID or from a local pathname.  We allow an OID because
