

	/* Add all external refs */
{


	if (prepare_revision_walk(revs))

	revs->blob_objects = 1;
}
{
struct recent_data {
	if (bitmap_git) {
static void add_recent_object(const struct object_id *oid,
		 * we should abort, since we might then fail to mark objects
	object = parse_object_or_die(oid, path);
}
					   timestamp_t timestamp)
}
static void mark_object(struct object *obj, const char *name, void *data)
	 * Set up revision parsing, and mark us as being interested
	return 0;
		die("revision walk setup failed");
static int add_one_ref(const char *path, const struct object_id *oid,
	traverse_commit_list(revs, mark_commit, mark_object, &cp);
	data.timestamp = timestamp;
	for_each_ref(add_one_ref, revs);
};
		break;
		return 0;
	/* detached HEAD is not included in the list above */
			die("unable to mark recent objects");
	case OBJ_COMMIT:

#include "commit.h"
	case OBJ_TREE:
	struct object *obj;
	cp.count = 0;


	 * We do not want to call parse_object here, because
int add_unseen_recent_objects_to_traversal(struct rev_info *revs,
	r = for_each_loose_object(add_recent_loose, &data,
};
}

#include "packfile.h"
		return lookup_commit(r, oid);
	update_progress(data);
	 * later processing, and the revision machinery expects
}
			     uint32_t name_hash,
 * only need to handle any progress reporting here.
	 * in all object types, not just commits.

	struct connectivity_progress cp;
static void update_progress(struct connectivity_progress *cp)
	if (type < 0)
	mark_object(&c->object, NULL, data);
	struct object *obj = lookup_object(the_repository, oid);
		obj = parse_object_or_die(oid, NULL);
		revs->ignore_missing_links = 1;
		if (prepare_revision_walk(revs))
	if (mark_reflog)

	 */
		 * could be due to a simultaneous repack. But anything else


	 * Set up the revision walk - this will move all commits
		return r;
void mark_reachable_objects(struct rev_info *revs, int mark_reflog,

		obj = (struct object *)lookup_tree(the_repository, oid);
#include "diff.h"
#include "list-objects.h"
			return 0;

static int mark_object_seen(const struct object_id *oid,
{
			     void *data)
		return 0;
struct connectivity_progress {
	case OBJ_COMMIT:
	default:
	}
	/*
	}
	/*
	revs->tree_objects = 1;
			     enum object_type type,
	case OBJ_BLOB:

#include "tag.h"
	case OBJ_TREE:
#include "cache.h"
}
	add_pending_object(revs, object, "");
	data.revs = revs;
		return error_errno("unable to stat %s", oid_to_hex(oid));
		return;
	if (!obj)
	if (stat(path, &st) < 0) {

		return 0;
		traverse_commit_list(revs, mark_commit, mark_object, &cp);
				   enum object_type type)
	if (!obj)
			     off_t found_offset)
		    oid_to_hex(oid), type_name(type));
		if (errno == ENOENT)
{
	cp->count++;
			      timestamp_t mtime,

	struct progress *progress;
		die("unable to lookup %s", oid_to_hex(oid));
		return lookup_blob(r, oid);
	add_recent_object(oid, p->mtime, data);
	struct object *obj = lookup_object(the_repository, oid);
	 * from the pending list to the commit walking list.
#include "refs.h"
{
	if (r)
	 */
	if (mtime <= data->timestamp)
 */
	other_head_refs(add_one_ref, revs);
	cp.progress = progress;
		return;

{
	struct bitmap_index *bitmap_git;
		return lookup_tag(r, oid);
	return for_each_packed_object(add_recent_packed, &data,

	}
	/* Add all reflog info */
		return lookup_tree(r, oid);


	switch (type) {
	unsigned long count;
	add_pending_object(data->revs, obj, "");
}




	add_index_objects_to_pending(revs, 0);
	 * inflating blobs and trees could be very expensive.
static int add_recent_packed(const struct object_id *oid,
 * The traversal will have already marked us as SEEN, so we
	/* Add all refs from the index file */
#include "reachable.h"
#include "cache-tree.h"
			      struct recent_data *data)
{
	}
static void mark_commit(struct commit *c, void *data)

}
}
		display_progress(cp->progress, cp->count);

	switch (type) {
	if (mark_recent) {
		 * It's OK if an object went away during our iteration; this
	if (obj && obj->flags & SEEN)
	bitmap_git = prepare_bitmap_walk(revs, NULL);
	obj->flags |= SEEN;

	return 0;
	display_progress(cp.progress, cp.count);
#include "pack-bitmap.h"


		traverse_bitmap_commit_list(bitmap_git, revs, mark_object_seen);
		 */
	if ((cp->count & 1023) == 0)
	struct rev_info *revs = (struct rev_info *)cb_data;
#include "object-store.h"
			    timestamp_t mark_recent, struct progress *progress)
	 */
	if (obj && obj->flags & SEEN)

{
	head_ref(add_one_ref, revs);
	if ((flag & REF_ISSYMREF) && (flag & REF_ISBROKEN)) {
static int add_recent_loose(const struct object_id *oid,
		break;
			     int exclude,
		add_reflogs_to_pending(revs, 0);
		/*
		die("BUG: unknown object type %d", type);
static void *lookup_object_by_type(struct repository *r,
	enum object_type type;
		die("unable to create object '%s'", oid_to_hex(oid));
	add_recent_object(oid, st.st_mtime, data);
		break;
	type = oid_object_info(the_repository, oid, NULL);
}
#include "blob.h"
	revs->tag_objects = 1;
		if (add_unseen_recent_objects_to_traversal(revs, mark_recent))
				   const struct object_id *oid,
#include "progress.h"
		 * which should not be pruned.


/*
	return 0;

	struct stat st;
}
	}
	struct object *object;

	case OBJ_TAG:
			     struct packed_git *p, uint32_t pos,
#include "revision.h"
	}
		       int flag, void *cb_data)

{

	/*
	struct rev_info *revs;
			     struct packed_git *found_pack,
	struct object *obj = lookup_object_by_type(the_repository, oid, type);
		die("unable to get object info for %s", oid_to_hex(oid));
				      FOR_EACH_OBJECT_LOCAL_ONLY);
		die("unknown object type for %s: %s",
	case OBJ_BLOB:
	timestamp_t timestamp;
	struct recent_data data;
	 * However, we do need to know the correct type for
	int r;
			die("revision walk setup failed");
#include "worktree.h"
			    const char *path, void *data)
		obj = (struct object *)lookup_blob(the_repository, oid);
		warning("symbolic ref is dangling: %s", path);
				  FOR_EACH_OBJECT_LOCAL_ONLY);
	return 0;
	default:
	case OBJ_TAG:
	 * commits and tags to have been parsed.
		free_bitmap_index(bitmap_git);
{
{
