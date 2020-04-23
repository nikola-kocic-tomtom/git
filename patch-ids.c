	struct patch_id *key;

	if (!patch_id_defined(commit))
	hashmap_entry_init(&patch->ent, oidhash(&header_only_patch_id));
{
	    commit_patch_id(a->commit, opt, &a->patch_id, 0, 0))
}
			      &commit->object.oid, "", options);
	diff_setup_done(&ids->diffopts);
		return NULL;

	diffcore_std(options);

 * When we cannot load the full patch-id for both commits for whatever
	/* NEEDSWORK: const correctness? */
	memset(&patch, 0, sizeof(patch));
#include "patch-ids.h"
 * the side of safety.  The actual value being negative does not have
	if (is_null_oid(&b->patch_id) &&
	hashmap_init(&ids->patches, patch_id_neq, &ids->diffopts, 256);

	repo_diff_setup(r, &ids->diffopts);
#include "diff.h"
	struct patch_id patch;
		return -1;
static int patch_id_defined(struct commit *commit)
		return NULL;
			oid_to_hex(&a->commit->object.oid));

	return hashmap_get_entry(&ids->patches, &patch, ent, NULL);
		return NULL;
 * reason, the function returns -1 (i.e. return error(...)). Despite
int init_patch_ids(struct repository *r, struct patch_ids *ids)
	struct diff_options *opt = (void *)cmpfn_data;
struct patch_id *add_commit_patch_id(struct commit *commit,

	return !commit->parents || !commit->parents->next;
	return 0;
	struct patch_id *a, *b;
#include "cache.h"
	}
}
static int init_patch_id_entry(struct patch_id *patch,
	else
	if (!patch_id_defined(commit))
#include "sha1-lookup.h"
}
	if (commit->parents)

		return error("Could not get patch ID for %s",
			const struct hashmap_entry *eptr,
	struct object_id header_only_patch_id;

{
				     struct patch_ids *ids)

 * the "neq" in the name of this function, the caller only cares about

		return NULL;
			oid_to_hex(&b->commit->object.oid));
	ids->diffopts.flags.recursive = 1;

 * and b are different), and returning non-zero would keep both in the
		    struct object_id *oid, int diff_header_only, int stable)

 * result, even if they actually were equivalent, in order to err on
int commit_patch_id(struct commit *commit, struct diff_options *options,
	return key;
{
			       struct commit *commit,

	hashmap_add(&ids->patches, &key->ent);


	if (init_patch_id_entry(key, commit, ids)) {

 * any significance; only that it is non-zero matters.
		free(key);
			const void *unused_keydata)

{
{
 * the return value being zero (a and b are equivalent) or non-zero (a
		diff_root_tree_oid(&commit->object.oid, "", options);
#include "commit.h"
	ids->diffopts.detect_rename = 0;
}
	if (!patch_id_defined(commit))
		return error("Could not get patch ID for %s",
{
				     struct patch_ids *ids)
 */
	key = xcalloc(1, sizeof(*key));
	b = container_of(entry_or_key, struct patch_id, ent);
	if (is_null_oid(&a->patch_id) &&
		return -1;
			const struct hashmap_entry *entry_or_key,
	return !oideq(&a->patch_id, &b->patch_id);
int free_patch_ids(struct patch_ids *ids)
	hashmap_free_entries(&ids->patches, struct patch_id, ent);
		diff_tree_oid(&commit->parents->item->object.oid,
/*
}
	patch->commit = commit;
	/* must be 0 or 1 parents */
	return 0;
{
	a = container_of(eptr, struct patch_id, ent);
	memset(ids, 0, sizeof(*ids));
}
	if (commit_patch_id(commit, &ids->diffopts, &header_only_patch_id, 1, 0))
}
{
	    commit_patch_id(b->commit, opt, &b->patch_id, 0, 0))
	return diff_flush_patch_id(options, oid, diff_header_only, stable);


struct patch_id *has_commit_patch_id(struct commit *commit,
static int patch_id_neq(const void *cmpfn_data,
	return 0;
	if (init_patch_id_entry(&patch, commit, ids))
			       struct patch_ids *ids)
}
