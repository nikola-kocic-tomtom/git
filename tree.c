	}
	struct object *obj = parse_object(r, oid);
	tree->object.parsed = 0;
	 void *buffer;
	len = strlen(pathname);
		free(buffer);
	/*
	if (item->object.parsed)
{
	ce1 = *((const struct cache_entry **)a_);
			  const char *pathname, unsigned mode, int stage,
	memcpy(ce->name + baselen, pathname, len+1);
	tree->size = 0;
		switch (fn(&entry.oid, base,
			if (parse_commit(commit))
}
	return read_one_entry_opt(istate, oid, base->buf, base->len, pathname,
	struct index_state *istate = context;
				    oid_to_hex(&entry.oid),
{
		if (retval)
	err = read_tree_recursive(r, tree, "", 0, stage, match, fn, istate);
}
				die("Commit %s in submodule path %s%s not found",

#include "cache-tree.h"

			      const char *base, int baselen,
	int ret;
			oidcpy(&oid, &entry.oid);
		default:
			return -1;
{
	buffer = read_object_file(&item->object.oid, &type, &size);
	ce->ce_flags = create_ce_flags(stage);
}
#include "alloc.h"
				const char *pathname, unsigned mode, int stage,

			   entry.path, entry.mode, stage, context)) {
}
	struct repository *r = the_repository;
	enum interesting retval = entry_not_interesting;
	if (S_ISDIR(mode))

		       int stage, const struct pathspec *pathspec,
	int len, oldlen = base->len;
	if (fn == read_one_entry || err)
}
			oidcpy(&oid, get_commit_tree_oid(commit));
			if (retval == all_entries_not_interesting)

	 unsigned long size;
	if (!obj)
static int read_one_entry(const struct object_id *oid, struct strbuf *base,
	 *
			return -1;
	ce->ce_namelen = baselen + len;
	struct name_entry entry;
#include "object-store.h"
		       struct tree *tree, struct strbuf *base,
	 * sort at the end.
			      unsigned mode, int stage, int opt)
				     fn, context);

{
		len = tree_entry_len(&entry);
	item->size = size;
		strbuf_addch(base, '/');
		}
}
	struct strbuf sb = STRBUF_INIT;

	 * call it with stage=1 and after making sure there is nothing
	 * to matter.

			     oid_to_hex(&item->object.oid));


int read_tree(struct repository *r, struct tree *tree, int stage,
	 * But when we decide to straighten out git-read-tree not to
	ce = make_empty_cache_entry(istate, baselen + len);

			const char *base, int baselen,
	int len;

	return object_as_type(r, obj, OBJ_TREE, 0);

	if (!fn)
			  void *context)
	return 0;
			struct tree *tree,


			fn = read_one_entry;
			int stage, const struct pathspec *pathspec,
	cache_tree_free(&istate->cache_tree);

{
		return err;

			error("Could not read %s",
				  mode, stage,
	if (parse_tree(tree))
		if (ce_stage(ce) == stage)
static int read_tree_1(struct repository *r,
				  ADD_CACHE_OK_TO_ADD|ADD_CACHE_SKIP_DFCHECK);

			if (!commit)
		else
	struct object_id oid;
				    base->buf, entry.path);
		else if (S_ISGITLINK(entry.mode)) {
const char *tree_type = "tree";
	ce2 = *((const struct cache_entry **)b_);


	return (struct tree *)repo_peel_to_type(r, NULL, 0, obj, OBJ_TREE);
			continue;
{
	if (type != OBJ_TREE) {
	memcpy(ce->name, base, baselen);

 */
	return parse_tree_buffer(item, buffer, size);
	/*
static int read_one_entry_opt(struct index_state *istate,
int parse_tree_buffer(struct tree *item, void *buffer, unsigned long size)
				continue;
#include "commit.h"
		strbuf_add(base, entry.path, len);
}
				     base, stage, pathspec,
	struct cache_entry *ce;
	 * at that stage; we could always use read_one_entry_quick().
	return cache_name_stage_compare(ce1->name, ce1->ce_namelen, ce_stage(ce1),
}
/*
				void *context)
void free_tree_buffer(struct tree *tree)
	const struct cache_entry *ce1, *ce2;
	return add_index_entry(istate, ce, opt);

		return create_object(r, oid, alloc_tree_node(r));

struct tree *parse_tree_indirect(const struct object_id *oid)
	 */
	 * Sort the cache entry -- we need to nuke the cache tree, though.
static int read_one_entry_quick(const struct object_id *oid, struct strbuf *base,
	/*

{
				die("Invalid commit %s in submodule path %s%s",

				  mode, stage,
	}
		case 0:
}
				  ADD_CACHE_JUST_APPEND);

		       read_tree_fn_t fn, void *context)
		return READ_TREE_RECURSIVE;
int parse_tree_gently(struct tree *item, int quiet_on_missing)
		retval = read_tree_1(r, lookup_tree(r, &oid),
	int i, err;
	item->buffer = buffer;
	return read_one_entry_opt(istate, oid, base->buf, base->len, pathname,

struct tree *lookup_tree(struct repository *r, const struct object_id *oid)
{
#include "tree.h"
{
}

}
		}
		if (S_ISDIR(entry.mode))
		fn = read_one_entry_quick;
	strbuf_add(&sb, base, baselen);
		const struct cache_entry *ce = istate->cache[i];
		return quiet_on_missing ? -1 :
	 * do it the original slow way, otherwise, append and then
	while (tree_entry(&desc, &entry)) {
	 */
	for (i = 0; !fn && i < istate->cache_nr; i++) {
	if (!buffer)
#include "tag.h"
		return error("Object %s not a tree",
#include "cache.h"
	return ret;
				    oid_to_hex(&entry.oid),
			      const struct object_id *oid,
	struct object *obj = lookup_object(r, oid);
	return 0;
	 */
				    base->buf, entry.path);
			continue;
		strbuf_setlen(base, oldlen);
				break;
			      const char *pathname,
{
	}

		return 0;
	read_tree_fn_t fn = NULL;
static int cmp_cache_name_compare(const void *a_, const void *b_)
	 * Currently the only existing callers of this function all
	FREE_AND_NULL(tree->buffer);
			if (retval == entry_not_interesting)
#include "repository.h"
	init_tree_desc(&desc, tree->buffer, tree->size);
		}
	struct tree_desc desc;
int read_tree_recursive(struct repository *r,
	ce->ce_mode = create_ce_mode(mode);
			     oid_to_hex(&item->object.oid));

			struct commit *commit;
			commit = lookup_commit(r, &entry.oid);
	 * See if we have cache entry at the stage.  If so,
	if (item->object.parsed)
			retval = tree_entry_interesting(r->index, &entry,
#include "tree-walk.h"
}
	item->object.parsed = 1;
{
							base, 0, pathspec);
			break;
{

	 enum object_type type;
		case READ_TREE_RECURSIVE:
#include "blob.h"
	ret = read_tree_1(r, tree, &sb, stage, pathspec, fn, context);
	QSORT(istate->cache, istate->cache_nr, cmp_cache_name_compare);

				  ce2->name, ce2->ce_namelen, ce_stage(ce2));
 * the stage that will conflict with the entry being added.
	return 0;
		if (retval != all_entries_interesting) {
	strbuf_release(&sb);
 * This is used when the caller knows there is no existing entries at
		return -1;

	      struct pathspec *match, struct index_state *istate)
			read_tree_fn_t fn, void *context)
	struct index_state *istate = context;
	 * use unpack_trees() in some cases, this will probably start
	oidcpy(&ce->oid, oid);
		return 0;
