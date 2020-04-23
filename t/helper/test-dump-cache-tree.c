		/* missing in either */
	cache_tree_update(&istate, WRITE_TREE_DRY_RUN);
	return errs;
		printf("%s %s%s (%d entries, %d subtrees)\n",
{

	}
		    ref->subtree_nr != it->subtree_nr) {

		die("unable to read index file");
		return 0;
	struct index_state istate;
	if (it->entry_count < 0)
			/* claims to be valid but is lying */
	int i;
	for (i = 0; i < it->subtree_nr; i++) {
			   struct cache_tree *ref,
		struct cache_tree_sub *down = it->down[i];
	if (it->entry_count < 0) {
		struct cache_tree_sub *rdwn;
	setup_git_directory();
#include "cache.h"
}
		xsnprintf(path, sizeof(path), "%s%.*s/", pfx, down->namelen, down->name);
		       it->entry_count, it->subtree_nr);
		    ref->entry_count != it->entry_count ||
	}
		dump_one(it, pfx, "");
		dump_one(ref, pfx, "#(ref) ");
		       oid_to_hex(&it->oid), x, pfx,
	istate.cache_tree = another;
		rdwn = cache_tree_sub(ref, down->name);
		printf("%-40s %s%s (%d subtrees)\n",
static int dump_cache_tree(struct cache_tree *it,
		       "invalid", x, pfx, it->subtree_nr);
	if (!it || !ref)
	istate = the_index;
	}
			errs = 1;

	if (read_cache() < 0)

		dump_one(it, pfx, "");
#include "cache-tree.h"
#include "tree.h"
			errs = 1;
{
	return dump_cache_tree(active_cache_tree, another, "");
			   const char *pfx)

{
		/* invalid */

}
		}
		char path[PATH_MAX];

#include "test-tool.h"
static void dump_one(struct cache_tree *it, const char *pfx, const char *x)
	int errs = 0;
		if (dump_cache_tree(down->cache_tree, rdwn->cache_tree, path))

	struct cache_tree *another = cache_tree();
	else
}
int cmd__dump_cache_tree(int ac, const char **av)
		if (!oideq(&it->oid, &ref->oid) ||
			dump_one(ref, pfx, "#(ref) ");
	else {
