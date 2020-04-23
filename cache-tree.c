
		strbuf_addf(path, "%s/", it->down[i]->name);

{
			return mi;
		}
	int ret;
		strbuf_add(&buffer, oid->hash, the_hash_algo->rawsz);
{
	} else if (dryrun) {
			continue;
			cnt += sub->cache_tree->entry_count;


		}
}

	}
			if (!subtree->object.parsed)
	return cache_tree_find(our_parent, info->name);
		 * which means conflicting one would immediately follow.
	/*
	struct cache_tree *it;
			pathlen, path, it->subtree_nr);
		struct cache_entry *ce = istate->cache[pos + i];
	if (subtree_nr != it->subtree_nr)
	struct cache_tree_sub *down;

			(has_promisor_remote() &&
		oid_to_hex(&it->oid));
{
		path = ce->name;
	while (i < entries) {
		if (ce->ce_flags & (CE_STAGEMASK | CE_INTENT_TO_ADD | CE_REMOVE))


			cache_tree_free(&s->cache_tree);
		/* path/file always comes after path because of the way
			const struct cache_entry *ce = index_state->cache[i];
		 * "sub" can be an empty tree if all subentries are i-t-a.
		}
	i = 0;
	hi = it->subtree_nr;

		 */
#endif
		return NULL;
		if (ce_stage(ce)) {
				return -1;
	struct cache_tree *our_parent;
		int i;


	}
{

	lo = 0;
	}
{
}
	}
					int cache_tree_valid,
	funny = 0;
			mode = S_IFDIR;
		}
	int was_valid, ret;
	if (0 <= it->entry_count)
		int pos;
 free_return:
	return 0;
		struct cache_tree *subtree;
		path = slash;
}
	if (i)
	if (0 <= it->entry_count)
	 * Then write out the tree object for this level.
	struct object_id new_oid;

#endif
			free(it->down[pos]);

					   int pathlen,
		return -1;
}
		const struct object_id *oid;
{
	return i;
	strbuf_grow(buffer, pathlen + 100);
}
		unsigned mode;
			to_invalidate = 1;
		int expected_missing = 0;
}
		return;
	struct cache_tree_sub **down = it->down;
	if (flags & WRITE_TREE_IGNORE_CACHE_TREE) {

	cp = ep;
	 * subtree_nr "cache-tree" entries for subtrees.

}
{
			down[dst++] = s;
			 */

		it = sub->cache_tree;
	int repair = flags & WRITE_TREE_REPAIR;
	 * marking existing subtrees -- the ones that are unmarked
		const struct cache_entry *ce = cache[i];
	/* a/b/c
	return it;

	return find_subtree(it, path, pathlen, 1);
			if (subtree_name_cmp(down->name, down->namelen,
			}
	}
				 struct name_entry *ent,
		    "Expected %s got %s", len, path->buf,
		 */
	istate->cache_changed |= CACHE_TREE_CHANGED;
		 * with the future on-disk index.
			 * move 4 and 5 up one place (2 entries)
#include "object-store.h"
	if (0 <= it->entry_count) {
	while (size && *buf && *buf != '\n') {
			   it->subtree_nr - pos - 1);

	int i;
			i += sub->count;
	int i;
			sub = cache_tree_sub(it, entry.path);
{
	}
{
	struct cache_entry **cache = istate->cache;
			    ce->name, ce->ce_flags);
	int entries = istate->cache_nr;
		subtree = cache_tree_find(index_state->cache_tree, prefix);
	if (!it)
		return;
}
#endif
}
	 * ==> find "a", have it invalidate "b/c"
		strbuf_setlen(path, len);
	funny = 0;
	struct cache_tree *it = istate->cache_tree;
	}
		const struct cache_entry *ce = cache[i];
	int nr = it->subtree_nr;
			if (ce_stage(ce))
	const char *cp;
out:
	if (!it)
	if (0 <= pos)
			oid_to_hex(&it->oid));
	if (ret == WRITE_TREE_UNMERGED_INDEX) {



		if (slash) {
static void verify_one(struct repository *r,
	return read_one(&buffer, &size);
}
static void write_one(struct strbuf *buffer, struct cache_tree *it,
			sub = find_subtree(it, path + baselen, entlen, 0);
		sub = find_subtree(it, path + baselen, sublen, 1);
		fprintf(stderr, "BUG: There are unmerged index entries:\n");
	} else if (write_object_file(buffer.buf, buffer.len, tree_type,
	subtree_nr = strtol(cp, &ep, 10);
	while (lo < hi) {

	return NULL;
	if (funny)
	}
		return it->entry_count;
			mode = ce->ce_mode;
	for (i = 0; i < it->subtree_nr; i++)
		      int baselen,
				die("cache-tree.c: '%.*s' in '%s' not found",
	pos = -pos-1;
	for (i = 0; i < entries; i++) {
	fprintf(stderr, "cache-tree invalidate <%s>\n", path);
		return WRITE_TREE_UNMERGED_INDEX;
	for (i = 0; i < it->subtree_nr; i++) {
	for (i = 0; i < entries - 1; i++) {
	trace_performance_leave("cache_tree_update");
			 *       ^     ^subtree_nr = 6
		write_locked_index(index_state, &lock_file, COMMIT_LOCK);

		      struct tree *tree)
	unsigned long size = *size_p;
	int i, pos, len = path->len;
		return -1;
	if (path->len) {
		      int flags)
	 */
		else
	int lo, hi;

		struct cache_tree_sub *sub = NULL;
	 * hence +2.
			struct tree *subtree = lookup_tree(r, &entry.oid);
			i++;
		MOVE_ARRAY(it->down + pos + 1, it->down + pos,

			 &new_oid);
{
		hash_object_file(the_hash_algo, buffer.buf, buffer.len,
		istate->cache_changed |= CACHE_TREE_CHANGED;
		while (*path == '/')
{
		return -1;

		slash = strchr(path + baselen, '/');
		die("cache-tree: internal error");
	struct name_entry entry;
	init_tree_desc(&desc, tree->buffer, tree->size);
		 * in updating the cache-tree part, and if the next caller
		}
			if (!sub || sub->cache_tree->entry_count < 0)
	 */
		if (cmp < 0)
	while (i < entries) {
#include "tree-walk.h"
		}
	struct object_id o;
	return 0;

}
			oid = &ce->oid;
	struct strbuf buffer;
		return it->down[pos];
		return;
			}
#if DEBUG_CACHE_TREE
		it->entry_count, it->subtree_nr,
			oidcpy(&it->oid, &oid);
{




		pathlen = ce_namelen(ce);
		strbuf_addf(&tree_buf, "%o %.*s%c", mode, entlen, name, '\0');
	 * ==> if "a" exists as a subtree, remove it.
				    cache + i, entries - i,
				return -1;
			BUG("%s with flags 0x%x should not be in cache-tree",
}
		    index_state->cache_tree &&
		    cache_tree_fully_valid(index_state->cache_tree);
#include "cache-tree.h"
					int flags,
		}
			entlen = slash - name;
		const char *next_name = cache[i+1]->name;
		if (!cache_tree_fully_valid(it->down[i]->cache_tree))
				 tree_type, &it->oid);
		 * Between path and slash is the name of the subtree
	int missing_ok = flags & WRITE_TREE_MISSING_OK;
		return 0;
	int namelen;

}
	if (buffer[0])
 * (2) Otherwise, find the cache_tree that corresponds to one level

				 struct tree *tree)

	}
				mode, oid_to_hex(oid), entlen+baselen, path);
		    oid_to_hex(&new_oid), oid_to_hex(&it->oid));
#endif

		struct cache_tree_sub *subtree;
		if (slash) {
	*skip_count = 0;
{

}
		if (this_len < strlen(next_name) &&
	}
	/*
}
		fprintf(stderr, "cache-tree <%.*s> (%d subtree) invalid\n",
int write_index_as_tree(struct object_id *oid, struct index_state *index_state, const char *index_path, int flags, const char *prefix)
 * find the cache_tree that corresponds to the current level without
		if (pathlen <= baselen || memcmp(base, path, baselen))
		strbuf_grow(&buffer, entlen + 100);
	    lookup_replace_object(r, &it->oid) != &it->oid)

		 */
		if (subcnt < 0)

		 * they are not part of generated trees. Invalidate up
	i = update_one(it, cache, entries, "", 0, &skip, flags);

			it->subtree_nr--;
				ce->name, oid_to_hex(&ce->oid));
		}

	/* One "cache-tree" entry consists of the following:
	it->entry_count = -1;
	int silent = flags & WRITE_TREE_SILENT;
			if (expected_missing)
	if (0 <= it->entry_count && has_object_file(&it->oid))
		subtree->cache_tree = sub;
	return 1;
		return 0;
		 * a/bbb/c (base = a/, slash = /c)
		}

		struct cache_tree_sub *s = down[src];
			sub->cache_tree = cache_tree();
	for (i = 0; i < it->subtree_nr; i++) {
			pathlen, path, it->entry_count, it->subtree_nr,

			it->subtree_nr--;
		else
					   mdl->name, mdl->namelen);
			 *       pos
	int i;
				fprintf(stderr, "BUG: %d %.*s\n", ce_stage(ce),
		 */
	 * at the same time.  At this point we know the cache has only
		    (!ce_missing_ok && !has_object_file(oid))) {
			die("index cache-tree records empty sub-tree");

				break;
		pos = subtree_pos(it, path, namelen);
	entries = read_index_from(index_state, index_path, get_git_dir());
		if (s->used)
		struct cache_tree_sub *sub;
	/*
	it->entry_count = to_invalidate ? -1 : i - *skip_count;
	strbuf_release(&tree_buf);
	}
	int skip, i = verify_cache(cache, entries, flags);
 * cache tree is given as "root", and our current level is "info".
	 * ==> invalidate self

		subcnt = update_one(sub->cache_tree,
	return memcmp(one, two, onelen);
	if (down)
		struct cache_tree_sub *sub = NULL;
	return down;
	return it;
			oid = &sub->cache_tree->oid;
				die("fatal - unsorted cache subtree");

			mode = S_IFDIR;
		if (ce->ce_flags & CE_REMOVE) {
 * (1) When at root level, info->prev is NULL, so it is "root" itself.
	}
			goto free_return;
	if (it && it->entry_count > 0 && oideq(&ent->oid, &it->oid))
		slash = strchr(path + baselen, '/');
	ALLOC_GROW(it->down, it->subtree_nr + 1, it->subtree_alloc);
		 */
			*buffer, subtree_nr);
		      int *skip_count,

		strbuf_addf(&buffer, "%o %.*s%c", mode, entlen, path + baselen, '\0');
			i++;
		      const char *path, int pathlen)
	down->cache_tree = NULL;
				expected_missing = 1;
	it = find_cache_tree_from_traversal(root, info);
		ret = WRITE_TREE_UNREADABLE_INDEX;
		sub->count = subcnt; /* to be used in the next loop */
	was_valid = index_state->cache_tree &&
static struct cache_tree *read_one(const char **buffer, unsigned long *size_p)
}
	struct index_state *index_state	= repo->index;
#if DEBUG_CACHE_TREE
	 * a
	it->entry_count = strtol(cp, &ep, 10);
		      int entries,
}
	} else {
		if (contains_ita && is_empty_tree_oid(oid))
	rollback_lock_file(&lock_file);
					const char *prefix)
			entlen = pathlen - baselen;
	if (repair) {
			return NULL;
		goto free_return;
		 */
		subtree = cache_tree_sub(it, name);
					     prev->name, prev->namelen) <= 0)
		       struct cache_tree *it,
void cache_tree_write(struct strbuf *sb, struct cache_tree *root)
	 * stage 0 entries.
	}
	our_parent = find_cache_tree_from_traversal(root, info->prev);
			cache_tree_free(&it->down[pos]->cache_tree);
		      struct index_state *istate,
	return 0;
	if (it->entry_count < 0 || !has_object_file(&it->oid))
			if (10 < ++funny) {
	ret = write_index_as_tree_internal(&o, index_state, was_valid, 0, NULL);
		else {
			oid = &sub->cache_tree->oid;
		size--;
		/* Not being able to write is fine -- we are only interested
		 * path+baselen = bbb/c, sublen = 3
 * exploding the full path into textual form.  The root of the
	if (!istate->cache_tree)
		const char *slash;
		 * ends up using the old index with unupdated cache-tree part
	if (it->entry_count < 0 ||
		 * to look for.
static int verify_cache(struct cache_entry **cache,
	buf++; size--;
		*skip_count += subskip;
int cache_tree_update(struct index_state *istate, int flags)
		verify_one(r, istate, it->down[i]->cache_tree, path);
			fprintf(stderr, "You have both %s and %s\n",
	/* Verify that the tree is merged */
		/*
			return error("invalid object %06o %s for '%.*s'",
void cache_tree_verify(struct repository *r, struct index_state *istate)
		int entlen;
	strbuf_release(&path);
	it->subtree_nr++;
		goto free_return;
		pos = 0;

	const char *buf = *buffer;
static void prime_cache_tree_rec(struct repository *r,
	int entries, was_valid;
			i += sub->cache_tree->entry_count;

	const unsigned rawsz = the_hash_algo->rawsz;

		pathlen = ce_namelen(ce);
		buf += rawsz;
		cache_tree_valid = 0;
}
#include "replace-object.h"
		else {
			sub = find_subtree(it, ce->name + path->len, entlen, 0);
				BUG("bad subtree '%.*s'", entlen, name);
	struct strbuf path = STRBUF_INIT;
			int entries, int flags)
	strbuf_init(&buffer, 8192);


void cache_tree_free(struct cache_tree **it_p)

		 * to root to force cache-tree users to read elsewhere.
void prime_cache_tree(struct repository *r,
	*buffer = buf;
	it->down[pos] = down;
			contains_ita = sub->cache_tree->entry_count < 0;
		sublen = slash - (path + baselen);
		const struct object_id *oid;
		do_invalidate_path(down->cache_tree, slash + 1);
				     &it->oid)) {
			}
{

		goto free_return;
	if (twolen < onelen)
		sub = read_one(&buf, &size);
		const char *path, *slash;

			lo = mi + 1;
			oid = &ce->oid;
	for (i = 0; i < it->subtree_nr; i++) {

		return i;
	 * entry_count, subtree_nr ("%d %d\n")
		return NULL; /* not the whole tree */
	struct strbuf tree_buf = STRBUF_INIT;
				 struct traverse_info *info)
	 */
	    /* no verification on tests (t7003) that replace trees */
{
	it->entry_count = cnt;
#if DEBUG_CACHE_TREE
	down = find_subtree(it, path, namelen, 0);
	strbuf_addf(buffer, "%c%d %d\n", 0, it->entry_count, it->subtree_nr);
		int pathlen, entlen;
				    baselen + sublen + 1,

			*buffer, it->entry_count, subtree_nr,
		name = ce->name + path->len;
	assert(!(dryrun && repair));

	*it_p = NULL;
		BUG("cache-tree for path %.*s does not match. "
	int i;
	while (tree_entry(&desc, &entry)) {
		return 1;
	for (i = 0; i < it->subtree_nr; i++)
		if (!cmp)
		    cache_tree_fully_valid(index_state->cache_tree);
	struct cache_tree *it;
	it = cache_tree();
	free(it->down);
	if (!oideq(&new_oid, &it->oid))
			if (contains_ita) {
		ce_missing_ok = mode == S_IFGITLINK || missing_ok ||
	int cnt;
		if (!subcnt)
		slash = strchrnul(path, '/');
		const char *name;
	i = 0;
			oid_to_hex(&it->oid));
 */
	if (cp == ep)
	 * tree-sha1 (missing if invalid)
		if (!sub && ce_intent_to_add(ce)) {
		    next_name[this_len] == '/') {
		fprintf(stderr, "cache-tree <%s> (%d ent, %d subtree) %s\n",
			path++;
	it = cache_tree_find(it, ent->path);
	}
	int dryrun = flags & WRITE_TREE_DRY_RUN;
				 struct cache_tree *it,
}
static struct cache_tree *find_cache_tree_from_traversal(struct cache_tree *root,
		strbuf_add(buffer, it->oid.hash, the_hash_algo->rawsz);
	struct tree_desc desc;
			mode = ce->ce_mode;
		fprintf(stderr, "cache-tree update-one %o %.*s\n",
	struct cache_tree_sub **down = it->down;
	struct cache_tree *it = xcalloc(1, sizeof(struct cache_tree));
			return subcnt;
		if (!slash) {
	if (!size)
static int write_index_as_tree_internal(struct object_id *oid,


		/*
		strbuf_release(&buffer);
			struct cache_tree_sub *prev = it->down[i-1];
				   it->subtree_nr - pos - 1);
	return -lo-1;
		      const char *base,
{

		return i;
	strbuf_setlen(path, len);
			free(s);

		sub->used = 1;
	return 0;
	write_one(sb, root, "", 0);
		if (!sub)
		return NULL;
struct cache_tree *cache_tree(void)
		path = ce->name;
	 */
	down->namelen = pathlen;
				parse_tree(subtree);
{
		int pathlen, sublen, subcnt, subskip;
			MOVE_ARRAY(it->down + pos, it->down + pos + 1,
	strbuf_add(buffer, path, pathlen);
				 tree_type, &oid);
		}
{
{
	}
		oidcpy(oid, &index_state->cache_tree->oid);
		if (is_null_oid(oid) ||

				break;
	it->subtree_alloc = subtree_nr + 2;
	it = NULL;
	 * should not be in the result.
 *     above us, and find ourselves in there.
#if DEBUG_CACHE_TREE
	if (!ret && !was_valid) {
	fprintf(stderr, "cache-tree update-one (%d ent, %d subtree) %s\n",
	it->down = xcalloc(it->subtree_alloc, sizeof(struct cache_tree_sub *));
		else {
		}

				fprintf(stderr, "...\n");
	FLEX_ALLOC_MEM(down, name, path, pathlen);

				    entlen, path + baselen, path);
static int subtree_name_cmp(const char *one, int onelen,
int cache_tree_fully_valid(struct cache_tree *it)
	}
	int pathlen = strlen(path);
/*
{
		return 1;
		struct cache_tree_sub *sub;
				this_name, next_name);
	istate->cache_changed |= CACHE_TREE_CHANGED;
		unsigned mode;

		 * CE_INTENT_TO_ADD entries exist on on-disk index but
		       struct strbuf *path)

	if (!size)
	cache_tree_free(&istate->cache_tree);
		    strncmp(this_name, next_name, this_len) == 0 &&
	if (!info->prev)
	strbuf_release(&buffer);
			break; /* at the end of this level */
	if (0 <= it->entry_count) {
		if (has_object_file_with_flags(&oid, OBJECT_INFO_SKIP_FETCH_OBJECT))
	const char *slash;
	}
}
	if (!it)
		if (0 <= pos) {
#define DEBUG_CACHE_TREE 0
	while (i < it->entry_count) {
void cache_tree_invalidate_path(struct index_state *istate, const char *path)
			entlen = slash - (path + baselen);
	if (!index_state->cache_tree)
		int this_len = strlen(this_name);

		 * written to disk. Skip them to remain consistent
}
	if (entries < 0) {
		size -= rawsz;

		hash_object_file(the_hash_algo, buffer.buf, buffer.len,


	int pos = subtree_pos(it, path, pathlen);
		}
		fprintf(stderr, "cache-tree <%.*s> (%d ent, %d subtree) %s\n",
		if (!S_ISDIR(entry.mode))
	cache_tree_free(&it);
static struct cache_tree_sub *find_subtree(struct cache_tree *it,

	for (dst = src = 0; src < nr; src++) {
				    path,

			prime_cache_tree_rec(r, sub->cache_tree, subtree);
	hold_lock_file_for_update(&lock_file, index_path, LOCK_DIE_ON_ERROR);
		return root;
			continue;
			if (10 < ++funny) {
							 struct traverse_info *info)

	 * Just a heuristic -- we do not add directories that often but
	return it;
	}
			break; /* at the end of this level */
			return WRITE_TREE_PREFIX_ERROR;
		index_state->cache_tree = cache_tree();
#include "promisor-remote.h"
	i = 0;
	while (size && *buf) {
	if (!it)
			struct cache_tree_sub *sub;

	else
	cnt = 0;
		size--;
	return 1;
		return -1;
	if (!*slash) {
	}
		       struct index_state *istate,
		int cmp = subtree_name_cmp(path, pathlen,
		if (i) {
	it->entry_count = -1;

	 */
	else
	struct cache_tree *it = *it_p;
			cache_tree_free(&it->down[i]->cache_tree);
#include "cache.h"
	}
					(int)ce_namelen(ce), ce->name);
		buf++;
		 * the cache is sorted.  Also path can appear only once,
		if (!sub->cache_tree)
		slash = strchr(name, '/');
}
}
		/*
	struct cache_tree_sub *down;
int cache_tree_matches_traversal(struct cache_tree *root,
		i += subcnt;
	*size_p = size;


static void discard_unused_subtrees(struct cache_tree *it)
		const char *path, *slash;
		struct cache_tree_sub *down = it->down[i];
struct tree* write_in_core_index_as_tree(struct repository *repo) {
	 */
	if (funny)
	 * Find the subtrees and update them.
		const struct cache_entry *ce = cache[i];
			fprintf(stderr, "%s: unmerged (%s)\n",
			 ce_skip_worktree(ce));
}
				    &subskip,

	prime_cache_tree_rec(r, istate->cache_tree, tree);
{
		if (pathlen <= baselen || memcmp(base, path, baselen))
		if (!subtree)
					   int create)
	return ret;
			*skip_count = *skip_count + 1;
			sub->cache_tree = cache_tree();
		for (i = 0; i < index_state->cache_nr; i++) {
	char *ep;
		sub = find_subtree(it, path, slash - path, 0);
static struct cache_tree *cache_tree_find(struct cache_tree *it, const char *path)
	if (i < 0)
		buf++;
		const char *this_name = cache[i]->name;
	if (onelen < twolen)
		oidcpy(oid, &subtree->oid);
	struct lock_file lock_file = LOCK_INIT;
{
#if DEBUG_CACHE_TREE
		pos = index_name_pos(istate, path->buf, path->len);
{
		goto out;
		 */
		 * ==>
		int ce_missing_ok;
	hash_object_file(r->hash_algo, tree_buf.buf, tree_buf.len, tree_type,
		write_one(buffer, down->cache_tree, down->name, down->namelen);
struct cache_tree_sub *cache_tree_sub(struct cache_tree *it, const char *path)

			return 0;
	/* skip name, but make sure name exists */
	}
{
#include "lockfile.h"

					   prefix);
	/*

			goto free_return;
		/*
		/* read each subtree */
		return 0;
	namelen = slash - path;
			entlen = ce_namelen(ce) - path->len;
	if (do_invalidate_path(istate->cache_tree, path))
		}
		cache_tree_free(&index_state->cache_tree);
	ret = write_index_as_tree_internal(oid, index_state, was_valid, flags,
	int to_invalidate = 0;
		const char *name = buf;
	for (i = 0; i < subtree_nr; i++) {
	while (*path) {
}
		oidread(&it->oid, (const unsigned char *)buf);

		int contains_ita = 0;
#endif
	was_valid = !(flags & WRITE_TREE_IGNORE_CACHE_TREE) &&
		it->down[i]->used = 0;
				to_invalidate = 1;
		goto free_return;
static int update_one(struct cache_tree *it,
#include "tree.h"
		} else {
		struct cache_tree *sub;
			mode, entlen, path + baselen);
			free(it->down[i]);
		if (size < rawsz)
		strbuf_add(&tree_buf, oid->hash, r->hash_algo->rawsz);
	/* Also verify that the cache does not have path and path/file
			strbuf_release(&buffer);
	 * path (NUL terminated)

	discard_unused_subtrees(it);
		const char *slash;
}
			hi = mi;
}
			    const char *two, int twolen)
	cp = buf;
		 * performance penalty and not a big deal.
	if (prefix) {
		 * CE_REMOVE entries are removed before the index is
	oidcpy(&it->oid, &tree->object.oid);
		 * it misses the work we did here, but that is just a
#endif
			/* 0 1 2 3 4 5
				    flags);
	 * We first scan for subtrees and update them; we start by
					struct index_state *index_state,
		if (it->down[i]) {


			if (silent)
	if (!cache_tree_valid && cache_tree_update(index_state, flags) < 0)
	 * ==> invalidate self
		return it->entry_count;
		}
	int i, subtree_nr;
		struct cache_tree_sub *mdl = down[mi];
	int i, funny;
		struct object_id oid;
		pos = -pos - 1;
	}
	}
	 */


	else
static int subtree_pos(struct cache_tree *it, const char *path, int pathlen)
	if (cp == ep)
	if (!create)
		BUG("unmerged index entries when writing inmemory index");
static int do_invalidate_path(struct cache_tree *it, const char *path)
			continue;
{
	verify_one(r, istate, istate->cache_tree, &path);
	trace_performance_enter();
{
				fprintf(stderr, "...\n");
			continue;
			cnt++;
	int dst, src;
	 * we do not want to have to extend it immediately when we do,
		/*
		      struct cache_entry **cache,
	if (pos < it->subtree_nr)
		fprintf(stderr, "cache-tree <%s> (%d subtrees) invalid\n",
	}

	buf++; size--;
struct cache_tree *cache_tree_read(const char *buffer, unsigned long size)
			to_invalidate = 1;
	}
			 * 2 = 6 - 3 - 1 = subtree_nr - pos - 1
	slash = strchrnul(path, '/');
#ifndef DEBUG_CACHE_TREE
			if (!sub)
	free(it);
			i++;
	return lookup_tree(repo, &index_state->cache_tree->oid);
					   const char *path,
		if (!sub)
	istate->cache_tree = cache_tree();

		}
		int mi = lo + (hi - lo) / 2;
