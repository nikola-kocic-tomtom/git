	iter = xcalloc(1, sizeof(*iter));
	 */

		if (last && is_dup_ref(last, entry))
	return strcmp(one->name, two->name);
	struct ref_entry *entry;
				 * don't have to check the prefix

			break;
			continue;
		char *dirname = xmemdupz(refname, refname_len - 1);

	} else {

	int i, j;
 * oids.
	 */
}
	key.str = refname;
			level->dir = get_ref_dir(entry);
{
					 const char *prefix)

	int entry_index;
	if (cmp)
		}
static void prime_ref_dir(struct ref_dir *dir, const char *prefix)
		prefix++;
	if (dir->sorted == dir->nr)
		    dir->entries[dir->nr - 1]->name) < 0))
		if (level->prefix_state == PREFIX_WITHIN_DIR) {

 * `prefix` is NULL, prime unconditionally.


	struct ref_entry **r;
		dir = find_containing_dir(dir, dirname, 0);

			dir = NULL;
static void free_ref_entry(struct ref_entry *entry)
	    (dir->nr == dir->sorted + 1 &&
	struct ref_dir *dir;
	}
static int cache_ref_iterator_abort(struct ref_iterator *ref_iterator)
	struct cache_ref_iterator *iter;

	iter->levels_nr = 1;
	 * A stack of levels. levels[0] is the uppermost level that is
	cache_ref_iterator_peel,
				 */
		/*
		/* There's nothing to iterate over. */
	return ref;
{
		return -1;
{

	free_ref_entry(entry);
		if (!(entry->flag & REF_DIR)) {
/*
		if (!subdir) {
		if (!mkdir)
					      const char *prefix,


		enum prefix_state entry_prefix_state;
struct ref_entry *create_dir_entry(struct ref_cache *cache,
}
	 * which is a problem on some platforms.
#include "refs-internal.h"
	struct ref_iterator base;
 * Represent an iteration through a ref_dir in the memory cache. The
		(struct cache_ref_iterator *)ref_iterator;
}
/*
		entry = dir->entries[entry_index];
}
	 * The ref_dir being iterated over at this level. The ref_dir

		} else {

	FLEX_ALLOC_MEM(direntry, name, dirname, len);
void free_ref_cache(struct ref_cache *cache)
}
	else if (!*dirname)
	return dir->nr;
	if (!*prefix)
	free_ref_entry(cache->root);

	return 1;
#include "../cache.h"


		 * the trailing slash; otherwise we will get the
	level = &iter->levels[0];
	cache_ref_iterator_advance,
	}
		return -1;

	ret->ref_store = refs;

static void clear_ref_dir(struct ref_dir *dir)
	QSORT(dir->entries, dir->nr, ref_entry_cmp);
	free(cache);
	/*

	if (prefix && *prefix)
		 */
	}
	ref_iterator = &iter->base;
#include "../refs.h"
	} else {
	 * even need to care about sorting, as traversal order does not matter
	if (entry_index == -1)
	ret->fill_ref_dir = fill_ref_dir;
	if (!dir)


	return get_ref_dir(entry);
}
			}
		/*
				   iter->levels_alloc);
	const struct string_slice *key = key_;
		return -1;
		(struct cache_ref_iterator *)ref_iterator;
					 const char *subdirname, size_t len,
	while (1) {
		 * therefore, create an empty record for it but mark
	entry = dir->entries[entry_index];
	 * The hard work of loading loose refs is done by get_ref_dir(), so we
	 * hasn't yet begun. If index == dir->nr, then the iteration
	for (i = 0; i < dir->nr; i++)
 */


		dir = find_containing_dir(dir, prefix, 0);
{
		if (entry->flag & REF_DIR) {
				   fill_ref_dir_fn *fill_ref_dir)
	ALLOC_GROW(iter->levels, 10, iter->levels_alloc);
		 * trigger the reading of loose refs.
 */
 */
	const char *str;
{
 */
			iter->base.oid = &entry->u.value.oid;
		entry = create_dir_entry(dir->cache, subdirname, len, 0);
 * A level in the reference hierarchy that is currently being iterated
static void sort_ref_dir(struct ref_dir *dir)
	if (is_dir) {
enum prefix_state {
{
}
				   int incomplete)
		/* This is impossible by construction */
		return NULL;

	struct ref_entry *one = *(struct ref_entry **)a;
	free(iter->levels);
	}
}
		 */
	return (entry->flag & REF_DIR) ? NULL : entry;
	free((char *)iter->prefix);
	 * at least 1, because when it becomes zero the iteration is
{
	/* Some, but not all, refs within the directory might match prefix: */
			iter->base.refname = entry->name;
/*
	for (i = 0, j = 0; j < dir->nr; j++) {
	direntry->flag = REF_DIR | (incomplete ? REF_INCOMPLETE : 0);
		dirname++;
	direntry->u.subdir.cache = cache;
	return dir;
	 * The prefix is matched textually, without regard for path

				   const struct object_id *oid, int flag)
	for (i = 0; i < dir->nr; i++) {
				prime_ref_dir(get_ref_dir(entry), prefix);

	size_t len;
				   const char *dirname, size_t len,
				break;
	/*
struct ref_entry *create_ref_entry(const char *refname,
		level->prefix_state = PREFIX_CONTAINS_DIR;
					 int mkdir)
					   const char *refname, int mkdir)
	struct ref_entry *two = *(struct ref_entry **)b;
struct ref_dir *get_ref_dir(struct ref_entry *entry)
{
			/* This level is exhausted; pop up a level */
	 */
/*
	base_ref_iterator_init(ref_iterator, &cache_ref_iterator_vtable, 1);
			sort_ref_dir(dir);
	int refname_len = strlen(refname);

	oidcpy(&ref->u.value.oid, oid);
	for (slash = strchr(refname, '/'); slash; slash = strchr(slash + 1, '/')) {
	int i;


 * (i.e., it ends in '/'), then return that ref_dir itself. dir must
};


 * return NULL if the desired directory cannot be found.

			return ITER_OK;
	int i;
	/* Remove any duplicates: */
				 * Recurse, and from here down we
/*
	dir->entries[dir->nr++] = entry;

static enum prefix_state overlaps_prefix(const char *dirname,
		iter->prefix = xstrdup(prefix);
struct cache_ref_iterator {
}
				return ref_iterator_abort(ref_iterator);
int search_ref_dir(struct ref_dir *dir, const char *refname, size_t len)
	ALLOC_GROW(dir->entries, dir->nr + 1, dir->alloc);
		 * Since dir is complete, the absence of a subdir
		 * means that the subdir really doesn't exist;
		} else {
	/* optimize for the case that entries are added in order */
		}
		entry->flag &= ~REF_INCOMPLETE;
static void sort_ref_dir(struct ref_dir *dir);
	struct ref_entry *direntry;
int remove_entry_from_dir(struct ref_dir *dir, const char *refname)
	 * being iterated over in this iteration. (This is not
		if (level->index == -1)
	int entry_index = search_ref_dir(dir, subdirname, len);
			switch (overlaps_prefix(entry->name, prefix)) {
		}
	r = bsearch(&key, dir->entries, dir->nr, sizeof(*dir->entries),
	if (entry_index == -1)
	entry_index = search_ref_dir(dir, refname, refname_len);

	int is_dir = refname[refname_len - 1] == '/';
	key.len = len;
}
			if (entry_prefix_state == PREFIX_EXCLUDES_DIR)
 */
					      int prime_dir)
struct ref_entry *find_ref_entry(struct ref_dir *dir, const char *refname)
		return PREFIX_EXCLUDES_DIR;

	size_t levels_alloc;
{
	struct ref_dir *dir;
 * name (i.e., end in '/').  If mkdir is set, then create the
	struct ref_entry *ref;
	int index;
	return '\0' - (unsigned char)ent->name[key->len];
 * Return a `prefix_state` constant describing the relationship
static int ref_entry_cmp_sslice(const void *key_, const void *ent_)
{
		}
	dir->sorted = dir->nr = dir->alloc = 0;
{
	 * The index of the current entry within dir (which might
{
			iter->base.flags = entry->flag;

	/* No refs within the directory could possibly match prefix: */
			return NULL;
			case PREFIX_WITHIN_DIR:
static int cache_ref_iterator_peel(struct ref_iterator *ref_iterator,
	free(entry);
	if ((ref1->flag & REF_DIR) || (ref2->flag & REF_DIR))
static int cache_ref_iterator_advance(struct ref_iterator *ref_iterator)

	dir->nr--;
			case PREFIX_CONTAINS_DIR:
{
	/* The number of levels that have been allocated on the stack */
		return PREFIX_CONTAINS_DIR;
		dir = subdir;
		struct ref_dir *dir = level->dir;
		dir->sorted--;
	if (entry->flag & REF_INCOMPLETE) {
	struct cache_ref_iterator *iter =
	FLEX_ALLOC_STR(ref, name, refname);
static void clear_ref_dir(struct ref_dir *dir);
{
}
 */
	/* Duplicate name; make sure that they don't conflict: */
 * through.
		 * refname represents a reference directory.  Remove
	}

	struct ref_iterator *ref_iterator;
/*

	level->dir = dir;
		return empty_ref_iterator_begin();
	if (!dir)

		}
	     strcmp(dir->entries[dir->nr - 2]->name,
	 * itself be a directory). If index == -1, then the iteration
	 * just need to recurse through all of the sub-directories. We do not
	struct ref_entry *last = NULL;
	if (!dir)
	PREFIX_WITHIN_DIR,

 * represent the top-level directory and must already be complete.
	ref->flag = flag;
int add_ref_entry(struct ref_dir *dir, struct ref_entry *ref)
	if (r == NULL)

	struct string_slice key;
	if (prefix && *prefix) {
	entry = dir->entries[entry_index];
struct ref_iterator *cache_ref_iterator_begin(struct ref_cache *cache,
 * sorted) and remove any duplicate entries.
/*
	return 0;
		if (++level->index == level->dir->nr) {
#include "../iterator.h"
		struct cache_ref_iterator_level *level =
				   struct object_id *peeled)
void add_entry_to_dir(struct ref_dir *dir, struct ref_entry *entry)
};
	struct cache_ref_iterator *iter =
	}
				/*
			entry_prefix_state = level->prefix_state;
}
	if (refname == NULL || !dir->nr)
	entry_index = search_ref_dir(dir, refname, strlen(refname));
{
	}
	} else {
		   &dir->entries[entry_index + 1], dir->nr - entry_index - 1);
 * Clear and free all entries in dir, recursively.
	if (dir->sorted > entry_index)
 * recursing).  Sort dir if necessary.  subdirname must be a directory
	if (strcmp(ref1->name, ref2->name))
		die("Duplicated ref, and SHA1s don't match: %s", ref1->name);
		level->prefix_state = PREFIX_WITHIN_DIR;
static int is_dup_ref(const struct ref_entry *ref1, const struct ref_entry *ref2)
 * tree that should hold refname. If refname is a directory name
 * Sort ref_dirs and recurse into subdirectories as necessary. If
static struct ref_iterator_vtable cache_ref_iterator_vtable = {

	 * is sorted before being stored here.
	 * are iterating through a subtree, then levels[0] will hold
	/* All refs within the directory would match prefix: */
	MOVE_ARRAY(&dir->entries[entry_index],
	struct ref_dir *dir;
			free_ref_entry(entry);
		return PREFIX_WITHIN_DIR;
			level = &iter->levels[iter->levels_nr++];
		 */
}
}

		if (!dir->cache->fill_ref_dir)
}
}
	struct ref_cache *ret = xcalloc(1, sizeof(*ret));
	/*
{
		 * Do not use get_ref_dir() here, as that might
 * iteration recurses through subdirectories.
		return -1;
			/* Recurse in any case: */
			level->index = -1;
	dir = find_containing_dir(dir, ref->name, 1);
			level->prefix_state = entry_prefix_state;
 * and the same oid. Die if they have the same name but different
	const struct ref_entry *ent = *(const struct ref_entry * const *)ent_;
	 * the ref_dir for that subtree, and subsequent levels will go
		dir->cache->fill_ref_dir(dir->cache->ref_store, dir, entry->name);
		size_t dirnamelen = slash - refname + 1;
			case PREFIX_EXCLUDES_DIR:
	 */

	dir = find_containing_dir(dir, refname, 0);
		free(dirname);
	if (!oideq(&ref1->u.value.oid, &ref2->u.value.oid))
	if (!dir)
 */
	else
		 * directory *representing* refname rather than the
}
struct cache_ref_iterator_level {
		clear_ref_dir(&entry->u.subdir);
		dir = find_containing_dir(dir, refname, 0);
	ret->root = create_dir_entry(ret, "", 0, 1);
	dir->sorted = dir->nr = i;
	return ITER_DONE;
	warning("Duplicated ref: %s", ref1->name);
	 * This check also prevents passing a zero-length array to qsort(),
			entry_prefix_state = overlaps_prefix(entry->name, iter->prefix);

 */
{
	return dir;
		return NULL;
};
static struct ref_dir *find_containing_dir(struct ref_dir *dir,
	const char *prefix;
 * mkdir is set, then create any missing directories; otherwise,
};
			/* push down a level */
	return direntry;
	return ret;
/*
struct ref_cache *create_ref_cache(struct ref_store *refs,

	base_ref_iterator_free(ref_iterator);
		prime_ref_dir(dir, prefix);

	}
	assert(entry->flag & REF_DIR);

	dir = &entry->u.subdir;
struct string_slice {
};
 * If refname is a reference name, find the ref_dir within the dir
				break;

}
 * Search for a directory entry directly within dir (without
 * Sort the entries in dir non-recursively (if they are not already
{
	 */
		struct ref_dir *subdir;
	/*
			last = dir->entries[i++] = entry;
	return r - dir->entries;
		 * the record complete.
		return 0;
		free_ref_entry(dir->entries[i]);
	if (prime_dir)
 * contain references matching `prefix` into our in-memory cache. If

	const char *slash;
	enum prefix_state prefix_state;
	}
static int ref_entry_cmp(const void *a, const void *b)
		dir->sorted = dir->nr;
		struct ref_entry *entry = dir->entries[j];
		add_entry_to_dir(dir, entry);
	/*
		return;
		struct ref_entry *entry = dir->entries[i];

}
{

	 * ended and this struct is freed.
 * Load all of the refs from `dir` (recursively) that could possibly
	add_entry_to_dir(dir, ref);
 * Emit a warning and return true iff ref1 and ref2 have the same name
{
	PREFIX_EXCLUDES_DIR
			if (--iter->levels_nr == 0)
	int entry_index;

	 * to us.
		} else {

	size_t levels_nr;
	 * The number of levels currently on the stack. This is always


{
		 * one *containing* it.
				/* No need to prime this directory. */
}
	 * on from there.)
	struct cache_ref_iterator_level *levels;
	 * necessary the top level in the references hierarchy. If we
		} else if (!prefix) {

#include "ref-cache.h"
	dir = get_ref_dir(cache->root);
}
	while (*prefix && *dirname == *prefix) {
		return cmp;
			BUG("incomplete ref_store without fill_ref_dir function");

		die("Reference directory conflict: %s", ref1->name);

	return peel_object(ref_iterator->oid, peeled);
{

{
	 */
		else
			&iter->levels[iter->levels_nr - 1];
	sort_ref_dir(dir);
 * directory if it is missing; otherwise, return NULL if the desired
}
	return ref_iterator;

	/*
}
 */
	struct cache_ref_iterator_level *level;
			prime_ref_dir(get_ref_dir(entry), NULL);
				break;
	 * Only include references with this prefix in the iteration.
	}
static struct ref_dir *search_for_subdir(struct ref_dir *dir,
/*

		return -1;


	cache_ref_iterator_abort
				continue;
	struct ref_entry *entry;
	FREE_AND_NULL(dir->entries);

		/*
{
	 * component boundaries.
		struct ref_entry *entry;
	if (entry->flag & REF_DIR) {
 * between the directory with the specified `dirname` and `prefix`.
	/*
			/* Not a directory; no need to recurse. */
}
	 */
	level->index = -1;

	int cmp = strncmp(key->str, ent->name, key->len);
				prime_ref_dir(get_ref_dir(entry), NULL);
	if (dir->nr == 1 ||
		entry = dir->entries[level->index];
 * directory cannot be found.  dir must already be complete.
	PREFIX_CONTAINS_DIR,
				 * anymore:
	if (entry_index == -1) {
		    ref_entry_cmp_sslice);
		subdir = search_for_subdir(dir, refname, dirnamelen, mkdir);
	struct ref_entry *entry;

	 * through this level is over.
			ALLOC_GROW(iter->levels, iter->levels_nr + 1,

