			lazy_entries[k].hash_name = memihash(ce_k->name, ce_namelen(ce_k));
};

		if (k_start > istate->cache_nr)
	struct dir_entry *parent,
		hashmap_entry_init(&dir->ent, hash);
 *

		int nr;
	if (istate->name_hash_initialized)
		 * Disable item counting and automatic rehashing because
		int end = k_end;
static int dir_entry_cmp(const void *unused_cmp_data,
}
			c2 = toupper(c2);
	while (k < k_end) {
	const char *name = keydata;
	if (istate->cache_nr < 2 * LAZY_THREAD_COST)

		hashmap_enable_item_counting(&istate->dir_hash);
	 * decide whether the entry matches in same_name.
	if (nr_cpus < 2)
	return NULL;
	 * Phase 1:
	return dir;
 * Initialize n mutexes for use when searching and inserting
struct lazy_name_thread_data {
	 * reach this point, because they are stored
		hashmap_disable_item_counting(&istate->dir_hash);
		dir->namelen = prefix->len;
}
void adjust_dirname_case(struct index_state *istate, char *name)
		td_dir_t->istate = istate;
	lazy_nr_dir_threads = nr_cpus;
	int nr_each;
{
			int mid = begin + ((end - begin) >> 1);
static int same_name(const struct cache_entry *ce, const char *name, int namelen, int icase)
		dir->namelen = namelen;
struct dir_entry {

 * chains based on their hash values.  Use that to create n

static int handle_range_1(

	/*
	 *
{
				parent->ent.hash,


	return lazy_nr_dir_threads;
		 */
	struct lazy_dir_thread_data *td_dir;
 * to insert partial pathnames into the hash as they iterate
	nr_cpus = online_cpus();
	return lazy_nr_dir_threads;
		struct lazy_dir_thread_data *td_dir_t = td_dir + t;
	return 1;
/*

	if (istate->cache_nr < nr_cpus * LAZY_THREAD_COST)
		add_dir_entry(istate, ce);
	rc = handle_range_1(istate, k_start, k, dir_new, prefix, lazy_entries);
	return rc;
	 * Always do exact compare, even if we want a case-ignoring comparison;
 * high.
		assert(begin >= 0);
	struct dir_entry *dir;
	for (t = 0; t < lazy_nr_dir_threads; t++) {
	}

			lazy_entries[k].hash_dir = parent->ent.hash;
		k = k_start + 1;
static void add_dir_entry(struct index_state *istate, struct cache_entry *ce)

	/*

		free(dir);
	return k - k_start;
{
	lazy_nr_dir_threads = 0;
	struct index_state *istate,

	while (*ptr) {
	const struct hashmap *map,
		const char *name, *slash;

	/*
	istate->name_hash_initialized = 1;
 * We use n mutexes to guard n partitions of the "istate->dir_hash"

 * intermediate results.  These values are then referenced by
static struct dir_entry *hash_dir_entry_with_parent_and_prefix(
	}
	if (len == namelen && !memcmp(name, ce->name, len))
int test_lazy_init_name_hash(struct index_state *istate, int try_threaded)
	td_dir = xcalloc(lazy_nr_dir_threads, sizeof(struct lazy_dir_thread_data));
				return 0;
		 * permanent data structures until phase 2 (where we
	hashmap_for_each_entry_from(&istate->name_hash, ce, ent) {
		die(_("unable to join lazy_name thread: %s"), strerror(err));
	err = pthread_create(&td_name->pthread, NULL, lazy_name_thread_proc, td_name);

}
			}

	hashmap_init(&istate->name_hash, cache_entry_cmp, NULL, istate->cache_nr);
				memcpy((void *)startPtr, dir->name + (startPtr - name), ptr - startPtr);
/*
		if (prefix->len && strncmp(ce_k->name, prefix->buf, prefix->len))
};
			processed = handle_range_1(istate, k, k_end, dir_new, prefix, lazy_entries);
	if (!dir) {
 */

		return 0;
 * Returns the number of threads used or 0 when
	struct lazy_dir_thread_data *d = _data;
	while (dir && !(dir->nr++))
			 const struct hashmap_entry *eptr,
{
}
	/*
	const char *startPtr = name;
static void hash_index_entry(struct index_state *istate, struct cache_entry *ce)
int index_dir_exists(struct index_state *istate, const char *name, int namelen)
		/*
		return;
	} else {
	struct dir_entry *dir_new;
	e2 = container_of(entry_or_key, const struct dir_entry, ent);
	lazy_entries = xcalloc(istate->cache_nr, sizeof(struct lazy_entry));


	namelen--;
		const char *name, unsigned int namelen)
	unsigned int namelen;
	int k;
	free(td_name);
static struct dir_entry *find_dir_entry__hash(struct index_state *istate,
	struct hashmap_entry ent;
	free(td_dir);
static inline void lazy_update_dir_ref_counts(
			/* All I really need here is an InterlockedIncrement(&(parent->nr)) */
	struct lazy_entry *lazy_entries;
		struct lazy_dir_thread_data *td_dir_t = td_dir + t;
	 * using a single "name" background thread.
		 * data array).
static pthread_mutex_t *lazy_dir_mutex_array;
void free_name_hash(struct index_state *istate)
	 * need the complexity here.
	int k_start;

			struct dir_entry *dir_new;
				k += processed;

		 * [k_start,k_end) that this thread was given.
		k = begin;
{
		init_recursive_mutex(&lazy_dir_mutex_array[j]);

	 * Build "istate->dir_hash" using n "dir" threads (and a read-only index).
	 * Either we have a parent directory and path with slash(es)
		return;
		hashmap_entry_init(&dir->ent, memihash(ce->name, namelen));
			   const struct hashmap_entry *eptr,
static void *lazy_dir_thread_proc(void *_data)
}



	struct lazy_entry *lazy_entries;
		hashmap_add(&istate->dir_hash, &dir->ent);
	int t;
			int len = slash - name;
			die("unable to join lazy_dir_thread");
 * However, the hashmap is going to put items into bucket
		struct dir_entry *parent = dir->parent;
		 * We do not need to lock the lazy_entries array because
			k += processed;
		}


		if (same_name(ce, name, namelen, icase))
	return dir && dir->nr;

	nr_each = DIV_ROUND_UP(istate->cache_nr, lazy_nr_dir_threads);
	struct dir_entry **dir_new_out)

			lazy_entries[k].dir->nr++;


	/* get length of parent directory */
		err = pthread_create(&td_dir_t->pthread, NULL, lazy_dir_thread_proc, td_dir_t);


			lazy_entries[k].hash_name = memihash_cont(
 * the hash tables.  We set "lazy_nr_dir_threads" to zero when
static void init_dir_mutex(void)

		pthread_mutex_destroy(&lazy_dir_mutex_array[j]);
	/*
	if (istate->name_hash_initialized)
}
				end = mid;
	lazy_init_name_hash(istate);


static int cache_entry_cmp(const void *unused_cmp_data,
	struct lazy_entry *lazy_entries)
	int input_prefix_len = prefix->len;
	td_name->istate = istate;
}
}
	struct dir_entry *parent,
	/*

}
			prefix->len - parent->namelen);
		return 0;
	const char *ptr = startPtr;

	return e1->namelen != e2->namelen || strncasecmp(e1->name,
		}
	 * If we are respecting case, just use the original
		hashmap_add(&d->istate->name_hash, &ce_k->ent);
			parent->nr++;

	k_start = 0;
			strbuf_addch(prefix, '/');

	ce2 = container_of(entry_or_key, const struct cache_entry, ent);

{
}
	return hashmap_get_entry(&istate->dir_hash, &key, ent, name);
 * For guidance setting the lower per-thread bound, see:
					 struct cache_entry, ent);
	assert((parent != NULL) ^ (strchr(prefix->buf, '/') == NULL));
	err = pthread_join(td_name->pthread, NULL);
 * the number on the system).
	int input_prefix_len = prefix->len;
		threaded_lazy_init_name_hash(istate);
{
	int k_end,
		struct cache_entry *ce, int namelen)
 * the non-threaded code path was used.
	 */
		hash = memihash_cont(parent->ent.hash,
		return 0;
		} else {


 * into "istate->dir_hash".  All "dir" threads are trying
			struct dir_entry *dir;
	int k_end;
			 const void *keydata)
	return remove ? !(ce1 == ce2) : 0;
 * that "all chains mod n" are guarded by the same mutex -- rather
	e1 = container_of(eptr, const struct dir_entry, ent);

 * directory.
		lazy_entries[k].dir = parent;
 */
	lock_dir_mutex(lock_nr);

			strbuf_setlen(prefix, input_prefix_len);

	unsigned int hash_name;


	istate->name_hash_initialized = 0;
	/*
			int processed;
void add_name_hash(struct index_state *istate, struct cache_entry *ce)

{


static int handle_range_1(
	key.namelen = namelen;
		unsigned char c1 = *name1++;
	int j;
		k = k_end;
	hashmap_entry_init(&key.ent, hash);

	for (j = 0; j < LAZY_MAX_MUTEX; j++)

	handle_range_1(d->istate, d->k_start, d->k_end, NULL, &prefix, d->lazy_entries);
		 * we do per-chain (mod n) locking rather than whole hashmap
 * Hashing names in the index state

static int slow_same_name(const char *name1, int len1, const char *name2, int len2)

		namelen--;
	if (ignore_case)

{
	hashmap_entry_init(&ce->ent, memihash(ce->name, ce_namelen(ce)));
	 * closing slash.  Despite submodules being a directory, they never
				begin = mid + 1;
	struct dir_entry key;
struct cache_entry *index_file_exists(struct index_state *istate, const char *name, int namelen, int icase)
static struct dir_entry *hash_dir_entry(struct index_state *istate,
	hashmap_free_entries(&istate->dir_hash, struct dir_entry, ent);
 * A test routine for t/helper/ sources.
{
				die("cache entry out of order");
	*dir_new_out = dir_new;
 */

	if (err)
 * hashtable.  Since "find" and "insert" operations will hash to a

{

/*
		 * on the "parent" dir.  So we defer actually updating
 * over their portions of the index, so lock contention is
	/* lookup existing entry for that directory */
static int lazy_try_threaded = 1;
};
	 * (Testing showed it wasn't worth running more than 1 thread for this.)
{
	lazy_init_name_hash(istate);
	ce = hashmap_get_entry_from_hash(&istate->name_hash, hash, NULL,
 *
		unsigned char c2 = *name2++;
		return;
		if (err)


		hashmap_add(&istate->dir_hash, &dir->ent);
		nr_cpus = istate->cache_nr / LAZY_THREAD_COST;
}
		 */
static int lookup_lazy_params(struct index_state *istate)

 */

	lazy_dir_mutex_array = xcalloc(LAZY_MAX_MUTEX, sizeof(pthread_mutex_t));
#define LAZY_THREAD_COST (2000)
	struct strbuf *prefix,
static void lock_dir_mutex(int j)
			c1 = toupper(c1);
			else
{

	for (j = 0; j < LAZY_MAX_MUTEX; j++)
		remove_dir_entry(istate, ce);
struct lazy_entry {
		if (slash) {

 * clear_ce_flags_1() and clear_ce_flags_dir() in unpack-trees.c
	int lock_nr;
		hashmap_entry_init(&ce_k->ent, d->lazy_entries[k].hash_name);

	lazy_update_dir_ref_counts(istate, lazy_entries);
				continue;
	}
	if (!istate->name_hash_initialized)
			name ? name : e2->name, e1->namelen);
	 */
	 * Phase 2:
	hashmap_add(&istate->name_hash, &ce->ent);
 * An array of lazy_entry items is used by the n threads in

	lazy_nr_dir_threads = 0;
		k++;
	struct index_state *istate;

	return dir;
	int k_start,
		dir = dir->parent;
}
	 * with parent directory.

static void *lazy_name_thread_proc(void *_data)
	 * Scan forward in the index array for index entries having the same
		return 0;
		/* recursively add missing parent directories */
	struct index_state *istate,
		k_start += nr_each;
{
			else if (cmp > 0) /* mid is past group; look in first part */
		 * accumulate our current results into the lazy_entries
	int err;
	}

	}

	struct dir_entry *dir = hash_dir_entry(istate, ce, ce_namelen(ce));
{
static void threaded_lazy_init_name_hash(
			if (processed) {
static void cleanup_dir_mutex(void)
	struct dir_entry *parent;
			   const struct hashmap_entry *entry_or_key,

}
	 * we do the quick exact one first, because it will be the common case.
			break;
}

			int cmp = strncmp(istate->cache[mid]->name, prefix->buf, prefix->len);
}
	cleanup_dir_mutex();
		dir->parent = hash_dir_entry(istate, ce, namelen);
	 * Throw each directory component in the hash for quick lookup

			prefix->buf + parent->namelen,
		td_dir_t->k_start = k_start;
		const char *name, unsigned int namelen, unsigned int hash)
		return;
}
	struct lazy_name_thread_data *d = _data;
		name = ce_k->name + prefix->len;
			if (dir) {
		return 0;
};
	char name[FLEX_ARRAY];
#define LAZY_MAX_MUTEX   (32)
			lock_nr = compute_dir_lock_nr(&istate->dir_hash, parent->ent.hash);
				strbuf_setlen(prefix, input_prefix_len);
{
	 */
	ce1 = container_of(eptr, const struct cache_entry, ent);
	struct strbuf *prefix,
		slash = strchr(name, '/');
}
	}
}
	else if (strncmp(istate->cache[k_end - 1]->name, prefix->buf, prefix->len) == 0)
	 */
	return find_dir_entry__hash(istate, name, namelen, memihash(name, namelen));
 *
	struct dir_entry *dir = hash_dir_entry(istate, ce, ce_namelen(ce));
	const struct dir_entry *e1, *e2;
	int k_start;
	if (ce->ce_flags & CE_HASHED)
 * Set a minimum number of cache_entries that we will handle per
	struct index_state *istate,
			}
				startPtr = ptr + 1;
 * mutexes and lock on mutex[bucket(hash) % n].  This will
 * it is not worth it.
	/*

	lazy_init_name_hash(istate);

		hashmap_remove(&istate->dir_hash, &dir->ent, NULL);
 * require that we disable "rehashing" on the hashtable.)
	if (namelen <= 0)
	strbuf_addch(prefix, '/');
	dir_new = hash_dir_entry_with_parent_and_prefix(istate, parent, prefix);
			ptr++;
	struct dir_entry *dir;
	}
	struct strbuf *prefix,
	hashmap_free(&istate->name_hash);
	 */
			return ce;
	if (!icase)
	while (namelen > 0 && !is_dir_sep(ce->name[namelen - 1]))
{
#include "thread-utils.h"
	hashmap_init(&istate->dir_hash, dir_entry_cmp, NULL, istate->cache_nr);
{
			hash_index_entry(istate, istate->cache[nr]);
	else
	 * or the directory is an immediate child of the root directory.
		}
	 * Meanwhile, finish updating the parent directory ref-counts for each
			dir = find_dir_entry(istate, name, ptr - name);
	struct cache_entry *ce;
		/*

 * the 2 threads in the second phase.
	lock_nr = compute_dir_lock_nr(&istate->dir_hash, hash);
		 * It is too expensive to take a lock to insert "ce_k"
	dir = find_dir_entry(istate, name, namelen);
static int handle_range_dir(
	struct index_state *istate,
}
	struct lazy_entry *lazy_entries)
	unsigned int hash;
		while (begin < end) {
}
}
	if (ignore_case)

	/*
 * the directory parse (first) phase to (lock-free) store the
	 * index_file_exists, find all entries with matching hash code and
	/*
				ce_k->name + parent->namelen,

		if (c1 != c2) {
}
	strbuf_setlen(prefix, input_prefix_len);
		if (parent) {
		td_dir_t->lazy_entries = lazy_entries;

	return slow_same_name(name, namelen, ce->name, len);
			ptr++;
	 * Iterate over all index entries and add them to the "istate->name_hash"
{
}
			if (c1 != c2)
	if (k_start + 1 >= k_end)

			continue;
	 */
	int nr_cpus;
		if (parent) {
	}
	dir = find_dir_entry__hash(istate, prefix->buf, prefix->len, hash);
		td_dir_t->k_end = k_start;
			   const void *remove)
	unsigned int hash)
 * So, a larger value here decreases the probability of a collision
	 * Recurse and process what we can of this subset [k_start, k).
}
	lazy_init_name_hash(istate);
{
			k_start = istate->cache_nr;
	int j;
		while (*ptr && *ptr != '/')
	pthread_t pthread;
			lock_dir_mutex(lock_nr);
	free(lazy_dir_mutex_array);
	struct index_state *istate;
		dir->parent = parent;
		k = k_end;
static void lazy_init_name_hash(struct index_state *istate)
 */
	int rc, k;

}

		return NULL;
	td_name = xcalloc(1, sizeof(struct lazy_name_thread_data));
/*
 */
	/* Add reference to the directory entry (and parents if 0). */
	if (lookup_lazy_params(istate)) {
	free(lazy_entries);
	}
/*
{

	trace_performance_leave("initialize name hash");

{
	 * code to build the "istate->name_hash".  We don't
	else if (strncmp(istate->cache[k_start + 1]->name, prefix->buf, prefix->len) > 0)
	hashmap_remove(&istate->name_hash, &ce->ent, ce);
}

	struct dir_entry *parent,
	}

	struct lazy_name_thread_data *td_name;
		 *
	init_dir_mutex();



{
				ce_namelen(ce_k) - parent->namelen);
	int k;
	 */
 * particular bucket and modify/search a single chain, we can say
		return 1;
{
static void unlock_dir_mutex(int j)
struct lazy_dir_thread_data {
	while (len1) {

		FLEX_ALLOC_MEM(dir, name, prefix->buf, prefix->len);
	pthread_t pthread;

	}
		die(_("unable to create lazy_name thread: %s"), strerror(err));
		return 0;
{
	const struct cache_entry *ce1, *ce2;
	trace_performance_enter();
	struct strbuf prefix = STRBUF_INIT;
		}
	for (k = 0; k < istate->cache_nr; k++) {

/*
	if (len1 != len2)
		/* not found, create it and add to hash table */
	unsigned int hash_dir;
			processed = handle_range_dir(istate, k, k_end, parent, prefix, lazy_entries, &dir_new);
{
		 * into "istate->name_hash" and increment the ref-count

		 * can change the locking requirements) and simply
		 * and bucket items from being redistributed.
 * and the time that each thread must wait for the mutex.

}
 * than having a single mutex to guard the entire table.  (This does
	return hashmap_bucket(map, hash) % LAZY_MAX_MUTEX;
{
{
 *
	if (err)
 * name-hash.c
		struct cache_entry *ce_k = istate->cache[k];
	ce->ce_flags &= ~CE_HASHED;
	return NULL;

 * They use recursion for adjacent entries in the same parent


	 * during a git status. Directory components are stored without their
			unlock_dir_mutex(lock_nr);

void remove_name_hash(struct index_state *istate, struct cache_entry *ce)
 * Copyright (C) 2008 Linus Torvalds
			 const struct hashmap_entry *entry_or_key,
	struct dir_entry *dir;
}

	 */
	int nr;
		dir = parent;
	if (!ignore_case)
	td_name->lazy_entries = lazy_entries;

	if (parent)
	struct index_state *istate)
static int lazy_nr_dir_threads;
	strbuf_release(&prefix);
 *
	 * doesn't need threading.)

	 * in index_state.name_hash (as ordinary cache_entries).
	int k_start,
	if (!HAVE_THREADS)
	 * index entry using the current thread.  (This step is very fast and
	 */
 */
 *
	struct dir_entry *parent,
		FLEX_ALLOC_MEM(dir, name, ce->name, namelen);
	if (!istate->name_hash_initialized || !(ce->ce_flags & CE_HASHED))
	if (!lazy_try_threaded)
	lazy_try_threaded = try_threaded;
 * decrease the collision rate by (hopefully) a factor of n.
	ce->ce_flags |= CE_HASHED;
 * Requesting threading WILL NOT override guards
{
}
	 * path prefix (that are also in this directory).
static struct dir_entry *find_dir_entry(struct index_state *istate,
}
static void remove_dir_entry(struct index_state *istate, struct cache_entry *ce)
		len1--;
#include "cache.h"
 * handle_range_1() and handle_range_dir() are derived from
		if (lazy_entries[k].dir)
			die(_("unable to create lazy_dir thread: %s"), strerror(err));
{
		 * we have exclusive access to the cells in the range
 *     t/helper/test-lazy-init-name-hash --analyze
	}
	int k_start,
static inline int compute_dir_lock_nr(
 *
	struct lazy_entry *lazy_entries);
	struct dir_entry *dir;
	int k_end,
	int k_end,
	unlock_dir_mutex(lock_nr);
	struct lazy_entry *lazy_entries;

	while (dir && !(--dir->nr)) {
	return NULL;
		 * locking and we need to prevent the table-size from changing
		return;

	dir = find_dir_entry(istate, ce->name, namelen);
 * thread and use that to decide how many threads to run (up to
		if (pthread_join(td_dir_t->pthread, NULL))
		int begin = k_start;
	for (k = 0; k < d->istate->cache_nr; k++) {
		}

	pthread_mutex_lock(&lazy_dir_mutex_array[j]);
	if (!dir) {
		}
			if (cmp == 0) /* mid has same prefix; look in second part */

		for (nr = 0; nr < istate->cache_nr; nr++)
/*


 * and handle the iteration over the entire array of index entries.
	pthread_mutex_unlock(&lazy_dir_mutex_array[j]);
	struct strbuf *prefix)
	unsigned int hash = memihash(name, namelen);

	 * For remove_name_hash, find the exact entry (pointer equality); for
	else {
	struct lazy_entry *lazy_entries,
		ce_k->ce_flags |= CE_HASHED;
		hash_index_entry(istate, ce);

	 */
}
 */
	for (t = 0; t < lazy_nr_dir_threads; t++) {
	int len = ce_namelen(ce);
	}
	struct index_state *istate,
/*
		struct cache_entry *ce_k = d->istate->cache[k];
		if (*ptr == '/') {
 * Decide if we want to use threads (if available) to load
			strbuf_add(prefix, name, len);
{
	int k = k_start;
 * in lookup_lazy_params().
	 * Release reference to the directory entry. If 0, remove and continue
		hash = memihash(prefix->buf, prefix->len);
