			if (is_null_oid(&ce->oid))
				} else if (!ce_uptodate(ce) &&

}
	if (istate->split_index) {

		 * CE_UPDATE_IN_BASE. If istate->cache[i] is a

				 struct cache_entry *new_entry)
	for (i = si->nr_replacements; i < si->saved_cache_nr; i++) {
		if (!ce_namelen(si->saved_cache[i]))
				}
void replace_index_entry_in_base(struct index_state *istate,
		base->cache[i]->index = i + 1;
			}
void finish_writing_split_index(struct index_state *istate)
		discard_split_index(istate);
}
}
					 * The entry is only present in the
			ce = istate->cache[i];
}
		 */
		si->saved_cache[i] = NULL;
	si->nr_replacements = 0;
	 * for writing
				/*
 * Compare most of the fields in two cache entries, i.e. all except the
					/*
		die("entry %d is marked as both replaced and deleted",


			 * validate them.

	src->index = pos + 1;
	si->replace_bitmap = NULL;
	sz -= ret;
}
{
		new_entry->index = old_entry->index;
		return;
 */
	if (ret < 0)
{
	 */
		 * memory pool has been incorporated into the
	if (si->nr_deletions)
	si->nr_replacements++;
void remove_split_index(struct index_state *istate)
					  CE_EXTENDED_FLAGS;
	istate->cache[pos]->ce_flags |= CE_REMOVE;
	src = si->saved_cache[si->nr_replacements];
				ADD_CACHE_OK_TO_ADD |
	 */
void move_cache_to_base_index(struct index_state *istate)
				ce->index = 0;
}
				 * that already has a cache entry in the
		 * entry with positive index. We'll go through
				 * Thoroughly compare the cached data to see

	if (si->base &&
			struct cache_entry *base;
	ret = ewah_read_mmap(si->delete_bitmap, data, sz);
	istate->cache_nr = si->saved_cache_nr;
				 * added to the split index.
	int ret;
			}
	    istate->split_index->base &&
			/*
					 * can smudge its stat data.
	ewah_each_bit(si->replace_bitmap, replace_entry, istate);
{
				 * file was modified and the cached stat data
{
			 * mark the index as having no cache entries, so it
	}
	struct index_state *istate = data;
				 * does, which has this flag on
		istate->cache_changed |= SPLIT_INDEX_ORDERED;
		 * duplicate, deduplicate it.
	istate->split_index->nr_deletions++;
{

					 istate->split_index->base->ce_mem_pool);
	ewah_serialize_strbuf(si->delete_bitmap, sb);
	 * To keep track of the shared entries between
				 * During simple update index operations this
		/* Go through istate->cache[] and mark CE_MATCHED to
			istate->split_index->base->cache_nr = 0;
		ce->ce_flags |= CE_REMOVE;
int read_link_extension(struct index_state *istate,
	b->ce_flags = base_flags;
	 * istate->base->cache[] and istate->cache[], base entry
				 */
	ALLOC_GROW(istate->cache, istate->cache_nr, istate->cache_alloc);
	si->saved_cache_nr = istate->cache_nr;
	ewah_free(si->delete_bitmap);
				/*
		    "zero length name", (int)pos);
	si->nr_deletions = 0;
				ADD_CACHE_KEEP_CACHE_TREE |
void merge_base_index(struct index_state *istate)
			    strcmp(ce->name, base->name)) {
	b->ce_flags &= ondisk_flags;
				continue;
		die("too many replacements (%d vs %d)",
static int compare_ce_content(struct cache_entry *a, struct cache_entry *b)
{

			mem_pool_combine(istate->ce_mem_pool,
		return error("corrupt link extension (too short)");
	if (ret != sz)
	if (pos >= istate->cache_nr)
				 * the split index.
	src->ce_flags |= CE_UPDATE_IN_BASE;
	struct split_index *si = istate->split_index;
				ALLOC_GROW(entries, nr_entries+1, nr_alloc);
					 * Nothing more to do here.
	si->base->cache_nr = istate->cache_nr;
	strbuf_add(sb, si->base_oid.hash, the_hash_algo->rawsz);
		si->base->cache[i]->ce_flags &= ~CE_UPDATE_IN_BASE;
				/*
		 * base->cache[] later to delete all entries in base
				/*
	si->delete_bitmap = NULL;
{
	 * position is stored in each base entry. All positions start
		}
			 * ownership of the mem_pool associated with the
		/*
	 * The mem_pool needs to move with the allocated entries.
	ewah_free(si->replace_bitmap);
}
	unsigned int i;

	    istate->split_index &&
	if (!si)
	si->delete_bitmap  = NULL;
		 * memory pool associated with the the_index.
	istate->cache = entries;
				 * A copy of a racily clean cache entry from
			} else if (!ce_uptodate(ce) &&
				 * shared index, but a new index has just

}
				 * entry already had a replacement entry in
		    (int)pos, istate->cache_nr);
	}
	 * from 1 instead of 0, which is reserved to say "this is a new
		init_split_index(istate);
{

		add_index_entry(istate, si->saved_cache[i],
	 * entries to the parent index.

				continue;
	struct cache_entry **entries = NULL, *ce;
	    ce == istate->split_index->base->cache[ce->index - 1])
	COPY_ARRAY(si->base->cache, istate->cache, istate->cache_nr);
	if (!si->delete_bitmap && !si->replace_bitmap)
	FREE_AND_NULL(si->saved_cache);
				 * split index.
		    (int)pos);
				ce->ce_flags |= CE_UPDATE_IN_BASE;
			 */
					/*
				/*
{
	 */

{
	ewah_each_bit(si->delete_bitmap, mark_entry_for_delete, istate);
				 * original entry in the shared index will be
	si->delete_bitmap = ewah_new();
	mark_base_index_entries(si->base);
		}
 * hashmap_entry and the name.
		istate->split_index = xcalloc(1, sizeof(*istate->split_index));
				if (ce->ce_flags & CE_UPDATE_IN_BASE) {
			discard_cache_entry(istate->split_index->base->cache[new_entry->index - 1]);
	si->saved_cache_nr = 0;
					 */
				 * in the split index.
				} else {
					ce->ce_flags |= CE_UPDATE_IN_BASE;
				 * marked as deleted, and this entry will be
				 * index, e.g. during 'read-tree -m HEAD^' or
	}
	const unsigned int ondisk_flags = CE_STAGEMASK | CE_VALID |
			 */
	    old_entry->index <= istate->split_index->base->cache_nr) {
			if (ce->ce_flags & CE_UPDATE_IN_BASE) {
	ewah_serialize_strbuf(si->replace_bitmap, sb);
	 */
			}
			 * When removing the split index, we need to move
	free(istate->cache);
	si->refcount--;
	struct split_index *si = istate->split_index;
					 * the corresponding file was
	istate->split_index = NULL;
		 * We can discard the split index because its
					 * Already marked for inclusion in


}
	/* zero timestamp disables racy test in ce_write_index() */
{
	struct index_state *istate = data;
	COPY_ARRAY(istate->cache, si->base->cache, istate->cache_nr);
				entries[nr_entries++] = ce;
				 * is a cache entry that is not present in
#include "ewah/ewok.h"
		if (istate->split_index->base) {

	if (!istate->split_index) {

		return;
			if (!ce->index) {
					 * be added to the split index, so
	if (!istate->split_index) {
					 */
				ewah_set(si->delete_bitmap, i);
		if ((!si->base || !ce->index) && !(ce->ce_flags & CE_REMOVE)) {
	mark_base_index_entries(si->base);
void add_split_index(struct index_state *istate)
void save_or_free_index_entry(struct index_state *istate, struct cache_entry *ce)
	istate->ce_mem_pool = NULL;
		si->base->ce_mem_pool) {
	si->replace_bitmap = NULL;
		}
	for (i = 0; i < istate->cache_nr; i++) {
				 */
	src->ce_namelen = dst->ce_namelen;
		istate->split_index->refcount = 1;
	hashcpy(si->base_oid.hash, data);
	int i, nr_entries = 0, nr_alloc = 0;
			 * This is the copy of a cache entry that is present
	    ce->index <= istate->split_index->base->cache_nr &&
				 * the split index, so the subsequent
			base = si->base->cache[ce->index - 1];
	if (si->base) {
		return 0;
			if (ce->ce_namelen != base->ce_namelen ||
					 * was refreshed, or because there
	if (si->refcount)
		}
	sz -= the_hash_algo->rawsz;
	}
	struct split_index *si = istate->split_index;

{
	int i;
	for (i = 0; i < si->base->cache_nr; i++)
			} else {
			discard_cache_entry(base);
	struct split_index *si;
				 * index, either because the corresponding
	}
				 * we may have to replay what
	struct split_index *si = init_split_index(istate);
	return istate->split_index;
static void replace_entry(size_t pos, void *data)
}
				 *
void prepare_to_write_split_index(struct index_state *istate)
		    si->nr_replacements, si->saved_cache_nr);
					 * the split index, either because
		for (i = 0; i < si->base->cache_nr; i++) {
			 const void *data_, unsigned long sz)
}
	if (sz < the_hash_algo->rawsz)
			/*
	int ret;
			    !(ce->ce_flags & CE_MATCHED))
	    istate->split_index &&


		if (old_entry != istate->split_index->base->cache[new_entry->index - 1])
	istate->cache_nr = nr_entries;
			 * its cache array. As we are discarding this index,
		     offsetof(struct cache_entry, ce_stat_data));
		 * that are not marked with either CE_MATCHED or
			entries[nr_entries++] = ce;

	for (i = 0; i < base->cache_nr; i++)


				 * was refreshed, or because the original
		discard_cache_entry(ce);
				 * Already marked for inclusion in the split
				 * Nothing to do.
					 * the split index.
	/*
	si->base->version = istate->version;

				 * do_write_index() can smudge its stat data.
	istate->cache_alloc = 0;
	/*
				 * been constructed by unpack_trees(), and
	/*
		if (!istate->ce_mem_pool)
	struct split_index *si = istate->split_index;
{
	const unsigned char *data = data_;
void discard_split_index(struct index_state *istate)
	dst = istate->cache[pos];

	istate->cache	    = NULL;
			}
			 * allocated from the base's memory pool that are shared with

	unsigned int ce_flags = a->ce_flags;
			}
		mem_pool_combine(istate->ce_mem_pool, istate->split_index->base->ce_mem_pool);
			 * the_index.cache[].
}


	a->ce_flags &= ondisk_flags;
					 * modified and the cached stat data
			 * base index to the main index. There may be cache entries
				 */
			 * will not attempt to clean up the cache entries or
	ALLOC_GROW(si->base->cache, istate->cache_nr, si->base->cache_alloc);
					 * Just leave it there.
	if (si->base) {
			if ((ce->ce_flags & CE_REMOVE) ||
			 */
				 * merge-recursive.c:update_stages()
				 * However, it might also represent a file
					 * A racily clean cache entry stored
				   is_racy_timestamp(istate, ce)) {
	return ret;
					ce->ce_flags |= CE_UPDATE_IN_BASE;
			mem_pool_init(&istate->ce_mem_pool, 0);
	struct split_index *si = istate->split_index;
	struct split_index *si = init_split_index(istate);
			ALLOC_GROW(entries, nr_entries+1, nr_alloc);
				 struct cache_entry *old_entry,
}

	unsigned int base_flags = b->ce_flags;
		return error("corrupt replace bitmap in link extension");
		return error("garbage at the end of link extension");
		return 0;

				ADD_CACHE_SKIP_DFCHECK);
	si->base = xcalloc(1, sizeof(*si->base));


}
	struct cache_entry *dst, *src;
		ce->ce_flags &= ~CE_MATCHED;
	/*
	si->base->timestamp = istate->timestamp;
		ce = istate->cache[i];
	si->saved_cache = istate->cache;
				 * code paths modifying the cached data do
			assert(!(ce->ce_flags & CE_STRIP_NAME));
				BUG("ce refers to a shared ce at %d, which is beyond the shared index size %d",
				ce->ce_flags |= CE_STRIP_NAME;
	istate->cache_nr    = si->base->cache_nr;
				 *
	copy_cache_entry(dst, src);
	discard_cache_entry(src);
				 */
}
	si->base->ce_mem_pool = istate->ce_mem_pool;
	data += the_hash_algo->rawsz;

			}
				/* The entry is present in the shared index. */
static void mark_entry_for_delete(size_t pos, void *data)
	}
		istate->cache_changed |= SOMETHING_CHANGED;
		     offsetof(struct cache_entry, name) -
	ewah_free(si->delete_bitmap);
					 * refreshed.
				 * 'checkout HEAD^'.  In this case the
		return error("corrupt delete bitmap in link extension");
				continue;
		die("position for delete %d exceeds base index size %d",
struct split_index *init_split_index(struct index_state *istate)
#include "split-index.h"
	/* only on-disk flags matter */
		free(si->base);

	si->replace_bitmap = ewah_new();
			    "have non-zero length name", i);
					 * shared index and it was not
	else
		remove_marked_cache_entries(istate, 0);
{
				 * this entry now refers to different content
			 * while it constructed a new index.
				 * the shared index.  It will be added to the
	if (dst->ce_flags & CE_REMOVE)
		    (int)pos, istate->cache_nr);
int write_link_extension(struct strbuf *sb,
	ret = ewah_read_mmap(si->replace_bitmap, data, sz);
		die("position for replacement %d exceeds base index size %d",
		for (i = 0; i < istate->cache_nr; i++) {
				if (compare_ce_content(ce, base))
	 * If there was a previous base index, then transfer ownership of allocated
	}
			si->base->cache[ce->index - 1] = ce;
	istate->cache = si->saved_cache;
	free(si);
		istate->split_index->base->cache[new_entry->index - 1] = new_entry;
			if (ce->index > si->base->cache_nr) {
			if (ce == base) {
	    istate->split_index->base &&
	if (ret < 0)
	ewah_free(si->replace_bitmap);
					 * only in the shared index: it must
					 * the subsequent do_write_index()
}
					/*
	if (ce_namelen(src))
	 * entry".
				 * whether it should be marked for inclusion
				 * the shared index.  It must be added to
			die("corrupt link extension, entry %d should "
			 * The split index no longer owns the mem_pool backing
/*
	if (old_entry->index &&
					 * is already a replacement entry in
	if (!sz)
	ret = memcmp(&a->ce_stat_data, &b->ce_stat_data,
			ce->ce_flags |= CE_MATCHED; /* or "shared" */
	if (si->nr_replacements >= si->saved_cache_nr)
#include "cache.h"
					   is_racy_timestamp(istate, ce)) {
			/*
	}
	data += ret;
{
				 * set CE_UPDATE_IN_BASE as well.
			ce = si->base->cache[i];
			 struct index_state *istate)


		 */
				 */
	int i;
	return 0;
{
					 */
	si->saved_cache_nr  = istate->cache_nr;
				    ce->index, si->base->cache_nr);
		die("corrupt link extension, entry %d should have "

		discard_index(si->base);
			 * in the shared index, created by unpack_trees()
	si = init_split_index(istate);
	a->ce_flags = ce_flags;
	return 0;
	si->delete_bitmap = ewah_new();
	si->saved_cache	    = istate->cache;
	if (pos >= istate->cache_nr)
static void mark_base_index_entries(struct index_state *base)
	}

				istate->drop_cache_tree = 1;
			else if (ce->ce_flags & CE_UPDATE_IN_BASE) {
	if (ce->index &&
	si->replace_bitmap = ewah_new();
				 * than what was recorded in the original
	 * take cache[] out temporarily, put entries[] in its place
				 * This comparison might be unnecessary, as
				ewah_set(si->replace_bitmap, i);
