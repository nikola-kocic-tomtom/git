		}

		die_errno("unable to make temporary bitmap file readable");
			parent->item->object.flags |= SEEN;
		return NULL;
}
static void compute_xor_offsets(void)
	revs.no_walk = 0;

	writer.selected[writer.selected_nr].bitmap = reused;

			break;
	next = (offset < MAX_COMMITS) ? offset : MAX_COMMITS;
			real_type = oid_object_info(to_pack->repo,
			object_array_clear(&revs.pending);
	revs.include_check = should_include;
	ALLOC_ARRAY(to_pack->in_pack_pos, to_pack->nr_objects);

	writer.tags = ewah_new();

}
	struct ewah_bitmap *commits;

static int date_compare(const void *_a, const void *_b)
		next++;
		die_errno("unable to rename temporary bitmap file to '%s'", filename);
	return oe_in_pack_pos(writer.to_pack, entry);

			int curr = next - i;

	uint32_t bitmap_pos = find_object_pos(&commit->object.oid);
			stored->flags |= BITMAP_FLAG_REUSE;



}
{

		hashwrite(f, &hash_value, sizeof(hash_value));
	need_reset = 0;


	finalize_hashfile(f, NULL, CSUM_HASH_IN_STREAM | CSUM_FSYNC | CSUM_CLOSE);

		case OBJ_TAG:
		struct ewah_bitmap *test_xor;
	struct bitmap *base = data;
		return;

{
}
	struct bitmapped_commit *selected;
		if (max_bitmaps > 0 && writer.selected_nr >= max_bitmaps) {

	dump_bitmap(f, writer.blobs);

				struct commit *cm = indexed_commits[i + j];

		int hash_ret;

			need_reset = 1;
			if (prepare_revision_walk(&revs))
void bitmap_writer_build_type_index(struct packing_data *to_pack,
	int show_progress;
		REALLOC_ARRAY(writer.selected, writer.selected_alloc);
			}
}
	static const unsigned int MAX_COMMITS = 5000;
{
		kh_value(writer.bitmaps, hash_pos) = stored;

		writer.progress = start_progress("Selecting bitmap commits", 0);

}
				      uint32_t index_nr)
}
	for (i = writer.selected_nr - 1; i >= 0; --i) {
#include "sha1-lookup.h"
 * Build the initial type index for the packfile

	int flags;

		hashwrite_u8(f, stored->xor_offset);
	struct ewah_bitmap *tags;
#include "diff.h"
{
	header.options = htons(flags | options);
					chosen = cm;
{

	struct bitmap *base = _data;
#include "list-objects.h"
	mark_as_seen((struct object *)commit);
		case OBJ_TREE:
	revs.tree_objects = 1;
static const unsigned char *sha1_access(size_t pos, void *table)
		seen_objects[i]->flags &= ~(SEEN | ADDED | SHOWN);
	static uint16_t flags = BITMAP_OPT_FULL_DAG;
	if (writer.show_progress)
					     stored->commit))) {
	return 1;
	if (indexed_commits_nr < 100) {
	mark_as_seen(object);
	}
static inline void reset_all_seen(void)
	}
static struct bitmap_writer writer;

	header.version = htons(default_version);
						    &entry->idx.oid, NULL);
};

static uint32_t find_object_pos(const struct object_id *oid)
	bitmap_set(base, find_object_pos(&object->oid));
	/* hashwrite will die on error */
			writer.selected_nr = max_bitmaps;
			  uint32_t index_nr,

#include "revision.h"
		case OBJ_BLOB:


		stored->write_as = best_bitmap;
	writer.bitmaps = kh_init_oid_map();
	int i;
 */
		enum object_type real_type;

	seen_objects_nr = 0;
{
	if (!entry) {


}

				ewah_pool_free(test_xor);

	/*
					break;

		oe_set_in_pack_pos(to_pack, entry, i);

	hashwrite(f, buf, len);
			die("Missing type information for %s (%d/%d)",
			}
	if (ewah_serialize_to(bitmap, hashwrite_ewah_helper, f) < 0)
	bitmap_set(base, bitmap_pos);
void bitmap_writer_set_checksum(unsigned char *sha1)
		}


	hash_pos = kh_get_oid_map(writer.reused, *oid);
{
		struct commit *chosen = NULL;
	write_selected_commits_v1(f, index, index_nr);
static void show_object(struct object *object, const char *name, void *data)
			reused_bitmap = find_reused_bitmap(&chosen->object.oid);

void bitmap_writer_show_progress(int show)
		struct object_entry *entry = (struct object_entry *)index[i];
{

	if (adjust_shared_perm(tmp_file.buf))
#include "pack-bitmap.h"
		display_progress(writer.progress, i);
	static const unsigned int MUST_REGION = 100;
{

			break;
			  const char *filename,


		switch (oe_type(entry)) {
}
	 */

			chosen = indexed_commits[i + next];
}
	dump_bitmap(f, writer.trees);
static inline void mark_as_seen(struct object *object)

}
	if (writer.selected_nr >= writer.selected_alloc) {
		uint32_t hash_value = htonl(entry->hash);
				    uint32_t index_nr)
	writer.blobs = ewah_new();
		case OBJ_COMMIT:
/**
				die("revision walk setup failed");
{
{
 */
			break;
static struct object **seen_objects;

	hashcpy(header.checksum, writer.pack_checksum);
	writer.to_pack = to_pack;
			ewah_set(writer.trees, i);

			"(object %s is missing)", oid_to_hex(oid));
	if (options & BITMAP_OPT_HASH_CACHE)

		if (stored->bitmap == NULL) {

}
	struct pack_idx_entry **index = table;
		if (i >= reuse_after)
			break;
	dump_bitmap(f, writer.tags);
	writer.commits = ewah_new();
{

#include "object-store.h"

	if (!add_to_include_set(base, commit)) {
			     uint32_t index_nr)
	}
	static const int MAX_XOR_OFFSET_SEARCH = 10;
		hash_pos = kh_put_oid_map(writer.bitmaps, object->oid, &hash_ret);
}
{
		return NULL;
		case OBJ_TREE:
	struct commit *commit;
	struct commit *b = *(struct commit **)_b;

	writer.show_progress = show;
			chosen = indexed_commits[i];
		hashwrite_be32(f, commit_pos);
	struct commit *a = *(struct commit **)_a;
		struct ewah_bitmap *best_bitmap = stored->bitmap;
	struct progress *progress;
		}
{
static inline void push_bitmapped_commit(struct commit *commit, struct ewah_bitmap *reused)
	writer.selected[writer.selected_nr].flags = 0;

#include "pack.h"

	if (rename(tmp_file.buf, filename))
	hashwrite(f, &header, sizeof(header) - GIT_MAX_RAWSZ + the_hash_algo->rawsz);
			if (curr < 0)

}
	}
	if (idx <= MIN_REGION) {

static inline void dump_bitmap(struct hashfile *f, struct ewah_bitmap *bitmap)
	return 1;
#include "commit.h"

					ewah_pool_free(best_bitmap);
	struct rev_info revs;
		struct bitmapped_commit *stored = &writer.selected[next];

{
	repo_init_revisions(to_pack->repo, &revs, NULL);
#include "commit-reach.h"
static void write_hash_cache(struct hashfile *f,
		struct bitmapped_commit *stored = &writer.selected[i];
		mark_as_seen((struct object *)commit);
		if (hash_ret == 0)
	return (long)b->date - (long)a->date;



 */
					chosen = cm;
	 * some bitmaps in bitmap_git, so we can't free the latter.


void bitmap_writer_select_commits(struct commit **indexed_commits,

	struct strbuf tmp_file = STRBUF_INIT;
	int i, reuse_after, need_reset;
#include "pack-revindex.h"

		for (i = 1; i <= MAX_XOR_OFFSET_SEARCH; ++i) {
			if (i < writer.selected_nr - 1 &&
	reset_revision_walk();
		khiter_t hash_pos;
			  uint16_t options)

#include "progress.h"
	revs.blob_objects = 1;

			ewah_set(writer.commits, i);

#include "cache.h"
		if (i + next >= indexed_commits_nr)
static inline unsigned int next_commit_index(unsigned int idx)

{

 * Write the bitmap index to disk

	static const unsigned int MIN_COMMITS = 100;
		} else {
		write_hash_cache(f, index, index_nr);
			die("Duplicate entry when writing index: %s",
				    struct pack_idx_entry **index,
		default:
		stored->xor_offset = best_offset;
		i += next + 1;
add_to_include_set(struct bitmap *base, struct commit *commit)
	hashcpy(writer.pack_checksum, sha1);

{

	uint32_t i;
	revs.tag_objects = 1;
	}

		display_progress(writer.progress, writer.selected_nr - i);
		die("Failed to write bitmap index. Packfile doesn't have full closure "
			}
	dump_bitmap(f, writer.commits);
}

	struct ewah_bitmap *bitmap;
		return 0;
	 * NEEDSWORK: rebuild_existing_bitmaps() makes writer.reused reference
	unsigned int i;

		} else
		hashwrite_u8(f, stored->flags);
		next = next_commit_index(i);
			push_bitmapped_commit(indexed_commits[i], NULL);
	stop_progress(&writer.progress);
				break;
static int hashwrite_ewah_helper(void *f, const void *buf, size_t len)
	unsigned char pack_checksum[GIT_MAX_RAWSZ];


	memcpy(header.magic, BITMAP_IDX_SIGNATURE, sizeof(BITMAP_IDX_SIGNATURE));
		return (offset < MIN_COMMITS) ? offset : MIN_COMMITS;
	}

	for (i = 0; i < seen_objects_nr; ++i) {

	kh_oid_map_t *bitmaps;

	writer.selected_nr++;
			    oid_to_hex(&object->oid));
		die("Failed to write bitmap index");

{
		offset = idx - MUST_REGION;

	strbuf_release(&tmp_file);

	struct bitmap *base = bitmap_new();
	QSORT(indexed_commits, indexed_commits_nr, date_compare);
			add_pending_object(&revs, object, "");
		case OBJ_COMMIT:
	struct bitmap_index *bitmap_git;
	if (hash_pos >= kh_end(writer.reused))
		}
			    bitmap_reset(base);
	return index[pos]->oid.hash;
};
			for (j = 0; j <= next; ++j) {

	struct bitmap_disk_header header;
	}
	unsigned int i = 0, j, next;
	khiter_t hash_pos;
{
	uint32_t i;
		stored = &writer.selected[i];
	}

static void show_commit(struct commit *commit, void *data)
	writer.reused = kh_init_oid_map();
	static uint16_t default_version = 1;
 * Select the commits that will be bitmapped
		writer.progress = start_progress("Building bitmaps", writer.selected_nr);
static struct ewah_bitmap *find_reused_bitmap(const struct object_id *oid)
	hash_pos = kh_get_oid_map(writer.bitmaps, commit->object.oid);
	ALLOC_GROW(seen_objects, seen_objects_nr + 1, seen_objects_alloc);
	if (writer.show_progress)
		struct commit_list *parent = commit->parents;
should_include(struct commit *commit, void *_data)
 */
}

			parent = parent->next;
			sha1_pos(stored->commit->object.oid.hash, index, index_nr, sha1_access);
	unsigned int selected_nr, selected_alloc;

static int

static void write_selected_commits_v1(struct hashfile *f,
	return kh_value(writer.reused, hash_pos);
		return 0;
		switch (real_type) {
	for (i = 0; i < index_nr; ++i) {
	for (;;) {
			need_reset = 0;
		struct bitmapped_commit *bc = kh_value(writer.bitmaps, hash_pos);
	if (!writer.reused)
	static const unsigned int MIN_REGION = 20000;
			real_type = oe_type(entry);


	if (!(bitmap_git = prepare_bitmap_git(to_pack->repo)))

		bitmap_or_ewah(base, bc->bitmap);
	kh_oid_map_t *reused;




void bitmap_writer_finish(struct pack_idx_entry **index,
			    (need_reset ||
	int xor_offset;

	}
	if (bitmap_get(base, bitmap_pos))
			ewah_xor(writer.selected[curr].bitmap, stored->bitmap, test_xor);

		dump_bitmap(f, stored->write_as);
struct bitmapped_commit {
			if (test_xor->buffer_size < best_bitmap->buffer_size) {
	struct hashfile *f;
	}
			traverse_commit_list(&revs, show_commit, show_object, base);
				  unsigned int indexed_commits_nr,
	writer.selected[writer.selected_nr].commit = commit;
static unsigned int seen_objects_nr, seen_objects_alloc;
			mark_as_seen((struct object *)parent->item);

{


	uint32_t commit_pos;
/**
		struct bitmapped_commit *stored;
		push_bitmapped_commit(chosen, reused_bitmap);
	int fd = odb_mkstemp(&tmp_file, "pack/tmp_bitmap_XXXXXX");
	}
		return;

				reused_bitmap = find_reused_bitmap(&cm->object.oid);
		int commit_pos =
		for (i = 0; i < indexed_commits_nr; ++i)
{
			} else {
{
	compute_xor_offsets();
	if (idx <= MUST_REGION)
			ewah_set(writer.blobs, i);
}
		}
			revs.include_check_data = base;
		struct object_entry *entry = (struct object_entry *)index[i];
	stop_progress(&writer.progress);
	static const double REUSE_BITMAP_THRESHOLD = 0.2;
	rebuild_existing_bitmaps(bitmap_git, to_pack, writer.reused,
				best_bitmap = test_xor;

				if (best_bitmap != stored->bitmap)

			break;
				 writer.show_progress);
			     !in_merge_bases(writer.selected[i + 1].commit,


			break;
}
}
	header.entry_count = htonl(writer.selected_nr);
void bitmap_writer_build(struct packing_data *to_pack)
static int

	struct ewah_bitmap *write_as;
			test_xor = ewah_pool_new();


				      struct pack_idx_entry **index,

		while (parent) {
}
		}
}
 * Compute the actual bitmaps
				}
	int i, next = 0;
#include "pack-objects.h"

	unsigned int offset, next;
			ewah_set(writer.tags, i);

	f = hashfd(fd, tmp_file.buf);
			break;
	struct packing_data *to_pack;
	for (i = 0; i < writer.selected_nr; ++i) {
		struct object *object;
			     struct pack_idx_entry **index,
			BUG("trying to write commit not in index");
}



			stored->bitmap = bitmap_to_ewah(base);
	struct ewah_bitmap *blobs;
		case OBJ_TAG:
		writer.selected_alloc = (writer.selected_alloc + 32) * 2;
				if (cm->parents && cm->parents->next)
	struct ewah_bitmap *trees;
		struct ewah_bitmap *reused_bitmap = NULL;
	}

/**
	khiter_t hash_pos;
		if (commit_pos < 0)

{
		if (next == 0) {

	seen_objects[seen_objects_nr++] = object;
#include "tag.h"
void bitmap_writer_reuse_bitmaps(struct packing_data *to_pack)
	reuse_after = writer.selected_nr * REUSE_BITMAP_THRESHOLD;
/**
	if (hash_pos < kh_end(writer.bitmaps)) {

	offset = idx - MIN_REGION;
struct bitmap_writer {
		return 0;
		return 0;
		object = (struct object *)stored->commit;
	struct object_entry *entry = packlist_find(writer.to_pack, oid);
				  int max_bitmaps)
}
{
	while (next < writer.selected_nr) {
				if (reused_bitmap || (cm->object.flags & NEEDS_BITMAP) != 0) {
}

			    oe_type(entry));
	return (next > MIN_COMMITS) ? next : MIN_COMMITS;
		default:
		int best_offset = 0;
	writer.trees = ewah_new();
			    oid_to_hex(&entry->idx.oid), real_type,
		case OBJ_BLOB:

				best_offset = i;
	}
			break;
			    reset_all_seen();
	return len;
	for (i = 0; i < index_nr; ++i) {

	bitmap_free(base);

