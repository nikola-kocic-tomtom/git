		struct revindex_entry *entry;
{
	     i++) {
	revs->tree_objects = 1;
	 * When trying to perform bitmap operations with objects that are not

				     &commit->object.oid);
	bitmap_git->map = NULL;
		if (base_pos < 0)
	/* if we don't want anything, we're done here */

		if (xor_offset > MAX_XOR_OFFSET || xor_offset > i)
 * the repository), since bitmap indexes need full closure.
				break;
	eword_t word;
{
#include "cache.h"
		}
		 */
				  show_reachable_fn show_reach)
		return; /* not actually in the pack */
};
	struct revindex_entry *revidx;
	if (revs->blob_objects)
void test_bitmap_walk(struct rev_info *revs)
			continue;

			if ((word >> offset) == 0)
int reuse_partial_packfile_from_bitmap(struct bitmap_index *bitmap_git,
	/*
	}
	struct object_list *p;
	bitmap_git = xcalloc(1, sizeof(*bitmap_git));
	/* If not NULL, this is a name-hash cache pointing into map. */
	 * Clear any blobs that weren't in the packfile (and so would not have
				  struct rev_info *revs,
				    struct object_list *tip_objects,

	if (b->map)
			unsigned char *end = index->map + index->map_size - the_hash_algo->rawsz;
		commit_idx_pos = read_be32(index->map, &index->map_pos);
		 * in our bitmaps. If we can't come up with an offset, or if
{
			struct tag *tag = (struct tag *) object;
{
	struct eindex *eindex = &bitmap_git->ext_index;
		incdata.bitmap_git = bitmap_git;
#include "tag.h"

				continue;
	if (load_bitmap_entries_v1(bitmap_git) < 0)
{
}
	     i++) {
	bitmap_git->map_size = 0;
			die(_("unable to get size of %s"), oid_to_hex(&obj->oid));
	}
	if (commits)
	 * individually.
		bitmap_and_not(wants_bitmap, haves_bitmap);
	display_progress(tdata->prg, ++tdata->seen);

		if (find_pack_entry_one(object->oid.hash, bitmap_git->pack) > 0)
	if (prepare_revision_walk(revs))
	if (i > bitmap_git->pack->num_objects / BITS_IN_EWORD)

	struct stat st;
		uint32_t pos = i + bitmap_git->pack->num_objects;
			  struct bitmap *dest)
failed:

		!(bitmap_git->trees = read_bitmap_1(bitmap_git)) ||
{
	struct bitmap_show_data *data = data_;
	tdata.prg = start_progress("Verifying bitmap entries", result_popcnt);
		}
}

static int load_bitmap_header(struct bitmap_index *index)
				  enum object_type type)
		if (haves_bitmap == NULL)
	/* filter choice not handled */
	if (!strip_suffix(p->pack_name, ".pack", &len))
struct bitmap_test_data {
	return idx >= 0 && bitmap_get(bitmap, idx);
		kh_oid_pos_t *positions;
	} else {

	idx = bitmap_position(bitmap_git, oid);



	struct eindex *eindex = &bitmap_git->ext_index;
	 * Drop any reused objects from the result, since they will not
			if (pos < kh_end(bitmap_git->bitmaps)) {
	struct object_list *wants = NULL;
	while (roots) {
	for (; i < result->word_alloc; ++i) {
		return -1;

	free(b);
			continue;
	struct stored_bitmap *stored;
}


	}
	tdata.base = bitmap_new();
	default:
	if (fstat(fd, &st)) {
			      uint32_t *commits, uint32_t *trees,
static char *pack_bitmap_filename(struct packed_git *p)
		show_objects_for_type(bitmap_git, OBJ_TAG, show_reachable);
	/*
			return;
			xor_bitmap = recent_bitmaps[(i - xor_offset) % MAX_XOR_OFFSET];
static void filter_bitmap_blob_none(struct bitmap_index *bitmap_git,
				else
{
#include "pack.h"
					base = ewah_to_bitmap(or_with);
{
				hash = get_be32(bitmap_git->hashes + entry->nr);
	bitmap_git->ext_index.positions = NULL;

	close(fd);
	struct ewah_bitmap *b = ewah_pool_new();
	if (needs_walk) {
		 * find REF_DELTA in a bitmapped pack, since we only bitmap
}
	ewah_pool_free(b->trees);

							  stored->oid,
	unsigned int i;
	result_popcnt = bitmap_popcount(result);

	fprintf(stderr, "Bitmap v%d test (%d entries loaded)\n",
		struct object *object = roots->item;

static unsigned long get_size_by_pos(struct bitmap_index *bitmap_git,

			if ((word >> offset) == 0)
	int ret = -1;
	if (load_pack_revindex(bitmap_git->pack))
			else /* can't reuse, we don't have the object */


	struct ewah_bitmap *blobs;
{
static void try_partial_reuse(struct bitmap_index *bitmap_git,
	struct ewah_iterator it;
		show_data.bitmap_git = bitmap_git;
		struct include_data incdata;

	object_list_free(&haves);
	/* Parse known bitmap format options */
static int ext_index_add_object(struct bitmap_index *bitmap_git,
{
#include "repository.h"
		bitmap_git->version, bitmap_git->entry_count);
		if (bitmap_git)
	/*
		    !bitmap_get(tips, pos) &&
			bitmap_reset(rebuild);

	struct bitmap *tips;


	parent = lookup_stored_bitmap(st->xor);

	 *
			oid_to_hex(&root->oid), (int)bm->bit_size, ewah_checksum(bm));
	return 0;
		show_objects_for_type(bitmap_git, OBJ_TREE, show_reachable);
	kh_oid_map_t *bitmaps;


		if (bitmap_git)
	int needs_walk = 0;
	struct ewah_bitmap *tags;

	if (haves_bitmap)


	ewah_pool_free(b->tags);


}
		struct object *obj;
	return !filter_bitmap(NULL, NULL, NULL, filter);
	uint32_t entry_count;
		base_pos = find_revindex_position(bitmap_git->pack, base_offset);
static inline uint8_t read_u8(const unsigned char *buffer, size_t *pos)
	     i < to_filter->word_alloc && ewah_iterator_next(&mask, &it);
	struct bitmap *objects = bitmap_git->result;

		size_t pos = (i * BITS_IN_EWORD);
		bitmap = read_bitmap_1(index);
			    get_size_by_pos(bitmap_git, pos) >= limit)
	}
	 * to push them to an actual walk and run it until we can confirm
}

 * If there is more than one bitmap index available (e.g. because of alternates),
						  NULL);
		pos += BITS_IN_EWORD;
		uint32_t pos = i + bitmap_git->pack->num_objects;

	/*
			     struct object_list *roots)
		 * and the normal slow path will complain about it in
	stored->xor = xor_with;
	}
		revs->ignore_missing_links = 0;
		eword_t word = objects->words[i++] & filter;
		goto failed;
	assert(bitmap_git->result);
					  struct stored_bitmap *xor_with,
					   const struct object_id *oid)
	off_t offset;
 */
	int pos = bitmap_position_packfile(bitmap_git, oid);
			REALLOC_ARRAY(eindex->hashes, eindex->alloc);

	}
					  struct ewah_bitmap *root,
#include "progress.h"
	init_type_iterator(&it, bitmap_git, type);

	revs->tag_objects = 1;
	 *
	}
}

		munmap(b->map, b->map_size);

			nth_packed_object_id(&oid, bitmap_git->pack, entry->nr);
	unsigned int version;

	return 1;
				     struct object_list *tip_objects,
	} else {
	while (i < result->word_alloc && result->words[i] == (eword_t)~0)
	assert(result);
					bitmap_or_ewah(base, or_with);
			parse_object_or_die(&object->oid, NULL);


			REALLOC_ARRAY(eindex->objects, eindex->alloc);
	return xstrfmt("%.*s.bitmap", (int)len, p->pack_name);
	/*
#define MAX_XOR_OFFSET 160


			parent = parent->next;
{
	stop_progress(&progress);
	size_t len;
void count_bitmap_commit_list(struct bitmap_index *bitmap_git,
		eindex->count++;
				struct ewah_bitmap *or_with = lookup_stored_bitmap(st);
		ewah_iterator_init(it, bitmap_git->commits);
		int xor_offset, flags;
		}

	return ret;
	for (i = 0; i < revs->pending.nr; ++i) {
	 * on the bitmap index will be `or`ed together to form an initial
		return 0;
{
		bitmap_walk_contains(bitmap_git, bitmap_git->haves, oid);
			      size_t pos,
	unsigned long size;

		    (obj->type == OBJ_TAG && !revs->tag_objects))
			     int show_progress)
		ewah_iterator_init(it, bitmap_git->blobs);
		return -1;
	if (load_pack_bitmap(bitmap_git) < 0)
						 to_filter,
		eword_t word = to_filter->words[i] & mask;
				 struct rev_info *revs,
	return count;

	*entries = bitmap_popcount(reuse);


		eindex->hashes[eindex->count] = pack_name_hash(name);
		obj = eindex->objects[i];
		*tags = count_object_type(bitmap_git, OBJ_TAG);
			add_pending_object(revs, object, "");

			return -1;

	size_t seen;
	 */
		bitmap_pos = eindex->count;
	traverse_commit_list(revs, &test_show_commit, &test_show_object, &tdata);
{
			eindex->alloc = (eindex->alloc + 16) * 3 / 2;
	struct bitmap_index *bitmap_git;
				hash_pos = kh_put_oid_map(reused_bitmaps,
	return bitmap_pos + bitmap_git->pack->num_objects;

{
	for (i = 0; i < num_objects; ++i) {
struct bitmap_index *prepare_bitmap_git(struct repository *r)
	uint32_t pos = 0;

			offset += ewah_bit_ctz64(word >> offset);
	hash_pos = kh_get_oid_map(bitmap_git->bitmaps, *oid);
 * Read a bitmap from the current read position on the mmaped
		while (parent) {

	return 0;
 * the active bitmap index is the largest one.
}

	uint32_t *hashes;
			index->hashes = ((uint32_t *)end) - index->pack->num_objects;


			object->flags &= ~UNINTERESTING;
	return bitmap_git;
}
			 struct bitmap *to_filter,
	int bitmap_pos;
	 * because the SHA1 already existed on the map. this is bad, there
		struct object *object = revs->pending.objects[i].item;
	if (revs->tree_objects)
	composed = ewah_pool_new();
	struct eindex *eindex = &bitmap_git->ext_index;
		return NULL;
			bitmap_unset(to_filter, pos);
	khiter_t hash_pos;
		 * lets us do a single pass, and is basically always true


	}
	}
	 * If we got here, then the object is OK to reuse. Mark it.
		die("revision walk setup failed");
				break;

		recent_bitmaps[i % MAX_XOR_OFFSET] = store_bitmap(
}
		uint32_t count, alloc;
		entry = &bitmap_git->pack->revindex[i];

{
	object_list_free(&wants);
};
						to_filter);
	}
	bitmap_free(tips);
		return 0;
		bitmap_pos = kh_value(eindex->positions, hash_pos);
	}
	 * We can't do pathspec limiting with bitmaps, because we don't know
	bitmap_and_not(result, reuse);
	}
	struct packed_git *p;
				       uint32_t *entries,
			    struct bitmap_index *bitmap_git)
 * The active bitmap index for a repository. By design, repositories only have
		incdata.seen = seen;
	 * need to be handled separately.
		struct ewah_bitmap *bm = lookup_stored_bitmap(st);
		i = bitmap_git->pack->num_objects / BITS_IN_EWORD;
			object_list_insert(object, &wants);
	}

}
						  (struct object *)commit,
	eword_t filter;
				if (base == NULL)
	rebuild = bitmap_new();

			object->flags |= SEEN;
	}
	struct bitmap_index *bitmap_git,
	bitmap_free(b->result);

	if (index->version != 1)
#include "pack-bitmap.h"
			pos = i * BITS_IN_EWORD + offset;

		if (p->item->type != OBJ_BLOB)
/*
	struct bitmap_index *bitmap_git;

				 show_reachable_fn show_reachable)
		int bitmap_pos = kh_value(positions, pos);
	if (haves && !in_bitmapped_pack(bitmap_git, haves))
		struct revindex_entry *entry = &pack->revindex[pos];

	if (filter->choice == LOFC_BLOB_NONE) {

				   struct object_list *roots,
	uint32_t i = 0, count = 0;
	 * they are reachable

			entry = &bitmap_git->pack->revindex[pos + offset];
	if (open_pack_index(packfile))
		haves_bitmap = find_objects(bitmap_git, revs, haves, NULL);


	struct ewah_iterator it;
	*packfile_out = bitmap_git->pack;

	if (pos < kh_end(positions)) {
struct include_data {
		struct object *object = roots->item;


	type = unpack_object_header(bitmap_git->pack, w_curs, &offset, &size);
	}
	/* mmapped buffer of the whole bitmap index */

	else
		 * There's nothing we can do, so just punt on this object,

		 * due to the way OFS_DELTAs work. You would not typically
					bitmap_to_ewah(rebuild);
	}
	offset = revidx->offset;
	/*

			ret = 0;
		reset_revision_walk();
		BUG("pack_name does not end in .pack");
		struct object_id oid;
		die("Object not in bitmap: %s\n", oid_to_hex(&object->oid));
			 struct list_objects_filter_options *filter)
		return -1;


		return error("Corrupted bitmap index file (wrong header)");
		    get_size_by_pos(bitmap_git, pos) >= limit)
		struct object **objects;
	 * Best case scenario: We found bitmaps for all the roots,
	bitmap_pos = bitmap_position(tdata->bitmap_git,
	if (!offset)
				       struct bitmap **reuse_out)

	bitmap_set(tdata->base, bitmap_pos);
		if (eindex->objects[i]->type == OBJ_BLOB &&
		 * packs we write fresh, and OFS_DELTA is the default). But



cleanup:
	return 0;
static int load_pack_bitmap(struct bitmap_index *bitmap_git)
		/*
	 * Type indexes.
#include "pack-objects.h"
	}
	num_objects = bitmap_git->pack->num_objects;
	 *
		progress = start_progress("Reusing bitmaps", 0);

			   const struct object_id *oid)
	size_t i = 0;
	return NULL;
			      struct pack_window **w_curs)

	revs->blob_objects = 1;
}

#include "revision.h"
		*blobs = count_object_type(bitmap_git, OBJ_BLOB);
	bitmap_free(rebuild);
	struct bitmap *objects = bitmap_git->result;
	struct stored_bitmap *xor;
	return result;

	ewah_pool_free(b->commits);
		xor_offset = read_u8(index->map, &index->map_pos);
		}
		if (!base_offset)
}
		if (xor_offset > 0) {
		return -1;

	for (i = 0, init_type_iterator(&it, bitmap_git, OBJ_BLOB);

	if (!wants_bitmap)
				    struct bitmap *to_filter)


	struct bitmap_test_data *tdata = data;



	size_t map_pos; /* current position when loading the index */

		 * let's double check to make sure the pack wasn't written with
			bitmap_unset(to_filter, pos);
		goto failed;
	case OBJ_TREE:
			}
	int ret;
	if (bitmap_git->pack) {
			      int bitmap_pos)
							  &hash_ret);


	kh_value(index->bitmaps, hash_pos) = stored;
		goto failed;
	bitmap_pos = bitmap_position(tdata->bitmap_git, &object->oid);
		!(bitmap_git->blobs = read_bitmap_1(bitmap_git)) ||
		return bitmap_git;
			if (xor_bitmap == NULL)

	while (roots) {
static int rebuild_bitmap(uint32_t *reposition,

	 * been caught by the loop above. We'll have to check them
	return NULL;
	int bitmap_pos;
		eword_t word = result->words[i];

	struct bitmap *result = bitmap_new();
		for (offset = 0; offset < BITS_IN_EWORD; ++offset) {
	struct bitmap *haves_bitmap = NULL;
				     &show_data);

	i = 0;

	return size;
}
static int open_pack_bitmap(struct repository *r,
	root = revs->pending.objects[0].item;
		index->map + index->map_pos,

	 * packed in `pack`, these objects are added to this "fake index" and
	uint32_t offset;
				   struct rev_info *revs,
			index, bitmap, &oid, xor_bitmap, flags);



				bitmap_set(dest, bit_pos - 1);

			ewah_iterator_next(&filter, &it); i++) {
	tips = find_tip_blobs(bitmap_git, tip_objects);
		base_offset = get_delta_base(bitmap_git->pack, w_curs,
	return -1;
	return buffer[(*pos)++];
		if ((flags & BITMAP_OPT_FULL_DAG) == 0)

			BUG("failed to perform bitmap walk");
		break;
}
	struct object_list *not_mapped = NULL;

		 * object_entry code path handle it.
		*commits = count_object_type(bitmap_git, OBJ_COMMIT);
	struct stored_bitmap *stored;


				struct stored_bitmap *st = kh_value(bitmap_git->bitmaps, pos);
struct bitmap_index {
	for (i = 0; i < eindex->count; i++) {

		return;
	 */

		 * to REF_DELTA on the fly. Better to just let the normal
			     kh_oid_map_t *reused_bitmaps,
			bit_pos = reposition[pos + offset];
			continue;
			if (!bitmap_get(tips, pos) &&
	struct ewah_iterator it;

 *
	if (!b)
	bitmap_pos = bitmap_position(data->bitmap_git, &object->oid);

			object = parse_object_or_die(get_tagged_oid(tag), NULL);
		    (obj->type == OBJ_TREE && !revs->tree_objects) ||
			count++;
	 * Extended index.
{
		uint32_t offset, bit_pos;
	bitmap_git->result = wants_bitmap;
static void show_commit(struct commit *commit, void *data)
}

		 * odd parameters.
	if (data->seen && bitmap_get(data->seen, bitmap_pos))
/*
	return 0;
#include "object-store.h"
	return 0;
		struct eindex *eindex = &bitmap_git->ext_index;
	return (pos >= 0) ? pos : bitmap_position_extended(bitmap_git, oid);
		}

	bitmap_git->haves = haves_bitmap;
	oi.sizep = &size;

			if (!rebuild_bitmap(reposition,
	bitmap_git->bitmaps = kh_init_oid_map();


	object_list_free(&haves);

		die("Object not in bitmap: %s\n", oid_to_hex(&commit->object.oid));
	free(b->ext_index.objects);

				    const struct object_id *oid)
		bitmap_or_ewah(data->base, lookup_stored_bitmap(st));
	if (not_mapped == NULL)
		oe = packlist_find(mapping, &oid);
		 * more detail.

			offset += ewah_bit_ctz64(word >> offset);
	int idx;

static int should_include(struct commit *commit, void *_data)

	}
{
	}
{

/*
	char *idx_name;
	case OBJ_TAG:
	tips = find_tip_blobs(bitmap_git, tip_objects);
	case OBJ_BLOB:

		struct stored_bitmap *st = kh_value(bitmap_git->bitmaps, pos);
		    !bitmap_get(tips, pos))

		bitmap_set(result, pos);
			parent->item->object.flags |= SEEN;
	pos = kh_get_oid_map(bitmap_git->bitmaps, root->oid);
	}
			offset += ewah_bit_ctz64(word >> offset);

	ewah_pool_free(st->root);
	struct bitmap_index *bitmap_git;
			khiter_t pos = kh_get_oid_map(bitmap_git->bitmaps, object->oid);
		bitmap_pos = ext_index_add_object(data->bitmap_git,
	bitmap_set(data->base, bitmap_pos);
	 */
				"(Git requires BITMAP_OPT_FULL_DAG)");
	 * for the objects that are actually in the bitmapped packfile.
}
				break;
			die(_("unable to get size of %s"), oid_to_hex(&oid));
		bitmap_free(reuse);
		fprintf(stderr, "OK!\n");

		count += ewah_bit_popcount64(word);
		bitmap_git->map = NULL;
		if (flags & BITMAP_OPT_HASH_CACHE) {
		/*
		result = ewah_to_bitmap(bm);


	if (bitmap_size < 0) {

	off_t offset = find_pack_entry_one(oid->hash, bitmap_git->pack);

	 * Each bitmap marks which objects in the packfile  are of the given

		return -1;
						 filter->blob_limit_value);
	for (i = 0; i < eindex->count; ++i) {

		if (base_pos >= pos)
		 * Find the position of the base object so we can look it up
	uint32_t i;

				     struct object_list *tip_objects)
	uint32_t *reposition;
	if (!add_to_include_set(data->bitmap_git, data, &commit->object.oid,
#include "list-objects-filter-options.h"
		incdata.base = base;
	stored = xmalloc(sizeof(struct stored_bitmap));
	return composed;
			base = bitmap_new();
static void test_show_object(struct object *object, const char *name,
		off_t base_offset;

			}

}
		if (eindex->objects[i]->type == OBJ_BLOB &&

static int filter_bitmap(struct bitmap_index *bitmap_git,
	return bitmap_git &&
	/* Number of bitmapped commits */
	for (p = get_all_packs(r); p; p = p->next) {
{
	/*
	struct object_info oi = OBJECT_INFO_INIT;
	struct bitmap *reuse;
		return 0;
	free(reposition);
			continue;

		bitmap_git->map_size = 0;
	memset(reuse->words, 0xFF, i * sizeof(eword_t));

static inline uint32_t read_be32(const unsigned char *buffer, size_t *pos)

		show_reach(&obj->oid, obj->type, 0, eindex->hashes[i], NULL, 0);

#include "pack-revindex.h"


		int base_pos;
			struct object_id oid;
	 * We can use the blob type-bitmap to work in whole words

	 * they will be sent as-is without using them for repacking
	index->map_pos += sizeof(*header) - GIT_MAX_RAWSZ + the_hash_algo->rawsz;
	}
		if (oid_object_info_extended(the_repository, &obj->oid, &oi, 0) < 0)

	 */
	free_bitmap_index(bitmap_git);
struct bitmap_show_data {
	(*pos) += sizeof(result);
	struct ewah_iterator it;
			show_reach(&oid, object_type, 0, hash, bitmap_git->pack, entry->offset);

	display_progress(tdata->prg, ++tdata->seen);
	bitmap_git->pack = packfile;
		 */
static void filter_bitmap_blob_limit(struct bitmap_index *bitmap_git,
		ewah_iterator_init(it, bitmap_git->trees);

		    bitmap_get(to_filter, pos) &&
	/*
		 * would come after us, along with other objects not
void traverse_bitmap_commit_list(struct bitmap_index *bitmap_git,
	return result;
	for (p = tip_objects; p; p = p->next) {
	struct ewah_bitmap *composed;

	unsigned long size;
		revs->include_check_data = &incdata;
static inline int bitmap_position_packfile(struct bitmap_index *bitmap_git,
		eindex->objects[eindex->count] = object;
		return NULL;
	 */
	init_type_iterator(&it, bitmap_git, object_type);
		fprintf(stderr, "Mismatch!\n");
	}
					 struct list_objects_filter_options *filter)
	if (!(bitmap_git = prepare_bitmap_git(revs->repo)))




		return -1;
	struct bitmap *objects = bitmap_git->result;
		return 0;
{
	 */
		 * necessarily in the pack, which means we'd need to convert

	int hash_ret;
	int flags;
		int pos;
		roots = roots->next;
	 */
	struct object_list *haves = NULL;
}
	 * from disk. this is the point of no return; after this the rev_list

	}
void free_bitmap_index(struct bitmap_index *b)

		error("Failed to load bitmap index (corrupted?)");

		 * reuse chunk, then don't send this object either. The base
		    bitmap_get(to_filter, pos) &&
	stored->flags = flags;
	kh_destroy_oid_map(b->bitmaps);


}
	ewah_pool_free(b->blobs);

static struct ewah_bitmap *read_bitmap_1(struct bitmap_index *index)

	size_t i = 0;
	uint32_t i;
}
{
		unsigned offset;
	struct ewah_bitmap *root;
static void show_extended_objects(struct bitmap_index *bitmap_git,

static struct stored_bitmap *store_bitmap(struct bitmap_index *index,
	struct include_data *data = _data;
	struct eindex *eindex = &bitmap_git->ext_index;
{
}
	 * now we're going to use bitmaps, so load the actual bitmap entries
	int bitmap_pos;



}
	if (type == OBJ_REF_DELTA || type == OBJ_OFS_DELTA) {
}
	 * so we must match that behavior.

	struct ewah_iterator it;
}
	filter_bitmap(bitmap_git, wants, wants_bitmap, filter);
	if (tags)
	assert(bitmap_git->result);
	if (bitmap_pos < 0)

			die("revision walk setup failed");
	reuse = bitmap_word_alloc(i);
	bitmap_set(reuse, pos);
}
	struct bitmap *base;


	uint32_t result = get_be32(buffer + *pos);
	});
		fprintf(stderr, "Found bitmap for %s. %d bits / %08x checksum\n",
	if (!can_filter_bitmap(filter))
#include "diff.h"
		break;
	struct bitmap *haves;
static struct ewah_bitmap *lookup_stored_bitmap(struct stored_bitmap *st)
{

	if (!bitmap)

				bitmap_pos)) {
		nth_packed_object_id(&oid, bitmap_git->pack, entry->nr);
	show_extended_objects(bitmap_git, revs, show_reachable);
				break;
	 * calculations
				     uint32_t pos)
		struct ewah_bitmap *bitmap = NULL;
	struct bitmap *wants_bitmap = NULL;
	uint32_t reuse_objects;
		to_filter->words[i] &= ~mask;
	 * check if we can determine them to be reachable from the existing

		return; /* broken packfile, punt */
			if (object->flags & UNINTERESTING)
			filter_bitmap_blob_none(bitmap_git, tip_objects,
		struct object_entry *oe;
{

};
			  struct ewah_bitmap *source,
	/*
				object_list_insert(object, &haves);
	}
 * index, and increase the read position accordingly
	/* Version of the bitmap index */
	for (i = 0; i < index->entry_count; ++i) {
		goto cleanup;

		return error("Corrupted bitmap index (missing header data)");
		error("Duplicate entry in bitmap index: %s", oid_to_hex(oid));
	free_bitmap_index(bitmap_git);
		return 0;
	/*
	bitmap_set(data->base, bitmap_pos);
	/*
		if (pos < 0 || base == NULL || !bitmap_get(base, pos)) {
		int pos;
	int bitmap_pos;

	show_objects_for_type(bitmap_git, OBJ_COMMIT, show_reachable);
			uint32_t pos;
						  name);
	struct eindex *eindex = &bitmap_git->ext_index;
	if (bitmap_get(data->base, bitmap_pos))
		eword_t word = objects->words[i] & filter;
		for (offset = 0; offset < BITS_IN_EWORD; offset++) {
		return 0;
	unuse_pack(&w_curs);
			filter_bitmap_blob_limit(bitmap_git, tip_objects,
{
	khiter_t pos;
			if (bit_pos > 0)
	 * The ones without bitmaps in the index will be stored in the
			mask &= ~tips->words[i];
	roots = not_mapped;
	ssize_t bitmap_size = ewah_read_mmap(b,
static int can_filter_bitmap(struct list_objects_filter_options *filter)
	if (trees)
		struct object *object = roots->item;
	/* Packfile to which this bitmap index belongs to */
	st->root = composed;
	unsigned char *map;
		close(fd);
};
	 * because we may not need to use it */
	free_bitmap_index(bitmap_git);

	uint32_t i;
		object_list_insert(object, &not_mapped);
	oidcpy(&stored->oid, oid);
				     unsigned long limit)

	 */
{
	for (i = 0, init_type_iterator(&it, bitmap_git, OBJ_BLOB);
		pos = bitmap_position(bitmap_git, &p->item->oid);
	if (type < 0)

	struct bitmap_disk_header *header = (void *)index->map;
	/* Map from object ID -> `stored_bitmap` for all the bitmapped commits */
		flags = read_u8(index->map, &index->map_pos);
				       struct packed_git **packfile_out,
	 * global bitmap.
	ewah_xor(st->root, parent, composed);
	}
	 * Let's iterate through all the roots that don't have bitmaps to

		if (oe)



	bitmap_git->bitmaps = NULL;
	bitmap_set(tdata->base, bitmap_pos);
			 struct bitmap *bitmap, const struct object_id *oid)

		if (base == NULL)
			      struct bitmap *reuse,


		roots = roots->next;
{

	bitmap_git->ext_index.positions = kh_init_oid_pos();
			return;
		pos = bitmap_position(bitmap_git, &object->oid);
	hash_pos = kh_put_oid_map(index->bitmaps, stored->oid, &ret);
	 * Go through all the roots for the walk. The ones that have bitmaps
			else
	 * so the resulting `or` bitmap has the full reachability analysis
		 * We assume delta dependencies always point backwards. This

	 * type. This provides type information when yielding the objects from
		return 0;
			needs_walk = 1;
static inline int bitmap_position_extended(struct bitmap_index *bitmap_git,
	if (hash_ret > 0) {
	 */


	return b;
		goto cleanup;
	if (pos < pack->num_objects) {
	size_t map_size; /* size of the mmaped buffer */
{
	}
int rebuild_existing_bitmaps(struct bitmap_index *bitmap_git,

	assert(bitmap_git->map);
	if (revs->prune)
}
		if ((obj->type == OBJ_BLOB && !revs->blob_objects) ||

	khiter_t hash_pos;
	}
		else



	struct progress *progress = NULL;
static uint32_t count_object_type(struct bitmap_index *bitmap_git,
			       struct bitmap_index *bitmap_git,
	object_list_free(&wants);
	switch (type) {
}
	for (i = 0; i < objects->word_alloc &&
			object_list_insert(object, &haves);

			     struct packing_data *mapping,
	struct bitmap *seen;
	bitmap_git->map_pos = 0;
	hash_pos = kh_put_oid_pos(eindex->positions, object->oid, &hash_ret);
		!(bitmap_git->tags = read_bitmap_1(bitmap_git)))
#include "packfile.h"
	struct bitmap_test_data *tdata = data;


				struct object *object, const char *name)
	 * The non-bitmap version of this filter never removes
	stop_progress(&tdata.prg);
	uint32_t i;
	return -1;
			return error("Corrupted bitmap pack index");

}


}

	if (pos >= bitmap_git->pack->num_objects)

	 * if we have a HAVES list, but none of those haves is contained
				   struct bitmap *seen)
	     i < to_filter->word_alloc && ewah_iterator_next(&mask, &it);
	for (i = 0; i < eindex->count; ++i) {

	if (haves) {
	if (show_progress)
};
		if (pos < 0)


	return stored;
{

	eword_t mask;
	kh_oid_pos_t *positions = bitmap_git->ext_index.positions;
	if (fd < 0)
}
	if (bitmap_pos < 0)

		struct stored_bitmap *st = kh_value(bitmap_git->bitmaps, hash_pos);
	}
	struct bitmap *rebuild;
}
	index->entry_count = ntohl(header->entry_count);
 * commit.
	struct packed_git *pack = bitmap_git->pack;


	reposition = xcalloc(num_objects, sizeof(uint32_t));
			      uint32_t *blobs, uint32_t *tags)
	if (bitmap_equals(result, tdata.base))
	return 0;

		BUG("failed to perform bitmap walk");
		i++;
	return 0;
	 */
	return base;

		break;
			struct revindex_entry *entry;
		BUG("object type %d not stored by bitmap type index", type);

	if (filter->choice == LOFC_BLOB_LIMIT) {
		if (!bitmap)
		return -1;
	if (blobs)
				object->flags |= SEEN;
		if (i < tips->word_alloc)
	for (i = 0; i < eindex->count; i++) {
	struct object *root;
	return find_revindex_position(bitmap_git->pack, offset);
	if (ret == 0) {
	bitmap_git->map = xmmap(NULL, bitmap_git->map_size, PROT_READ, MAP_PRIVATE, fd, 0);
 */

		if (object->flags & UNINTERESTING)

		return error("Unsupported version for bitmap index file (%d)", index->version);


	return -1;

	/* Bitmap result of the last performed walk */
static int open_pack_bitmap_1(struct bitmap_index *bitmap_git, struct packed_git *packfile)
	kh_destroy_oid_map(bitmap_git->bitmaps);
			reposition[i] = oe_in_pack_pos(mapping, oe) + 1;

{
	if (open_pack_bitmap(revs->repo, bitmap_git) < 0)

	/*
					    rebuild)) {
	struct bitmap *result;
}
				bitmap_unset(to_filter, pos);

	 * `not_mapped_list` for further processing.
static void test_show_commit(struct commit *commit, void *data)

		*trees = count_object_type(bitmap_git, OBJ_TREE);
		break;
	kh_destroy_oid_pos(bitmap_git->ext_index.positions);
		revs->ignore_missing_links = 1;
static int load_bitmap_entries_v1(struct bitmap_index *index)
		uint32_t *hashes;
	struct eindex {
		 * that offset is not in the revidx, the pack is corrupt.
	return 1;
		if (prepare_revision_walk(revs))
}

	struct bitmap *base = NULL;

	 * in the packfile that has a bitmap, we don't have anything to
		show_objects_for_type(bitmap_git, OBJ_BLOB, show_reachable);
	tdata.bitmap_git = bitmap_git;
		die("Commit %s doesn't have an indexed bitmap", oid_to_hex(&root->oid));

 * a single bitmap index available (the index for the biggest packfile in
	/*

 * An entry on the bitmap index, representing the bitmap for a given
				return error("Invalid XOR offset in bitmap pack index");
		if (object->type == OBJ_COMMIT) {
{
		if (!bitmap_get(reuse, base_pos))
		struct bitmap_show_data show_data;
static struct bitmap *find_tip_blobs(struct bitmap_index *bitmap_git,

		bitmap_pos = ext_index_add_object(data->bitmap_git, object,
		kh_value(eindex->positions, hash_pos) = bitmap_pos;
		while (object->type == OBJ_TAG) {

		goto cleanup;
	ewah_iterator_init(&it, source);

		return 0;
		struct object *obj = eindex->objects[pos - pack->num_objects];
	struct ewah_bitmap *trees;
	revidx = &bitmap_git->pack->revindex[pos];
{
		for (offset = 0; offset < BITS_IN_EWORD; ++offset) {
static void show_objects_for_type(
	struct packed_git *pack;
			bitmap_get(objects, bitmap_git->pack->num_objects + i))
	int fd;
		if (eindex->objects[i]->type == type &&

	/* Don't mark objects not in the packfile */

{
	size_t result_popcnt;
	if (index->map_size < sizeof(*header) + the_hash_algo->rawsz)
	kh_foreach_value(bitmap_git->bitmaps, stored, {
			return error("Unsupported options for bitmap index file "
		}
#include "commit.h"
	struct bitmap_index *bitmap_git;
	khiter_t pos = kh_get_oid_pos(positions, *oid);
	if (!wants)
}
			return;
	 * are assumed to appear at the end of the packfile for all operations
		return st->root;
	bitmap_free(b->haves);
{
	assert(!bitmap_git->map);

int bitmap_has_oid_in_uninteresting(struct bitmap_index *bitmap_git,

		goto cleanup;


		 * And finally, if we're not sending the base as part of our
	int bitmap_pos;
}

static int bitmap_position(struct bitmap_index *bitmap_git,

	if (load_bitmap_header(bitmap_git) < 0) {
	if (!(bitmap_git->commits = read_bitmap_1(bitmap_git)) ||
		 */
		break;
		return NULL;
{
		index->map_size - index->map_pos);
	 * even which objects are associated with which paths).

	if (result == NULL)
		struct commit_list *parent = commit->parents;
		size_t pos = (i * BITS_IN_EWORD);
		}
	}

	if (pos < kh_end(bitmap_git->bitmaps)) {
	if (revs->tag_objects)



			if (bitmap_git->hashes)
}
			uint32_t hash = 0;
					  int flags)
	}
			 struct object_list *tip_objects,
		struct stored_bitmap *xor_bitmap = NULL;
		if (stored->flags & BITMAP_FLAG_REUSE) {
	}
		if (packed_object_info(the_repository, pack,
		for (offset = 0; offset < BITS_IN_EWORD; ++offset) {
	/* try to open a bitmapped pack, but don't parse it yet
		traverse_commit_list(revs, show_commit, show_object,

	 * blobs which the other side specifically asked for,

					     &offset, type, revidx->offset);
{

	{
		ewah_pool_free(b);

	struct bitmap *tips;
	free(idx_name);
		}
		struct object_id oid;
	stored->root = root;
	uint32_t i, num_objects;
	if (memcmp(header->magic, BITMAP_IDX_SIGNATURE, sizeof(BITMAP_IDX_SIGNATURE)) != 0)
	while (ewah_iterator_next(&word, &it)) {
		return NULL;


	uint32_t offset;
		}
	 *
		close(fd);


			nth_packed_object_id(&oid, pack, entry->nr);

			try_partial_reuse(bitmap_git, pos + offset, reuse, &w_curs);
		return base;
					   const struct object_id *oid)
	bitmap_git->map_size = xsize_t(st.st_size);
	 * the packfile during a walk, which allows for better delta bases.
	}
		}
	while (roots) {

	 * shouldn't be duplicated commits in the index */
	struct bitmap_test_data tdata;

	 */
static void init_type_iterator(struct ewah_iterator *it,
	 */
	struct object_id oid;
			     void *data)
			       enum object_type type)
{
	struct ewah_bitmap *parent;
				kh_value(reused_bitmaps, hash_pos) =
static void show_object(struct object *object, const char *name, void *data_)


	}

		ewah_iterator_init(it, bitmap_git->tags);

}
	eword_t mask;
			offset += ewah_bit_ctz64(word >> offset);
	khiter_t hash_pos;
	/* a 0 return code means the insertion succeeded with no changes,

	 * Mark the first `reuse_objects` in the packfile as reused:
	}
	case OBJ_COMMIT:
	if (hash_pos < kh_end(bitmap_git->bitmaps)) {

	if (!filter || filter->choice == LOFC_DISABLED)
	idx_name = pack_bitmap_filename(packfile);
		warning("ignoring extra bitmap file: %s", packfile->pack_name);
		die("you must specify exactly one commit to test");
	bitmap_pos = bitmap_position(data->bitmap_git, &commit->object.oid);
	/*
	if (!open_pack_bitmap(r, bitmap_git) && !load_pack_bitmap(bitmap_git))

		}

	st->xor = NULL;
	 */
		uint32_t commit_idx_pos;
		uint32_t flags = ntohs(header->options);
	free(b->ext_index.hashes);
{
				return -1;
	tdata.seen = 0;
	struct progress *prg;
		}
	fd = git_open(idx_name);
	 * If we cannot find them in the existing global bitmap, we'll need
{
	struct stored_bitmap *recent_bitmaps[MAX_XOR_OFFSET] = { NULL };
			      struct include_data *data,
	if (revs->pending.nr != 1)
		revs->include_check = should_include;


static struct bitmap *find_objects(struct bitmap_index *bitmap_git,
			return;
}
	struct bitmap *result = NULL;
					    lookup_stored_bitmap(stored),
}
			      const struct object_id *oid,
	}
	int hash_ret;
{
	enum object_type object_type,
				object_list_insert(object, &wants);

		}
	 * optimize here
}
struct stored_bitmap {


	struct bitmap_index *bitmap_git;
			if ((word >> offset) == 0)
{
	bitmap_free(tips);
	object_array_clear(&revs->pending);
		if (!word)
		} else {
	return 0;

}
	while (i < objects->word_alloc && ewah_iterator_next(&filter, &it)) {

{
	 * which commits are associated with which object changes (let alone
			if ((word >> offset) == 0)
	} ext_index;
int bitmap_walk_contains(struct bitmap_index *bitmap_git,

		if (eindex->count >= eindex->alloc) {
	struct bitmap *base;
	show_reachable_fn show_reach)
{
			struct object_id oid;
	}
			return 1;
{

	index->map_pos += bitmap_size;
struct bitmap_index *prepare_bitmap_walk(struct rev_info *revs,
			continue;
 */

}
	wants_bitmap = find_objects(bitmap_git, revs, wants, haves_bitmap);

static int in_bitmapped_pack(struct bitmap_index *bitmap_git,
	khiter_t hash_pos;
	struct pack_window *w_curs = NULL;

		return bitmap_pos + bitmap_git->pack->num_objects;
			display_progress(progress, ++i);
	}
	struct bitmap *result = bitmap_git->result;
static int add_to_include_set(struct bitmap_index *bitmap_git,
					  const struct object_id *oid,
	munmap(bitmap_git->map, bitmap_git->map_size);
	if (!*entries) {
{
	 * global reachability analysis.
		if (!bitmap_get(objects, bitmap_git->pack->num_objects + i))

		if (open_pack_bitmap_1(bitmap_git, p) == 0)
		munmap(bitmap_git->map, bitmap_git->map_size);
		die("failed to load bitmap indexes");

	struct bitmap *base;
	if (bitmap_pos < 0)

				       entry->offset, &oi) < 0) {
				     struct bitmap *to_filter,
	*reuse_out = reuse;


	index->version = ntohs(header->version);
		roots = roots->next;
	if (st->xor == NULL)

	/* "have" bitmap from the last performed walk */
	struct bitmap_index *bitmap_git = xcalloc(1, sizeof(*bitmap_git));
	if (bitmap_pos < 0)
		nth_packed_object_id(&oid, index->pack, commit_idx_pos);

		if (object->type == OBJ_NONE)
}
	enum object_type type;
}

		/*
	 * becomes invalidated and we must perform the revwalk through bitmaps
	struct ewah_bitmap *commits;
		show_data.base = base;
#include "list-objects.h"
	eword_t filter;
	 */
