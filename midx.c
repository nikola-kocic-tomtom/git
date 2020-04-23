	    !config_value))
				written += write_midx_object_offsets(f, large_offsets_needed, pack_perm, entries, nr_entries);
			close_pack_fd(m->packs[pairs[i-1].pack_int_id]);
	byte_values[3] = 0; /* unused */
		cur_chunk++;
	va_start(ap, fmt);
	free(packs.info);
		UNLEAK(midx_name);
	unsigned char *include_pack;
		list = next;
static size_t write_midx_large_offsets(struct hashfile *f, uint32_t nr_large_offset,
	return 0;


		die(_("multi-pack-index missing required pack-name chunk"));
		}
		result = 1;
			FREE_AND_NULL(packs->info[packs->nr].p);
	}
				break;
static int fill_included_packs_all(struct multi_pack_index *m,
	for (i = 0; i < nr_objects; i++) {
				drop_index++;


	chunk_ids[cur_chunk] = MIDX_CHUNKID_OIDLOOKUP;
		for (i = 0; i < packs.m->num_packs; i++) {
	m->fd = -1;
				BUG("trying to write unknown chunk id %"PRIx32,
}
		goto cleanup;

			hashwrite_be32(f, (uint32_t)obj->offset);


	struct pack_midx_entry *list = objects;
				drop_index++;
		 * Remaining tests assume that we have objects, so we can
							  full_path_len,
		include_pack[pack_int_id] = 1;
	struct pack_info *info;
		m_offset = e.offset;

		}
		struct pack_midx_entry *obj = list++;




	uint32_t pos;
}
		if (open_pack_index(p) || !p->num_objects)
				      packs_to_drop->items[drop_index].string);
	return bsearch_hash(oid->hash, m->chunk_oid_fanout, m->chunk_oid_lookup,
	}
	if (!m)
	}
	while (*idx_name && *idx_name == *idx_or_pack_name) {

	 * If we didn't match completely, we may have matched "pack-1234." and

			close_pack_index(m->packs[pairs[i-1].pack_int_id]);
		display_progress(progress, i + 1);

	}
			packs.info[packs.nr].expired = 0;
	uint32_t pack_int_id;
	 * pack_perm stores a permutation between pack-int-ids from the
		goto cleanup_fail;

		total_objects += info[cur_pack].p->num_objects;
	}
		    chunk_offsets[num_chunks]);
	}
#include "packfile.h"
			pack_perm[packs.info[i].orig_pack_int_id] = PACK_EXPIRED;
		progress = start_sparse_progress(_("Verifying OID order in multi-pack-index"),



	cur_chunk++;
	else
	uint32_t i;
			pack_name_concat_len += strlen(packs.info[i].pack_name) + 1;
		include_pack[i] = 1;
	e->offset = nth_midxed_offset(m, pos);

					 * pack_info[i].referenced_objects);
		UNLEAK(midx);
	uint32_t pack_int_id;
				start = ntohl(m->chunk_oid_fanout[cur_fanout - 1]);
				uint32_t num_packs)
#define MIDX_CHUNKID_OIDLOOKUP 0x4f49444c /* "OIDL" */
					  m->num_packs);
	}
		      m->version);
		hashwrite_be32(f, offset >> 32);
	free(count);
struct pack_list {
	while (nr_large_offset) {
{
		error(_("could not start pack-objects"));
}
	if (a->mtime > b->mtime)

		written += i;



		if (fill_included_packs_batch(r, m, include_pack, batch_size))
	stop_progress(&progress);
{

		if (!packs->info[packs->nr].p) {
	if (packs.m)
	}

		switch (chunk_ids[i]) {


	struct multi_pack_index *m = load_multi_pack_index(object_dir, 1);

	return MIDX_HEADER_SIZE;
static int midx_oid_compare(const void *_a, const void *_b)


	*nr_objects = 0;

		packs.m = m;
	m->num_packs = get_be32(m->data + MIDX_BYTE_NUM_PACKS);
			return;
	 */
		offset = obj->offset;
	return verify_midx_error;
#define SPARSE_PROGRESS_INTERVAL (1 << 12)
	for (i = 0; i < m->num_packs; i++) {
				    uint32_t nr_objects)
}
	FLEX_ALLOC_STR(m, object_dir, object_dir);
	time_t pack_mtime;
			close_pack(packs->info[packs->nr].p);
	}
	for (cur_fanout = 0; cur_fanout < 256; cur_fanout++) {


		env_value = git_env_bool(GIT_TEST_MULTI_PACK_INDEX, 0);
	 */
static int pack_info_compare(const void *_a, const void *_b)
}
				 * extensions to add optional chunks.
	if (pos >= m->num_objects)
	packs.pack_paths_checked = 0;
		pack_info[i].mtime = m->packs[i]->mtime;
			warning(_("failed to add packfile '%s'"),
			}
			die(_("invalid chunk offset (too large)"));
		nth_midxed_object_oid(&oid, m, pairs[i].pos);
		progress = start_progress(_("Counting referenced objects"),

	struct progress *progress = NULL;

			case 0:
						 MIDX_CHUNKLOOKUP_WIDTH * i);

		uint32_t chunk_id = get_be32(m->data + MIDX_HEADER_SIZE +
		if (chunk_offset >= m->data_len)
			if (hasheq(oid.hash,

				missing_drops++;
	}
		if (chunk_offsets[i] % MIDX_CHUNK_ALIGNMENT)
			BUG("incorrect chunk offsets: %"PRIu64" before %"PRIu64,

				unsigned char num_chunks,
static int nth_midxed_pack_midx_entry(struct multi_pack_index *m,
		if (expected_size >= batch_size)
				start = get_pack_fanout(info[cur_pack].p, cur_fanout - 1);
			       &entries_by_fanout[cur_object],
		packs_to_repack++;
	if (!bsearch_midx(oid, m, &pos))
	size_t total_size;
	 * match a raw strcmp(). That makes it OK to use this to binary search
/* Match "foo.idx" against either "foo.pack" _or_ "foo.idx". */
	e->pack_mtime = 0;
	}
		    struct pack_entry *e,
		for (i = 0; i < p->num_bad_objects; i++)
#define MIDX_SIGNATURE 0x4d494458 /* "MIDX" */
	else
	uint32_t i, nr_large_offset = 0;
#include "config.h"

	uint32_t *pack_perm = NULL;


int midx_contains_pack(struct multi_pack_index *m, const char *idx_or_pack_name)
		if (perm[obj->pack_int_id] == PACK_EXPIRED)
	} else if (fill_included_packs_all(m, include_pack))
int verify_midx_file(struct repository *r, const char *object_dir, unsigned flags)
	return b->pack_int_id - a->pack_int_id;
		int cmp;
#include "sha1-lookup.h"
#define MIDX_VERSION 1
{
	*/

	return m;
	struct packed_git *p;
	return written;
			if (cur_object && oideq(&entries_by_fanout[cur_object - 1].oid,
			continue;

		progress = start_progress(_("Finding and deleting unreferenced packfiles"),
		xwrite(cmd.in, "\n", 1);
 *
}
		packs->info[packs->nr].orig_pack_int_id = packs->nr;
	    (repo_config_get_bool(r, "core.multipackindex", &config_value) ||
{

}
				break;
		display_progress(progress, i + 1);
	ALLOC_ARRAY(entries_by_fanout, alloc_fanout);



		else
	struct progress *progress;
	unsigned pack_paths_checked;
	if (!m)
}
	hashwrite_be32(f, num_packs);
			num_large_offsets++;
	trace2_data_intmax("midx", the_repository, "load/num_objects", m->num_objects);

	 */
	free(pack_perm);
		result = write_midx_internal(object_dir, m, &packs_to_drop, flags);
	unsigned char padding[MIDX_CHUNK_ALIGNMENT];
	free(pairs);
			default:

	else
	for (i = 0; i < 255; i++) {



				 uint32_t pos)


	if (packs.m) {
	struct stat st;
 * this memory pressure without a significant performance drop, automatically

	vfprintf(stderr, fmt, ap);



			midx_report(_("failed to load pack-index for packfile %s"),
	strbuf_addstr(&base_name, object_dir);
	FREE_AND_NULL(midx_name);
			for (cur_object = start; cur_object < end; cur_object++) {
	cur_chunk = 0;
	chunk_ids[cur_chunk] = MIDX_CHUNKID_OBJECTOFFSETS;
 * we are to create a list of all objects before de-duplication. To reduce
	 * time.
	chunk_offsets[cur_chunk] = written + (num_chunks + 1) * MIDX_CHUNKLOOKUP_WIDTH;
			BUG("chunk offset %"PRIu64" is not properly aligned",
	if (packs.nr - dropped_packs == 0) {
	for (i = 0; i < packs.nr; i++) {
		return -1;
int bsearch_midx(const struct object_id *oid, struct multi_pack_index *m, uint32_t *result)
			int cmp = strcmp(packs.info[i].pack_name,
	for (i = 0; total_size < batch_size && i < m->num_packs; i++) {

	return result;
		if (i && chunk_offsets[i] < chunk_offsets[i - 1])
	/* add padding to be aligned */
{
				break;

}
}
		packs.m = load_multi_pack_index(object_dir, 1);
						 m->num_objects);
		hashwrite_be32(f, offset & 0xffffffffUL);
static uint32_t nth_midxed_pack_int_id(struct multi_pack_index *m, uint32_t pos)
	m = load_multi_pack_index(object_dir, local);




						&entries_by_fanout[cur_object].oid))

static void fill_pack_entry(uint32_t pack_int_id,

				   unsigned char *include_pack)

#define MIDX_BYTE_NUM_PACKS 8
		r->objects->multi_pack_index = m;
		for (cur_object = 0; cur_object < nr_fanout; cur_object++) {

	struct pack_list packs;
}
		unlink_pack_path(pack_name, 0);

}
		pack_name_concat_len += MIDX_CHUNK_ALIGNMENT -
			       struct string_list *packs_to_drop, unsigned flags)
	ALLOC_ARRAY(packs.info, packs.alloc);
	size_t written = 0;
				fill_pack_entry(cur_pack, info[cur_pack].p, cur_object, &entries_by_fanout[nr_fanout]);

	return oid;
	stop_progress(&progress);
	entry->pack_int_id = pack_int_id;
		struct pack_midx_entry *obj;

		uint32_t mid = first + (last - first) / 2;
		if (entries[i].offset > 0xffffffff)

	struct multi_pack_index *m;

	}
#include "lockfile.h"
	struct string_list packs_to_drop = STRING_LIST_INIT_DUP;
struct pair_pos_vs_id
			display_progress(progress, _n); \
		goto cleanup_fail;

{



	while (first < last) {
	for (i = 0; i < m->num_objects; i++) {
	if (ends_with(file_name, ".idx")) {
{
	chunk_ids[cur_chunk] = MIDX_CHUNKID_PACKNAMES;
	timestamp_t mtime;


		BUG("incorrect final offset %"PRIu64" != %"PRIu64,
		    struct multi_pack_index *m)
static char *get_midx_filename(const char *object_dir)
#define midx_display_sparse_progress(progress, n) \
	uint32_t first = 0, last = m->num_packs;
			ALLOC_GROW(packs.info, packs.nr + 1, packs.alloc);

		return 0;
		cmp = cmp_idx_or_pack_name(idx_or_pack_name, current);
				m->chunk_pack_names = m->data + chunk_offset;
	if (flags & MIDX_PROGRESS)

#define MIDX_BYTE_NUM_CHUNKS 6
		midx_report(_("the midx contains no oid"));
		}
			struct pack_midx_entry *next = list;
	close(cmd.in);
static void add_pack_to_midx(const char *full_path, size_t full_path_len,
	uint32_t cur_fanout, cur_pack, cur_object;
			    struct packed_git *p,
		int missing_drops = 0;
	unsigned char byte_values[4];
	if (m->packs[pack_int_id])
	if (cmp)
	struct progress *progress = NULL;
static int verify_midx_error;
	}
	strbuf_addf(&pack_name, "%s/pack/%s", m->object_dir,
{
{
	return strcmp(a->pack_name, b->pack_name);

	const unsigned char *offset_data;
	struct multi_pack_index *m = load_multi_pack_index(object_dir, 1);
	if (pos >= m->num_objects)
				    i, oid_to_hex(&oid1), oid_to_hex(&oid2), i + 1);

				m->chunk_object_offsets = m->data + chunk_offset;
		    const struct object_id *oid,
		uint32_t i;
		uint32_t pack_int_id = nth_midxed_pack_int_id(m, i);
		error_errno(_("failed to read %s"), midx_name);
	}
		if (m->packs[i])
			warning(_("failed to open pack-index '%s'"),
	return result;
						  uint32_t *nr_objects)
	free(midx_name);

struct object_id *nth_midxed_object_oid(struct object_id *oid,
	byte_values[2] = num_chunks;
		if (m_offset != p_offset)

				break;
{
			dropped_packs++;
						 m->num_objects - 1);


	 * previous multi-pack-index to the new one we are writing:
{
	if (nth_packed_object_id(&entry->oid, p, cur_object) < 0)
	free(m);


	uint64_t offset;

	struct pair_pos_vs_id *pairs = NULL;

	 */
		display_progress(packs->progress, ++packs->pack_paths_checked);
	if (m->signature != MIDX_SIGNATURE)
	if (flags & MIDX_PROGRESS)
	struct strbuf base_name = STRBUF_INIT;
		}
		if (entries[i].offset > 0x7fffffff)


	int large_offsets_needed = 0;
		expected_size /= p->num_objects;
	stop_progress(&progress);

	 * allocate slightly more than one 256th.
		nr_large_offset--;
	e->p = p;
		if (missing_drops) {
	if (!m)
	for_each_file_in_pack_dir(object_dir, add_pack_to_midx, &packs);
	fprintf(stderr, "\n");

			close_pack(packs.info[i].p);

	close(m->fd);

	struct pack_midx_entry *deduplicated_entries = NULL;
	total_size = 0;
	if (fd < 0)

	struct pack_info *a = (struct pack_info *)_a;
			hashwrite_be32(f, MIDX_LARGE_OFFSET_NEEDED | nr_large_offset++);
	}
 * of a packfile containing the object).
	int cmp = oidcmp(&a->oid, &b->oid);
				    pairs[i].pos, oid_to_hex(&oid), m_offset, p_offset);
	if (!m->chunk_pack_names)
	}
		die(_("multi-pack-index missing required OID lookup chunk"));
	const char *cur_pack_name;
		string_list_insert(&packs_to_drop, m->pack_names[i]);
		cur_pack_name += strlen(cur_pack_name) + 1;
	stop_progress(&progress);

		 * Take only the first duplicate.
			midx_report(_("oid lookup out of order: oid[%d] = %s >= %s = oid[%d]"),
	if (!is_pack_valid(p))

		if (i > 0 && pairs[i-1].pack_int_id != pairs[i].pack_int_id &&
static struct pack_midx_entry *get_sorted_entries(struct multi_pack_index *m,
	if (m->chunk_large_offsets && offset32 & MIDX_LARGE_OFFSET_NEEDED) {
		packs.progress = start_progress(_("Adding packfiles to multi-pack-index"), 0);
				    struct pack_midx_entry *objects,
		return 0;
	int dropped_packs = 0;
		if (large_offset_needed && obj->offset >> 31)
		error(_("could not finish pack-objects"));
		chunk_ids[cur_chunk] = MIDX_CHUNKID_LARGEOFFSETS;
	 * be left with "idx" and "pack" respectively, which is also OK. We do
	hash_version = m->data[MIDX_BYTE_HASH_VERSION];
	}
		return get_be64(m->chunk_large_offsets + sizeof(uint64_t) * offset32);
	for (i = 0; i < m->num_packs; i++) {
	struct multi_pack_index *m = NULL;
				m->chunk_oid_fanout = (uint32_t *)(m->data + chunk_offset);
		struct object_id oid;
		return cmp;

	unsigned expired : 1;
	}
}
	if (flags & MIDX_PROGRESS)




		}

		hashwrite_be32(f, perm[obj->pack_int_id]);

		struct object_id oid;
	uint32_t hash_version;
}


			if (cur_fanout)
	 * not have to check for "idx" and "idx", because that would have been
	 * each of the objects and only require 1 packfile to be open at a
		count[pack_int_id]++;

	void *midx_map = NULL;
	struct progress *progress = NULL;
 * group objects by the first byte of their object id. Use the IDX fanout
	}

		if (m) {
	entries = get_sorted_entries(packs.m, packs.info, packs.nr, &nr_entries);

			    uint32_t cur_object,
		}

		nth_midxed_object_oid(&oid, m, pos);
		idx_or_pack_name++;

		die(_("multi-pack-index version %d not recognized"),
			uint32_t start = 0, end;

		uint64_t chunk_offset = get_be64(m->data + MIDX_HEADER_SIZE + 4 +
	}
	result = write_midx_internal(object_dir, m, NULL, flags);
	if (m->num_objects == 0) {
{
			}
	nth_midxed_object_oid(&e->oid, m, pos);
}
			if (cur_fanout)
	if (prepare_midx_pack(r, m, pack_int_id))

	m->packs[pack_int_id] = p;
{
#define PACK_EXPIRED UINT_MAX
			memcpy(&deduplicated_entries[*nr_objects],
						  uint32_t nr_packs,
	if (a->pack_mtime > b->pack_mtime)


	int config_value;
		close_midx(m);

 */
		munmap(midx_map, midx_size);

static size_t write_midx_oid_lookup(struct hashfile *f, unsigned char hash_len,
		for (cur_pack = start_pack; cur_pack < nr_packs; cur_pack++) {
				m->chunk_large_offsets = m->data + chunk_offset;
	uint32_t i;
				      uint32_t pos)
{
	commit_lock_file(&lk);
	m->data_len = midx_size;

};
	count = xcalloc(m->num_packs, sizeof(uint32_t));
	 *
#define MIDX_HASH_VERSION 1

	uint64_t chunk_offsets[MIDX_MAX_CHUNKS + 1];


	}
	pack_int_id = nth_midxed_pack_int_id(m, pos);
		}
	display_progress(progress, 0); /* TODO: Measure QSORT() progress */
		progress = start_sparse_progress(_("Verifying object offsets"), m->num_objects);
			    obj->offset);

			packs.info[packs.nr].pack_name = xstrdup(packs.m->pack_names[i]);
		packs->nr++;

		if (packs.info[i].p) {



		return -1;
	}

			case MIDX_CHUNKID_PACKNAMES:
		free(packs.info[i].pack_name);
		packs->info[packs->nr].pack_name = xstrdup(file_name);
		}
{

{
			BUG("incorrect chunk offset (%"PRIu64" != %"PRIu64") for chunk id %"PRIx32,
}
	 * the first non-identical character, which means our ordering will

					(pack_name_concat_len % MIDX_CHUNK_ALIGNMENT);
			     const char *file_name, void *data)
	const struct pack_midx_entry *a = (const struct pack_midx_entry *)_a;
	 * Create an array mapping each object to its packfile id.  Sort it
	byte_values[1] = MIDX_HASH_VERSION;
	if (!env_value &&
#define MIDX_HEADER_SIZE 12
				const char *idx_name)

	e->pack_int_id = nth_midxed_pack_int_id(m, pos);
	if (!m->chunk_object_offsets)

		packs->info[packs->nr].expired = 0;
			    chunk_offsets[i],


	strbuf_release(&pack_name);
				written += write_midx_oid_lookup(f, the_hash_algo->rawsz, entries, nr_entries);
			case MIDX_CHUNKID_OIDFANOUT:
			goto cleanup;
	hashcpy(oid->hash, m->chunk_oid_lookup + m->hash_len * n);
			  midx_name);
	}
	if (n >= m->num_objects)
			packs.info[packs.nr].p = NULL;

	return 0;
		if (!include_pack[pack_int_id])

	e->offset = nth_midxed_offset(m, pos);
		die(_("multi-pack-index missing required object offsets chunk"));
		if (!packs.info[i].expired)
int prepare_midx_pack(struct repository *r, struct multi_pack_index *m, uint32_t pack_int_id)
		uint32_t oid_fanout1 = ntohl(m->chunk_oid_fanout[i]);
		 */
static int fill_included_packs_batch(struct repository *r,
 * duplicate copies of objects. That can create high memory pressure if

	if (pack_name_concat_len % MIDX_CHUNK_ALIGNMENT)

void close_midx(struct multi_pack_index *m)

		return 1;
		hashwrite_be32(f, chunk_offsets[i] >> 32);
	}
	free(entries_by_fanout);

	free(midx_name);
			packs.info[packs.nr].orig_pack_int_id = i;
		free(pack_name);
				    i, oid_fanout1, oid_fanout2, i + 1);
	}


	for (i = 0; batch_size && i < m->num_objects; i++) {
	uint32_t pack_int_id;
		goto cleanup;
		int pack_int_id = nth_midxed_pack_int_id(m, i);

	struct pair_pos_vs_id *a = (struct pair_pos_vs_id *)_a;

		argv_array_push(&cmd.args, "--progress");
	finalize_hashfile(f, NULL, CSUM_FSYNC | CSUM_HASH_IN_STREAM);
}
				     unsigned char *include_pack,
cleanup:
					   num_large_offsets * MIDX_CHUNK_LARGE_OFFSET_WIDTH;
			    info[i].pack_name);
				break;
		if (m->packs[i]->pack_keep)
		if (i < nr_objects - 1) {
struct pack_midx_entry {
	fd = git_open(midx_name);

	for (i = 0; i < m->num_packs; i++) {
				    struct pack_midx_entry *objects,
		while (next < last && next->oid.hash[0] == i) {
		pack_info[i].pack_int_id = i;
		packs.progress = NULL;
{
		if (i && strcmp(m->pack_names[i], m->pack_names[i - 1]) <= 0)
	if (packs_to_drop.nr)

	int fd;
				break;
			}
struct multi_pack_index *load_multi_pack_index(const char *object_dir, int local)
			m->packs[i]->multi_pack_index = 0;
	packs.nr = 0;
	}
int write_midx_file(const char *object_dir, unsigned flags)
	struct pack_list *packs = (struct pack_list *)data;
				 */
		offset32 ^= MIDX_LARGE_OFFSET_NEEDED;

	cmd.in = cmd.out = -1;
				    uint32_t nr_objects)
}
	m->packs = xcalloc(m->num_packs, sizeof(*m->packs));
	return 1;
		return 0;
	}
	}



				m->chunk_oid_lookup = m->data + chunk_offset;
			    written,
#include "trace2.h"
	 * slices to be evenly distributed, with some noise. Hence,
			goto cleanup;
		struct object_id oid1, oid2;
	FREE_AND_NULL(midx_name);

	uint32_t i;
		if (packs.info[i].expired) {
		obj = list++;


				   p->bad_object_sha1 + the_hash_algo->rawsz * i))

			case MIDX_CHUNKID_PACKNAMES:
	cur_chunk++;
};
	midx_size = xsize_t(st.st_size);
	}

			(*nr_objects)++;
			    chunk_offsets[i - 1],
	uint32_t offset32;
				return 0;
{
	if (total_size < batch_size || packs_to_repack < 2)
	chunk_ids[cur_chunk] = 0;
 */

		if (!p)
	/* consider objects in midx to be from "old" packs */
			continue;

	p = add_packed_git(pack_name.buf, pack_name.len, m->local);
	* answer, as it may have been deleted since the MIDX was

	if (!m)
};


	entry->offset = nth_packed_object_offset(p, cur_object);
				    uint32_t num_packs)
	if (remove_path(midx)) {
		}
	hashwrite(f, byte_values, sizeof(byte_values));
	}
	}
	uint32_t alloc_fanout, alloc_objects, total_objects = 0;

		die(_("hash version %u does not match"), hash_version);
	uint32_t alloc;

#define MIDX_CHUNK_ALIGNMENT 4
	uint32_t orig_pack_int_id;
	verify_midx_error = 1;

			midx_report(_("failed to load pack entry for oid[%d] = %s"),
	char *midx = get_midx_filename(r->objects->odb->path);
		return 0;
{
			    obj->pack_int_id);
	for (i = 0; i < num_packs; i++) {
		pack_name = xstrdup(m->packs[i]->pack_name);
		      m->signature, MIDX_SIGNATURE);
	uint32_t referenced_objects;

			midx_report(_("oid fanout out of order: fanout[%d] = %"PRIx32" > %"PRIx32" = fanout[%d]"),

			      m->pack_names[i]);
	struct pack_info *b = (struct pack_info *)_b;
}
	return MIDX_CHUNK_FANOUT_SIZE;




	size_t midx_size;
	/* Skip past any initial matching prefix. */
	struct multi_pack_index *m = load_multi_pack_index(object_dir, 1);
	return m->num_packs < 2;
	return 0;
}
	midx_map = xmmap(NULL, midx_size, PROT_READ, MAP_PRIVATE, fd, 0);
				     size_t batch_size)
struct repack_info {
	struct hashfile *f = NULL;
				     struct multi_pack_index *m,
			return;
		uint64_t offset;
#include "csum-file.h"
	* still here and can be accessed before supplying that
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + MIDX_CHUNK_FANOUT_SIZE;
static size_t write_midx_oid_fanout(struct hashfile *f,

					uint32_t *perm,
			case MIDX_CHUNKID_OIDFANOUT:
		hashwrite(f, obj->oid.hash, (int)hash_len);
 * tables to group the data, copy to a local array, then sort.
				written += write_midx_oid_fanout(f, entries, nr_entries);
	m->hash_len = the_hash_algo->rawsz;
				       struct pack_midx_entry *objects, uint32_t nr_objects)
#define MIDX_BYTE_HASH_VERSION 5
	uint32_t i;
				    oid_to_hex(&obj->oid),
	}
	 * As we de-duplicate by fanout value, we expect the fanout
#define MIDX_CHUNK_LARGE_OFFSET_WIDTH (sizeof(uint64_t))
	if (!p)
	if (hash_version != MIDX_HASH_VERSION)


};
		close_midx(packs.m);
	if (finish_command(&cmd)) {
		struct pack_entry e;
	include_pack = xcalloc(m->num_packs, sizeof(unsigned char));
	for (i = 0; i < m->num_objects; i++) {

				    chunk_ids[i]);
			case MIDX_CHUNKID_OIDLOOKUP:
	if (m)
		} else {
	/*
			    chunk_offsets[i]);
	return result;

							   cur_object);
		r->objects->multi_pack_index = NULL;
	if (safe_create_leading_directories(midx_name)) {
	if (flags & MIDX_PROGRESS)

		progress = start_progress(_("Writing chunks to multi-pack-index"),
	packs.info = NULL;


		const char *current;
}
	free(pack_info);
	if (!m->chunk_oid_fanout)


	struct pack_midx_entry *list = objects;
				full_path);
		m->next = r->objects->multi_pack_index;

	return xstrfmt("%s/pack/multi-pack-index", object_dir);

			for (cur_object = start; cur_object < end; cur_object++) {
	}
				ALLOC_GROW(entries_by_fanout, nr_fanout + 1, alloc_fanout);
	struct strbuf pack_name = STRBUF_INIT;
	const struct repack_info *a, *b;

	for (i = 0; i < m->num_chunks; i++) {
					  m->num_objects);
	uint32_t i;
}
	if (!m->chunk_oid_lookup)
		if (packs->m && midx_contains_pack(packs->m, file_name))

			return 1;

	uint32_t i;
static int cmp_idx_or_pack_name(const char *idx_or_pack_name,

	struct lock_file lk;
		progress = start_sparse_progress(_("Sorting objects by packfile"),
			packs.nr++;
	/*
	uint64_t written = 0;
	for (i = 0; i < 256; i++) {
		display_progress(progress, i + 1);

	struct multi_pack_index *m;
			    oid_to_hex(&obj->oid),
	if (large_offsets_needed) {
	int result = 0;
	verify_midx_error = 0;

				full_path);
		display_progress(progress, i + 1);
		return 1;

	* We are about to tell the caller where they can locate the
	stop_progress(&progress);

		size_t writelen;
		if (prepare_midx_pack(r, m, i))
	int pack_name_concat_len = 0;
	}
	p->multi_pack_index = 1;
		if (oidcmp(&oid1, &oid2) >= 0)
		pack_info[pack_int_id].referenced_objects++;
	offset_data = m->chunk_object_offsets + pos * MIDX_CHUNK_OFFSET_WIDTH;
		m->pack_names[i] = cur_pack_name;
				nr_fanout++;
			free(packs.info[i].p);
#define MIDX_CHUNK_FANOUT_SIZE (sizeof(uint32_t) * 256)
#define MIDX_CHUNK_OFFSET_WIDTH (2 * sizeof(uint32_t))
	 * we'll correctly return 0 from the final strcmp() below.
{
	uint32_t chunk_ids[MIDX_MAX_CHUNKS + 1];
int midx_repack(struct repository *r, const char *object_dir, size_t batch_size, unsigned flags)
			       sizeof(struct pack_midx_entry));
{
				break;
	char *midx_name;
#define MIDX_CHUNKID_PACKNAMES 0x504e414d /* "PNAM" */
	free(midx);
	b = (const struct repack_info *)b_;


			if (oidcmp(&obj->oid, &next->oid) >= 0)
}
		if ((_n & (SPARSE_PROGRESS_INTERVAL - 1)) == 0) \

	for (i = 0; i < packs.nr; i++) {
	size_t written = 0;
#define MIDX_CHUNKID_OBJECTOFFSETS 0x4f4f4646 /* "OOFF" */
	if (0 <= fd)
				break;


	}
	m->signature = get_be32(m->data);
{

		/*
	if (flags & MIDX_PROGRESS)
	return written;
	trace2_data_intmax("midx", the_repository, "load/num_packs", m->num_packs);
		QSORT(entries_by_fanout, nr_fanout, midx_oid_compare);
	p = m->packs[pack_int_id];
		written += MIDX_CHUNK_OFFSET_WIDTH;

		goto cleanup;
		if (list >= end)
		die(_("multi-pack-index signature 0x%08x does not match signature 0x%08x"),
	struct packed_git *p;
				nr_fanout++;

		idx_name++;
	for (i = 0; i < nr_objects; i++) {

	struct packed_git *p;


#define MIDX_BYTE_FILE_VERSION 4
			result = 1;
	m->fd = fd;
	/*
	if (packs.m && packs.nr == packs.m->num_packs && !packs_to_drop)
				break;
	chunk_ids[cur_chunk] = MIDX_CHUNKID_OIDFANOUT;
	size_t written = 0;
	}

	*/


	cur_chunk++;
	for (i = 0; i < m->num_objects - 1; i++) {
		result = 1;
};
	return nth_midxed_pack_entry(r, m, e, pos);

		result = 1;

	return NULL;

	free(include_pack);
			continue;
	/*

cleanup:
		midx_display_sparse_progress(progress, i + 1);
	free(entries);
/*
		}
/*

		if (!strcmp(object_dir, m_search->object_dir))
			continue;
		return 0;
		if (!fill_midx_entry(r, &oid, &e, m)) {

				die(_("terminating multi-pack-index chunk id appears earlier than expected"));
	struct repack_info *pack_info = xcalloc(m->num_packs, sizeof(struct repack_info));
static void midx_report(const char *fmt, ...)

	 * pack_perm[old_id] = new_id
			case MIDX_CHUNKID_LARGEOFFSETS:
		hashwrite(f, padding, i);
		}
{
{
	if (flags & MIDX_PROGRESS)
		close_pack(m->packs[i]);
			BUG("too many large-offset objects");

		if (prepare_midx_pack(r, m, i))
				nth_midxed_pack_midx_entry(m,
	char *midx_name = get_midx_filename(object_dir);
static size_t write_midx_header(struct hashfile *f,

	strbuf_release(&base_name);
		return 1;
static off_t nth_midxed_offset(struct multi_pack_index *m, uint32_t pos)
struct pack_info {
			end = ntohl(m->chunk_oid_fanout[cur_fanout]);
		die(_("failed to clear multi-pack-index at %s"), midx);
		uint64_t _n = (n); \
		if (written != chunk_offsets[i])
	for (i = 0; i <= num_chunks; i++) {

{
{
		written += hash_len;
static int nth_midxed_pack_entry(struct repository *r,
		if (cmp > 0) {
	FREE_AND_NULL(m->pack_names);
}
			first = mid + 1;
	}
	strbuf_addstr(&base_name, "/pack/pack");
	hashwrite_be32(f, MIDX_SIGNATURE);
	m->num_chunks = m->data[MIDX_BYTE_NUM_CHUNKS];
		goto cleanup_fail;
	stop_progress(&packs.progress);
	struct pack_midx_entry *entries_by_fanout = NULL;
	* Write the first-level table (the list is sorted,
	struct multi_pack_index *m_search;
		goto cleanup;
	/*
static int compare_pair_pos_vs_id(const void *_a, const void *_b)
	install_packed_git(r, p);
	}
	if (packs_to_drop && packs_to_drop->nr) {
				i--;

	return a->pack_int_id - b->pack_int_id;
		else if (!large_offset_needed && obj->offset >> 32)
	cur_chunk++;
	if (batch_size) {




	/*
		if (count[i])
#define MIDX_CHUNKID_OIDFANOUT 0x4f494446 /* "OIDF" */
#include "midx.h"
				ALLOC_GROW(entries_by_fanout, nr_fanout + 1, alloc_fanout);
			continue;
			} else {

			pack_perm[packs.info[i].orig_pack_int_id] = i - dropped_packs;
		char *pack_name;
			    struct pack_midx_entry *entry)
{
	return 0;
	struct pack_midx_entry *list = objects, *end = objects + nr_objects;
	entry->pack_mtime = p->mtime;
	if (m->version != MIDX_VERSION)
	for (cur_pack = start_pack; cur_pack < nr_packs; cur_pack++)
					  m->num_packs);
	return written;
#include "progress.h"
		nth_midxed_object_oid(&oid, m, i);
	va_list ap;
	return strcmp(idx_or_pack_name, idx_name);
						  struct pack_info *info,

}
	return deduplicated_entries;
				      struct pack_midx_entry *e,
	char *pack_name;

	i = MIDX_CHUNK_ALIGNMENT - (written % MIDX_CHUNK_ALIGNMENT);
			case MIDX_CHUNKID_OIDLOOKUP:
		int drop_index = 0;


				break;
	m->pack_names = xcalloc(m->num_packs, sizeof(*m->pack_names));
		hashwrite_be32(f, chunk_ids[i]);
			continue;
	struct pair_pos_vs_id *b = (struct pair_pos_vs_id *)_b;
	for (m_search = r->objects->multi_pack_index; m_search; m_search = m_search->next)
					uint32_t n)

	f = hashfd(lk.tempfile->fd, lk.tempfile->filename.buf);
{
	uint32_t i, *count, result = 0;
		written += 2 * sizeof(uint32_t);
	if (flags & MIDX_PROGRESS)
	* requested object.  We better make sure the packfile is
		 * return here.
			if (!cmp) {
{
		expected_size = (size_t)(p->pack_size
	packs.alloc = packs.m ? packs.m->num_packs : 16;

	struct object_id oid;
				    oid_to_hex(&next->oid));
	struct pack_midx_entry *list = objects;
	 * This not only checks for a complete match, but also orders based on

				packs.info[i].expired = 0;
					     MIDX_CHUNKLOOKUP_WIDTH * i);
		hashwrite(f, info[i].pack_name, writelen);

			return;
	for (i = 0; i < m->num_packs; i++) {
}
	}
			return 1;
		for (i = 0; i < packs.nr && drop_index < packs_to_drop->nr; i++) {
		hashwrite_be32(f, chunk_offsets[i]);

			case MIDX_CHUNKID_OBJECTOFFSETS:
 * It is possible to artificially get into a state where there are many
		return verify_midx_error;
			BUG("object %s requires a large offset (%"PRIx64") but the MIDX is not writing large offsets!",
	ALLOC_ARRAY(pairs, m->num_objects);
		argv_array_push(&cmd.args, "-q");
		die(_("failed to locate object %d in packfile"), cur_object);
		error(_("no pack files to index."));
			die(_("multi-pack-index stores a 64-bit offset, but off_t is too small"));
		}
			midx_report(_("incorrect object offset for oid[%d] = %s: %"PRIx64" != %"PRIx64),
	stop_progress(&progress);
	if (m)
		if (open_pack_index(e.p)) {
		 * The batch is now sorted by OID and then mtime (descending).
}
				error(_("did not see pack-file %s to drop"),
				break;
	va_end(ap);
	 * to group the objects by packfile.  Use this permutation to visit
		packs->info[packs->nr].p = add_packed_git(full_path,
		}
	if (start_command(&cmd)) {
int prepare_multi_pack_index_one(struct repository *r, const char *object_dir, int local)
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + pack_name_concat_len;
			uint32_t start = 0, end;
	/*
		xwrite(cmd.in, oid_to_hex(&oid), the_hash_algo->hexsz);
		close_midx(r->objects->multi_pack_index);
		return 1;
			next++;

			} else if (cmp > 0) {
static size_t write_midx_object_offsets(struct hashfile *f, int large_offset_needed,
	m->num_objects = ntohl(m->chunk_oid_fanout[255]);
				    e.p->pack_name);
	}

	QSORT(packs.info, packs.nr, pack_info_compare);
	cmd.git_cmd = 1;
	return get_be32(m->chunk_object_offsets + pos * MIDX_CHUNK_OFFSET_WIDTH);

	if (flags & MIDX_PROGRESS)
#include "dir.h"

	cur_pack_name = (const char *)m->chunk_pack_names;
			BUG("incorrect pack-file order: %s before %s",
	a = (const struct repack_info *)a_;
	m->local = local;
		struct object_id oid;
			    chunk_offsets[i]);
	uint32_t start_pack = m ? m->num_packs : 0;
	if (env_value < 0)
		written += MIDX_CHUNKLOOKUP_WIDTH;
#define MIDX_MAX_CHUNKS 5
	for (i = 0; i < packs.nr; i++) {
}
		nth_midxed_object_oid(&oid1, m, i);
#define MIDX_CHUNKLOOKUP_WIDTH (sizeof(uint32_t) + sizeof(uint64_t))
}

		}
		die(_("multi-pack-index missing required OID fanout chunk"));


	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + nr_entries * the_hash_algo->rawsz;
int fill_midx_entry(struct repository * r,
			default:
		return;

	struct pack_midx_entry *entries = NULL;
		memset(padding, 0, sizeof(padding));
		size_t expected_size;
							  0);
		uint32_t oid_fanout2 = ntohl(m->chunk_oid_fanout[i + 1]);
	chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] + nr_entries * MIDX_CHUNK_OFFSET_WIDTH;
}
	uint32_t i, packs_to_repack;
			    info[i - 1].pack_name,
					struct multi_pack_index *m,
		return 1;
	return write_midx_internal(object_dir, NULL, NULL, flags);
				 * Do nothing on unrecognized chunks, allowing future
	if (m) {
		if (info[i].expired)
	for (i = 0; i < num_chunks; i++) {

	struct pack_midx_entry *last = objects + nr_objects;
{

	* loaded!

			large_offsets_needed = 1;
		nth_midxed_object_oid(&oid2, m, i + 1);
	return written;
		switch (chunk_id) {

	hold_lock_file_for_update(&lk, midx_name, LOCK_DIE_ON_ERROR);
		}
	list_add_tail(&p->mru, &r->objects->packed_git_mru);
	num_chunks = large_offsets_needed ? 5 : 4;
			midx_report("failed to load pack in position %d", i);
			continue;
					 packs_to_drop->items[drop_index].string);
	QSORT(pack_info, m->num_packs, compare_by_mtime);
	stop_progress(&progress);
	if (pack_int_id >= m->num_packs)


 * Limit calls to display_progress() for performance reasons.
{
	}
		    m->pack_names[pack_int_id]);

	} while (0)
			      m->pack_names[i - 1],
	const struct pack_midx_entry *b = (const struct pack_midx_entry *)_b;

				break;
	argv_array_push(&cmd.args, "pack-objects");
		midx_display_sparse_progress(progress, i + 1);
		return 0;
		ALLOC_GROW(packs->info, packs->nr + 1, packs->alloc);
{
	* having to do eight extra binary search iterations).
		    m->packs[pairs[i-1].pack_int_id])
	uint32_t count = 0;
			break;
		if (sizeof(off_t) < sizeof(uint64_t))
	offset32 = get_be32(offset_data + sizeof(uint32_t));
{
}
cleanup_fail:
	if (p->num_bad_objects) {
					struct pack_midx_entry *objects, uint32_t nr_objects)

	 * a naively-sorted list.
}
	 * Technically this matches "fooidx" and "foopack", but we'd never have
	for (i = 0; i < nr_entries; i++) {
		    pack_int_id, m->num_packs);

#define MIDX_MIN_SIZE (MIDX_HEADER_SIZE + the_hash_algo->rawsz)

				written += write_midx_large_offsets(f, num_large_offsets, entries, nr_entries);
	if (!strcmp(idx_name, "idx") && !strcmp(idx_or_pack_name, "pack"))
	written = write_midx_header(f, num_chunks, packs.nr - dropped_packs);
	do { \
#include "run-command.h"
	return 0;

	for (i = 0; i < m->num_objects; i++) {
	}

		if (!cmp)
	argv_array_push(&cmd.args, base_name.buf);
	if (fstat(fd, &st)) {
		progress = start_progress(_("Looking for referenced packfiles"),
				 struct pack_entry *e,
	uint32_t i;
		hashwrite_be32(f, count);
	unsigned char cur_chunk, num_chunks = 0;
		uint32_t pack_int_id = nth_midxed_pack_int_id(m, i);
	string_list_clear(&packs_to_drop, 0);
	if (midx_size < MIDX_MIN_SIZE) {
	 */
	static int env_value = -1;
	m = NULL;
		return NULL;

 * Copy only the de-duplicated entries (selected by most-recent modified time
		if (prepare_midx_pack(r, m, i))

			    chunk_ids[i]);

			count++;
		    written,

			continue;
	if (r->objects && r->objects->multi_pack_index) {
		{
		return 0;
		last = mid;


			continue;
	alloc_objects = alloc_fanout = total_objects > 3200 ? total_objects / 200 : 16;
#define MIDX_CHUNKID_LARGEOFFSETS 0x4c4f4646 /* "LOFF" */
			continue;
	munmap((unsigned char *)m->data, m->data_len);
			case MIDX_CHUNKID_LARGEOFFSETS:
			BUG("object %s is in an expired pack with int-id %d",
		die(_("bad pack-int-id: %u (%u total packs)"),

	uint32_t nr_entries, num_large_offsets = 0;
		off_t m_offset, p_offset;

	uint32_t pos;
		goto cleanup;

		return 0;
static size_t write_midx_pack_names(struct hashfile *f,
					  num_chunks);
#include "object-store.h"
	 *
	if (flags & MIDX_PROGRESS)
	size_t written = 0;
			case MIDX_CHUNKID_OBJECTOFFSETS:
	else if (a->pack_mtime < b->pack_mtime)
		return 1;
	}
#define MIDX_LARGE_OFFSET_NEEDED 0x80000000
			end = get_pack_fanout(info[cur_pack].p, cur_fanout);
	if (a->mtime < b->mtime)
		total_size += expected_size;
				/*
		p_offset = find_pack_entry_one(oid.hash, e.p);
		return 0;
	packs_to_repack = 0;
	 * a complete match (and in that case these strcmps will be false, but
		}
{

}

		error(_("multi-pack-index file %s is too small"), midx_name);
			    oid_to_hex(&obj->oid),
		chunk_offsets[cur_chunk] = chunk_offsets[cur_chunk - 1] +
				    struct pack_info *info,
	}
	m->data = midx_map;

		int pack_int_id = pack_info[i].pack_int_id;

static int write_midx_internal(const char *object_dir, struct multi_pack_index *m,

				packs.info[i].expired = 1;
		struct pack_midx_entry *obj = list++;
		writelen = strlen(info[i].pack_name) + 1;
		die(_("error preparing packfile from multi-pack-index"));

		 */
{
	uint32_t i;
		if (i && strcmp(info[i].pack_name, info[i - 1].pack_name) <= 0)
		if (oid_fanout1 > oid_fanout2)
		die_errno(_("unable to create leading directories of %s"),

int expire_midx_packs(struct repository *r, const char *object_dir, unsigned flags)
 * The interval here was arbitrarily chosen.

	if (midx_map)
		pairs[i].pos = i;
		pairs[i].pack_int_id = nth_midxed_pack_int_id(m, i);
		close(fd);
	for (i = 0; i < m->num_objects; i++) {
	if (i < MIDX_CHUNK_ALIGNMENT) {
			continue;
	byte_values[0] = MIDX_VERSION;
	int result = 0;

	for (i = 0; i < m->num_packs; i++)
{
	ALLOC_ARRAY(deduplicated_entries, alloc_objects);
static int compare_by_mtime(const void *a_, const void *b_)
		}
		written += writelen;

				    pairs[i].pos, oid_to_hex(&oid));
	return offset32;
	QSORT(pairs, m->num_objects, compare_pair_pos_vs_id);
	return 0;
		uint32_t nr_fanout = 0;
		struct pack_midx_entry *next = list;
				BUG("OIDs not in order: %s >= %s",

void clear_midx_file(struct repository *r)
		}
							   &entries_by_fanout[nr_fanout],
				written += write_midx_pack_names(f, packs.info, packs.nr);
	struct child_process cmd = CHILD_PROCESS_INIT;

	for (i = 0; i < m->num_packs; i++) {
			continue;
		struct packed_git *p = m->packs[pack_int_id];
	midx_name = get_midx_filename(object_dir);
				continue;
		current = m->pack_names[mid];
		/*
	uint32_t nr;
	 * such names in the first place.
	ALLOC_ARRAY(pack_perm, packs.nr);
{

			    the_hash_algo->rawsz, result);

	m->version = m->data[MIDX_BYTE_FILE_VERSION];
		if (!(offset >> 31))
#include "cache.h"
	uint32_t pack_int_id;
	}


}
			die(_("multi-pack-index pack names out of order: '%s' before '%s'"),

	uint32_t i;
				 struct multi_pack_index *m,
	if (written != chunk_offsets[num_chunks])

}
	* but we use a 256-entry lookup to be able to avoid


}
	FREE_AND_NULL(m->packs);
			ALLOC_GROW(deduplicated_entries, *nr_objects + 1, alloc_objects);
		if (open_pack_index(packs->info[packs->nr].p)) {


