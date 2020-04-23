		free(data);
	git_hash_ctx ctx;
	unsigned int nr;
		len -= avail;

		unsigned char *in = use_pack(p, w_curs, offset, &remaining);
	do {
	} while (len);
			data = unpack_entry(r, p, entries[i].offset, &type, &size);
	const uint32_t *index_crc;

	r->hash_algo->final_fn(hash, &ctx);
	unsigned char hash[GIT_MAX_RAWSZ], *pack_sig;

	unuse_pack(w_curs);
{
	struct idx_entry *entries;

		else if (check_object_signature(r, &oid, data, size, type_name(type)))
		return error("packfile %s cannot be accessed", p->pack_name);
		curpos = entries[i].offset;
static int compare_entries(const void *e1, const void *e2)
	unuse_pack(&w_curs);
		unsigned long size;

	uint32_t nr_objects, i;
	free(entries);
	if (!p->index_data)
	return data_crc != ntohl(*index_crc);

					    oid_to_hex(&oid),

	the_hash_algo->update_fn(&ctx, index_base, (unsigned int)(index_size - the_hash_algo->rawsz));
}
	for (i = 0; i < nr_objects; i++) {
}
	return 0;
				data = NULL;
	display_progress(progress, base_count + i);
	struct pack_window *w_curs = NULL;
	off_t offset = 0, pack_sig_ofs = 0;
	ALLOC_ARRAY(entries, nr_objects + 1);
		void *data = use_pack(p, w_curs, offset, &avail);
		void *data;
			    (unsigned long)entries[i].nr, p->pack_name);
		offset += avail;
	the_hash_algo->init_fn(&ctx);
}
	do {
			 * the streaming interface; no point slurping
int check_pack_crc(struct packed_git *p, struct pack_window **w_curs,

			display_progress(progress, base_count + i);
			if (check_pack_crc(p, w_curs, offset, len, nr))

	int err = 0;
	}
			data = NULL;
	/* Verify SHA1 sum of the index file */

			data_valid = 0;
			off_t len = entries[i+1].offset - offset;

	int err = 0;
					    "from %s at offset %"PRIuMAX"",
	git_hash_ctx ctx;

#include "pack-revindex.h"
			data_valid = 1;
		enum object_type type;
			   verify_fn fn,
			 * Let check_object_signature() check it with
}
		entries[i].nr = i;
	const unsigned char *index_base;
	if (open_pack_index(p))
			remaining -= (unsigned int)(offset - pack_sig_ofs);
	const struct idx_entry *entry2 = e2;
			if (eaten)
	const struct idx_entry *entry1 = e1;
			   struct progress *progress, uint32_t base_count)
			unsigned int nr = entries[i].nr;
#include "progress.h"
	nr_objects = p->num_objects;
	err |= verify_pack_index(p);
			err |= fn(&oid, type, size, data, &eaten);
			    p->pack_name);
					    p->pack_name, (uintmax_t)offset);
			   struct packed_git *p,
		unuse_pack(w_curs);
				    (uintmax_t)entries[i].offset);
	if (entry1->offset > entry2->offset)
			 * the data in-core only to discard.
		struct progress *progress, uint32_t base_count)
		if (!pack_sig_ofs)
	index_size = p->index_size;
		if (p->index_version > 1) {
		if (nth_packed_object_id(&oid, p, entries[i].nr) < 0)
		return -1;

int verify_pack(struct repository *r, struct packed_git *p, verify_fn fn,
		if (((base_count + i) & 1023) == 0)
		int data_valid;
	QSORT(entries, nr_objects, compare_entries);
	if (!is_pack_valid(p))
			avail = len;
			   struct pack_window **w_curs,
	}
		if (type == OBJ_BLOB && big_file_threshold <= size) {
		off_t curpos;
	index_crc = p->index_data;
			/*
		unsigned long avail;
		offset += remaining;
	return err;
		return -1;
			    p->pack_name);
	index_base = p->index_data;
#include "repository.h"

	 */
		if (data_valid && !data)
	if (!hasheq(index_base + index_size - r->hash_algo->hexsz, pack_sig))
		r->hash_algo->update_fn(&ctx, in, remaining);
		if (offset > pack_sig_ofs)
		}
		entries[i].offset = nth_packed_object_offset(p, i);
			err = error("cannot unpack %s from %s at offset %"PRIuMAX"",
		err = error("Packfile index for %s hash mismatch",
		if (avail > len)
				    oid_to_hex(&oid), p->pack_name,
		   off_t offset, off_t len, unsigned int nr)
				err = error("index CRC mismatch for object %s "
	pack_sig = use_pack(p, w_curs, pack_sig_ofs, NULL);
		type = unpack_object_header(p, w_curs, &curpos, &size);
	the_hash_algo->final_fn(hash, &ctx);
		}
	int err = 0;
{
			int eaten = 0;

	for (i = 0; i < nr_objects; i++) {
struct idx_entry {
	if (!hasheq(hash, index_base + index_size - the_hash_algo->rawsz))
	err |= verify_packfile(r, p, &w_curs, fn, progress, base_count);
				    oid_to_hex(&oid), p->pack_name);
{
#include "packfile.h"
	/* Make sure everything reachable from idx is valid.  Since we

		else if (fn) {
	const unsigned char *index_base = p->index_data;
		return error("packfile %s index not opened", p->pack_name);
#include "cache.h"
			pack_sig_ofs = p->pack_size - r->hash_algo->rawsz;
		err = error("%s pack checksum does not match its index",
#include "object-store.h"

	/* first sort entries by pack offset, since unpacking them is more efficient that way */

		} else {
		data_crc = crc32(data_crc, data, avail);

	if (!hasheq(hash, pack_sig))
{
	entries[nr_objects].offset = pack_sig_ofs;
	r->hash_algo->init_fn(&ctx);
	off_t index_size = p->index_size;
static int verify_packfile(struct repository *r,
}
	off_t                offset;
	 * we do not do scan-streaming check on the pack file.
			BUG("unable to get oid of object %lu from %s",
		unsigned long remaining;

			off_t offset = entries[i].offset;
	unsigned char hash[GIT_MAX_RAWSZ];
	if (entry1->offset < entry2->offset)

			err = error("packed %s from %s is corrupt",
		}
int verify_pack_index(struct packed_git *p)
			 */
			    p->pack_name);
	off_t index_size;
	return err;
		struct object_id oid;

		return 1;
	uint32_t data_crc = crc32(0, NULL, 0);
#include "pack.h"
	 * have verified that nr_objects matches between idx and pack,

	} while (offset < pack_sig_ofs);
		err = error("%s pack checksum mismatch",

{
};
	index_crc += 2 + 256 + p->num_objects * (the_hash_algo->rawsz/4) + nr;
	return err;


