 * data (i.e. from partial_pack_offset to the end) is then computed and
			 * Now let's compute the SHA1 of the remainder of the
	}
				  ? (0x80000000 | nr_large_offset++)
}
		hdr.idx_signature = htonl(PACK_IDX_SIGNATURE);
			 unsigned char *partial_pack_hash,
	struct pack_idx_entry **sorted_by_sha, **list, **last;

			the_hash_algo->final_fn(hash, &old_hash_ctx);
		if (skip_prefix(packname, "keep\t", &name))
		struct pack_idx_header hdr;
				  : obj->offset);
	char *buf;
 * will be sorted by SHA1 on exit.
		if (!aligned_sz)
			unlink(index_name);
		the_hash_algo->final_fn(partial_pack_hash, &old_hash_ctx);
{
 */
	ofsval = offset;
	*hdr = c;
	 * Write the first-level table (the list is sorted,

		const char *name;
		die_errno("Failed seeking to start of '%s'", pack_name);
	/* if last object's offset is >= 2^31 we should use index V2 */
 *  - first byte: low four bits are "size", then three bits of "type",
}
	int basename_len = name_buffer->len;
	if (rename(idx_tmp_name, name_buffer->buf))
			if (objects[i]->offset > last_obj_offset)
}
/*
	for (i = 0; i < nr_objects; i++) {
		unsigned int nr_large_offset = 0;
 * returned in partial_pack_sha1.
char *index_pack_lockfile(int ip_out)
	return NULL;
	uint32_t b = *((uint32_t *)b_);
 * The per-object header is a pretty dense thing, which is
		hdr.idx_version = htonl(index_version);
		} else {
	struct pack_idx_entry *b = *(struct pack_idx_entry **)_b;
		die_errno("unable to rename temporary index file");
		partial_pack_offset -= n;
				       get_object_directory(), name);
	} else {
		the_hash_algo->update_fn(&new_hash_ctx, buf, n);
{
		list = sorted_by_sha;
	hdr.hdr_version = htonl(PACK_VERSION);

		while (next < last) {
			hashwrite(f, split, 8);
}
{
		for (i = 0; i < nr_objects; ++i) {

	off_t last_obj_offset = 0;
	opts->off32_limit = 0x7fffffff;

	else
	if (type < OBJ_COMMIT || type > OBJ_REF_DELTA)
	buf = xmalloc(buf_sz);
		if (partial_pack_offset == 0) {
	hashwrite(f, array, 256 * 4);
			break;

			struct strbuf tmp_file = STRBUF_INIT;
	c = (type << 4) | (size & 15);
 *    and the high bit is "size continues".
	hdr.hdr_entries = htonl(nr_entries);
		die_errno("Unable to reread header of '%s'", pack_name);

		last = sorted_by_sha + nr_objects;
	return !!bsearch(&ofsval, opts->anomaly, opts->anomaly_nr,
	uint32_t a = *((uint32_t *)a_);
			unsigned char hash[GIT_MAX_RAWSZ];

	the_hash_algo->update_fn(&new_hash_ctx, &hdr, sizeof(hdr));
			 * pack, which also means making partial_pack_offset
	hashwrite(f, &hdr, sizeof(hdr));
		sorted_by_sha = objects;
		aligned_sz -= n;
		die_errno("unable to make temporary pack file readable");
}
		QSORT(sorted_by_sha, nr_objects, sha1_compare);
	}
void finish_tmp_packfile(struct strbuf *name_buffer,
	}
			struct pack_idx_entry *obj = *list++;
}
#include "pack.h"
		*hdr++ = c | 0x80;
			next++;
				 enum object_type type, uintmax_t size)
	 * is "pack\t%40s\n" or "keep\t%40s\n" (46 bytes) where
	partial_pack_offset -= sizeof(hdr);
			die_errno("Failed to checksum '%s'", pack_name);
		assert(index_name);
		if (!partial_pack_hash)

 * On entry *sha1 contains the pack content SHA1 hash, on exit it is

			 struct pack_idx_entry **written_list,
	 */
				      pack_idx_opts, hash);
 * associated to pack_fd, and write that SHA1 at the end.  That new SHA1
		/* write the 32-bit offset table */
	size >>= 4;
			    oid_to_hex(&obj->oid));
		}
			   const unsigned char *sha1)
	 */

	}
		packname[len-1] = 0;
	uint32_t ofsval;
		}
	 * The first thing we expect from index-pack's output
{
			 const char *pack_tmp_name,
{
			 uint32_t nr_written,
	return oidcmp(&a->oid, &b->oid);
			if (!hasheq(hash, partial_pack_hash))

			 struct pack_idx_option *pack_idx_opts,
	return index_name;
			struct pack_idx_entry *obj = *list++;
		n = xread(pack_fd, buf, m);
			 */
	uint32_t array[256];
#include "csum-file.h"
	if (lseek(pack_fd, 0, SEEK_SET) != 0)


	strbuf_setlen(name_buffer, basename_len);

		hashwrite(f, &hdr, sizeof(hdr));
	}
			/*
void fixup_pack_header_footer(int pack_fd,
/*

	if (!opts->anomaly_nr)

		struct pack_idx_entry *obj = *list++;
			if (fd < 0)

		return 1;
			the_hash_algo->init_fn(&old_hash_ctx);
	 * later on.  If we don't get that then tough luck with it.
 * partial_pack_sha1 can refer to the same buffer if the caller is not
 * the SHA1 hash of sorted object names. The objects array passed in
}
	else if (read_result != sizeof(hdr))
			 unsigned char hash[])
	 * having to do eight extra binary search iterations).
			index_name = strbuf_detach(&tmp_file, NULL);
	uint32_t index_version;
		if (!index_name) {
			hashwrite(f, &offset, 4);
	if (adjust_shared_perm(idx_tmp_name))
		}
			uint32_t split[2];


		die_errno("Failed seeking to start of '%s'", pack_name);
		array[i] = htonl(next - sorted_by_sha);
	}
				    ((opts->flags & WRITE_IDX_VERIFY)
 * one provided in partial_pack_sha1.  The validation is performed at
 * Note that new_pack_sha1 is updated last, so both new_pack_sha1 and
 */
static int sha1_compare(const void *_a, const void *_b)
	fsync_or_die(pack_fd, pack_name);
	fd = odb_mkstemp(&tmpname, "pack/tmp_pack_XXXXXX");
			 const char *pack_name,

	}
	the_hash_algo->init_fn(&new_hash_ctx);
			hashwrite(f, &crc32_val, 4);
	struct hashfile *f;
		the_hash_algo->update_fn(&old_hash_ctx, buf, n);
				    ? 0 : CSUM_FSYNC));

		list = sorted_by_sha;
	hdr.hdr_entries = htonl(object_count);
		list = sorted_by_sha;
		if ((opts->flags & WRITE_IDX_STRICT) &&
				continue;
	if (read_in_full(ip_out, packname, len) == len && packname[len-1] == '\n') {
	 */

}
		    (i && oideq(&list[-2]->oid, &obj->oid)))
 *
			continue;
			die("object size is too enormous to format");

			nr_large_offset--;

			partial_pack_offset : aligned_sz;

	ssize_t read_result;
 * partial_pack_offset bytes in the pack file.  The SHA1 of the remaining
	}

	const int len = the_hash_algo->hexsz + 6;
	return n;

		die_errno("unable to rename temporary pack file");
}
			aligned_sz = buf_sz;
const char *write_idx_file(const char *index_name, struct pack_idx_entry **objects,
	/*
		m = (partial_pack_hash && partial_pack_offset < aligned_sz) ?
	 * but we use a 256-entry lookup to be able to avoid
	if (partial_pack_hash)
		return 0;
{
struct hashfile *create_tmp_packfile(char **pack_tmp_name)
 * interested in the resulting SHA1 of pack data above partial_pack_offset.
{
	struct pack_header hdr;
 * is also returned in new_pack_sha1.
			 unsigned char *new_pack_hash,
	return (a < b) ? -1 : (a != b);
{

	if (index_version >= 2) {
 *  - each byte afterwards: low seven bits are size continuation,
		size >>= 7;
				break;

	/* index versions 2 and above need a header */

	index_version = need_large_offset(last_obj_offset, opts) ? 2 : opts->version;
	memset(opts, 0, sizeof(*opts));
		for (i = 0; i < nr_objects; i++) {
	const char *idx_tmp_name;
		/* write the large offset table */
			 uint32_t object_count,
	aligned_sz = buf_sz - sizeof(hdr);

	write_or_die(pack_fd, new_pack_hash, the_hash_algo->rawsz);
	strbuf_addf(name_buffer, "%s.idx", hash_to_hex(hash));
	idx_tmp_name = write_idx_file(NULL, written_list, nr_written,
		}
		sorted_by_sha = list = last = NULL;

	int n = 1;
	if (nr_objects) {
			struct pack_idx_entry *obj = *next;
		list = next;
	the_hash_algo->update_fn(&old_hash_ctx, &hdr, sizeof(hdr));
		ssize_t m, n;
}
			uint32_t offset = htonl(obj->offset);
		f = hashfd(fd, index_name);
		die_errno("Unexpected short read for header of '%s'",
			if (obj->oid.hash[0] != i)

	 * case, we need it to remove the corresponding .keep file
#include "cache.h"
	strbuf_addf(name_buffer, "%s.pack", hash_to_hex(hash));
	if (index_version >= 2) {
 * Update pack header with object_count and compute new SHA1 for pack data
			partial_pack_offset = ~partial_pack_offset;
	git_hash_ctx old_hash_ctx, new_hash_ctx;
		f = hashfd_check(index_name);
	*pack_tmp_name = strbuf_detach(&tmpname, NULL);
}

		if (!n)
			   int nr_objects, const struct pack_idx_option *opts,
	the_hash_algo->final_fn(new_pack_hash, &new_hash_ctx);
{
off_t write_pack_header(struct hashfile *f, uint32_t nr_entries)
			offset = (need_large_offset(obj->offset, opts)
{
			fd = odb_mkstemp(&tmp_file, "pack/tmp_idx_XXXXXX");

		if (n < 0)
	unsigned char c;
void reset_pack_idx_option(struct pack_idx_option *opts)
	while (size) {
			split[1] = htonl(offset & 0xffffffff);
			uint32_t crc32_val = htonl(obj->crc32);
	write_or_die(pack_fd, &hdr, sizeof(hdr));
			die("The same object %s appears twice in the pack",
	hashwrite(f, sha1, the_hash_algo->rawsz);
	read_result = read_in_full(pack_fd, &hdr, sizeof(hdr));
			partial_pack_offset -= MSB(partial_pack_offset, 1);
		if (index_version < 2) {
	return hashfd(fd, *pack_tmp_name);
				die_errno("unable to create '%s'", index_name);
			offset = htonl(offset);
		while (nr_large_offset) {
		}

	finalize_hashfile(f, NULL, CSUM_HASH_IN_STREAM | CSUM_CLOSE |
static int cmp_uint32(const void *a_, const void *b_)
			uint64_t offset = obj->offset;
	char packname[GIT_MAX_HEXSZ + 6];
static int need_large_offset(off_t offset, const struct pack_idx_option *opts)


	if (opts->flags & WRITE_IDX_VERIFY) {
			  pack_name);
/*
				die("Unexpected checksum for %s "
		struct pack_idx_entry **next = list;
	 * Write the actual SHA1 entries..
		list = sorted_by_sha;
		}
		if (n == hdr_len)
		}
	for (;;) {

{
			fd = open(index_name, O_CREAT|O_EXCL|O_WRONLY, 0600);
	 * %40s is the newly created pack SHA1 name.  In the "keep"
	free((void *)idx_tmp_name);

	int fd;
			return xstrfmt("%s/pack/pack-%s.keep",
			 off_t partial_pack_offset)
				last_obj_offset = objects[i]->offset;
		hashwrite(f, obj->oid.hash, the_hash_algo->rawsz);
	for (i = 0; i < 256; i++) {

	int aligned_sz, buf_sz = 8 * 1024;
			if (!need_large_offset(offset, opts))
			struct pack_idx_entry *obj = *list++;
				    "(disk corruption?)", pack_name);
	int i, fd;
 */
	struct pack_header hdr;
	/*
	return sizeof(hdr);
		/* write the crc32 table */

	list = sorted_by_sha;
	if (read_result < 0)
		die_errno("unable to make temporary index file readable");

			uint32_t offset;
	the_hash_algo->init_fn(&old_hash_ctx);
	if (rename(pack_tmp_name, name_buffer->buf))
			hashwrite(f, &offset, 4);
	struct pack_idx_entry *a = *(struct pack_idx_entry **)_a;

		die("bad type %d", type);
	struct strbuf tmpname = STRBUF_INIT;
	if (lseek(pack_fd, 0, SEEK_SET) != 0)
	hdr.hdr_signature = htonl(PACK_SIGNATURE);
	if ((offset >> 31) || (opts->off32_limit < offset))
	}
			split[0] = htonl(offset >> 32);
 *    with the high bit being "size continues"
 * (without the header update) is computed and validated against the
	opts->version = 2;
 *
		for (i = 0; i < nr_objects; i++) {

	if (adjust_shared_perm(pack_tmp_name))
			 * big enough not to matter anymore.
	/*
int encode_in_pack_object_header(unsigned char *hdr, int hdr_len,
 * If partial_pack_sha1 is non null, then the SHA1 of the existing pack
		}
		c = size & 0x7f;
	free(buf);
			 sizeof(ofsval), cmp_uint32);
		n++;
	strbuf_setlen(name_buffer, basename_len);
