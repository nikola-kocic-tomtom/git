		win->last_used = pack_used_ctr++;
	stream.next_out = delta_head;
static unsigned int get_max_fd_limit(void)
	if (a->mtime < b->mtime)
	if (oi->disk_sizep) {

#include "object-store.h"
	/*
	}

				*lru_l = w_l;
				      st_mult(GIT_MAX_RAWSZ,

	if (!force_delete) {
	off_t curpos = obj_offset;
				strbuf_addstr(oi->type_name, tn);
	strbuf_addstr(&path, objdir);
		obj_read_lock();
	if (!p->pack_size && p->pack_fd == -1 && open_packed_git(p))
	if (!strip_suffix_mem(path, &path_len, ".idx"))
#define UNPACK_ENTRY_STACK_PREALLOC 64
	struct list_head *lru, *tmp;

	return find_pack_entry(the_repository, oid, &e);

	stream.avail_out = size + 1;
{
	data.r = r;
	index_lookup = index_fanout + 4 * 256;
	delta_base_cached -= ent->size;
	case OBJ_TREE:
		 *  - 24-byte entries * nr (object ID + 4-byte offset)
}
	enum object_type type;
	}
			       void *data)
		    && delta_stack == small_delta_stack) {
		"pack_report: pack_open_windows        = %10u / %10u\n"
}

		 *  - 8 bytes of header
	void *content;
static int delta_base_cache_hash_cmp(const void *unused_cmp_data,
{

		 * Total size:
				   p->bad_object_sha1 + the_hash_algo->rawsz * i))
		oidset_insert(set, get_commit_tree_oid(commit));
	}
}
{
	}

		/* Don't reopen a pack we already have. */
	if (!promisor_objects_prepared) {

	if (oi->contentp) {
static int close_one_pack(void)
	list_for_each(pos, &r->objects->packed_git_mru) {
		struct rlimit lim;

struct packed_git *get_packed_git(struct repository *r)
	if (ends_with(file_name, ".idx") ||
	off_t win_off = win->offset;
		 *     and signaled an error with -1; or
	}
	 */

}
	if (check_packed_git_idx(idx_path, p)) {


	unsigned long used;

	}
	if (offset < 0)
			     p->num_objects);
	}
		void *external_base = NULL;
	if (type <= OBJ_NONE)
struct packed_git *parse_pack_index(unsigned char *sha1, const char *idx_path)
{
		 * is a lot simpler.

	const uint32_t *level1_ofs = p->index_data;
			add_delta_base_cache(p, obj_offset, base, base_size, type);
	hashcpy(oid.hash, sha1);
	git_zstream stream;
}
		size += (c & 0x7f) << shift;
 * Give a fast, rough count of the number of objects in the repository. This
	struct packed_git *p, *lru_p = NULL;
}
void clear_delta_base_cache(void)

		die("offset beyond end of packfile (truncated pack?)");
			strbuf_release(&buf);
			win->next = p->windows;

	for (i = 0; i < ARRAY_SIZE(exts); i++) {
		if (!base_offset)
}
}

		for (m = the_repository->objects->multi_pack_index;
		free(delta_stack);
	r->objects->packed_git = llist_mergesort(
	/* Force the pack to open to prove its valid. */
		if (w->last_used > this_mru_w->last_used)
	hashmap_entry_init(&pack->packmap_ent, strhash(pack->pack_name));
	while (pack_max_fds <= pack_open_fds && close_one_pack())
		 * "closing the file descriptor does not unmap the region". And


			ALLOC_ARRAY(delta_stack, delta_stack_alloc);
			count += m->num_objects;
	struct string_list *garbage;
	return hash;
{
	if (ret)
			continue;
		 * tell these two cases apart and return a huge number
static int delta_base_cache_key_eq(const struct delta_base_cache_key *a,
	ent = get_delta_base_cache_entry(p, base_offset);
	 * has that one hash excess) must be used.  This is to support
		shift += 7;
	used = unpack_object_header_buffer(base, left, &type, sizep);
		uint32_t pos;
			  int seen_bits, int first, int last)
	unuse_pack(&w_curs);
		*curpos += used;
		if ((flags & FOR_EACH_OBJECT_PROMISOR_ONLY) &&
				; /* nothing */
}
	return content;

				nth_packed_object_id(&base_oid, p, revidx->nr);
	if (lru_p)
		unsigned long *left)
	 * answer, as it may have been deleted since the index was
		prepare_packed_git_one(r, odb->path, local);
		}
			base_offset += 1;
		base_offset = c & 127;
		return unpack_entry(r, p, base_offset, type, base_size);
	 * requested object.  We better make sure the packfile is
		else
	fprintf(stderr,
			struct object_id base_oid;
			prepare_midx_pack(r, m, i);
		}
	} else if (type == OBJ_REF_DELTA) {
int is_pack_valid(struct packed_git *p)
	 * the use xsnprintf double-checks that)
		if ((flags & FOR_EACH_OBJECT_LOCAL_ONLY) && !p->pack_local)
		munmap((void *)p->index_data, p->index_size);
			delta_stack_alloc = alloc_nr(delta_stack_nr);
}
	hashmap_entry_init(&ent->ent, pack_entry_hash(p, base_offset));
	if (!index_fanout)
	 *   'data' holds the base data, or NULL if there was corruption
	const unsigned char *index_lookup;

	 * is unpacking the same object, in unpack_entry() (since its phases I
	struct list_head *pos;
	case OBJ_BLOB:
#include "packfile.h"
	 * If this is a tree, commit, or tag, the objects it refers
	}
	}
	}
			off_t len = revidx[1].offset - obj_offset;
	if (oi->delta_base_oid) {
	pack_open_fds--;
	INIT_LIST_HEAD(&r->objects->packed_git_mru);
	/* use_pack() assures us we have [base, base + 20) available

	enum object_type type;
	git_inflate_init(&stream);
	case OBJ_COMMIT:
	}
		 * we return NULL. Those code paths will take care of making
	buffer = xmallocz_gently(size);
			continue;

	}
	while (p->windows) {

	ent->key.base_offset = base_offset;
	}
	return type;
	size = c & 15;
	for (w_l = NULL, w = p->windows; w; w = w->next) {
static void *read_object(struct repository *r,

	p->pack_local = local;
struct packed_git *get_all_packs(struct repository *r)
	const unsigned char *data;
	report_pack_garbage(data.garbage);
	 */
			return open_max;

		if (0 < open_max)
				goto out;
			*oi->typep = ptot;
	}
		long open_max = sysconf(_SC_OPEN_MAX);
	}
{

			if (check_pack_crc(p, &w_curs, obj_offset, len, revidx->nr)) {
		 * used more recently than the previously selected pack.
	for (m = r->objects->multi_pack_index; m; m = m->next) {
}
		struct pack_window **w_cursor,
			win->base = xmmap_gently(NULL, win->len,
 * Open and mmap the index file at path, perform a couple of
	struct pack_header hdr;
		return get_be64(index);
	/*
				type = OBJ_BAD;
						   type, delta_obj_offset);
{
	const unsigned char *end = start + p->index_size;
	close(fd);
		munmap(w->base, w->len);
	size_t len;
				base = read_object(r, &base_oid, &type, &base_size);
	key.base_offset = base_offset;

		      type, (uintmax_t)obj_offset, p->pack_name);
		 */
	struct pack_window *mru_w = NULL;
	if (version > 1)
		if (!revidx)
		 * but the previously selected pack did not have any


		ent = get_delta_base_cache_entry(p, curpos);
	stream.avail_out = sizeof(delta_head);
}
			pack_mapped += win->len;
	if (p->index_version > 1) {
	for (p = packs; p; p = p->next) {
		 * a more explicit warning and retrying with another copy of
	    get_sha1_hex(path + path_len - the_hash_algo->hexsz, p->hash))
	return !!get_delta_base_cache_entry(p, base_offset);
{

	ent->data = base;
		type = retry_bad_packed_offset(r, p, obj_offset);
			base_offset = (base_offset << 7) + (c & 127);
		unsigned long count;
{
	    ends_with(file_name, ".promisor"))
	for (i = 0; i < list->nr; i++) {

#ifdef RLIMIT_NOFILE
		 * Our failure will be noticed either in the next iteration of

	index += 4 * 256;
		return NULL;
	if (!obj)
	return &r->objects->packed_git_mru;
}
	oi.contentp = &content;
	data.m = r->objects->multi_pack_index;
	for (; first < last; first++)
		return 0;
	struct hashmap_entry entry, *e;
		return -st;
		struct delta_base_cache_entry *f =
			 uint32_t n)


	 */
	prepare_packed_git(r);
		free(external_base);

		index_lookup_width = hashsz;

	 * the maximum deflated object size is 2^137, which is just
		/*
}
		 */
		r->objects->approximate_object_count = count;
}
}



			if (midx_contains_pack(m, pack_name))

 * you should repack because your performance will be awful, or they are
}

			 * We're probably in deep shit, but let's try to fetch
	if (oi->typep || oi->type_name) {
	struct packed_git *p;
}
	int st;
		index += 8;
	const unsigned hashsz = the_hash_algo->rawsz;
	 */
};
{
			}
		if (n < nr)

 */
	 */
			 * of a corrupted pack, and is better than failing outright.
		w->inuse_cnt--;

		}
	struct unpack_entry_stack_ent small_delta_stack[UNPACK_ENTRY_STACK_PREALLOC];
	 * is stupid, as then a REF_DELTA would be smaller to store.
		unsigned i;
	default:
	for (i = 0; i < p->num_bad_objects; i++)
}
		}
}
	goto out;
	int st;
}
		munmap(idx_map, idx_size);
				goto out;
	}


			      (uintmax_t)curpos, p->pack_name);
	{
	const struct packed_git *b = b_;
int bsearch_pack(const struct object_id *oid, const struct packed_git *p, uint32_t *result)
			      struct pack_window **w_curs,
	*sizep = size;
		 * the loop, or if this is the final delta, in the caller when
		free(poi_stack);

		strbuf_release(&path);
		if (idx_size != min_size &&

		 *  - file checksum

				  struct packed_git *packs)
	struct stat st;
		"pack_report: pack_mmap_calls          = %10u\n"
	free(idx_name);
			       void *set_)
			data = ent->data;
		obj_read_lock();

#include "list.h"
		sz_fmt(packed_git_window_size),
	}
	case OBJ_BLOB:
	if (!p->index_data)
	key.p = p;
	data.local = local;
}
	 */
		/*
{

			return;
				&& unuse_one_window(p))
	return ((const struct packed_git *)p)->next;
			       each_file_in_pack_dir_fn fn,
	obj_read_lock();
		 * which can close packs even with in-use windows, and to
		BUG("pack_name does not end in .pack");
 * Do not call this directly as this leaks p->pack_fd on error return;
	if (n >= p->num_objects)
				&& !p->do_not_close)
		error("unknown object type %i at offset %"PRIuMAX" in %s",
		}
	 * Check required to avoid redundant entries when more than one thread
	int st;
	struct pack_window *w, *w_l;
		type = unpack_object_header(p, &w_curs, &curpos, &size);
			if (p->pack_fd == -1 && open_packed_git(p))
	*mru_w = this_mru_w;

static int open_packed_git_1(struct packed_git *p)
int nth_packed_object_id(struct object_id *oid,
				   delta_stack_nr);
void (*report_garbage)(unsigned seen_bits, const char *path);
		if (w->inuse_cnt)
		&& (offset + the_hash_algo->rawsz) <= (win_off + win->len);
			       struct packed_git *pack,
	strbuf_release(&path);
				   p->bad_object_sha1 + the_hash_algo->rawsz * i))
	prepare_packed_git(r);
			lru_p->windows = lru_w->next;
		if (r)
	mark_bad_packed_object(p, oid.hash);
		 * counter is incremented before window reading and checked
			if (win->base == MAP_FAILED)
						      &type);
		if (!base)
	e->p = p;
	}
	 * Local packs tend to contain objects specific to our
	if (p->windows) {
		break;
{
}
		string_list_append(data->garbage, full_name);
	}
	return win_off <= offset

				die("packfile %s cannot be accessed", p->pack_name);
	 * end of the mapped window.  Its actually the hash size
		if (nth_packed_object_id(&oid, p, pos) < 0)
	    ends_with(file_name, ".keep") ||
			pack_max_fds = 1;
	/* look for the multi-pack-index for this object directory */
	struct hashmap_entry ent;
		pack_mapped -= w->len;
}
	struct list_head *lru, *tmp;
			error("bad object header");
	struct prepare_pack_data data;
			return 0;  /* out of bound */
	 * the descriptor is not currently open.
/*

		if (!base_offset) {
			baselen = dot - path + 1;

	}
		*final_size = size;
static size_t delta_base_cached;
							  OI_PACKED;
	if (!hasheq(hash, idx_hash))
#ifdef _SC_OPEN_MAX
	 * often.
	struct delta_base_cache_key key;
#endif
		check_pack_index_ptr(p, index);
static unsigned int pack_open_fds;
		unsigned int max_fds = get_max_fd_limit();
	string_list_sort(list);
{
		 *  - 256 index entries 4 bytes each
	}
		if (!w->offset && w->len == p->pack_size)
		 *  - 4-byte crc entry * nr
		free(p);
static size_t pack_mapped;
	do {
		if (!win) {
				external_base = base;
		index_lookup += 8;
	}
{
{
 */
	}
		return;
	return OPEN_MAX;
			}
				return 0;
			return -1;

 * call open_packed_git() instead.
static void prepare_packed_git(struct repository *r)
		}
	r->objects->packed_git_initialized = 0;
		/*


		*final_type = type;
		/* The base entry _must_ be in the same pack */
		 * get_size_from_delta() to see how this is done.
static struct delta_base_cache_entry *
		if (!base) {

		 */
	if (!index) {
	unsigned char *base_info = use_pack(p, w_curs, *curpos, NULL);

					      struct packed_git *p,

		return error("packfile %s signature is unavailable", p->pack_name);
		unsigned long len, enum object_type *type, unsigned long *sizep)
int packed_object_info(struct repository *r, struct packed_git *p,

}
#include "delta.h"
	oi->whence = in_delta_base_cache(p, obj_offset) ? OI_DBCACHED :
					      enum object_type type,
		oidread(oid, base);
			lru_l->next = lru_w->next;
{
	strbuf_addstr(&buf, pack_name);
				return 0;  /* overflow */
		*oi->contentp = cache_or_unpack_entry(r, p, obj_offset, oi->sizep,
}
		}


		if (!delta_data) {

		if (baselen != -1 &&
				close_pack_fd(p);
		stream.next_in = in;
	memset(p, 0, sizeof(*p));
			return error("pack too large for current definition of off_t in %s", path);
			ALLOC_ARRAY(poi_stack, poi_stack_alloc);
	git_zstream stream;
		if (hasheq(sha1, p->bad_object_sha1 + hashsz * i))
			data = NULL;
	off_t curpos = obj_offset;
	revidx = find_pack_revindex(p, obj_offset);
		}
		return ntohl(*((uint32_t *)(index + (hashsz + 4) * n)));
		sz_fmt(getpagesize()),
		}
	unsigned long size;

	r->objects->approximate_object_count_valid = 0;
{
		int local = (odb == r->objects->odb);

	return 0;
static void write_pack_access_log(struct packed_git *p, off_t obj_offset)
	alloc = st_add3(path_len, strlen(".promisor"), 1);
	dir = opendir(path.buf);

{

	if (!used) {
		close(fd);

	if (!is_pack_valid(p))
		unsigned long max_size = min_size;
{
{
			 const struct object_id *oid,
	xsnprintf(p->pack_name + path_len, alloc - path_len, ".promisor");
#include "tree-walk.h"
 * entry data. The caller takes ownership of the "data" buffer, and
	if (read_result != sizeof(hdr))
		*left = win->len - xsize_t(offset);
	return p;
		return error("packfile %s claims to have %"PRIu32" objects"
		i = delta_stack_nr++;
{
	}
		if (base_offset <= 0 || base_offset >= delta_obj_offset)

	 * and III might run concurrently across multiple threads).
	unsigned int hash;

	memset(&stream, 0, sizeof(stream));
	return oidset_contains(&promisor_objects, oid);

		return NULL;
				type = OBJ_BAD;
		r = for_each_object_in_pack(p, cb, data, flags);
			size = ent->size;
	*type = (c >> 4) & 7;
	 * offset is available from this window, otherwise the offset

			free(external_base);
	     size_t idx_size, struct packed_git *p)
		return nth_packed_object_id(oid, p, revidx->nr);
	ent->type = type;
			 enum object_type *type,
}
			 unsigned long *sizep)
		if (idx_size < min_size || idx_size > max_size)

				   struct packed_git *p,
	if (offset > (p->pack_size - the_hash_algo->rawsz))
	}
	 * to are also promisor objects. (Blobs refer to no objects->)
		i = --delta_stack_nr;
	if (final_size)
	 * We are about to tell the caller where they can locate the
}
	int r = 0;
		}
		 * fallback OPEN_MAX codepath take care of these cases

 * all unreachable objects about to be pruned, in which case they're not really
			return lim.rlim_cur;

	if (stat(sha1_pack_index_name(sha1), &st))
		 *  - hash of the packfile
#include "cache.h"
	if (delta_stack != small_delta_stack)
 * interesting as a measure of repo size in the first place.
	unsigned char *idx_hash;
	} else
	 */
	struct object_directory *odb;
				report_garbage(PACKDIR_FILE_GARBAGE, path);
					      st_add(p->num_bad_objects, 1)));
		    p->pack_name);
{
				   delta_data, delta_size,
		return -1;

	 * Reject this pack if it has windows and the previously selected
			COPY_ARRAY(poi_stack, small_poi_stack, poi_stack_nr);
	return r;
	return 1; /* see the caller ;-) */
		if (w->inuse_cnt) {
{
			goto out;
		struct delta_base_cache_entry *entry =
		delta_stack[i].size = size;
}
	struct packed_git *p;
	const struct delta_base_cache_key *key = vkey;
	if (ptr < start)
	close_commit_graph(o);
}
		uint32_t i;
	if (poi_stack != small_poi_stack)
}

			data = unpack_compressed_entry(p, &w_curs, curpos, size);

	off_t curpos;
		     off_t *curpos,
		return error_errno("error reading from %s", p->pack_name);
 * success.
		report_garbage(PACKDIR_FILE_GARBAGE, full_name);
		if (len <= used || bitsizeof(long) <= shift) {
	return base_offset;
		pack_open_fds++;

		off_t base_offset;
		else
static int retry_bad_packed_offset(struct repository *r,

	p->pack_size = st.st_size;
		in = use_pack(p, w_curs, curpos, &stream.avail_in);
			      (uintmax_t)curpos, p->pack_name);

{
		 * Other worrying sections could be the call to close_pack_fd(),
};
				return;
		pack_open_windows, peak_pack_open_windows,
{
	if (type)
	const unsigned char *index = p->index_data;
}
	strbuf_release(&buf);
				     pos, p->pack_name);
			if (hasheq(oid->hash,
		if (!m && open_pack_index(p))
		uint32_t n = ntohl(index[i]);
{
	return r->objects->packed_git;
		}
	struct pack_window **lru_l)
{

		    p->pack_name);
	return data;
	if (!p->index_data) {
	read_result = read_in_full(p->pack_fd, &hdr, sizeof(hdr));
			if (!dot) {
	do {
	/* versions of zlib can clobber unconsumed portion of outbuf */
		       off_t obj_offset, struct object_info *oi)
			if (hasheq(sha1,
		revidx = find_pack_revindex(p, base_offset);
		if (load_pack_revindex(p))
	p = alloc_packed_git(alloc);


		index += 8 + p->num_objects * (hashsz + 4);
			return error("wrong index v2 file size in %s", path);
	size_t base_len = full_name_len;
	p->num_objects = nr;
		if (!stream.avail_out)
#define POI_STACK_PREALLOC 64
	struct packed_git *p = alloc_packed_git(alloc);
		if (delta_base_cached <= delta_base_cache_limit)
	data.garbage = &garbage;
	const unsigned int hashsz = the_hash_algo->rawsz;
			 unsigned long *size)
{
char *sha1_pack_index_name(const unsigned char *sha1)
		 * Reject this pack if any of its windows are in use,
					      off_t curpos)
			 */
	struct object_id oid;
	 * a "real" type later if the caller is interested.
}
		}
	*accept_windows_inuse = has_windows_inuse;
{
{
	if (p->num_objects != ntohl(hdr.hdr_entries))

		hashmap_init(&delta_base_cache, delta_base_cache_hash_cmp, NULL, 0);
{
	/* No need to check for underflow; .idx files must be at least 8 bytes */
	c = buf[used++];
	return 0;
	 */
 */
}
			      "at offset %"PRIuMAX" from %s",

out:
{
};
void mark_bad_packed_object(struct packed_git *p, const unsigned char *sha1)
	static struct strbuf buf = STRBUF_INIT;
	}
		unsigned char *base = use_pack(p, w_curs, curpos, NULL);

	uint32_t i;
#define SZ_FMT PRIuMAX
int open_pack_index(struct packed_git *p)
#include "sha1-lookup.h"
	index += 4 * 256;
	/* Verify the pack matches its index. */
	 * file size, the pack is known to be valid even if
		return 0;
	    ends_with(file_name, ".pack") ||
	if (seen_bits == (PACKDIR_FILE_PACK|PACKDIR_FILE_IDX))
{
{
	p->pack_fd = -1;
		type = OBJ_BAD;
		 */
	void *base, unsigned long base_size, enum object_type type)
	if (win != *w_cursor) {
int for_each_object_in_pack(struct packed_git *p,

void reprepare_packed_git(struct repository *r)
	if (read_result < 0)
		level1_ofs += 2;


	if (r->objects->packed_git_initialized)
}
}
}
			if (revidx) {
		"pack_report: getpagesize()            = %10" SZ_FMT "\n"
		free(buffer);
		if (idx_size != 4 * 256 + nr * (hashsz + 4) + hashsz + hashsz)
	free(ent->data);
	hashmap_remove(&delta_base_cache, &ent->ent, &ent->key);
}
	struct strbuf path = STRBUF_INIT;
	idx_size = xsize_t(st.st_size);
			break;
		strbuf_setlen(&buf, plen);
	unsigned char *base;
	off_t small_poi_stack[POI_STACK_PREALLOC];

			base_from_cache = 1;
	for (p = the_repository->objects->packed_git; p; p = p->next)
		return 1;
	prepare_packed_git_mru(r);
	rearrange_packed_git(r);
		 *  - hash of the packfile
		unsigned long size;
	struct unpack_entry_stack_ent *delta_stack = small_delta_stack;
	ent->size = base_size;
	return NULL;

		if (base)
	if (p->index_data) {
			pos = i;
	if (p->pack_fd < 0)
		p->index_data = NULL;
		}
}

				   &size);
static int add_promisor_object(const struct object_id *oid,
}
	while (type == OBJ_OFS_DELTA || type == OBJ_REF_DELTA) {




	return ret;

	return type;
		struct hashmap_entry hent;
	int poi_stack_nr = 0, poi_stack_alloc = POI_STACK_PREALLOC;
		 *  - file checksum
		int i;

	if (!r->objects->approximate_object_count_valid) {
	int r = 0;
		if (!hashmap_get(&data->r->objects->pack_map, &hent, pack_name)) {
	off_t base_offset;
		return error("index file %s is too small", path);
{
			error("failed to apply delta");
	 */
		 *
			pack_errors = 1;
	 */
		if (data)
}
{
	} else
	off_t offset;

		sz_fmt(pack_mapped), sz_fmt(peak_pack_mapped));
		return error("packfile %s size changed", p->pack_name);
		 * If the previously selected pack had windows inuse and
int for_each_packed_object(each_packed_object_fn cb, void *data,
				     path, version);

		   enum object_type *final_type, unsigned long *final_size)

		/*
		 * before window disposal.
	/* If the pack has one window completely covering the

	/* Since packfiles end in a hash of their content and it's
			if (p)
		if (!S_ISREG(st.st_mode))
		return !delta_base_cache_key_eq(&a->key, &b->key);
			      off_t curpos,
	if (fd < 0)

		p->windows = w->next;

			return 1;

		close_midx(o->multi_pack_index);
			error("failed to validate delta base reference "
get_delta_base_cache_entry(struct packed_git *p, off_t base_offset)
	p->index_version = version;
{
	if (ret)
	int has_windows_inuse = 0;
}
			return 1;
 */
{
		void *delta_data;
{
	if (!dir) {
}
			list_entry(lru, struct delta_base_cache_entry, lru);
static inline uintmax_t sz_fmt(size_t s) { return s; }
			 * This is costly but should happen only in the presence

#include "commit-graph.h"
		*curpos += the_hash_algo->rawsz;
			revidx = find_pack_revindex(p, obj_offset);
			if (*oi->sizep == 0) {
	 * the index looks sane.
	int delta_stack_nr = 0, delta_stack_alloc = UNPACK_ENTRY_STACK_PREALLOC;
		if (find_pack_entry_one(sha1, p))
	struct packed_git **lru_p,
	 */
{
		stream.next_in = in;
	struct pack_window *w, *this_mru_w;
	} else {
	const unsigned char *ptr = vptr;
#include "promisor-remote.h"

	for (m = r->objects->multi_pack_index; m; m = m->next) {
	unsigned i;
		return 0;
}
		return nth_packed_object_offset(p, result);
	struct strbuf buf = STRBUF_INIT;
	switch (type) {

		curpos = obj_offset = base_offset;
		 * Note: the window section returned by use_pack() must be
				   const struct delta_base_cache_key *b)
		p->pack_keep = 1;
	struct packed_git *p;
		     off_t delta_obj_offset)
		return 0;
			COPY_ARRAY(delta_stack, small_delta_stack,
struct packed_git *find_sha1_pack(const unsigned char *sha1,
static void prepare_packed_git_one(struct repository *r, char *objdir, int local)
		free(delta_data);
	while (c & 0x80) {
int load_idx(const char *path, const unsigned int hashsz, void *idx_map,
		index_lookup += 4;
	 */

		index += 2;  /* skip index header */
char *sha1_pack_name(const unsigned char *sha1)
	}
	return 0;
	nth_packed_object_id(&oid, p, revidx->nr);
			}
		if (fill_midx_entry(r, oid, e, m))

		 * for offsets larger than 2^31.
{

		oidset_insert(set, get_tagged_oid(tag));

const char *pack_basename(struct packed_git *p)
	unsigned long size;
		 * Minimum size:
			break;
		while (c & 128) {
	void *data;
		} else {
	memcpy(p->pack_name, path, path_len);

			      "at offset %"PRIuMAX" from %s",
	/*
	struct object *obj = parse_object(the_repository, oid);

struct multi_pack_index *get_multi_pack_index(struct repository *r)
		if (!w->inuse_cnt) {

unsigned long get_size_from_delta(struct packed_git *p,
				error("failed to read delta base object %s"
	strbuf_reset(buf);
		if (r)
	if (stat(p->pack_name, &st) || !S_ISREG(st.st_mode)) {

			       uint32_t pos,
		pack_open_windows--;
		p->pack_promisor = 1;

{

off_t get_delta_base(struct packed_git *p,
	for (p = r->objects->packed_git; p; p = p->next)
	struct object_directory *odb;
	obj_read_unlock();
		pack_mapped -= lru_w->len;
	if (ptr >= end - 8)
			if (get_delta_base_oid(p, &w_curs, curpos,
	strip_suffix_mem(buf.buf, &buf.len, ".pack");
		     * 32-bit unsigned one will be.
}
	ent->key.p = p;
	hashmap_add(&delta_base_cache, &ent->ent);
	static int promisor_objects_prepared;
#include "tag.h"
	/*

	return e ? container_of(e, struct delta_base_cache_entry, ent) : NULL;


	prepare_alt_odb(r);

			return;
	struct dirent *de;
		 * reprepare_packed_git(). Regarding the former, mmap doc says:
	/* Skip index checking if in multi-pack-index */
	if (!buffer)
out:
	}
		type = unpack_object_header(p, &w_curs, &curpos, &size);
		if (win)
		p->pack_size = st.st_size;

	return r ? r : pack_errors;
unsigned char *use_pack(struct packed_git *p,
	uint32_t result;
			data = NULL;
			close_pack(p);
	return type;
		"pack_report: pack_mapped              = "
	close_pack_fd(p);
	if (p->pack_fd != -1)
			/*
		if (!base_offset)
			     " while index indicates %"PRIu32" objects",
	shift = 4;
 * with no used windows, or the oldest mtime if it has no windows allocated.
	}
struct prepare_pack_data {
				PROT_READ, MAP_PRIVATE,
int has_pack_index(const unsigned char *sha1)
	const struct delta_base_cache_entry *a, *b;
	 * it if the pack file is newer than the previously selected one.
}
{
		}
	unsigned char hash[GIT_MAX_RAWSZ];
		pack_mmap_calls,

static unsigned int peak_pack_open_windows;
	case OBJ_TREE:
	/* use_pack() assured us we have [base_info, base_info + 20)
	/*
	 * still here and can be accessed before supplying that
				     " (try upgrading GIT to a newer version)",

			win->len = (size_t)len;
}
	if (flags & FOR_EACH_OBJECT_PACK_ORDER) {
{
		base_offset = find_pack_entry_one(base_info, p);
	if (base_size)
}
		struct pack_window *w = p->windows;

			 struct pack_window **w_curs,
	xsnprintf(p->pack_name + path_len, alloc - path_len, ".keep");
		data.m = data.m->next;

{
		die("packfile %s cannot be accessed", p->pack_name);
 */
	return buf->buf;
		data = NULL;
	prepare_packed_git(r);
			off_t len;
		if (type != OBJ_OFS_DELTA && type != OBJ_REF_DELTA)

#ifdef OPEN_MAX

		/*
	int fd = git_open(path), ret;
		delta_stack[i].curpos = curpos;
		delta_stack[i].obj_offset = obj_offset;

#include "dir.h"
}
			die("pack '%s' still has open windows to it",
		strbuf_setlen(&path, dirnamelen);
	const struct packed_git *a = a_;
			this_mru_w = w;
 * The LRU pack is the one with the oldest MRU window, preferring packs
		if (!strcmp(path + baselen, "pack"))
	} else {

	struct pack_window *w = *w_cursor;
			return p;
		strbuf_addstr(&path, de->d_name);
		die(_("offset before start of pack index for %s (corrupt index?)"),
			oidclr(oi->delta_base_oid);
		off_t offset,
			continue;

	while (data.m && strcmp(data.m->object_dir, objdir))
				      p->pack_name);
	if (idx_map == NULL)


	for (odb = r->objects->odb; odb; odb = odb->next)


		if (oi->typep)
		    (sizeof(off_t) <= 4))
static void find_lru_pack(struct packed_git *p, struct packed_git **lru_p, struct pack_window **mru_w, int *accept_windows_inuse)
{
	if (!access(p->pack_name, F_OK))
	}
	 */
{
	ret = load_idx(path, hashsz, idx_map, idx_size, p);
		     struct pack_window **w_curs,
	}
		 * Otherwise, we got -1 for one of the two
				install_packed_git(data->r, p);
			const char *tn = type_name(ptot);
	if (pack->pack_fd != -1)
	for (p = get_all_packs(the_repository); p; p = p->next) {
	type = OBJ_BAD;
		while (tree_entry_gently(&desc, &entry))
	 */
	 * one does not.  If this pack does not have windows, reject
	if ((st != Z_STREAM_END) || stream.total_out != size) {

	type = oid_object_info(r, &oid, NULL);


	if (p->pack_fd < 0 || fstat(p->pack_fd, &st))
	return used;
		if (open_pack_index(p))
static unsigned int pack_used_ctr;
/*
			if (pack_open_windows > peak_pack_open_windows)
				  off_t curpos)
			pack_mmap_calls++;
		free(w);
static int check_packed_git_idx(const char *path, struct packed_git *p)
			oidset_insert(set, &parents->item->object.oid);
	    !(data->m && midx_contains_pack(data->m, file_name))) {
			goto out;
				break;
	delta_base_cached += base_size;
	/* PHASE 3: apply deltas in order */
	struct packed_git *p;
				goto out;
		 * We could not apply the delta; warn the user, but keep going.
			break;
	if (path_len < the_hash_algo->hexsz ||
		struct commit_list *parents = commit->parents;
		w_l = w;
	int index_lookup_width;
		if (delta_stack_nr >= delta_stack_alloc
	int pack_errors = 0;

	for (i = 0; i < 256; i++) {
 * Like get_delta_base above, but we return the sha1 instead of the pack
					       type, obj_offset) < 0) {
		/* push object, proceed to base */
	plen = buf.len;
		}
	case OBJ_TAG:
	} else {

		    strncmp(path, list->items[first].string, baselen)) {
int close_pack_fd(struct packed_git *p)
			 */
void close_pack_windows(struct packed_git *p)
	return 0;
		obj_offset = delta_stack[i].obj_offset;
static int in_window(struct pack_window *win, off_t offset)

{

		data = patch_delta(base, base_size,
	((struct packed_git *)p)->next = next;
	size_t alloc;
}
	return 1;
	if (hdr->idx_signature == htonl(PACK_IDX_SIGNATURE)) {
		return OBJ_BAD;
{
				return p;
	return bsearch_hash(oid->hash, (const uint32_t*)index_fanout,
		 * use_pack() will be available throughout git_inflate()'s
	if (!index) {
	 * don't allow an offset too close to the end of the file.
	}
		return error("index file %s is too small", path);
static struct packed_git *alloc_packed_git(int extra)
	case OBJ_REF_DELTA:
}
		base_offset = get_delta_base(p, &w_curs, &curpos, type, obj_offset);
	if (!r->objects->packed_git && !r->objects->multi_pack_index)
	struct stat st;
	struct multi_pack_index *m;



			c = base_info[used++];
		release_delta_base_cache(f);
		 */
		return close_pack_fd(lru_p);
		return error("file %s is far too short to be a packfile", p->pack_name);
		} else
	if (lru_p) {
		report_garbage(seen_bits, list->items[first].string);
				   off_t base_offset, unsigned long *base_size,
			goto unwind;
	struct list_head lru;
		} else {
	if (in_delta_base_cache(p, base_offset))
			continue;
	if (!revidx)
			      off_t delta_obj_offset)
{
			 * the required base anyway from another pack or loose.
	 * and more recent objects tend to get accessed more
	/*
	close_pack_windows(p);
	for (w = this_mru_w = p->windows; w; w = w->next) {
	close(p->pack_fd);
void close_pack(struct packed_git *p)
static int open_packed_git(struct packed_git *p)

		if (!(off & 0x80000000))
	 * loaded!
	void *idx_map;
			break;
			if (in_window(win, offset))
	struct delta_base_cache_entry *ent = xmalloc(sizeof(*ent));
struct delta_base_cache_entry {
struct delta_base_cache_key {
			break;
	int ret;
		return NULL;
			return off;
#include "mergesort.h"
		enum object_type ptot;

	}
	list_del(&ent->lru);
	e->offset = offset;
	}
	*lru_p = p;
	if (p->index_version == 1) {
		if (baselen == -1) {
#include "repository.h"
static int fill_pack_entry(const struct object_id *oid,
	struct packed_git *p;
	unuse_pack(&w_curs);
				continue;
}

		if (!getrlimit(RLIMIT_NOFILE, &lim))
struct unpack_entry_stack_ent {
	unsigned long used = 0;
	int base_from_cache = 0;

			return error("packfile %s index unavailable", p->pack_name);
		if (is_dot_or_dotdot(de->d_name))
}
		struct packed_git *p = list_entry(pos, struct packed_git, mru);
	}
		index = p->index_data;
	while ((de = readdir(dir)) != NULL) {
struct list_head *get_packed_git_mru(struct repository *r)
		delta_data = unpack_compressed_entry(p, &w_curs, curpos, delta_size);
}


		return error("empty data");
		char *pack_name = xstrfmt("%.*s.pack", (int)base_len, full_name);
	if (!oi->contentp && oi->sizep) {
}
		     * 31-bit signed offset won't be enough, neither
	} else if (obj->type == OBJ_COMMIT) {
	if (!offset)
	struct revindex_entry *revidx;

		return OBJ_BAD;
				      " at offset %"PRIuMAX" from %s",
		r = cb(&oid, p, pos, data);
			      struct object_id *oid,
	size_t alloc = st_add(strlen(path), 1);
			 * verified, so do not print any here.
/*
	} else if (version == 2) {
		if (ent) {
	for (p = r->objects->packed_git; p; p = p->next)
 * have to load the revidx to convert the offset back into a sha1).

		odb_clear_loose_cache(odb);
void close_pack_index(struct packed_git *p)
	for (p = the_repository->objects->packed_git; p; p = p->next) {
	const unsigned char *start = p->index_data;
	b = container_of(vb, const struct delta_base_cache_entry, ent);
	idx_name = xstrfmt("%.*s.idx", (int)len, p->pack_name);

	prepare_packed_git(the_repository);
		return;

			error("failed to unpack compressed delta "
	close_pack_index(p);
		if (open_pack_index(p)) {
				goto out;
		data = NULL;
	}
	struct object_info oi = OBJECT_INFO_INIT;
		if (!*oi->contentp)
		return error("file %s is not a GIT packfile", p->pack_name);
	 * size that is assured.)  With our object header encoding
		st = git_inflate(&stream, Z_FINISH);
		struct delta_base_cache_entry *ent;
#include "commit.h"

		list_add_tail(&p->mru, &r->objects->packed_git_mru);
		int i;
		if (p->do_not_close)
}
		 * inuse windows.  Otherwise, record that this pack
		version = ntohl(hdr->idx_version);
{
	return -1;
			return 0;
				  struct packed_git *p)
		off_t base_offset;
		st = git_inflate(&stream, Z_FINISH);
{
	if ((st != Z_STREAM_END) && stream.total_out != sizeof(delta_head)) {
static unsigned int pack_mmap_calls;
			if (!win->offset && win->len == p->pack_size
		 * has windows in use.
		}
			else

static void report_helper(const struct string_list *list,

}
	const char *path = sha1_pack_name(sha1);
	enum object_type type;
		const char *pack_name = pack_basename(p);
			BUG("unpack_entry: left loop at a valid delta");
				len = packed_git_window_size;
	}
	struct prepare_pack_data *data = (struct prepare_pack_data *)_data;
			seen_bits = 0;
	 */
	if (!report_garbage)
	git_inflate_end(&stream);
}
			if (!base_offset || MSB(base_offset, 7))
	p->num_bad_objects++;
		if (type > OBJ_NONE)
	p->pack_fd = -1;
				      oid_to_hex(&base_oid), (uintmax_t)obj_offset,
			return error("wrong index v1 file size in %s", path);
{
	for_each_file_in_pack_dir(objdir, prepare_pack, &data);
{

{
		    hash_to_hex(hash), ext);
static void add_delta_base_cache(struct packed_git *p, off_t base_offset,
	if (!pack_version_ok(hdr.hdr_version))
			break; /* the payload is larger than it should be */
	return get_delta_hdr_size(&data, delta_head+sizeof(delta_head));
			ALLOC_GROW(delta_stack, delta_stack_nr+1, delta_stack_alloc);
	 * is not actually in this window and a different window (which
		hashmap_entry_init(&hent, hash);
static int sort_pack(const void *a_, const void *b_)
	/* invariants:
	} else
	for (i = 0; i < p->num_objects; i++) {
static void *unpack_compressed_entry(struct packed_git *p,
			 * retry the base, otherwise unwind */

	const unsigned char *index_fanout = p->index_data;
	int local;
		die("I am totally screwed");
{
		return error("packfile %s is version %"PRIu32" and not"
off_t find_pack_entry_one(const unsigned char *sha1,
	if (current)

			p = add_packed_git(full_name, full_name_len, data->local);
					       &promisor_objects,
	/* PHASE 1: drill down to the innermost base object */
		index_fanout += 8;
			return 0;
		 * (2) sysconf() said there is no limit.
		 */
char *odb_pack_name(struct strbuf *buf,
	}
static void prepare_packed_git_mru(struct repository *r)
		for (i = 0; i < p->num_bad_objects; i++)

		munmap(lru_w->base, lru_w->len);


		 * in the latter case to let the caller cap it to a

}
	return buffer;
				p->pack_fd, win->offset);
}
}
{

				     const struct hashmap_entry *va,

	uint32_t version, nr, i, *index;
		if (type == OBJ_OFS_DELTA || type == OBJ_REF_DELTA) {
	 * Favor local ones for these reasons.

	if (!access(p->pack_name, F_OK))

	if (read_result != hashsz)
		free(p);
	 * as a range that we can look at.  (Its actually the hash
		free(lru_w);
		*w_cursor = NULL;
		"pack_report: core.packedGitWindowSize = %10" SZ_FMT "\n"
	struct object_id oid;
	if (!delta_base_cache.cmpfn)
		"pack_report: pack_used_ctr            = %10u\n"
		curpos = delta_stack[i].curpos;
		 * reasons:
	}
	 * that is assured.  An OFS_DELTA longer than the hash size
	}
 * offset. This means it is cheaper for REF deltas (we do not have to do
	/* ignore base size */
			/* If getting the base itself fails, we first
		 stream.total_out < sizeof(delta_head));
		return 0;
	hashmap_add(&r->objects->pack_map, &pack->packmap_ent);

		ret = p->pack_name; /* we only have a base */

		    const unsigned char *hash,
	if (!level1_ofs) {
unsigned long unpack_object_header_buffer(const unsigned char *buf,
		delta_size = delta_stack[i].size;
{
			baselen = -1;
	}

		struct multi_pack_index *m;
	r->objects->packed_git_initialized = 1;
	list_for_each_safe(lru, tmp, &delta_base_cache_lru) {
 */
	 * variant of the project than remote ones.  In addition,
		die(_("offset before end of packfile (broken .idx?)"));
};
	return NULL;
	 * insane, so we know won't exceed what we have been given.
		win->inuse_cnt++;
	case OBJ_COMMIT:
}
	list_add_tail(&ent->lru, &delta_base_cache_lru);
	prepare_packed_git(r);
			seen_bits |= 1;
}
	if (obj->type == OBJ_TREE) {
}
		in = use_pack(p, w_curs, curpos, &stream.avail_in);
	unsigned long size, c;
			   struct pack_entry *e,
			return error("non-monotonic index %s", path);
			type = OBJ_BAD;
	/* We must promise at least one full hash after the

		"pack_report: core.packedGitLimit      = %10" SZ_FMT "\n",
{
		unsigned long delta_size, base_size = size;
}
		index_lookup_width = hashsz + 4;
	return win->base + offset;
	const char *ret = strrchr(p->pack_name, '/');
	struct pack_entry e;
	struct packed_git *p;
			/* bail to phase 2, in hopes of recovery */

}
 * the final object lookup), but more expensive for OFS deltas (we
		return;
	} else if (obj->type == OBJ_TAG) {
			" supported (try upgrading GIT to a newer version)",
			return;
#endif
					       oi->delta_base_oid,
	git_inflate_init(&stream);
	struct pack_window **lru_w,
	}
	}
	p->index_data = idx_map;
	static struct strbuf buf = STRBUF_INIT;

				data = NULL;
		     m; m = m->next) {
	xsnprintf(p->pack_name + path_len, alloc - path_len, ".pack");
	return ret;
			p->windows = win;
 * Remove the entry from the cache, but do _not_ free the associated

		}
}
{
		unsigned int hash = strhash(pack_name);
	const unsigned char *index = p->index_data;
}
		else
		curpos += stream.next_in - in;

		 * inuse windows to one that has inuse windows.


static unsigned int pack_open_windows;
	p->mtime = st.st_mtime;
	trace_printf_key(&pack_access, "%s %"PRIuMAX"\n",
		return 1;
		if (nr)


		count = 0;

	close_pack_fd(p);

	const unsigned char *index = p->index_data;
		}
		sz_fmt(packed_git_limit));
	if (hdr.hdr_signature != htonl(PACK_SIGNATURE))
		scan_windows(current, &lru_p, &lru_w, &lru_l);
		     */
			}
				error("bad packed object CRC for %s",
{
			if (*accept_windows_inuse)
{
 * ignores loose objects completely. If you have a lot of them, then either
				*lru_p = p;
static unsigned int pack_max_fds;

	hashcpy(p->bad_object_sha1 + hashsz * p->num_bad_objects, sha1);
	if (o->multi_pack_index) {



	return r->objects->packed_git;

{
#else
unwind:
	static struct trace_key pack_access = TRACE_KEY_INIT(PACK_ACCESS);
		if (!p->multi_pack_index && fill_pack_entry(oid, e, p)) {

		if (oi->type_name) {
		struct commit *commit = (struct commit *) obj;
	hashmap_entry_init(&entry, pack_entry_hash(p, base_offset));
#endif
		} else {
static void prepare_packed_git(struct repository *r);
 * consistency checks, then record its information to p.  Return 0 on

	return !open_packed_git(p);
			 p->pack_name, (uintmax_t)obj_offset);
				     const void *vkey)
		}
		if (!access(buf.buf, F_OK)) {
	data = delta_head;
}
	memcpy(p->pack_name, path, alloc); /* includes NUL */
			if (pack_mapped > peak_pack_mapped)
			size_t window_align = packed_git_window_size / 2;
static enum object_type packed_to_object_type(struct repository *r,
			}

		if (poi_stack_nr >= poi_stack_alloc && poi_stack == small_poi_stack) {
{
static void scan_windows(struct packed_git *p,
		 */
			ALLOC_GROW(poi_stack, poi_stack_nr+1, poi_stack_alloc);

}
	prepare_packed_git(r);
	st = a->pack_local - b->pack_local;
	return ntohl(level1_ofs[value]);

			count += p->num_objects;
	unsigned long size;
	if (key)
			   struct packed_git *p)

	oi.typep = type;
		struct multi_pack_index *m;
		level1_ofs = p->index_data;
	return type;
	return -1;
				   enum object_type *type)
					p->pack_size - hashsz);
			return error("packfile %s not a regular file", p->pack_name);
		break;
	memset(&stream, 0, sizeof(stream));
			win = xcalloc(1, sizeof(*win));
	return odb_pack_name(&buf, sha1, "idx");
				continue;
		 * ensure no other thread will modify the window in the
		if (ptot < 0) {
			list_move(&p->mru, &r->objects->packed_git_mru);
			p->pack_name, ntohl(hdr.hdr_version));
	pack->next = r->objects->packed_git;
	 * Younger packs tend to contain more recent objects,
	off_t base_offset;
	 * remote ones could be on a network mounted filesystem.
			/*
			list_entry(lru, struct delta_base_cache_entry, lru);
	return r->objects->multi_pack_index;
int has_object_pack(const struct object_id *oid)
{

	/* An already open pack is known to be valid. */
	hash += (hash >> 8) + (hash >> 16);
int unpack_object_header(struct packed_git *p,
	if (!strip_suffix(p->pack_name, ".pack", &len))
			off_t base_offset = get_delta_base(p, &w_curs, &tmp_pos,
		hashclr(p->hash);
	if (p->num_bad_objects) {
	struct oidset *set = set_;
		prepare_packed_git(r);
		return -1;
	ssize_t read_result;
	oidset_insert(set, oid);
		/* Push the object we're going to leave behind */

		return NULL;
			for_each_packed_object(add_promisor_object,
				    struct pack_window **w_curs,
	if (oid_object_info_extended(r, oid, &oi, 0) < 0)
		*w_cursor = win;
}
		for (p = r->objects->packed_git; p; p = p->next) {
		return 1;


	if (bsearch_pack(&oid, p, &result))
			win->inuse_cnt--;
	char *idx_name;
	switch (type) {
			BUG("want to close pack marked 'do-not-close'");
	idx_map = xmmap(NULL, idx_size, PROT_READ, MAP_PRIVATE, fd, 0);

	} while ((st == Z_OK || st == Z_BUF_ERROR) &&

	}
	else
{
				nth_packed_object_id(&oid, p, revidx->nr);
}
	idx_hash = ((unsigned char *)p->index_data) + p->index_size - hashsz * 2;
	/* Examine the initial part of the delta to figure out
	size_t dirnamelen;

	return a->p == b->p && a->base_offset == b->base_offset;
				     const struct hashmap_entry *vb,

	if (!report_garbage)
			continue;
	}

			continue;
	index = idx_map;

		return -1;
			pos = p->revindex[i].nr;
	if (st)
					      off_t obj_offset,
	/*
	closedir(dir);
#include "midx.h"
		 * value that is not so selfish, but letting the
	strbuf_addch(&path, '/');

	if (!open_packed_git_1(p))
out:
	offset -= win->offset;
			      enum object_type type,
	case OBJ_BAD:
		return;
	}
	if (!strcmp(file_name, "multi-pack-index"))
	oi.sizep = size;
			return -1;
		/*
	const unsigned int hashsz = the_hash_algo->rawsz;
	prepare_packed_git(r);
		strbuf_addstr(&buf, exts[i]);
	return ret;
			struct revindex_entry *revidx = find_pack_revindex(p, obj_offset);
	 * We always get the representation type, but only convert it to
	return 0;
	struct pack_idx_header *hdr = idx_map;
{

			if (!*lru_w || w->last_used < (*lru_w)->last_used) {
		/* Save 3 for stdin/stdout/stderr, 22 for work */
			 const char *file_name, void *_data)
		struct packed_git *p;
	int i, baselen = -1, first = 0, seen_bits = 0;
	struct multi_pack_index *m;
int do_check_packed_object_crc;
		obj_read_unlock();
		 * meantime, we rely on the packed_window.inuse_cnt. This
static int in_delta_base_cache(struct packed_git *p, off_t base_offset)
	while (delta_stack_nr) {
	string_list_clear(data.garbage, 0);
		 * inuse, skip this check since we prefer a pack with no
	case OBJ_OFS_DELTA:
	/* ok, it looks sane as far as we can check without
	struct repository *r;

		    !p->pack_promisor)

		*base_size = ent->size;
#include "streaming.h"
	return p;
	const unsigned int hashsz = the_hash_algo->rawsz;
		return error_errno("error reading from %s", p->pack_name);
	if (strip_suffix_mem(full_name, &base_len, ".idx") &&


{
	if (left)
				      oid_to_hex(&oid));
	 * Select this pack.
void pack_report(void)
	if (type == OBJ_REF_DELTA) {
struct packed_git *add_packed_git(const char *path, size_t path_len, int local)
	return xmemdupz(ent->data, ent->size);
static size_t peak_pack_mapped;
		; /* nothing */
			goto unwind;
	size_t plen;
		return -1;
	struct delta_base_cache_key key;
			off_t tmp_pos = curpos;
	}
		struct name_entry entry;
			if (open_pack_index(p))
	if (!ent)
int is_promisor_object(const struct object_id *oid)
	} else {

		return;


		/* If parsing the base offset fails, just unwind */

				    path.buf);
}
unsigned long repo_approximate_object_count(struct repository *r)
			    each_packed_object_fn cb, void *data,
					      struct pack_window **w_curs,
	/*


	}

	struct stat st;
		find_lru_pack(p, &lru_p, &mru_w, &accept_windows_inuse);
		curpos = obj_offset = base_offset;
		 *  - 256 index entries 4 bytes each
	}
}
	 */
		struct object_id oid;
		fn(path.buf, path.len, de->d_name, data);
	 * the object header and delta base parsing routines below.
{
		}
		scan_windows(p, &lru_p, &lru_w, &lru_l);
{
		base_offset = get_delta_base(p, w_curs, &curpos, type, obj_offset);
		oidread(oid, index + hashsz * n);
	 */
		}
	}
		return !delta_base_cache_key_eq(&a->key, key);
		if (lru_l)
		struct tag *tag = (struct tag *) obj;
		/*

	struct packed_git *p, *lru_p = NULL;

			}
void check_pack_index_ptr(const struct packed_git *p, const void *vptr)

			detach_delta_base_cache_entry(ent);
	p->index_size = idx_size;
void close_object_store(struct raw_object_store *o)
	struct string_list garbage = STRING_LIST_INIT_DUP;
		    this_mru_w->last_used > (*mru_w)->last_used)
{
		return;
		if (25 < max_fds)
	/* PHASE 2: handle the base */
}
	struct packed_git *p = xmalloc(st_add(sizeof(*p), extra));
{
		base_offset = delta_obj_offset - base_offset;
			if (tn)
				mark_bad_packed_object(p, oid.hash);
	return odb_pack_name(&buf, sha1, "pack");
	    ends_with(file_name, ".bitmap") ||
	return 1;
	unsigned char *buffer, *in;
			   enum for_each_object_flags flags)
		struct tree_desc desc;
	static const char *exts[] = {".pack", ".idx", ".keep", ".bitmap", ".promisor"};
			type = ent->type;
{

		return -1;
	case OBJ_TAG:
					       FOR_EACH_OBJECT_PROMISOR_ONLY);

	struct pack_window *w_curs = NULL;
			return -1;
	 * as a range that we can look at without walking off the
	struct packed_git *p;
	}
		die(_("offset beyond end of pack index for %s (truncated index?)"),
	 */
		 *  - object ID entry * nr
uint32_t get_pack_fanout(struct packed_git *p, uint32_t value)
	} while (st == Z_OK || st == Z_BUF_ERROR);

void unuse_pack(struct pack_window **w_cursor)
	return 0;
		 *

		    /*
void for_each_file_in_pack_dir(const char *objdir,
				peak_pack_mapped = pack_mapped;
	 * Make sure a corresponding .pack file exists and that
		void *base = data;
	p->pack_fd = git_open(p->pack_name);
		return 0;
	unsigned long size;
		error("unknown object type %i at offset %"PRIuMAX" in %s",
}
		return 0;
{
{
			*oi->sizep = size;
static void detach_delta_base_cache_entry(struct delta_base_cache_entry *ent)
		if (open_pack_index(p))
	get_delta_hdr_size(&data, delta_head+sizeof(delta_head));

	}
	struct pack_window *w_curs = NULL;
			if (len > packed_git_window_size)
		return 0;

			size = used = 0;
	int i;
static unsigned int pack_entry_hash(struct packed_git *p, off_t base_offset)
const struct packed_git *has_packed_and_bad(struct repository *r,
	unsigned char delta_head[20], *in;
		 * We _could_ clear errno before calling sysconf() to
		*curpos += used;
{
		}
		strbuf_addstr(&buf, ".keep");
	static struct oidset promisor_objects;
			struct revindex_entry *revidx;
	default:
		struct tree *tree = (struct tree *)obj;
	while (poi_stack_nr) {
#include "tree.h"
	struct multi_pack_index *m;
			oidset_insert(set, &entry.oid);
		struct pack_window *w = p->windows;
		for (; parents; parents = parents->next)

{
}
		c = buf[used++];
	struct pack_window *lru_w = NULL, *lru_l = NULL;
	}
			return error("unable to get sha1 of object %u in %s",
			}
	if (w) {
	}
	for (p = o->packed_git; p; p = p->next)
			    p->pack_name);
	write_pack_access_log(p, obj_offset);
	 * pointless to ask for an offset into the middle of that
	}
				   off_t obj_offset)

		set_next_packed_git, sort_pack);
			if (type > OBJ_NONE)
			pack_open_windows++;
		 * Note: we must ensure the window section returned by

	p->bad_object_sha1 = xrealloc(p->bad_object_sha1,
		struct revindex_entry *revidx;

	const unsigned hashsz = the_hash_algo->rawsz;

		    const char *ext)
{
static inline void release_delta_base_cache(struct delta_base_cache_entry *ent)
	off_t obj_offset;
	if (*lru_p && !*mru_w && (p->windows || p->mtime > (*lru_p)->mtime))
			const char *dot = strrchr(path, '.');

		unsigned long min_size = 8 + 4*256 + nr*(hashsz + 4 + 4) + hashsz + hashsz;
	stream.next_out = buffer;
							   type, obj_offset);
			if (!base_offset) {
				goto out;
/*
		free(pack_name);
		return 1;
				    off_t curpos,
		break;
		return;
		return 0;
	/* If we created the struct before we had the pack we lack size. */
		 * variable sized table containing 8-byte entries
		     * make sure we can deal with large pack offsets.
				type = OBJ_BAD;
			break;
					    const unsigned char *sha1)
		unsigned char c = base_info[used++];

		if (errno != ENOENT)

	strbuf_addstr(&path, "/pack");
int find_pack_entry(struct repository *r, const struct object_id *oid, struct pack_entry *e)
			report_helper(list, seen_bits, first, i);
	}
}
	if (p->index_version == 1) {
	if (!delta_base_cache.cmpfn)
{
	return p;

		return 0;
	else if (a->mtime == b->mtime)
	size_t idx_size;
	if (!win || !in_window(win, offset)) {
	if (type == OBJ_OFS_DELTA) {
			break;
		*oi->disk_sizep = revidx[1].offset - obj_offset;

	} else
		unsigned used = 0;
	off_t *poi_stack = small_poi_stack;
/*
		}
		close(fd);
				break;
		return error("packfile %s does not match index", p->pack_name);
	 * actually mapping the pack file.
}
		 * Reject this pack if it has windows that have been
	}
	report_helper(list, seen_bits, first, list->nr);
{

		 * we have not encountered a window in this pack that is
		 * the object.
void install_packed_git(struct repository *r, struct packed_git *pack)
			type = OBJ_BAD;

	detach_delta_base_cache_entry(ent);
			win->offset = (offset / window_align) * window_align;
	if (p->index_version == 1) {
		if (has_promisor_remote()) {
		poi_stack[poi_stack_nr++] = obj_offset;
{
			 off_t *curpos,
			"%10" SZ_FMT " / %10" SZ_FMT "\n",

		 * unlocked execution. Please refer to the comment at
		if (*mru_w && *accept_windows_inuse == has_windows_inuse &&
		 * for the latter, it won't re-open already available packs.
		 */
		for (win = p->windows; win; win = win->next) {
		prepare_multi_pack_index_one(r, odb->path, local);
static void *get_next_packed_git(const void *p)
	}
	if (idx_size < 4 * 256 + hashsz + hashsz) {
}
				    unsigned long size)
		if (open_pack_index(p))
	}
	struct delta_base_cache_entry *ent;

	offset = find_pack_entry_one(oid->hash, p);

				mark_bad_packed_object(p, base_oid.hash);
	if (!pack_max_fds) {
		struct revindex_entry *revidx = find_pack_revindex(p, obj_offset);
	hashcpy(p->hash, sha1);
static void set_next_packed_git(void *p, void *next)


			return 1;

		off_t base_offset = get_delta_base(p, w_curs, &curpos,
	return 0;
	unsigned long left;
	if (fstat(fd, &st)) {
		o->multi_pack_index = NULL;
			error_errno("unable to open object pack directory: %s",
		off = ntohl(*((uint32_t *)(index + 4 * n)));
	return r->objects->approximate_object_count;

		return NULL;
	if (!p->pack_size) {
			    enum for_each_object_flags flags)


		*type = ent->type;
		      type, (uintmax_t)obj_offset, p->pack_name);
			max_size += (nr - 1)*8;
			poi_stack_alloc = alloc_nr(poi_stack_nr);
		pack_open_windows--;
static void rearrange_packed_git(struct repository *r)
					  p->pack_name);
	list_for_each_safe(lru, tmp, &delta_base_cache_lru) {
	else
		index += p->num_objects * 4 + (off & 0x7fffffff) * 8;
		 * And after the 4-byte offset table might be a
	nr = 0;
			 struct packed_git *p,
		else if (!strcmp(path + baselen, "idx"))

	int accept_windows_inuse = 1;
	 * ".promisor" is long enough to hold any suffix we're adding (and
				  struct pack_window **w_curs,
		error("delta data unpack-initial failed");

#include "pack.h"
		}
{
	for (odb = r->objects->odb; odb; odb = odb->next) {
		ptot = packed_to_object_type(r, p, obj_offset,

}
		else
off_t nth_packed_object_offset(const struct packed_git *p, uint32_t n)
			pack_max_fds = max_fds - 25;
	/* Verify we recognize this pack file format. */
		nr = n;
static void prepare_pack(const char *full_name, size_t full_name_len,
				*lru_w = w;
		for (m = get_multi_pack_index(r); m; m = m->next)
	/*
	for (;;) {
			     p->pack_name, ntohl(hdr.hdr_entries),

	read_result = pread_in_full(p->pack_fd, hash, hashsz,
				has_windows_inuse = 1;
		uint32_t off;

			while (packed_git_limit < pack_mapped
#include "object.h"
		/*
	} else if (type == OBJ_OFS_DELTA) {
		r->objects->packed_git, get_next_packed_git,
	}
			return -1;
	strbuf_addf(buf, "%s/pack/pack-%s.%s", get_object_directory(),
}
			 * Error messages are given when packs are

	unsigned shift;
static void *cache_or_unpack_entry(struct repository *r, struct packed_git *p,
		pack_used_ctr,
				die_errno("packfile %s cannot be mapped",

}
	fprintf(stderr,
		if (type <= OBJ_NONE) {
		type = unpack_object_header(p, w_curs, &curpos, &size);

		BUG("bsearch_pack called without a valid pack-index");
		if (init_tree_desc_gently(&desc, tree->buffer, tree->size))

	if (version == 1) {
				peak_pack_open_windows = pack_open_windows;
	/*
void unlink_pack_path(const char *pack_name, int force_delete)


static struct hashmap delta_base_cache;
			return 0;
			return error("index file %s is version %"PRIu32

		if (p->pack_fd == -1)
	return 0;

	hash = (unsigned int)(intptr_t)p + (unsigned int)base_offset;
				     " and is not supported by this binary"
	/* Read the result size */
	r->objects->packed_git = pack;


	if (read_result < 0)
		if (!base_from_cache)
			    index_lookup, index_lookup_width, result);

		return NULL;
static LIST_HEAD(delta_base_cache_lru);
		obj_read_unlock();
			continue;
 * should copy out any fields it wants before detaching.
}
	int type;
		}
		promisor_objects_prepared = 1;
	dirnamelen = path.len;
	{
		unlink(buf.buf);
	struct packed_git *p;
{
	pack_open_fds++;
			len = p->pack_size - win->offset;
		     enum object_type type,
	}
{


		 *
		type = OBJ_BAD;
		if (do_check_packed_object_crc && p->index_version > 1) {
		obj_offset = poi_stack[--poi_stack_nr];
		if (version < 2 || version > 2)
		const char *path = list->items[i].string;
		return NULL;
		ret = ret + 1; /* skip past slash */
	buffer[size] = '\0';


static int unuse_one_window(struct packed_git *current)
		for (i = 0; i < m->num_packs; i++)
{
	}
		oidread(oid, index + (hashsz + 4) * n + 4);
	if (p->index_data)
			seen_bits |= 2;
	const unsigned int hashsz = the_hash_algo->rawsz;

		if (type == OBJ_OFS_DELTA || type == OBJ_REF_DELTA) {
static void report_pack_garbage(struct string_list *list)
	a = container_of(va, const struct delta_base_cache_entry, ent);

		for (i = 0; i < p->num_bad_objects; i++)


	ret = check_packed_git_idx(idx_name, p);
	struct stat st;
			type = retry_bad_packed_offset(r, p, base_offset);
	return 1;
static int get_delta_base_oid(struct packed_git *p,
			first = i;
	free(ent);
					     type, &w_curs, curpos);
		return 0;
		if (!data)
		return;
	struct pack_window *win = *w_cursor;
		version = 1;
void *unpack_entry(struct repository *r, struct packed_git *p, off_t obj_offset,
	void *data = NULL;
	 * hash, and the in_window function above wouldn't match
		curpos += stream.next_in - in;
	DIR *dir;
	git_inflate_end(&stream);

			*oi->sizep = get_size_from_delta(p, &w_curs, tmp_pos);
	else
		 * (1) sysconf() did not understand _SC_OPEN_MAX
	e = hashmap_get(&delta_base_cache, &entry, &key);
	if (idx_size < 4 * 256 + hashsz + hashsz)
	unsigned i;
		 * available throughout git_inflate()'s unlocked execution. To
		if (flags & FOR_EACH_OBJECT_PACK_ORDER)
				struct object_id oid;
/*
	} else if (p->pack_size != st.st_size)

}
	enum object_type type;
		 *  - 4-byte offset entry * nr
		release_delta_base_cache(entry);
	 * the result size.
		}

	base = use_pack(p, w_curs, *curpos, &left);
	if (final_type)
