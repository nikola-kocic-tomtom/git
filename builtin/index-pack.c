}
	if (from_stdin && !startup_info->have_repository)
static void final(const char *final_pack_name, const char *curr_pack_name,

			status = git_inflate(&stream, 0);
	header[n++] = c;
			} else if (!strcmp(arg, "--report-end-of-input")) {
	strbuf_addstr(buf, suffix);
static int is_delta_type(enum object_type type)

	int n = 0;

	 * NEEDSWORK: extract this bit from free_pack_by_name() in
	result->obj = delta_obj;
		free(data->buf);
static pthread_mutex_t counter_mutex;
	if (oid)
static struct object_entry *objects;
		flush();
			     chain_histogram[i]),
 * The second walker is this function, which goes from current node up
			output_fd = open(pack_name, O_CREAT|O_EXCL|O_RDWR, 0600);
	int status;
 */


			die(_("SHA1 COLLISION FOUND WITH %s !"),
		resolve_base(obj);
	struct object_id oid;
		if (!compare_and_swap_type(&child->real_type, OBJ_REF_DELTA,
	}
	objects[i].idx.offset = consumed_bytes;

		display_progress(progress, nr_resolved_deltas);
static const char *derive_filename(const char *pack_name, const char *suffix,
}
		printf_ln(Q_("chain length = %d: %lu object",
	pthread_mutex_destroy(&work_mutex);
	inbuf = xmalloc((len < 64*1024) ? (int)len : 64*1024);
	use(the_hash_algo->rawsz);
static void flush(void)
			if (!base_offset || MSB(base_offset, 7))
		n = xpread(get_thread_data()->pack_fd, inbuf, n, from);
		use(input_len - stream.avail_in);
	void *data;
			if (do_fsck_object &&
				   enum object_type type2)

		die(_("pack version %"PRIu32" unsupported"),
		    min);
			*report = suffix;
	struct ref_delta_entry *a = *(struct ref_delta_entry **)_a;
		stream.avail_out = sizeof(outbuf);
	size = (c & 15);
					   base->obj->real_type))
#define type_cas_lock()		lock_mutex(&type_cas_mutex)
		usage(index_pack_usage);
	 */
		       "This should only be reached when all threads are gone");
	/* The address of the 8-byte offset table */
				      struct pack_idx_option *opts)
		}
		oid = NULL;
static const char *open_pack_file(const char *pack_name)
static void sha1_object(const void *data, struct object_entry *obj_entry,
	strbuf_release(&name_buf);
	hash_object_file(the_hash_algo, result->data, result->size,
	return pack_name;
	flush();


	stop_progress(&progress);
	do {
	unsigned i, max, foreign_nr = 0;
			raw = get_data_from_pack(obj);
}
	base->ref_last = -1;
	}
	fd = odb_pack_keep(filename);

{
			sha1_object(data, NULL, obj->size, obj->type,
				char *end;
}
			final_pack_name = odb_pack_name(&pack_name, hash, "pack");

		the_hash_algo->update_fn(&input_ctx, input_buffer, input_offset);
		oid_array_clear(&to_fetch);
	const char *promisor_msg = NULL;
#include "fsck.h"
{
		if (!has_data)
static unsigned check_object(struct object *obj)
		unsigned long size;
		struct object_entry *obj = &objects[i];
			die_errno(_("cannot pread pack file"));
	unsigned long size;
	char buf[1024];
	}
	}


	 * REF_DELTA bases need to be fetched.
	if (!hasheq(fill(the_hash_algo->rawsz), hash))
	if (!obj)
			break;
	 * trunc deltas first, allowing for other deltas to resolve without
	struct ofs_delta_entry *ofs_delta = ofs_deltas;
	parse_pack_header();
}
			c = c->base;

{
	if (threads_active)
static int git_index_pack_config(const char *k, const char *v, void *cb)
		 * octets.  But idx2[off * 2] is Zero!!!
	return foreign_nr;

	struct strbuf index_name_buf = STRBUF_INIT;
	if (min > sizeof(input_buffer))
				}
				   struct strbuf *buf)
				    enum object_type type)
		if (!cmp)
	if (pack_name)
	       offset1 > offset2 ?  1 :
		if (report)
			continue;
			warning(_("no threads support, ignoring %s"), k);
		 * Let's just mimic git-unpack-objects here and write
		if (!cmp)
		++last;
	if (!pack_name && !from_stdin)
				nr_objects);
		if (err)
{
						   to_fetch.oid, to_fetch.nr);

 * "want"; if so, swap in "set" and return true. Otherwise, leave it untouched
 * - find locations of all objects;
		memmove(input_buffer, input_buffer + input_offset, input_len);
		struct oid_array to_fetch = OID_ARRAY_INIT;
	} while (input_len < min);
		free((void *) curr_index);
	if (check_self_contained_and_connected && foreign_nr)
		if (base->ref_last == -1 && base->ofs_last == -1) {
			ofs_delta->obj_no = i;

			die_errno(_("cannot write %s file '%s'"),
	return -first-1;
		pthread_mutex_lock(mutex);
		base_obj->data = read_object_file(&d->oid, &type,
		f = hashfd(output_fd, curr_pack);
}
		return;
			return NULL;
	}
		return 1;
	uint32_t b = *((uint32_t *)b_);
		if (nr_threads < 0)
#define counter_lock()		lock_mutex(&counter_mutex)
#include "packfile.h"

	/* The address of the 4-byte offset table */
		}
	while (first > 0 && ofs_deltas[first - 1].offset == offset)
			    oid_to_hex(&data->entry->idx.oid));
	case OBJ_OFS_DELTA:
	 * as possible by picking the
 * This function is part of find_unresolved_deltas(). There are two
	 * resolving deltas in the same order as their position in the pack.
	/*
		/*
		if (cmp < 0) {
	}
	default:
};
		obj->real_type = obj->type;
/*
static void conclude_pack(int fix_thin_pack, const char *curr_pack, unsigned char *pack_hash)
	int status;
			       const unsigned char *sha1, void *buf,
}
	data = unpack_entry_data(obj->idx.offset, obj->size, obj->type, oid);
			obj = c->obj;
static int show_stat;
	objects = xcalloc(st_add(nr_objects, 1), sizeof(struct object_entry));
	for (i = 0; i < nr_objects; i++)
		bad_object(delta_obj->idx.offset, _("failed to apply delta"));
			stream.next_out = buf;
	} else {

			nr_threads = 3;
		nr_delays--;
			prune_base_data(c);
		}
		    pack_name);
				hdr = (struct pack_header *)input_buffer;

			prev_base = base->base;
	struct compare_data data;
					      &obj->idx.oid);
						      NULL,
}
			} while (status == Z_OK && stream.avail_in);
{
	void *buf;
}
		nr_threads = online_cpus();

	 * accesses the repo to do hash collision checks and to check which
{
				struct pack_header *hdr;
			       "premature end of pack file, %"PRIuMAX" bytes missing",
			die(_("--verify with no packfile name given"));
			bad_object(obj->idx.offset, _("delta base offset is out of bound"));
						  &base_obj->size);
	for (i = 0; i < nr_threads; i++) {
		stream.next_out = outbuf;
			    oid_to_hex(&base->obj->idx.oid));
	obj[0].idx.crc32 = crc32_end(f);
	off_t offset;
		die(_("--stdin requires a git repository"));
	git_zstream stream;
#include "object-store.h"
	int first = 0, last = nr_ref_deltas;
static int find_ofs_delta(const off_t offset, enum object_type type)

	if (collision_test_needed && !data) {
{
			die_errno(_("error while closing pack file"));
		}
			if (!strcmp(arg, "--stdin")) {
static pthread_mutex_t work_mutex;
	case OBJ_REF_DELTA:
		has_data = read_object_file(oid, &has_type, &has_size);
	pthread_key_delete(key);
		if (base->ref_first == base->ref_last && base->ofs_last == -1)
 * memory for deflated nodes is limited by delta_base_cache_limit, so
		       nr_unresolved * sizeof(*objects));
	threads_active = 0;
		write_in_full(2, "\0", 1);
			     baseobjects),
 * - calculate SHA1 of all non-delta objects;
		ssize_t n = (len < 64*1024) ? (ssize_t)len : 64*1024;
	char hdr[32];

			    oid_to_hex(&obj->oid),
	free(delta_data);
static int compare_ref_delta_entry(const void *a, const void *b)
		the_hash_algo->update_fn(&c, hdr, hdrlen);
	return (a < b) ? -1 : (a != b);
 *
		the_hash_algo->init_fn(&c);
static int delta_pos_compare(const void *_a, const void *_b)

		find_ofs_delta_children(base->obj->idx.offset,
		struct ref_delta_entry *d = sorted_by_pos[i];


	}
		}
		       "pack has %d unresolved deltas",
				show_stat = 1;
static void show_pack_info(int stat_only)
	int fd;
}
static void resolve_base(struct object_entry *obj)
static struct ofs_delta_entry *ofs_deltas;
	sha1_object(result->data, NULL, result->size, delta_obj->real_type,
		    &delta_obj->idx.oid);
	opts->version = p->index_version;
			die(_("object %s: expected type %s, found %s"),
		p = fill(1);
	base_data = get_base_data(base);
	curr_pack = open_pack_file(pack_name);
			base_offset = (base_offset << 7) + (c & 127);
			    fsck_object(obj, buf, size, &fsck_options))
	type_cas_unlock();
static int nr_threads;
		return 0;
		if (errno != EEXIST)
static pthread_mutex_t read_mutex;
	const char *index_name = NULL, *pack_name = NULL;
{

		}
}
					  nr_ref_deltas + nr_ofs_deltas);
	 * before deltas depending on them, a good heuristic is to start
		obj->flags |= FLAG_CHECKED;

	 */
 * needs to apply delta.

		check_pack_index_ptr(p, &idx2[off * 2]);

}

struct base_data {
				&c->size);
	}
			/* large blobs, check later */
	data.st = open_istream(the_repository, &entry->idx.oid, &type, &size,
	for (i = 0; i < nr_threads; i++)

			  i + 1,
	input_offset += bytes;
					base_obj->data, base_obj->size, type);
		struct base_data *result = alloc_base_data();


	} else if (from_stdin)
						"pack/tmp_pack_XXXXXX");
	if (c->data) {
			prune_base_data(c);

				opts.version = strtoul(arg + 16, &c, 10);
	struct packed_git *p = add_packed_git(pack_name, strlen(pack_name), 1);
	unsigned char *p;
{
	for (i = 0; i < nr_objects; i++) {

	if (status != Z_STREAM_END)
	return buf->buf;
			return next;
		struct object_entry *obj = &objects[i];
	resolve_deltas();
int cmd_index_pack(int argc, const char **argv, const char *prefix)

	/* Header consistency check */
	} while (len && status == Z_OK && !stream.avail_in);
{
static inline void lock_mutex(pthread_mutex_t *mutex)
static NORETURN void bad_object(off_t offset, const char *format, ...)
			       (unsigned int)len),
			nr_delays++;
		input_offset = 0;
		return;
	} else {
		if (len == 0)
		+ hashwords * p->num_objects /* object ID table */

		       is_delta_type(objects[nr_dispatched].type))
	}
		data->buf_size = size;
			c->size = obj->size;
		c = *p;
	consumed_bytes += bytes;
	/*
		if (!base_obj->data)
		if (buf == fixed_buf) {
			obj->flags |= FLAG_CHECKED;
		unsigned char read_hash[GIT_MAX_RAWSZ], tail_hash[GIT_MAX_RAWSZ];
/* The content of each linked object must have been checked
	unsigned long size;
/* We always read in 4kB chunks. */
 * return the pointer to the buffer.
	return obj;
			chain_histogram[obj_stat[i].delta_depth - 1]++;
static int write_compressed(struct hashfile *f, void *in, unsigned int size)
	/*
		die(_("--fix-thin cannot be used without --stdin"));
						      OBJECT_INFO_FOR_PREFETCH))
		p = add_packed_git(final_index_name, strlen(final_index_name), 0);
	if (report_end_of_input)
	}
				stream.next_out = data;
				sizeof(input_buffer) - input_len);
#include "promisor-remote.h"
		  unsigned char *hash)
	 * sha1-file.c, perhaps?  It shouldn't matter very much as we
static void unlink_base_data(struct base_data *c)
 * - write the final pack hash
		}
	if (HAVE_THREADS && !nr_threads) {
		return -1;
		      index_name, curr_index,
	unsigned long s = size;
	if (type != OBJ_ANY && obj->type != type)
		--first;
				    int *first_index, int *last_index,
				verify = 1;
			     "chain length = %d: %lu objects",
}
	do {


	if (do_fsck_object && fsck_finish(&fsck_options))
#define type_cas_unlock()	unlock_mutex(&type_cas_mutex)
		void *has_data;
	enum object_type old;
		free(has_data);
		int next = first + (last - first) / 2;
			continue;
				    strerror(ret));
static struct object_entry *append_obj_to_pack(struct hashfile *f,
		resolve_delta(child, base, result);

	if (entry->size <= big_file_threshold || entry->type != OBJ_BLOB)
			continue;
#include "exec-cmd.h"

			c->data = patch_delta(
		if (!n)
"git index-pack [-v] [-o <index-file>] [--keep | --keep=<msg>] [--verify] [--strict] (<pack-file> | --stdin [--fix-thin] [<pack-file>])";
				  suffix, filename);
};
}
	if (nr_ofs_deltas + nr_ref_deltas != nr_resolved_deltas)
	if (strict)
static void read_idx_option(struct pack_idx_option *opts, const char *pack_name)
	data = xmallocz(consume ? 64*1024 : obj->size);
	} while (status == Z_OK);
static void find_unresolved_deltas(struct base_data *base)
			die(_("SHA1 COLLISION FOUND WITH %s !"),
static int find_ref_delta(const struct object_id *oid, enum object_type type)
			else
		return 0;
		cmp = compare_ref_delta_bases(oid, &delta->oid,
		if (!hasheq(read_hash, tail_hash))
	return git_default_config(k, v, cb);
	if (base->ref_first <= base->ref_last) {
		if (threads_active)
	memset(&stream, 0, sizeof(stream));
			    (uintmax_t)len);
					   type_name(type)))
	return 0;
	git_zstream stream;
{
	if (first < 0) {
		if (output_fd >= 0)
	unsigned shift;
	unsigned long *chain_histogram = NULL;
		struct object_entry *child = objects + ref_deltas[base->ref_first].obj_no;
		pack_name = arg;
	stream.next_out = buf;
 * First pass:
	obj->type = (c >> 4) & 7;
	if (consume) {
		filename = odb_pack_name(&name_buf, hash, suffix);

		ssize_t ret = xread(input_fd, input_buffer + input_len,
			    nr_objects - nr_objects_initial);
		input_fd = 0;
			die(Q_("premature end of pack file, %"PRIuMAX" byte missing",
{
}
			base_offset += 1;
	int end = nr_ref_deltas - 1;
			int ret = pthread_create(&thread_data[i].thread, NULL,
		+ p->num_objects /* CRC32 table */
	if (threads_active)
	return offset1 < offset2 ? -1 :
static void *unpack_entry_data(off_t offset, unsigned long size,
		if (!HAVE_THREADS && nr_threads != 1) {
	git_deflate_end(&stream);
		if (obj->real_type != OBJ_BAD)
	}
static int do_fsck_object;
{
static pthread_mutex_t type_cas_mutex;
	if (!data.st)
		} else
	input_crc32 = crc32(input_crc32, input_buffer + input_offset, bytes);
	int i;
		sorted_by_pos[i] = &ref_deltas[i];
	s >>= 4;
		final(pack_name, curr_pack,
					free(data);
				if (!HAVE_THREADS && nr_threads != 1) {
	 * REF_DELTA bases are missing (which are explicitly handled). It only
				index_name = argv[++i];

static void *unpack_raw_entry(struct object_entry *obj,
	const char *keep_msg = NULL;
	if (final_pack_name != curr_pack_name) {
	unlink_base_data(base);
	if (stream.total_out != size || status != Z_STREAM_END)
			    nr_threads);
	case OBJ_COMMIT:
static struct base_data *alloc_base_data(void)
static int input_fd, output_fd;
	if (baseobjects)
		+ 256 /* fan out */
 * walkers going in the opposite ways.

			nr_ofs_deltas++;
	}
				    int *first_index, int *last_index,
		if (check_object_signature(the_repository, &d->oid,
		if (n < 0)
#include "streaming.h"
{
		nothread_data.pack_fd = input_fd;
		die(_("used more bytes than were available"));

		struct object_entry *obj = &objects[i];

static int compare_ofs_delta_entry(const void *a, const void *b)
	for (b = data->base_cache;
	const uint32_t *idx1, *idx2;
	pthread_key_create(&key, NULL);

		int nr_objects_initial = nr_objects;
	obj[0].real_type = type;
						  &eaten);
	pthread_mutex_init(&work_mutex, NULL);
		read_v2_anomalous_offsets(p, opts);
	return oidcmp(&delta_a->oid, &delta_b->oid);
		pthread_mutex_init(&deepest_delta_mutex, NULL);
	size_t len;
	pthread_t thread;
			} else
		}
static pthread_key_t key;
		s >>= 7;

{
struct ref_delta_entry {
		if (memcmp(buf, data->buf, len))
			    &obj->idx.oid);
		      keep_msg, promisor_msg,
	 */
			 * buf is deleted by the caller.

 *   for some more deltas.
#include "builtin.h"
	if (fix_thin_pack && !from_stdin)
		 */
static struct thread_local nothread_data;
		die(_("fsck error in pack objects"));
	if (!threads_active)
	strbuf_release(&index_name);
			die(_("bad pack.indexversion=%"PRIu32), opts->version);
		fix_unresolved_deltas(f);
	return c->data;
	return 0;

	if (fd < 0) {
{
			struct object_entry *bobj = &objects[obj_stat[i].base_object_no];
	if (old == want)
	return delta_a->offset < delta_b->offset ? -1 :
		counter_lock();
		stream.avail_in = input_len;
			free(raw);
{
#include "progress.h"
	int i;


	if (size != entry->size || type != entry->type)
	off_t base_offset;
{
{
	stream.avail_out = buf == fixed_buf ? sizeof(fixed_buf) : size;
}
				     "completed with %d local objects",

				strict = 1;
				item->buffer = NULL;
	if (cmp)
					&base->ofs_first, &base->ofs_last,
			die(_("cannot store index file"));

			if (obj->type == OBJ_COMMIT) {
	size_t base_cache_used;
		if (!check_collison(obj_entry))
	void *base_data, *delta_data;
	       delta_a->offset > delta_b->offset ?  1 :
#include "commit.h"
			} else if (!strcmp(arg, "-o")) {

		get_thread_data()->base_cache = NULL;

static int threads_active;

			if (!ret)
		ssize_t len = read_istream(data->st, data->buf, size);
static struct object_stat *obj_stat;
			struct ref_delta_entry *d = sorted_by_pos[i];
	QSORT(ofs_deltas, nr_ofs_deltas, compare_ofs_delta_entry);
static void write_special_file(const char *suffix, const char *msg,
		header[n++] = c | 0x80;
		status = git_deflate(&stream, Z_FINISH);
		int i;
		base->child = c;

			die(_("cannot read existing object info %s"), oid_to_hex(oid));
			return pthread_getspecific(key);
				    enum object_type type)
				   hash, NULL);
	 * read anything from it).
	if (nr_threads > 1 || getenv("GIT_FORCE_THREADS")) {
		bad_object(obj->idx.offset, _("unknown object type %d"), obj->type);
}
		for (; delta_nr > 0; delta_nr--) {
	free(data.buf);

	struct compare_data *data = cb_data;
		return 0;
static git_hash_ctx input_ctx;
		link_base_data(prev_base, base);
			free_base_data(base);
	pthread_mutex_init(&counter_mutex, NULL);

static int nr_dispatched;
	const struct ofs_delta_entry *delta_b = b;
		if (!consume)
{
	if (keep_msg)
	}
static off_t consumed_bytes;
	c->child = NULL;
	for (i = 0; i < deepest_delta; i++) {
	obj->size = size;
		use(1);
	if (verbose)
			write_or_die(fd, msg, msg_len);
	uint32_t a = *((uint32_t *)a_);
		child->real_type = base->obj->real_type;
			/*
			} else if (!strcmp(arg, "--verify-stat-only")) {
	if (opts->version == 2)
	const uint32_t hashwords = the_hash_algo->rawsz / sizeof(uint32_t);
			die(_("unable to read %s"),
	hashwrite(f, header, n);
		int j = base->obj - objects;
}
	}
		    memcmp(data, has_data, size) != 0)
		REALLOC_ARRAY(objects, nr_objects + nr_unresolved + 1);
		}
	if (!(obj->flags & FLAG_LINK))
		    oid_to_hex(&entry->idx.oid));
/*
					warning(_("no threads support, ignoring %s"), arg);
		while (c & 128) {
#include "config.h"
{
		progress = start_progress(_("Resolving deltas"),
	else

		free(data);

		obj->real_type = obj->type;
				if (index_name || (i+1) >= argc)
	git_deflate_init(&stream, zlib_compression_level);
		if (size != has_size || type != has_type ||
	unsigned char hdr_size;
{


static int ref_deltas_alloc;
	free_base_data(c);

	 * know we haven't installed this pack (hence we never have
#include "pack.h"
{
	*first_index = first;
			pthread_join(thread_data[i].thread, NULL);
	struct object_entry *obj = &objects[nr_objects++];
		progress = start_delayed_progress(_("Checking objects"), max);
			if (strict && fsck_walk(obj, NULL, &fsck_options))
		 * the last part of the input buffer to stdout.
	unsigned char c = (type << 4) | (s & 15);

static int compare_ofs_delta_bases(off_t offset1, off_t offset2,
				if (*c || opts.off32_limit & 0x80000000)
 * Second pass:
			die("REF_DELTA at offset %"PRIuMAX" already resolved (duplicate base %s?)",
	obj[1].idx.offset = obj[0].idx.offset + n;
}
		pthread_mutex_unlock(mutex);
		len -= n;

					free(inbuf);
		 * Prefetch the delta bases.
	const char *curr_index;
			if (obj->type == OBJ_TREE) {
	}
		resolve_delta(child, base, result);
		if (pack_name)
}
{
}
			 void *cb_data)
		if (type != obj->type)
{
		nr_threads = git_config_int(k, v);
		buf = fixed_buf;
	}
 * parent node to children, deflating nodes along the way. However,
			}
	*first_index = first;
			last = next;
		read_unlock();


		die(_("pack exceeds maximum allowed size"));
	return input_buffer;
		obj_stat[i].delta_depth = obj_stat[j].delta_depth + 1;
				do_fsck_object = 1;
	max = get_max_object_index();
	if (show_stat)
		--first;
	the_hash_algo->final_fn(hash, &input_ctx);
			work_unlock();
 * we're running out of delta_base_cache_limit; we need to re-deflate
		+ 2 /* 8-byte header */
	return 0;
static struct base_data *find_unresolved_deltas_1(struct base_data *base,
		die_errno(_("cannot fstat packfile"));
{
	 */
}
		} else if (!data) {
		if (deepest_delta < obj_stat[i].delta_depth)

/* Remember to update object flag allocation in object.h */
			err = xwrite(1, input_buffer + input_offset, input_len);
		ALLOC_GROW(opts->anomaly, opts->anomaly_nr + 1, opts->anomaly_alloc);
				   enum object_type type1,
	 * index-pack never needs to fetch missing objects except when

 * Mutex and conditional variable can't be statically-initialized on Windows.
	int ref_first, ref_last;
			continue;
				if (*c != ',')
#include "csum-file.h"
			} else if (skip_prefix(arg, "--max-input-size=", &arg)) {
		uint32_t off = ntohl(idx1[i]);
	ALLOC_ARRAY(sorted_by_pos, nr_ref_deltas);
		counter_unlock();
	}

			if (err <= 0)
					OBJ_REF_DELTA);
		close(input_fd);
				   type_name(type),(uintmax_t)size) + 1;

		 */
	struct pack_idx_entry **idx_objects;
	if (final_index_name != curr_index_name) {
		data->buf = xmalloc(size);
		die(_("pack too large for current definition of off_t"));
	free(sorted_by_pos);
			} else if (!strcmp(arg, "--verify")) {
				return;
#include "blob.h"
	threads_active = 1;
static int show_resolving_progress;
						  size, buf,
	int err;
			prev_base = base;
	while (first < last) {
		obj_stat[i].base_object_no = j;

		struct object_entry *child = objects + ofs_deltas[base->ofs_first].obj_no;
		struct ref_delta_entry *delta = &ref_deltas[next];
	int ofs_first, ofs_last;

			die(_("did not receive expected object %s"),

}
	if (data->buf_size < size) {
static unsigned int input_offset, input_len;

 * Make sure at least "min" bytes are available in the buffer, and
		struct packed_git *p;
	if (index_name == NULL)

	}
			continue;
static void set_thread_data(struct thread_local *data)

		die(_("Cannot open existing pack idx file for '%s'"), pack_name);
	if (base)
static void init_thread(void)
	close_istream(data.st);

}
		usage(index_pack_usage);
				from_stdin ? _("Receiving objects") : _("Indexing objects"),
	for (;;) {
				; /* nothing to do */
		p = fill(1);
	data.entry = entry;
		read_lock();
				input_len = sizeof(*hdr);
static struct thread_local *thread_data;
static int nr_ofs_deltas;
		base->ref_first++;
}
					OBJ_OFS_DELTA);
		close(input_fd);
		int nr_unresolved = nr_ofs_deltas + nr_ref_deltas - nr_resolved_deltas;
						 threaded_second_pass, thread_data + i);
				die(_("early EOF"));
	enum object_type type;
			      struct object_id *oid)

		write_special_file("promisor", promisor_msg, final_pack_name,

		read_unlock();
	/* make sure off_t is sufficiently large not to wrap */
		printf("%s %-6s %"PRIuMAX" %"PRIuMAX" %"PRIuMAX,
		}
	if (!pack_version_ok(hdr->hdr_version))
	return unpack_data(obj, NULL, NULL);
		if (!final_pack_name)
}
static void find_ofs_delta_children(off_t offset,
			promisor_remote_get_direct(the_repository,
				struct commit *commit = (struct commit *) obj;
}
			delta[delta_nr++] = c;
		if (!(off & 0x80000000))
			    oid_to_hex(&data->entry->idx.oid));
}
		       (uintmax_t)obj->idx.offset);
			collision_test_needed = 0;

	void *new_data = NULL;
			} else if (starts_with(arg, "--pack_header=")) {

	nr_dispatched = 0;
		if (finalize_object_file(curr_index_name, final_index_name))
{
	if (!strcmp(k, "pack.indexversion")) {


	struct base_data *base_obj = alloc_base_data();
	}
struct thread_local {
		*first_index = 0;
		printf_ln(Q_("non delta: %d object",
			      oid_to_hex(&obj->oid));
	}
		fsync_or_die(output_fd, curr_pack_name);
 * situation, its parent node would be already deflated, so it just
	for (i = 1; i < argc; i++) {
		return;
		if (!data)
 * - append objects to convert thin pack to full pack if required
		init_thread();
		display_progress(progress, i+1);
}
	}
		return result;
		read_unlock();
	if (promisor_msg)
}
			struct strbuf tmp_file = STRBUF_INIT;
			 type_name(delta_obj->real_type), &delta_obj->idx.oid);
		show_pack_info(stat_only);
			oidcpy(&ref_deltas[nr_ref_deltas].oid, &ref_delta_oid);
				die(_("invalid %s"), type_name(type));
	}
		new_base = find_unresolved_deltas_1(base, prev_base);
static int verbose;
	struct pack_idx_option opts;
 * - if used as a base, uncompress the object and apply all deltas,

		if (nr_unresolved <= 0)
		struct base_data *base_obj = alloc_base_data();

		get_thread_data()->base_cache = c;

	struct thread_local *data = get_thread_data();
		display_progress(progress, i + 1);
		err = close(output_fd);
		      pack_hash);
	if (strict || do_fsck_object) {
		 * octets, and ntohl(idx2[off * 2 + 1]) in low 4
	git_zstream stream;
	close_pack_index(p);
};

	/* Read the attributes from the existing idx file */
 */
	unpack_data(entry, compare_objects, &data);
		c = *p;
			void *base, *raw;
				die(_("Not all child objects of %s are reachable"), oid_to_hex(&obj->oid));
	if (hdr->hdr_signature != htonl(PACK_SIGNATURE))
	}
		*first_index = 0;
	if (threads_active)
	} else {
	die(_("pack has bad object at offset %"PRIuMAX": %s"),
		i = nr_dispatched++;
		for (i = 0; i < nr_threads; i++)
			} else if (!strcmp(arg, "--fix-thin")) {
/* Discard current buffer used content. */
}
		get_thread_data()->base_cache_used -= c->size;
				fix_thin_pack = 1;
			  baseobjects);
	const struct ref_delta_entry *delta_b = b;
static int mark_link(struct object *obj, int type, void *data, struct fsck_options *options)

}
 * Standard boolean compare-and-swap: atomically check whether "*type" is
		stop_progress_msg(&progress, msg.buf);
	static char fixed_buf[8192];
		       oid_to_hex(&obj->idx.oid),
				char *c;
}
	unsigned char outbuf[4096];

static uint32_t input_crc32;
			} else if (skip_to_optional_arg(arg, "--keep", &keep_msg)) {
static void cleanup_thread(void)
 */
	strbuf_release(&index_name_buf);

		else {
			} else if (!strcmp(arg, "--fsck-objects")) {
				obj->parsed = 0;
				hdr->hdr_version = htonl(strtoul(arg + 14, &c, 10));
				nr_threads = strtoul(arg+10, &end, 0);
			base = get_base_data(c->base);
		const char *arg = argv[i];

		work_lock();
		input_len += ret;
	if (has_promisor_remote()) {
	read_replace_refs = 0;
		unsigned char *last_out = stream.next_out;
				hdr->hdr_signature = htonl(PACK_SIGNATURE);
	do {

		if (opts->version > 2)
		if (is_delta_type(obj->type))
			die(_("SHA1 COLLISION FOUND WITH %s !"), oid_to_hex(oid));

	if (!verify)
}
}
		if (base->ofs_first == base->ofs_last)
	set_thread_data(data);
static const char *curr_pack;

struct compare_data {
		enum object_type type;
{
		buf = xmallocz(size);
	}
			has_object_file_with_flags(oid, OBJECT_INFO_QUICK);
static struct fsck_options fsck_options = FSCK_OPTIONS_STRICT;
 * - remember base (SHA1 or offset) for all deltas.
		break;
	}
}

{
	git_inflate_end(&stream);
		break;
	for (i = 0; i < nr_ref_deltas; i++)
		if (close(fd) != 0)
}
		die(_("Cannot open existing pack file '%s'"), pack_name);
			die_errno(_("unable to open %s"), curr_pack);
			ref_deltas[nr_ref_deltas].obj_no = i;
		idx_objects[i] = &objects[i].idx;
{
		struct base_data **delta = NULL;
	unsigned foreign_nr = 1;	/* zero is a "good" value, assume bad */
 * In the worst case scenario, parent node is no longer deflated because
			       const char **report)
#define read_unlock()		unlock_mutex(&read_mutex)
	else
		die(Q_("cannot fill %d byte",

		 * The real offset is ntohl(idx2[off * 2]) in high 4
static int nr_resolved_deltas;
{

			die(_("SHA1 COLLISION FOUND WITH %s !"), oid_to_hex(oid));
{



				strict = 1;
					return NULL;
			deepest_delta = obj_stat[i].delta_depth;
		int i = delta_obj - objects;
static int compare_and_swap_type(signed char *type,


	signed char type;
	git_config(git_index_pack_config, &opts);

{
{
	}
};
}
	int i;
	if (prefix && chdir(prefix))
 *
	if (nr_delays)
	struct pack_idx_option *opts = cb;
	int collision_test_needed = 0;
					 curr_pack, nr_objects,
	git_inflate_end(&stream);
	shift = 4;
			continue;
				 enum object_type want,
 *   recursively checking if the resulting object is used as a base
	if (from_stdin) {
	if (deepest_delta)

	}
	if (HAVE_THREADS) {
		if (nr_dispatched >= nr_objects) {
static void fix_unresolved_deltas(struct hashfile *f)
			if (!oid_object_info_extended(the_repository, &d->oid,
 * at some point parent node's deflated content may be freed.
	if (type == OBJ_BLOB && size > big_file_threshold)

	for (i = 0; i < nr_ref_deltas; i++) {
	}
		int next = first + (last - first) / 2;
			base = prev_base;
	struct object_entry *obj;
			      "(disk corruption?)"), curr_pack);
	free(ref_deltas);
}
				stream.avail_out = 64*1024;

	while (size) {
		       type_name(obj->real_type), (uintmax_t)obj->size,
			the_hash_algo->update_fn(&c, last_out, stream.next_out - last_out);

			ALLOC_GROW(ref_deltas, nr_ref_deltas + 1, ref_deltas_alloc);
	nr_resolved_deltas++;

		if (obj->type == OBJ_OFS_DELTA) {
#define counter_unlock()	unlock_mutex(&counter_mutex)

	 * smallest number of base objects that would cover as much delta
		read_lock();
			die(_("cannot read existing object %s"), oid_to_hex(oid));
				     nr_objects - nr_objects_initial),
	struct object_entry *entry;
static void *unpack_data(struct object_entry *obj,

		chmod(final_pack_name, 0444);
				continue;
	prune_base_data(c);


	return base;
		stream.avail_in = n;
		die(_("pack is corrupted (SHA1 mismatch)"));

				check_self_contained_and_connected = 1;
struct object_entry {
				if (!arg[10] || *end || nr_threads < 0)
			      off_t *ofs_offset,
	int base_object_no;
	if (verbose)
		die(Q_("pack has %d unresolved delta",
		FREE_AND_NULL(data);
				die_errno(_("unable to create '%s'"), pack_name);
		hashcpy(read_hash, pack_hash);
		opts->anomaly[opts->anomaly_nr++] = ntohl(idx2[off * 2 + 1]);
			       oid_to_hex(&bobj->idx.oid));
		chain_histogram = xcalloc(deepest_delta, sizeof(unsigned long));
	if (show_stat)
	obj->flags |= FLAG_LINK;
			struct blob *blob = lookup_blob(the_repository, oid);
	find_unresolved_deltas(base_obj);
{
		display_progress(progress, nr_resolved_deltas);

	for (i = 0; i < nr_objects; i++) {
 *
		thread_data[i].pack_fd = open(curr_pack, O_RDONLY);
static unsigned check_objects(void)
		}

 * The first one in find_unresolved_deltas() traverses down from
{
				verbose = 1;
		die(_("SHA1 COLLISION FOUND WITH %s !"),

		if (len < 0)
	assert(data || obj_entry);
	switch (obj->type) {
	int first = find_ofs_delta(offset, type);
		}

			}
		free((void *) curr_pack);
	if (cmp)
		return;
};
	}
	 * for more unresolved deltas, we really want to include the
		       (uintmax_t)(obj[1].idx.offset - obj->idx.offset),
		foreign_nr += check_object(get_indexed_object(i));

	int end = nr_ofs_deltas - 1;
				show_stat = 1;
	int msg_len = strlen(msg);
	c->base = base;

}
	vsnprintf(buf, sizeof(buf), format, params);
	for (i = 0; i < nr_objects; i++) {
	/*
		die(_("unable to deflate appended object (%d)"), status);
	if (pack_name == NULL)
		void *data = unpack_raw_entry(obj, &ofs_delta->offset,

			  chain_histogram[i]);
	if (!p)
			obj = parse_object_buffer(the_repository, oid, type,
	unsigned char pack_hash[GIT_MAX_RAWSZ];
	}
	return (type == OBJ_REF_DELTA || type == OBJ_OFS_DELTA);
		FREE_AND_NULL(c->data);
	return -first-1;
	stream.avail_in = size;
		die(_("pack signature mismatch"));
	unsigned char *buf;

			die(_("cannot store pack file"));

	if (c->data)
		return 0;
			use(1);
		struct ofs_delta_entry *delta = &ofs_deltas[next];
{
	unsigned long size, c;
			    type_name(obj->type), type_name(type));
{
		if (new_base) {
{

	if (show_stat) {
	free(objects);
		*type = set;
#include "tag.h"
	int hdrlen;
				max_input_size = strtoumax(arg, NULL, 10);
		off = off & 0x7fffffff;
				blob->object.flags |= FLAG_CHECKED;
		strbuf_addf(&buf, "%s\t%s\n", report, hash_to_hex(hash));
	}
				base, c->base->size,
					 read_hash, consumed_bytes-the_hash_algo->rawsz);
	free(inbuf);
	free(p);
	if (!strcmp(k, "pack.threads")) {
	memset(&stream, 0, sizeof(stream));
			ntohl(hdr->hdr_version));
		}
				if (*c == ',')
		die(_("object type mismatch at %s"), oid_to_hex(&obj->oid));
	*last_index = last;
		++last;

	int i, nr_delays = 0;

	return oidcmp(oid1, oid2);
			last = next;
{
	struct base_data *base;
			c->data = get_data_from_pack(obj);
			get_thread_data()->base_cache_used += c->size;
	for (i = 0; i < max; i++) {
	return NULL;
		if (!pack_name) {
static int check_self_contained_and_connected;
				break;
static off_t max_input_size;
					die(_("bad %s"), arg);

 * All deflated objects here are subject to be freed if we exceed

		if (b->data && b != retain)
{
				do_fsck_object = 1;
	int pack_fd;

		} else if (obj->type == OBJ_REF_DELTA) {
	struct base_data *base = c->base;
	return data;
		} else {
	if (verbose || show_resolving_progress)
	int i, baseobjects = nr_objects - nr_ref_deltas - nr_ofs_deltas;
		if (stat_only)
					opts.off32_limit = strtoul(c+1, &c, 0);
		if (finalize_object_file(curr_pack_name, final_pack_name))
	}
				if (opts.version > 2)
				bad_object(obj->idx.offset, _("offset value overflow for delta base object"));

					   base_obj->data, base_obj->size,


			continue;
 * Third pass:

		return cmp;
}
		work_unlock();
	for (i = 0; i < p->num_objects; i++) {
			} else if (skip_to_optional_arg(arg, "--strict", &arg)) {
		       ...) __attribute__((format (printf, 2, 3)));
	input_crc32 = crc32(0, NULL, 0);

	for (i = 0; i < nr_objects; i++) {

	       0;

	unsigned char header[10];
		hashwrite(f, outbuf, sizeof(outbuf) - stream.avail_out);
			if (ret)

		assert(!threads_active &&
	int i, fix_thin_pack = 0, verify = 0, stat_only = 0;

	 * Let the caller know this pack is not self contained
		if (has_type != type || has_size != size)
			data = new_data = get_data_from_pack(obj_entry);
			if (!c->data)
			} else if (!strcmp(arg, "--verify-stat")) {
static void *threaded_second_pass(void *data)
	}

	the_hash_algo->init_fn(&input_ctx);
{
	while (s) {
		chmod(final_index_name, 0444);
	return old == want;
	use(1);
static pthread_mutex_t deepest_delta_mutex;
			      struct object_id *ref_oid,
		struct strbuf msg = STRBUF_INIT;
			write_or_die(fd, "\n", 1);
	struct ref_delta_entry **sorted_by_pos;
	fetch_if_missing = 0;
	free(new_data);
		has_type = oid_object_info(the_repository, oid, &has_size);


					die(_("bad %s"), arg);

 *   deltas;

		}
		read_lock();
{
	hashcpy(obj->idx.oid.hash, sha1);
			} else if (starts_with(arg, "--threads=")) {
	if (!(obj->flags & FLAG_CHECKED)) {
{
{
{
	counter_lock();
		}
}
			if (blob)
}
static void use(int bytes)
	struct base_data *new_base, *prev_base = NULL;
	parse_pack_objects(pack_hash);
			stream.avail_out = sizeof(fixed_buf);
}
static int from_stdin;
			 * we do not need to free the memory here, as the
			get_thread_data()->base_cache_used += c->size;
		return input_buffer + input_offset;
struct object_stat {
	git_inflate_init(&stream);
	if (input_offset) {

static void parse_pack_header(void)
		}

	} else

			continue;
		return result;

				show_resolving_progress = 1;
	reset_pack_idx_option(&opts);
	return 0;
static unsigned deepest_delta;
		       min),

				struct tree *item = (struct tree *) obj;
static void *fill(int min)
	use(sizeof(struct pack_header));
 *
		}
			int eaten;
	}
	QSORT(sorted_by_pos, nr_ref_deltas, delta_pos_compare);
		return;
	else
static struct progress *progress;
		collision_test_needed =
	if (show_stat)
	base_obj->obj = obj;
	free(idx_objects);
{

	size = stream.total_out;
			input_len -= err;
/*
		deepest_delta_unlock();
		size -= len;

{
		stream.next_in = fill(1);
	while (c & 0x80) {
			c = *p;
	va_start(params, format);
		return 1;

	ALLOC_ARRAY(idx_objects, nr_objects);
		find_ref_delta_children(&base->obj->idx.oid,
static void read_v2_anomalous_offsets(struct packed_git *p,
	if (!from_stdin) {
	off_t len = obj[1].idx.offset - from;
			final_index_name = odb_pack_name(&index_name, hash, "idx");
		return;
		strbuf_release(&buf);
	crc32_begin(f);

		if (objects[d->obj_no].real_type != OBJ_REF_DELTA)
	}
					      &ref_delta_oid,
		strbuf_addf(&msg, Q_("completed with %d local object",
				if (detach_commit_buffer(commit, NULL) != data)
						  struct base_data *prev_base)

		die(_("serious inflate inconsistency"));
		stop_progress(&progress);
		get_thread_data()->base_cache_used += c->size;
			if (output_fd < 0)
	int last = first;
			lseek(input_fd, 0, SEEK_CUR) - input_len != st.st_size)

		}
static int cmp_uint32(const void *a_, const void *b_)
			nr_dispatched++;
	delta_data = get_data_from_pack(delta_obj);
{

	struct base_data *child;
			return next;
	pthread_mutex_destroy(&read_mutex);
	if (collision_test_needed) {
{
	struct strbuf index_name = STRBUF_INIT;
static void resolve_deltas(void)
		if (is_delta_type(obj->type))
			  struct base_data *base, struct base_data *result)
 * just need to make sure the last node is not freed.
	off_t from = obj[0].idx.offset + obj[0].hdr_size;
	int first = 0, last = nr_ofs_deltas;
	}
	if (do_fsck_object) {
	if (max_input_size && consumed_bytes > max_input_size)
	stream.next_in = in;
	if (base->ofs_first <= base->ofs_last) {
				die(_("fsck error in packed object"));
		opts->version = git_config_int(k, v);

static int nr_ref_deltas;
			die(_("Unexpected tail checksum for %s "
	QSORT(ref_deltas, nr_ref_deltas, compare_ref_delta_entry);
		while (is_delta_type(c->obj->type) && !c->data) {
		write_special_file("keep", keep_msg, final_pack_name, hash,
	while (last < end && ofs_deltas[last + 1].offset == offset)
	if (min <= input_len)
		int cmp;
		struct base_data *result = alloc_base_data();
	}
			die_errno(_("cannot close written %s file '%s'"),
			write_or_die(output_fd, input_buffer, input_offset);
		output_fd = -1;
/*
	if (open_pack_index(p))
		free(delta);
	       0;
	}
		memset(objects + nr_objects + 1, 0,
			free(base->data);
	}

static int nr_objects;
static int compare_ref_delta_bases(const struct object_id *oid1,
			free_base_data(b);
				die(_("unable to create thread: %s"),
			display_throughput(progress, consumed_bytes + input_len);
		if (!final_index_name)
		hdrlen = xsnprintf(hdr, sizeof(hdr), "%s %"PRIuMAX,
	} else
{
	else
static void prune_base_data(struct base_data *retain)
 * - for all non-delta objects, look if it is used as a base for
	if (!c->data) {
	int first = find_ref_delta(oid, type);
		if (!delta_nr) {
		die(_("pack has junk at the end"));
	unsigned long size;
		read_lock();
		*ofs_offset = obj->idx.offset - base_offset;
	struct strbuf name_buf = STRBUF_INIT;
   or it must be already present in the object database */

		read_unlock();
}
#include "tree.h"
	if (!strip_suffix(pack_name, ".pack", &len))
	while (first > 0 && oideq(&ref_deltas[first - 1].oid, oid))

	old = *type;
	p = fill(1);
	va_list params;
	free(thread_data);
		*last_index = -1;
/*
	}
	     data->base_cache_used > delta_base_cache_limit && b;
		progress = start_progress(
		if (input_fd < 0)
{
		enum object_type has_type;
 */
	if (!from_stdin) {
			if (!base)
#define deepest_delta_lock()	lock_mutex(&deepest_delta_mutex)
	obj->hdr_size = consumed_bytes - obj->idx.offset;
				if (*c)
		nothread_data.pack_fd = output_fd;
	struct base_data *base = xcalloc(1, sizeof(struct base_data));
	pthread_mutex_init(&type_cas_mutex, NULL);
	struct stat st;
		       nr_ofs_deltas + nr_ref_deltas - nr_resolved_deltas),

	/* If input_fd is a file, we should have reached its end now. */
			    oid_to_hex(&data->entry->idx.oid));
		buf += len;
	if (base->ref_last == -1 && base->ofs_last == -1) {
		if (p)
				; /* already parsed */
		resolve_base(&objects[i]);
	c = *p;
	if (S_ISREG(st.st_mode) &&
			const struct object_id *oid)
		struct strbuf buf = STRBUF_INIT;

		       "cannot fill %d bytes",
		die(_("Cannot come back to cwd"));
	if (signed_add_overflows(consumed_bytes, bytes))
		if (to_fetch.nr)
					nr_threads = 1;
		break;
			input_offset += err;
}
		if (type <= 0)


				stat_only = 1;
		if (is_delta_type(obj->type)) {

	if (bytes > input_len)
		die(_("confusion beyond insanity in parse_pack_objects()"));
			struct object *obj;
	strbuf_add(buf, pack_name, len);
		int cmp;

		strbuf_release(&msg);

		for (i = 0; i < nr_threads; i++) {
}
				raw, obj->size,
	int last = first;
		if (has_type < 0)
		size += (c & 0x7f) << shift;

		use(the_hash_algo->rawsz);
	/* Check pack integrity */
	do {
	const char *filename;
		if (msg_len > 0) {
/*
static inline void unlock_mutex(pthread_mutex_t *mutex)
			die(_("confusion beyond insanity"));
		find_unresolved_deltas(base_obj);
			if (do_fsck_object &&
	/* This has been inflated OK when first encountered, so... */
			die(_("invalid number of threads specified (%d)"),
	uint32_t i;
		    nr_ofs_deltas + nr_ref_deltas - nr_resolved_deltas);
		base_obj->obj = append_obj_to_pack(f, d->oid.hash,
		if (from_stdin)
		if (idx2[off * 2])
}
		/* An experiment showed that more threads does not mean faster */
				   delta_data, delta_obj->size, &result->size);
{
	    (uintmax_t)offset, buf);
		 */
		c = s & 0x7f;
		write_or_die(1, buf.buf, buf.len);
	if (!index_name && pack_name)
		pthread_mutex_destroy(&deepest_delta_mutex);
		if (ret <= 0) {
			} else if (skip_to_optional_arg(arg, "--promisor", &promisor_msg)) {
		input_fd = open(pack_name, O_RDONLY);
	if (argc == 2 && !strcmp(argv[1], "-h"))
		use(1);
#define work_unlock()		unlock_mutex(&work_mutex)

}
static void *get_data_from_pack(struct object_entry *obj)
		first = next+1;
			} else if (!strcmp(arg, "-v")) {
		int delta_nr = 0, delta_alloc = 0;
static void resolve_delta(struct object_entry *delta_obj,
			ALLOC_GROW(delta, delta_nr + 1, delta_alloc);
#define FLAG_LINK (1u<<20)
			die(_("local object %s is corrupt"), oid_to_hex(&d->oid));

	struct strbuf pack_name = STRBUF_INIT;
			c = delta[delta_nr - 1];
	struct ref_delta_entry *b = *(struct ref_delta_entry **)_b;
			output_fd = odb_mkstemp(&tmp_file,
		*last_index = -1;
			void *buf = (void *) data;
	pthread_mutex_destroy(&counter_mutex);

 */
			usage(index_pack_usage);

	if (nr_ref_deltas + nr_ofs_deltas == nr_resolved_deltas) {
		close(thread_data[i].pack_fd);
	const struct ref_delta_entry *delta_a = a;
	const char *report = "pack";
			free_base_data(base);
		if (thread_data[i].pack_fd == -1)
			die_errno(_("cannot open packfile '%s'"), pack_name);
		} else {
}
{
	if (!is_delta_type(type)) {
				   enum object_type type2)
	}
	}
{
	return a->obj_no - b->obj_no;
	if (!obj)


	if (startup_info->have_repository) {

	return buf == fixed_buf ? NULL : buf;
	 * Since many unresolved deltas may well be themselves base objects
	ofs_deltas = xcalloc(nr_objects, sizeof(struct ofs_delta_entry));
	if (fix_thin_pack) {
		/*
static int compare_objects(const unsigned char *buf, unsigned long size,
static void parse_pack_objects(unsigned char *hash)

	QSORT(opts->anomaly, opts->anomaly_nr, cmp_uint32);
static NORETURN void bad_object(off_t offset, const char *format,
		base->ofs_first++;
	stream.next_out = data;
	return size;
	obj[1].idx.offset += write_compressed(f, buf, size);
	struct git_istream *st;
}
			if (!obj)
#define deepest_delta_unlock()	unlock_mutex(&deepest_delta_mutex)
	return NULL;
	if (fstat(input_fd, &st))
		foreign_nr = check_objects();
		/*
	/* Sort deltas by base SHA1/offset for fast searching */
	int obj_no;
				char *c;
	void *data;

			       enum object_type type, struct object_id *oid)

			 int (*consume)(const unsigned char *, unsigned long, void *),
	signed char real_type;
				  suffix, filename);
			die_errno(_("read error on input"));

	struct base_data *base_cache;
}
				verify = 1;
			continue;
	 * additional base objects.  Since most base objects are to be found
	case OBJ_BLOB:
{
				usage(index_pack_usage);
#define work_lock()		lock_mutex(&work_mutex)
		unsigned long has_size;

	unsigned long buf_size;
}
			   void *cb_data)
					die(_("bad %s"), arg);
			 */
	struct base_data *b;
			       const char *pack_name, const unsigned char *hash,
	 * Get rid of the idx file as we do not need it anymore.
 */
}
				   const struct object_id *oid2,
		struct hashfile *f;
		for (i = 0; i < nr_ref_deltas; i++) {
		cleanup_thread();
			    (uintmax_t)child->idx.offset,
		} else {
				from_stdin = 1;
#define read_lock()		lock_mutex(&read_mutex)
		}
		if (cmp < 0) {
	stream.avail_out = consume ? 64*1024 : obj->size;

	}


	case OBJ_TAG:
	base->ofs_last = -1;
				status = git_inflate(&stream, 0);
		struct object_entry *obj = c->obj;
	int obj_no;
 * to top parent if necessary to deflate the node. In normal
	fsck_options.walk = mark_link;
			       NULL);
	*last_index = last;
			} else if (!strcmp(arg, "--check-self-contained-and-connected")) {
			nr_ref_deltas++;
				    &obj->idx.oid);
	if (status != Z_STREAM_END || stream.total_out != obj->size)
		if (oid)
	int cmp = type1 - type2;
	stop_progress(&progress);
	if (!result->data)
#include "thread-utils.h"
{
	if (!nr_ofs_deltas && !nr_ref_deltas)
					usage(index_pack_usage);
	git_inflate_init(&stream);
		bad_object(offset, _("inflate returned %d"), status);
		}
	base_obj->data = NULL;
	obj->idx.crc32 = input_crc32;
					      type, objects[delta->obj_no].type);

	result->data = patch_delta(base_data, base->size,
		fixup_pack_header_footer(output_fd, pack_hash,
}
				fsck_set_msg_types(&fsck_options, arg);
	int i;
	}
			pack_name = strbuf_detach(&tmp_file, NULL);
					      type, objects[delta->obj_no].type);
	return 0;
}
		display_progress(progress, nr_resolved_deltas);
#define FLAG_CHECKED (1u<<21)
		  const char *final_index_name, const char *curr_index_name,
};
	conclude_pack(fix_thin_pack, curr_pack, pack_hash);
		shift += 7;
		return -1;
		while (input_len) {
		deepest_delta_lock();
		cmp = compare_ofs_delta_bases(offset, delta->offset,

	idx2 = idx1 + p->num_objects;
					usage(index_pack_usage);
				report_end_of_input = 1;
	}
				}
		hashcpy(ref_oid->hash, fill(the_hash_algo->rawsz));
	obj[0].type = type;
					&base->ref_first, &base->ref_last,
			} else if (starts_with(arg, "--index-version=")) {
			       unsigned long size, enum object_type type)
				bad_object(obj->idx.offset, _("failed to apply delta"));
		);
		obj_stat = xcalloc(st_add(nr_objects, 1), sizeof(struct object_stat));
	}
	if (verify) {
static void *get_base_data(struct base_data *c)
		finalize_hashfile(f, tail_hash, 0);
	if (strict)

				die(_("fsck error in packed object"));
static int check_collison(struct object_entry *entry)
			install_packed_git(the_repository, p);
				hdr->hdr_entries = htonl(strtoul(c + 1, &c, 10));

static void link_base_data(struct base_data *base, struct base_data *c)
static const char index_pack_usage[] =

static void fix_unresolved_deltas(struct hashfile *f);
		return cmp;
 */
			obj->real_type = OBJ_BAD;
	if (base)
	type_cas_lock();
	init_recursive_mutex(&read_mutex);
	if (first < 0) {
{
	struct pack_idx_entry idx;

 * and return false.
#include "delta.h"

	obj[0].size = size;
			nr_threads = 1;
/*
			unsigned long size, enum object_type type,

		int type = oid_object_info(the_repository, &obj->oid, &size);

		if (!chain_histogram[i])


		from += n;
		/* Flush remaining pack final hash. */
	}
	while (last < end && oideq(&ref_deltas[last + 1].oid, oid))
		if (nr_threads > 3)
		sha1_object(NULL, obj, obj->size, obj->type,
	int cmp = type1 - type2;
		putchar('\n');
			ofs_delta++;
		opts.flags |= WRITE_IDX_VERIFY | WRITE_IDX_STRICT;
	obj[0].hdr_size = n;

}
				   &report);
	flush();
		first = next+1;
		base_offset = c & 127;
	int status;
			free(base);


		pthread_setspecific(key, data);
			    fsck_object(&blob->object, (void *)data, size, &fsck_options))
	else
				 enum object_type set)

 * delta_base_cache_limit, just like in find_unresolved_deltas(), we
	}

static void find_ref_delta_children(const struct object_id *oid,
	unsigned char *data, *inbuf;
		if (*ofs_offset <= 0 || *ofs_offset >= obj->idx.offset)
		index_name = derive_filename(pack_name, "idx", &index_name_buf);

	pthread_mutex_destroy(&type_cas_mutex);
			} else if (!strcmp(arg, "--show-resolving-progress")) {
	for (;;) {
	unsigned delta_depth;
		while (nr_dispatched < nr_objects &&
}
				   enum object_type type1,
					BUG("parse_object_buffer transmogrified our buffer");
		if (!index_name)
		if (type == OBJ_BLOB) {
	}
	strbuf_addch(buf, '.');
			printf(" %u %s", obj_stat[i].delta_depth,
			base = new_base;
	curr_index = write_idx_file(index_name, idx_objects, nr_objects, &opts, pack_hash);
 * parents, possibly up to the top base.

	while (first < last) {
	input_len -= bytes;
		stream.next_in = inbuf;
			oid_array_append(&to_fetch, &d->oid);
		status = git_inflate(&stream, 0);
		if (*arg == '-') {
			continue;
			     "non delta: %d objects",

		printf("%s\n", hash_to_hex(hash));
				if (consume(data, stream.next_out - data, cb_data)) {
	nr_objects = ntohl(hdr->hdr_entries);
	return data;
	const struct ofs_delta_entry *delta_a = a;
				die(_("invalid blob object %s"), oid_to_hex(oid));
static struct ref_delta_entry *ref_deltas;
	int report_end_of_input = 0;
			assert(data && "data can only be NULL for large _blobs_");
}
			do {
	     b = b->child) {

	} else {
	idx1 = (((const uint32_t *)p->index_data)
			p = fill(1);
		opts.flags |= WRITE_IDX_STRICT;
		assert(child->real_type == OBJ_OFS_DELTA);
	case OBJ_TREE:
	struct pack_header *hdr = fill(sizeof(struct pack_header));
	git_hash_ctx c;
					die(_("bad %s"), arg);
				verify = 1;
	strbuf_release(&pack_name);
		}
	struct object_id ref_delta_oid;
	counter_unlock();
		base->child = NULL;
	thread_data = xcalloc(nr_threads, sizeof(*thread_data));

static void free_base_data(struct base_data *c)
static unsigned char input_buffer[4096];
		the_hash_algo->final_fn(oid->hash, &c);
static int strict;
		filename = derive_filename(pack_name, suffix, &name_buf);
	if (show_stat)
	return &nothread_data;
	va_end(params);

		  const char *keep_msg, const char *promisor_msg,
		die(_("packfile name '%s' does not end with '.pack'"),
		return -1;
	memset(&data, 0, sizeof(data));
		read_idx_option(&opts, index_name);
			continue;
		struct object_entry *obj = &objects[i];
{
	free(ofs_deltas);

	obj->idx.offset = consumed_bytes;
	hashflush(f);
	} while (status == Z_OK);
struct ofs_delta_entry {
static inline struct thread_local *get_thread_data(void)
};
