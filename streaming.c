			return pack_non_delta;

		struct pack_window *window = NULL;


	st = xmalloc(sizeof(*st));
	close_istream_filtered,
	struct pack_window *window;
				 sizeof(st->u.loose.hdr)) < 0) ||
		git_inflate_init(&st->z);
{
 close_and_exit:
ssize_t read_istream(struct git_istream *st, void *buf, size_t sz)
				 enum object_type *type,

			sz -= to_move;
		/*

{
		 * replenish them in the next use_pack() call when we loop. If
			fs->o_end = FILTER_BUFFER - to_receive;
				  st->u.in_pack.pos, &st->z.avail_in);
	oi->typep = type;
			if (readlen == holeto) {

			to_copy = sz;
{
static open_method_decl(incore);
}
			continue;

	}
		return NULL;
			return -1;
	read_istream_loose,
					enum object_type *type,

		return 0;
		}

		if (status != Z_OK && (status != Z_BUF_ERROR || total_read < sz)) {
		break;
	close_deflated_stream(st);
			unsigned long read_ptr;

	int r = st->vtbl->close(st);
			fs->o_end = FILTER_BUFFER - to_receive;
		     xwrite(fd, "", 1) != 1))
			git_inflate_end(&st->z);
					  NULL, NULL,
		size_t to_copy = st->u.loose.hdr_avail - st->u.loose.hdr_used;
			close_istream(st);


		/* do we have anything to feed the filter with? */

static struct stream_vtbl pack_non_delta_vtbl = {
#define FILTER_BUFFER (1024*16)
					    &st->size);
	struct git_istream *st;
struct git_istream *open_istream(struct repository *r,
			continue;

	pack_non_delta = 2
	struct git_istream *upstream;
	return ifs;
					const struct object_id *oid,
			off_t pos;
		st = nst;
{
					struct object_info *oi)
		memcpy(buf, st->u.incore.buf + st->u.incore.read_ptr, read_size);
		if (fs->o_ptr < fs->o_end) {
		if (kept && lseek(fd, kept, SEEK_CUR) == (off_t) -1)
		} loose;
#include "cache.h"
typedef ssize_t (*read_istream_fn)(struct git_istream *, char *, size_t);
};
		if (!fs->input_finished) {
 *
		/* fallthru */
		st->u.loose.hdr_used += to_copy;
			free(st);
static open_method_decl(pack_non_delta)

		}
	int input_finished;
 *
		if (fs->input_finished) {
#define open_method_decl(name) \
	default:
};
static struct stream_vtbl loose_vtbl = {
			size_t to_receive = FILTER_BUFFER;
static close_method_decl(pack_non_delta)

static open_istream_fn open_istream_tbl[] = {
		/* tell the filter to drain upon no more input */
		goto close_and_exit;
	return 0;
struct git_istream {
static open_method_decl(loose)
	return read_size;
		return loose;
static close_method_decl(filtered)

		 * we truly hit the end of the pack (i.e., because it's corrupt
		st->z.avail_out = sz - total_read;
};
static read_method_decl(loose)


			struct packed_git *pack;
		if (filter)
	return r;
	unsigned long sz;

 * Filtered stream
/*****************************************************************
			break;
static read_method_decl(incore)
		st->z.avail_out = sz - total_read;
}
	default:


		return -1;


/*****************************************************************
	stream_error = -1,
	}
static struct git_istream *attach_stream_filter(struct git_istream *st,
static enum input_source istream_source(struct repository *r,
		/* Add "&& !is_null_stream_filter(filter)" for performance */
#define close_method_decl(name) \
	} u;
				 st->u.loose.mapsize,
 *
/*****************************************************************
}

int stream_blob_to_fd(int fd, const struct object_id *oid, struct stream_filter *filter,

};


			if (stream_filter(fs->filter,
			st->z_state = z_done;
{
	free(st->u.incore.buf);
	int o_end, o_ptr;
			       struct repository *,
			       enum object_type *);
	while (total_read < sz) {
	}

		}
					  fs->obuf, &to_receive))
	char ibuf[FILTER_BUFFER];
#include "repository.h"
	unuse_pack(&window);
		read_size = remainder;
			git_inflate_end(&st->z);
	if (status < 0)
	}
	open_istream_loose,
	fs->input_finished = 0;
			size_t to_move = fs->o_end - fs->o_ptr;
		git_inflate_end(&st->z);
	ssize_t read_istream_ ##name \


			fs->i_end = read_istream(fs->upstream, fs->ibuf, FILTER_BUFFER);

		if (sz < to_copy)
				 struct stream_filter *filter)

					    &window,
static close_method_decl(incore)
}
	if (open_istream_tbl[src](st, r, &oi, real, type)) {
		struct filtered_istream filtered;
		} in_pack;
	return st;
	oi->sizep = &size;
};
	return result;
		else
	st->u.loose.hdr_used = strlen(st->u.loose.hdr) + 1;
	if (remainder <= read_size)
		struct git_istream *nst = attach_stream_filter(st, filter);
				if (buf[holeto])
	}
	return close_istream(st->u.filtered.upstream);
{
	status = oid_object_info_extended(r, oid, oi, 0);
			       const struct object_id *,
	 enum object_type *type)
	const struct object_id *real = lookup_replace_object(r, oid);
	fs->filter = filter;
static open_method_decl(pack_non_delta);
			goto close_and_exit;
{
	size_t total_read = 0;
		int status;
			filled += to_move;
	return filled;
				 st->u.loose.mapped,


/****************************************************************
	struct git_istream *st;
		st->z_state = z_used;
	size_t total_read = 0;
		if (can_seek && sizeof(buf) == readlen) {
 *****************************************************************/

}
		      int can_seek)
		ssize_t wrote, holeto;
	int status;
	return 0;
		return -1; /* we do not do deltas for now */
			if (!fs->o_end)
			size_t to_feed = fs->i_end - fs->i_ptr;
/*****************************************************************


 * Common helpers
	result = 0;

 * Users of streaming interface
		st->z.next_out = (unsigned char *)buf + total_read;
	while (sz) {
	switch (st->z_state) {

	close_istream_fn close;
	case z_error:
					break;
}
		git_inflate_end(&st->z);
{
	if (!st) {

	}
{
/*
			goto close_and_exit;

		if (!nst) {
	case z_done:
#include "object-store.h"
	}
		fs->input_finished = 1;
		if (fs->i_ptr < fs->i_end) {
			git_inflate_end(&st->z);
	if (st->z_state == z_used)
	int i_end, i_ptr;
		st->u.incore.read_ptr += read_size;
 * Loose object stream
						struct stream_filter *filter);

	enum object_type in_pack_type;
		break;
				to_move = sz;
				continue;
	if (kept && (lseek(fd, kept - 1, SEEK_CUR) == (off_t) -1 ||
	return total_read;
}

	free(st);
#include "packfile.h"

 */
	unsigned long size;
{
			unsigned long mapsize;

	in_pack_type = unpack_object_header(st->u.in_pack.pack,
	struct stream_filter *filter;
}
			free_stream_filter(filter);
	return st->vtbl->read(st, buf, sz);
	open_istream_pack_non_delta,
		if (readlen < 0)

 *
 *
			char *buf; /* from read_object() */
}
					  fs->ibuf + fs->i_ptr, &to_feed,
/* forward declaration */

};
	st->z_state = z_used;
}
	case z_used:
	case z_done:
 *
	case OI_PACKED:
	int close_istream_ ##name \


	free_stream_filter(st->u.filtered.filter);
		st->u.in_pack.pos += st->z.next_in - mapped;
static struct git_istream *attach_stream_filter(struct git_istream *st,
}
	enum object_type type;
				continue;
	switch (oi->whence) {
	if (filter) {
		 * we get Z_BUF_ERROR due to too few input bytes, then we'll
			}
	case OI_LOOSE:
			char hdr[32];
		status = git_inflate(&st->z, Z_FINISH);
				return -1;
	}

		memset(&st->z, 0, sizeof(st->z));
struct filtered_istream {
		munmap(st->u.loose.mapped, st->u.loose.mapsize);
			for (holeto = 0; holeto < readlen; holeto++)

		}
 *****************************************************************/
	size_t read_size = sz;

	case OBJ_BLOB:
static struct stream_vtbl filtered_vtbl = {
	case OBJ_TAG:
		wrote = write_in_full(fd, buf, readlen);
	loose = 1,
		}
			st->z_state = z_error;
			return NULL;
		 * or truncated), then use_pack() catches that and will die().
static struct stream_vtbl incore_vtbl = {
	return total_read;
	st->u.in_pack.pos = oi->u.packed.offset;
{
		if (status == Z_STREAM_END) {
 *****************************************************************/
	close_istream_incore,
		return 0;
	st->u.incore.read_ptr = 0;
		}
{
	int open_istream_ ##name \
			return -1;
		struct {
	if (!st->u.loose.mapped)
	ifs->size = -1; /* unknown */
			size_t to_receive = FILTER_BUFFER;
		total_read += to_copy;
	case z_unused:
}
				 unsigned long *size,
	st->vtbl = &incore_vtbl;
	git_zstream z;
	close_istream_pack_non_delta,
		unsigned char *mapped;

		 * Unlike the loose object case, we do not have to worry here
		char buf[1024 * 16];
		return -1;
typedef int (*open_istream_fn)(struct git_istream *,
#define read_method_decl(name) \
		if (!oi->u.packed.is_delta && big_file_threshold < size)

static void close_deflated_stream(struct git_istream *st)


	st = open_istream(the_repository, oid, &type, &sz, filter);
	    (parse_loose_header(st->u.loose.hdr, &st->size) < 0)) {
			memcpy(buf + filled, fs->obuf + fs->o_ptr, to_move);
		 * about running out of input bytes and spinning infinitely. If
		}
	}
enum input_source {
				kept += holeto;

	enum input_source src = istream_source(r, real, type, &oi);
{
			fs->i_ptr = fs->i_end - to_feed;
static read_method_decl(filtered)
		struct {
		return -1;
	struct git_istream *ifs = xmalloc(sizeof(*ifs));
	int result = -1;
};
		/* refill the input from the upstream */
	st->u.in_pack.pack = oi->u.packed.pack;
					  fs->obuf, &to_receive))
 *****************************************************************/
			return NULL;

			if (sz < to_move)
		return incore;
};
	while (total_read < sz) {
	}
	st->u.incore.buf = read_object_file_extended(r, oid, type, &st->size, 0);
	}

{
						struct stream_filter *filter)

static open_method_decl(loose);
	st->z_state = z_unused;
	size_t filled = 0;

{
		if (wrote < 0)
		}
	fs->upstream = st;
};
	ifs->vtbl = &filtered_vtbl;


			st->z_state = z_done;
	char obuf[FILTER_BUFFER];
	if (st->u.loose.hdr_used < st->u.loose.hdr_avail) {
	 struct object_info *oi, const struct object_id *oid, \
	return st->u.incore.buf ? 0 : -1;
		/* do we already have filtered output? */
 *****************************************************************/
	close_istream_loose,
	open_istream_incore,
		break;
 *
 * In-core stream
				return -1;


		goto close_and_exit;
	return 0;
	return 0;

		if (!readlen)
 * Non-delta packed object stream
{
		break;

		status = git_inflate(&st->z, Z_FINISH);
		unuse_pack(&window);
		 */
	if (src < 0)
			goto close_and_exit;
int close_istream(struct git_istream *st)
		total_read = st->z.next_out - (unsigned char *)buf;
#include "streaming.h"
				break;
	ssize_t kept = 0;
}
		st->z.next_out = (unsigned char *)buf + total_read;
			fs->o_ptr += to_move;
			git_inflate_end(&st->z);
typedef int (*close_istream_fn)(struct git_istream *);


			int hdr_used;
	fs->i_end = fs->i_ptr = 0;
	fs->o_end = fs->o_ptr = 0;
		memcpy(buf, st->u.loose.hdr + st->u.loose.hdr_used, to_copy);
			break;
	struct filtered_istream *fs = &(ifs->u.filtered);
}
	default:
	close_istream(st);
{
	}
}
	}
	struct filtered_istream *fs = &(st->u.filtered);
 ****************************************************************/
			void *mapped;

			int hdr_avail;
		int status;
}
		ssize_t readlen = read_istream(st, buf, sizeof(buf));
	(struct git_istream *st)
		fs->o_end = fs->o_ptr = 0;
	st->u.loose.hdr_avail = st->z.total_out;
	case OBJ_COMMIT:
		}
static read_method_decl(pack_non_delta)
	return 0;
#include "replace-object.h"

}
	read_istream_incore,
		} incore;
	close_deflated_stream(st);
				 st->u.loose.hdr,
	case z_error:
	}

 *
static open_method_decl(incore)
	switch (in_pack_type) {

		if (status == Z_STREAM_END) {
		mapped = use_pack(st->u.in_pack.pack, &window,
				return -1;
			if (stream_filter(fs->filter,
					    &st->u.in_pack.pos,
	if ((unpack_loose_header(&st->z,
		return -1;
		fs->i_end = fs->i_ptr = 0;
	switch (st->z_state) {
	size_t remainder = st->size - st->u.incore.read_ptr;
			if (fs->i_end < 0)
			break;
	(struct git_istream *st, char *buf, size_t sz)
{
	incore = 0,
		return result;
		return stream_error;
		st->z.next_in = mapped;
		struct {
 *
	read_istream_fn read;
			kept = 0;


			if (fs->i_end)

	st->u.loose.mapped = map_loose_object(r, oid, &st->u.loose.mapsize);
	enum { z_unused, z_used, z_done, z_error } z_state;
			continue;
	unsigned long size; /* inflated size of full object */
	*size = st->size;
struct stream_vtbl {

	for (;;) {
	read_istream_filtered,
 * Copyright (c) 2011, Google Inc.

	(struct git_istream *st, struct repository *r, \
		if (status != Z_OK && status != Z_BUF_ERROR) {
	union {
static close_method_decl(loose)

		if (open_istream_incore(st, r, &oi, real, type)) {
				 const struct object_id *oid,
	st->vtbl = &pack_non_delta_vtbl;
		}
		total_read = st->z.next_out - (unsigned char *)buf;
	munmap(st->u.loose.mapped, st->u.loose.mapsize);
	st->vtbl = &loose_vtbl;
 *
	const struct stream_vtbl *vtbl;
		}
			       struct object_info *,
	read_istream_pack_non_delta,

			st->z_state = z_error;

/*****************************************************************
	window = NULL;

	if (read_size) {
}
	case OBJ_TREE:
	if (type != OBJ_BLOB)
	struct object_info oi = OBJECT_INFO_INIT;
