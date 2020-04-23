					 state->nr_written, oid.hash,
			s.avail_in = rsize;

	if ((flags & HASH_WRITE_OBJECT) != 0)

	/* The object may already exist in the repository */
	if (!state->f)
 * by returning a negative value when the resulting pack would exceed
				/* would we bust the size limit? */
	struct hashfile *f;


					the_hash_algo->update_fn(ctx, ibuf, hsize);
		unlink(state->pack_tmp_name);
#include "repository.h"
	int i;
	s.next_out = obuf + hdrlen;
				    (int)rsize, path);

static int already_written(struct bulk_checkin_state *state, struct object_id *oid)

		}

		return 0;
		}
			}

 * Read the contents from fd for size bytes, streaming it to the
		}
		if (!stream_to_pack(state, &ctx, &already_hashed_to,
	if (state->nr_written == 0) {
	struct object_id oid;
				if (rsize < hsize)
	state.plugged = 1;
		close(fd);
#include "bulk-checkin.h"
 * Copyright (c) 2011, Google Inc.

	for (i = 0; i < state->nr_written; i++)
	free(state->written);
static int deflate_to_pack(struct bulk_checkin_state *state,
#include "strbuf.h"
	/* Make objects we just wrote available to ourselves */
		case Z_BUF_ERROR:
clear_exit:
	/* Note: idx is non-NULL when we are writing */
static struct bulk_checkin_state {
	the_hash_algo->update_fn(&ctx, obuf, header_len);
		status = git_deflate(&s, size ? 0 : Z_FINISH);
{
	strbuf_release(&packname);
	if (has_object_file(oid))

	if (!state->offset)
	int i;

		}
 * status before calling us just in case we ask it to call us again
	if (seekback == (off_t) -1)
{
 * by truncating it and opening a new one. The caller will then call
		       int fd, size_t size, enum object_type type,
			    &state->pack_idx_opts, oid.hash);
}
{
		state->offset = checkpoint.offset;
			   int fd, size_t size,
		 * pack, and write into it.
 */
				if (hsize)
	unsigned hdrlen;
	header_len = xsnprintf((char *)obuf, sizeof(obuf), "%s %" PRIuMAX,
			continue;
			   struct object_id *result_oid,
				size_t written = s.next_out - obuf;
		/*
				if (state->nr_written &&
	int write_object = (flags & HASH_WRITE_OBJECT);
	if (!(flags & HASH_WRITE_OBJECT) || state->f)
		 */
			return 1;
			      unsigned flags)
	state.plugged = 0;
			s.next_out = obuf;
void unplug_bulk_checkin(void)
}
				state->offset += written;
static void prepare_to_stream(struct bulk_checkin_state *state,
	state->f = create_tmp_packfile(&state->pack_tmp_name);
		prepare_to_stream(state, flags);
		die_errno("unable to write pack header");
			if (read_result != rsize)

#include "pack.h"
/*
		state->offset = checkpoint.offset;
	return 0;
		default:
static int stream_to_pack(struct bulk_checkin_state *state,
/* Lazily create backing packfile for the state */
	struct pack_idx_entry **written;
			if (*already_hashed_to < offset) {
static void finish_bulk_checkin(struct bulk_checkin_state *state)
				    pack_size_limit_cfg < state->offset + written) {
		int fd = finalize_hashfile(state->f, oid.hash, 0);
			if (read_result < 0)
		if (lseek(fd, seekback, SEEK_SET) == (off_t) -1)
		idx = xcalloc(1, sizeof(*idx));

	struct pack_idx_entry *idx = NULL;
{
			ssize_t rsize = size < sizeof(ibuf) ? size : sizeof(ibuf);
	git_hash_ctx ctx;
		hashfile_truncate(state->f, &checkpoint);
		 * Writing this object to the current pack will make
		finalize_hashfile(state->f, oid.hash, CSUM_HASH_IN_STREAM | CSUM_FSYNC | CSUM_CLOSE);
	/* Might want to keep the list sorted */
	git_deflate_end(&s);
		state->written[state->nr_written++] = idx;
			BUG("should not happen");
	git_deflate_init(&s, pack_compression_level);
	}
		oidcpy(&idx->oid, result_oid);
		finish_bulk_checkin(&state);
	return 0;

					return -1;
			  int fd, size_t size, enum object_type type,
	if (state.f)
				}
					 state->offset);

				size_t hsize = offset - *already_hashed_to;
} state;
			break;
		hashfile_truncate(state->f, &checkpoint);


	if (already_written(state, result_oid)) {
	char *pack_tmp_name;
			    state->written, state->nr_written,
}
	struct pack_idx_option pack_idx_opts;
	return status;
 * again. This way, the caller does not have to checkpoint its hash
			   unsigned flags)
				die_errno("failed to read from '%s'", path);

		return error("cannot find the current offset");
			offset += rsize;
	int status = deflate_to_pack(&state, oid, fd, size, type,
	s.avail_out = sizeof(obuf) - hdrlen;
			  const char *path, unsigned flags)
				die("failed to read %d bytes from '%s'",
		 * it too big; we need to truncate it, start a new
	while (1) {
	}
	memset(state, 0, sizeof(*state));
#include "csum-file.h"
	strbuf_addf(&packname, "%s/pack/pack-", get_object_directory());
		if (!idx)
		if (size && !s.avail_in) {
	uint32_t alloc_written;

			ssize_t read_result = read_in_full(fd, ibuf, rsize);
/*
{
	off_t seekback, already_hashed_to;

		       const char *path, unsigned flags)
	struct strbuf packname = STRBUF_INIT;
	finish_tmp_packfile(&packname, state->pack_tmp_name,
			return error("cannot seek back");
		if (oideq(&state->written[i]->oid, oid))
	reset_pack_idx_option(&state->pack_idx_opts);
		goto clear_exit;
	git_zstream s;
	for (i = 0; i < state->nr_written; i++)
 * so that the caller can discard what we wrote from the current pack
	} else {
int index_bulk_checkin(struct object_id *oid,
				    fd, size, type, path, flags))
	off_t offset = 0;
}

{
			hashfile_checkpoint(state->f, &checkpoint);
	hdrlen = encode_in_pack_object_header(obuf, sizeof(obuf), type, size);
	/* This is a new object we need to keep */
	if (!state.plugged)
 * the pack size limit and this is not the first object in the pack,
	if (!idx)
		ALLOC_GROW(state->written,
		close(state->f->fd);

		finish_bulk_checkin(&state);
}
					hsize = rsize;
		switch (status) {
}
	unsigned char obuf[16384];
	unsigned plugged:1;
	while (status != Z_STREAM_END) {
		return;
 */
	uint32_t nr_written;
	int status = Z_OK;
		case Z_OK:
 * The already_hashed_to pointer is kept untouched by the caller to
	off_t offset;
 *
			crc32_begin(state->f);
	return 0;
void plug_bulk_checkin(void)

			   state->nr_written + 1,
					git_deflate_abort(&s);

			   state->alloc_written);
	seekback = lseek(fd, 0, SEEK_CUR);
	struct hashfile_checkpoint checkpoint = {0};


#include "cache.h"
{
		finish_bulk_checkin(state);

				    pack_size_limit_cfg &&
}
	}
	already_hashed_to = 0;
				     path, flags);
		free(state->written[i]);
			die("unexpected deflate failure: %d", status);
			idx->offset = state->offset;
			if (write_object) {
 * make sure we do not hash the same byte when we are called
	unsigned header_len;
		if (!s.avail_out || status == Z_STREAM_END) {
		return 1;
}
		free(idx);
			  git_hash_ctx *ctx, off_t *already_hashed_to,
	/* Pretend we are going to write only one object */
	}
 * us again after rewinding the input fd.
		unsigned char ibuf[16384];
{
	unsigned char obuf[16384];
	state->offset = write_pack_header(state->f, 1);


		return;

#include "packfile.h"
			size -= rsize;
	the_hash_algo->final_fn(result_oid->hash, &ctx);

			s.next_in = ibuf;
	the_hash_algo->init_fn(&ctx);

			}
	} else {
 * packfile in state while updating the hash in ctx. Signal a failure
	idx->crc32 = crc32_end(state->f);
				hashwrite(state->f, obuf, written);
	reprepare_packed_git(the_repository);
		fixup_pack_header_footer(fd, oid.hash, state->pack_tmp_name,

			       type_name(type), (uintmax_t)size) + 1;

	} else if (state->nr_written == 1) {

			   enum object_type type, const char *path,
		if (idx) {
#include "object-store.h"
				*already_hashed_to = offset;
 * with a new pack.
			s.avail_out = sizeof(obuf);
		case Z_STREAM_END:

