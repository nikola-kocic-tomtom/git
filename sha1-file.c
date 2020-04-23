{
	if (co) {
 */
{
	init_recursive_mutex(&obj_read_mutex);
	return check_and_freshen_local(oid, freshen) ||
	errno = most_interesting_errno;
	finish_command(&cmd);
const struct git_hash_algo hash_algos[GIT_HASH_NALGOS] = {


	stream->avail_in = mapsize;
			check_tag(buf, size);
	ret = 0; /* everything checks out */
					   *contents, *size,
		do {
#include "tree.h"
		return PH_ERROR_EOF;
 * want read_object_file() to be able to return, but yet you do not want

	if (!alt_odb_usable(r->objects, &pathbuf, normalized_objdir)) {
		return 0;
			ref_type = "object ";

		struct strbuf sb = STRBUF_INIT;
	if (close(fd) != 0)
		type = OBJ_BLOB;
	if (!map)
		return 0;

			void *buffer, unsigned long bufsiz)
			     struct stat *st, const char **path)
	co->buf = xmalloc(len);
		ret = errno;
		/*
}
		    !is_absolute_path(sb.buf) ||


	the_hash_algo->init_fn(&c);
	if (size > 9)
	unsigned char *buf = xmallocz(size);
	if ((flags & OBJECT_INFO_ALLOW_UNKNOWN_TYPE) && (type < 0))
	return type;
		strbuf_add(header, buffer, stream->next_out - (unsigned char *)buffer);
	if (!oideq(oid, &parano_oid))
		stream->next_out = buffer;

	strbuf_release(&path);
	if (seen_error) {

	int i;
		strbuf_release(&pathbuf);
		cb(&oid, data);
	strbuf_release(&entry);
int fetch_if_missing = 1;
	fclose(fh);

				       unsigned int flags)
}
		 * error, so we have to rewrite the whole buffer from
	total_read = stream->total_out - strlen(hdr) - 1;
		if (the_repository->objects->loaded_alternates)
		argv_array_push(&cmd->args, repo_path);
	 */
	else if (errno != ENOENT)
static void *read_object(struct repository *r,
		if (!path_copy.len)
	 * caller doesn't care about the disk-size, since our
		die(_("corrupt tag"));
	 * We already read some bytes into hdr, but the ones up to the NUL
/*
		total_read += stream->next_out - buf;
cleanup:
	/*
{
	if (*end)
out:
		if (type == required_type) {
	/* Make sure we have the terminating NUL */
	if (!r && subdir_cb)
#endif
				each_loose_subdir_fn subdir_cb,


{

				       struct object_info *oi, unsigned flags)
		0x00000000,
		die(_("%s is not a valid '%s' object"), oid_to_hex(oid),
{
	static struct strbuf tmp_file = STRBUF_INIT;

{
	obj_read_lock();
}
		    unsigned long *sizep)
		char c = *hdr++;
	return check_and_freshen_nonlocal(oid, 0);
 * We want to avoid cross-directory filename renames, because those
{
	 */
			break;
	if (strbuf_normalize_path(&objdirbuf) < 0)
	git_hash_ctx c;
			break;
	if (!limit) {
	if (!pack_version_ok(header->hdr_version))
		goto out;
	if (status < Z_OK)
/*
		if (!o_cloexec && 0 <= fd && fd_cloexec) {
		oi->sizep = NULL;
		if (type == OBJ_TREE)
			*size = xsize_t(st.st_size);
	while ((de = readdir(dir))) {
/*



{
			promisor_remote_get_direct(r, real, 1);
	while (git_deflate(&stream, 0) == Z_OK)
		if (!fspathcmp(path->buf, odb->path))
	return ret;
}
				  void *data)
	} else if (errno == ENOENT && create_directories_remaining-- > 0) {
	oi->whence = OI_LOOSE;
static void close_loose_object(int fd)
			return error(_("%s: failed to insert into database"),
}
		    const struct object_id *oid,
			continue;
		munmap(map, mapsize);

		strbuf_add(oi->type_name, type_buf, type_len);
		 */
	stream->avail_out = bufsiz;
		if (!(flags & HASH_WRITE_OBJECT))
static int check_and_freshen_nonlocal(const struct object_id *oid, int freshen)
	int ret, save_errno;
static int refs_from_alternate_cb(struct object_directory *e,
	/*

	assert(path);
				each_loose_cruft_fn cruft_cb,
/*
		NULL,
	 */
	 * option.
static int unpack_loose_header_to_strbuf(git_zstream *stream, unsigned char *map,
				 int freshen)
	loose_object_path(the_repository, &filename, oid);

		}
{
}
	return s - filename + 1;
 * Like stat_loose_object(), but actually open the object and return the
		strbuf_addf(err, _("reference repository '%s' is not a "
		return do_oid_object_info_extended(r, real, oi, 0);
			return NULL;
		return -1;
}
{
		    !hex_to_bytes(oid.hash + 1, de->d_name,
{
			git_inflate_end(&stream);
{
				     path);


 * Return non-zero iff the path is usable as an alternate object database.
static struct cached_object *find_cached_object(const struct object_id *oid)
/*
	if (obj_read_use_lock)
#include "list.h"
	struct alternate_refs_data cb;
	}
	}
		cmd->use_shell = 1;
	convert_to_git_filter_fd(istate, path, fd, &sbuf,
	if (ret != Z_STREAM_END)
	 * buffer[0..bufsiz] was not large enough.  Copy the partial
		die(_("attempting to mmap %"PRIuMAX" over limit %"PRIuMAX),
	if (!ret)
static int quick_has_loose(struct repository *r,

	 * a space.


}

	prepare_alt_odb(r);
static void git_hash_sha256_final(unsigned char *hash, git_hash_ctx *ctx)
int repo_has_object_file_with_flags(struct repository *r,
	if (oideq(oid, the_hash_algo->empty_tree))
			break;
	enum scld_error ret = SCLD_OK;
 * SHA1, an extra slash for the first level indirection, and the
			if (actual_oid_return)

	char *path;

		die(_("packed object %s (stored in %s) is corrupt"),
		 * tree_entry() will die() on malformed entries */

		if (mkdir(tmp->buf, 0777) && errno != EEXIST)
		if (!stat(path, &st)) {
	if (object_creation_mode == OBJECT_CREATION_USES_RENAMES)
			goto out;
	struct strbuf sb = STRBUF_INIT;
		fd = open(path, O_RDONLY);
		 * We know that the caller doesn't actually need the
	EMPTY_BLOB_SHA256_BIN_LITERAL
	int ret;
	}
				       oid_to_hex(oid));
			return error_errno(_("unable to create temporary file"));

			 const struct object_id *oid, enum object_type *type,

{
	the_hash_algo->update_fn(&c, hdr, hdrlen);
	int fd;
		strbuf_release(&sb);
}
	enum object_type type;
		static int fd_cloexec = FD_CLOEXEC;
		ret = index_pipe(istate, oid, fd, type, path, flags);
	const char *value;
	 * do not count against the object's content size.
int git_open_cloexec(const char *name, int flags)
			*oi->contentp = xmemdupz(co->buf, co->size);
	int seen_error = 0;
				ret = SCLD_VANISHED;
	return r;
/* returns enum object_type or negative */
	struct strbuf objdirbuf = STRBUF_INIT;

	while (strbuf_getline_lf(&line, fh) != EOF) {
	int status = Z_OK;

	for (odb = the_repository->objects->odb; odb; odb = odb->next) {
	else if (stream->avail_in)
		goto try_rename;


	mmap_limit_check(length);
		return data;
	return NULL;
	if (!(flags & HASH_WRITE_OBJECT))
}
					oid);
{


		ret = index_mem(istate, oid, "", size, type, path, flags);

			free(*contents);
}
/*
		struct stat st;
	return (status < 0) ? status : 0;
const struct object_id null_oid;
		if (size - total_read < stream->avail_out)
 * 'filename'
	 * The same holds for FAT formatted media.


 * Note that it may point to static storage and is only valid until another
			}
		strbuf_addch(&pathbuf, '/');
			  enum for_each_object_flags flags)
#define SMALL_FILE_SIZE (32*1024)
	return NULL;
	/*
}
	if (!stat_loose_object(r, repl, &st, &path))
			   const struct object_id *oid)
	}


	BUG("trying to finalize unknown hash");
	/*
 * 0, you should not assume that it is safe to skip a write of the object (it
	return ret;
	unsigned long mapsize;
	cb.fn = fn;
char *compute_alternate_path(const char *path, struct strbuf *err)
		return 0;
	return ref_git;
				      "checkout is not supported yet."),
	return -1;
	return ret;
	int fd;

	else
		return error(_("%s: unsupported file type"), path);
	if (type == OBJ_BLOB && path && would_convert_to_git_filter_fd(istate, path))
			    !stat(path, &st) && S_ISDIR(st.st_mode))
		if (fd < 0)
 * Copyright (C) Linus Torvalds, 2005
{
		stream.next_out = compressed;
	/* type string, SP, %lu of the length plus NUL must fit this */
	if ((type == OBJ_BLOB) && path) {
}
	FILE *fh;
	if (freshen && !freshen_file(fn))
	if (!freshen_file(e.p->pack_name))

					       buffer, bufsiz);
	if (adjust_shared_perm(filename))
	oi.sizep = sizep;

		git_inflate_end(&stream);
	int fd, ret;
static const char *parse_alt_odb_entry(const char *string,
		ref_length = strlen(ref_type);
			die_errno(_("unable to move new alternates file into place"));
	memcpy(co->buf, buf, len);
	*type = parse_loose_header(hdr, size);
	strbuf_reset(out);
		FREE_AND_NULL(ref_git);
void assert_oid_type(const struct object_id *oid, enum object_type expect)
		return 0;

	return fd;

			r = cruft_cb(de->d_name, path->buf, data);
	obj_read_unlock();
			limit = SIZE_MAX;
	if (status != Z_STREAM_END) {

{
static int freshen_loose_object(const struct object_id *oid)
	if (!repo && is_directory(mkpath("%s/.git/objects", ref_git))) {

		/*
	}
				 * just removed.  Either way, inform

	/* Sha1.. */
	 * Make sure alternates are initialized, or else our entry may be

 */
}
#include "tag.h"

		strbuf_addch(buf, hex[val >> 4]);

{
 * result, which we need to know beforehand when writing a git object.
				enum object_type *type,
};
	int r = 0;
	struct object_id oid;
			return 1;
static void check_commit(const void *buf, size_t size)
		    !already_retried && r == the_repository &&
			r = error_errno(_("unable to open %s"), path->buf);
	algo->init_fn(&c);
	void *buf;
 * object name actually matches "oid" to detect object corruption.
	 * return value implicitly indicates whether the
		 * Make sure the directory exists; note that the contents

	return oid_to_hex_r(buf, the_hash_algo->empty_tree);
		void *buf = xmmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);


static int index_pipe(struct index_state *istate, struct object_id *oid,
	 * need to look inside the object at all. Note that we

			      oid_to_hex(expected_oid));
		      oid_to_hex(expected_oid));
	}
		if (!git_config_get_value("core.alternateRefsPrefixes", &value)) {
	while (1) {
	if (parse_commit_buffer(the_repository, &c, buf, size, 0))
		/* do nothing
	} else {
static const struct object_id empty_blob_oid = {
	 */
	odb->loose_objects_subdir_seen[subdir_nr] = 1;


		hash_object_file(r->hash_algo, map, size, type, &real_oid);
		error(_("unable to unpack header of %s"), path);
		if (!rename(tmpfile, filename))
		if (fd >= 0)

	in = fopen(alts, "r");
		limit = git_env_ulong("GIT_MMAP_LIMIT", 0);
{
		}

	const struct object_id *real = oid;
		    oid_to_hex(repl), oid_to_hex(oid));
		ret = hash_object_file(the_hash_algo, buf, size,
		}
	}

	assert(*path);
static void read_alternate_refs(const char *path,
	int hdrlen, status = 0;

		goto cleanup;
		 * whose original repository does not yet have it?
	if (repl != oid)
	return ret;
static int create_tmpfile(struct strbuf *tmp, const char *filename)
		return error(_("cannot read object for %s"), oid_to_hex(oid));
	fd = create_tmpfile(&tmp_file, filename.buf);
	void *map;
		seen_error = 1;
		int ref_length = -1;
	 * The type can be of any size but is followed by
			buf = strbuf_detach(&nbuf, &size);
	 */
		 * consumed all the input to reach the expected size;
			       void *data)
		struct strbuf sb = STRBUF_INIT;

		/* Most likely it's a loose object. */

				 * the file that was in our way was
static void git_hash_sha256_init(git_hash_ctx *ctx)

	write_object_file_prepare(the_hash_algo, buf, len, type, oid, header,
	if (!buf)
	char *header;
				r = obj_cb(&oid, path->buf, data);
{
		return 1;
void *map_loose_object(struct repository *r,
{

	const char *s = strrchr(filename, '/');
	while (*alt) {
	origlen = path->len;

}
}
				break;
{
	struct object_id actual_oid;
	 */
}
/*

static int unpack_loose_short_header(git_zstream *stream,
				       oid_to_hex(oid));
				int lookup_replace)
	close(fd);
	if (flags & HASH_RENORMALIZE)
	else if (flags & HASH_WRITE_OBJECT)
	obj_read_unlock();
}
struct oid_array *odb_loose_cache(struct object_directory *odb,
			status = error(_("unable to unpack %s header with --allow-unknown-type"),
const char *empty_blob_oid_hex(void)
		return -1;
	co->size = len;
		 (path && would_convert_to_git(istate, path)))
			re_allocated = 1;
	struct object_directory *odb;
	*hdrlen = xsnprintf(hdr, *hdrlen, "%s %"PRIuMAX , type, (uintmax_t)len)+1;
			return 0;
				  void *data)
 * whose contents is similar to that environment variable but can be
}
	if (strbuf_read(&sbuf, fd, 4096) >= 0)
	struct pack_entry e;
	size = *hdr++ - '0';
	}
		 * an entry that doesn't end with a quote) falls
	}
	if (subdir_nr < 0 ||
		strbuf_addf(err, _("path '%s' does not exist"), path);
	 * overwritten when they are.
			goto retry_fn;
	if (!find_pack_entry(the_repository, oid, &e))
		error(_("hash mismatch for %s (expected %s)"), path,
	size_t origlen, baselen;
	if (r->objects->loaded_alternates)
		if (r)
	static struct object_info blank_oi = OBJECT_INFO_INIT;
	algo->final_fn(oid->hash, &c);
		fd = open(name, flags | o_cloexec);
}
	if (!memchr(buffer, '\0', stream->next_out - (unsigned char *)buffer))
}
	strbuf_setlen(path, baselen - 1);
				      const char *type, struct object_id *oid,
	strbuf_release(&sbuf);
	       sizeof(odb->loose_objects_subdir_seen));
					const char *repo_path)
	if (fd < 0) {
	status = unpack_loose_short_header(stream, map, mapsize, buffer, bufsiz);
static int parse_loose_header_extended(const char *hdr, struct object_info *oi,

{
					 blob_type, oid);
		unsigned char *in0 = stream.next_in;
}

}
		o_cloexec &= ~O_CLOEXEC;
	pthread_mutex_destroy(&obj_read_mutex);
	while (1) {
	static struct strbuf buf = STRBUF_INIT;
 */
{
	struct strbuf buf = STRBUF_INIT;
	return oid_to_hex_r(buf, the_hash_algo->empty_blob);
}
				alternate_ref_fn *cb,
static void read_info_alternates(struct repository *r,
const char *empty_tree_oid_hex(void)
static inline int directory_size(const char *filename)


		return error(_("unable to set permission to '%s'"), filename);
 * This creates one packfile per large blob unless bulk-checkin
			enum object_type type, const char *path,
 * This function dies on corrupt objects; the callers who want to

		error(_("object directory %s does not exist; "
			else
static int loose_object_info(struct repository *r,
static int index_mem(struct index_state *istate,
{
		argv_array_push(&cmd->args, value);
#include "sha1-lookup.h"
	return 0;

	{ EMPTY_TREE_SHA1_BIN_LITERAL },

			/*
	git_inflate_init(stream);
		oid_array_clear(&odb->loose_objects_cache[i]);
int for_each_loose_file_in_objdir_buf(struct strbuf *path,
	void *content;

			       const struct object_id *oid)
	} else {
	return 0;
}
static void git_hash_sha1_init(git_hash_ctx *ctx)

	"\x47\x3a\x0f\x4c\x3b\xe8\xa9\x36\x81\xa2" \

		return 0;
int foreach_alt_odb(alt_odb_fn fn, void *cb)
	/*
		 * Maybe the containing directory didn't exist, or
}
 * We used to just use "sscanf()", but that's actually way
	write_object_file_prepare(the_hash_algo, buf, len, type, oid, hdr,
	 * trying to create them.
	}
	struct object_id parano_oid;
}
{
	int rtype;
	if (start_command(&cmd))
{
 * somewhat complicated, as we do not know the size of the filter
/*
{
		if (fetch_if_missing && has_promisor_remote() &&
				       int sep,
	}

 * Find "oid" as a loose object in the local repository or in an alternate.
	/*
			       oid_to_hex(oid));
{
		if (format_id == hash_algos[i].format_id)
}
		 */
	return 0;
}
static void fill_loose_path(struct strbuf *buf, const struct object_id *oid)

	git_zstream stream;
static const struct object_id empty_tree_oid_sha256 = {
static void git_hash_unknown_update(git_hash_ctx *ctx, const void *data, size_t len)
	}
 */
	if (!out)
	return rc;
	do {
			 unsigned long *size)
	strbuf_release(&line);
		if (oi->disk_sizep)
#if defined(F_GETFD) && defined(F_SETFD) && defined(FD_CLOEXEC)
	for (;;) {
	 */
	 * decimal format (ie "010" is not valid).
	fill_loose_path(buf, oid);
		if (commit_lock_file(&lock))
static int check_and_freshen_local(const struct object_id *oid, int freshen)
}
			else if (errno == ENOENT)
	int prot, int flags, int fd, off_t offset)
	r->hash_algo->init_fn(&c);

}
}
	errno = 0;
void odb_clear_loose_cache(struct object_directory *odb)
int unpack_loose_header(git_zstream *stream,
	char hdr[MAX_HEADER_LEN];
	stream->avail_out = bufsiz;
	map = NULL;
int mkdir_in_gitdir(const char *path)
		if (r)

		namelen = strlen(de->d_name);
	return *hdr ? -1 : type;
	return ret;
				   get_conv_flags(flags))) {
	return ret;

			return co;
		git_hash_sha256_clone,
		(status == Z_BUF_ERROR && !stream->avail_out))) {
	struct strbuf path = STRBUF_INIT;
{
				 const char *required_type_name,
		if (get_common_dir(&sb, ref_git)) {
	return r;
			if (obj_cb) {
		fd = git_open(*path);

 * The variable alt_odb_list points at the list of struct
		fprintf_or_die(out, "%s\n", reference);
	void *buf;


	/*
	oidcpy(&co->oid, oid);
		die(_("unable to normalize object directory: %s"),
		if (find_pack_entry(r, real, &e))
	free(path);
			link_alt_odb_entries(the_repository, reference,
};
		if (oi->sizep)
			break;
				  each_loose_subdir_fn subdir_cb,
	 "\x4b\x82\x5d\xc6\x42\xcb\x6e\xb9\xa0\x60" \


#include "streaming.h"
 *
				  each_loose_object_fn obj_cb,
		}

}
	int remove_directories_remaining = 1;

{
	if (!startup_info->have_repository)
	else if (st->st_size <= big_file_threshold || type != OBJ_BLOB ||
	/*

	 */
	oi.typep = &type;
				      char *hdr, int *hdrlen)
	unsigned char buf[4096];
		    mkdir(sb.buf, 0777)) {

		free(buffer);
}
		repo = read_gitfile(mkpath("%s/.git", ref_git));

	EMPTY_TREE_SHA256_BIN_LITERAL
		 */
	link_alt_odb_entries(r, r->objects->alternate_db, PATH_SEP, NULL, 0);
	return -1;
	else

			if (errno == EEXIST &&
		git_hash_sha256_update,
}
	 * in the way of path. This is only 1 because if another
{
					     '\n', NULL, 0);
				break;
	int already_retried = 0;
}
	free(header);
	struct strbuf pathbuf = STRBUF_INIT;
	r->hash_algo->update_fn(&c, hdr, hdrlen);
{
	strbuf_reset(tmp);
			ref_type = "tree ";
	prepare_alt_odb(the_repository);
		r->hash_algo->update_fn(&c, buf, readlen);
}
		if (!*oi->contentp) {

	if (fd >= 0) {
	data = read_object(r, repl, type, size);
			unsigned flags)
	const struct packed_git *p;
	if (ret) {
			hdr++;
	int ret, re_allocated = 0;
				 type, path, flags);
}
		if (!(flags & OBJECT_INFO_QUICK)) {
} *cached_objects;
					  path ? path : "<unknown>");
		}
	type = type_from_string_gently(type_buf, type_len, 1);
		free(ref_git);
	}
	header = xmalloc(hdrlen);
	int i;
static void link_alt_odb_entries(struct repository *r, const char *alt,
	}
	stream->next_out = buffer;
		ret = index_stream_convert_blob(istate, oid, fd, path, flags);

	int status;
		r = subdir_cb(subdir_nr, path->buf, data);
			"check .git/objects/info/alternates"),
	return 1;

	static struct strbuf buf = STRBUF_INIT;

 * `err` must not be null.
{
				/*
		if (adjust_shared_perm(tmp->buf))

	return map;
	for (odb = r->objects->odb; odb; odb = odb->next) {
{

}
		return r;
	if (subdir_nr > 0xff)
		      path->buf);
				       type_name(OBJ_BLOB), oid);
	static struct strbuf path = STRBUF_INIT;
int check_object_signature(struct repository *r, const struct object_id *oid,


	int ret;
{
	 "\xe5\x4b\xf8\xd6\x92\x88\xfb\xee\x49\x04"
		} else if (adjust_shared_perm(path)) {
			return quick_has_loose(r, oid) ? 0 : -1;

static int write_buffer(int fd, const void *buf, size_t len)
	int status = 0;
static void git_hash_sha1_clone(git_hash_ctx *dst, const git_hash_ctx *src)
		if (!entry.len)
}
	if (depth > 5) {
 * descriptor. See the caveats on the "path" parameter above.

	} else {
		GIT_SHA1_RAWSZ,
	return index_bulk_checkin(oid, fd, size, type, path, flags);
		fclose(in);

	return 0;
			return -1;
		goto out;
		if (!limit)

		ret = write_object_file(buf, size, type_name(type), oid);
				fd_cloexec = 0;
			hash_object_file(the_hash_algo, sb.buf, sb.len,

		strbuf_release(&pathbuf);
int parse_loose_header(const char *hdr, unsigned long *sizep)
		}
	int ret;
	BUG("trying to clone unknown hash");
		error(_("unable to normalize alternate object path: %s"),
	struct alternate_refs_data *cb = data;
			    const char *path,
{
		git_hash_unknown_update,
		while (status == Z_OK) {
		     const char *path, unsigned flags)

	cb.data = data;
	if (write_in_full(fd, buf, len) < 0)

	"",

		     enum object_type type,
		if (namelen == the_hash_algo->hexsz - 2 &&
static void git_hash_unknown_final(unsigned char *hash, git_hash_ctx *ctx)
		    objdirbuf.buf);
				     struct object_id *oid,
	 * If we don't care about type or size, then we don't
	return 0;
{
			int flags = fcntl(fd, F_GETFD);
 * tree file and to avoid mmaping it in core is to deal with large
	if (oi->delta_base_oid)
				  each_loose_cruft_fn cruft_cb,
			    path);
	{
	memset(&c, 0, sizeof(c));


		goto out;
	/* Set it up */
	int hdrlen = sizeof(hdr);

	t.actime = t.modtime = time(NULL);
}
		return resolve_gitlink_ref(path, "HEAD", oid);

		/* Try again */
		real = lookup_replace_object(r, oid);
		}
	if (!obj_read_use_lock)

	}

		argv_array_push(&cmd->args, "--format=%(objectname)");
	if (ret != Z_OK)
		if (!remove_dir_recursively(&path_copy, REMOVE_DIR_EMPTY_ONLY))
out:
		obj_read_unlock();
}
		goto out;

	 * process is racily creating directories that conflict with
void add_to_alternates_file(const char *reference)


		}
				close(fd);
static int index_core(struct index_state *istate,
	munmap(map, mapsize);

	unsigned long n;
}
}
static void git_hash_sha256_clone(git_hash_ctx *dst, const git_hash_ctx *src)
#define EMPTY_TREE_SHA256_BIN_LITERAL \
	 */
		     unsigned long len, const char *type,
	r->objects->loaded_alternates = 1;
	baselen = path->len;
int pretend_object_file(void *buf, unsigned long len, enum object_type type,
		"sha1",
static void write_object_file_prepare(const struct git_hash_algo *algo,

		;
		      const struct object_id *expected_oid,
	hdrlen = xsnprintf(hdr, sizeof(hdr), "%s %"PRIuMAX , type_name(type), (uintmax_t)len) + 1;

}
	strbuf_release(&buf);
	strbuf_setlen(&path, base_len);
			return i;
int read_loose_object(const char *path,
	/* add the alternate entry */
		strbuf_release(&sb);
	const char *repo;
	if (status >= 0 && oi->contentp) {
	hold_lock_file_for_update(&lock, alts, LOCK_DIE_ON_ERROR);
	}
	 *
		 * A directory is in the way. Maybe it is empty; try

			    each_loose_subdir_fn subdir_cb,
		strbuf_addstr(tmp, "/tmp_obj_XXXXXX");
{
				void *data)
	}
	else if (link(tmpfile, filename))
	if (length > limit)
	{
		      int fd, enum object_type type,
	/*

	return map_loose_object_1(r, NULL, oid, size);
	struct object_directory *ent;

			fprintf_or_die(out, "%s\n", line.buf);
	for (i = 0; i < ARRAY_SIZE(odb->loose_objects_cache); i++)
		 * maybe it was just deleted by a process that is
 */
#include "bulk-checkin.h"
 * machinery is "plugged".
		    oid_to_hex(repl), path);
		return CONV_EOL_RENORMALIZE;
			return fd;
static int index_stream(struct object_id *oid, int fd, size_t size,
{
	if (*string == '#') {
	}
/*
		char *buf = xmalloc(size);
	void *ret = xmmap_gently(start, length, prot, flags, fd, offset);
	if (!ref_git) {
		 * expect no more output and set avail_out to zero,
	if (freshen_packed_object(oid) || freshen_loose_object(oid))
#include "string-list.h"
	 * directories containing path. We are willing to attempt this
	/*
	dir = opendir(path->buf);
	/*
	if ((flags & OBJECT_INFO_ALLOW_UNKNOWN_TYPE)) {
		 * Otherwise we would not be able to test that we
	unsigned long size;
 * environment variable, and $GIT_OBJECT_DIRECTORY/info/alternates,
	required_type = type_from_string(required_type_name);
	"\x3b\x14\xb4\xb9\xb9\x39\xdd\x74\xde\xcc" \
		return;
{
#include "promisor-remote.h"
/* The maximum size for an object header. */
	/*
#include "cache.h"
static int link_alt_odb_entry(struct repository *r, const char *entry,
		git_hash_unknown_final,
 * either does not exist on disk, or has a stale mtime and may be subject to
			already_retried = 1;
{
{
	 * see the comment in unpack_loose_rest for details.
{
		      unsigned long *size,

static int index_stream_convert_blob(struct index_state *istate,

		if (flags & FOR_EACH_OBJECT_LOCAL_ONLY)
	obj_read_lock();
		if (check_object_signature(the_repository, expected_oid,

	oidcpy(&actual_oid, oid);

{
			return 0;

			return 1;
	       check_and_freshen_nonlocal(oid, freshen);
		struct stat st;
	}
		die(_("invalid object type"));
	memcpy(buf, (char *) buffer + bytes, n);
		return 0;

{
	struct object_id real_oid;
		    type_name(expect));

		return !oideq(oid, &real_oid) ? -1 : 0;
		 * of the buffer are undefined after mkstemp returns an
{
 * too permissive for what we want to check. So do an anal
	if (!size) {
		fd = git_open(path);
		    oid_to_hex(oid));


{

				 * directory, or stat() failed because
	unsigned long total_read;

	 *
		return -1;
		status = git_inflate(stream, Z_FINISH);

{
		return;
		stream->next_out = buf + bytes;
		struct strbuf nbuf = STRBUF_INIT;

	 * this function at the end. Remove duplicates.
 * terminating NUL.
	return 1;
	if (oi->disk_sizep)
		      struct object_id *oid, int fd, size_t size,
		die_errno(_("unable to fdopen alternates lockfile"));


		const char *p;
		/* comment; consume up to next separator */
	} else if (size <= SMALL_FILE_SIZE) {

}
	int r;
	struct dirent *de;
	ret = mmap(start, length, prot, flags, fd, offset);

{

				    path ? path : "<unknown>");
		}
	return !utime(fn, &t);
		*oi->contentp = unpack_loose_rest(&stream, hdr,
			error(_("hash mismatch for %s (expected %s)"), path,
				goto retry_fn;
			*(oi->sizep) = co->size;
			status = git_inflate(stream, Z_FINISH);
	return 0;
	link_alt_odb_entries(the_repository, reference,
		return;
}
			if (fcntl(fd, F_SETFD, flags | fd_cloexec))
	 * left to unlink.
	}
	       const char *path, struct stat *st, unsigned flags)
		return -1;
	struct strbuf sbuf = STRBUF_INIT;
		 * scratch.
void *read_object_with_reference(struct repository *r,
	enum scld_error result = safe_create_leading_directories(buf);
		GIT_SHA1_HEXSZ,
			map = xmmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
};
static struct cached_object {
}
	char hdr[MAX_HEADER_LEN];
	void *map = NULL;
	if (oid_object_info_extended(r, oid, &oi, 0) < 0)
		 * the input zlib stream may have bytes that express
		0x73686131,
		git_hash_sha1_init,
			return -1;
	buf = read_object(the_repository, oid, &type, &len);
	/*
{
		GIT_SHA256_HEXSZ,
			return NULL;
	struct object_directory *odb;
	return parse_loose_header_extended(hdr, &oi, 0);
	*contents = NULL;
		slash_character = *slash;
		} else if (mkdir(path, 0777)) {
		goto out;
	char hdr[MAX_HEADER_LEN];
		error(_("garbage at end of loose object '%s'"),
	if (map) {
		git_hash_sha1_final,
{
int oid_object_info_extended(struct repository *r, const struct object_id *oid,
		git_hash_sha1_update,
		return 0;
	else if (!S_ISREG(st->st_mode))
	free(buf);
		error(_("corrupt loose object '%s'"), oid_to_hex(expected_oid));
	if (!oi)
	if (ret && ret != EEXIST) {
	map = map_loose_object(r, oid, &mapsize);
	struct object_info oi = OBJECT_INFO_INIT;
/* Returns 1 if we have successfully freshened the file, 0 otherwise. */
{
			free(buffer);
	static int o_cloexec = O_CLOEXEC;
			 const struct object_id *oid)
}
	if (!strbuf_realpath(&path, e->path, 0))

		strbuf_reset(tmp);
 *
	if (oi == &blank_oi)
	git_inflate_end(stream);
	the_hash_algo->final_fn(parano_oid.hash, &c);
	const char *relative_base, int depth, const char *normalized_objdir)
	if (parse_tag_buffer(the_repository, &t, buf, size))
int hash_algo_by_name(const char *name)
{
static int check_and_freshen(const struct object_id *oid, int freshen)

		stream->avail_out = bufsiz;
 * non-empty elements from colon separated ALTERNATE_DB_ENVIRONMENT
		fd = git_mkstemp_mode(tmp->buf, 0444);
	if (!access(mkpath("%s/info/grafts", ref_git), F_OK)) {



};
		oi->sizep = &size_scratch;
		ret = hash_object_file(the_hash_algo, sbuf.buf, sbuf.len,
		return;
		if (!*contents) {
	}
				     const char *path,
		if (ret != EEXIST) {
		}
}
	void *buffer;
		}
		die(_("loose object %s (stored in %s) is corrupt"),
 * Since the primary motivation for trying to stream from the working
}
			continue;
	}
		die_errno(_("error when closing loose object file"));
}
	e.p->freshened = 1;
	}
		ret = index_stream(oid, fd, xsize_t(st->st_size), type, path,
			strbuf_addf(err,
		alt = parse_alt_odb_entry(alt, sep, &entry);
}
	}
	if (!repo)

	alternate_ref_fn *fn;
		if (!readlen)

 */
				  struct strbuf *buf,
				ret = SCLD_EXISTS;
	if (type != expect)
	if (status && oi->typep)
	int fd, dirlen = directory_size(filename);
#include "delta.h"
{
		 * went well with status == Z_STREAM_END at the end.
	}
				if (r)
		goto out;
	int bytes = strlen(buffer) + 1;
	struct strbuf line = STRBUF_INIT;
{

	"\x29\xae\x77\x5a\xd8\xc2\xe4\x8c\x53\x91"
		ret = index_mem(istate, oid, buf, size, type, path, flags);
	if (write_object)
	strbuf_release(&hdrbuf);
	int status = unpack_loose_short_header(stream, map, mapsize,

		/*
		 * The above condition must be (bytes <= size), not
	}
	enum object_type obj_type;
	 * die() for large files.
	for (odb = o->odb; odb; odb = odb->next) {

	 * The number of times we will try to remove empty directories
	return check_and_freshen(oid, 1);
		 * back to the unquoted case below.
	 * The trailing slash after the directory name is given by
		if (memchr(buffer, '\0', stream->next_out - (unsigned char *)buffer))
	return &odb->loose_objects_cache[subdir_nr];
	 */
			die(_("unable to write loose object file"));
		if (strbuf_readlink(&sb, path, st->st_size))
	ret = write_loose_object(oid, hdr, hdrlen, buf, len, mtime);
	int r = 0;

	if (!map) {
				 unsigned long *size,
	strbuf_addch(buf, '/');
		type = 0;
int oid_object_info(struct repository *r,
	void *data;
	struct object_directory *odb;
	co = &cached_objects[cached_object_nr++];
	return 1;
}
		ssize_t read_result = read_in_full(fd, buf, size);
	}
}
		    ret);
	return -1;
	}
		oi->u.packed.pack = e.p;
	stream.avail_in = len;
			rc = error(_("%s: failed to insert into database"), path);
{
		} while (scld_result == SCLD_VANISHED && create_directories_remaining-- > 0);
{
	 * it out into .git/objects/??/?{38} file.
		git_hash_unknown_init,
	hdrlen = xsnprintf(hdr, sizeof(hdr), "%s %"PRIuMAX , type_name(obj_type), (uintmax_t)size) + 1;

	strbuf_setlen(path, origlen);
		if (type == OBJ_COMMIT)
#include "dir.h"
	     enum object_type type, const char *path, unsigned flags)
			 * TODO return value and stopping on error here.
	case S_IFREG:
 * This is meant to hold a *small* number of objects that you would
	if (!type)
		*contents = unpack_loose_rest(&stream, hdr, *size, expected_oid);
	struct object_directory *ent;
		    ret);
			 * TODO Investigate checking promisor_remote_get_direct()
	if (!s)
}
			unsigned long c = *hdr - '0';
	char *next_component = path + offset_1st_component(path);
 */
			strbuf_addstr(&path_copy, path);
				 const char *relative_base,
	}
 * object header parse by hand.

static void mmap_limit_check(size_t length)
	prepare_alt_odb(the_repository);
}
		0,
		      oid_to_hex(expected_oid));
	the_hash_algo->update_fn(&c, hdr, stream->total_out);
		if (most_interesting_errno == ENOENT)
		obj_read_lock();
	struct strbuf path_copy = STRBUF_INIT;
				     void *buffer, unsigned long bufsiz)

int hash_algo_by_length(int len)
 * functions and insert that before feeding the data to fast-import
	while (pathbuf.len && pathbuf.buf[pathbuf.len - 1] == '/')
		}
				   flags);
{
	 */
	if (type < 0)
			if (!strcmp(reference, line.buf)) {
				       const struct object_id *oid,
	save_errno = errno;
	if (odb->loose_objects_subdir_seen[subdir_nr])
		 * we also want to check that zlib tells us that all
static const struct object_id empty_tree_oid = {
	if (errno == EISDIR && remove_directories_remaining-- > 0) {
			break;

	unsigned char compressed[4096];
	}
		error(_("garbage at end of loose object '%s'"),
 * purpose. We could write a streaming version of the converting
		if (!fstat(fd, &st)) {
	rtype = packed_object_info(r, e.p, e.offset, oi);
}
	}
	cmd->out = -1;
		if (!strcmp(name, hash_algos[i].name))
	if (!oi->typep && !oi->type_name && !oi->sizep && !oi->contentp) {
static int write_loose_object(const struct object_id *oid, char *hdr,
	/* First header.. */
		type_len++;
{

		git_inflate_end(&stream);
{
	oid_array_append(data, oid);
			return error_errno("open(\"%s\")", path);
	int r = 0;
		ssize_t readlen = read_istream(st, buf, sizeof(buf));
	return !oideq(oid, &real_oid) ? -1 : 0;
				 */
}
			continue;
				  &hdrlen);
		 * "this concludes the stream", and we *do* want to

			 */
				 struct object_id *actual_oid_return)
	EMPTY_TREE_SHA1_BIN_LITERAL
	unsigned long mapsize;
	if (path)
	if (bytes <= size) {
static int alt_odb_usable(struct raw_object_store *o,
		return &empty_tree;
		goto out;
 */
		ret = index_mem(istate, oid, sbuf.buf, sbuf.len, type, path, flags);
		oi->u.packed.is_delta = (rtype == OBJ_REF_DELTA ||
		free(path);
	unsigned long size_scratch;
				void *data)
	foreach_alt_odb(refs_from_alternate_cb, &cb);
			scld_result = safe_create_leading_directories(path_copy.buf);
		return -1;
			    each_loose_object_fn obj_cb,
				 * the caller that it might be worth
		if (type == OBJ_TAG)
	struct object_directory *odb;
	strbuf_addstr(buf, odb->path);
		argv_array_pushf(&cmd->args, "--git-dir=%s", repo_path);
		if (cruft_cb) {
 * deal with them should arrange to call read_object() and give error
}
	if (is_null_oid(real))
{
	switch (st->st_mode & S_IFMT) {
	struct cached_object *co;
		if (unpack_loose_header_to_strbuf(&stream, map, mapsize, hdr, sizeof(hdr), &hdrbuf) < 0)
		fd = open_loose_object(r, oid, &path);
 * LF separated.  Its base points at a statically allocated buffer that
	return fd;
	int i;
}
				     unsigned char *map, unsigned long mapsize,
		if (!lstat(*path, st))
		      enum object_type type, const char *path,
		if (!c)



	out = fdopen_lock_file(&lock, "w");
	if (!oideq(expected_oid, &real_oid)) {
		      pathbuf.buf);
	}
		if (convert_to_git(istate, path, buf, size, &nbuf,
			*(oi->typep) = co->type;

		}
static int freshen_file(const char *fn)
int repo_has_object_file(struct repository *r,


		}
}

#include "blob.h"
	void *map;
			return i;
int has_loose_object_nonlocal(const struct object_id *oid)
		status = error(_("unable to unpack %s header"),
			check_tree(buf, size);
	return finalize_object_file(tmp_file.buf, filename.buf);
	FILE *in, *out;
		if (oi->type_name)
	if (flags & HASH_FORMAT_CHECK) {
	if (status < Z_OK)
		return 0;
}
	"\x18\x13"
}
{
	} else if (*string == '"' && !unquote_c_style(out, string, &end)) {
			     struct object_info *oi, int flags)
	obj_read_lock();
	}
			    void *data)
	for (i = 0; i < 256; i++) {
		if (errno == EACCES)

	static char buf[GIT_MAX_HEXSZ + 1];
	int i;
		stream->avail_out = size - bytes;
	return NULL;
/* Finalize a file on disk, and close it. */
	return 0;
			/* path exists */
	"\x6e\xf1\x9b\x41\x22\x5c\x53\x69\xf1\xc1" \
static void git_hash_unknown_clone(git_hash_ctx *dst, const git_hash_ctx *src)
	fh = xfdopen(cmd.out, "r");

	int i;
	/* Then the data itself.. */
/*
	git_zstream stream;
	git_deflate_init(&stream, zlib_compression_level);
	 */
	}
	else

	if (map)
		/*

			warning(_("invalid line while parsing alternate refs: %s"),

	int i;
	st = open_istream(r, oid, &obj_type, &size, NULL);
					   type_name(*type))) {
	 * do not optimize out the stat call, even if the
			slash++;


			obj_read_lock();
	}
	free(alts);
	unsigned long isize;
	stream.next_in = (void *)buf;

void for_each_alternate_ref(alternate_ref_fn fn, void *data)
	} else {
		const char *ref_type = NULL;
		if (oi->disk_sizep)
	}

{

		GIT_SHA256_BLKSZ,
	errno = save_errno;
	the_hash_algo->final_fn(real_oid.hash, &c);

	ent = xcalloc(1, sizeof(*ent));
				each_loose_object_fn obj_cb,

		      oid_to_hex(oid));
		break;
		*oi->sizep = size;

		 * to create it:
	return check_and_freshen_file(path.buf, freshen);
		}
				found = 1;

				 int depth);
		/* "protocol error (pack signature mismatch detected)" */
	if (oi->sizep)
		return 0;
#include "pack-revindex.h"

	struct strbuf buf = STRBUF_INIT;
	free(buf);
	/* Get the data stream */
static int has_loose_object(const struct object_id *oid)
			status = error(_("unable to parse %s header with --allow-unknown-type"),
 * With an in-core object data in "map", rehash it to make sure the
	status = write_loose_object(oid, header, hdrlen, buf, len, 0);
		struct stat st;
	return ret;
int for_each_loose_file_in_objdir(const char *path,
static void check_tree(const void *buf, size_t size)
static struct cached_object empty_tree = {
		ret = git_deflate(&stream, Z_FINISH);
		     struct object_id *oid, void *buf, size_t size,
}
	r->objects->odb_tail = &(ent->next);
		return -1;
	/* Detect cases where alternate disappeared */

/*
static void git_hash_sha1_final(unsigned char *hash, git_hash_ctx *ctx)
	strbuf_add(header, buffer, stream->next_out - (unsigned char *)buffer);
static int open_loose_object(struct repository *r,

		if (check_and_freshen_odb(odb, oid, freshen))

{

		/*
			    path);
	return ret;
	}
		if (ref_length + the_hash_algo->hexsz > isize ||
				    path);
int check_and_freshen_file(const char *fn, int freshen)
		GIT_SHA256_RAWSZ,
	struct cached_object *co = cached_objects;
	co->type = type;
}
		 * eat that input.

	}

 *
	while (tree_entry(&desc, &entry))
}
 * application).
		    oid_to_hex(repl), p->pack_name);
	r->hash_algo->final_fn(real_oid.hash, &c);
			     '\n', NULL, 0);
			strbuf_addch(buf, '/');
	int hdrlen;
	repo = read_gitfile(ref_git);
	the_hash_algo->init_fn(&c);
}
 */
				oidcpy(actual_oid_return, &actual_oid);
			return 0;
{
	if (!fspathcmp(path->buf, normalized_objdir))
	git_SHA1_Update(&ctx->sha1, data, len);
	git_SHA256_Update(&ctx->sha256, data, len);
}

	int hdrlen;
		return buf;
		unsigned int val = oid->hash[i];
	for (i = 1; i < GIT_HASH_NALGOS; i++)
		 * conflict resolution yet?
	return result;
 * Returns 0 on success, negative on failure.
{
}
		if (index_fd(istate, oid, fd, st, OBJ_BLOB, path, flags) < 0)
#include "tree-walk.h"
static void fill_alternate_refs_command(struct child_process *cmd,
	},

		BUG("subdir_nr out of range");
		}
#include "object-store.h"
	strbuf_complete(path, '/');

	}
 * callers should avoid this code path when filters are requested.
		r = for_each_file_in_obj_subdir(i, path, obj_cb, cruft_cb,
void prepare_alt_odb(struct repository *r)
		; /* nothing */
	/* path points to cache entries, so xstrdup before messing with it */
				return NULL;
	    subdir_nr >= ARRAY_SIZE(odb->loose_objects_subdir_seen))
		seen_error = 1;
		buffer = repo_read_object_file(r, &actual_oid, &type, &isize);

	else if (type < 0)
	if ((o_cloexec & O_CLOEXEC) && fd < 0 && errno == EINVAL) {

		return PH_ERROR_PROTOCOL;
static void read_info_alternates(struct repository *r,
	read_alternate_refs(path.buf, cb->fn, cb->data);
 * This also bypasses the usual "convert-to-git" dance, and that is on
		struct object_id oid;
}
						subdir_cb, data);
}
	read_info_alternates(r, pathbuf.buf, depth + 1);
#include "refs.h"
				       struct strbuf *out)
	       (status == Z_OK ||
	char hdr[MAX_HEADER_LEN];
{
		ret = -1;

	return check_and_freshen(oid, 0);
		munmap(buf, size);
			return r;
	}
	}
	if (!strbuf_strip_suffix(&path, "/objects"))
		/* Try again w/o O_CLOEXEC: the kernel might not support it */
			struct object_id *oid)
	if (oi->typep)
void *read_object_file_extended(struct repository *r,
		if (write_buffer(fd, compressed, stream.next_out - compressed) < 0)
		error_errno(_("unable to mmap %s"), path);
int index_fd(struct index_state *istate, struct object_id *oid,
	int ret = -1;

		status = error(_("unable to parse %s header"), oid_to_hex(oid));
		goto cleanup;
	int ret = 0;
	memset(&t, 0, sizeof(t));
				break;
	struct lock_file lock = LOCK_INIT;
		else if (read_result != size)
		if (!path_copy.len)
		&empty_blob_oid,
}
	if (access(fn, F_OK))
	}

			if (r)

			stream->avail_out = size - total_read;
		else if (type == OBJ_COMMIT)
{
				; /* somebody created it since we checked */

	struct tag t;
	return content;
		if (flags & OBJECT_INFO_IGNORE_LOOSE)
	int status = Z_OK;
		    strbuf_readlink(&sb, path, st.st_size) ||

	obj_read_unlock();
			check_commit(buf, size);
	char *alts = git_pathdup("objects/info/alternates");
	 * Check if entire header is unpacked in the first iteration.
{
		     struct object_id *oid)
#include "pack.h"
static int append_loose_object(const struct object_id *oid, const char *path,
{
	if (strbuf_read_file(&buf, path, 1024) < 0) {
	ref_git = real_pathdup(path, 0);
	case S_IFLNK:
	} else {
			 * promisor_remote_get_direct(), such that arbitrary
{
	return 0;
		return 0;
int raceproof_create_file(const char *path, create_file_fn fn, void *cb)
			ret = error_errno(_("read error while indexing %s"),
	git_SHA256_Clone(&dst->sha256, &src->sha256);
			}

		return;
	struct object_info oi = OBJECT_INFO_INIT;
	try_rename:
		the_hash_algo->update_fn(&c, buf, stream->next_out - buf);
	return buf->buf;
		strbuf_release(&line);
			argv_array_split(&cmd->args, value);

	return adjust_shared_perm(path);
#include "commit.h"
};
}


void *xmmap_gently(void *start, size_t length,

	if (in) {
	assert(would_convert_to_git_filter_fd(istate, path));
			errno = saved_errno;
		0,
	 */


		 * quoted path; unquote_c_style has copied the

		r = fn(ent, cb);
	return odb_loose_path(r->objects->odb, buf, oid);
	ent->path = xstrdup(pathbuf.buf);
	}
	git_SHA1_Final(hash, &ctx->sha1);
	int found = 0;



	unsigned long size;
}
	for (i = 0; i < the_hash_algo->rawsz; i++) {
	if (fsync_object_files)


{
	 * result out to header, and then append the result of further
		if (!i)
	for (odb = r->objects->odb; odb; odb = odb->next) {
				error(_("object file %s is empty"), path);
			unsigned char *map, unsigned long mapsize,
	/* Sha1.. */
		while (strbuf_getline(&line, in) != EOF) {
		return 0;

	base_len = path.len;

	case S_IFDIR:
		 */
	if (ret == MAP_FAILED)
	if (errno && errno != ENOENT)
	path = xstrfmt("%s/info/alternates", relative_base);
	/* die if we replaced an object with one that does not exist */
		; /* Do nothing */
}
	 */
	} else
	if (re_allocated)
	 */

	}
{
int for_each_file_in_obj_subdir(unsigned int subdir_nr,
				     int fd,
		goto out;
		if (oi->contentp)
	static size_t limit = 0;
	if (!git_config_get_value("core.alternateRefsCommand", &value)) {

		*path = odb_loose_path(odb, &buf, oid);
	r = for_each_loose_file_in_objdir_buf(&buf, obj_cb, cruft_cb,
static void *unpack_loose_rest(git_zstream *stream,
		ret = write_object_file(sbuf.buf, sbuf.len, type_name(OBJ_BLOB),
	 * object even exists.
	for_each_file_in_obj_subdir(subdir_nr, &buf,
{
	0
			     const struct object_id *oid,
	/*
	if (mkdir(path, 0777)) {
	if (write_object)
{
	static char buf[GIT_MAX_HEXSZ + 1];
					 rtype == OBJ_OFS_DELTA);
			      time_t mtime)
			*oi->disk_sizep = st.st_size;
			git_inflate_end(&stream);
}
			       const char *type, struct object_id *oid,
{
			return error_errno(_("unable to write file %s"), filename);
		 */
	memset(stream, 0, sizeof(*stream));
		utb.actime = mtime;
			free(buffer);
	if (!access(mkpath("%s/shallow", ref_git), F_OK)) {
	/*
static void git_hash_sha1_update(git_hash_ctx *ctx, const void *data, size_t len)
		git_hash_unknown_clone,
 * contains "/the/directory/corresponding/to/.git/objects/...", while
	 * we're obtaining the type using '--allow-unknown-type'
	int ret;
{
		return 0;

		 * to remove it:
				 const char *relative_base,
}
	int i;
			reprepare_packed_git(r);
		else
	return 0;
	struct cached_object *co;
static void git_hash_unknown_init(git_hash_ctx *ctx)
		free(buf);
 * the streaming interface and rehash it to do the same.
}

		 * repository in which the user hasn't performed any
	char *buf = xstrdup(path);
	if (mtime) {
	oi.typep = type;
enum scld_error safe_create_leading_directories(char *path)
		return -1;

		error(_("unable to parse header of %s"), path);
int write_object_file(const void *buf, unsigned long len, const char *type,
	read_info_alternates(r, r->objects->odb->path, 0);
}
						      NULL, data);
}
		if (lstat(path, &st) || !S_ISLNK(st.st_mode) ||

		return 0;
	} else if (oi->whence == OI_PACKED) {
		oi = &blank_oi;
			}
 * to write them into the object store (e.g. a browse-only
	}
/*
	stream->next_in = map;
		if (!*next_component)
		return &odb->loose_objects_cache[subdir_nr];

	 */
	return oid_object_info_extended(r, oid, NULL, flags) >= 0;
		git_inflate_end(stream);
{
	struct object_id real_oid;
		stream->avail_out = sizeof(buf);
			return buffer;
		end = strchrnul(string, sep);
				line.buf);
#include "run-command.h"
	ALLOC_GROW(cached_objects, cached_object_nr + 1, cached_object_alloc);
		die_errno(_("unable to read alternates file"));
{
	close_loose_object(fd);
	}
		"sha256",
	static struct strbuf filename = STRBUF_INIT;
		stream.avail_out = sizeof(compressed);
	if (size) {
	strbuf_release(&buf);
	if (*type == OBJ_BLOB && *size > big_file_threshold) {
				      OBJECT_INFO_LOOKUP_REPLACE) < 0)
			goto out;
	 * This size comparison must be "<=" to read the final zlib packets;

					 unsigned long bufsiz, struct strbuf *header)
	 * Set type to 0 if its an unknown object and
		if (parse_oid_hex(line.buf, &oid, &p) || *p) {
 * Map the loose object at "path" if it is not NULL, or the path found by
			    const struct object_id *expected_oid)
	strbuf_addstr(&path, "/refs");


		       unsigned long *size)
			if (find_pack_entry(r, real, &e))
		if (c == ' ')
		*slash = slash_character;
			return -1;

	enum object_type type;
{
	return 0;
static int check_and_freshen_odb(struct object_directory *odb,

int hash_object_file(const struct git_hash_algo *algo, const void *buf,
out:
		git_hash_sha1_clone,

 *
		else if (write_object_file(sb.buf, sb.len, blob_type, oid))
	 * Prevent the common mistake of listing the same
			goto out;
		strbuf_setlen(path, baselen);

			break;
	strbuf_addstr(&buf, path);
 * This creates a temporary file in the same directory as the final
				 const struct object_id *oid,
			if (c > 9)
	strbuf_addstr(&buf, odb->path);
	stream.avail_out = sizeof(compressed);
						  *oi->sizep, oid);
			 * repositories work.
		if (stat_loose_object(r, oid, &st, &path) < 0)
		strbuf_addch(buf, hex[val & 0xf]);
{

	closedir(dir);
}
}
			return NULL;
	enum object_type type = oid_object_info(the_repository, oid, NULL);
		die(_("replacement %s not found for %s"),
		break;
static int freshen_packed_object(const struct object_id *oid)
}
	oid.hash[0] = subdir_nr;
	}
		int saved_errno = errno;

	struct tree_desc desc;
static void git_hash_sha256_update(git_hash_ctx *ctx, const void *data, size_t len)

		while (is_dir_sep(*next_component))
 * searching for a loose object named "oid".
		      struct object_id *oid)
	return 0;

		strbuf_addf(err,
	}
	const char *type_buf = hdr;
		char *ref_git_git = mkpathdup("%s/.git", ref_git);
	git_hash_ctx c;
		strbuf_add(path, de->d_name, namelen);
static const char *odb_loose_path(struct object_directory *odb,
		return -1;
		return -1;
	for (odb = the_repository->objects->odb->next; odb; odb = odb->next) {

	}
			strbuf_addstr(oi->type_name, type_name(co->type));
	int ret;
static int get_conv_flags(unsigned flags)
	return ret;

	}
	else
void enable_obj_read_lock(void)
			warning_errno(_("failed utime() on %s"), tmp_file.buf);
	 * reading the stream.
		 * data for us and set "end". Broken quoting (e.g.,
	struct object_directory *odb;
int index_path(struct index_state *istate, struct object_id *oid,
			    const char *hdr,
}
	co = find_cached_object(real);
	 * won't be able to check collisions, but that's not a
	strbuf_addstr(&pathbuf, entry);
 */
		GIT_SHA1_BLKSZ,
{
	git_hash_ctx c;
		}

		close(fd);
		}
pthread_mutex_t obj_read_mutex;
		n = size;
}
	strbuf_add(tmp, filename, dirlen);
	if (oid_object_info_extended(r, oid, &oi,
	if (oi->type_name)
	if (n > size)

}
	git_SHA256_Final(hash, &ctx->sha256);
		strbuf_add(out, string, end - string);
void add_to_alternates_memory(const char *reference)

/*
	/* Normally if we have it in the pack then we do not bother writing
				    append_loose_object,
	errno = save_errno;
		}
		 */

		enum scld_error scld_result;
}
#include "lockfile.h"
int finalize_object_file(const char *tmpfile, const char *filename)
		utb.modtime = mtime;
			return error(_("insufficient permission for adding an object to repository database %s"), get_object_directory());
static int do_oid_object_info_extended(struct repository *r,
	struct stat st;
	{
		goto out;
		if (r)
			     struct object_info *oi, unsigned flags)
		rollback_lock_file(&lock);
		oidclr(oi->delta_base_oid);
	"\x53\x21"
			ret = error(_("short read while indexing %s"),

	if (freshen_packed_object(oid) || freshen_loose_object(oid))
		 */
	struct pack_entry e;

		git_hash_sha256_final,
		ret = NULL;
	if (*type < 0) {
			     const struct object_id *oid, unsigned long *size)
	int most_interesting_errno = ENOENT;
	if (unpack_loose_header(&stream, map, mapsize, hdr, sizeof(hdr)) < 0) {

		*slash = '\0';
		if (utime(tmp_file.buf, &utb) < 0)
			break;
		char buf[1024 * 16];
	oi.contentp = &content;
		return GIT_HASH_UNKNOWN;
		return 0;
				unsigned long *size,
	}
				 * trying again:
	char hdr[MAX_HEADER_LEN];
		if (oi->typep)
	int type, type_len = 0;
		if (is_dot_or_dotdot(de->d_name))
	 */
{
	ret = fn(path, cb);
	OBJ_TREE,
 */
	 * Convert blobs to git internal format
{
		oi->u.packed.offset = e.offset;


}
			return -1;
static void check_tag(const void *buf, size_t size)
	else if (hdrbuf.len) {


		0x73323536,
		git_hash_sha256_init,
	return 0;
	const int write_object = flags & HASH_WRITE_OBJECT;
	return ret;
		return;
retry_fn:
				ret = SCLD_FAILED;
	if (strbuf_normalize_path(&pathbuf) < 0 && relative_base) {


			obj_read_unlock();
				struct strbuf *path,
		if ((status = parse_loose_header_extended(hdrbuf.buf, oi, flags)) < 0)
		return status;
		argv_array_push(&cmd->args, "for-each-ref");
 * object_directory.  The elements on this list come from
	algo->update_fn(&c, buf, len);
	const char *path;
	do {
{
		 *
 * Prepare alternate object database registry.
	enum object_type type, required_type;

		 * actual_oid.  Check again. */

	struct strbuf entry = STRBUF_INIT;
	}

 * `path` may be relative and should point to $GIT_DIR.
		      const char *path, unsigned flags)
	return GIT_HASH_UNKNOWN;

static int cached_object_nr, cached_object_alloc;
	else
					break;
		the_hash_algo->update_fn(&c, in0, stream.next_in - in0);

	int subdir_nr = oid->hash[0];
		strbuf_addf(err, _("reference repository '%s' is shallow"),
		    !(flags & OBJECT_INFO_SKIP_FETCH_OBJECT)) {
	if (found) {
 * This handles basic git sha1 object files - packing, unpacking,
	strbuf_add_absolute_path(&objdirbuf, r->objects->odb->path);

 * Compute the exact path an alternate is at and returns it. In case of
	/* Sanity check: */
	strbuf_release(&path_copy);
					"local repository."), path);
 *

	 * big deal.
{
		/*

		goto out;
		if (!*slash)
		}
}

	}
		      unsigned flags)
{
		 * e.g. .git/rr-cache pointing at its original
		struct strbuf line = STRBUF_INIT;
}
				relative_base);
		ret = errno;
 * error NULL is returned and the human readable error is added to `err`
	 * thing twice, or object directory itself.
		*oi->disk_sizep = mapsize;
	if (has_object_file(oid) || find_cached_object(oid))
	prepare_alt_odb(the_repository);
{
	unlink_or_warn(tmpfile);
	stream.next_in = (unsigned char *)hdr;
				     unsigned flags)

			       void *buffer, unsigned long size,
		else if (type == OBJ_TAG)
#include "quote.h"

	unsigned long len;
	if (ret == MAP_FAILED && !length)
enum scld_error safe_create_leading_directories_const(const char *path)
			 * TODO Pass a repository struct through
 */

		ref_git = xstrdup(repo);
{



				  const struct object_id *oid)


			close_istream(st);
	} while (ret == Z_OK);
		&empty_tree_oid_sha256,
		struct utimbuf utb;
	int fd;
		/* "eof before pack header was fully read" */
	}
	enum object_type type;
	git_zstream stream;
			return i;
	strbuf_release(&pathbuf);
 * (or equivalent in-core API described above). However, that is
	for (i = 1; i < GIT_HASH_NALGOS; i++)
	BUG("trying to init unknown hash");
	struct name_entry entry;
			/* Opened w/o O_CLOEXEC?  try with fcntl(2) to add it */
			}
}
}
				  const struct object_id *oid)
	bytes = n;
			ret = index_mem(istate, oid, buf, size, type, path, flags);
			return -1;

		/* FIXME!!! Collision check here ? */
{
		strbuf_add(tmp, filename, dirlen - 1);

	return repo_has_object_file_with_flags(r, oid, 0);
				 int depth)
	struct object_info oi = OBJECT_INFO_INIT;
	return ret;
		 * information below, so return early.
		error(_("%s: ignoring alternate object stores, nesting too deep"),
		if (!loose_object_info(r, real, oi, flags))

{
		return PH_ERROR_PACK_SIGNATURE;
		size_t namelen;
	int create_directories_remaining = 3;


out:
				  the_hash_algo->rawsz - 1)) {

			     const struct object_id *oid, const char **path)
	int save_errno;
		if (errno != ENOENT)
 * its name points just after the slash at the end of ".git/objects/"
{
	 * Coda hack - coda doesn't like cross-directory links,
{
				const struct object_id *oid,
#define EMPTY_BLOB_SHA1_BIN_LITERAL \
		struct stat st;
	*r->objects->odb_tail = ent;
	stream.avail_in = hdrlen;

	}
	if (rtype < 0) {
		return -1;

				/* mmap() is forbidden on empty files */
	struct utimbuf t;

	if (stream->avail_in) {

	return 0;

 * messages themselves.
	while (total_read <= size &&
{
	if (e.p->freshened)
		die_errno(_("mmap failed"));
	if (!alt || !*alt)
	if (fd < 0 && dirlen && errno == ENOENT) {
		const char *path;
			ret = SCLD_PERMS;

	obj_read_use_lock = 0;
		&empty_tree_oid,
out:
		}
	} while (status != Z_STREAM_END);
}
			if (scld_result == SCLD_OK)
	write_object_file_prepare(algo, buf, len, type, oid, hdr, &hdrlen);
 * binary blobs, they generally do not want to get any conversion, and

		die_errno(_("failed to read object %s"), oid_to_hex(oid));
	git_SHA256_Init(&ctx->sha256);
	hash_object_file(the_hash_algo, buf, len, type_name(type), oid);

	ret = git_inflate(stream, 0);
			goto out;
	save_errno = errno;
{
	cmd->env = local_repo_env;
	free(buf);
	/* Is this a git repository with refs? */
	}

		/* Not a loose object; someone else may have just packed it. */
	close_istream(st);
}
	/* A scratch copy of path, filled lazily if we need it: */
				       type_name(type), oid);
		link_alt_odb_entry(r, entry.buf,
	 * us, we don't want to fight against them.
			argv_array_push(&cmd->args, "--");
	EMPTY_BLOB_SHA1_BIN_LITERAL

	"\xe6\x9d\xe2\x9b\xb2\xd1\xd6\x43\x4b\x8b" \
		return 0;

		die(_("unable to deflate new object %s (%d)"), oid_to_hex(oid),
static const struct object_id empty_blob_oid_sha256 = {
			status = -1;
		if (!buffer)
	prepare_alt_odb(the_repository);
 * GIT - The information manager from hell

{
	/* Generate the header */
	struct child_process cmd = CHILD_PROCESS_INIT;
	if (!is_absolute_path(entry) && relative_base) {
		return;

		return -1;

		}
	{

 */
		else {
 *
		free(buf);
			    _("reference repository '%s' is grafted"),

				    NULL, NULL,
}
	return check_and_freshen_odb(the_repository->objects->odb, oid, freshen);
		/* Check if it is a missing object */
}

		 * (bytes < size).  In other words, even though we
	init_tree_desc(&desc, buf, size);
	if (oi->sizep == &size_scratch)
	while (ret == SCLD_OK && next_component) {
	}
	for (;;) {
		if (errno != EEXIST)
	fd = git_mkstemp_mode(tmp->buf, 0444);
		NULL,
	ent->next = NULL;
		if (read_result < 0)
	if (memchr(buffer, '\0', stream->next_out - (unsigned char *)buffer))
			error(_("unable to unpack contents of %s"), path);
		      void **contents)
	} else if ((status = parse_loose_header_extended(hdr, oi, flags)) < 0)
			return -1;
			      int hdrlen, const void *buf, unsigned long len,
			    each_loose_cruft_fn cruft_cb,

}
	strbuf_addch(path, '/');
	hdrlen = strlen(type) + MAX_HEADER_LEN;
				    const struct object_id *oid, int flags)

	/*

		*oi->typep = status;
	strbuf_release(&buf);
	const struct object_id *repl = lookup_replace ?
	int hdrlen = sizeof(hdr);
	void *data;
		/* normal, unquoted path */
	else
{
#include "repository.h"


		goto out;
				break;

};
		int r = for_each_loose_file_in_objdir(odb->path, cb, NULL,
	if (!oi->sizep)
		die(_("%s is not a valid object"), oid_to_hex(oid));
			strbuf_addstr(&path_copy, path);
	 * When this succeeds, we just return.  We have nothing
int read_pack_header(int fd, struct pack_header *header)
		oi->whence = OI_CACHED;

	strbuf_release(&objdirbuf);
static void *map_loose_object_1(struct repository *r, const char *path,
/* Size of directory component, including the ending '/' */
				 * Either mkdir() failed because
		strbuf_setlen(path, origlen);
void disable_obj_read_lock(void)
				 int sep, const char *relative_base, int depth)
		 * racing with us to clean up empty directories. Try
	return GIT_HASH_UNKNOWN;
	oi.sizep = sizep;
	BUG("trying to update unknown hash");
}
	int ret;
 * With "map" == NULL, try reading the object named with "oid" using
	int write_object = flags & HASH_WRITE_OBJECT;
	stream->next_out = buffer;

}
	n = stream->total_out - bytes;
	"\x6f\xe1\x41\xf7\x74\x91\x20\xa3\x03\x72" \
	struct object_directory *odb;

	}
 * freshened (if freshening was requested), 0 otherwise. If they return
static int stat_loose_object(struct repository *r, const struct object_id *oid,
		lookup_replace_object(r, oid) : oid;
	}
		if (len == hash_algos[i].rawsz)
		if (oideq(&co->oid, oid))
	int rc = 0;
		}
			  struct strbuf *path,

	if (!is_directory(path.buf))
{
	if (has_loose_object(oid))
}
static int check_stream_oid(git_zstream *stream,
	fd = open(name, flags | o_cloexec);
#include "config.h"
		else
 * The "path" out-parameter will give the path of the object we found (if any).
			       unsigned flags)
 */
		return 0;
/*
 * call to stat_loose_object().
		    (uintmax_t)length, (uintmax_t)limit);
		NULL,
	 * The length must follow immediately, and be in canonical
	}
			size = size * 10 + c;
			*(oi->disk_sizep) = 0;
	struct git_istream *st;
{
		die(_("confused by unstable object source data for %s"),
	return r;
	odb_loose_path(odb, &path, oid);
	 * clean up empty directories at the same time as we are
			next_component++;
	}

	strbuf_addf(path, "%02x", subdir_nr);
}
			return -1;
		fsync_or_die(fd, "loose object file");
	stream.next_out = compressed;
int force_object_loose(const struct object_id *oid, time_t mtime)
				    &odb->loose_objects_cache[subdir_nr]);
		status = git_inflate(stream, 0);

		/* Handle references */
	size_t base_len;
				    _("reference repository '%s' as a linked "
		  int prot, int flags, int fd, off_t offset)
#include "mergesort.h"
	if (!st)
	git_SHA1_Clone(&dst->sha1, &src->sha1);
{
		ret = index_core(istate, oid, fd, xsize_t(st->st_size),
};
	int ret;
 */
		*path = odb_loose_path(odb, &buf, oid);
		static char hex[] = "0123456789abcdef";

			      const struct object_id *oid)

 * can have problems on various filesystems (FAT, NFS, Coda).
	if (!dir) {
	if (!name)
struct alternate_refs_data {
	},
}
		if (oid_array_lookup(odb_loose_cache(odb, oid), oid) >= 0)
		return global_conv_flags_eol | CONV_WRITE_OBJECT;

		for (;;) {
	 * Call xsize_t() only when needed to avoid potentially unnecessary

	oi.sizep = size;
		strbuf_setlen(&pathbuf, pathbuf.len - 1);
		if (check_stream_oid(&stream, hdr, *size, path, expected_oid) < 0)
int hash_algo_by_id(uint32_t format_id)
	return ret;
	return GIT_HASH_UNKNOWN;
{
				errno = ENOTDIR;
					      subdir_cb, data);
	/* recursively add alternates */

		free(ref_git);

{
	if ((p = has_packed_and_bad(r, repl->hash)) != NULL)
	map = map_loose_object_1(the_repository, path, NULL, &mapsize);

	}
	return write_loose_object(oid, hdr, hdrlen, buf, len, 0);
		 * Are we looking at a path in a symlinked worktree

	"\x04\xd4\x5d\x8d\x85\xef\xa9\xb0\x57\xb5" \
	for (odb = r->objects->odb; odb; odb = odb->next) {
	return end;
{
	 */
			return 0;
		if (oi->delta_base_oid)

			goto out;
		       const struct object_id *oid,
	/* Generate the header */
	if (data)
	return status;
int hash_object_file_literally(const void *buf, unsigned long len,
			if (!S_ISDIR(st.st_mode)) {
		/* "protocol error (pack version unsupported)" */
	if (status < 0)
		0,
		mark_bad_packed_object(e.p, real->hash);
	return r;

	char hdr[MAX_HEADER_LEN];

	strbuf_addstr(tmp, "tmp_obj_XXXXXX");
	if (repo) {
				   relative_base, depth, objdirbuf.buf);
	prepare_alt_odb(r);
	link_alt_odb_entries(r, buf.buf, '\n', relative_base, depth);
				      const void *buf, unsigned long len,
 * All of the check_and_freshen functions return 1 if the file exists and was


#include "replace-object.h"
		/* "s256", big-endian */
	struct object_id oid;
					 unsigned long mapsize, void *buffer,
				 * somebody just pruned the containing
{
{
		/*
	DIR *dir;
	fill_alternate_refs_command(&cmd, path);
			return -1;

		/* Now we have the ID of the referred-to object in
 * creation etc.
void *xmmap(void *start, size_t length,
		      enum object_type *type,
	struct strbuf sbuf = STRBUF_INIT;
	for (ent = the_repository->objects->odb->next; ent; ent = ent->next) {
{
	if (status == Z_STREAM_END && !stream->avail_in) {

		return error_errno(_("file write error"));
			break;
	 * so we fall back to a rename, which will mean that it
		strbuf_realpath(&pathbuf, relative_base, 1);
	if (header->hdr_signature != htonl(PACK_SIGNATURE))
	}
			  const char *normalized_objdir)
	} else if (!is_directory(mkpath("%s/objects", ref_git))) {
		if (readlen < 0) {
	git_SHA1_Init(&ctx->sha1);
const char *loose_object_path(struct repository *r, struct strbuf *buf,
{
	strbuf_reset(buf);
				  &hdrlen);
		return NULL;
		char *slash = next_component, slash_character;

	memset(&odb->loose_objects_subdir_seen, 0,
	ret = do_oid_object_info_extended(r, oid, oi, flags);
	     int fd, struct stat *st,
	algo->update_fn(&c, hdr, *hdrlen);


	 * The length must be followed by a zero byte
	}
		stream->next_out = buf;
			*size = isize;

	git_hash_ctx c;
	struct strbuf buf = STRBUF_INIT;

		return -1;
			    unsigned long size,
	if (read_in_full(fd, header, sizeof(*header)) != sizeof(*header))
		while (*slash && !is_dir_sep(*slash))
}
}
	struct strbuf hdrbuf = STRBUF_INIT;
		warn_on_fopen_errors(path);
	/*
			   void *map, unsigned long size, const char *type)
			continue;
				 const struct object_id *oid,
		*oi->typep = type;
}
/*
			return error_errno("readlink(\"%s\")", path);
		error(_("corrupt loose object '%s'"), oid_to_hex(oid));
{
	if (!is_directory(path->buf)) {
}
int obj_read_use_lock = 0;


}
		    get_oid_hex((char *) buffer + ref_length, &actual_oid)) {
	if (flags & OBJECT_INFO_LOOKUP_REPLACE)
	if (status < 0)
		if (!oi->disk_sizep && (flags & OBJECT_INFO_QUICK))
		seen_error = 1;
		die(_("corrupt commit"));
		    memcmp(buffer, ref_type, ref_length) ||
	ret = git_deflate_end_gently(&stream);
	int fd;
			most_interesting_errno = errno;
}
		cmd->git_cmd = 1;
	void *ret;
 * pruning).
#define EMPTY_TREE_SHA1_BIN_LITERAL \
	struct commit c;
	for (i = 0; i < cached_object_nr; i++, co++) {

	const char *end;
	prepare_alt_odb(r);
	return ret;
#define EMPTY_BLOB_SHA256_BIN_LITERAL \
	default:

{
#define MAX_HEADER_LEN 32
	strbuf_release(&sbuf);
		BUG("invalid loose object subdirectory: %x", subdir_nr);

	char *ref_git = NULL;

				 get_conv_flags(flags));
	}
 * Move the just written object into its final resting place.
	 * The number of times that we will try to create the
	}
		die(_("deflateEnd on object %s failed (%d)"), oid_to_hex(oid),

			if (!*size) {

	"\x67\xe3\xb1\xe9\xa7\xdc\xda\x11\x85\x43" \
	} else if (unpack_loose_header(&stream, map, mapsize, hdr, sizeof(hdr)) < 0)

 * in the example above, and has enough space to hold 40-byte hex
	 * more than once, because another process could be trying to
}
			oidclr(oi->delta_base_oid);
#include "packfile.h"

	return 0;
		next_component = slash + 1;
int for_each_loose_object(each_loose_object_fn cb, void *data,

		ref_git = ref_git_git;
		end++;
			strbuf_release(&sb);
			break;

		&empty_blob_oid_sha256,
		seen_error = 1;
	obj_read_use_lock = 1;
	for (i = 1; i < GIT_HASH_NALGOS; i++)
{
		end = strchrnul(string, sep);
		/* "sha1", big-endian */
		return -1;
