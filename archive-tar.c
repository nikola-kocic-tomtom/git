static void write_trailer(void)

 * pax extended header records have the format "%u %s=%s\n".  %u contains
	write_tar_archive,
}
static int write_tar_filter_archive(const struct archiver *ar,
		args->time = USTAR_MAX_MTIME;
#define RECORDSIZE	(512)
				  const struct object_id *oid,

	filter.in = -1;
		do_write_blocked(buf, readlen);
#include "archive.h"
	}
			memcpy(header.prefix, path, plen);
	if (S_ISREG(mode) && size > USTAR_MAX_SIZE) {
			strbuf_append_ext_header(&ext_header, "path",
		*header.typeflag = TYPEFLAG_REG;
	}

	if (offset) {
	size_in_header = size;
static int nr_tar_filters;
	unsigned long size, size_in_header;

	close(filter.in);
	xsnprintf(header.name, sizeof(header.name), "%s.paxheader", oid_to_hex(oid));

 * Copyright (c) 2005, 2006 Rene Scharfe
		strbuf_addf(&cmd, " -%d", args->compression_level);
	if (S_ISDIR(mode) || S_ISGITLINK(mode)) {
}
static int write_tar_filter_archive(const struct archiver *ar,
	tail = offset % RECORDSIZE;
	struct ustar_header header;
	strbuf_addch(sb, '\n');
{
	xsnprintf(header.name, sizeof(header.name), "pax_global_header");
	return NULL;
	char buf[BLOCKSIZE];
	if (!ext_header.len)
	int i;
		ar->data = xstrdup(value);
		if (!strncmp(ar->name, name, len) && !ar->name[len])
 *
	}

void init_tar_archiver(void)

		if (size < chunk)
{
			register_archiver(tar_filters[i]);
{
		else
	memcpy(header->version, "00", 2);

}
{
{
		mode |= 0777;
		buf += BLOCKSIZE;
}
		i--;
	if (pathlen > sizeof(header.name)) {
	"tar",
		else
	strbuf_addf(sb, "%"PRIuMAX" %s=", (uintmax_t)len, keyword);
	int tail = BLOCKSIZE - offset;
}
		buffer = object_file_to_archive(args, path, oid, old_mode, &type, &size);
			ar->flags &= ~ARCHIVER_REMOTE;
 */
static void strbuf_append_ext_header_uint(struct strbuf *sb,
		return error(_("cannot stream blob %s"), oid_to_hex(oid));
		return 0;
		size_t plen = get_path_prefix(path, pathlen,
	len = xsnprintf(buf, sizeof(buf), "%"PRIuMAX, value);
	int err = 0;
		size_in_header = 0;

	if (finish_command(&filter) != 0)
		offset = 0;

	chksum += sizeof(header->chksum) * ' ';
 * this size.
 * at 11 octal digits. POSIX specifies that we switch to extended headers at

		chksum += *p++;
	return err;

				    struct archiver_args *args);
	for (tmp = 1; len / 10 >= tmp; tmp *= 10)

	return chksum;
		enum object_type type;
		size -= BLOCKSIZE;
		if (!value)
			return error(_("cannot read %s"), oid_to_hex(oid));
 * follows the rest of the block (if any).
	if (offset == BLOCKSIZE) {
}
	size_t len, tmp;
static int tar_umask = 002;
		memcpy(header.name, path, pathlen);
	strbuf_addstr(&cmd, ar->data);
{
 * This is the max value that a ustar size header can specify, as it is fixed
					  uintmax_t value)
					 oid_to_hex(oid),
 */
	strbuf_append_ext_header(sb, keyword, buf, len);
	xsnprintf(header->devmajor, sizeof(header->devmajor), "%07o", 0);
			return config_error_nonbool(var);
			tar_umask = umask(0);
		return error(_("unsupported file mode: 0%o (SHA1: %s)"),
	if (dup2(filter.in, 1) < 0)

	strbuf_release(&ext_header);
static void do_write_blocked(const void *data, unsigned long size)
static void prepare_header(struct archiver_args *args,
	if (!readlen)
	struct child_process filter = CHILD_PROCESS_INIT;
	if (!strcmp(var, "tar.umask")) {
	strbuf_release(&ext_header);
	int r;
	err = write_archive_entries(args, write_tar_entry);
	}
		    (uintmax_t)len, (uintmax_t)(sb->len - orig_len));
{
	if (tail < 2 * RECORDSIZE) {
 * string and appends it to a struct strbuf.
			strbuf_append_ext_header(&ext_header, "linkpath",
 */
	struct git_istream *st;
	} else
		free(ar->data);
		size_t rest = pathlen - plen - 1;
static void write_if_needed(void)
		BUG("tar-filter archiver called with no filter defined");
		mode = (mode | 0777) & ~tar_umask;
	if (S_ISREG(mode) && !args->convert &&
	int err = 0;
	if (!ar->data)
#endif
static struct archiver **tar_filters;
{

	if (args->time > USTAR_MAX_MTIME) {
#include "streaming.h"
static void strbuf_append_ext_header(struct strbuf *sb, const char *keyword,
					      sizeof(header.prefix));
	struct archiver *ar;
	size_t i = pathlen;

		} else {
	unsigned int old_mode = mode;
	return err;
	xsnprintf(header->size, sizeof(header->size), "%011"PRIoMAX , S_ISREG(mode) ? (uintmax_t)size : (uintmax_t)0);
	argv[0] = cmd.buf;
				  oid_to_hex(oid));
#else
 * keyword, the second one is the value.  This function constructs such a
 * Like strbuf_append_ext_header, but for numeric values.
	const char *name;
		memset(block + offset, 0, RECORDSIZE - tail);
/*
};
			   const char *path, size_t pathlen,
	write_global_extended_header(args);
			memcpy(header.name, path + plen + 1, rest);
	ARCHIVER_REMOTE
	write_blocked(ext_header.buf, ext_header.len);
	register_archiver(&tar_archiver);
 * queues up writes, so that all our write(2) calls write exactly one

	xsnprintf(header->devminor, sizeof(header->devminor), "%07o", 0);

	write_blocked(&header, sizeof(header));
	xsnprintf(header->mtime, sizeof(header->mtime), "%011lo", (unsigned long) args->time);
	xsnprintf(header->chksum, sizeof(header->chksum), "%07o", ustar_header_chksum(header));
	close_istream(st);
#define USTAR_MAX_SIZE 077777777777UL
 * the size of the whole string (including the %u), the first %s is the
	} else if (S_ISREG(mode)) {
}

	}

	} else {
	close(1);
			err = stream_blocked(args->repo, oid);

		buffer = NULL;

	argv[1] = NULL;
	ar = find_tar_filter(name, namelen);
		    ", should be %"PRIuMAX,
	memcpy(header->magic, "ustar", 6);
	const char *buf = data;
	mode = 0100666;
 * Likewise for the mtime (which happens to use a buffer of the same size).

/*
	if (!strcmp(type, "remote")) {
		mode = (mode | ((mode & 0100) ? 0777 : 0666)) & ~tar_umask;
	if (len != sb->len - orig_len)
			   unsigned int mode, unsigned long size)
		return;


	return readlen;
	xsnprintf(header->gid, sizeof(header->gid), "%07o", 0);
	}
		offset += chunk;

{

	*header.typeflag = TYPEFLAG_GLOBAL_HEADER;
		return 0;
		memcpy(block + offset, buf, size);
	memset(&header, 0, sizeof(header));
			write_blocked(buffer, size);
			break;
	strbuf_release(&cmd);
		} else {
/*
	write_if_needed();
		strbuf_append_ext_header(&ext_header, "comment",
	xsnprintf(header->mode, sizeof(header->mode), "%07o", mode & 07777);
	return i;
{
}
			   struct ustar_header *header,
			     struct archiver_args *args)
{

 */
	r = write_tar_archive(ar, args);
#endif

	unsigned int mode;
	} while (i > 0 && path[i] != '/');
{
/*
/*
	tar_filter_config("tar.tgz.remote", "true", NULL);
	git_config(git_tar_config, NULL);
		size -= chunk;
	}
static size_t get_path_prefix(const char *path, size_t pathlen, size_t maxlen)
		i--;
	memset(&header, 0, sizeof(header));
}
	if (!strcmp(type, "command")) {
	    size > big_file_threshold)
		buf += chunk;
{
	strbuf_add(sb, value, valuelen);
	unsigned long sz;
	if (!st)
	while (p < (const unsigned char *)header->chksum)
	return 0;
			   unsigned int mode)
	prepare_header(args, &header, mode, size_in_header);
}
}
	strlcpy(header->gname, "root", sizeof(header->gname));

		if (value && !strcmp(value, "user")) {

		tar_filters[nr_tar_filters++] = ar;
	if (S_ISLNK(mode)) {
}
	}
}
	char buf[40]; /* big enough for 2^128 in decimal, plus NUL */
	write_blocked(&header, sizeof(header));
{


			                         buffer, size);
	}
{
 * The end of tar archives is marked by 2*512 nul bytes and after that
		len++;
			ar->flags |= ARCHIVER_REMOTE;
		die_errno(_("unable to start '%s' filter"), argv[0]);
	for (i = 0; i < nr_tar_filters; i++) {
	p += sizeof(header->chksum);
		memset(block, 0, offset);
}
		ar = xcalloc(1, sizeof(*ar));

		ar->flags = ARCHIVER_WANT_COMPRESSION_LEVELS;

	struct strbuf ext_header = STRBUF_INIT;
	}
	else if (S_ISLNK(mode) || S_ISREG(mode)) {
{
static void write_global_extended_header(struct archiver_args *args)
		finish_record();
 * queues up writes, so that all our write(2) calls write exactly one
		write_or_die(1, block, BLOCKSIZE);
	if (S_ISREG(mode) && size > 0) {

		if (buffer)
		unsigned long chunk = BLOCKSIZE - offset;
}
	int i;
		offset += size;
	return r;
#define USTAR_MAX_MTIME TIME_MAX
	}
#if TIME_MAX == 0xFFFFFFFF
/* writes out the whole block, but only if it is full */
				      ext_header.len);
	if (ext_header.len > 0) {
 */
	mode = 0100666;
	int len;
static int alloc_tar_filters;
	if (i > maxlen)
	while (p < (const unsigned char *)header + sizeof(struct ustar_header))
	prepare_header(args, &header, mode, ext_header.len);

		write_extended_header(args, oid, ext_header.buf,
		if (readlen <= 0)
static void write_blocked(const void *data, unsigned long size)
	if (i > 1 && path[i - 1] == '/')
	struct ustar_header header;
	} else if (S_ISLNK(mode)) {
		return 0;

	filter.use_shell = 1;
				    struct archiver_args *args)
		ar->name = xmemdupz(name, namelen);
		size = 0;
		ar->write_archive = write_tar_filter_archive;
	memset(&header, 0, sizeof(header));
static int write_tar_archive(const struct archiver *ar,
					 the_hash_algo->hexsz);
	if (oid)
#include "tar.h"
#include "run-command.h"
		/* omit any filters that never had a command configured */
	const struct object_id *oid = args->commit_oid;
		write_or_die(1, block, BLOCKSIZE);
static int git_tar_config(const char *var, const char *value, void *cb)
	*header.typeflag = TYPEFLAG_EXT_HEADER;

	tar_filter_config("tar.tgz.command", "gzip -cn", NULL);
		write_if_needed();
#else
	}
			   const struct object_id *oid,
	}
	const char *argv[2];
	if (size) {
	tar_filter_config("tar.tar.gz.remote", "true", NULL);
 */
}
		}
		*header.typeflag = TYPEFLAG_LNK;

}
 */
	prepare_header(args, &header, mode, size);
	for (i = 0; i < nr_tar_filters; i++) {
	}
static unsigned int ustar_header_chksum(const struct ustar_header *header)
	struct strbuf ext_header = STRBUF_INIT;
	filter.argv = argv;

	    oid_object_info(args->repo, oid, &size) == OBJ_BLOB &&

static struct archiver *find_tar_filter(const char *name, int len)
			xsnprintf(header.linkname, sizeof(header.linkname),
				  "see %s.paxheader", oid_to_hex(oid));

		write_trailer();
static int tar_filter_config(const char *var, const char *value, void *data)
static void write_extended_header(struct archiver_args *args,
		*header.typeflag = TYPEFLAG_DIR;
	}
			xsnprintf(header.name, sizeof(header.name), "%s.data",

	if (start_command(&filter) < 0)
static int stream_blocked(struct repository *r, const struct object_id *oid)
			umask(tar_umask);
	xsnprintf(header->uid, sizeof(header->uid), "%07o", 0);
#define USTAR_MAX_MTIME 077777777777ULL
		if (!buffer)
			memcpy(header.linkname, buffer, size);
		strbuf_append_ext_header_uint(&ext_header, "mtime",

			tar_umask = git_config_int(var, value);


	finish_record();
						 path, pathlen);
/*

static void finish_record(void)
	if (!ar) {
		offset += RECORDSIZE - tail;
	if (tail)  {

	if (!err)
#if ULONG_MAX == 0xFFFFFFFF
{
	unsigned long tail;
		if (git_config_bool(var, value))

				  const void *buffer, unsigned long size)
	const unsigned char *p = (const unsigned char *)header;
	ssize_t readlen;
	unsigned int mode;
			chunk = size;

	do {
		if (size > sizeof(header.linkname)) {
static int write_tar_entry(struct archiver_args *args,
	size_t orig_len = sb->len;
	st = open_istream(r, oid, &type, &sz, NULL);
	}
#define USTAR_MAX_SIZE ULONG_MAX
		BUG("pax extended header length miscalculated as %"PRIuMAX

		if (tar_filters[i]->data)
	}
	void *buffer;
}
static struct archiver tar_archiver = {
#include "cache.h"
}
	if (args->compression_level >= 0)
	const char *type;
	for (;;) {
	return tar_filter_config(var, value, cb);
		} else
		struct archiver *ar = tar_filters[i];
		if (plen > 0 && rest <= sizeof(header.name)) {
			return ar;
{
static char block[BLOCKSIZE];
	strlcpy(header->uname, "root", sizeof(header->uname));
					  const char *keyword,
		buffer = NULL;
		strbuf_append_ext_header_uint(&ext_header, "size", size);
	strbuf_grow(sb, len);
{
	}
	do_write_blocked(data, size);
	unsigned int chksum = 0;
	} else {


#define BLOCKSIZE	(RECORDSIZE * 20)
	int namelen;
/*
 * full block; pads writes to RECORDSIZE

	enum object_type type;
	memset(block + offset, 0, tail);

	struct strbuf cmd = STRBUF_INIT;
 * full block; pads writes to RECORDSIZE
		readlen = read_istream(st, buf, sizeof(buf));
	write_blocked(&header, sizeof(header));

	free(buffer);
	write_or_die(1, block, BLOCKSIZE);

	}
}
				     const char *value, size_t valuelen)
		i = maxlen;

	if (parse_config_key(var, "tar", &name, &namelen, &type) < 0 || !name)
	close(1);
	tar_filter_config("tar.tar.gz.command", "gzip -cn", NULL);
	write_blocked(buffer, size);
#include "config.h"
					      args->time);
	len = 1 + 1 + strlen(keyword) + 1 + valuelen + 1;
static unsigned long offset;
#include "object-store.h"

			     mode, oid_to_hex(oid));
		memcpy(block + offset, buf, chunk);
		chksum += *p++;
		ALLOC_GROW(tar_filters, nr_tar_filters + 1, alloc_tar_filters);
{
		write_or_die(1, buf, BLOCKSIZE);
		die_errno(_("unable to redirect descriptor"));
		return 0;
	}
		die(_("'%s' filter reported error"), argv[0]);
	/* "%u %s=%s\n" */
	while (size >= BLOCKSIZE) {
		}
	struct ustar_header header;
