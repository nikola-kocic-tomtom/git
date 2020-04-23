			oidclr(&obj_list[nr].oid);
static git_hash_ctx ctx;

{
			      void *delta, unsigned long size)
{
			     delta, delta_size,
		if (!base_found) {
	/* Write the last part of the buffer to stdout */
			free(delta_data);
			      off_t base_offset,
	consumed_bytes += bytes;


static const char unpack_usage[] = "git unpack-objects [-n] [-q] [-r] [--strict]";
static void write_object(unsigned nr, enum object_type type,
		obj_list[nr].obj = NULL;
	unsigned shift;


};

#include "pack.h"
	return 1;
	void *buf = xmallocz(size);
		display_progress(progress, i + 1);
	read_replace_refs = 0;
		return;
	return buffer;

struct delta_info {
			}
		if (dry_run || !delta_data) {
	if (!obj)
		while (c & 128) {
	pack = fill(1);
	stop_progress(&progress);
	obj_buffer = lookup_object_buffer(obj);
	} else {
	off_t base_offset;
int cmd_unpack_objects(int argc, const char **argv, const char *prefix)
	resolve_delta(nr, obj->type, obj_buffer->buffer,
					  type, size, buf,

		unpack_non_delta_entry(type, size, nr);

	the_hash_algo->init_fn(&ctx);
	unsigned nr;
	struct obj_buffer *obj_buf;

	free(base);
}
 */
		return;
				continue;
				hdr->hdr_entries = htonl(strtoul(c + 1, &c, 10));
	display_throughput(progress, consumed_bytes);
		obj->flags |= FLAG_WRITTEN;
#include "object-store.h"
{
			has_errors = 1;
		if (blob)
			}
	nr_objects = ntohl(hdr->hdr_entries);
	size = (c & 15);
	int i;
		write_rest();
		}
	if (!obj_buffer)
		if (dry_run || !delta_data) {
	resolve_delta(nr, type, base, base_size, delta_data, delta_size);
				continue;
			} else if (base_offset > obj_list[mid].offset) {
				char *c;
		die("failed to apply delta");
			return;
	}
static void add_delta_to_list(unsigned nr, const struct object_id *base_oid,
			if (!strcmp(arg, "-n")) {
		if (stream.total_out == size && ret == Z_STREAM_END)
		obj = parse_object_buffer(the_repository, &obj_list[nr].oid,
	git_inflate_init(&stream);
 * When running under --strict mode, objects whose reachability are
	case OBJ_TAG:
		/* We don't take any non-flag arguments now.. Maybe some day */
#include "decorate.h"
				hdr->hdr_version = htonl(strtoul(arg + 14, &c, 10));
		}
	stream.avail_in = len;
static void use(int bytes)
		return 0;
	}
	if (min > sizeof(buffer))
static unsigned nr_objects;
#include "fsck.h"
		die("pack too large for current definition of off_t");
		return buffer + offset;
		hi = nr;
}
		struct object *obj;
		use(1);
}
	struct object_id oid;
				base_found = !is_null_oid(&base_oid);
			}
			if (!strcmp(arg, "-r")) {

	unsigned i;
			 */
	void *result;
		if (ret <= 0)
		hashcpy(base_oid.hash, fill(the_hash_algo->rawsz));
		die(_("pack exceeds maximum allowed size"));
		unsigned char *pack, c;
 * Verify its reachability and validity recursively and write it out.

 * return the pointer to the buffer.


			return;
	struct delta_info *info;

	write_object(nr, type, result, result_size);
	for (i = 1 ; i < argc; i++) {
#include "cache.h"
	struct object_id base_oid;
			}
	use(sizeof(struct pack_header));

	for (i = 0; i < nr_objects; i++) {
			if (base_offset < obj_list[mid].offset) {
			resolve_delta(info->nr, type, data, size,
	unsigned long size;
		}
				fsck_set_msg_types(&fsck_options, arg);
	off_t offset;
		}
 * At the very end of the processing, write_rest() scans the objects
		else {
		add_object_buffer(obj, buf, size);
	return 0;
}
	use(the_hash_algo->rawsz);
			die(_("fsck error in pack objects"));
		    info->base_offset == obj_list[nr].offset) {

			      type_name(obj->type), &oid) < 0)
			c = *pack;
			/* cannot resolve yet --- queue it */
	unpack_all();
			base_offset += 1;
				if (*c)
		die("final sha1 did not match");
				max_input_size = strtoumax(arg, NULL, 10);

	struct delta_info *next;
		else
	}

	case OBJ_COMMIT:

static void *get_data(unsigned long size)

	struct object_id oid;
		pack = fill(1);
		free(buf);
		offset += ret;
	free(delta);
		struct blob *blob;
	}
			break;
	if (add_decoration(&obj_decorate, object, obj))


/* We always read in 4kB chunks. */
				quiet = 1;
	else
		free(buf);

	}
				   unsigned nr)
			/*
	for (i = 0; i < nr_objects; i++) {
		unpack_delta_entry(type, size, nr);
			if (skip_prefix(arg, "--strict=", &arg)) {
		added_object(nr, type, buf, size);
#include "tag.h"

	git_zstream stream;
	}
		offset = 0;
				exit(1);

	obj_buf = lookup_object_buffer(obj);
 */
struct obj_info {

	stream.next_out = buf;
			base_offset = (base_offset << 7) + (c & 127);
static void unpack_delta_entry(enum object_type type, unsigned long delta_size,
			die("object of unexpected type");
		const char *arg = argv[i];
			oidclr(&obj_list[nr].oid);

	/* make sure off_t is sufficiently large not to wrap */
			}
}
{
				oidcpy(&base_oid, &obj_list[mid].oid);
		else if (resolve_against_held(nr, &base_oid,
 */
				void *delta_data, unsigned long delta_size)
static struct fsck_options fsck_options = FSCK_OPTIONS_STRICT;
		unsigned lo, mid, hi;
#include "object.h"
		while (lo < hi) {
}
{
			 * has not been resolved yet.
	}
		}
	enum object_type type;
	git_inflate_end(&stream);
			free(info);

				continue;
			if (!strcmp(arg, "--strict")) {

		unsigned base_found = 0;
		stream.avail_in = len;
	info->next = delta_list;
{
	shift = 4;
			die("failed to write object");

	do {
			if (!ret)
{

		}
static int dry_run, quiet, recover, has_errors, strict;
			return;
	case OBJ_REF_DELTA:
/*
	memset(&stream, 0, sizeof(stream));
static void write_cached_object(struct object *obj, struct obj_buffer *obj_buf)
/*
		base_offset = c & 127;
 * is Ok.
		added_object(nr, type, buf, size);
		delta_data = get_data(delta_size);
}
#include "config.h"
	if (resolve_against_held(nr, &base_oid, delta_data, delta_size))
	if (type != OBJ_ANY && obj->type != type)
				struct pack_header *hdr;
		write_object(nr, type, buf, size);

	c = *pack;
		return 0;
		if (*arg == '-') {
 */
		die("fsck error in packed object");
		if (write_object_file(buf, size, type_name(type),
static struct delta_info *delta_list;
	} else if (type == OBJ_BLOB) {
 * store.
			return; /* we are done */
		if (ret <= 0) {
	if (strict) {
			error("inflate returned %d", ret);
	switch (type) {

	if (fsck_object(obj, obj_buf->buffer, obj_buf->size, &fsck_options))

	if (delta_list)
	type = (c >> 4) & 7;
			  void *delta, unsigned long delta_size)
#include "tree.h"
	struct object_id base_oid;

}
		if (oideq(&info->base_oid, &obj_list[nr].oid) ||
	/* All done */
			die("invalid blob object");
	info->size = size;
	if (offset) {
{
				continue;
/*
				break;
			die("offset value out of bound for delta base object");
		      obj_buffer->size, delta_data, delta_size);
				die("early EOF");
			free(delta_data);
		die("unresolved deltas left after unpacking");
}
}
			     &result_size);
		progress = start_progress(_("Unpacking objects"), nr_objects);
		if (recover)
	if (!hasheq(fill(the_hash_algo->rawsz), oid.hash))
	obj->flags |= FLAG_WRITTEN;

				die("offset value overflow for delta base object");
static void unpack_non_delta_entry(enum object_type type, unsigned long size,
#include "tree-walk.h"

			add_delta_to_list(nr, &null_oid, base_offset, delta_data, delta_size);
		if (ret != Z_OK) {
		len -= ret;
	struct object *obj;
				len = sizeof(*hdr);
/*
static struct obj_buffer *lookup_object_buffer(struct object *base)
}
		stream.next_in = fill(1);
}

	unsigned char *pack;
static void add_object_buffer(struct object *object, char *buffer, unsigned long size)
		if (write_object_file(buf, size, type_name(type),


 * that have reachability requirements and calls this function.
		size += (c & 0x7f) << shift;
#include "builtin.h"
		exit(1);
			}

			*p = info->next;
			add_delta_to_list(nr, &base_oid, 0, delta_data, delta_size);
				      &obj_list[nr].oid) < 0)
}
			break;
	for (;;) {
	oidcpy(&info->base_oid, base_oid);
		if (base_offset <= 0 || base_offset >= obj_list[nr].offset)
			mid = lo + (hi - lo) / 2;
	struct object_id oid;
	if (obj->flags & FLAG_WRITTEN)
	return lookup_decoration(&obj_decorate, base);
	if (signed_add_overflows(consumed_bytes, bytes))
 * We now know the contents of an object (which is nr-th in the pack);
				      info->delta, info->size);
			break;
	case OBJ_OFS_DELTA:
static unsigned int offset, len;
static void write_rest(void)
		delta_data = get_data(delta_size);
				lo = mid + 1;
	default:

	if (!base) {
		die("failed to write object %s", oid_to_hex(&obj->oid));
				continue;
		return 0;
	struct object *obj;
		memmove(buffer, buffer + offset, len);
static void unpack_one(unsigned nr)
	if (write_object_file(obj_buf->buffer, obj_buf->size,
};
	if (ntohl(hdr->hdr_signature) != PACK_SIGNATURE)
	obj = xcalloc(1, sizeof(struct obj_buffer));
#define FLAG_WRITTEN (1u<<21)
		blob = lookup_blob(the_repository, &obj_list[nr].oid);
	base = read_object_file(&base_oid, &type, &base_size);
					die("bad %s", arg);
	use(1);
 * Make sure at least "min" bytes are available in the buffer, and
	return has_errors;
 */
	}
 * resolve all the deltified objects that are based on it.
					  &eaten);
	if (max_input_size && consumed_bytes > max_input_size)
static void unpack_all(void)

	if (min <= len)

				strict = 1;
}
			p = &delta_list;
			 void *data, unsigned long size)
			; /* Ok we have this one */
	info->nr = nr;
	git_config(git_default_config, NULL);
		p = &info->next;
			use(1);
#include "delta.h"
	struct pack_header *hdr = fill(sizeof(struct pack_header));
	}
		base_offset = obj_list[nr].offset - base_offset;
	unsigned long size, c;
	void *delta_data, *base;
		return 1;
		die("object %s tried to add buffer twice!", oid_to_hex(&object->oid));
		int ret = xwrite(1, buffer + offset, len);
	struct delta_info *info = xmalloc(sizeof(*info));
		int eaten;
	int i;
		die("cannot fill %d bytes", min);
static void resolve_delta(unsigned nr, enum object_type type,
				      &obj_list[nr].oid) < 0)
	info->base_offset = base_offset;

#include "blob.h"

		if (!obj)
	info->delta = delta;
	struct delta_info **p = &delta_list;
					      delta_data, delta_size))
				continue;
	unsigned long base_size;
	}

	while ((info = *p) != NULL) {
	} else {
	while (c & 0x80) {

			check_object(obj_list[i].obj, OBJ_ANY, NULL, NULL);
			return;
		}
{
static int check_object(struct object *obj, int type, void *data, struct fsck_options *options)
		free(buf);
static struct decoration obj_decorate;
{
/*
		c = *pack;
static struct progress *progress;
				if (*c != ',')
{
				continue;
	void *delta;
			if (skip_prefix(arg, "--max-input-size=", &arg)) {
 * suspect are kept in core without getting written in the object
	obj_list[nr].offset = consumed_bytes;
	obj_list = xcalloc(nr_objects, sizeof(*obj_list));
			die_errno("read error on input");
/*

		if (!recover)
			 void *data, unsigned long size);
 */
static struct obj_info *obj_list;
	struct obj_buffer *obj;
				recover = 1;
		use(the_hash_algo->rawsz);
		}
	if (!(obj->flags & FLAG_OPEN)) {
static void added_object(unsigned nr, enum object_type type,
			if (!base_offset || MSB(base_offset, 7))

static off_t consumed_bytes;
 * to be checked at the end.
	}
#include "progress.h"
	void *buf = get_data(size);

				strict = 1;
	if (!pack_version_ok(hdr->hdr_version))
			ntohl(hdr->hdr_version));
static unsigned char buffer[4096];
			usage(unpack_usage);
		the_hash_algo->update_fn(&ctx, buffer, offset);
	stream.next_in = fill(1);


	char *buffer;

	if (!result)

			if (!recover)
		error("bad object type %d", type);
	obj = lookup_object(the_repository, base);
{
		len += ret;
		}
			if (starts_with(arg, "--pack_header=")) {
				 &obj_list[nr].oid);
	case OBJ_TREE:
			die("invalid %s", type_name(type));
	if (!strict) {
	while (len) {
		obj_list[nr].obj = obj;
	}
	obj->buffer = buffer;
		has_errors = 1;
			blob->object.flags |= FLAG_WRITTEN;
		if (obj_list[i].obj)
			  void *base, unsigned long base_size,
{
	obj->size = size;
		off_t base_offset;

static void *fill(int min)
		die("Error on reachable objects of %s", oid_to_hex(&obj->oid));
{
			exit(1);
		die("bad pack file");
	if (!obj)
}
		unpack_one(i);
			} else {
			 void *buf, unsigned long size)
static int resolve_against_held(unsigned nr, const struct object_id *base,
	if (!dry_run && buf)
}
		      oid_to_hex(&base_oid));
		}
			continue;
	the_hash_algo->final_fn(oid.hash, &ctx);

	if (bytes > len)
	if (type == OBJ_REF_DELTA) {
	if (!quiet)
		if (has_object_file(&base_oid))
{
 * Called only from check_object() after it verified this object
		hash_object_file(the_hash_algo, buf, size, type_name(type),
			 * The delta base object is itself a delta that
	quiet = !isatty(2);
	return buf;
		unsigned long size;
		pack = fill(1);
		int ret = git_inflate(&stream, 0);
		die("object type mismatch");
			if (!strcmp(arg, "-q")) {
		use(len - stream.avail_in);
#define FLAG_OPEN (1u<<20)
}
		use(1);

{
		int type = oid_object_info(the_repository, &obj->oid, &size);
		c = *pack;
				hi = mid;
	delta_list = info;
		ssize_t ret = xread(0, buffer + len, sizeof(buffer) - len);
static void added_object(unsigned nr, enum object_type type,
		return;
	fsck_options.walk = check_object;
struct obj_buffer {
			FREE_AND_NULL(buf);
{
			}

		has_errors = 1;
		added_object(nr, type, buf, size);
};

				hdr->hdr_signature = htonl(PACK_SIGNATURE);
					die("bad %s", arg);
static off_t max_input_size;
	unsigned long size;
		if (fsck_finish(&fsck_options))
	len -= bytes;
		lo = 0;
	offset += bytes;
			pack = fill(1);
				dry_run = 1;
			       unsigned nr)
	stream.avail_out = size;

	result = patch_delta(base, base_size,
}
		obj->flags |= FLAG_OPEN;
		usage(unpack_usage);
		die("used more bytes than were available");
	struct obj_buffer *obj_buffer;
/* Remember to update object flag allocation in object.h */
		error("failed to read delta-pack base object %s",

		if (type != obj->type || type <= 0)
	} while (len < min);
			return;
	the_hash_algo->update_fn(&ctx, buffer, offset);
	}
 * of it.  Under --strict, this buffers structured objects in-core,
		return 0;
#include "commit.h"
			}
	}

		return;
		shift += 7;
				hdr = (struct pack_header *)buffer;
	unsigned long result_size;
 * Write out nr-th object from the list, now we know the contents
		die("Whoops! Cannot find object '%s'", oid_to_hex(&obj->oid));
{
	if (!obj_buf)
	case OBJ_BLOB:
		obj_list[nr].obj = NULL;
		die("unknown pack file version %"PRIu32,
	if (fsck_walk(obj, NULL, &fsck_options))
	write_cached_object(obj, obj_buf);
			die("failed to write object");
