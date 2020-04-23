
	if (buf >= tail)
	} else {
		} else {
		/* nada */;
		return error("Object %s not a tag",
	if (item->object.parsed)
		return -1;
#include "tree.h"
				name_to_report ?
		return -1;
	return ret;

		item->tagged = (struct object *)lookup_tag(r, &oid);
		return 0;

	while (buf < tail && *buf++ != '>')
	memset(&sigc, 0, sizeof(sigc));
	while (buf < tail && *buf++ != '\n')
				name_to_report ?
				find_unique_abbrev(oid, DEFAULT_ABBREV),
	return parse_timestamp(dateptr, NULL, 10);

	unsigned long size;
	if (!nl || sizeof(type) <= (nl - bufptr))
	} else if (!strcmp(type, commit_type)) {

	if (size == payload_size) {
void release_tag_memory(struct tag *t)
	if (!o && warn) {
#include "packfile.h"
	}
	return object_as_type(r, obj, OBJ_TAG, 0);
		return -1;
	if (!nl)
		return error("%s: cannot verify a non-tag object of type %s.",
	type = oid_object_info(the_repository, oid, NULL);
	unsigned long size;
	}
		return 0;
	const char *nl;
		return error("no signature found");
	const char *bufptr = data;
		if (o && o->type == OBJ_TAG && ((struct tag *)o)->tagged)
	if (type != OBJ_TAG) {
			o = ((struct tag *)o)->tagged;

	else
	ret = parse_tag_buffer(the_repository, item, data, size);
	char *buf;
			o = parse_object(r, last_oid);
			o = NULL;
			     oid_to_hex(&oid),
	ret = check_signature(buf, payload_size, buf + payload_size,
		item->date = parse_tag_date(bufptr, tail);

}
	signature_check_clear(&sigc);
	free(data);
struct object_id *get_tagged_oid(struct tag *tag)
{
{
{
	if (bufptr + 4 < tail && starts_with(bufptr, "tag "))
{
	type[nl - bufptr] = '\0';
{
	dateptr = buf;
		unsigned flags)


	nl = memchr(bufptr, '\n', tail - bufptr);


	} else if (!strcmp(type, tree_type)) {


	if (item->tag) {
	t->tagged = NULL;
#include "alloc.h"
		 * hit the same error, which lets us tell our current caller
	while (o && o->type == OBJ_TAG)
			last_oid = &((struct tag *)o)->tagged->oid;

			     oid_to_hex(&item->object.oid));
			     oid_to_hex(&item->object.oid));
	bufptr = nl + 1;
		die("bad tag");
	const char *tail = bufptr + size;

{
	} else if (!strcmp(type, tag_type)) {
	int ret;
			return NULL;
#include "object-store.h"
		item->tagged = (struct object *)lookup_blob(r, &oid);
	int ret;

	else
	payload_size = parse_signature(buf, size);
	if (!item->tagged)
	if (item->object.parsed)
#include "cache.h"

static int run_gpg_verify(const char *buf, unsigned long size, unsigned flags)
		 * clear it out in preparation for re-parsing (we'll probably
		return 0;
				find_unique_abbrev(oid, DEFAULT_ABBREV));
	enum object_type type;
	if (!buf)
			warnlen = strlen(warn);
}

	buf = read_object_file(oid, &type, &size);
	struct signature_check sigc;
	const char *dateptr;
		error("missing object referenced by '%.*s'", warnlen, warn);
}
	if (bufptr + 7 < tail && starts_with(bufptr, "tagger "))
		 * about the problem).
	if (type != OBJ_TAG)
				name_to_report :

	}
struct tag *lookup_tag(struct repository *r, const struct object_id *oid)
		return error("unknown tag type '%s' in %s",
{
	}
	}
	struct object_id *last_oid = NULL;
	if (!tag->tagged)
	t->object.parsed = 0;
		print_signature_buffer(&sigc, flags);
		return -1;
struct object *deref_tag(struct repository *r, struct object *o, const char *warn, int warnlen)
}
	if (!starts_with(bufptr, "type "))
		if (last_oid && is_promisor_object(last_oid))
	if (!data)
	return o;
int parse_tag(struct tag *item)

		item->tagged = (struct object *)lookup_tree(r, &oid);
		free(data);
		return -1;
	item->object.parsed = 1;
		; 		/* good */
		return error("bad tag pointer to %s in %s",
		return -1;
}
		if (flags & GPG_VERIFY_VERBOSE)
		/* nada */;
{

		return 0;
	free(buf);
}
				name_to_report :
struct object *deref_tag_noverify(struct object *o)
		return create_object(r, oid, alloc_tag_node(r));
	void *data;
	return ret;
				size - payload_size, &sigc);
	/* dateptr < buf && buf[-1] == '\n', so parsing will stop at buf-1 */
		item->date = 0;

}
	size_t payload_size;
	if (!obj)
#include "tag.h"
#include "gpg-interface.h"
static timestamp_t parse_tag_date(const char *buf, const char *tail)
	bufptr += 4;
	t->date = 0;
	data = read_object_file(&item->object.oid, &type, &size);

			     oid_to_hex(&item->object.oid));

		}

const char *tag_type = "tag";
			     type, oid_to_hex(&item->object.oid));

	return 0;
	return &tag->tagged->oid;
{
	if (!strcmp(type, blob_type)) {
		return error("Could not read %s",
			o = NULL;
		else
	free(t->tag);
{



	struct object *obj = lookup_object(r, oid);
#include "commit.h"
}
	item->tag = xmemdupz(bufptr, nl - bufptr);
				type_name(type));
		item->tagged = (struct object *)lookup_commit(r, &oid);
	if (memcmp("object ", bufptr, 7) || parse_oid_hex(bufptr + 7, &oid, &bufptr) || *bufptr++ != '\n')
}
		o = parse_object(the_repository, &o->oid);
}

		/*
int parse_tag_buffer(struct repository *r, struct tag *item, const void *data, unsigned long size)

	}
	enum object_type type;
	bufptr = nl + 1;
	nl = memchr(bufptr, '\n', tail - bufptr);
	while (o && o->type == OBJ_TAG) {
		if (((struct tag *)o)->tagged) {
		return error("%s: unable to read file.",
	memcpy(type, bufptr, nl - bufptr);
	return o;
		FREE_AND_NULL(item->tag);
	bufptr += 5;
	if (!(flags & GPG_VERIFY_OMIT_STATUS))
		if (!warnlen)
	char type[20];
			last_oid = NULL;
		 * Presumably left over from a previous failed parse;
#include "blob.h"
	if (size < the_hash_algo->hexsz + 24)
	return ret;
	struct object_id oid;
			write_in_full(1, buf, payload_size);
	ret = run_gpg_verify(buf, size, flags);
		 */
	if (buf >= tail)
	int ret;

int gpg_verify_tag(const struct object_id *oid, const char *name_to_report,
