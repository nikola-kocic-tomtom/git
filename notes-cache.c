

	struct pretty_print_context pretty_ctx;
		return -1;
	memset(&pretty_ctx, 0, sizeof(pretty_ctx));
char *notes_cache_get(struct notes_cache *c, struct object_id *key_oid,
	strbuf_addf(&ref, "refs/notes/%s", name);

}
	enum object_type type;
		    const char *data, size_t size)
#include "object-store.h"
{

	if (commit_tree(c->validity, strlen(c->validity), &tree_oid, NULL,
int notes_cache_put(struct notes_cache *c, struct object_id *key_oid,
{
	struct object_id oid;
	return add_note(&c->tree, key_oid, &value_oid, NULL);

	int flags = NOTES_INIT_WRITABLE;
	c->validity = xstrdup(validity);
void notes_cache_init(struct repository *r, struct notes_cache *c,
#include "repository.h"
}
#include "refs.h"
	struct object_id tree_oid, commit_oid;
		       NULL, 0, UPDATE_REFS_QUIET_ON_ERR) < 0)
}
{

	char *value;
				      const char *validity)
	format_commit_message(commit, "%s", &msg, &pretty_ctx);

{

		return 0;
	if (!commit)
	const struct object_id *value_oid;
	struct commit *commit;

		flags |= NOTES_INIT_EMPTY;
		return 0;
	value = read_object_file(value_oid, &type, &size);

		      size_t *outsize)

		return -1;
	if (write_notes_tree(&c->tree, &tree_oid))
	memset(c, 0, sizeof(*c));
	value_oid = get_note(&c->tree, key_oid);
	return value;
		      const char *name, const char *validity)
}
	strbuf_release(&msg);

		return NULL;
				      const char *ref,
		return 0;
	commit = lookup_commit_reference_gently(r, &oid, 1);
	if (!c || !c->tree.initialized || !c->tree.update_ref ||
	return ret;

		return -1;
	strbuf_release(&ref);
int notes_cache_write(struct notes_cache *c)
	struct object_id value_oid;
	*outsize = size;
	strbuf_trim(&msg);
static int notes_cache_match_validity(struct repository *r,

	struct strbuf ref = STRBUF_INIT;
	int ret;
{
			&commit_oid, NULL, NULL) < 0)
}
	ret = !strcmp(msg.buf, validity);
	if (read_ref(ref, &oid) < 0)

	if (!c->tree.dirty)
#include "notes-cache.h"
		return -1;

	    !*c->tree.update_ref)
	if (!notes_cache_match_validity(r, ref.buf, validity))

	unsigned long size;
#include "cache.h"
	if (!value_oid)
	init_notes(&c->tree, ref.buf, combine_notes_overwrite, flags);
	if (update_ref("update notes cache", c->tree.update_ref, &commit_oid,
	return 0;
		return -1;
	if (write_object_file(data, size, "blob", &value_oid) < 0)

#include "commit.h"
	struct strbuf msg = STRBUF_INIT;
